//! Reading a secret from a terminal without echoing it
//!
//! The unix tests drive the reader through a pseudo-terminal and check the
//! terminal's echo flag while the reader waits and after it returns, on the
//! success path and on the error paths.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use alice_os_keystore::prompt::{read_secret_from, PromptError};

/// A plain file is not a terminal: the reader refuses it before writing a prompt.
#[test]
fn input_that_is_not_a_terminal_is_refused() {
    let path = std::env::temp_dir().join(format!("read-secret-{}", std::process::id()));
    std::fs::write(&path, b"secret\n").unwrap();
    let input = std::fs::File::open(&path).unwrap();
    let mut prompt_out = Vec::new();
    let r = read_secret_from(&input, &mut prompt_out, "Passphrase: ");
    assert!(matches!(r, Err(PromptError::NotATerminal)), "{r:?}");
    assert!(
        prompt_out.is_empty(),
        "a prompt was written for a non-terminal"
    );
    let _ = std::fs::remove_file(&path);
}

#[cfg(unix)]
mod pty {
    use super::*;
    use rustix::fs::{Mode, OFlags};
    use rustix::pty::{grantpt, openpt, ptsname, unlockpt, OpenptFlags};
    use rustix::termios::{tcgetattr, tcsetattr, InputModes, LocalModes, OptionalActions};
    use std::io::Write;
    use std::os::fd::OwnedFd;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    type Read = Result<zeroize::Zeroizing<String>, PromptError>;

    /// Runs the reader on `terminal` in a thread; the result arrives on the channel (a reader
    /// that never returns shows up as a timeout instead of a hung test)
    fn spawn_reader(terminal: OwnedFd) -> mpsc::Receiver<Read> {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let r = read_secret_from(&terminal, &mut Vec::new(), "> ");
            let _ = tx.send(r);
        });
        rx
    }

    fn result(rx: &mpsc::Receiver<Read>) -> Read {
        rx.recv_timeout(Duration::from_secs(10))
            .expect("the reader did not return within 10 s")
    }

    /// A connected pair: the controller side the test writes to, and the
    /// terminal side the reader reads from.
    fn pair() -> (std::fs::File, OwnedFd) {
        let controller = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
        grantpt(&controller).unwrap();
        unlockpt(&controller).unwrap();
        let name = ptsname(&controller, Vec::new()).unwrap();
        let terminal = rustix::fs::open(
            name.as_c_str(),
            OFlags::RDWR | OFlags::NOCTTY,
            Mode::empty(),
        )
        .unwrap();
        (std::fs::File::from(controller), terminal)
    }

    fn echo_on(fd: &OwnedFd) -> bool {
        tcgetattr(fd)
            .unwrap()
            .local_modes
            .contains(LocalModes::ECHO)
    }

    /// Waits until the reader has turned echo off (it does so before reading).
    fn wait_for_echo_off(fd: &OwnedFd) {
        let start = Instant::now();
        while echo_on(fd) {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "echo was never turned off"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn echo_is_off_while_reading_and_restored_after() {
        let (mut controller, terminal) = pair();
        assert!(echo_on(&terminal), "a new pseudo-terminal echoes");
        let watched = terminal.try_clone().unwrap();
        let reader = std::thread::spawn(move || {
            let mut out = Vec::new();
            let r = read_secret_from(&terminal, &mut out, "Passphrase: ");
            (r, out)
        });
        wait_for_echo_off(&watched);
        controller.write_all(b"correct horse\n").unwrap();
        let (r, out) = reader.join().unwrap();
        assert_eq!(r.unwrap().as_str(), "correct horse");
        assert_eq!(out, b"Passphrase: ");
        assert!(echo_on(&watched), "echo was not restored after reading");
    }

    #[test]
    fn an_empty_line_is_its_own_error_and_echo_is_restored() {
        let (mut controller, terminal) = pair();
        let watched = terminal.try_clone().unwrap();
        let reader = std::thread::spawn(move || read_secret_from(&terminal, &mut Vec::new(), "> "));
        wait_for_echo_off(&watched);
        controller.write_all(b"\n").unwrap();
        let r = reader.join().unwrap();
        assert!(matches!(r, Err(PromptError::Empty)), "{r:?}");
        assert!(
            echo_on(&watched),
            "echo was not restored after an empty line"
        );
    }

    #[test]
    fn input_that_ends_without_a_newline_is_an_error_and_echo_is_restored() {
        // the end-of-file character (Ctrl-D) delivers "abc" without a newline, a second one at
        // the start of the line makes the read return 0: the input ended before the line did
        // (the controller stays open: on Linux a terminal whose controller closed no longer
        // answers tcgetattr, so the mode could not be checked afterwards)
        let (mut controller, terminal) = pair();
        let watched = terminal.try_clone().unwrap();
        let reader = std::thread::spawn(move || read_secret_from(&terminal, &mut Vec::new(), "> "));
        wait_for_echo_off(&watched);
        let eof =
            tcgetattr(&watched).unwrap().special_codes[rustix::termios::SpecialCodeIndex::VEOF];
        controller.write_all(&[b'a', b'b', b'c', eof, eof]).unwrap();
        let r = reader.join().unwrap();
        assert!(matches!(r, Err(PromptError::Closed)), "{r:?}");
        assert!(echo_on(&watched), "echo was not restored after an error");
        drop(controller);
    }

    #[test]
    fn a_line_longer_than_the_limit_is_refused_and_echo_is_restored() {
        let (mut controller, terminal) = pair();
        let watched = terminal.try_clone().unwrap();
        let reader = std::thread::spawn(move || read_secret_from(&terminal, &mut Vec::new(), "> "));
        wait_for_echo_off(&watched);
        let long = vec![b'a'; alice_os_keystore::prompt::MAX_SECRET_LEN + 1];
        // canonical mode delivers a line at most this long per read: send it in pieces
        for chunk in long.chunks(512) {
            controller.write_all(chunk).unwrap();
        }
        controller.write_all(b"\n").unwrap();
        let r = reader.join().unwrap();
        assert!(matches!(r, Err(PromptError::TooLong)), "{r:?}");
        assert!(
            echo_on(&watched),
            "echo was not restored after a refused line"
        );
    }

    /// Enter sends a carriage return; a terminal whose mode does not translate it (ICRNL
    /// cleared, e.g. left so by another program) still ends the line, and the mode the reader
    /// found is the mode it leaves
    #[test]
    fn a_carriage_return_ends_the_line_when_the_terminal_does_not_translate_it() {
        let (mut controller, terminal) = pair();
        let mut mode = tcgetattr(&terminal).unwrap();
        mode.input_modes.remove(InputModes::ICRNL);
        tcsetattr(&terminal, OptionalActions::Now, &mode).unwrap();
        let watched = terminal.try_clone().unwrap();
        let rx = spawn_reader(terminal);
        wait_for_echo_off(&watched);
        controller.write_all(b"abc\r").unwrap();
        assert_eq!(result(&rx).unwrap().as_str(), "abc");
        let after = tcgetattr(&watched).unwrap();
        assert!(
            after.local_modes.contains(LocalModes::ECHO),
            "echo was not restored"
        );
        assert!(
            !after.input_modes.contains(InputModes::ICRNL),
            "the reader did not restore the mode it found"
        );
    }

    /// The same in a terminal left in non-canonical mode (no line editing, reads that do not wait)
    #[test]
    fn a_carriage_return_ends_the_line_in_a_non_canonical_terminal() {
        let (mut controller, terminal) = pair();
        let mut mode = tcgetattr(&terminal).unwrap();
        mode.input_modes.remove(InputModes::ICRNL);
        mode.local_modes.remove(LocalModes::ICANON);
        // a read that returns at once with nothing (as a polling program leaves it): only line
        // mode makes the reader wait for the line
        mode.special_codes[rustix::termios::SpecialCodeIndex::VMIN] = 0;
        mode.special_codes[rustix::termios::SpecialCodeIndex::VTIME] = 0;
        tcsetattr(&terminal, OptionalActions::Now, &mode).unwrap();
        let watched = terminal.try_clone().unwrap();
        let rx = spawn_reader(terminal);
        wait_for_echo_off(&watched);
        controller.write_all(b"xyz\r").unwrap();
        assert_eq!(result(&rx).unwrap().as_str(), "xyz");
        let after = tcgetattr(&watched).unwrap();
        assert!(
            after.local_modes.contains(LocalModes::ECHO),
            "echo was not restored"
        );
        assert!(
            !after.local_modes.contains(LocalModes::ICANON),
            "the reader did not restore the mode it found"
        );
    }

    #[test]
    fn a_non_ascii_secret_is_read_as_typed() {
        let (mut controller, terminal) = pair();
        let watched = terminal.try_clone().unwrap();
        let rx = spawn_reader(terminal);
        wait_for_echo_off(&watched);
        controller.write_all("pässwörd 秘密\n".as_bytes()).unwrap();
        assert_eq!(result(&rx).unwrap().as_str(), "pässwörd 秘密");
    }

    #[test]
    fn a_line_that_is_not_utf8_is_refused_and_echo_is_restored() {
        let (mut controller, terminal) = pair();
        let watched = terminal.try_clone().unwrap();
        let rx = spawn_reader(terminal);
        wait_for_echo_off(&watched);
        controller.write_all(b"ab\xff\xfecd\n").unwrap();
        let r = result(&rx);
        assert!(matches!(r, Err(PromptError::NotUtf8)), "{r:?}");
        assert!(
            echo_on(&watched),
            "echo was not restored after a line that is not UTF-8"
        );
    }

    /// A prompt output that panics (after echo was turned off): the panic unwinds through the
    /// reader and the mode is restored on the way
    #[test]
    fn a_panic_inside_the_reader_restores_echo() {
        /// Panics on the prompt, after recording that echo was off at that moment
        struct Panics(OwnedFd, bool);
        impl Write for Panics {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                self.1 = !echo_on(&self.0);
                panic!("injected");
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let (_controller, terminal) = pair();
        assert!(echo_on(&terminal));
        let mut out = Panics(terminal.try_clone().unwrap(), false);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            read_secret_from(&terminal, &mut out, "> ")
        }));
        assert!(r.is_err(), "the injected panic did not happen");
        assert!(out.1, "echo was not off when the panic happened");
        assert!(echo_on(&terminal), "echo was not restored after a panic");
    }

    /// A terminal left ignoring carriage returns (IGNCR): the reader clears it,
    /// so Enter still ends the line, and the mode it found is the mode it leaves
    #[test]
    fn a_carriage_return_ends_the_line_when_the_terminal_ignores_it() {
        let (mut controller, terminal) = pair();
        let mut mode = tcgetattr(&terminal).unwrap();
        mode.input_modes.insert(InputModes::IGNCR);
        tcsetattr(&terminal, OptionalActions::Now, &mode).unwrap();
        let watched = terminal.try_clone().unwrap();
        let rx = spawn_reader(terminal);
        wait_for_echo_off(&watched);
        controller.write_all(b"igncr\r").unwrap();
        assert_eq!(result(&rx).unwrap().as_str(), "igncr");
        let after = tcgetattr(&watched).unwrap();
        assert!(
            after.local_modes.contains(LocalModes::ECHO),
            "echo was not restored"
        );
        assert!(
            after.input_modes.contains(InputModes::IGNCR),
            "the reader did not restore the mode it found"
        );
    }

    /// A terminal left turning line feeds into carriage returns (INLCR): the
    /// reader clears it, so a line feed still ends the line, and the mode it found
    /// is the mode it leaves
    #[test]
    fn a_line_feed_ends_the_line_when_the_terminal_turns_it_into_a_carriage_return() {
        let (mut controller, terminal) = pair();
        let mut mode = tcgetattr(&terminal).unwrap();
        mode.input_modes.insert(InputModes::INLCR);
        tcsetattr(&terminal, OptionalActions::Now, &mode).unwrap();
        let watched = terminal.try_clone().unwrap();
        let rx = spawn_reader(terminal);
        wait_for_echo_off(&watched);
        controller.write_all(b"inlcr\n").unwrap();
        assert_eq!(result(&rx).unwrap().as_str(), "inlcr");
        let after = tcgetattr(&watched).unwrap();
        assert!(
            after.local_modes.contains(LocalModes::ECHO),
            "echo was not restored"
        );
        assert!(
            after.input_modes.contains(InputModes::INLCR),
            "the reader did not restore the mode it found"
        );
    }
}
