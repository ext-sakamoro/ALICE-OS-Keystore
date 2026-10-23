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
    use rustix::termios::{tcgetattr, LocalModes};
    use std::io::Write;
    use std::os::fd::OwnedFd;
    use std::time::{Duration, Instant};

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
    fn a_closed_terminal_is_an_error_and_echo_is_restored() {
        // the controller goes away before a line arrives: the read ends without a newline
        let (controller, terminal) = pair();
        let watched = terminal.try_clone().unwrap();
        let reader = std::thread::spawn(move || read_secret_from(&terminal, &mut Vec::new(), "> "));
        wait_for_echo_off(&watched);
        drop(controller);
        let r = reader.join().unwrap();
        assert!(
            matches!(r, Err(PromptError::Io(_) | PromptError::Closed)),
            "{r:?}"
        );
        assert!(echo_on(&watched), "echo was not restored after an error");
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
}
