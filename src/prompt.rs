//! Reading a secret from a terminal without echoing it
//!
//! [`read_secret`] writes a prompt to standard error and reads one line from
//! standard input with the terminal's echo turned off. While it reads, the
//! terminal is in line mode with Enter ending the line: on unix canonical mode
//! with a carriage return translated to a line feed (`ICANON`, `ICRNL`, and
//! `INLCR` / `IGNCR` cleared), on Windows line and processed input. Either a
//! line feed or a carriage return ends the line, so a terminal left in another
//! mode by a previous program does not keep the read waiting.
//!
//! The terminal's previous mode is restored when the call returns a line, returns
//! an error, or unwinds from a panic (a guard restores it when dropped). It is
//! **not** restored when the process ends without unwinding while the prompt is
//! waiting: the default action of `SIGINT` / Ctrl-C (and other signals that end
//! the process), a console control handler that ends it, `panic = "abort"`, or
//! `std::process::exit`. The terminal is then left without echo; `stty sane` (or
//! `stty echo`) restores a unix terminal, and closing the console window restores
//! a Windows console.
//!
//! Standard input that is not a terminal (a pipe, a file, no console) is
//! refused with [`PromptError::NotATerminal`] before anything is written, so a
//! caller that also accepts the secret from somewhere else (an environment
//! variable) chooses that path deliberately instead of reading a pipe as if a
//! person had typed it.
//!
//! The line is read into one heap buffer of fixed size ([`MAX_SECRET_LEN`]
//! bytes) that is never grown or moved and is zeroed before the call returns or
//! unwinds; the returned value is the only other copy, and it is zeroed when
//! dropped. On Windows the console is read as UTF-16 (so text in any code page
//! arrives as typed) and converted to UTF-8 one unit at a time in fixed storage
//! that is zeroed as it is consumed; an unpaired surrogate is refused as
//! [`PromptError::NotUtf8`]. A Windows console in line mode does not report the
//! end of input for Ctrl-Z: it arrives as the byte `0x1A` within the line, so
//! [`PromptError::Closed`] is in practice not returned there (Ctrl-C ends the
//! process as described above).
//!
//! ```no_run
//! let secret = alice_os_keystore::prompt::read_secret("Passphrase: ")?;
//! assert!(!secret.is_empty());
//! # Ok::<(), alice_os_keystore::prompt::PromptError>(())
//! ```

use std::fmt;
use std::io::Write;

use zeroize::Zeroizing;

use crate::sys;

mod line;
#[cfg(test)]
mod tests;
#[cfg(any(windows, test))]
pub(crate) mod utf16;

/// The longest secret [`read_secret`] accepts, in bytes (a longer line is
/// refused with [`PromptError::TooLong`]).
pub const MAX_SECRET_LEN: usize = 512;

/// Why a secret could not be read
#[derive(Debug)]
#[non_exhaustive]
pub enum PromptError {
    /// The input is not a terminal (nothing was written or read)
    NotATerminal,
    /// The line was empty
    Empty,
    /// The line was longer than [`MAX_SECRET_LEN`] bytes (the whole line was
    /// consumed and discarded)
    TooLong,
    /// The input ended before a line was complete
    Closed,
    /// The line is not UTF-8
    NotUtf8,
    /// Reading the input, writing the prompt, or changing the terminal's mode failed
    Io(std::io::Error),
}

impl fmt::Display for PromptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotATerminal => write!(f, "the input is not a terminal"),
            Self::Empty => write!(f, "the input was empty"),
            Self::TooLong => write!(f, "the input was longer than {MAX_SECRET_LEN} bytes"),
            Self::Closed => write!(f, "the input ended before a line was complete"),
            Self::NotUtf8 => write!(f, "the input is not UTF-8"),
            Self::Io(e) => write!(f, "terminal input failed: {e}"),
        }
    }
}

impl std::error::Error for PromptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for PromptError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// An input [`read_secret_from`] can read: a file descriptor on unix, a
/// handle on Windows (standard input, a terminal device, an open file).
#[cfg(unix)]
pub trait Input: std::os::fd::AsFd {}
#[cfg(unix)]
impl<T: std::os::fd::AsFd + ?Sized> Input for T {}

/// An input [`read_secret_from`] can read: a file descriptor on unix, a
/// handle on Windows (standard input, a console, an open file).
#[cfg(windows)]
pub trait Input: std::os::windows::io::AsHandle {}
#[cfg(windows)]
impl<T: std::os::windows::io::AsHandle + ?Sized> Input for T {}

/// Writes `prompt` to standard error and reads one line from standard input
/// without echoing it.
///
/// # Errors
///
/// [`PromptError::NotATerminal`] when standard input is not a terminal, and
/// the other [`PromptError`] variants as described there.
pub fn read_secret(prompt: &str) -> Result<Zeroizing<String>, PromptError> {
    let stdin = std::io::stdin();
    read_secret_from(&stdin, &mut std::io::stderr(), prompt)
}

/// [`read_secret`] with an explicit input and prompt output.
///
/// # Errors
///
/// As [`read_secret`], for `input`.
pub fn read_secret_from<I: Input + ?Sized>(
    input: &I,
    out: &mut dyn Write,
    prompt: &str,
) -> Result<Zeroizing<String>, PromptError> {
    let mut guard = sys::NoEcho::begin(input)?;
    out.write_all(prompt.as_bytes())?;
    out.flush()?;

    let mut buf = line::line_buf();
    let read = line::collect_line(&mut buf, || guard.next_byte());
    drop(guard);
    // a console with echo off does not show the Enter key (on unix the terminal echoes the
    // newline itself, ECHONL): move past the prompt
    #[cfg(windows)]
    {
        out.write_all(b"\n")?;
        out.flush()?;
    }
    read
}
