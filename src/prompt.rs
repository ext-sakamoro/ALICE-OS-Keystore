//! Reading a secret from a terminal without echoing it
//!
//! [`read_secret`] writes a prompt to standard error and reads one line from
//! standard input with the terminal's echo turned off. The terminal's previous
//! mode is restored on every way out of the call: a line read, an error, or a
//! panic (a guard restores it when dropped).
//!
//! Standard input that is not a terminal (a pipe, a file, no console) is
//! refused with [`PromptError::NotATerminal`] before anything is written, so a
//! caller that also accepts the secret from somewhere else (an environment
//! variable) chooses that path deliberately instead of reading a pipe as if a
//! person had typed it.
//!
//! The line is read into a buffer of fixed capacity ([`MAX_SECRET_LEN`]) that
//! never grows, so no reallocation leaves a copy of the secret behind, and the
//! returned value is zeroed when dropped.
//!
//! ```no_run
//! let secret = alice_os_keystore::prompt::read_secret("Passphrase: ")?;
//! assert!(!secret.is_empty());
//! # Ok::<(), alice_os_keystore::prompt::PromptError>(())
//! ```

use std::fmt;
use std::io::Write;

use zeroize::{Zeroize, Zeroizing};

use crate::sys;

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
    let guard = sys::NoEcho::begin(input)?;
    out.write_all(prompt.as_bytes())?;
    out.flush()?;

    let mut line = Zeroizing::new(Vec::<u8>::with_capacity(MAX_SECRET_LEN));
    let mut too_long = false;
    loop {
        let mut byte = [0u8; 1];
        if guard.read(&mut byte)? == 0 {
            return Err(PromptError::Closed);
        }
        match byte[0] {
            b'\n' => break,
            b'\r' => {}
            b if line.len() < MAX_SECRET_LEN => line.push(b),
            _ => too_long = true,
        }
        byte.zeroize();
    }
    drop(guard);
    // a console with echo off does not show the Enter key (on unix the terminal echoes the
    // newline itself, ECHONL): move past the prompt
    #[cfg(windows)]
    {
        out.write_all(b"\n")?;
        out.flush()?;
    }

    if too_long {
        return Err(PromptError::TooLong);
    }
    if line.is_empty() {
        return Err(PromptError::Empty);
    }
    match String::from_utf8(std::mem::take(&mut *line)) {
        Ok(s) => Ok(Zeroizing::new(s)),
        Err(e) => {
            e.into_bytes().zeroize();
            Err(PromptError::NotUtf8)
        }
    }
}
