//! Swapping two directories in one step
//!
//! An application that replaces a directory holding its keys and data (restoring
//! a backup) needs the replacement to be all or nothing: if the process stops
//! halfway, the directory must be either the old one or the new one, never a mix.
//! [`exchange`] swaps two paths in one atomic step where the operating system
//! offers it (Linux `renameat2` with `RENAME_EXCHANGE`, Apple `renameatx_np` with
//! `RENAME_SWAP`, through `rustix`'s safe API). Elsewhere it returns
//! [`ExchangeError::Unsupported`] without touching anything, so the caller
//! chooses a fallback it can recover from (for example a marker file and two
//! renames).
//!
//! The swap itself does not make the new names durable: after a successful call,
//! sync the parent directory if a crash right afterwards must not undo it.

use std::fmt;
use std::path::Path;

/// Why [`exchange`] did not swap the paths
#[derive(Debug)]
#[non_exhaustive]
pub enum ExchangeError {
    /// This platform has no atomic exchange (nothing was changed)
    Unsupported,
    /// The swap failed (a path does not exist, the paths are on different file
    /// systems, permission is denied …); nothing was changed
    Io(std::io::Error),
}

impl fmt::Display for ExchangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(f, "this platform cannot swap two paths atomically"),
            Self::Io(e) => write!(f, "swapping the paths failed: {e}"),
        }
    }
}

impl std::error::Error for ExchangeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Unsupported => None,
        }
    }
}

/// Swaps the paths `a` and `b` (both must exist) in one atomic step.
///
/// # Errors
///
/// [`ExchangeError::Unsupported`] on a platform without an atomic exchange,
/// [`ExchangeError::Io`] when the swap fails. In both cases nothing changed.
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
pub fn exchange(a: impl AsRef<Path>, b: impl AsRef<Path>) -> Result<(), ExchangeError> {
    use rustix::fs::{renameat_with, RenameFlags, CWD};
    renameat_with(CWD, a.as_ref(), CWD, b.as_ref(), RenameFlags::EXCHANGE)
        .map_err(|e| ExchangeError::Io(e.into()))
}

/// Swaps the paths `a` and `b` (both must exist) in one atomic step.
///
/// # Errors
///
/// Always [`ExchangeError::Unsupported`] on this platform (nothing is changed).
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
pub fn exchange(a: impl AsRef<Path>, b: impl AsRef<Path>) -> Result<(), ExchangeError> {
    let _ = (a.as_ref(), b.as_ref());
    Err(ExchangeError::Unsupported)
}
