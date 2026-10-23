//! Operating system calls
//!
//! This is the only module of the crate allowed to contain `unsafe` code
//! (`scripts/unsafe_scope_check.py` enforces it): each `unsafe` block carries a
//! `SAFETY:` note stating why the call is sound. Today: the Windows console mode
//! and DPAPI (the Windows key store). The macOS Keychain is reached through the
//! `security-framework` crate and needs nothing here.
//!
//! On unix the terminal is controlled through `rustix`'s safe termios API, so the
//! unix code has no `unsafe` blocks.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub(crate) use unix::NoEcho;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::NoEcho;

#[cfg(windows)]
pub(crate) mod dpapi;

/// Test-only allocator for observing what a `Drop` leaves in a freed block
#[cfg(test)]
pub(crate) mod watch_alloc;
