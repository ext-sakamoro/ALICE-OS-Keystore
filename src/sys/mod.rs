//! Operating system calls
//!
//! This is the only module of the crate allowed to contain `unsafe` code
//! (`scripts/unsafe_scope_check.py` enforces it): each `unsafe` block carries a
//! `SAFETY:` note stating why the call is sound. The desktop key stores (Keychain,
//! DPAPI / CNG, Secret Service) go here as well when they are implemented.
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

/// Test-only allocator for observing what a `Drop` leaves in a freed block
#[cfg(test)]
pub(crate) mod watch_alloc;
