//! Terminal echo control on unix (safe termios API, no `unsafe`)

use std::os::fd::BorrowedFd;

use rustix::termios::{isatty, tcgetattr, tcsetattr, LocalModes, OptionalActions, Termios};

use crate::prompt::{Input, PromptError};

/// Echo turned off on a terminal until dropped (the previous mode is restored)
pub(crate) struct NoEcho<'a> {
    fd: BorrowedFd<'a>,
    saved: Termios,
}

impl<'a> NoEcho<'a> {
    pub(crate) fn begin<I: Input + ?Sized>(input: &'a I) -> Result<Self, PromptError> {
        let fd = input.as_fd();
        if !isatty(fd) {
            return Err(PromptError::NotATerminal);
        }
        let saved = tcgetattr(fd).map_err(std::io::Error::from)?;
        let mut quiet = saved.clone();
        quiet
            .local_modes
            .remove(LocalModes::ECHO | LocalModes::ECHOE | LocalModes::ECHOK);
        // the newline still shows, so the cursor moves past the prompt
        quiet.local_modes.insert(LocalModes::ECHONL);
        tcsetattr(fd, OptionalActions::Now, &quiet).map_err(std::io::Error::from)?;
        Ok(Self { fd, saved })
    }

    /// Reads into `buf`, retrying an interrupted read
    pub(crate) fn read(&self, buf: &mut [u8]) -> Result<usize, PromptError> {
        loop {
            match rustix::io::read(self.fd, &mut *buf) {
                Ok(n) => return Ok(n),
                Err(rustix::io::Errno::INTR) => {}
                Err(e) => return Err(std::io::Error::from(e).into()),
            }
        }
    }
}

impl Drop for NoEcho<'_> {
    fn drop(&mut self) {
        // nothing more can be done when restoring fails while dropping
        let _ = tcsetattr(self.fd, OptionalActions::Now, &self.saved);
    }
}
