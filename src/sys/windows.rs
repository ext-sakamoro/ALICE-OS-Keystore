//! Console echo control on Windows (console mode)

use std::os::windows::io::{AsRawHandle, BorrowedHandle};

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use windows_sys::Win32::System::Console::{
    GetConsoleMode, SetConsoleMode, CONSOLE_MODE, ENABLE_ECHO_INPUT,
};

use crate::prompt::{Input, PromptError};

/// Echo turned off on a console until dropped (the previous mode is restored)
pub(crate) struct NoEcho<'a> {
    handle: BorrowedHandle<'a>,
    saved: CONSOLE_MODE,
}

fn raw(handle: BorrowedHandle<'_>) -> HANDLE {
    handle.as_raw_handle().cast()
}

impl<'a> NoEcho<'a> {
    pub(crate) fn begin<I: Input + ?Sized>(input: &'a I) -> Result<Self, PromptError> {
        let handle = input.as_handle();
        let mut saved: CONSOLE_MODE = 0;
        // SAFETY: `handle` is a handle borrowed for 'a (open for the call) and
        // `saved` is a valid, writable CONSOLE_MODE for the out pointer.
        // GetConsoleMode fails (returns 0) on a handle that is not a console.
        if unsafe { GetConsoleMode(raw(handle), &raw mut saved) } == 0 {
            return Err(PromptError::NotATerminal);
        }
        // SAFETY: the same borrowed console handle; the mode is a plain value.
        if unsafe { SetConsoleMode(raw(handle), saved & !ENABLE_ECHO_INPUT) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self { handle, saved })
    }

    /// Reads into `buf`
    pub(crate) fn read(&self, buf: &mut [u8]) -> Result<usize, PromptError> {
        let len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let mut read: u32 = 0;
        // SAFETY: the borrowed console handle is open; `buf` is valid for writes
        // of `len` bytes and `read` for the count; no OVERLAPPED (synchronous read).
        let ok = unsafe {
            ReadFile(
                raw(self.handle),
                buf.as_mut_ptr(),
                len,
                &raw mut read,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(read as usize)
    }
}

impl Drop for NoEcho<'_> {
    fn drop(&mut self) {
        // SAFETY: the same borrowed console handle; restoring the saved mode.
        // Nothing more can be done when restoring fails while dropping.
        let _ = unsafe { SetConsoleMode(raw(self.handle), self.saved) };
    }
}
