//! Console echo control and UTF-16 console input on Windows (console mode)

use std::os::windows::io::{AsRawHandle, BorrowedHandle};

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Console::{
    GetConsoleMode, ReadConsoleW, SetConsoleMode, CONSOLE_MODE, ENABLE_ECHO_INPUT,
    ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
};
use zeroize::Zeroize;

use crate::prompt::utf16::Utf16Bytes;
use crate::prompt::{Input, PromptError};

/// Echo turned off on a console until dropped (the previous mode is restored)
pub(crate) struct NoEcho<'a> {
    handle: BorrowedHandle<'a>,
    saved: CONSOLE_MODE,
    /// Decoded bytes not taken yet (on the heap, so the guard's moves copy no input)
    decoded: Box<Utf16Bytes>,
}

fn raw(handle: BorrowedHandle<'_>) -> HANDLE {
    handle.as_raw_handle().cast()
}

const CR: u16 = 0x0D;

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
        // line input with Enter ending the line, whatever mode the console was left in
        // (echo input needs line input), and no echo
        let quiet = (saved | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT) & !ENABLE_ECHO_INPUT;
        // SAFETY: the same borrowed console handle; the mode is a plain value.
        if unsafe { SetConsoleMode(raw(handle), quiet) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self {
            handle,
            saved,
            decoded: Box::default(),
        })
    }

    /// One UTF-16 unit from the console (`None` when nothing was read)
    fn read_unit(&self) -> Result<Option<u16>, PromptError> {
        let mut unit = [0u16; 1];
        let mut read: u32 = 0;
        // SAFETY: the borrowed console handle is open; `unit` is valid for writes of one
        // UTF-16 unit (the count is in units) and `read` for the count; no input control.
        let ok = unsafe {
            ReadConsoleW(
                raw(self.handle),
                unit.as_mut_ptr().cast(),
                1,
                &raw mut read,
                std::ptr::null(),
            )
        };
        let value = unit[0];
        unit.zeroize();
        if ok == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok((read == 1).then_some(value))
    }

    /// The next byte of the input as UTF-8 (`None` at its end)
    pub(crate) fn next_byte(&mut self) -> Result<Option<u8>, PromptError> {
        loop {
            if let Some(b) = self.decoded.next_byte() {
                return Ok(Some(b));
            }
            let Some(mut unit) = self.read_unit()? else {
                return Ok(None);
            };
            if unit == CR {
                // line input ends a line with CR LF: take the LF now, so it is not left
                // for the next read (it is already in the console's line)
                if let Some(mut lf) = self.read_unit()? {
                    lf.zeroize();
                }
            }
            self.decoded.feed(unit);
            unit.zeroize();
        }
    }
}

impl Drop for NoEcho<'_> {
    fn drop(&mut self) {
        // SAFETY: the same borrowed console handle; restoring the saved mode.
        // Nothing more can be done when restoring fails while dropping.
        let _ = unsafe { SetConsoleMode(raw(self.handle), self.saved) };
    }
}
