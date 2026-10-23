//! Collecting one line into the fixed line buffer

use zeroize::{Zeroize, Zeroizing};

use super::{PromptError, MAX_SECRET_LEN};

/// The line buffer: allocated once on the heap, never grown or moved, zeroed when dropped
pub(crate) type LineBuf = Box<Zeroizing<[u8; MAX_SECRET_LEN]>>;

pub(crate) fn line_buf() -> LineBuf {
    Box::new(Zeroizing::new([0; MAX_SECRET_LEN]))
}

/// Zeroes the borrowed buffer when dropped, so every way out of [`collect_line`]
/// (a result, an error, a panic in `next`) leaves it zero
struct Wipe<'a>(&'a mut [u8; MAX_SECRET_LEN]);

impl Drop for Wipe<'_> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Reads bytes from `next` (`None` is the end of the input) into `buf` up to a
/// line feed or a carriage return. A line longer than the buffer is consumed to
/// its end and refused. `buf` is zero again when this returns or unwinds; the
/// returned `String` is the only other copy of the line.
pub(crate) fn collect_line(
    buf: &mut [u8; MAX_SECRET_LEN],
    mut next: impl FnMut() -> Result<Option<u8>, PromptError>,
) -> Result<Zeroizing<String>, PromptError> {
    let line = Wipe(buf);
    let mut len = 0;
    let mut too_long = false;
    loop {
        let Some(mut byte) = next()? else {
            return Err(PromptError::Closed);
        };
        match byte {
            b'\n' | b'\r' => break,
            b if len < MAX_SECRET_LEN => {
                line.0[len] = b;
                len += 1;
            }
            _ => too_long = true,
        }
        byte.zeroize();
    }
    if too_long {
        return Err(PromptError::TooLong);
    }
    if len == 0 {
        return Err(PromptError::Empty);
    }
    match core::str::from_utf8(&line.0[..len]) {
        Ok(s) => Ok(Zeroizing::new(s.to_owned())),
        Err(_) => Err(PromptError::NotUtf8),
    }
}
