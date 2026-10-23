//! Console input (UTF-16 units) to UTF-8 bytes, one unit at a time, in fixed
//! storage that is zeroed as it is consumed and when dropped

use zeroize::Zeroize;

/// A byte that never occurs in UTF-8: an unpaired surrogate becomes this byte,
/// so the line is refused as not UTF-8 instead of being changed
pub(crate) const INVALID: u8 = 0xFF;

/// The bytes of the units given so far that have not been taken
#[derive(Default)]
pub(crate) struct Utf16Bytes {
    /// A high surrogate waiting for its low half (0 when none; 0 is not a surrogate)
    high: u16,
    out: [u8; 8],
    len: u8,
    pos: u8,
}

impl Utf16Bytes {
    /// Takes one unit. Call it only when [`Self::next_byte`] has returned `None`.
    pub(crate) fn feed(&mut self, unit: u16) {
        debug_assert_eq!(self.len, 0, "a unit fed with bytes not taken");
        if self.high != 0 {
            let high = core::mem::take(&mut self.high);
            if (0xDC00..0xE000).contains(&unit) {
                let scalar =
                    0x1_0000 + ((u32::from(high) - 0xD800) << 10) + (u32::from(unit) - 0xDC00);
                self.emit_scalar(scalar);
                return;
            }
            self.emit(INVALID);
        }
        match unit {
            0xD800..=0xDBFF => self.high = unit,
            0xDC00..=0xDFFF => self.emit(INVALID),
            other => self.emit_scalar(u32::from(other)),
        }
    }

    /// The next byte, zeroing its place
    pub(crate) fn next_byte(&mut self) -> Option<u8> {
        if self.pos == self.len {
            return None;
        }
        let at = usize::from(self.pos);
        let byte = self.out[at];
        self.out[at] = 0;
        self.pos += 1;
        if self.pos == self.len {
            self.pos = 0;
            self.len = 0;
        }
        Some(byte)
    }

    fn emit(&mut self, byte: u8) {
        self.out[usize::from(self.len)] = byte;
        self.len += 1;
    }

    fn emit_scalar(&mut self, scalar: u32) {
        let Some(c) = char::from_u32(scalar) else {
            // not reached: surrogates are handled before, and a pair is always a scalar value
            self.emit(INVALID);
            return;
        };
        let mut bytes = [0u8; 4];
        for &b in c.encode_utf8(&mut bytes).as_bytes() {
            self.emit(b);
        }
        bytes.zeroize();
    }

    /// Nothing is held: no waiting half, no bytes
    #[cfg(test)]
    pub(crate) fn is_clear(&self) -> bool {
        self.high == 0 && self.len == 0 && self.pos == 0 && self.out.iter().all(|&b| b == 0)
    }
}

impl Drop for Utf16Bytes {
    fn drop(&mut self) {
        self.high.zeroize();
        self.out.zeroize();
        self.len = 0;
        self.pos = 0;
    }
}
