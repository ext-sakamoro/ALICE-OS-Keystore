//! DPAPI (`CryptProtectData` / `CryptUnprotectData`) for the current user

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};
use zeroize::Zeroize;

/// Why DPAPI did not seal or open the data (the operating system's code is not kept)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DpapiError {
    /// The input is larger than DPAPI takes (`u32::MAX` bytes)
    TooLarge,
    /// DPAPI refused (for unprotect: the blob is damaged, sealed by another user or
    /// with other entropy)
    Refused,
}

fn blob(data: &[u8]) -> Result<CRYPT_INTEGER_BLOB, DpapiError> {
    Ok(CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len()).map_err(|_| DpapiError::TooLarge)?,
        // DPAPI only reads the input blobs
        pbData: data.as_ptr().cast_mut(),
    })
}

/// Copy DPAPI's output out, optionally zeroing it, and free it with `LocalFree`
fn take(out: &mut CRYPT_INTEGER_BLOB, zero: bool) -> Vec<u8> {
    if out.pbData.is_null() {
        return Vec::new();
    }
    let len = out.cbData as usize;
    // SAFETY: on success DPAPI sets `pbData` to a LocalAlloc'd block of `cbData` bytes that
    // this process owns until it calls LocalFree; nothing else aliases it.
    let data = unsafe { std::slice::from_raw_parts_mut(out.pbData, len) };
    let copy = data.to_vec();
    if zero {
        data.zeroize();
    }
    // SAFETY: `pbData` came from DPAPI's LocalAlloc and is freed exactly once here; it is
    // set to null right after so it cannot be used again.
    unsafe { LocalFree(out.pbData.cast()) };
    out.pbData = std::ptr::null_mut();
    copy
}

/// Seal `data` for the current user, bound to `entropy` (needed again to open it)
pub(crate) fn protect(data: &[u8], entropy: &[u8]) -> Result<Vec<u8>, DpapiError> {
    let input = blob(data)?;
    let extra = blob(entropy)?;
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: `input` and `extra` point at live slices of the stated lengths for the
    // duration of the call; the description, reserved and prompt pointers are null (all
    // optional); `out` is a valid out pointer DPAPI fills with a LocalAlloc'd block.
    let ok = unsafe {
        CryptProtectData(
            &raw const input,
            std::ptr::null(),
            &raw const extra,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut out,
        )
    };
    if ok == 0 {
        return Err(DpapiError::Refused);
    }
    Ok(take(&mut out, false))
}

/// Open a blob sealed by [`protect`] for the current user with the same `entropy`
///
/// The plaintext DPAPI returns is zeroed before its block is freed; the returned copy is
/// the caller's to zero.
pub(crate) fn unprotect(sealed: &[u8], entropy: &[u8]) -> Result<Vec<u8>, DpapiError> {
    let input = blob(sealed)?;
    let extra = blob(entropy)?;
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: as in `protect`; the description out pointer is null, so DPAPI allocates no
    // description string.
    let ok = unsafe {
        CryptUnprotectData(
            &raw const input,
            std::ptr::null_mut(),
            &raw const extra,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut out,
        )
    };
    if ok == 0 {
        return Err(DpapiError::Refused);
    }
    Ok(take(&mut out, true))
}
