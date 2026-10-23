//! Windows DPAPI store
//!
//! Each generation is one file `gen-<n>.dpapi` (decimal, no leading zero) in the store's
//! directory, by default `%LOCALAPPDATA%\<service>`: the 32 key bytes sealed with DPAPI for
//! the current user (`CryptProtectData`, no UI). The sealing is bound to the directory's
//! own name (DPAPI's optional entropy), so a file copied into another store's directory
//! does not open there. A file is written to a temporary name first and then hard-linked
//! to its final name, which fails when that name exists: the item appears complete or not
//! at all, and two processes creating the same generation cannot both succeed. For every
//! generation issued an empty marker file `issued-<n>` is created (create-only) after the key
//! file (see the generation model in `desktop`).
//!
//! DPAPI ties the files to the Windows user (and, for a local account, its password): a
//! file does not open for another user, and an administrator resetting the user's password
//! makes it unreadable; that is reported as [`KeyProviderError::Irrecoverable`]. The
//! plaintext DPAPI returns is zeroed before it is freed, and the copy read into the
//! [`Key`] is zeroed with it on drop.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use zeroize::Zeroize;

use super::{by_generation_of, current_of, generation_of, rotate_of, GenerationItems, Inventory};
use crate::sys::dpapi;
use crate::{Key, KeyGeneration, KeyProvider, KeyProviderError};

const SUFFIX: &str = ".dpapi";
const MARKER_PREFIX: &str = "issued-";
const ENTROPY_PREFIX: &[u8] = b"alice-os-keystore/dpapi/v1\0";

/// Keys kept as DPAPI-sealed files of the current Windows user, one file per generation
pub struct WindowsDpapiStore {
    dir: PathBuf,
    entropy: Vec<u8>,
}

/// A name usable as one directory name on Windows: not empty, not `.` / `..`, no path
/// separator, drive colon, wildcard, quote, pipe or control character, no trailing dot
/// or space, and not a reserved device name (`CON`, `NUL`, `COM1`, ...)
fn plain_directory_name(name: &str) -> bool {
    if name.is_empty() || name == "." || name == ".." || name.ends_with(['.', ' ']) {
        return false;
    }
    if name.chars().any(|c| {
        c.is_control() || matches!(c, '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
    }) {
        return false;
    }
    let stem = name.split('.').next().unwrap_or(name).to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit());
    !reserved
}

fn file_name(generation: KeyGeneration) -> String {
    format!("gen-{generation}{SUFFIX}")
}

impl WindowsDpapiStore {
    /// A store for the keys of `service` in `%LOCALAPPDATA%\<service>` (a name only this
    /// application uses)
    ///
    /// Nothing is read or created until the first call. `None` when `service` is not one
    /// plain directory name, or when `LOCALAPPDATA` is not set.
    #[must_use]
    pub fn new(service: &str) -> Option<Self> {
        if !plain_directory_name(service) {
            return None;
        }
        let local = std::env::var_os("LOCALAPPDATA")?;
        Some(Self::in_dir(Path::new(&local).join(service)))
    }

    /// A store whose files live in `dir` (created on first use); the sealing is bound to
    /// the last component of `dir`
    #[must_use]
    pub fn in_dir(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        let mut entropy = ENTROPY_PREFIX.to_vec();
        if let Some(name) = dir.file_name() {
            entropy.extend_from_slice(name.to_string_lossy().as_bytes());
        }
        Self { dir, entropy }
    }

    /// The directory holding the files
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Add a fresh random key as the next generation (1 when the directory holds none)
    /// and return it; the older files stay
    ///
    /// # Errors
    /// [`KeyProviderError::Unavailable`] when the directory cannot be written, DPAPI
    /// refuses to seal, the entropy source fails, the generation counter would overflow,
    /// or other processes keep adding generations faster than this call can claim one
    pub fn rotate(&self) -> Result<KeyGeneration, KeyProviderError> {
        rotate_of(self)
    }

    fn temp_path(&self, generation: KeyGeneration) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        self.dir
            .join(format!("gen-{generation}.{}.{n}.tmp", std::process::id()))
    }
}

impl GenerationItems for WindowsDpapiStore {
    fn inventory(&self) -> Result<Inventory, KeyProviderError> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Inventory::default()),
            Err(_) => {
                return Err(KeyProviderError::Unavailable(
                    "the key directory cannot be read",
                ))
            }
        };
        let mut inv = Inventory::default();
        for entry in entries {
            let entry = entry
                .map_err(|_| KeyProviderError::Unavailable("the key directory cannot be read"))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if let Some(g) = generation_of(name, "gen-", SUFFIX) {
                inv.keys.insert(g);
            } else if let Some(g) = generation_of(name, MARKER_PREFIX, "") {
                inv.issued.insert(g);
            }
        }
        Ok(inv)
    }

    fn read(&self, generation: KeyGeneration) -> Result<Option<Key>, KeyProviderError> {
        let sealed = match std::fs::read(self.dir.join(file_name(generation))) {
            Ok(sealed) => sealed,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(KeyProviderError::Unavailable("the key file cannot be read")),
        };
        let mut plain = dpapi::unprotect(&sealed, &self.entropy).map_err(|_| {
            KeyProviderError::Irrecoverable("the key file does not open for this user")
        })?;
        let key = Key::from_slice(&plain).map_err(|_| {
            KeyProviderError::Irrecoverable("the key file does not hold a 32-byte key")
        });
        plain.zeroize();
        key.map(Some)
    }

    fn create(&self, generation: KeyGeneration, key: &Key) -> Result<bool, KeyProviderError> {
        std::fs::create_dir_all(&self.dir)
            .map_err(|_| KeyProviderError::Unavailable("the key directory cannot be created"))?;
        let sealed = dpapi::protect(key.as_bytes(), &self.entropy)
            .map_err(|_| KeyProviderError::Unavailable("DPAPI refused to seal the key"))?;
        let temp = self.temp_path(generation);
        let written = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .and_then(|mut f| {
                f.write_all(&sealed)?;
                f.sync_all()
            });
        let linked =
            written.and_then(|()| std::fs::hard_link(&temp, self.dir.join(file_name(generation))));
        // the temporary name is not a generation (another suffix), so a leftover is ignored
        let _ = std::fs::remove_file(&temp);
        match linked {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(_) => Err(KeyProviderError::Unavailable(
                "the key file cannot be written",
            )),
        }
    }
    fn mark(&self, generation: KeyGeneration) -> Result<(), KeyProviderError> {
        std::fs::create_dir_all(&self.dir)
            .map_err(|_| KeyProviderError::Unavailable("the key directory cannot be created"))?;
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.dir.join(format!("{MARKER_PREFIX}{generation}")))
        {
            Ok(f) => f
                .sync_all()
                .map_err(|_| KeyProviderError::Unavailable("the marker file cannot be written")),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(_) => Err(KeyProviderError::Unavailable(
                "the marker file cannot be written",
            )),
        }
    }
}

impl KeyProvider for WindowsDpapiStore {
    /// The highest generation, creating generation 1 when the directory holds none
    fn current(&self) -> Result<(KeyGeneration, Key), KeyProviderError> {
        current_of(self)
    }

    fn by_generation(&self, generation: KeyGeneration) -> Result<Key, KeyProviderError> {
        by_generation_of(self, generation)
    }
}

#[cfg(test)]
mod tests {
    use super::plain_directory_name;

    #[test]
    fn plain_directory_names() {
        for good in ["com.example.app", "app", "a b", "COM10", "console", "lpt"] {
            assert!(plain_directory_name(good), "{good:?}");
        }
        for bad in [
            "", ".", "..", "a\\b", "a/b", "C:x", "a*", "a?", "a\"", "a<", "a>", "a|", "a\0", "a\n",
            "trail.", "trail ", "CON", "con", "nul.txt", "COM1", "lpt9",
        ] {
            assert!(!plain_directory_name(bad), "{bad:?}");
        }
    }
}
