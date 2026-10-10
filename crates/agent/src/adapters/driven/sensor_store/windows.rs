//! Real sensor store (feature `driver`): per-boot randomized directory with a
//! restrictive DACL (SYSTEM + Administrators only) under
//! `%ProgramData%\SecOutfall\sensors`, the sensor DLL copied under a random
//! name, and the copy hash-pinned to the source before injection is armed.
//!
//! Hygiene: sibling boot directories from previous boots are pruned
//! (best-effort) so yesterday's sensor bytes never linger readable on disk.

use std::{
    fs,
    path::{
        Path,
        PathBuf,
    },
};

use windows::{
    Win32::{
        Foundation::{
            ERROR_ALREADY_EXISTS,
            HANDLE,
            HLOCAL,
            LocalFree,
        },
        Security::{
            PSECURITY_DESCRIPTOR,
            SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::CreateDirectoryW,
    },
    core::PCWSTR,
};

use crate::ports::driven::sensor_store::{
    MaterializedSensor,
    SensorStoreError,
    SensorStorePort,
};

/// Every directory this store creates gets SYSTEM + Administrators + the
/// creating token's user, with inheritance blocked (the `P`). Production
/// creator is the `LocalSystem` service (the extra user ACE is then just
/// SYSTEM again); a lab console run grants its own operator — the analyzed
/// process (a DIFFERENT user in the VM) stays out either way.
const STORE_SDDL_BASE: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// The SDDL actually applied: base + the current token user's ACE when that
/// SID resolves (the token query can only fail to deny — we then keep the
/// strict base).
fn store_sddl() -> String {
    match current_token_user_sid_blocking() {
        Some(sid) => format!("{STORE_SDDL_BASE}(A;OICI;FA;;;{sid})"),
        None => STORE_SDDL_BASE.to_owned(),
    }
}

/// The current process token user's SID string, or `None` on ANY FFI failure.
fn current_token_user_sid_blocking() -> Option<String> {
    use windows::Win32::{
        Foundation::{
            CloseHandle,
            HANDLE,
        },
        Security::TOKEN_QUERY,
        System::Threading::{
            GetCurrentProcess,
            OpenProcessToken,
        },
    };

    let mut token = HANDLE::default();
    // SAFETY: out-handle initialized by the API; closed on every path.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) }.is_err() {
        return None;
    }
    let sid = current_token_user_sid_from(token);
    // SAFETY: owned handle, closed exactly once.
    let _ = unsafe { CloseHandle(token) };
    sid
}

// Token query + SID string for an already-open token handle.
fn current_token_user_sid_from(token: HANDLE) -> Option<String> {
    use windows::{
        Win32::{
            Foundation::{
                HLOCAL,
                LocalFree,
            },
            Security::{
                Authorization::ConvertSidToStringSidW,
                GetTokenInformation,
                TOKEN_USER,
                TokenUser,
            },
        },
        core::PWSTR,
    };

    let mut needed = 0_u32;
    // SAFETY: sizing call expects None and reports the needed length.
    let _ =
        unsafe { GetTokenInformation(token, TokenUser, None, 0, std::ptr::from_mut(&mut needed)) };
    if needed == 0 {
        return None;
    }
    let mut buffer = vec![0_u8; usize::try_from(needed).ok()?];
    // SAFETY: `buffer` is `needed` bytes; the class writes a TOKEN_USER.
    let filled = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            needed,
            std::ptr::from_mut(&mut needed),
        )
    };
    filled.ok()?;
    // SAFETY: the buffer holds a TOKEN_USER per the contract; read unaligned
    // because a Vec<u8> only guarantees 1-byte alignment.
    let token_user = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<TOKEN_USER>()) };
    let mut sid_string = PWSTR::null();
    // SAFETY: valid out-pointer; the returned string is freed below.
    unsafe { ConvertSidToStringSidW(token_user.User.Sid, std::ptr::from_mut(&mut sid_string)) }
        .ok()?;
    if sid_string.is_null() {
        return None;
    }
    // SAFETY: NUL-terminated wide string allocated by the call above.
    let sid = unsafe { sid_string.to_string() }.ok();
    // SAFETY: the string was allocated by ConvertSidToStringSidW.
    unsafe { LocalFree(HLOCAL(sid_string.0.cast())) };
    sid
}

/// Real store rooted at a base directory (production:
/// `%ProgramData%\SecOutfall\sensors`).
pub struct WindowsSensorStore {
    base: PathBuf,
}

impl WindowsSensorStore {
    /// Store at the production location.
    ///
    /// # Errors
    /// [`SensorStoreError::Security`] when `%ProgramData%` is not resolvable.
    pub fn new() -> Result<Self, SensorStoreError> {
        let program_data = std::env::var("ProgramData")
            .map_err(|_| SensorStoreError::Security("%ProgramData% not set".to_owned()))?;
        Ok(Self::with_base(Path::new(&program_data).join("SecOutfall").join("sensors")))
    }

    /// Store at an explicit base (tests).
    #[must_use]
    pub fn with_base(base: PathBuf) -> Self {
        Self { base }
    }

    /// Creates `path` (all missing levels) with the restrictive DACL.
    /// Existing directories are left untouched.
    fn create_protected_dir(path: &Path) -> Result<(), SensorStoreError> {
        use windows::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SDDL_REVISION_1,
        };

        // One descriptor conversion for the whole walk; freed on every exit.
        let sddl = store_sddl();
        let mut descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        // SAFETY: out-pointers initialized by the API on success.
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                &windows::core::HSTRING::from(sddl),
                SDDL_REVISION_1,
                &raw mut descriptor,
                None,
            )
        };
        if converted.is_err() || descriptor.0.is_null() {
            return Err(SensorStoreError::Security(format!("SDDL convert failed: {converted:?}")));
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
            lpSecurityDescriptor: descriptor.0.cast(),
            bInheritHandle: false.into(),
        };

        let mut current = PathBuf::new();
        for component in path.components() {
            current.push(component);
            if current.is_dir() {
                continue;
            }
            let wide = to_wide_nul(&current.to_string_lossy());
            // SAFETY: `wide` is NUL-terminated for the duration of the call;
            // `attributes` borrows the descriptor converted above.
            let created =
                unsafe { CreateDirectoryW(PCWSTR(wide.as_ptr()), Some(&raw const attributes)) };
            if created.is_err() {
                let error = windows::core::Error::from_win32();
                if error.code() != ERROR_ALREADY_EXISTS.to_hresult() {
                    // SAFETY: single free of the descriptor allocated above.
                    unsafe { LocalFree(HLOCAL(descriptor.0.cast())) };
                    return Err(SensorStoreError::Security(format!(
                        "create dir {}: {error}",
                        current.display()
                    )));
                }
            }
        }
        // SAFETY: single free of the descriptor allocated above.
        unsafe { LocalFree(HLOCAL(descriptor.0.cast())) };
        Ok(())
    }

    fn prune_other_boots(&self, keep: &str) {
        let Ok(entries) = fs::read_dir(&self.base) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name != keep {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
    }
}

impl SensorStorePort for WindowsSensorStore {
    fn materialize(&self, source: &str) -> Result<MaterializedSensor, SensorStoreError> {
        let source_bytes = fs::read(source)
            .map_err(|error| SensorStoreError::SourceMissing(format!("{source}: {error}")))?;
        let source_hash = super::sha256_hex(&source_bytes);

        let boot = format!("boot-{}", super::random_hex(8));
        let file = format!("sensor-{}.dll", super::random_hex(8));
        let dir = self.base.join(&boot);
        Self::create_protected_dir(&dir)?;
        let destination = dir.join(&file);

        // create_new: a random-name collision must fail loudly, never
        // overwrite.
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)
            .and_then(|mut file| std::io::Write::write_all(&mut file, &source_bytes))
            .map_err(|error| {
                SensorStoreError::Io(format!("write {}: {error}", destination.display()))
            })?;

        // Hash what actually landed on disk — pins the copy, catches a
        // source that changed mid-copy or a torn write.
        let copy_bytes = fs::read(&destination).map_err(|error| {
            SensorStoreError::Io(format!("reread {}: {error}", destination.display()))
        })?;
        let copy_hash = super::sha256_hex(&copy_bytes);
        if copy_hash != source_hash {
            let _ = fs::remove_file(&destination);
            return Err(SensorStoreError::HashMismatch {
                expected: source_hash,
                actual: copy_hash,
            });
        }

        self.prune_other_boots(&boot);

        let dos_path = destination.to_string_lossy().into_owned();
        Ok(MaterializedSensor {
            nt_path: super::to_nt_path(&dos_path),
            dos_path,
            sha256_hex: copy_hash,
        })
    }
}

fn to_wide_nul(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(all(test, windows))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn temp_base(tag: &str) -> PathBuf {
        // Unique per run: a previous run's protected dir may be undeletable
        // for an unelevated user (that is the DACL working), so it must never
        // collide.
        let unique = format!("{tag}-{}-{}", std::process::id(), super::super::random_hex(4));
        let base = std::env::temp_dir().join(format!("secoutfall-sensor-store-{unique}"));
        fs::create_dir_all(&base).unwrap();
        base
    }

    #[test]
    fn materialize_copies_pins_and_prunes() {
        let base = temp_base("copy");
        let store = WindowsSensorStore::with_base(base.join("sensors"));

        // A stale boot dir from a "previous boot" must disappear.
        let stale = store.base.join("boot-deadbeef");
        fs::create_dir_all(&stale).unwrap();
        fs::write(stale.join("sensor-old.dll"), b"stale").unwrap();

        let source = base.join("the-sensor.dll");
        let payload = b"MZ fake sensor bytes".to_vec();
        fs::write(&source, &payload).unwrap();

        let first = store.materialize(source.to_str().unwrap()).unwrap();
        assert_eq!(first.sha256_hex, super::super::sha256_hex(&payload));
        assert!(first.nt_path.starts_with(r"\??\"));
        let copy_path = PathBuf::from(first.dos_path.clone());
        assert_eq!(fs::read(&copy_path).unwrap(), payload);

        // Second call: fresh names; the previous boot's copy is pruned by
        // design — only the live sensor survives on disk.
        let second = store.materialize(source.to_str().unwrap()).unwrap();
        assert_ne!(first.dos_path, second.dos_path);
        assert!(!stale.exists(), "previous-boot dirs must be pruned");
        assert!(!copy_path.exists(), "previous boot's sensor copy must be pruned");
        assert!(PathBuf::from(second.dos_path.clone()).exists());
        assert_eq!(fs::read(&second.dos_path).unwrap(), payload);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn missing_source_is_a_source_error_not_a_panic() {
        let base = temp_base("missing");
        let store = WindowsSensorStore::with_base(base.join("sensors"));
        let error = store.materialize(base.join("nope.dll").to_str().unwrap()).unwrap_err();
        assert!(matches!(error, SensorStoreError::SourceMissing(_)));
        let _ = fs::remove_dir_all(&base);
    }
}
