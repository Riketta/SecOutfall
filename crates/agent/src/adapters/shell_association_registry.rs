//! Registry-backed shell-association lookup (Windows only, feature
//! `associations`).
//!
//! Resolution order follows the shell: a direct
//! `HKCR\<ext>\shell\open\command` override first, then the extension's
//! `ProgID`. The `%1`/`%L` substitution itself is pure logic in
//! [`crate::domain::shell_command`] (tested everywhere) — this adapter only
//! talks to the registry.
//!
//! Any registry failure (missing key, unreadable value) maps to "no usable
//! association" — the same outcome Windows would produce when opening the
//! document by hand; there is nothing to retry.

use async_trait::async_trait;
use windows::{
    Win32::{
        Foundation::ERROR_SUCCESS,
        System::Registry::{
            HKEY_CLASSES_ROOT,
            RRF_RT_REG_SZ,
            RegGetValueW,
        },
    },
    core::PCWSTR,
};

use crate::{
    domain::shell_command::substitute_command,
    ports::shell_association::{
        ShellAssociationError,
        ShellAssociationPort,
    },
};

/// Registry adapter implementing [`ShellAssociationPort`].
#[derive(Debug, Clone, Copy, Default)]
pub struct RegistryShellAssociationAdapter;

impl RegistryShellAssociationAdapter {
    /// Assemble the adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

/// `HKEY_CLASSES_ROOT`-rooted `REG_SZ` (or auto-expanded `REG_EXPAND_SZ`)
/// read; `None` = missing or unreadable.
fn read_sz(sub_key: &str, value: &str) -> Option<String> {
    let sub_key_wide: Vec<u16> = sub_key.encode_utf16().chain(std::iter::once(0)).collect();
    let value_wide: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();

    let mut size: u32 = 0;
    // SAFETY: both wide strings are NUL-terminated locals; the first call
    // only reports the required buffer size (`pvData = None`).
    let status = unsafe {
        RegGetValueW(
            HKEY_CLASSES_ROOT,
            PCWSTR::from_raw(sub_key_wide.as_ptr()),
            PCWSTR::from_raw(value_wide.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            None,
            Some(&raw mut size),
        )
    };
    if status != ERROR_SUCCESS || size == 0 {
        return None;
    }

    let mut buffer: Vec<u8> = vec![0; size as usize];
    // SAFETY: `buffer` is sized to `size` bytes as reported by the first
    // call; the API writes at most that many bytes and the NUL terminator.
    let status = unsafe {
        RegGetValueW(
            HKEY_CLASSES_ROOT,
            PCWSTR::from_raw(sub_key_wide.as_ptr()),
            PCWSTR::from_raw(value_wide.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buffer.as_mut_ptr().cast()),
            Some(&raw mut size),
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    let text = String::from_utf8_lossy(&buffer).trim_end_matches('\0').to_owned();
    Some(text)
}

/// The `shell\open\command` for a `HKCR` subkey, if present.
fn open_command_for(sub_key: &str) -> Option<String> {
    read_sz(&format!("{sub_key}\\shell\\open\\command"), "")
}

/// Extension of a document path, lowercased with the leading dot.
fn extension_of(document: &str) -> Option<String> {
    let path = std::path::Path::new(document);
    let extension = path.extension()?.to_str()?;
    if extension.is_empty() {
        return None;
    }
    Some(format!(".{}", extension.to_lowercase()))
}

fn blocking_resolve(document: &str) -> Result<String, ShellAssociationError> {
    let Some(extension) = extension_of(document) else {
        return Err(ShellAssociationError::NotFound(document.to_owned()));
    };

    // Direct per-extension override wins, then the ProgID default value.
    let command = open_command_for(&extension).or_else(|| {
        let prog_id = read_sz(&extension, "")?;
        open_command_for(&prog_id)
    });
    let Some(command) = command else {
        return Err(ShellAssociationError::NotFound(document.to_owned()));
    };

    substitute_command(&command, document).map_err(|_| ShellAssociationError::Unusable {
        extension,
        detail: "registered command is empty".to_owned(),
    })
}

#[async_trait]
impl ShellAssociationPort for RegistryShellAssociationAdapter {
    async fn resolve_open_command(
        &self,
        document_path: &str,
    ) -> Result<String, ShellAssociationError> {
        let document = document_path.to_owned();
        tokio::task::spawn_blocking(move || blocking_resolve(&document))
            .await
            .map_err(|error| ShellAssociationError::Registry(error.to_string()))?
    }
}
