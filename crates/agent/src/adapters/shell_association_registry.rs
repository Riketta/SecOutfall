//! Registry-backed shell-association lookup (Windows only, feature
//! `associations`).
//!
//! Resolution order follows the shell: a direct
//! `HKCR\\<ext>\\shell\\open\\command` override first, then the extension's
//! `ProgID`. Values are read as `REG_SZ` **or** `REG_EXPAND_SZ` (the latter is
//! auto-expanded by `RegGetValueW`, as the shell does); the UTF-16LE buffer is
//! decoded by [`decode_utf16_reg_sz`] — never lossy UTF-8, which would corrupt
//! every non-ASCII command line with embedded NULs. The `%1`/`%L` substitution
//! itself is pure logic in [`crate::domain::shell_command`] (tested
//! everywhere) — this adapter only talks to the registry.
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
            RRF_RT_REG_EXPAND_SZ,
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
    // `REG_EXPAND_SZ` values are auto-expanded (the shell does the same)
    // instead of the read failing outright.
    let sz_flags = RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ;
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
            sz_flags,
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
            sz_flags,
            None,
            Some(buffer.as_mut_ptr().cast()),
            Some(&raw mut size),
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    buffer.get(..size as usize).and_then(decode_utf16_reg_sz)
}

/// Decode a `REG_SZ` buffer as returned by `RegGetValueW`: UTF-16LE units
/// with a single trailing NUL terminator. The odd trailing byte of a hostile
/// or truncated buffer is ignored (the registry never produces one); invalid
/// UTF-16 and an empty result (no bytes, or a lone terminator) yield `None`.
/// Only ONE terminator is trimmed — embedded NULs beyond it stay visible
/// instead of being silently eaten.
fn decode_utf16_reg_sz(buffer: &[u8]) -> Option<String> {
    let units: Vec<u16> = buffer
        .chunks_exact(2)
        .map(|pair| match pair {
            [low, high] => u16::from_le_bytes([*low, *high]),
            _ => 0, // unreachable: `chunks_exact` yields exactly two bytes
        })
        .collect();
    let mut text = String::from_utf16(&units).ok()?;
    if text.ends_with('\0') {
        text.pop();
    }
    if text.is_empty() {
        return None;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// UTF-16LE byte encoding, as `RegGetValueW` fills the buffer.
    fn wide(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn ascii_command_with_terminator_decodes() {
        let command = r#""C:\Windows\notepad.exe" "%1""#;
        let mut buffer = wide(command);
        buffer.extend_from_slice(&[0, 0]);
        assert_eq!(decode_utf16_reg_sz(&buffer).as_deref(), Some(command));
    }

    #[test]
    fn cyrillic_path_decodes_bomless() {
        let path = "C:\\Отчёты\\программа.exe";
        let mut buffer = wide(path);
        buffer.extend_from_slice(&[0, 0]);
        assert_eq!(decode_utf16_reg_sz(&buffer).as_deref(), Some(path));
    }

    #[test]
    fn missing_terminator_returns_text_as_is() {
        assert_eq!(decode_utf16_reg_sz(&wide("cmd.exe")).as_deref(), Some("cmd.exe"));
    }

    #[test]
    fn empty_buffer_is_no_value() {
        assert_eq!(decode_utf16_reg_sz(&[]), None);
    }

    #[test]
    fn odd_trailing_byte_is_ignored() {
        let mut buffer = wide("cmd.exe");
        buffer.extend_from_slice(&[0, 0, 0xAA]); // terminator + a stray byte
        assert_eq!(decode_utf16_reg_sz(&buffer).as_deref(), Some("cmd.exe"));
    }

    #[test]
    fn only_one_terminator_is_trimmed() {
        let mut buffer = wide("a");
        buffer.extend_from_slice(&[0, 0, 0, 0]); // two NUL units
        assert_eq!(decode_utf16_reg_sz(&buffer), Some("a\0".to_owned()));
    }

    #[test]
    fn invalid_utf16_is_rejected() {
        // A lone high surrogate (0xD800) is not valid UTF-16.
        assert_eq!(decode_utf16_reg_sz(&0xD800_u16.to_le_bytes()), None);
    }
}
