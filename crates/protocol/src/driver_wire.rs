//! Driver wire schema v2 — the kernel driver ↔ user-mode contract, mirrored
//! from `driver/secoutfall/secoutfallCommon.h` (the C side of the same
//! schema).
//!
//! Pinned by golden tests against the committed fixture
//! `driver/tests/golden_v2.bin`, which the C-side `wiretest` host tool
//! generates and re-verifies on every driver build: if either interpretation
//! drifts, at least one golden test fails. This module is decode-only by
//! design — the driver *produces* records; user-mode only ever consumes them.
//!
//! Layout contract (little-endian, natural x64 alignment in the C structs):
//! every record starts with a 48-byte [`HEADER_SIZE`] header (magic, version,
//! truncation flags, type, pid, per-boot sequence, timestamps, total size)
//! followed by type-specific fixed fields and variable-length UTF-16 name
//! data. String lengths are capped (`MAX_*_BYTES`) and truncated strings are
//! flagged in the header — a flagged string is a PREFIX of the truth.

use std::{
    borrow::Cow,
    path::{
        Path,
        PathBuf,
    },
};

/// Wire magic: `'SF'`, the first two bytes of every record.
pub const WIRE_MAGIC: u16 = 0x5346;
/// Wire schema version; a consumer must reject other versions, never guess.
pub const WIRE_VERSION: u8 = 2;
/// Fixed header extent in bytes (offsets pinned by C-side `static_assert`s).
pub const HEADER_SIZE: usize = 48;
/// Hard cap on a single record: a hostile stream cannot make the decoder
/// allocate; anything above this is refused before the payload is inspected.
pub const MAX_RECORD_BYTES: usize = 64 * 1024;

/// Per-field truncation flags (header `TruncFlags`).
pub const TRUNC_NONE: u8 = 0x00;
/// Per-field truncation flags (header `TruncFlags`).
pub const TRUNC_CMDLINE: u8 = 0x01;
/// Per-field truncation flags (header `TruncFlags`).
pub const TRUNC_KEY_PATH: u8 = 0x02;
/// Per-field truncation flags (header `TruncFlags`).
pub const TRUNC_VALUE_NAME: u8 = 0x04;
/// Per-field truncation flags (header `TruncFlags`).
pub const TRUNC_DATA: u8 = 0x08;
/// Per-field truncation flags (header `TruncFlags`).
pub const TRUNC_IMAGE_NAME: u8 = 0x10;
/// Per-field truncation flags (header `TruncFlags`).
pub const TRUNC_FILE_PATH: u8 = 0x20;
/// Per-field truncation flags (header `TruncFlags`).
pub const TRUNC_OLD_PATH: u8 = 0x40;
/// Per-field truncation flags (header `TruncFlags`).
pub const TRUNC_NEW_PATH: u8 = 0x80;

/// String caps in bytes (whole WCHARs on the wire) — mirrored from the header.
pub const MAX_COMMAND_LINE_BYTES: usize = 8192;
/// String caps in bytes (whole WCHARs on the wire) — mirrored from the header.
pub const MAX_KEY_PATH_BYTES: usize = 1024;
/// String caps in bytes (whole WCHARs on the wire) — mirrored from the header.
pub const MAX_VALUE_NAME_BYTES: usize = 512;
/// String caps in bytes (whole WCHARs on the wire) — mirrored from the header.
pub const MAX_IMAGE_NAME_BYTES: usize = 1024;
/// String caps in bytes (whole WCHARs on the wire) — mirrored from the header.
pub const MAX_FILE_PATH_BYTES: usize = 1024;
/// Registry value data cap in bytes (the driver copies at most this much).
pub const MAX_VALUE_DATA_BYTES: usize = 128;

/// `REG_SZ`, the only value type the fixture pins explicitly.
pub const REG_SZ: u32 = 1;

/// Record type discriminator (wire values are stable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    /// A process was created.
    ProcessCreated,
    /// A process exited.
    ProcessExited,
    /// A thread was created.
    ThreadCreated,
    /// A thread exited.
    ThreadExited,
    /// A user-mode image was mapped into a process.
    ImageLoaded,
    /// A registry key under HKLM was created.
    RegistryKeyCreated,
    /// A registry key under HKLM was deleted.
    RegistryKeyDeleted,
    /// A registry value under HKLM was written.
    RegistrySetValue,
    /// A file was created.
    FileCreated,
    /// A file was written.
    FileWritten,
    /// The last handle to a file was closed.
    FileCleanedUp,
    /// A file was marked for deletion.
    FileDeleted,
    /// A file was renamed.
    FileRenamed,
}

impl RecordKind {
    fn from_wire(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::ProcessCreated),
            2 => Some(Self::ProcessExited),
            3 => Some(Self::ThreadCreated),
            4 => Some(Self::ThreadExited),
            5 => Some(Self::ImageLoaded),
            6 => Some(Self::RegistryKeyCreated),
            7 => Some(Self::RegistryKeyDeleted),
            8 => Some(Self::RegistrySetValue),
            9 => Some(Self::FileCreated),
            10 => Some(Self::FileWritten),
            11 => Some(Self::FileCleanedUp),
            12 => Some(Self::FileDeleted),
            13 => Some(Self::FileRenamed),
            _ => None,
        }
    }
}

/// Why a byte sequence is not a valid v2 record stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Fewer bytes than the header (or the declared size) provide.
    Truncated {
        /// Bytes actually available.
        available: usize,
        /// Bytes the position required.
        needed: usize,
    },
    /// Magic mismatch.
    BadMagic(u16),
    /// Schema version this decoder refuses to guess at.
    BadVersion(u8),
    /// Header extent differs from the pinned layout.
    BadHeaderSize(u16),
    /// Record size below the header or past the available bytes.
    BadSize {
        /// Declared total size.
        size: u32,
        /// Bytes actually available from the record start.
        available: usize,
    },
    /// Record size above [`MAX_RECORD_BYTES`] — hostile-stream bound.
    Oversize(u32),
    /// Unknown record type: forward-compat is the CALLER's choice (skip by
    /// size), never the decoder's silent guess.
    UnknownType(u16),
    /// A variable-length string whose extent leaves the record or is not a
    /// whole number of WCHARs.
    BadString {
        /// String offset from the record start.
        offset: usize,
        /// String byte length.
        bytes: usize,
        /// Total record size it must fit within.
        record_size: usize,
    },
}

/// A decoded record: header fields plus the typed payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    kind: RecordKind,
    pid: u32,
    sequence: u64,
    time: u64,
    process_create_time: u64,
    trunc_flags: u8,
    payload: Payload,
}

/// Type-specific payload, one variant per record kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// A process was created; the command line is capped and may be absent.
    ProcessCreated {
        /// Creator pid.
        parent_pid: u32,
        /// UTF-16 command line, lossy-decoded; `None` when absent on the wire.
        command_line: Option<String>,
    },
    /// A process exited.
    ProcessExited,
    /// A thread lifecycle event.
    Thread {
        /// Thread id within the record's process.
        thread_id: u32,
    },
    /// A user-mode image was mapped.
    ImageLoaded {
        /// Load address.
        base: u64,
        /// Mapped size in bytes.
        size: u32,
        /// Full image path, lossy-decoded; `None` when absent on the wire.
        name: Option<String>,
    },
    /// A registry key was created.
    RegistryKeyCreated {
        /// Full key path, lossy-decoded.
        path: String,
    },
    /// A registry key was deleted.
    RegistryKeyDeleted {
        /// Full key path, lossy-decoded.
        path: String,
    },
    /// A registry value was written.
    RegistrySetValue {
        /// Full key path, lossy-decoded.
        key_path: String,
        /// Value name, lossy-decoded.
        value_name: String,
        /// `REG_*` value type as reported by the kernel.
        data_type: u32,
        /// Value data bytes actually carried (already capped by the driver).
        data: Vec<u8>,
    },
    /// A file was created.
    FileCreated {
        /// Normalized full path, lossy-decoded (empty = name query failed).
        path: String,
    },
    /// A file was written.
    FileWritten {
        /// Start of the write.
        offset: u64,
        /// Write length in bytes.
        bytes: u32,
        /// Normalized full path, lossy-decoded.
        path: String,
    },
    /// The last handle to a file was closed.
    FileCleanedUp {
        /// Normalized full path, lossy-decoded.
        path: String,
    },
    /// A file was marked for deletion.
    FileDeleted {
        /// Normalized full path, lossy-decoded.
        path: String,
    },
    /// A file was renamed.
    FileRenamed {
        /// Pre-rename path, lossy-decoded (empty = the pre-callback query
        /// failed — the rename still happened, the old name is unknown).
        old_path: String,
        /// Post-rename path, lossy-decoded.
        new_path: String,
    },
}

impl Record {
    /// Record kind discriminator.
    #[must_use]
    pub fn kind(&self) -> RecordKind {
        self.kind
    }

    /// Owning (or acting) process id.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Per-boot monotonic sequence assigned by the driver.
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Kernel system time at the event (NOT fake-clock unix ms — the agent
    /// maps this at drain; see KERNEL.md).
    #[must_use]
    pub fn time(&self) -> u64 {
        self.time
    }

    /// Identity token: driver-witnessed creation time; 0 = unknown (pre-load
    /// process). Identity is (pid, creation time), never pid alone.
    #[must_use]
    pub fn process_create_time(&self) -> u64 {
        self.process_create_time
    }

    /// [`TRUNC_*`] flags: which variable-length fields were clamped.
    #[must_use]
    pub fn trunc_flags(&self) -> u8 {
        self.trunc_flags
    }

    /// Typed payload.
    #[must_use]
    pub fn payload(&self) -> &Payload {
        &self.payload
    }
}

// Little-endian readers with explicit bounds — no indexing, no slicing, no
// unwraps (workspace lints), and the input is hostile by definition.
fn trunc(needed: usize, available: usize) -> DecodeError {
    DecodeError::Truncated { available, needed }
}

fn u8_at(buf: &[u8], at: usize) -> Result<u8, DecodeError> {
    buf.get(at).copied().ok_or(trunc(at + 1, buf.len()))
}

fn u16_at(buf: &[u8], at: usize) -> Result<u16, DecodeError> {
    let lo = u8_at(buf, at)?;
    let hi = u8_at(buf, at + 1)?;
    Ok(u16::from_le_bytes([lo, hi]))
}

fn u32_at(buf: &[u8], at: usize) -> Result<u32, DecodeError> {
    let b0 = u8_at(buf, at)?;
    let b1 = u8_at(buf, at + 1)?;
    let b2 = u8_at(buf, at + 2)?;
    let b3 = u8_at(buf, at + 3)?;
    Ok(u32::from_le_bytes([b0, b1, b2, b3]))
}

fn u64_at(buf: &[u8], at: usize) -> Result<u64, DecodeError> {
    let mut bytes = [0u8; 8];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = u8_at(buf, at + index)?;
    }
    Ok(u64::from_le_bytes(bytes))
}

fn str_field(buf: &[u8], offset: usize, bytes: usize) -> Result<Cow<'_, str>, DecodeError> {
    if !bytes.is_multiple_of(2) {
        return Err(DecodeError::BadString { offset, bytes, record_size: buf.len() });
    }
    if bytes == 0 {
        return Ok(Cow::Borrowed(""));
    }
    let end = offset + bytes;
    let slice = buf.get(offset..end).ok_or(DecodeError::BadString {
        offset,
        bytes,
        record_size: buf.len(),
    })?;
    let units: Vec<u16> =
        slice.as_chunks::<2>().0.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
    Ok(String::from_utf16_lossy(&units).into())
}

fn string_at(buf: &[u8], offset: usize, bytes: usize) -> Result<String, DecodeError> {
    Ok(str_field(buf, offset, bytes)?.into_owned())
}

/// Decodes one record from the front of `buf`. The record's declared size
/// bounds every read; trailing bytes (further records) are ignored — batch
/// iteration is the caller's job.
///
/// # Errors
/// [`DecodeError`] for every way a hostile stream can be malformed: bad
/// magic/version/header size, out-of-range or over-cap sizes, unknown types,
/// and string extents that leave their record. Never panics on any input.
pub fn decode(buf: &[u8]) -> Result<Record, DecodeError> {
    if buf.len() < HEADER_SIZE {
        return Err(DecodeError::Truncated { available: buf.len(), needed: HEADER_SIZE });
    }
    let magic = u16_at(buf, 0)?;
    if magic != WIRE_MAGIC {
        return Err(DecodeError::BadMagic(magic));
    }
    let version = u8_at(buf, 2)?;
    if version != WIRE_VERSION {
        return Err(DecodeError::BadVersion(version));
    }
    let trunc_flags = u8_at(buf, 3)?;
    let raw_type = u16_at(buf, 4)?;
    let header_size = u16_at(buf, 6)?;
    if usize::from(header_size) != HEADER_SIZE {
        return Err(DecodeError::BadHeaderSize(header_size));
    }
    let pid = u32_at(buf, 8)?;
    let sequence = u64_at(buf, 16)?;
    let time = u64_at(buf, 24)?;
    let process_create_time = u64_at(buf, 32)?;
    // The declared size comes off the wire as u32 and is echoed back in
    // errors verbatim — never a round-trip cast.
    let size_raw = u32_at(buf, 40)?;
    let size = size_raw as usize;
    if size < HEADER_SIZE || size > buf.len() {
        return Err(DecodeError::BadSize { size: size_raw, available: buf.len() });
    }
    if size > MAX_RECORD_BYTES {
        return Err(DecodeError::Oversize(size_raw));
    }
    let record = buf.get(..size).ok_or(trunc(size, buf.len()))?;

    let kind = RecordKind::from_wire(raw_type).ok_or(DecodeError::UnknownType(raw_type))?;
    let payload = payload_of(kind, record, size, size_raw)?;

    Ok(Record { kind, pid, sequence, time, process_create_time, trunc_flags, payload })
}

/// Type-specific fixed-field extents on the wire (mirrors the C `*Fixed`
/// constants): the minimum record size each kind requires.
fn min_size(kind: RecordKind) -> usize {
    match kind {
        RecordKind::ProcessExited => 48,
        RecordKind::ProcessCreated | RecordKind::FileRenamed => 56,
        RecordKind::ThreadCreated
        | RecordKind::ThreadExited
        | RecordKind::RegistryKeyCreated
        | RecordKind::RegistryKeyDeleted
        | RecordKind::FileCreated
        | RecordKind::FileCleanedUp
        | RecordKind::FileDeleted => 52,
        RecordKind::ImageLoaded | RecordKind::RegistrySetValue | RecordKind::FileWritten => 64,
    }
}

fn payload_of(
    kind: RecordKind,
    record: &[u8],
    size: usize,
    size_raw: u32,
) -> Result<Payload, DecodeError> {
    let short = || DecodeError::BadSize { size: size_raw, available: record.len() };
    if size < min_size(kind) {
        return Err(short());
    }

    let payload = match kind {
        RecordKind::ProcessCreated => {
            let parent_pid = u32_at(record, 48)?;
            let cmd_offset = u16_at(record, 52)? as usize;
            let cmd_bytes = u16_at(record, 54)? as usize;
            let command_line =
                if cmd_bytes == 0 { None } else { Some(string_at(record, cmd_offset, cmd_bytes)?) };
            Payload::ProcessCreated { parent_pid, command_line }
        }
        RecordKind::ProcessExited => Payload::ProcessExited,
        RecordKind::ThreadCreated | RecordKind::ThreadExited => {
            let thread_id = u32_at(record, 48)?;
            Payload::Thread { thread_id }
        }
        RecordKind::ImageLoaded => {
            let base = u64_at(record, 48)?;
            let img_size = u32_at(record, 56)?;
            let name_offset = u16_at(record, 60)? as usize;
            let name_bytes = u16_at(record, 62)? as usize;
            let name = if name_bytes == 0 {
                None
            } else {
                Some(string_at(record, name_offset, name_bytes)?)
            };
            Payload::ImageLoaded { base, size: img_size, name }
        }
        RecordKind::RegistryKeyCreated | RecordKind::RegistryKeyDeleted => {
            let path_offset = u16_at(record, 48)? as usize;
            let path_bytes = u16_at(record, 50)? as usize;
            let path = string_at(record, path_offset, path_bytes)?;
            match kind {
                RecordKind::RegistryKeyCreated => Payload::RegistryKeyCreated { path },
                _ => Payload::RegistryKeyDeleted { path },
            }
        }
        RecordKind::RegistrySetValue => {
            let key_offset = u16_at(record, 48)? as usize;
            let key_bytes = u16_at(record, 50)? as usize;
            let value_offset = u16_at(record, 52)? as usize;
            let value_bytes = u16_at(record, 54)? as usize;
            let data_type = u32_at(record, 56)?;
            let data_bytes = u32_at(record, 60)? as usize;
            let key_path = string_at(record, key_offset, key_bytes)?;
            let value_name = string_at(record, value_offset, value_bytes)?;
            let data = record
                .get(value_offset + value_bytes..value_offset + value_bytes + data_bytes)
                .ok_or(DecodeError::BadString {
                    offset: value_offset + value_bytes,
                    bytes: data_bytes,
                    record_size: size,
                })?
                .to_vec();
            Payload::RegistrySetValue { key_path, value_name, data_type, data }
        }
        RecordKind::FileCreated | RecordKind::FileCleanedUp | RecordKind::FileDeleted => {
            let path_offset = u16_at(record, 48)? as usize;
            let path_bytes = u16_at(record, 50)? as usize;
            let path = string_at(record, path_offset, path_bytes)?;
            match kind {
                RecordKind::FileCreated => Payload::FileCreated { path },
                RecordKind::FileCleanedUp => Payload::FileCleanedUp { path },
                _ => Payload::FileDeleted { path },
            }
        }
        RecordKind::FileWritten => {
            let offset = u64_at(record, 48)?;
            let bytes = u32_at(record, 56)?;
            let path_offset = u16_at(record, 60)? as usize;
            let path_bytes = u16_at(record, 62)? as usize;
            let path = string_at(record, path_offset, path_bytes)?;
            Payload::FileWritten { offset, bytes, path }
        }
        RecordKind::FileRenamed => {
            let old_offset = u16_at(record, 48)? as usize;
            let old_bytes = u16_at(record, 50)? as usize;
            let new_offset = u16_at(record, 52)? as usize;
            let new_bytes = u16_at(record, 54)? as usize;
            let old_path = string_at(record, old_offset, old_bytes)?;
            let new_path = string_at(record, new_offset, new_bytes)?;
            Payload::FileRenamed { old_path, new_path }
        }
    };
    Ok(payload)
}

/// Decodes a whole drain buffer (records back to back). Returns all records,
/// or the first error — callers that prefer forward-compat over strictness
/// can instead walk `decode` + declared sizes themselves (the driver surfaces
/// unknown types on purpose; unknown types here are an error by default).
///
/// # Errors
/// [`DecodeError`] from [`decode`] for the first malformed record.
pub fn decode_all(buf: &[u8]) -> Result<Vec<Record>, DecodeError> {
    let mut records = Vec::new();
    let mut rest = buf;
    while !rest.is_empty() {
        let record = decode(rest)?;
        let consumed = record_size(rest)?;
        rest = rest.get(consumed..).ok_or(trunc(consumed, rest.len()))?;
        records.push(record);
    }
    Ok(records)
}

// The declared size of the record at the front of `buf` (assumes `decode`
// already validated the header).
fn record_size(buf: &[u8]) -> Result<usize, DecodeError> {
    let size_raw = u32_at(buf, 40)?;
    let size = size_raw as usize;
    if size < HEADER_SIZE || size > buf.len() {
        return Err(DecodeError::BadSize { size: size_raw, available: buf.len() });
    }
    Ok(size)
}

/// Path of the committed golden fixture, for tests that pin this module to
/// the C-side `wiretest` output.
#[must_use]
pub fn golden_fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("driver")
        .join("tests")
        .join("golden_v2.bin")
}

#[cfg(test)]
mod tests {
    // Test construction is allowed to index and unwrap: these are fixed-size
    // synthetic buffers, not hostile input (the precedent is prop_wire.rs).
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation
    )]

    use super::*;

    const TIME_BASE: u64 = 0x01D9_0000_0000_0000;
    const IDENTITY_BASE: u64 = 0x01C8_0000_0000_0000;

    #[test]
    fn golden_fixture_decodes_to_the_canonical_records() {
        let bytes = std::fs::read(golden_fixture_path())
            .expect("committed fixture must exist — regenerate with wiretest --generate");
        let records = decode_all(&bytes).expect("fixture must decode");

        assert_eq!(records.len(), 13);
        for (index, record) in records.iter().enumerate() {
            assert_eq!(record.sequence(), index as u64 + 1, "per-boot seq is gap-free");
            assert_eq!(record.time(), TIME_BASE + record.sequence());
        }

        // 1: process created with a full command line.
        assert_eq!(records[0].kind(), RecordKind::ProcessCreated);
        assert_eq!(records[0].pid(), 1004);
        assert_eq!(records[0].process_create_time(), IDENTITY_BASE + 1004);
        assert_eq!(records[0].trunc_flags(), TRUNC_NONE);
        let Payload::ProcessCreated { parent_pid, command_line } = records[0].payload() else {
            panic!("payload kind mismatch")
        };
        assert_eq!(*parent_pid, 998);
        assert_eq!(command_line.as_deref(), Some("C:\\Windows\\system32\\cmd.exe /c whoami"));

        // 2: process exited.
        assert_eq!(records[1].kind(), RecordKind::ProcessExited);
        assert_eq!(records[1].payload(), &Payload::ProcessExited);

        // 3, 4: thread create/exit.
        for (record, kind) in
            records[2..4].iter().zip([RecordKind::ThreadCreated, RecordKind::ThreadExited])
        {
            assert_eq!(record.kind(), kind);
            let Payload::Thread { thread_id } = record.payload() else {
                panic!("payload kind mismatch")
            };
            assert_eq!(*thread_id, 2004);
        }

        // 5: image loaded.
        assert_eq!(records[4].kind(), RecordKind::ImageLoaded);
        let Payload::ImageLoaded { base, size, name } = records[4].payload() else {
            panic!("payload kind mismatch")
        };
        assert_eq!(*base, 0x7FF8_0000_0000);
        assert_eq!(*size, 0x8_0000);
        assert_eq!(name.as_deref(), Some("C:\\Windows\\System32\\kernel32.dll"));

        // 6, 7: registry key create/delete.
        assert_eq!(records[5].kind(), RecordKind::RegistryKeyCreated);
        let Payload::RegistryKeyCreated { path } = records[5].payload() else {
            panic!("payload kind mismatch")
        };
        assert_eq!(path, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
        assert_eq!(records[6].kind(), RecordKind::RegistryKeyDeleted);
        let Payload::RegistryKeyDeleted { path } = records[6].payload() else {
            panic!("payload kind mismatch")
        };
        assert_eq!(path, "\\REGISTRY\\MACHINE\\SOFTWARE\\Evil\\Persist");

        // 8: registry set-value with a TRUNCATED key path (hostile-length
        // coverage) — the flag must survive the round trip.
        assert_eq!(records[7].kind(), RecordKind::RegistrySetValue);
        assert_eq!(records[7].trunc_flags(), TRUNC_KEY_PATH);
        let Payload::RegistrySetValue { key_path, value_name, data_type, data } =
            records[7].payload()
        else {
            panic!("payload kind mismatch")
        };
        assert_eq!(key_path.len(), MAX_KEY_PATH_BYTES / 2, "clamped to the cap");
        assert!(key_path.starts_with(
            "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"
        ));
        assert_eq!(value_name, "Backdoor");
        assert_eq!(*data_type, REG_SZ);
        assert_eq!(data, b"C:\\Users\\Public\\payload.exe");

        // 9: file created.
        assert_eq!(records[8].kind(), RecordKind::FileCreated);
        assert_eq!(records[8].trunc_flags(), TRUNC_NONE);
        let Payload::FileCreated { path } = records[8].payload() else {
            panic!("payload kind mismatch")
        };
        assert_eq!(path, "\\Device\\HarddiskVolume2\\Users\\user\\AppData\\payload.dll");

        // 10: file written with offset + length.
        assert_eq!(records[9].kind(), RecordKind::FileWritten);
        let Payload::FileWritten { offset, bytes, path } = records[9].payload() else {
            panic!("payload kind mismatch")
        };
        assert_eq!(*offset, 512);
        assert_eq!(*bytes, 240);
        assert_eq!(path, "\\Device\\HarddiskVolume2\\Users\\user\\Documents\\notes.txt");

        // 11: file cleaned up.
        assert_eq!(records[10].kind(), RecordKind::FileCleanedUp);
        let Payload::FileCleanedUp { path } = records[10].payload() else {
            panic!("payload kind mismatch")
        };
        assert_eq!(path, "\\Device\\HarddiskVolume2\\Users\\user\\AppData\\payload.dll");

        // 12: file deleted.
        assert_eq!(records[11].kind(), RecordKind::FileDeleted);
        let Payload::FileDeleted { path } = records[11].payload() else {
            panic!("payload kind mismatch")
        };
        assert_eq!(path, "\\Device\\HarddiskVolume2\\Users\\user\\AppData\\log.tmp");

        // 13: file renamed, both paths.
        assert_eq!(records[12].kind(), RecordKind::FileRenamed);
        assert_eq!(records[12].trunc_flags(), TRUNC_NONE);
        let Payload::FileRenamed { old_path, new_path } = records[12].payload() else {
            panic!("payload kind mismatch")
        };
        assert_eq!(old_path, "\\Device\\HarddiskVolume2\\Users\\user\\Documents\\draft.txt");
        assert_eq!(new_path, "\\Device\\HarddiskVolume2\\Users\\user\\Documents\\final.txt");
    }

    #[test]
    fn empty_and_truncated_inputs_are_errors_not_panics() {
        assert_eq!(decode(&[]), Err(DecodeError::Truncated { available: 0, needed: HEADER_SIZE }));
        let short = vec![0u8; HEADER_SIZE - 1];
        assert!(decode(&short).is_err());
    }

    #[test]
    fn wrong_magic_and_version_are_rejected() {
        let mut bytes = vec![0u8; HEADER_SIZE];
        bytes[0..2].copy_from_slice(&0x4141u16.to_le_bytes());
        assert_eq!(decode(&bytes), Err(DecodeError::BadMagic(0x4141)));
        let mut bytes = vec![0u8; HEADER_SIZE];
        bytes[0..2].copy_from_slice(&WIRE_MAGIC.to_le_bytes());
        bytes[2] = WIRE_VERSION + 1;
        assert_eq!(decode(&bytes), Err(DecodeError::BadVersion(WIRE_VERSION + 1)));
    }

    #[test]
    fn unknown_types_are_errors_the_caller_may_skip_by_size() {
        let mut bytes = vec![0u8; HEADER_SIZE];
        bytes[0..2].copy_from_slice(&WIRE_MAGIC.to_le_bytes());
        bytes[2] = WIRE_VERSION;
        bytes[4..6].copy_from_slice(&9999u16.to_le_bytes());
        bytes[6..8].copy_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
        bytes[40..44].copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
        assert_eq!(decode(&bytes), Err(DecodeError::UnknownType(9999)));
    }

    #[test]
    fn over_cap_sizes_are_rejected_before_payload_inspection() {
        // The buffer must actually CONTAIN the claimed extent: a declared size
        // beyond the available bytes is BadSize (truncated claim), while a
        // size the buffer satisfies but above the cap is Oversize.
        let mut bytes = vec![0u8; MAX_RECORD_BYTES + 1];
        bytes[0..2].copy_from_slice(&WIRE_MAGIC.to_le_bytes());
        bytes[2] = WIRE_VERSION;
        bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
        bytes[6..8].copy_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
        bytes[40..44].copy_from_slice(&((MAX_RECORD_BYTES + 1) as u32).to_le_bytes());
        assert_eq!(decode(&bytes), Err(DecodeError::Oversize((MAX_RECORD_BYTES + 1) as u32)));
    }
}

#[cfg(test)]
mod proptests {
    //! Hostile-input doctrine: the decoder consumes attacker-controlled
    //! bytes (any SYSTEM/Admin process can drain the device), so arbitrary
    //! and mutated inputs may be rejected but must never panic, over-read,
    //! or over-allocate.

    use proptest::prelude::*;

    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]

        #[test]
        fn arbitrary_bytes_decode_without_panicking(input in any::<Vec<u8>>()) {
            let _ = decode(&input);
            let _ = decode_all(&input);
        }

        #[test]
        fn fixture_with_flipped_bytes_decodes_without_panicking(
            index in 0usize..4096,
            delta in 1u8..=255,
        ) {
            let Ok(mut bytes) = std::fs::read(golden_fixture_path()) else {
                return Ok(());
            };
            if let Some(slot) = bytes.get_mut(index) {
                *slot = slot.wrapping_add(delta);
            }
            let _ = decode_all(&bytes);
        }
    }
}
