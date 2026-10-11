//! Driver control port (driven): the agent's policy + status channel to the
//! kernel driver. The composition root pushes the `[driver]` config through
//! this port at startup; the real adapter wraps `DeviceIoControl` against
//! `\\.\secoutfall` (feature `driver`), the fake records calls for tests.
//!
//! The control-plane CONTRACT lives here, not in the adapter: the IOCTL
//! codes ([`codes`]), the policy blob encoders and the stats decoder are
//! pure, compiled on every host, and pinned byte-exact against fixtures the
//! C tool emits (`driver/tests/emit_*.bin` — the C structs are the
//! authority). The whole-project review found the old arrangement — adapter-
//! local hand serialization — had drifted from the C contract in five places
//! (wrong IOCTL methods, misordered stats fields, two mis-shaped policy
//! blobs); the pins make that class structurally impossible.

use std::collections::HashMap;

/// Injection policy: sensor DLL path + extra per-process exclusions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InjectionPolicy {
    /// Sensor DLL path (verbatim to `LdrLoadDll` — NT form recommended).
    pub sensor_path: String,
    /// Extra per-process exclusion names (with extension).
    pub exclusions: Vec<String>,
}

/// Drop-capture policy: target directory + extension filter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DropPolicy {
    /// Drops directory in normalized NT form.
    pub dir: String,
    /// Extension filter (with the dot; empty = all files).
    pub extensions: Vec<String>,
}

/// Protection policy: process names with `ObCallbacks` handle-stripping.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProtectionPolicy {
    /// Protected image names (with extension).
    pub names: Vec<String>,
}

/// Every policy in one application — atomic from the agent's perspective
/// (the adapter serializes each blob; order between them is irrelevant).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DriverPolicies {
    /// Sensor injection (disabled when the path is empty).
    pub injection: Option<InjectionPolicy>,
    /// Drop capture (disabled when the dir is empty).
    pub drops: Option<DropPolicy>,
    /// Process protection (disabled when the name list is empty).
    pub protection: Option<ProtectionPolicy>,
}

/// Loss/health snapshot from the driver (`GET_STATS`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DriverStatsSnapshot {
    /// Control-queue depth.
    pub queue_depth: u32,
    /// Control-queue capacity.
    pub queue_capacity: u32,
    /// File-queue depth.
    pub file_queue_depth: u32,
    /// File-queue capacity.
    pub file_queue_capacity: u32,
    /// Drops-queue depth.
    pub drops_queue_depth: u32,
    /// Drops-queue capacity.
    pub drops_queue_capacity: u32,
    /// Last assigned per-boot sequence.
    pub sequence: u64,
    /// Control-class drop-oldest events.
    pub queue_overwritten: u64,
    /// Pool allocation failures in callbacks.
    pub alloc_failures: u64,
    /// Drain-side oversized skip+count.
    pub oversized_skipped: u64,
    /// Identity lookups for unknown pids.
    pub identity_misses: u64,
    /// File-class drop-oldest events.
    pub files_overwritten: u64,
    /// File-name query failures (skipped records).
    pub file_name_queries_failed: u64,
    /// Write-noise heuristic skips.
    pub noise_writes_skipped: u64,
    /// Drops-class stop-collect events (queue full).
    pub drops_stopped: u64,
    /// Capture attempts above `PASSIVE_LEVEL`.
    pub drops_missed_busy: u64,
    /// Hard-link failures that fell back to copy.
    pub drops_link_failed: u64,
    /// Stream-copy failures at cleanup.
    pub drops_copy_failed: u64,
    /// APCs queued onto first threads.
    pub injections_queued: u64,
    /// Injection allocation / thread-gone / queue failures.
    pub injections_failed: u64,
    /// Nonce echoes accepted.
    pub sensors_registered: u64,
    /// Challenge/register denials.
    pub sensors_rejected: u64,
    /// Ring slots promoted to records.
    pub sensor_events_drained: u64,
    /// Slots skipped: torn, stale or garbage.
    pub sensor_events_dropped: u64,
    /// Currently registered sensors with rings (u64 in the C struct).
    pub sensor_rings_active: u64,
    /// Handle-open attempts stripped.
    pub protections_stripped: u64,
    /// Attempts allowed (trusted caller).
    pub protection_trusted: u64,
}

/// The device SDDL the agent pushes: the driver's compiled SDDL
/// (SYSTEM + Administrators, `GA`) plus, when a console-session user exists,
/// a generic-all ACE for that user — the sensor reaches the device from a
/// non-elevated target. Pure: the adapter does the Win32 conversion.
#[must_use]
pub fn device_security_sddl(console_user_sid: Option<&str>) -> String {
    match console_user_sid {
        Some(sid) => format!(r"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{sid})"),
        None => r"D:P(A;;GA;;;SY)(A;;GA;;;BA)".to_owned(),
    }
}

/// The complete IOCTL code table. The values are computed by the `CTL_CODE`
/// formula (const-evaluated, so no hand arithmetic can slip in) and pinned
/// against the C compiler's own macro expansion: `wiretest --emit codes`
/// prints the codes straight from `secoutfallCommon.h`, the fixture is
/// committed (`driver/tests/emit_codes.txt`), and the test below asserts
/// equality line by line. The review found two hand-derived methods wrong
/// (driver source dead against the real device) AND the injectee's
/// handshake codes broken the same way — after which the parent agent
/// reintroduced the same class of bug hand-writing hex literals. Formula +
/// C-fixture, never hand hex.
pub mod codes {
    const fn ctl_code(device: u32, function: u32, method: u32, access: u32) -> u32 {
        (device << 16) | (access << 14) | (function << 2) | method
    }

    const DEVICE: u32 = 0x8000;
    const METHOD_BUFFERED: u32 = 0;
    const METHOD_OUT_DIRECT: u32 = 2;
    const FILE_READ_ACCESS: u32 = 1;
    const FILE_WRITE_ACCESS: u32 = 2;

    /// The event-record drain (`GET_DATA`): the OUT buffer is an MDL, so the
    /// method is `OUT_DIRECT` — the review found method `IN_DIRECT` here, which
    /// made every drain call fail against the real device.
    pub const GET_DATA: u32 = ctl_code(DEVICE, 0x800, METHOD_OUT_DIRECT, FILE_READ_ACCESS);
    /// The [`DriverStatsSnapshot`] query — `METHOD_BUFFERED`, not `OUT_DIRECT`
    /// (the second wrong-method finding; the agent's constant was even
    /// mislabeled `METHOD_OUT_DIRECT` while holding method 1).
    pub const GET_STATS: u32 = ctl_code(DEVICE, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS);
    /// File-telemetry extension filter (reserved; the agent does not send
    /// it yet — the driver's boot default applies).
    pub const SET_FILE_WATCH: u32 = ctl_code(DEVICE, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS);
    /// Lab-only self-flood; never sent by the agent.
    pub const SELFTEST_FLOOD: u32 = ctl_code(DEVICE, 0x803, METHOD_BUFFERED, FILE_WRITE_ACCESS);
    /// Drop-capture policy push.
    pub const SET_DROP_POLICY: u32 = ctl_code(DEVICE, 0x804, METHOD_BUFFERED, FILE_WRITE_ACCESS);
    /// Sensor-injection policy push.
    pub const SET_INJECTION_POLICY: u32 =
        ctl_code(DEVICE, 0x805, METHOD_BUFFERED, FILE_WRITE_ACCESS);
    /// Sensor handshake step 1 (the injectee mirrors this value).
    pub const SENSOR_CHALLENGE: u32 = ctl_code(DEVICE, 0x806, METHOD_BUFFERED, FILE_READ_ACCESS);
    /// Sensor handshake step 2 (the injectee mirrors this value).
    pub const SENSOR_REGISTER: u32 = ctl_code(DEVICE, 0x807, METHOD_BUFFERED, FILE_WRITE_ACCESS);
    /// `ObCallbacks` protection name push.
    pub const SET_PROTECTED: u32 = ctl_code(DEVICE, 0x808, METHOD_BUFFERED, FILE_WRITE_ACCESS);
    /// Device-DACL replacement.
    pub const SET_DEVICE_SECURITY: u32 =
        ctl_code(DEVICE, 0x809, METHOD_BUFFERED, FILE_WRITE_ACCESS);
}

/// UTF-16LE bytes of `value` including the NUL terminator — the wire form of
/// every policy string.
fn wide_nul(value: &str) -> Vec<u8> {
    let mut blob: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
    blob.extend_from_slice(&0u16.to_le_bytes());
    blob
}

/// Wire bytes of a NUL-separated UTF-16 list, C-array convention: every
/// entry carries its NUL AND the list as a whole carries the array's
/// implicit terminating NUL (the driver's writers derive byte counts from
/// `sizeof(WCHAR[])`, so the last entry is double-terminated and the counts
/// include it). The driver's parsers consume that shape; the first fixture
/// comparison caught the difference.
fn wide_list(values: &[String]) -> Vec<u8> {
    let mut blob = Vec::new();
    for value in values {
        blob.extend_from_slice(&wide_nul(value));
    }
    if !values.is_empty() {
        // The implicit array terminator exists only when there IS an array;
        // an empty list (the disarm push) is zero bytes, NamesBytes = 0.
        blob.extend_from_slice(&0u16.to_le_bytes());
    }
    blob
}

/// Serializes the injection policy into the `InjectionPolicy` input blob:
/// 12-byte header `{Enabled u8, Reserved[3], DllPathBytes u32,
/// ExclusionsBytes u32}` followed by the path then the exclusion list,
/// NUL-terminated UTF-16LE (terminators included in the counts).
#[must_use]
pub fn encode_injection_policy(policy: &InjectionPolicy) -> Vec<u8> {
    let path = wide_nul(&policy.sensor_path);
    let exclusions = wide_list(&policy.exclusions);
    let mut blob = Vec::with_capacity(12 + path.len() + exclusions.len());
    blob.push(1); // Enabled
    blob.extend_from_slice(&[0; 3]);
    blob.extend_from_slice(&u32::to_le_bytes(u32::try_from(path.len()).unwrap_or(u32::MAX)));
    blob.extend_from_slice(&u32::to_le_bytes(u32::try_from(exclusions.len()).unwrap_or(u32::MAX)));
    blob.extend_from_slice(&path);
    blob.extend_from_slice(&exclusions);
    blob
}

/// Serializes the drop-capture policy into the `DropPolicy` input blob:
/// 16-byte header `{Enabled u8, Reserved[3], ExtensionsCount u32,
/// ExtensionsBytes u32, DirBytes u32}` followed by the extension list then
/// the directory (NUL-terminated UTF-16LE). The extension COUNT is a real
/// field — the review found the agent omitting it, and the driver's length
/// check then rejected every push.
#[must_use]
pub fn encode_drop_policy(policy: &DropPolicy) -> Vec<u8> {
    let extensions = wide_list(&policy.extensions);
    let dir = wide_nul(&policy.dir);
    let mut blob = Vec::with_capacity(16 + extensions.len() + dir.len());
    blob.push(1); // Enabled
    blob.extend_from_slice(&[0; 3]);
    blob.extend_from_slice(&u32::to_le_bytes(
        u32::try_from(policy.extensions.len()).unwrap_or(u32::MAX),
    ));
    blob.extend_from_slice(&u32::to_le_bytes(u32::try_from(extensions.len()).unwrap_or(u32::MAX)));
    blob.extend_from_slice(&u32::to_le_bytes(u32::try_from(dir.len()).unwrap_or(u32::MAX)));
    blob.extend_from_slice(&extensions);
    blob.extend_from_slice(&dir);
    blob
}

/// Serializes the protection policy into the `ProtectionPolicy` input blob:
/// 8-byte header `{Enabled u8, Reserved[3], NamesBytes u32}` followed by the
/// name list (NUL-terminated UTF-16LE). ONE byte-count field — the review
/// found the agent sending a two-field 12-byte header that could never pass
/// the driver's length check (the disarm push included).
#[must_use]
pub fn encode_protection_policy(policy: &ProtectionPolicy) -> Vec<u8> {
    let names = wide_list(&policy.names);
    let mut blob = Vec::with_capacity(8 + names.len());
    blob.push(u8::from(!policy.names.is_empty())); // Enabled
    blob.extend_from_slice(&[0; 3]);
    blob.extend_from_slice(&u32::to_le_bytes(u32::try_from(names.len()).unwrap_or(u32::MAX)));
    blob.extend_from_slice(&names);
    blob
}

/// Serializes the device-security push into the `DeviceSecurityBlob`: 8-byte
/// header `{Enabled u8, Reserved[3], SdBytes u32}` followed by the raw
/// self-relative security descriptor (opaque on the wire; the driver
/// validates its shape before applying).
#[must_use]
pub fn encode_device_security(enabled: bool, security_descriptor: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(8 + security_descriptor.len());
    blob.push(u8::from(enabled));
    blob.extend_from_slice(&[0; 3]);
    blob.extend_from_slice(&u32::to_le_bytes(
        u32::try_from(security_descriptor.len()).unwrap_or(u32::MAX),
    ));
    blob.extend_from_slice(security_descriptor);
    blob
}

/// Decodes the `GET_STATS` reply (the `DriverStats` C struct, natural x64
/// alignment: 4-byte magic trio, six `ULONG`s, then 8-aligned `ULONG64`s —
/// the tail order per secoutfallCommon.h is sensors → protections → sensor
/// events → rings; the review found the agent reading protections as sensor
/// events and vice versa). Unknown trailing bytes (a LONGER driver) are
/// ignored; a short reply is an error.
///
/// # Errors
/// [`DriverControlError::Io`] when the reply is shorter than the pinned
/// struct or carries the wrong magic/version.
pub fn decode_driver_stats(bytes: &[u8]) -> Result<DriverStatsSnapshot, DriverControlError> {
    // Offsets after the 6 ULONGs (4..28): padding to 8 → u64s start at 32.
    const OFF_QUEUE_DEPTH: usize = 4;
    const OFF_QUEUE_CAPACITY: usize = 8;
    const OFF_FILE_QUEUE_DEPTH: usize = 12;
    const OFF_FILE_QUEUE_CAPACITY: usize = 16;
    const OFF_DROPS_QUEUE_DEPTH: usize = 20;
    const OFF_DROPS_QUEUE_CAPACITY: usize = 24;
    const OFF_SEQUENCE: usize = 32;
    const OFF_QUEUE_OVERWRITTEN: usize = 40;
    const OFF_ALLOC_FAILURES: usize = 48;
    const OFF_OVERSIZED_SKIPPED: usize = 56;
    const OFF_IDENTITY_MISSES: usize = 64;
    const OFF_FILES_OVERWRITTEN: usize = 72;
    const OFF_NAME_QUERIES_FAILED: usize = 80;
    const OFF_NOISE_WRITES_SKIPPED: usize = 88;
    const OFF_DROPS_STOPPED: usize = 96;
    const OFF_DROPS_MISSED_BUSY: usize = 104;
    const OFF_DROPS_LINK_FAILED: usize = 112;
    const OFF_DROPS_COPY_FAILED: usize = 120;
    const OFF_INJECTIONS_QUEUED: usize = 128;
    const OFF_INJECTIONS_FAILED: usize = 136;
    const OFF_SENSORS_REGISTERED: usize = 144;
    const OFF_SENSORS_REJECTED: usize = 152;
    const OFF_PROTECTIONS_STRIPPED: usize = 160;
    const OFF_PROTECTION_TRUSTED: usize = 168;
    const OFF_SENSOR_EVENTS_DRAINED: usize = 176;
    const OFF_SENSOR_EVENTS_DROPPED: usize = 184;
    const OFF_SENSOR_RINGS_ACTIVE: usize = 192;
    const STATS_SIZE: usize = 200;

    // Magic + version header, same trio the record stream carries.
    // SECOUTFALL_WIRE_MAGIC = 0x5346 ('SF'), SECOUTFALL_WIRE_VERSION = 2
    // (secoutfallCommon.h) — the stats fixture test pins the full layout.
    const WIRE_MAGIC: u16 = 0x5346;
    const WIRE_VERSION: u8 = 2;

    if bytes.len() < STATS_SIZE {
        return Err(DriverControlError::Io(format!(
            "stats reply too short: {} < {STATS_SIZE}",
            bytes.len()
        )));
    }
    let u16_at = |at: usize| {
        Ok::<u16, DriverControlError>(u16::from_le_bytes(
            bytes
                .get(at..at + 2)
                .ok_or_else(|| DriverControlError::Io("stats reply truncated".to_owned()))?
                .try_into()
                .map_err(|_| DriverControlError::Io("stats reply truncated".to_owned()))?,
        ))
    };
    let u32_at = |at: usize| {
        let mut b = [0u8; 4];
        b.copy_from_slice(bytes.get(at..at + 4)?);
        Some(u32::from_le_bytes(b))
    };
    let u64_at = |at: usize| {
        let mut b = [0u8; 8];
        b.copy_from_slice(bytes.get(at..at + 8)?);
        Some(u64::from_le_bytes(b))
    };
    if u16_at(0)? != WIRE_MAGIC || bytes.get(2).copied() != Some(WIRE_VERSION) {
        return Err(DriverControlError::Io("stats reply: bad magic/version".to_owned()));
    }
    let field = |at: usize| {
        u32_at(at).ok_or_else(|| DriverControlError::Io("stats reply truncated".to_owned()))
    };
    let field64 = |at: usize| {
        u64_at(at).ok_or_else(|| DriverControlError::Io("stats reply truncated".to_owned()))
    };
    Ok(DriverStatsSnapshot {
        queue_depth: field(OFF_QUEUE_DEPTH)?,
        queue_capacity: field(OFF_QUEUE_CAPACITY)?,
        file_queue_depth: field(OFF_FILE_QUEUE_DEPTH)?,
        file_queue_capacity: field(OFF_FILE_QUEUE_CAPACITY)?,
        drops_queue_depth: field(OFF_DROPS_QUEUE_DEPTH)?,
        drops_queue_capacity: field(OFF_DROPS_QUEUE_CAPACITY)?,
        sequence: field64(OFF_SEQUENCE)?,
        queue_overwritten: field64(OFF_QUEUE_OVERWRITTEN)?,
        alloc_failures: field64(OFF_ALLOC_FAILURES)?,
        oversized_skipped: field64(OFF_OVERSIZED_SKIPPED)?,
        identity_misses: field64(OFF_IDENTITY_MISSES)?,
        files_overwritten: field64(OFF_FILES_OVERWRITTEN)?,
        file_name_queries_failed: field64(OFF_NAME_QUERIES_FAILED)?,
        noise_writes_skipped: field64(OFF_NOISE_WRITES_SKIPPED)?,
        drops_stopped: field64(OFF_DROPS_STOPPED)?,
        drops_missed_busy: field64(OFF_DROPS_MISSED_BUSY)?,
        drops_link_failed: field64(OFF_DROPS_LINK_FAILED)?,
        drops_copy_failed: field64(OFF_DROPS_COPY_FAILED)?,
        injections_queued: field64(OFF_INJECTIONS_QUEUED)?,
        injections_failed: field64(OFF_INJECTIONS_FAILED)?,
        sensors_registered: field64(OFF_SENSORS_REGISTERED)?,
        sensors_rejected: field64(OFF_SENSORS_REJECTED)?,
        protections_stripped: field64(OFF_PROTECTIONS_STRIPPED)?,
        protection_trusted: field64(OFF_PROTECTION_TRUSTED)?,
        sensor_events_drained: field64(OFF_SENSOR_EVENTS_DRAINED)?,
        sensor_events_dropped: field64(OFF_SENSOR_EVENTS_DROPPED)?,
        sensor_rings_active: field64(OFF_SENSOR_RINGS_ACTIVE)?,
    })
}

#[cfg(test)]
mod pin_tests {
    //! Contract pins against the C compiler's own output. The fixtures are
    //! generated by `wiretest --emit` (built from the REAL C policy structs
    //! and macros) and committed under `driver/tests/` — regenerate them
    //! after ANY header change and these tests fail until Rust agrees.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::string_slice
    )]

    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../driver/tests/").to_owned() + name;
        std::fs::read(&path)
            .unwrap_or_else(|error| panic!("fixture {path} missing (wiretest --emit): {error}"))
    }

    /// The C compiler's macro expansion is the authority for the code table.
    #[test]
    fn ioctl_codes_match_the_c_macros() {
        let text = String::from_utf8(fixture("emit_codes.txt")).unwrap();
        let expected = [
            ("GET_DATA", codes::GET_DATA),
            ("GET_STATS", codes::GET_STATS),
            ("SET_FILE_WATCH", codes::SET_FILE_WATCH),
            ("SELFTEST_FLOOD", codes::SELFTEST_FLOOD),
            ("SET_DROP_POLICY", codes::SET_DROP_POLICY),
            ("SET_INJECTION_POLICY", codes::SET_INJECTION_POLICY),
            ("SENSOR_CHALLENGE", codes::SENSOR_CHALLENGE),
            ("SENSOR_REGISTER", codes::SENSOR_REGISTER),
            ("SET_PROTECTED", codes::SET_PROTECTED),
            ("SET_DEVICE_SECURITY", codes::SET_DEVICE_SECURITY),
        ];
        for (name, ours) in expected {
            let needle = format!("{name}=0x");
            let line = text
                .lines()
                .find(|line| line.starts_with(&needle))
                .unwrap_or_else(|| panic!("C fixture lacks {name}"));
            let theirs = u32::from_str_radix(&line[needle.len()..], 16).unwrap();
            assert_eq!(ours, theirs, "{name}: Rust {ours:#010x} != C {theirs:#010x}");
        }
    }

    #[test]
    fn injection_policy_bytes_match_the_c_struct() {
        let policy = InjectionPolicy {
            sensor_path: r"\??\C:\ProgramData\SecOutfall\sensors\boot-1f2e3d4c5b6a7988".to_owned()
                + r"\sensor-0a1b2c3d4e5f6071.dll",
            exclusions: vec!["wiretest-helper.exe".to_owned()],
        };
        assert_eq!(encode_injection_policy(&policy), fixture("emit_injection.bin"));
    }

    #[test]
    fn drop_policy_bytes_match_the_c_struct() {
        let policy = DropPolicy {
            dir: r"\??\C:\ProgramData\SecOutfall\Drops\boot-1f2e3d4c5b6a7988".to_owned(),
            extensions: vec![".exe".to_owned(), ".dll".to_owned()],
        };
        assert_eq!(encode_drop_policy(&policy), fixture("emit_drops.bin"));
    }

    #[test]
    fn protection_policy_bytes_match_the_c_struct() {
        let policy = ProtectionPolicy {
            names: vec!["secoutfall-agent.exe".to_owned(), "secoutfall-user-actor.exe".to_owned()],
        };
        assert_eq!(encode_protection_policy(&policy), fixture("emit_protection.bin"));
    }

    #[test]
    fn device_security_bytes_match_the_c_struct() {
        let sd: Vec<u8> = (0xA0u8..=0xBF).collect();
        assert_eq!(encode_device_security(true, &sd), fixture("emit_security.bin"));
    }

    #[test]
    fn stats_decode_matches_every_c_canary() {
        let stats = decode_driver_stats(&fixture("emit_stats.bin")).unwrap();
        assert_eq!(stats.queue_depth, 1);
        assert_eq!(stats.queue_capacity, 2);
        assert_eq!(stats.file_queue_depth, 3);
        assert_eq!(stats.file_queue_capacity, 4);
        assert_eq!(stats.drops_queue_depth, 5);
        assert_eq!(stats.drops_queue_capacity, 6);
        assert_eq!(stats.sequence, 0x0102_0304_0506_0708);
        assert_eq!(stats.queue_overwritten, 0x1112_1314_1516_1718);
        assert_eq!(stats.alloc_failures, 0x2122_2324_2526_2728);
        assert_eq!(stats.oversized_skipped, 0x3132_3334_3536_3738);
        assert_eq!(stats.identity_misses, 0x4142_4344_4546_4748);
        assert_eq!(stats.files_overwritten, 0x5152_5354_5556_5758);
        assert_eq!(stats.file_name_queries_failed, 0x6162_6364_6566_6768);
        assert_eq!(stats.noise_writes_skipped, 0x7172_7374_7576_7778);
        assert_eq!(stats.drops_stopped, 0x8182_8384_8586_8788);
        assert_eq!(stats.drops_missed_busy, 0x9192_9394_9596_9798);
        assert_eq!(stats.drops_link_failed, 0xA1A2_A3A4_A5A6_A7A8);
        assert_eq!(stats.drops_copy_failed, 0xB1B2_B3B4_B5B6_B7B8);
        assert_eq!(stats.injections_queued, 0xC1C2_C3C4_C5C6_C7C8);
        assert_eq!(stats.injections_failed, 0xD1D2_D3D4_D5D6_D7D8);
        assert_eq!(stats.sensors_registered, 0xE1E2_E3E4_E5E6_E7E8);
        assert_eq!(stats.sensors_rejected, 0xF1F2_F3F4_F5F6_F7F8);
        // The canaries make an offset swap visible: these five fields were
        // misread as each other before the review (protections vs sensor
        // events). Values are the C fixture's, nibble for nibble.
        assert_eq!(stats.protections_stripped, 0x090A_0B0C_0D0E_0F10);
        assert_eq!(stats.protection_trusted, 0x192A_2B2C_2D2E_2F30);
        assert_eq!(stats.sensor_events_drained, 0x394A_4B4C_4D4E_4F50);
        assert_eq!(stats.sensor_events_dropped, 0x596A_6B6C_6D6E_6F70);
        assert_eq!(stats.sensor_rings_active, 0x798A_8B8C_8D8E_8F90);
    }

    #[test]
    fn short_stats_reply_is_an_error_not_a_panic() {
        let bytes = fixture("emit_stats.bin");
        assert!(decode_driver_stats(&bytes[..199]).is_err());
        assert!(decode_driver_stats(&[]).is_err());
    }

    #[test]
    fn encoders_terminate_every_string_with_nul() {
        let policy = encode_injection_policy(&InjectionPolicy {
            sensor_path: "x.dll".to_owned(),
            exclusions: vec!["a.exe".to_owned(), "b.exe".to_owned()],
        });
        // "x.dll" = 5 chars + NUL = 12 bytes (single-string paths carry one
        // terminator). The exclusion LIST is C-array-shaped: each entry +
        // NUL, then the implicit list terminator (a double NUL on the last
        // entry): 12 + 12 + 2 = 26.
        let path_bytes = 12_u32;
        let excl_bytes = 26_u32;
        assert_eq!(&policy[..4], &[1, 0, 0, 0]);
        assert_eq!(&policy[4..8], &u32::to_le_bytes(path_bytes));
        assert_eq!(&policy[8..12], &u32::to_le_bytes(excl_bytes));
        assert_eq!(policy.len(), 12 + path_bytes as usize + excl_bytes as usize);
        // The double terminator is really there.
        assert_eq!(&policy[policy.len() - 4..], &[0, 0, 0, 0]);

        // Disarm push (enabled = 0, no names) is a VALID 8-byte blob —
        // the old 12-byte header shape could not even disarm.
        let disarm = encode_protection_policy(&ProtectionPolicy::default());
        assert_eq!(disarm, vec![0, 0, 0, 0, 0, 0, 0, 0]);
    }
}

/// Errors from the control device.
#[derive(Debug, thiserror::Error)]
pub enum DriverControlError {
    /// The control device is not present (driver not installed/started).
    #[error("driver device not found: \\\\.\\secoutfall")]
    DeviceMissing,
    /// The driver rejected a policy (invalid blob or resource failure).
    #[error("driver rejected policy: {0}")]
    Rejected(String),
    /// Any other Win32 failure, message carries the context.
    #[error("driver control io error: {0}")]
    Io(String),
}

/// Driven port: agent → driver policy + status channel.
pub trait DriverControlPort: Send + Sync + 'static {
    /// Applies all policies. Idempotent; safe to re-send on config reload.
    ///
    /// # Errors
    /// [`DriverControlError`] when the device is missing or a policy is
    /// rejected.
    fn apply_policies(&self, policies: &DriverPolicies) -> Result<(), DriverControlError>;

    /// Replaces the device object's DACL. `sddl` is an SDDL string; the
    /// adapter converts it to a self-relative descriptor. Idempotent.
    ///
    /// Used to grant the console-session user access so the injected sensor
    /// (running in the analysis user's context) can reach the device for its
    /// challenge/register handshake from a non-elevated target.
    ///
    /// # Errors
    /// [`DriverControlError`] when the device is missing or the driver
    /// rejects the descriptor.
    fn apply_device_security(&self, sddl: &str) -> Result<(), DriverControlError>;

    /// Queries the loss/health snapshot.
    ///
    /// # Errors
    /// [`DriverControlError`] when the device is missing or the stats blob
    /// is malformed.
    fn query_stats(&self) -> Result<DriverStatsSnapshot, DriverControlError>;

    /// Loss counters keyed for reporting (default: flattened snapshot).
    ///
    /// # Errors
    /// [`DriverControlError`] from [`Self::query_stats`].
    fn loss_counters(&self) -> Result<HashMap<String, u64>, DriverControlError> {
        let stats = self.query_stats()?;
        let mut map = HashMap::new();
        map.insert("queue_overwritten".to_owned(), stats.queue_overwritten);
        map.insert("alloc_failures".to_owned(), stats.alloc_failures);
        map.insert("oversized_skipped".to_owned(), stats.oversized_skipped);
        map.insert("identity_misses".to_owned(), stats.identity_misses);
        map.insert("files_overwritten".to_owned(), stats.files_overwritten);
        map.insert("file_name_queries_failed".to_owned(), stats.file_name_queries_failed);
        map.insert("noise_writes_skipped".to_owned(), stats.noise_writes_skipped);
        map.insert("drops_stopped".to_owned(), stats.drops_stopped);
        map.insert("drops_missed_busy".to_owned(), stats.drops_missed_busy);
        map.insert("drops_link_failed".to_owned(), stats.drops_link_failed);
        map.insert("drops_copy_failed".to_owned(), stats.drops_copy_failed);
        map.insert("injections_queued".to_owned(), stats.injections_queued);
        map.insert("injections_failed".to_owned(), stats.injections_failed);
        map.insert("sensors_registered".to_owned(), stats.sensors_registered);
        map.insert("sensors_rejected".to_owned(), stats.sensors_rejected);
        map.insert("sensor_events_drained".to_owned(), stats.sensor_events_drained);
        map.insert("sensor_events_dropped".to_owned(), stats.sensor_events_dropped);
        map.insert("protections_stripped".to_owned(), stats.protections_stripped);
        map.insert("protection_trusted".to_owned(), stats.protection_trusted);
        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn device_sddl_covers_system_admins_and_optional_console_user() {
        assert_eq!(device_security_sddl(None), r"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
        assert_eq!(
            device_security_sddl(Some("S-1-5-21-1004336348-1176667385-1801674531-1001")),
            r"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;S-1-5-21-1004336348-1176667385-1801674531-1001)"
        );
        // Degenerate input cannot break the builder's shape; the driver's
        // SD validation stays the real gate.
        assert!(device_security_sddl(Some("")).ends_with("(A;;GA;;;)"));
    }
}
