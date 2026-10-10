#pragma once

#include <stddef.h> // offsetof — freestanding, safe in kernel mode

// secoutfall driver <-> user-mode wire format, v2 (D1).
//
// v1 inherited the WKP SysMon base layout: no magic/version, `short` sizes,
// fixed name buffers with unchecked copies. v2 is the hardened contract:
//   - magic + version in every record header,
//   - total record size as u32; per-string lengths u16 capped well below
//     that, with per-field truncation flags in the header,
//   - process identity = (pid, creation time) — never pid alone (recycling),
//   - a per-boot monotonic sequence for ordering,
//   - loss counters and stats surfaced via a dedicated IOCTL.
//
// The canonical fixture for BOTH sides lives in driver/tests/golden_v2.bin:
// the `wiretest` host tool generates/verifies it (C side), and
// crates/protocol/src/driver_wire.rs decodes it (Rust side). Changing this
// file without regenerating the fixture and the Rust mirror breaks the
// golden tests — by design.

#define SECOUTFALL_NAME L"secoutfall"

#define SECOUTFALL_WIRE_MAGIC 0x5346   // 'SF'
#define SECOUTFALL_WIRE_VERSION 2

// Record types (wire enum, stable values).
enum RecordType : USHORT {
	ProcessCreated = 1,
	ProcessExited = 2,
	ThreadCreated = 3,
	ThreadExited = 4,
	ImageLoaded = 5,
	RegistryKeyCreated = 6,
	RegistryKeyDeleted = 7,
	RegistrySetValue = 8,
	FileCreated = 9,
	FileWritten = 10,
	FileCleanedUp = 11,
	FileDeleted = 12,
	FileRenamed = 13,
	DropCaptured = 14,
};

// Truncation flags (header TruncFlags): which variable-length field hit its
// cap. A consumer must treat flagged strings as PREFIXES of the truth.
const UCHAR TRUNC_NONE = 0x00;
const UCHAR TRUNC_CMDLINE = 0x01;
const UCHAR TRUNC_KEY_PATH = 0x02;
const UCHAR TRUNC_VALUE_NAME = 0x04;
const UCHAR TRUNC_DATA = 0x08;
const UCHAR TRUNC_IMAGE_NAME = 0x10;
const UCHAR TRUNC_FILE_PATH = 0x20;
const UCHAR TRUNC_OLD_PATH = 0x40;
const UCHAR TRUNC_NEW_PATH = 0x80;

// String caps in BYTES (whole WCHARs on the wire). All fit u16 lengths.
const USHORT MaxCommandLineBytes = 8192;
const USHORT MaxKeyPathBytes = 1024;
const USHORT MaxValueNameBytes = 512;
const USHORT MaxImageNameBytes = 1024;
const USHORT MaxFilePathBytes = 1024;
const ULONG MaxValueDataBytes = 128;

//
// Record layout: RecordHeader followed by the type-specific fixed payload
// and variable-length WCHAR data. All offsets are from the record start.
// Natural x64 alignment, little-endian; no #pragma pack — the static_asserts
// pin every offset and the total header size.
//
struct RecordHeader {
	USHORT Magic;              // +0  SECOUTFALL_WIRE_MAGIC
	UCHAR Version;             // +2  SECOUTFALL_WIRE_VERSION
	UCHAR TruncFlags;          // +3  TRUNC_*
	USHORT Type;               // +4  RecordType
	USHORT HeaderSize;         // +6  sizeof(RecordHeader)
	ULONG ProcessId;           // +8
	ULONG64 Sequence;          // +16 per-boot monotonic
	ULONG64 Time;              // +24 system time at the event
	ULONG64 ProcessCreateTime; // +32 identity token; 0 = pre-load process
	ULONG Size;                // +40 total record bytes (header included)
};                             // sizeof = 48

struct ProcessCreatedRecord {
	RecordHeader Header;       // +0
	ULONG ParentProcessId;     // +48
	USHORT CommandLineOffset;  // +52 from record start; 0 = absent
	USHORT CommandLineBytes;   // +54 whole WCHARs
	// WCHAR CommandLine[] at CommandLineOffset (when non-zero)
};

struct ProcessExitedRecord {
	RecordHeader Header;       // +0
	// exit status intentionally omitted: our taxonomy models liveness, not
	// exit codes; add behind a version bump if scoring ever needs it.
};

struct ThreadRecord {
	RecordHeader Header;       // +0
	ULONG ThreadId;            // +48
};

struct ImageLoadedRecord {
	RecordHeader Header;       // +0
	ULONG64 ImageBase;         // +48
	ULONG ImageSize;           // +56
	USHORT NameOffset;         // +60 from record start
	USHORT NameBytes;          // +62 whole WCHARs
	// WCHAR Name[] at NameOffset
};

struct RegistryKeyRecord {
	RecordHeader Header;       // +0
	USHORT PathOffset;         // +48 from record start
	USHORT PathBytes;          // +50 whole WCHARs
	// WCHAR Path[] at PathOffset
};

struct RegistrySetValueRecord {
	RecordHeader Header;       // +0
	USHORT KeyPathOffset;      // +48 from record start
	USHORT KeyPathBytes;       // +50 whole WCHARs
	USHORT ValueNameOffset;    // +52 from record start
	USHORT ValueNameBytes;     // +54 whole WCHARs
	ULONG DataType;            // +56 REG_* value type
	ULONG DataBytes;           // +60 bytes actually copied (<= MaxValueDataBytes)
	// WCHAR KeyPath[] at KeyPathOffset
	// WCHAR ValueName[] at ValueNameOffset
	// UCHAR Data[] at the end (after ValueName)
};

// created / cleaned_up / deleted: one path, no byte counts.
struct FileRecord {
	RecordHeader Header;       // +0
	USHORT PathOffset;         // +48 from record start
	USHORT PathBytes;          // +50 whole WCHARs
	// WCHAR Path[] at PathOffset
};

struct FileWrittenRecord {
	RecordHeader Header;       // +0
	ULONG64 ByteOffset;        // +48 start of the write
	ULONG BytesCount;          // +56 write length
	USHORT PathOffset;         // +60 from record start
	USHORT PathBytes;          // +62 whole WCHARs
	// WCHAR Path[] at PathOffset
};

struct FileRenamedRecord {
	RecordHeader Header;       // +0
	USHORT OldPathOffset;      // +48 from record start (pre-rename name)
	USHORT OldPathBytes;       // +50 whole WCHARs
	USHORT NewPathOffset;      // +52 from record start
	USHORT NewPathBytes;       // +54 whole WCHARs
	// WCHAR OldPath[] at OldPathOffset
	// WCHAR NewPath[] at NewPathOffset
};

// Drop evidence preserved into the drops directory. StoredName is driver-
// generated ("drop-<counter><ext>"), so its truncation flag (TRUNC_NEW_PATH,
// reused as the generic second-path flag here) never fires in practice —
// only the ORIGINAL path can hit a cap (TRUNC_FILE_PATH).
struct DropCapturedRecord {
	RecordHeader Header;       // +0
	USHORT PathOffset;         // +48 original file path
	USHORT PathBytes;          // +50 whole WCHARs
	USHORT StoredOffset;       // +52 stored name inside the drops directory
	USHORT StoredBytes;        // +54 whole WCHARs
	ULONG Method;              // +56 DROP_METHOD_*
	// WCHAR Path[] at PathOffset
	// WCHAR StoredName[] at StoredOffset
};

const ULONG DROP_METHOD_HARDLINK = 0;
const ULONG DROP_METHOD_COPY = 1;

// Kernel-side loss/diagnostic counters (also the wire shape of
// IOCTL_SECOUTFALL_GET_STATS: magic + version prefixed, stats only — the
// client checks them the same way as records).
struct DriverStats {
	USHORT Magic;
	UCHAR Version;
	UCHAR Reserved;
	ULONG QueueDepth;
	ULONG QueueCapacity;
	ULONG FileQueueDepth;
	ULONG FileQueueCapacity;
	ULONG DropsQueueDepth;
	ULONG DropsQueueCapacity;
	ULONG64 Sequence;          // last assigned sequence == records emitted
	ULONG64 QueueOverwritten;  // drop-oldest events, control class
	ULONG64 AllocFailures;     // pool allocation failures in callbacks
	ULONG64 OversizedSkipped;  // drain-side skip+count
	ULONG64 IdentityMisses;    // identity lookups for unknown pids
	ULONG64 FilesOverwritten;  // drop-oldest events, file class
	ULONG64 FileNameQueriesFailed; // name query failures (skipped records)
	ULONG64 NoiseWritesSkipped;    // write-noise heuristic skips
	ULONG64 DropsStopped;      // drops-class stop-collect events (queue full)
	ULONG64 DropsMissedBusy;   // capture attempts above APC_LEVEL (rare)
	ULONG64 DropsLinkFailed;   // hard-link failures that fell back to copy
	ULONG64 DropsCopyFailed;   // stream-copy failures at cleanup
};

// Fixed payload extents ON THE WIRE: header + payload FIELDS, excluding any
// struct tail padding (records are byte-packed — the next record starts at
// `Size`, so sizeof(ThreadRecord)'s 56-byte tail-padded form never goes on
// the wire). static_asserts keep the constants honest against the structs.
const ULONG ProcessExitedFixed = sizeof(ProcessExitedRecord);       // 48
const ULONG ProcessCreatedFixed = sizeof(ProcessCreatedRecord);     // 56
const ULONG ThreadFixed = 52;
const ULONG ImageLoadedFixed = sizeof(ImageLoadedRecord);           // 64
const ULONG RegistryKeyFixed = 52;
const ULONG RegistrySetValueFixed = sizeof(RegistrySetValueRecord); // 64
const ULONG FileFixed = 52;
const ULONG FileWrittenFixed = sizeof(FileWrittenRecord);           // 64
const ULONG FileRenamedFixed = sizeof(FileRenamedRecord);           // 56
const ULONG DropCapturedFixed = 60;
static_assert(offsetof(ThreadRecord, ThreadId) + sizeof(ULONG) == ThreadFixed, "wire layout pinned");
static_assert(offsetof(RegistryKeyRecord, PathBytes) + sizeof(USHORT) == RegistryKeyFixed, "wire layout pinned");
static_assert(offsetof(FileRecord, PathBytes) + sizeof(USHORT) == FileFixed, "wire layout pinned");

// IOCTLs. Unsigned literals: 0x8000 << 16 would overflow int (UB) and the
// value would stop being a constant expression (unusable as a case label).
#define IOCTL_SECOUTFALL_GET_DATA \
	CTL_CODE(0x8000u, 0x800u, METHOD_OUT_DIRECT, FILE_READ_ACCESS)
#define IOCTL_SECOUTFALL_GET_STATS \
	CTL_CODE(0x8000u, 0x801u, METHOD_BUFFERED, FILE_READ_ACCESS)
// Enables/disables file telemetry (flood class stays silent until asked):
// input is a FILE_WATCH_POLICY blob. SDDL-gated like every other IOCTL.
#define IOCTL_SECOUTFALL_SET_FILE_WATCH \
	CTL_CODE(0x8000u, 0x802u, METHOD_BUFFERED, FILE_WRITE_ACCESS)
// Test hook (lab only): enqueues Count synthetic records of Class
// (0 = control, 1 = file) to drive overflow counters and the merged drain
// without a minifilter storm. SYSTEM/Admins only via the device SDDL.
#define IOCTL_SECOUTFALL_SELFTEST_FLOOD \
	CTL_CODE(0x8000u, 0x803u, METHOD_BUFFERED, FILE_WRITE_ACCESS)
// Arms drop capture: extensions (same NUL-terminated blob form as
// SET_FILE_WATCH) + the drops DIRECTORY in normalized NT form
// (e.g. \Device\HarddiskVolume2\Drops). Directory is created on first use.
#define IOCTL_SECOUTFALL_SET_DROP_POLICY \
	CTL_CODE(0x8000u, 0x804u, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Input blob for IOCTL_SECOUTFALL_SET_FILE_WATCH: ExtensionsCount UTF-16
// names (with the dot, e.g. L".exe"), each NUL-terminated, concatenated after
// the header (ExtensionsBytes includes the terminators). An empty list means
// ALL files; Enabled = FALSE turns file telemetry off.
struct FileWatchPolicy {
	UCHAR Enabled;
	UCHAR Reserved[3];
	ULONG ExtensionsCount;
	ULONG ExtensionsBytes; // total blob bytes, terminators included
	// WCHAR extensions[]: name L"ext" L"\0" name L"ext" L"\0" ...
};

// Input blob for IOCTL_SECOUTFALL_SELFTEST_FLOOD. Class 0 = control queue,
// 1 = file queue. Synthetic records carry pid 0xDEAD0000+i / path "\\??\\flood".
struct SelftestFloodRequest {
	ULONG Class;
	ULONG Count;
};

// Input blob for IOCTL_SECOUTFALL_SET_DROP_POLICY: extension names
// (NUL-terminated UTF-16, same form as SET_FILE_WATCH) followed by the drops
// directory (NUL-terminated UTF-16, normalized NT form).
struct DropPolicy {
	UCHAR Enabled;
	UCHAR Reserved[3];
	ULONG ExtensionsCount;
	ULONG ExtensionsBytes; // total extension blob bytes, terminators included
	ULONG DirBytes;        // directory blob bytes, terminator included
	// WCHAR extensions[] then WCHAR directory[]
};

static_assert(sizeof(RecordHeader) == 48, "wire header layout pinned");
static_assert(offsetof(RecordHeader, Magic) == 0, "wire header layout pinned");
static_assert(offsetof(RecordHeader, Version) == 2, "wire header layout pinned");
static_assert(offsetof(RecordHeader, TruncFlags) == 3, "wire header layout pinned");
static_assert(offsetof(RecordHeader, Type) == 4, "wire header layout pinned");
static_assert(offsetof(RecordHeader, HeaderSize) == 6, "wire header layout pinned");
static_assert(offsetof(RecordHeader, ProcessId) == 8, "wire header layout pinned");
static_assert(offsetof(RecordHeader, Sequence) == 16, "wire header layout pinned");
static_assert(offsetof(RecordHeader, Time) == 24, "wire header layout pinned");
static_assert(offsetof(RecordHeader, ProcessCreateTime) == 32, "wire header layout pinned");
static_assert(offsetof(RecordHeader, Size) == 40, "wire header layout pinned");
static_assert(offsetof(ProcessCreatedRecord, ParentProcessId) == 48, "wire layout pinned");
static_assert(offsetof(ProcessCreatedRecord, CommandLineOffset) == 52, "wire layout pinned");
static_assert(offsetof(ProcessCreatedRecord, CommandLineBytes) == 54, "wire layout pinned");
static_assert(offsetof(ThreadRecord, ThreadId) == 48, "wire layout pinned");
static_assert(offsetof(ImageLoadedRecord, ImageBase) == 48, "wire layout pinned");
static_assert(offsetof(ImageLoadedRecord, ImageSize) == 56, "wire layout pinned");
static_assert(offsetof(ImageLoadedRecord, NameOffset) == 60, "wire layout pinned");
static_assert(offsetof(ImageLoadedRecord, NameBytes) == 62, "wire layout pinned");
static_assert(offsetof(RegistryKeyRecord, PathOffset) == 48, "wire layout pinned");
static_assert(offsetof(RegistryKeyRecord, PathBytes) == 50, "wire layout pinned");
static_assert(offsetof(RegistrySetValueRecord, KeyPathOffset) == 48, "wire layout pinned");
static_assert(offsetof(RegistrySetValueRecord, KeyPathBytes) == 50, "wire layout pinned");
static_assert(offsetof(RegistrySetValueRecord, ValueNameOffset) == 52, "wire layout pinned");
static_assert(offsetof(RegistrySetValueRecord, ValueNameBytes) == 54, "wire layout pinned");
static_assert(offsetof(RegistrySetValueRecord, DataType) == 56, "wire layout pinned");
static_assert(offsetof(RegistrySetValueRecord, DataBytes) == 60, "wire layout pinned");
static_assert(offsetof(FileRecord, PathOffset) == 48, "wire layout pinned");
static_assert(offsetof(FileRecord, PathBytes) == 50, "wire layout pinned");
static_assert(offsetof(FileWrittenRecord, ByteOffset) == 48, "wire layout pinned");
static_assert(offsetof(FileWrittenRecord, BytesCount) == 56, "wire layout pinned");
static_assert(offsetof(FileWrittenRecord, PathOffset) == 60, "wire layout pinned");
static_assert(offsetof(FileWrittenRecord, PathBytes) == 62, "wire layout pinned");
static_assert(offsetof(FileRenamedRecord, OldPathOffset) == 48, "wire layout pinned");
static_assert(offsetof(FileRenamedRecord, OldPathBytes) == 50, "wire layout pinned");
static_assert(offsetof(FileRenamedRecord, NewPathOffset) == 52, "wire layout pinned");
static_assert(offsetof(FileRenamedRecord, NewPathBytes) == 54, "wire layout pinned");
static_assert(offsetof(DropCapturedRecord, PathOffset) == 48, "wire layout pinned");
static_assert(offsetof(DropCapturedRecord, PathBytes) == 50, "wire layout pinned");
static_assert(offsetof(DropCapturedRecord, StoredOffset) == 52, "wire layout pinned");
static_assert(offsetof(DropCapturedRecord, StoredBytes) == 54, "wire layout pinned");
static_assert(offsetof(DropCapturedRecord, Method) == 56, "wire layout pinned");
