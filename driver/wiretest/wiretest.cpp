// wiretest — pins the secoutfall wire-v2 contract on the C side.
//
//   wiretest --generate <file>   writes the canonical fixture (deterministic)
//   wiretest --verify <file>     byte-exact compares against the fixture
//   wiretest --emit <name> <file> writes one control-plane blob (deterministic)
//                                name: injection | drops | filewatch |
//                                      protection | security | stats |
//                                      minimal-rename
//
// The record fixture (driver/tests/golden_v2.bin) is committed: the same
// bytes are decoded by crates/protocol/src/driver_wire.rs golden tests, so
// the C and Rust interpretations of the wire format cannot drift apart
// silently. The --emit blobs pin the CONTROL plane (policy structs, stats
// layout) the same way — the review that found the IOCTL/policy drift made
// these fixtures mandatory: any schema change must regenerate the fixture
// AND update the Rust mirror — both golden tests fail until they agree.
//
// Records are built from the REAL wire structs (offsets pinned by
// static_asserts in secoutfallCommon.h) — hand-packed byte writers would
// silently diverge from the compiler's implicit alignment padding.

#include <windows.h> // ULONG/USHORT/UCHAR/REG_SZ — secoutfallCommon.h relies on the platform types
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "..\secoutfall\secoutfallCommon.h"

namespace {

// Deterministic constants — the fixture must be byte-stable across runs.
constexpr ULONG64 TimeBase = 0x01D9000000000000ull;
constexpr ULONG64 IdentityBase = 0x01C8000000000000ull;

std::vector<BYTE> g_out;
ULONG64 g_seq = 0;

// Raw append of exactly `bytes` — the WIRE extent of a fixed part (struct
// tail padding is never on the wire; see the *Fixed constants).
void AppendRaw(const void* data, size_t bytes) {
	auto p = static_cast<const BYTE*>(data);
	g_out.insert(g_out.end(), p, p + bytes);
}

void AppendWstr(const std::wstring& s) {
	AppendRaw(s.data(), s.size() * sizeof(WCHAR));
}

RecordHeader MakeHeader(RecordType type, ULONG pid, ULONG64 createTime, UCHAR truncFlags, ULONG totalSize) {
	RecordHeader header {};
	header.Magic = SECOUTFALL_WIRE_MAGIC;
	header.Version = SECOUTFALL_WIRE_VERSION;
	header.TruncFlags = truncFlags;
	header.Type = static_cast<USHORT>(type);
	header.HeaderSize = sizeof(RecordHeader);
	header.ProcessId = pid;
	header.Sequence = ++g_seq;
	header.Time = TimeBase + header.Sequence;
	header.ProcessCreateTime = createTime;
	header.Size = totalSize;
	return header;
}

// Emulates the driver's clamping (CopyNameW): whole WCHARs, capped, truncation
// reported — so the fixture exercises the truncation-flag path.
std::wstring Clamp(const std::wstring& s, USHORT capBytes, bool& truncated) {
	auto bytes = static_cast<USHORT>(min(s.size() * sizeof(WCHAR), static_cast<size_t>(capBytes)));
	bytes &= static_cast<USHORT>(~1);
	truncated = bytes < s.size() * sizeof(WCHAR);
	return s.substr(0, bytes / sizeof(WCHAR));
}

void BuildProcessCreated() {
	bool truncated = false;
	auto cmd = Clamp(L"C:\\Windows\\system32\\cmd.exe /c whoami", MaxCommandLineBytes, truncated);
	bool imageTruncated = false;
	auto image = Clamp(L"C:\\Windows\\system32\\cmd.exe", MaxImageNameBytes, imageTruncated);
	ULONG pid = 1004;
	UCHAR flags = TRUNC_NONE;
	if (truncated)
		flags |= TRUNC_CMDLINE;
	if (imageTruncated)
		flags |= TRUNC_IMAGE_NAME;
	ProcessCreatedRecord record {};
	record.Header = MakeHeader(ProcessCreated, pid, IdentityBase + pid, flags,
		ProcessCreatedFixed
			+ static_cast<ULONG>((cmd.size() + image.size()) * sizeof(WCHAR)));
	record.ParentProcessId = 998;
	record.CommandLineOffset = cmd.empty() ? 0 : ProcessCreatedFixed;
	record.CommandLineBytes = static_cast<USHORT>(cmd.size() * sizeof(WCHAR));
	record.ImageNameOffset = image.empty() ? 0
		: static_cast<USHORT>(record.CommandLineOffset + record.CommandLineBytes);
	record.ImageNameBytes = static_cast<USHORT>(image.size() * sizeof(WCHAR));
	AppendRaw(&record, ProcessCreatedFixed);
	AppendWstr(cmd);
	AppendWstr(image);
}

void BuildProcessExited() {
	ULONG pid = 1000;
	ProcessExitedRecord record {};
	record.Header = MakeHeader(ProcessExited, pid, IdentityBase + pid, TRUNC_NONE, ProcessExitedFixed);
	AppendRaw(&record, ProcessExitedFixed);
}

void BuildThread(RecordType type, ULONG pid, ULONG tid) {
	ThreadRecord record {};
	record.Header = MakeHeader(type, pid, IdentityBase + pid, TRUNC_NONE, ThreadFixed);
	record.ThreadId = tid;
	AppendRaw(&record, ThreadFixed);
}

void BuildImageLoaded() {
	bool truncated = false;
	auto name = Clamp(L"C:\\Windows\\System32\\kernel32.dll", MaxImageNameBytes, truncated);
	ULONG pid = 1004;
	ImageLoadedRecord record {};
	record.Header = MakeHeader(ImageLoaded, pid, IdentityBase + pid,
		truncated ? TRUNC_IMAGE_NAME : TRUNC_NONE,
		ImageLoadedFixed + static_cast<ULONG>(name.size() * sizeof(WCHAR)));
	record.ImageBase = 0x7FF800000000ull;
	record.ImageSize = 0x80000;
	record.NameOffset = ImageLoadedFixed;
	record.NameBytes = static_cast<USHORT>(name.size() * sizeof(WCHAR));
	AppendRaw(&record, ImageLoadedFixed);
	AppendWstr(name);
}

void BuildRegistryKey(RecordType type, ULONG pid, const std::wstring& rawPath) {
	bool truncated = false;
	auto path = Clamp(rawPath, MaxKeyPathBytes, truncated);
	RegistryKeyRecord record {};
	record.Header = MakeHeader(type, pid, IdentityBase + pid,
		truncated ? TRUNC_KEY_PATH : TRUNC_NONE,
		RegistryKeyFixed + static_cast<ULONG>(path.size() * sizeof(WCHAR)));
	record.PathOffset = RegistryKeyFixed;
	record.PathBytes = static_cast<USHORT>(path.size() * sizeof(WCHAR));
	AppendRaw(&record, RegistryKeyFixed);
	AppendWstr(path);
}

void BuildFileRecord(RecordType type, ULONG pid, const std::wstring& rawPath) {
	bool truncated = false;
	auto path = Clamp(rawPath, MaxFilePathBytes, truncated);
	FileRecord record {};
	record.Header = MakeHeader(type, pid, IdentityBase + pid,
		truncated ? TRUNC_FILE_PATH : TRUNC_NONE,
		FileFixed + static_cast<ULONG>(path.size() * sizeof(WCHAR)));
	record.PathOffset = FileFixed;
	record.PathBytes = static_cast<USHORT>(path.size() * sizeof(WCHAR));
	AppendRaw(&record, FileFixed);
	AppendWstr(path);
}

void BuildFileWritten() {
	bool truncated = false;
	auto path = Clamp(L"\\Device\\HarddiskVolume2\\Users\\user\\Documents\\notes.txt",
		MaxFilePathBytes, truncated);
	ULONG pid = 1004;
	FileWrittenRecord record {};
	record.Header = MakeHeader(FileWritten, pid, IdentityBase + pid,
		truncated ? TRUNC_FILE_PATH : TRUNC_NONE,
		FileWrittenFixed + static_cast<ULONG>(path.size() * sizeof(WCHAR)));
	record.ByteOffset = 512;
	record.BytesCount = 240;
	record.PathOffset = FileWrittenFixed;
	record.PathBytes = static_cast<USHORT>(path.size() * sizeof(WCHAR));
	AppendRaw(&record, FileWrittenFixed);
	AppendWstr(path);
}

void BuildDropCaptured() {
	ULONG pid = 1004;
	bool pathTruncated = false;
	auto path = Clamp(L"\\Device\\HarddiskVolume2\\Users\\user\\AppData\\payload.dll",
		MaxFilePathBytes, pathTruncated);
	// Stored names are driver-GENERATED ("drop-<8 hex><ext>") — bounded by
	// construction, never truncated.
	std::wstring stored = L"drop-00000001.dll";

	DropCapturedRecord record {};
	record.Header = MakeHeader(DropCaptured, pid, IdentityBase + pid,
		pathTruncated ? TRUNC_FILE_PATH : TRUNC_NONE,
		DropCapturedFixed + static_cast<ULONG>((path.size() + stored.size()) * sizeof(WCHAR)));
	record.PathOffset = DropCapturedFixed;
	record.PathBytes = static_cast<USHORT>(path.size() * sizeof(WCHAR));
	record.StoredOffset = static_cast<USHORT>(record.PathOffset + record.PathBytes);
	record.StoredBytes = static_cast<USHORT>(stored.size() * sizeof(WCHAR));
	record.Method = DROP_METHOD_HARDLINK;
	AppendRaw(&record, DropCapturedFixed);
	AppendWstr(path);
	AppendWstr(stored);
}

void BuildProtectionEvent() {
	ULONG pid = 4242; // the OPENER (unprotected caller)
	ProtectionEventRecord record {};
	record.Header = MakeHeader(ProtectionEvent, pid, 0, TRUNC_NONE, ProtectionEventFixed);
	record.ProtectedPid = 1004;
	record.TargetIsThread = 0;
	record.ProtectedCreateTime = IdentityBase + 1004;
	record.OriginalDesiredAccess = 0x1FFFFF; // PROCESS_ALL_ACCESS
	record.StrippedAccess = 0x0001 | 0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0040;
	AppendRaw(&record, ProtectionEventFixed);
}

void BuildBehaviorCall() {
	ULONG pid = 1004;
	BehaviorCallRecord record {};
	record.Header = MakeHeader(BehaviorCall, pid, IdentityBase + pid, TRUNC_NONE,
		BehaviorCallFixed);
	record.ThreadId = 2004;
	record.Api = BehaviorNtCreateFile;
	record.Arg0 = 0xC000000000000000ull;
	record.Arg1 = 0x1234;
	record.Arg2 = 0x5678;
	record.Arg3 = 0x9ABC;
	AppendRaw(&record, BehaviorCallFixed);
}

void BuildFileRenamed() {
	bool truncated = false;
	auto oldPath = Clamp(L"\\Device\\HarddiskVolume2\\Users\\user\\Documents\\draft.txt",
		MaxFilePathBytes, truncated);
	auto newPath = Clamp(L"\\Device\\HarddiskVolume2\\Users\\user\\Documents\\final.txt",
		MaxFilePathBytes, truncated);
	ULONG pid = 1004;
	UCHAR flags = TRUNC_NONE;
	if (truncated)
		flags |= TRUNC_OLD_PATH | TRUNC_NEW_PATH;
	FileRenamedRecord record {};
	record.Header = MakeHeader(FileRenamed, pid, IdentityBase + pid, flags,
		FileRenamedFixed + static_cast<ULONG>((oldPath.size() + newPath.size()) * sizeof(WCHAR)));
	record.OldPathOffset = FileRenamedFixed;
	record.OldPathBytes = static_cast<USHORT>(oldPath.size() * sizeof(WCHAR));
	record.NewPathOffset = static_cast<USHORT>(record.OldPathOffset + record.OldPathBytes);
	record.NewPathBytes = static_cast<USHORT>(newPath.size() * sizeof(WCHAR));
	AppendRaw(&record, FileRenamedFixed);
	AppendWstr(oldPath);
	AppendWstr(newPath);
}

void BuildRegistrySetValue() {
	ULONG pid = 1004;
	// A path longer than the cap: the clamp must truncate it and flag the
	// record — this is the fixture's hostile-length coverage.
	bool keyTruncated = false, valueTruncated = false;
	auto key = Clamp(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\"
		L"LongRunner\\" + std::wstring(600, L'A'), MaxKeyPathBytes, keyTruncated);
	auto value = Clamp(L"Backdoor", MaxValueNameBytes, valueTruncated);
	std::string data = "C:\\Users\\Public\\payload.exe";
	auto dataBytes = static_cast<ULONG>(min(data.size(), static_cast<size_t>(MaxValueDataBytes)));

	// Separate flags per field — a shared bool here would let the (short)
	// value name clear the key path's truncation flag.
	UCHAR flags = TRUNC_NONE;
	if (keyTruncated)
		flags |= TRUNC_KEY_PATH;
	if (valueTruncated)
		flags |= TRUNC_VALUE_NAME;

	RegistrySetValueRecord record {};
	record.Header = MakeHeader(RegistrySetValue, pid, IdentityBase + pid, flags,
		RegistrySetValueFixed + static_cast<ULONG>(key.size() * sizeof(WCHAR)
			+ value.size() * sizeof(WCHAR) + dataBytes));
	record.KeyPathOffset = RegistrySetValueFixed;
	record.KeyPathBytes = static_cast<USHORT>(key.size() * sizeof(WCHAR));
	record.ValueNameOffset = static_cast<USHORT>(record.KeyPathOffset + record.KeyPathBytes);
	record.ValueNameBytes = static_cast<USHORT>(value.size() * sizeof(WCHAR));
	record.DataType = REG_SZ;
	record.DataBytes = dataBytes;
	AppendRaw(&record, RegistrySetValueFixed);
	AppendWstr(key);
	AppendWstr(value);
	AppendRaw(data.data(), dataBytes);
}

//
// Control-plane blobs (--emit): built from the REAL policy structs so the
// compiler's alignment/padding is the authority, exactly like the records.
// Every field value is distinct so a Rust-side offset swap shows up as a
// byte mismatch, not a silent pass.
//

void EmitInjectionPolicy() {
	const WCHAR path[] = L"\\??\\C:\\ProgramData\\SecOutfall\\sensors\\boot-1f2e3d4c5b6a7988\\sensor-0a1b2c3d4e5f6071.dll";
	const WCHAR exclusions[] = L"wiretest-helper.exe\0";
	InjectionPolicy policy {};
	policy.Enabled = 1;
	policy.DllPathBytes = static_cast<ULONG>(sizeof(path));
	policy.ExclusionsBytes = static_cast<ULONG>(sizeof(exclusions));
	AppendRaw(&policy, sizeof(policy));
	AppendRaw(path, sizeof(path));
	AppendRaw(exclusions, sizeof(exclusions));
}

void EmitDropPolicy() {
	const WCHAR extensions[] = L".exe\0.dll\0";
	const WCHAR dir[] = L"\\??\\C:\\ProgramData\\SecOutfall\\Drops\\boot-1f2e3d4c5b6a7988";
	DropPolicy policy {};
	policy.Enabled = 1;
	policy.ExtensionsCount = 2;
	policy.ExtensionsBytes = static_cast<ULONG>(sizeof(extensions));
	policy.DirBytes = static_cast<ULONG>(sizeof(dir));
	AppendRaw(&policy, sizeof(policy));
	AppendRaw(extensions, sizeof(extensions));
	AppendRaw(dir, sizeof(dir));
}

void EmitProtectionPolicy() {
	const WCHAR names[] = L"secoutfall-agent.exe\0secoutfall-user-actor.exe\0";
	ProtectionPolicy policy {};
	policy.Enabled = 1;
	policy.NamesBytes = static_cast<ULONG>(sizeof(names));
	AppendRaw(&policy, sizeof(policy));
	AppendRaw(names, sizeof(names));
}

void EmitDeviceSecurity() {
	// The SD itself is opaque to the wire layer (the driver validates shape
	// before applying); the fixture pins the ENVELOPE: enabled + byte count
	// + raw bytes, byte-exact.
	const UCHAR sd[32] = {
		0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
		0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
		0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
		0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
	};
	DeviceSecurityBlob blob {};
	blob.Enabled = 1;
	blob.SdBytes = sizeof(sd);
	AppendRaw(&blob, sizeof(blob));
	AppendRaw(sd, sizeof(sd));
}

void EmitStats() {
	DriverStats stats {};
	stats.Magic = SECOUTFALL_WIRE_MAGIC;
	stats.Version = SECOUTFALL_WIRE_VERSION;
	stats.QueueDepth = 1;
	stats.QueueCapacity = 2;
	stats.FileQueueDepth = 3;
	stats.FileQueueCapacity = 4;
	stats.DropsQueueDepth = 5;
	stats.DropsQueueCapacity = 6;
	stats.Sequence = 0x0102030405060708ull;
	stats.QueueOverwritten = 0x1112131415161718ull;
	stats.AllocFailures = 0x2122232425262728ull;
	stats.OversizedSkipped = 0x3132333435363738ull;
	stats.IdentityMisses = 0x4142434445464748ull;
	stats.FilesOverwritten = 0x5152535455565758ull;
	stats.FileNameQueriesFailed = 0x6162636465666768ull;
	stats.NoiseWritesSkipped = 0x7172737475767778ull;
	stats.DropsStopped = 0x8182838485868788ull;
	stats.DropsMissedBusy = 0x9192939495969798ull;
	stats.DropsLinkFailed = 0xA1A2A3A4A5A6A7A8ull;
	stats.DropsCopyFailed = 0xB1B2B3B4B5B6B7B8ull;
	stats.InjectionsQueued = 0xC1C2C3C4C5C6C7C8ull;
	stats.InjectionsFailed = 0xD1D2D3D4D5D6D7D8ull;
	stats.SensorsRegistered = 0xE1E2E3E4E5E6E7E8ull;
	stats.SensorsRejected = 0xF1F2F3F4F5F6F7F8ull;
	stats.ProtectionsStripped = 0x090A0B0C0D0E0F10ull;
	stats.ProtectionTrusted = 0x192A2B2C2D2E2F30ull;
	stats.SensorEventsDrained = 0x394A4B4C4D4E4F50ull;
	stats.SensorEventsDropped = 0x596A6B6C6D6E6F70ull;
	stats.SensorRingsActive = 0x798A8B8C8D8E8F90ull;
	stats.SensorRingsSkipped = 0x99AABBCCDDEEFF00ull;
	AppendRaw(&stats, sizeof(stats));
}

void EmitFileWatch() {
	// Same NUL-terminated-per-entry list convention as the other policy
	// blobs: the array's implicit terminator double-NULs the last entry.
	FileWatchPolicy blob {};
	blob.Enabled = 1;
	const WCHAR exts[] = L".exe\0.dll\0";
	blob.ExtensionsCount = 2;
	blob.ExtensionsBytes = sizeof(exts);
	AppendRaw(&blob, sizeof(blob));
	AppendRaw(exts, sizeof(exts));
}

void EmitMinimalRename() {
	// The degenerate rename: both name lookups failed (RenameContext absent,
	// post-op name query failed) — the driver emits FileRenamedFixed bytes
	// with BOTH strings absent. The Rust decoder must accept exactly this.
	FileRenamedRecord record {};
	record.Header = MakeHeader(FileRenamed, 1004, IdentityBase + 1004,
		TRUNC_OLD_PATH | TRUNC_NEW_PATH, FileRenamedFixed);
	record.OldPathOffset = 0;
	record.OldPathBytes = 0;
	record.NewPathOffset = 0;
	record.NewPathBytes = 0;
	AppendRaw(&record, FileRenamedFixed);
}

bool ReadFileBytes(const char* path, std::vector<BYTE>& bytes) {
	FILE* f = nullptr;
	if (fopen_s(&f, path, "rb") != 0 || f == nullptr)
		return false;
	_fseeki64(f, 0, SEEK_END);
	auto size = _ftelli64(f);
	_fseeki64(f, 0, SEEK_SET);
	bytes.resize(static_cast<size_t>(size));
	auto read = fread(bytes.data(), 1, bytes.size(), f);
	fclose(f);
	return read == bytes.size();
}

bool WriteFileBytes(const char* path, const std::vector<BYTE>& bytes) {
	FILE* f = nullptr;
	if (fopen_s(&f, path, "wb") != 0 || f == nullptr)
		return false;
	auto written = fwrite(bytes.data(), 1, bytes.size(), f);
	fclose(f);
	return written == bytes.size();
}

// Self-check: walk the built fixture with the same invariants the dumper and
// the Rust mirror enforce (magic, version, header size, bounded sizes).
bool WalkFixture(const std::vector<BYTE>& bytes) {
	size_t offset = 0;
	int count = 0;
	while (offset < bytes.size()) {
		if (bytes.size() - offset < sizeof(RecordHeader)) {
			printf("FAIL: trailing %zu bytes\n", bytes.size() - offset);
			return false;
		}
		auto header = reinterpret_cast<const RecordHeader*>(bytes.data() + offset);
		if (header->Magic != SECOUTFALL_WIRE_MAGIC || header->Version != SECOUTFALL_WIRE_VERSION
			|| header->HeaderSize != sizeof(RecordHeader)) {
			printf("FAIL: bad header at %zu\n", offset);
			return false;
		}
		if (header->Size < sizeof(RecordHeader) || header->Size > bytes.size() - offset) {
			printf("FAIL: bad size at %zu\n", offset);
			return false;
		}
		++count;
		offset += header->Size;
	}
	printf("fixture walks clean: %d records, %zu bytes\n", count, bytes.size());
	return count == 16;
}

} // namespace

void EmitCodes() {
	// The macro expansion IS the authority: the parent agent's Rust port
	// pins these exact values (crates/agent/src/ports/driven/driver_control.rs).
	struct { const char* name; ULONG code; } codes[] = {
		{ "GET_DATA", IOCTL_SECOUTFALL_GET_DATA },
		{ "GET_STATS", IOCTL_SECOUTFALL_GET_STATS },
		{ "SET_FILE_WATCH", IOCTL_SECOUTFALL_SET_FILE_WATCH },
		{ "SELFTEST_FLOOD", IOCTL_SECOUTFALL_SELFTEST_FLOOD },
		{ "SET_DROP_POLICY", IOCTL_SECOUTFALL_SET_DROP_POLICY },
		{ "SET_INJECTION_POLICY", IOCTL_SECOUTFALL_SET_INJECTION_POLICY },
		{ "SENSOR_CHALLENGE", IOCTL_SECOUTFALL_SENSOR_CHALLENGE },
		{ "SENSOR_REGISTER", IOCTL_SECOUTFALL_SENSOR_REGISTER },
		{ "SET_PROTECTED", IOCTL_SECOUTFALL_SET_PROTECTED },
		{ "SET_DEVICE_SECURITY", IOCTL_SECOUTFALL_SET_DEVICE_SECURITY },
	};
	char line[128];
	for (auto& entry : codes) {
		sprintf_s(line, "%s=0x%08X\n", entry.name, entry.code);
		g_out.insert(g_out.end(), line, line + strlen(line));
	}
	sprintf_s(line, "MAX_RECORD_BYTES=%lu\n",
		static_cast<ULONG>(SECOUTFALL_MAX_RECORD_BYTES));
	g_out.insert(g_out.end(), line, line + strlen(line));
}

int main(int argc, char** argv) {
	if (argc == 3 && strcmp(argv[1], "--emit") == 0 && strcmp(argv[2], "codes") == 0) {
		EmitCodes();
		if (!WriteFileBytes("driver/tests/emit_codes.txt", g_out)) {
			// Fall back to stdout when the default path is not writable.
			fwrite(g_out.data(), 1, g_out.size(), stdout);
			return 1;
		}
		printf("emitted codes -> driver/tests/emit_codes.txt (%zu bytes)\n", g_out.size());
		return 0;
	}

	if (argc == 4 && strcmp(argv[1], "--emit") == 0) {
		g_out.clear();
		g_seq = 0;
		const char* name = argv[2];
		if (strcmp(name, "injection") == 0) EmitInjectionPolicy();
		else if (strcmp(name, "drops") == 0) EmitDropPolicy();
		else if (strcmp(name, "filewatch") == 0) EmitFileWatch();
		else if (strcmp(name, "protection") == 0) EmitProtectionPolicy();
		else if (strcmp(name, "security") == 0) EmitDeviceSecurity();
		else if (strcmp(name, "stats") == 0) EmitStats();
		else if (strcmp(name, "minimal-rename") == 0) EmitMinimalRename();
		else {
			printf("FAIL: unknown emit target '%s'\n", name);
			return 2;
		}
		if (g_out.empty()) {
			printf("FAIL: %s emitted nothing\n", name);
			return 1;
		}
		if (!WriteFileBytes(argv[3], g_out)) {
			printf("FAIL: cannot write %s\n", argv[3]);
			return 1;
		}
		printf("emitted %s -> %s (%zu bytes)\n", name, argv[3], g_out.size());
		return 0;
	}

	if (argc != 3 || (strcmp(argv[1], "--generate") != 0 && strcmp(argv[1], "--verify") != 0)) {
		printf("usage: wiretest --generate <file> | --verify <file> | --emit <name> <file>\n");
		return 2;
	}

	g_out.clear();
	g_seq = 0;
	BuildProcessCreated();   // 1
	BuildProcessExited();    // 2
	BuildThread(ThreadCreated, 1004, 2004);   // 3
	BuildThread(ThreadExited, 1004, 2004);    // 4
	BuildImageLoaded();      // 5
	BuildRegistryKey(RegistryKeyCreated, 1004,
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"); // 6
	BuildRegistryKey(RegistryKeyDeleted, 1004,
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\Evil\\Persist"); // 7
	BuildRegistrySetValue(); // 8
	BuildFileRecord(FileCreated, 1004,
		L"\\Device\\HarddiskVolume2\\Users\\user\\AppData\\payload.dll"); // 9
	BuildFileWritten(); // 10
	BuildFileRecord(FileCleanedUp, 1004,
		L"\\Device\\HarddiskVolume2\\Users\\user\\AppData\\payload.dll"); // 11
	BuildFileRecord(FileDeleted, 1004,
		L"\\Device\\HarddiskVolume2\\Users\\user\\AppData\\log.tmp"); // 12
	BuildFileRenamed(); // 13
	BuildDropCaptured(); // 14
	BuildBehaviorCall(); // 15
	BuildProtectionEvent(); // 16
	auto fixture = g_out;

	if (!WalkFixture(fixture)) {
		WriteFileBytes(argv[2], fixture); // debug: dump anyway for offline autopsy
		return 1;
	}

	if (strcmp(argv[1], "--generate") == 0) {
		if (!WriteFileBytes(argv[2], fixture)) {
			printf("FAIL: cannot write %s\n", argv[2]);
			return 1;
		}
		printf("generated %s (%zu bytes)\n", argv[2], fixture.size());
		return 0;
	}

	std::vector<BYTE> expected;
	if (!ReadFileBytes(argv[2], expected)) {
		printf("FAIL: cannot read %s\n", argv[2]);
		return 1;
	}
	if (fixture.size() != expected.size() || memcmp(fixture.data(), expected.data(), fixture.size()) != 0) {
		printf("FAIL: %s does not match the wire-v2 schema (%zu vs %zu bytes)\n",
			argv[2], fixture.size(), expected.size());
		return 1;
	}
	printf("OK: %s matches the wire-v2 schema (%zu bytes)\n", argv[2], fixture.size());
	return 0;
}
