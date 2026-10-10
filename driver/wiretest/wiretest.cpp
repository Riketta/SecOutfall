// wiretest — pins the secoutfall wire-v2 contract on the C side.
//
//   wiretest --generate <file>   writes the canonical fixture (deterministic)
//   wiretest --verify <file>     byte-exact compares against the fixture
//
// The fixture (driver/tests/golden_v2.bin) is committed: the same bytes are
// decoded by crates/protocol/src/driver_wire.rs golden tests, so the C and
// Rust interpretations of the wire format cannot drift apart silently. Any
// schema change must regenerate the fixture AND update the Rust mirror —
// both golden tests fail until they agree.
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

int main(int argc, char** argv) {
	if (argc != 3 || (strcmp(argv[1], "--generate") != 0 && strcmp(argv[1], "--verify") != 0)) {
		printf("usage: wiretest --generate <file> | --verify <file>\n");
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
