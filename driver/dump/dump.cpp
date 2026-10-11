// secoutfall console dumper: opens the driver's control device, prints
// drained wire-v2 events and the loss-counter stats. Standalone lab tool —
// the agent's DriverEventSourceAdapter is the production consumer.

#include <windows.h>
#include <cstdio>
#include <string>
#include <vector>

#include "..\secoutfall\secoutfallCommon.h"

enum class ConsoleColor : WORD {
	DarkGreen = 2,
	DarkRed = 4,
	DarkYellow = 6,
	Cyan = 11,
	Green = 10,
	Red = 12,
	Magenta = 13,
	Yellow = 14,
	Gray = 7,
	White = 15,
};

void SetColor(ConsoleColor color) {
	auto output = ::GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO info;
	if (::GetConsoleScreenBufferInfo(output, &info))
		::SetConsoleTextAttribute(output, (info.wAttributes & 0xF0) | static_cast<WORD>(color));
}

int Error(const char* msg) {
	printf("%s (error %lu)\n", msg, ::GetLastError());
	return 1;
}

// The drained stream is hostile input (any SYSTEM/Admin process can drain the
// device too): every offset and length from the record is validated against
// the checked record size before a single byte is read.
bool RangeOk(DWORD recordSize, USHORT offset, USHORT bytes) {
	return bytes % 2 == 0
		&& offset >= sizeof(RecordHeader)
		&& static_cast<ULONG>(offset) + bytes <= recordSize;
}

std::wstring ReadWstr(const BYTE* record, DWORD recordSize, USHORT offset, USHORT bytes) {
	if (!RangeOk(recordSize, offset, bytes))
		return L"<out of range>";
	return std::wstring(reinterpret_cast<const WCHAR*>(record + offset), bytes / sizeof(WCHAR));
}

std::wstring TruncSuffix(UCHAR flags, UCHAR bit, const WCHAR* what) {
	return (flags & bit) ? std::wstring(L" [") + what + L" TRUNCATED]" : L"";
}

void DisplayTime(const LARGE_INTEGER& time) {
	FILETIME ft;
	ft.dwLowDateTime = time.LowPart;
	ft.dwHighDateTime = time.HighPart;
	SYSTEMTIME st;
	::FileTimeToSystemTime(&ft, &st);
	printf("%02u:%02u:%02u.%03u", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

void DisplayStats(const DriverStats& stats) {
	SetColor(ConsoleColor::White);
	printf("stats: queue %lu/%lu, seq %llu | lost: overwritten %llu, alloc-fail %llu, oversized %llu, identity-miss %llu\n",
		stats.QueueDepth, stats.QueueCapacity,
		static_cast<unsigned long long>(stats.Sequence),
		static_cast<unsigned long long>(stats.QueueOverwritten),
		static_cast<unsigned long long>(stats.AllocFailures),
		static_cast<unsigned long long>(stats.OversizedSkipped),
		static_cast<unsigned long long>(stats.IdentityMisses));
}

void DisplayData(const BYTE* buffer, DWORD size) {
	while (size >= sizeof(RecordHeader)) {
		auto header = reinterpret_cast<const RecordHeader*>(buffer);
		if (header->Magic != SECOUTFALL_WIRE_MAGIC || header->Version != SECOUTFALL_WIRE_VERSION) {
			printf("unknown wire magic/version %04X/%u — stopping parse\n", header->Magic, header->Version);
			return;
		}
		if (header->HeaderSize != sizeof(RecordHeader)) {
			printf("unexpected header size %u — stopping parse\n", header->HeaderSize);
			return;
		}
		if (header->Size < sizeof(RecordHeader) || header->Size > size) {
			printf("malformed record size %lu — stopping parse\n", header->Size);
			return;
		}

		DisplayTime(*reinterpret_cast<const LARGE_INTEGER*>(&header->Time));
		printf(": ");

		switch (static_cast<RecordType>(header->Type)) {
			case ProcessCreated:
			{
				SetColor(ConsoleColor::Green);
				if (header->Size < ProcessCreatedFixed) {
					printf("short ProcessCreated record\n");
					return;
				}
				auto record = reinterpret_cast<const ProcessCreatedRecord*>(buffer);
				auto cmd = record->CommandLineBytes > 0
					? ReadWstr(buffer, header->Size, record->CommandLineOffset, record->CommandLineBytes)
					: std::wstring(L"<none>");
				printf("process %lu created (parent %lu, id %llu): %ws%ws\n",
					header->ProcessId, record->ParentProcessId,
					static_cast<unsigned long long>(header->ProcessCreateTime), cmd.c_str(),
					TruncSuffix(header->TruncFlags, TRUNC_CMDLINE, L"cmdline").c_str());
				break;
			}

			case ProcessExited:
			{
				SetColor(ConsoleColor::DarkGreen);
				printf("process %lu exited (id %llu)\n",
					header->ProcessId, static_cast<unsigned long long>(header->ProcessCreateTime));
				break;
			}

			case ThreadCreated:
			case ThreadExited:
			{
				SetColor(ConsoleColor::Gray);
				if (header->Size < ThreadFixed) {
					printf("short thread record\n");
					return;
				}
				auto record = reinterpret_cast<const ThreadRecord*>(buffer);
				printf("thread %lu %hs in process %lu\n",
					record->ThreadId,
					header->Type == ThreadCreated ? "created" : "exited",
					header->ProcessId);
				break;
			}

			case ImageLoaded:
			{
				SetColor(ConsoleColor::White);
				if (header->Size < ImageLoadedFixed) {
					printf("short image record\n");
					return;
				}
				auto record = reinterpret_cast<const ImageLoadedRecord*>(buffer);
				auto name = ReadWstr(buffer, header->Size, record->NameOffset, record->NameBytes);
				printf("image %ws loaded in process %lu (base %llx, %lu bytes)%ws\n",
					name.c_str(), header->ProcessId,
					static_cast<unsigned long long>(record->ImageBase), record->ImageSize,
					TruncSuffix(header->TruncFlags, TRUNC_IMAGE_NAME, L"name").c_str());
				break;
			}

			case RegistryKeyCreated:
			case RegistryKeyDeleted:
			{
				SetColor(ConsoleColor::Cyan);
				if (header->Size < RegistryKeyFixed) {
					printf("short registry-key record\n");
					return;
				}
				auto record = reinterpret_cast<const RegistryKeyRecord*>(buffer);
				auto path = ReadWstr(buffer, header->Size, record->PathOffset, record->PathBytes);
				printf("registry key %hs: %ws (process %lu)%ws\n",
					header->Type == RegistryKeyCreated ? "created" : "deleted",
					path.c_str(), header->ProcessId,
					TruncSuffix(header->TruncFlags, TRUNC_KEY_PATH, L"path").c_str());
				break;
			}

			case RegistrySetValue:
			{
				SetColor(ConsoleColor::Cyan);
				if (header->Size < RegistrySetValueFixed) {
					printf("short registry set-value record\n");
					return;
				}
				auto record = reinterpret_cast<const RegistrySetValueRecord*>(buffer);
				auto key = ReadWstr(buffer, header->Size, record->KeyPathOffset, record->KeyPathBytes);
				auto value = ReadWstr(buffer, header->Size, record->ValueNameOffset, record->ValueNameBytes);
				printf("registry write (process %lu): %ws\\%ws type %lu size %lu%ws%ws\n",
					header->ProcessId, key.c_str(), value.c_str(),
					record->DataType, record->DataBytes,
					TruncSuffix(header->TruncFlags, TRUNC_KEY_PATH, L"key").c_str(),
					TruncSuffix(header->TruncFlags, TRUNC_DATA, L"data").c_str());
				break;
			}

			case FileCreated:
			case FileCleanedUp:
			case FileDeleted:
			{
				SetColor(ConsoleColor::Yellow);
				if (header->Size < FileFixed) {
					printf("short file record\n");
					return;
				}
				auto record = reinterpret_cast<const FileRecord*>(buffer);
				auto path = ReadWstr(buffer, header->Size, record->PathOffset, record->PathBytes);
				printf("file %hs: %ws (process %lu)%ws\n",
					header->Type == FileCreated ? "created"
					: header->Type == FileCleanedUp ? "cleaned-up" : "deleted",
					path.c_str(), header->ProcessId,
					TruncSuffix(header->TruncFlags, TRUNC_FILE_PATH, L"path").c_str());
				break;
			}

			case FileWritten:
			{
				SetColor(ConsoleColor::DarkYellow);
				if (header->Size < FileWrittenFixed) {
					printf("short file-write record\n");
					return;
				}
				auto record = reinterpret_cast<const FileWrittenRecord*>(buffer);
				auto path = ReadWstr(buffer, header->Size, record->PathOffset, record->PathBytes);
				printf("file write %lu bytes at +%llu: %ws (process %lu)%ws\n",
					record->BytesCount,
					static_cast<unsigned long long>(record->ByteOffset), path.c_str(),
					header->ProcessId,
					TruncSuffix(header->TruncFlags, TRUNC_FILE_PATH, L"path").c_str());
				break;
			}

			case FileRenamed:
			{
				SetColor(ConsoleColor::Yellow);
				if (header->Size < FileRenamedFixed) {
					printf("short file-rename record\n");
					return;
				}
				auto record = reinterpret_cast<const FileRenamedRecord*>(buffer);
				auto oldPath = ReadWstr(buffer, header->Size, record->OldPathOffset, record->OldPathBytes);
				auto newPath = ReadWstr(buffer, header->Size, record->NewPathOffset, record->NewPathBytes);
				printf("file renamed (process %lu): %ws -> %ws%ws%ws\n",
					header->ProcessId, oldPath.c_str(), newPath.c_str(),
					TruncSuffix(header->TruncFlags, TRUNC_OLD_PATH, L"old").c_str(),
					TruncSuffix(header->TruncFlags, TRUNC_NEW_PATH, L"new").c_str());
				break;
			}

			case DropCaptured:
			{
				SetColor(ConsoleColor::Magenta);
				if (header->Size < DropCapturedFixed) {
					printf("short drop record\n");
					return;
				}
				auto record = reinterpret_cast<const DropCapturedRecord*>(buffer);
				auto path = ReadWstr(buffer, header->Size, record->PathOffset, record->PathBytes);
				auto stored = ReadWstr(buffer, header->Size, record->StoredOffset, record->StoredBytes);
				printf("drop captured (%hs): %ws -> %ws (process %lu)%ws\n",
					record->Method == DROP_METHOD_HARDLINK ? "hardlink" : "copy",
					path.c_str(), stored.c_str(), header->ProcessId,
					TruncSuffix(header->TruncFlags, TRUNC_FILE_PATH, L"path").c_str());
				break;
			}

			case BehaviorCall:
			{
				SetColor(ConsoleColor::Red);
				if (header->Size < BehaviorCallFixed) {
					printf("short behavior record\n");
					return;
				}
				auto record = reinterpret_cast<const BehaviorCallRecord*>(buffer);
				printf("behavior api %lu (thread %lu): 0x%llx 0x%llx 0x%llx 0x%llx (process %lu)\n",
					record->Api, record->ThreadId,
					static_cast<unsigned long long>(record->Arg0),
					static_cast<unsigned long long>(record->Arg1),
					static_cast<unsigned long long>(record->Arg2),
					static_cast<unsigned long long>(record->Arg3),
					header->ProcessId);
				break;
			}

			case ProtectionEvent:
			{
				SetColor(ConsoleColor::Red);
				if (header->Size < ProtectionEventFixed) {
					printf("short protection record\n");
					return;
				}
				auto record = reinterpret_cast<const ProtectionEventRecord*>(buffer);
				printf("protection: %s %lu (opener %lu): stripped 0x%llx of 0x%llx\n",
					record->TargetIsThread ? "thread" : "process",
					record->ProtectedPid, header->ProcessId,
					static_cast<unsigned long long>(record->StrippedAccess),
					static_cast<unsigned long long>(record->OriginalDesiredAccess));
				break;
			}

			default:
				printf("unknown record type %u (size %lu) — skipping (forward compat)\n",
					header->Type, header->Size);
				break;
		}

		size -= header->Size;
		buffer += header->Size;
	}

	if (size > 0)
		printf("%lu trailing bytes — stopping parse\n", size);
}

int main() {
	SetColor(ConsoleColor::Gray);
	auto device = ::CreateFileW(L"\\\\.\\" SECOUTFALL_NAME, GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (device == INVALID_HANDLE_VALUE)
		return Error("failed to open \\\\.\\secoutfall — is the driver loaded? (sc query secoutfall)");

	std::vector<BYTE> buffer(1u << 20);
	DWORD size = 0;
	auto first = true;
	while (true) {
		// Stats are loss accounting, not telemetry: fetch per iteration, print
		// once at start and whenever any counter moves.
		static DriverStats last {};
		if (::DeviceIoControl(device, IOCTL_SECOUTFALL_GET_STATS, nullptr, 0UL,
			&last, sizeof(last), &size, nullptr) && size == sizeof(last))
			DisplayStats(last);

		if (!::DeviceIoControl(device, IOCTL_SECOUTFALL_GET_DATA, nullptr, 0UL,
			buffer.data(), static_cast<DWORD>(buffer.size()), &size, nullptr))
			return Error("DeviceIoControl failed");
		if (size > 0)
			DisplayData(buffer.data(), size);
		if (first) {
			printf("draining...\n");
			first = false;
		}
		::Sleep(100);
	}
}
