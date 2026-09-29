#pragma once

#define SECOUTFALL_NAME L"secoutfall"

enum ItemType : short {
	ProcessCreated,
	ProcessExited,
	ThreadCreated,
	ThreadExited,
	RegistrySetValue
};

// D0 wire format: inherited from the WKP SysMon base, kept byte-compatible
// with its client. D1 replaces this with the versioned schema (magic +
// version + u32 sizes + caps + truncation flags) mirrored into `protocol`.
struct ItemHeader {
	ItemType Type;
	short Size;
	LARGE_INTEGER Time;
};

struct ProcessCreateInfo : ItemHeader {
	ULONG ProcessId;
	ULONG ParentProcessId;
	short CommandLineOffset;
	short CommandLineLength;
};

struct ProcessExitInfo : ItemHeader {
	ULONG ProcessId;
};

struct ThreadCreateExitInfo : ItemHeader {
	ULONG ThreadId;
	ULONG ProcessId;
};

struct RegistrySetValueInfo : ItemHeader {
	ULONG ProcessId;
	WCHAR KeyName[256];
	WCHAR ValueName[64];
	ULONG DataType;
	UCHAR Data[128];
	ULONG DataSize;
};

// Command-line capture cap in bytes (whole WCHARs). The base captured the
// full ~64 KB command line, overflowing the `short Size` field; capped here
// until the D1 wire rework.
const USHORT MaxCommandLineBytes = 8192;

// Unsigned literals: 0x8000 << 16 would overflow int (UB) and the value
// would stop being a constant expression (unusable as a case label).
#define IOCTL_SECOUTFALL_GET_DATA \
	CTL_CODE(0x8000u, 0x800u, METHOD_OUT_DIRECT, FILE_READ_ACCESS)
