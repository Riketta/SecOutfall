//! ntdll/kernel32 APIs the sensor needs. Hand declarations via
//! `windows_link::link!` — the same mechanism the generated bindings use —
//! because windows-bindgen's filter does not carry the Nt* names and the
//! sensor deliberately avoids the heavy `windows` crate.

#![allow(clippy::upper_case_acronyms)]

windows_link::link!("ntdll.dll" "system" fn NtDelayExecution(alertable: BOOLEAN, delayinterval: *const i64) -> NTSTATUS);
windows_link::link!("ntdll.dll" "system" fn NtCreateThreadEx(threadhandle: *mut HANDLE, desiredaccess: ACCESS_MASK, objectattributes: *const core::ffi::c_void, processhandle: HANDLE, startroutine: PVOID, argument: PVOID, createflags: u32, zerobits: usize, stacksize: usize, maximumstacksize: usize, attributelist: *const core::ffi::c_void) -> NTSTATUS);

windows_link::link!("kernel32.dll" "system" fn CreateFileW(filename: *const u16, desiredaccess: u32, sharemode: u32, securityattributes: *const core::ffi::c_void, creationdisposition: u32, flagsandattributes: u32, templatefile: HANDLE) -> HANDLE);
windows_link::link!("kernel32.dll" "system" fn CloseHandle(handle: HANDLE) -> i32);
windows_link::link!("kernel32.dll" "system" fn DeviceIoControl(handle: HANDLE, dwiocontrolcode: u32, lpinbuffer: *const core::ffi::c_void, ninbuffersize: u32, lpoutbuffer: *mut core::ffi::c_void, noutbuffersize: u32, lpbytesreturned: *mut u32, lpoverlapped: *const core::ffi::c_void) -> i32);
windows_link::link!("kernel32.dll" "system" fn MapViewOfFile(hfilemappingobject: HANDLE, dwdesiredaccess: u32, dwfileoffsethigh: u32, dwfileoffsetlow: u32, dwbytecountofmap: usize) -> *mut core::ffi::c_void);
windows_link::link!("kernel32.dll" "system" fn UnmapViewOfFile(lpbaseaddress: *const core::ffi::c_void) -> i32);
windows_link::link!("kernel32.dll" "system" fn GetCurrentThreadId() -> u32);
windows_link::link!("kernel32.dll" "system" fn GetModuleHandleW(lpnmodulename: *const u16) -> HANDLE);
windows_link::link!("kernel32.dll" "system" fn GetProcAddress(hmodule: HANDLE, lpprocname: *const u8) -> PVOID);
windows_link::link!("kernel32.dll" "system" fn GetLastError() -> u32);

pub type BOOLEAN = u8;
pub type PVOID = *mut core::ffi::c_void;
pub type ACCESS_MASK = u32;
pub type HANDLE = *mut core::ffi::c_void;
pub type NTSTATUS = i32;

// Access/flag constants (Win32 values, local mirrors).
pub const GENERIC_READ: u32 = 0x8000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const FILE_SHARE_READ: u32 = 0x0000_0001;
pub const FILE_SHARE_WRITE: u32 = 0x0000_0002;
pub const OPEN_EXISTING: u32 = 3;
pub const FILE_MAP_READ: u32 = 0x0000_0004;
pub const FILE_MAP_WRITE: u32 = 0x0000_0002;
