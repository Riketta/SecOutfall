windows_link::link!("kernel32.dll" "system" fn GetTickCount() -> u32);
windows_link::link!("ntdll.dll" "system" fn NtClose(handle : HANDLE) -> NTSTATUS);
windows_link::link!("ntdll.dll" "system" fn NtCreateFile(filehandle : *mut HANDLE, desiredaccess : ACCESS_MASK, objectattributes : *const OBJECT_ATTRIBUTES, iostatusblock : *mut IO_STATUS_BLOCK, allocationsize : *const i64, fileattributes : u32, shareaccess : u32, createdisposition : u32, createoptions : u32, eabuffer : *const core::ffi::c_void, ealength : u32) -> NTSTATUS);
windows_link::link!("ntdll.dll" "system" fn NtWriteFile(filehandle : HANDLE, event : HANDLE, apcroutine : PIO_APC_ROUTINE, apccontext : *const core::ffi::c_void, iostatusblock : *mut IO_STATUS_BLOCK, buffer : *const core::ffi::c_void, length : u32, byteoffset : *const i64, key : *const u32) -> NTSTATUS);
windows_link::link!("kernel32.dll" "system" fn Sleep(dwmilliseconds : u32));
pub type ACCESS_MASK = u32;
pub type HANDLE = *mut core::ffi::c_void;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IO_STATUS_BLOCK {
    pub Anonymous: IO_STATUS_BLOCK_0,
    pub Information: usize,
}
impl Default for IO_STATUS_BLOCK {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union IO_STATUS_BLOCK_0 {
    pub Status: NTSTATUS,
    pub Pointer: *mut core::ffi::c_void,
}
impl Default for IO_STATUS_BLOCK_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
pub type NTSTATUS = i32;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: u32,
    pub RootDirectory: HANDLE,
    pub ObjectName: PUNICODE_STRING,
    pub Attributes: u32,
    pub SecurityDescriptor: *mut core::ffi::c_void,
    pub SecurityQualityOfService: *mut core::ffi::c_void,
}
pub type PIO_APC_ROUTINE = Option<
    unsafe extern "system" fn(
        apccontext: *mut core::ffi::c_void,
        iostatusblock: *mut IO_STATUS_BLOCK,
        reserved: u32,
    ),
>;
pub type PUNICODE_STRING = *mut UNICODE_STRING;
pub type PWSTR = *mut u16;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: PWSTR,
}
