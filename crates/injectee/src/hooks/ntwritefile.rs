//! `NtWriteFile` hook: file write activity — the sensor's view of what the
//! host asks the OS to write (the minifilter remains ground truth).
//! Observe-only.

#![allow(clippy::too_many_arguments, clippy::cast_sign_loss, clippy::cast_lossless, clippy::doc_markdown)]

crate::hook! {
    /// Reports file write calls, passes them through unchanged.
    in "ntdll.dll"!NtWriteFile as NTWRITEFILE_ORIGINAL
    fn ntwritefile_detour(
        file_handle: *mut core::ffi::c_void,
        event: *mut core::ffi::c_void,
        apc_routine: *const core::ffi::c_void,
        apc_context: *const core::ffi::c_void,
        io_status_block: *mut core::ffi::c_void,
        buffer: *const core::ffi::c_void,
        length: u32,
        byte_offset: *const i64,
        key: *const u32,
    ) -> i32 {
        let args = [
            file_handle as u64,
            u64::from(length),
            byte_offset as u64,
            0,
        ];
        crate::sensor::emit(crate::sensor::api::NT_WRITE_FILE, args);
        unsafe {
            NTWRITEFILE_ORIGINAL.call(
                file_handle,
                event,
                apc_routine,
                apc_context,
                io_status_block,
                buffer,
                length,
                byte_offset,
                key,
            )
        }
    }
}
