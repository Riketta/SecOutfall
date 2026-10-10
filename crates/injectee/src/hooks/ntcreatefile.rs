//! `NtCreateFile` hook: file open/create activity — chain edges for
//! droppers and persistence. Observe-only.

#![allow(clippy::too_many_arguments, clippy::cast_sign_loss, clippy::cast_lossless, clippy::doc_markdown)]

crate::hook! {
    /// Reports file open/create calls, passes them through unchanged.
    in "ntdll.dll"!NtCreateFile as NTCREATEFILE_ORIGINAL
    fn ntcreatefile_detour(
        file_handle: *mut core::ffi::c_void,
        desired_access: u32,
        object_attributes: *const core::ffi::c_void,
        io_status_block: *mut core::ffi::c_void,
        allocation_size: *const i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *const core::ffi::c_void,
        ea_length: u32,
    ) -> i32 {
        crate::sensor::emit(
            crate::sensor::api::NT_CREATE_FILE,
            [
                desired_access as u64,
                create_disposition as u64,
                create_options as u64,
                file_handle as u64,
            ],
        );
        unsafe {
            NTCREATEFILE_ORIGINAL.call(
                file_handle,
                desired_access,
                object_attributes,
                io_status_block,
                allocation_size,
                file_attributes,
                share_access,
                create_disposition,
                create_options,
                ea_buffer,
                ea_length,
            )
        }
    }
}
