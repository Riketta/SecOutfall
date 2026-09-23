//! Fuzz the IPC v1 frame-header parser — the first hostile-input boundary
//! between the user actor and the agent. The parser must return `Ok` or
//! `Err` for any input; an `Ok` verdict must carry only invariants the
//! schema promises (bounded payload, known type).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(header) = protocol::ipc::FrameHeader::from_bytes(data) {
        assert!(
            usize::try_from(header.payload_len).unwrap_or(usize::MAX)
                <= protocol::ipc::MAX_PAYLOAD_LEN
        );
        assert!(protocol::ipc::message_type::is_known(header.message_type));
        // Accepted headers survive their own wire form.
        assert_eq!(protocol::ipc::FrameHeader::from_bytes(&header.to_bytes()), Ok(header));
    }
});
