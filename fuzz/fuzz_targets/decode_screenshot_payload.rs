//! Fuzz the screenshot frame payload decoder (`{seq: u32 LE} + JPEG bytes`).
//! The agent decodes user-actor frames — hostile bytes in, sequence + slice
//! out, never a panic and never a slice outside the payload.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((seq, jpeg)) = protocol::ipc::messages::decode_screenshot(data) {
        // The JPEG slice is always the payload's tail after the 4-byte
        // sequence prefix.
        assert_eq!(jpeg.len() + protocol::ipc::messages::SCREENSHOT_SEQ_LEN, data.len());
        let _ = seq; // opaque; the bound above is the invariant
    } else {
        assert!(data.len() < protocol::ipc::messages::SCREENSHOT_SEQ_LEN);
    }
});
