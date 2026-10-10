//! Fuzz the driver wire decoder — the agent-side half of the IOCTL framing
//! (`GET_DATA` batches). Any SYSTEM/Admin process can drain the device, and
//! the bytes in a batch originate from kernel queues fed by a hostile
//! system; the decoder may reject but must never panic, over-read, or
//! over-allocate. Host proptest twin: `protocol::driver_wire::proptests`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = protocol::driver_wire::decode_all(data);
});
