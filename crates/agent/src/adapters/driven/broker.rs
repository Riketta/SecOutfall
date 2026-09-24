//! `BrokerPort` family: the NATS shipper, console/JSONL/tee variants for dev
//! modes, and the test fake.

pub mod console;
pub mod fake;
pub mod jsonl;
pub mod nats;
pub mod tee;
