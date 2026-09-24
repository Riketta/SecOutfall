//! Driven adapters: desktop effects implementing the outbound ports, one
//! family per port. Fakes live beside their production twins.

pub mod capture;
pub mod input;
pub mod launcher;
/// The production sink half lives in
/// [`crate::adapters::driving::ipc_client`] (the IPC channel pair spans both
/// directions); this is its fake.
pub mod sink_fake;
