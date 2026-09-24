//! Infrastructure adapters, grouped by role then family.
//!
//! - [`driving`] — inbound sources pushing `ActorEvent`s into the kernel
//!   inlet: the IPC client (whose channel pair also carries the driven
//!   screenshot-sink half) and the focus sources.
//! - [`driven`] — desktop effects the hexagon calls: capture, input, app
//!   launch, sink. Fakes live beside their production twins.

pub mod driven;
pub mod driving;
