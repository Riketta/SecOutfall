//! Infrastructure adapters, grouped by role then family.
//!
//! - [`driving`] — inbound sources: they run themselves and push events into
//!   the kernel's `EventInletPort` (ETW, scheduler, SCM, IPC server).
//! - [`driven`] — outbound services the hexagon calls, one family per port
//!   (`broker`, `clock`, …). Every fake lives beside its production twin in
//!   the same family, so a port and its test double drift together.

pub mod driven;
pub mod driving;
