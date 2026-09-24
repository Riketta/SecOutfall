//! Agent port contracts beyond the kernel's (inventory in root `AGENTS.md`),
//! split by direction: [`driving`] is the inbound-source adapter SPI, [`driven`]
//! are the outbound services the hexagon calls.

pub mod driven;
pub mod driving;
