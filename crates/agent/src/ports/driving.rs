//! Driving-side SPI: the contract inbound-source adapters fulfill to run and
//! push events into the kernel's driving port
//! ([`EventInletPort`](kernel::app::api_ports::EventInletPort)).

pub mod event_source;
