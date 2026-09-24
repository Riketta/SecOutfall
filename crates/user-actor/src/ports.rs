//! User-actor port contracts beyond the kernel's. All of them are DRIVEN —
//! the driving side (focus sources, IPC client) calls the kernel inlet
//! directly and is adapters, not ports here.

pub mod driven;
