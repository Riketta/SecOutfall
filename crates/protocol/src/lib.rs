//! Shared wire models at port/adapter boundaries — the contract between the
//! agent, the user-actor and the Controller.
//!
//! Pure DTOs: no hexagon or kernel types leak here. Every wire boundary has an
//! explicit, versioned schema (no opaque serialization — doctrine).
//!
//! - [`events`] — canonical, source-agnostic event taxonomy (ETW today, driver later).
//! - [`nats`] — NATS envelope (protocol v3) for `control_channel` / `event_channel`.
//! - [`ipc`] — agent↔user-actor named-pipe frame schema (IPC v1).
#![forbid(unsafe_code)]

pub mod events;
pub mod ipc;
pub mod nats;
