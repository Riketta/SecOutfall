//! Shared wire models at port/adapter boundaries — the contract between the
//! agent, the user-actor and the Controller.
//!
//! Pure DTOs: no hexagon or kernel types leak here. Every wire boundary has an
//! explicit, versioned schema (no opaque serialization — doctrine).
//!
//! - [`events`] — canonical, source-agnostic event taxonomy (ETW today, driver later).
//! - [`payload`] — typed `data` payload schemas, one per taxonomy member.
//! - [`driver_wire`] — kernel driver ↔ user-mode record schema (v2), golden-pinned
//!   to the C-side `wiretest` fixture.
//! - [`nats`] — NATS envelope (protocol v3) for `control_channel` / `event_channel`.
//! - [`ipc`] — agent↔user-actor named-pipe frame schema (IPC v1).
//! - [`upload`] — HTTP collector `meta` multipart-part schema (drops, screenshots).
//! - [`config`] — agent TOML config schema + the user-actor config pushed over IPC.
#![forbid(unsafe_code)]

pub mod config;
pub mod driver_wire;
pub mod events;
pub mod ipc;
pub mod nats;
pub mod payload;
pub mod upload;
