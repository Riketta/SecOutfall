//! Generic hexagonal microkernel: plugin lifecycle, middleware pipeline, event bus.
//!
//! Doctrine (root `AGENTS.md`):
//!
//! - Plugin contracts ARE ports; plugins ARE adapters; the kernel IS the inner hexagon.
//! - The kernel never imports plugins; plugins never import each other — the bus only.
//! - The pipeline is fire-and-forget: no response context; outputs happen only via
//!   driven ports carried in the services bundle.
//! - The event bus carries only derived plugin-owned domain events, never raw inbound
//!   events; the pipeline→bus bridge is plugin behavior.
//!
//! The kernel is generic over the inbound event type `E` and the services bundle `S`,
//! so both the agent and the user-actor instantiate it with their own taxonomies.
#![forbid(unsafe_code)]

pub mod app;
pub mod bus;
pub mod models;
