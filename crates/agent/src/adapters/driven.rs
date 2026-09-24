//! Driven adapters: implement the hexagon's outbound ports, one family per
//! port. Fakes live beside their production twins inside each family.

pub mod broker;
pub mod clock;
pub mod config_toml;
pub mod killer;
pub mod launcher;
pub mod scope_store;
pub mod shell_association;
pub mod upload;
