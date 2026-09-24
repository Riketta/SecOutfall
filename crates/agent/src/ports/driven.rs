//! Driven ports: outbound infrastructure the hexagon calls (never the
//! reverse — inbound events enter only through the kernel inlet).

pub mod broker;
pub mod clock;
pub mod process_killer;
pub mod process_launcher;
pub mod scope_repository;
pub mod shell_association;
pub mod uploader;
