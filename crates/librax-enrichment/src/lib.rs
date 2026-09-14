//! Business and identity context for canonical events.
//!
//! This crate owns the synthetic hospital environment (the [`Inventory`]) so the
//! simulator and the enrichment pipeline derive the *same* world from the same
//! seed. Nothing here is random at runtime: given a seed, the environment is
//! byte-for-byte reproducible, which is what makes the demo repeatable.

pub mod enrich;
pub mod intel;
pub mod inventory;

pub use enrich::Enricher;
pub use intel::{FLEET_SOFTWARE, IocKind, IocRecord, IocVerdict, ThreatIntel, hashes};
pub use inventory::{
    Asset, AssetRole, Hospital, Identity, Inventory, InventorySpec, Platform, demo,
};
