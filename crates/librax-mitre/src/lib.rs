//! ATT&CK as a knowledge layer over behaviour that has already been detected.
//!
//! Detectors propose technique IDs with a rationale; this crate is what decides
//! whether the proposal is real. An unknown ID is dropped and reported as
//! unmapped rather than invented, and nothing here infers a technique from an
//! event name.

pub mod catalog;
pub mod progression;

pub use catalog::{CatalogError, MitreCatalog, Technique};
pub use progression::{Progression, StageStatus};
