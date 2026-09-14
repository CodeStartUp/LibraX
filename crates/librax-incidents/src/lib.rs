//! Incident assembly.
//!
//! Eleven detections become one case. Two things this crate refuses to do: it
//! will not promote a lone low-grade signal into an incident just because the
//! detector fired, and it will not present an inference as a fact. Whatever the
//! evidence does not establish ends up in `unknowns`, visible to the analyst.

pub mod builder;
pub mod unknowns;

pub use builder::{BuiltIncident, IncidentBuilder, IncidentContext};
