//! Vendor payloads in, canonical events out.
//!
//! This is the only crate that knows what a Windows 4625 record or a firewall
//! flow summary looks like. Everything downstream sees [`CanonicalEvent`] only,
//! which is what keeps detectors from growing per-vendor branches.
//!
//! [`CanonicalEvent`]: librax_types::CanonicalEvent

pub mod normalizer;
pub mod parsers;

pub use normalizer::{NormalizeOutcome, Normalizer, RejectReason, Rejection};
