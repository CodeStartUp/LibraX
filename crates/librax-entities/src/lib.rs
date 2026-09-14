//! Entity resolution.
//!
//! Cross-source correlation only works if the firewall's `10.10.2.15` and the
//! EDR agent's `HR-PC-23` are understood to be the same machine. This crate owns
//! that collapse, and it refuses to guess: an address with no matching asset
//! stays an IP entity rather than being attached to a plausible-looking host.

pub mod resolver;

pub use resolver::{EntityResolver, ResolvedEntity};
