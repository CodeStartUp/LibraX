//! Correlation.
//!
//! Turns a pile of signals into a small number of clusters, and records *why*
//! each link exists so the incident page can answer "why did LibraX connect
//! these events?" with specifics rather than a similarity number.
//!
//! The rule that shapes this crate: proximity in time is never sufficient. Two
//! unrelated alerts a minute apart must not become one incident, so every link
//! requires shared context -- identity, host, address, or evidence -- on top of
//! falling inside the window.

pub mod correlator;

pub use correlator::{
    Cluster, CorrelationConfig, CorrelationWeights, Correlator, Link, LinkFactor,
};
