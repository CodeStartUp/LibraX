//! The evidence-backed attack graph.
//!
//! Every edge records the event ids that justify it. That is the whole point:
//! an analyst clicking `Alice -> HR-PC-23` must see the directory and endpoint
//! records that prove the relationship, not a confidence score with nothing
//! behind it. Structural facts from the asset inventory are the one exception,
//! and they are marked as such rather than dressed up as observations.

pub mod builder;
pub mod graph;

pub use builder::build;
pub use graph::{AttackGraph, GraphEdge, GraphNode, Reach};
// Re-exported so consumers of a graph node can read its platform without taking a
// direct dependency on the inventory crate.
pub use librax_enrichment::Platform;
