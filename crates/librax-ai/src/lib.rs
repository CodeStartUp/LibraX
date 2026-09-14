//! The analyst briefing layer.
//!
//! This runs *after* an incident exists. It does not detect anything and it is
//! not a model: [`DeterministicAnalyst`] is a rule-based generator that reads the
//! incident, the graph and the ATT&CK progression and writes them up. Every
//! briefing reports which generator produced it, so the console can say what the
//! reader is looking at instead of implying a model wrote it.
//!
//! [`AnalystEngine`] exists so a real model can be dropped in later. If that
//! happens, the [`Assertion`] labelling is the contract it has to honour: a claim
//! is a fact only when it cites the events that establish it.

pub mod analyst;

pub use analyst::{
    AnalystEngine, Assertion, Briefing, BriefingInput, DeterministicAnalyst, Statement,
};
