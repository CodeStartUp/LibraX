//! Containment playbooks, simulated only.
//!
//! Nothing in this crate can change the state of any system. There is no code
//! path that isolates a real endpoint or disables a real account: `simulate`
//! writes a description of what *would* happen and returns. Destructive actions
//! additionally refuse to run without a named approver, so the approval gate is
//! enforced here rather than left to the UI to remember.

pub mod engine;
pub mod playbooks;

pub use engine::{ResponseEngine, ResponseError, SimulationOutcome};
