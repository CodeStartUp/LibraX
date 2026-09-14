//! Risk and blast radius.
//!
//! Threat confidence and business impact are computed separately and never
//! folded together before the analyst sees them: a confident detection on a
//! spare laptop and a weak one on the patient database are different problems,
//! and a single blended number hides which is which.
//!
//! Every number here arrives with the contributions that produced it. Nothing in
//! this crate returns a score the UI cannot explain.

pub mod blast;
pub mod score;

pub use blast::assess_blast_radius;
pub use score::{RiskInputs, assess_risk};
