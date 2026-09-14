//! Detection fabric.
//!
//! Detectors read canonical events and emit [`SecuritySignal`]s. Two rules hold
//! everywhere in this crate: a detector fires on *behaviour* rather than on an
//! event name, and every signal carries an explanation an analyst can argue with.
//!
//! [`SecuritySignal`]: librax_types::SecuritySignal

pub mod detectors;
pub mod engine;
pub mod support;

pub use engine::{DetectionContext, DetectionEngine, Detector};
