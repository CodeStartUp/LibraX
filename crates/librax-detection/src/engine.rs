use std::sync::Arc;

use librax_mitre::MitreCatalog;
use librax_types::{CanonicalEvent, SecuritySignal};

use crate::detectors;

/// What a detector gets to look at: a window of canonical events plus the
/// ATT&CK catalog, so technique proposals are validated at the point of use.
pub struct DetectionContext<'a> {
    pub events: &'a [CanonicalEvent],
    pub catalog: &'a MitreCatalog,
}

impl<'a> DetectionContext<'a> {
    /// Events matching a predicate, which is how detectors scope themselves to
    /// the sources they understand.
    pub fn matching<F>(&self, predicate: F) -> impl Iterator<Item = &'a CanonicalEvent>
    where
        F: Fn(&CanonicalEvent) -> bool + 'a,
    {
        self.events.iter().filter(move |e| predicate(e))
    }
}

pub trait Detector: Send + Sync {
    fn id(&self) -> &'static str;

    fn title(&self) -> &'static str;

    fn evaluate(&self, ctx: &DetectionContext<'_>) -> Vec<SecuritySignal>;
}

/// Runs every detector over a window of events.
pub struct DetectionEngine {
    detectors: Vec<Box<dyn Detector>>,
    catalog: Arc<MitreCatalog>,
}

impl DetectionEngine {
    pub fn new(catalog: Arc<MitreCatalog>) -> Self {
        Self {
            detectors: detectors::all(),
            catalog,
        }
    }

    pub fn detector_ids(&self) -> Vec<&'static str> {
        self.detectors.iter().map(|d| d.id()).collect()
    }

    pub fn detector_count(&self) -> usize {
        self.detectors.len()
    }

    /// Evaluates the window and returns signals in timeline order.
    ///
    /// Signal IDs are derived from the detector plus its primary event, so
    /// re-running over an overlapping window cannot double-count.
    pub fn run(&self, events: &[CanonicalEvent]) -> Vec<SecuritySignal> {
        let ctx = DetectionContext {
            events,
            catalog: &self.catalog,
        };

        let mut signals: Vec<SecuritySignal> = self
            .detectors
            .iter()
            .flat_map(|detector| {
                let produced = detector.evaluate(&ctx);
                if !produced.is_empty() {
                    tracing::debug!(
                        detector = detector.id(),
                        count = produced.len(),
                        "detector fired"
                    );
                }
                produced
            })
            .collect();

        signals.sort_by(|a, b| {
            a.timestamp
                .cmp(&b.timestamp)
                .then_with(|| a.signal_id.cmp(&b.signal_id))
        });
        signals.dedup_by(|a, b| a.signal_id == b.signal_id);
        signals
    }
}
