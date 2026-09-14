use librax_types::{MitreTechniqueRef, Tactic};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StageStatus {
    /// At least one technique in this stage has evidence behind it.
    Observed,
    NotObserved,
}

#[derive(Debug, Clone, Serialize)]
pub struct Stage {
    pub tactic: Tactic,
    pub tactic_id: String,
    pub label: String,
    pub status: StageStatus,
    pub techniques: Vec<MitreTechniqueRef>,
}

/// How far along the kill chain an incident has actually been observed to travel.
#[derive(Debug, Clone, Serialize)]
pub struct Progression {
    pub stages: Vec<Stage>,
    pub observed_stages: usize,
    pub total_stages: usize,
    pub furthest: Option<Tactic>,
    /// 0-100. Deliberately suppressed when only one or two stages are evidenced,
    /// because a lone technique is an alert, not a campaign.
    pub score: f32,
}

impl Progression {
    pub fn observed_tactics(&self) -> Vec<Tactic> {
        self.stages
            .iter()
            .filter(|s| s.status == StageStatus::Observed)
            .map(|s| s.tactic)
            .collect()
    }
}

/// Buckets validated technique references into the UI's attack-chain ribbon.
pub fn analyse(refs: &[MitreTechniqueRef]) -> Progression {
    let chain = Tactic::chain();

    let stages: Vec<Stage> = chain
        .iter()
        .map(|&tactic| {
            let techniques: Vec<MitreTechniqueRef> = refs
                .iter()
                .filter(|r| r.tactic == tactic)
                .cloned()
                .collect();

            Stage {
                tactic,
                tactic_id: tactic.id().to_string(),
                label: tactic.label().to_string(),
                status: if techniques.is_empty() {
                    StageStatus::NotObserved
                } else {
                    StageStatus::Observed
                },
                techniques,
            }
        })
        .collect();

    let observed_stages = stages
        .iter()
        .filter(|s| s.status == StageStatus::Observed)
        .count();

    // Techniques outside the ribbon (Defense Evasion, Persistence) still count
    // towards how far the intrusion reached.
    let furthest = refs.iter().map(|r| r.tactic).max_by_key(|t| t.stage_order());

    let breadth = observed_stages as f32 / chain.len() as f32;
    let depth = furthest
        .map(|t| t.stage_order() as f32 / Tactic::Impact.stage_order() as f32)
        .unwrap_or(0.0);

    let mut score = 100.0 * (0.65 * breadth + 0.35 * depth);
    if observed_stages <= 1 {
        score *= 0.25;
    } else if observed_stages == 2 {
        score *= 0.60;
    }

    Progression {
        stages,
        observed_stages,
        total_stages: chain.len(),
        furthest,
        score: score.clamp(0.0, 100.0),
    }
}

#[cfg(test)]
mod tests {
    use crate::MitreCatalog;

    use super::*;

    fn refs(ids: &[&str]) -> Vec<MitreTechniqueRef> {
        let catalog = MitreCatalog::embedded();
        ids.iter()
            .filter_map(|id| catalog.reference(id, 0.9, "test"))
            .collect()
    }

    #[test]
    fn one_stage_scores_far_below_a_full_chain() {
        let single = analyse(&refs(&["T1059.001"]));
        let full = analyse(&refs(&[
            "T1566.001", "T1059.001", "T1071.001", "T1110.003", "T1046", "T1021.006", "T1213",
            "T1486",
        ]));

        assert_eq!(single.observed_stages, 1);
        assert_eq!(full.observed_stages, 8);
        assert!(
            single.score < full.score / 3.0,
            "single technique {} must not resemble a campaign {}",
            single.score,
            full.score
        );
    }

    #[test]
    fn full_demo_chain_reaches_every_stage() {
        let progression = analyse(&refs(&[
            "T1566.001", "T1059.001", "T1071.001", "T1110.003", "T1046", "T1021.006", "T1213",
            "T1490",
        ]));

        assert_eq!(progression.observed_stages, progression.total_stages);
        assert_eq!(progression.furthest, Some(Tactic::Impact));
        assert!(progression.score > 95.0);
    }

    #[test]
    fn empty_input_scores_zero() {
        let progression = analyse(&[]);
        assert_eq!(progression.observed_stages, 0);
        assert_eq!(progression.score, 0.0);
        assert!(progression.furthest.is_none());
    }

    #[test]
    fn ribbon_always_lists_every_stage() {
        let progression = analyse(&refs(&["T1059.001"]));
        assert_eq!(progression.stages.len(), Tactic::chain().len());
        assert!(
            progression
                .stages
                .iter()
                .any(|s| s.status == StageStatus::NotObserved)
        );
    }
}
