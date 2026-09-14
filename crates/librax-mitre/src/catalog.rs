use std::collections::HashMap;
use std::path::Path;

use librax_types::{MitreTechniqueRef, Tactic};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Shipped dataset. Replaceable at runtime, so upgrading ATT&CK is a data change
/// rather than a code change.
const EMBEDDED: &str = include_str!("../data/techniques.json");

#[derive(Debug, Error)]
pub enum CatalogError {
    #[error("could not read ATT&CK dataset: {0}")]
    Io(#[from] std::io::Error),

    #[error("could not parse ATT&CK dataset: {0}")]
    Parse(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technique {
    pub id: String,
    pub name: String,
    pub tactics: Vec<Tactic>,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Deserialize)]
struct Dataset {
    dataset: String,
    attack_version: String,
    techniques: Vec<Technique>,
}

/// Technique lookup, keyed by ATT&CK ID.
#[derive(Debug, Clone)]
pub struct MitreCatalog {
    dataset: String,
    attack_version: String,
    techniques: HashMap<String, Technique>,
}

impl Default for MitreCatalog {
    fn default() -> Self {
        Self::embedded()
    }
}

impl MitreCatalog {
    /// The dataset compiled into the binary, so the demo never needs network access.
    pub fn embedded() -> Self {
        Self::from_json(EMBEDDED).expect("embedded ATT&CK dataset must be valid")
    }

    pub fn from_json(raw: &str) -> Result<Self, CatalogError> {
        let dataset: Dataset = serde_json::from_str(raw)?;
        Ok(Self {
            dataset: dataset.dataset,
            attack_version: dataset.attack_version,
            techniques: dataset
                .techniques
                .into_iter()
                .map(|t| (t.id.clone(), t))
                .collect(),
        })
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, CatalogError> {
        Self::from_json(&std::fs::read_to_string(path)?)
    }

    /// Loads an override dataset if one is configured, otherwise the embedded set.
    pub fn load(path: Option<&str>) -> Self {
        match path {
            Some(path) => match Self::from_path(path) {
                Ok(catalog) => {
                    tracing::info!(path, version = %catalog.attack_version, "loaded ATT&CK dataset");
                    catalog
                }
                Err(error) => {
                    tracing::warn!(path, %error, "falling back to embedded ATT&CK dataset");
                    Self::embedded()
                }
            },
            None => Self::embedded(),
        }
    }

    pub fn attack_version(&self) -> &str {
        &self.attack_version
    }

    pub fn dataset_name(&self) -> &str {
        &self.dataset
    }

    pub fn len(&self) -> usize {
        self.techniques.len()
    }

    pub fn is_empty(&self) -> bool {
        self.techniques.is_empty()
    }

    pub fn lookup(&self, technique_id: &str) -> Option<&Technique> {
        self.techniques.get(technique_id)
    }

    /// Builds a validated reference, or `None` if the catalog has never heard of
    /// this technique. Callers treat `None` as "unmapped", never as a licence to
    /// make something up.
    pub fn reference(
        &self,
        technique_id: &str,
        confidence: f32,
        rationale: impl Into<String>,
    ) -> Option<MitreTechniqueRef> {
        let technique = self.lookup(technique_id)?;
        let tactic = *technique.tactics.first()?;
        Some(MitreTechniqueRef {
            technique_id: technique.id.clone(),
            name: technique.name.clone(),
            tactic,
            confidence: confidence.clamp(0.0, 1.0),
            rationale: rationale.into(),
        })
    }

    /// As [`Self::reference`], but pinning the tactic when a technique spans
    /// several and the observed behaviour tells us which one applies.
    pub fn reference_as(
        &self,
        technique_id: &str,
        tactic: Tactic,
        confidence: f32,
        rationale: impl Into<String>,
    ) -> Option<MitreTechniqueRef> {
        let technique = self.lookup(technique_id)?;
        if !technique.tactics.contains(&tactic) {
            tracing::debug!(
                technique_id,
                ?tactic,
                "refusing a tactic the technique does not belong to"
            );
            return None;
        }
        Some(MitreTechniqueRef {
            technique_id: technique.id.clone(),
            name: technique.name.clone(),
            tactic,
            confidence: confidence.clamp(0.0, 1.0),
            rationale: rationale.into(),
        })
    }

    /// Keeps only references the catalog recognises, refreshing their names, and
    /// reports the IDs it rejected so the UI can show them as unmapped.
    pub fn validate(&self, refs: Vec<MitreTechniqueRef>) -> (Vec<MitreTechniqueRef>, Vec<String>) {
        let mut kept = Vec::new();
        let mut unmapped = Vec::new();

        for mut reference in refs {
            match self.lookup(&reference.technique_id) {
                Some(technique) if technique.tactics.contains(&reference.tactic) => {
                    reference.name = technique.name.clone();
                    kept.push(reference);
                }
                _ => unmapped.push(reference.technique_id.clone()),
            }
        }

        (kept, unmapped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_dataset_loads() {
        let catalog = MitreCatalog::embedded();
        assert!(catalog.len() >= 15);
        assert!(!catalog.attack_version().is_empty());
    }

    #[test]
    fn demo_techniques_are_all_present() {
        let catalog = MitreCatalog::embedded();
        for id in [
            "T1566.001", "T1059.001", "T1071.001", "T1046", "T1110.003", "T1021.006", "T1213",
            "T1074.001", "T1490", "T1486", "T1498",
        ] {
            assert!(catalog.lookup(id).is_some(), "{id} missing from catalog");
        }
    }

    #[test]
    fn unknown_technique_yields_no_reference() {
        let catalog = MitreCatalog::embedded();
        assert!(catalog.reference("T9999", 0.9, "made up").is_none());
    }

    #[test]
    fn wrong_tactic_for_technique_is_refused() {
        let catalog = MitreCatalog::embedded();
        // PowerShell is Execution, never Impact.
        assert!(
            catalog
                .reference_as("T1059.001", Tactic::Impact, 0.9, "wrong tactic")
                .is_none()
        );
        assert!(
            catalog
                .reference_as("T1059.001", Tactic::Execution, 0.9, "right tactic")
                .is_some()
        );
    }

    #[test]
    fn validate_separates_known_from_unmapped() {
        let catalog = MitreCatalog::embedded();
        let refs = vec![
            catalog.reference("T1059.001", 0.9, "encoded command").unwrap(),
            MitreTechniqueRef {
                technique_id: "T0000".into(),
                name: "Invented".into(),
                tactic: Tactic::Impact,
                confidence: 0.9,
                rationale: "should be dropped".into(),
            },
        ];

        let (kept, unmapped) = catalog.validate(refs);
        assert_eq!(kept.len(), 1);
        assert_eq!(unmapped, vec!["T0000".to_string()]);
    }

    #[test]
    fn confidence_is_clamped() {
        let catalog = MitreCatalog::embedded();
        let reference = catalog.reference("T1486", 4.2, "over-eager detector").unwrap();
        assert_eq!(reference.confidence, 1.0);
    }
}
