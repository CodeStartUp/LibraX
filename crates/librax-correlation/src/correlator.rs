use std::collections::{HashMap, HashSet};

use chrono::Duration;
use librax_entities::EntityResolver;
use librax_types::{EntityKind, EntityRef, SecuritySignal, Severity};
use serde::Serialize;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkFactor {
    Temporal,
    Identity,
    Host,
    Network,
    AttackStage,
    SharedEvidence,
}

impl LinkFactor {
    pub fn label(self) -> &'static str {
        match self {
            LinkFactor::Temporal => "Close in time",
            LinkFactor::Identity => "Same identity",
            LinkFactor::Host => "Same host",
            LinkFactor::Network => "Same network address",
            LinkFactor::AttackStage => "ATT&CK progression",
            LinkFactor::SharedEvidence => "Shared evidence",
        }
    }


    pub fn is_substantive(self) -> bool {
        matches!(
            self,
            LinkFactor::Identity
                | LinkFactor::Host
                | LinkFactor::Network
                | LinkFactor::SharedEvidence
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FactorMatch {
    pub factor: LinkFactor,
    pub label: String,

    pub strength: f32,

    pub contribution: f32,
    pub detail: String,
}


#[derive(Debug, Clone, Serialize)]
pub struct Link {
    pub from_signal: String,
    pub to_signal: String,
    pub score: f32,
    pub factors: Vec<FactorMatch>,
}

impl Link {
    pub fn explains(&self) -> Vec<String> {
        self.factors.iter().map(|f| f.detail.clone()).collect()
    }
}

#[derive(Debug, Clone)]
pub struct CorrelationWeights {
    pub temporal: f32,
    pub identity: f32,
    pub host: f32,
    pub network: f32,
    pub attack_stage: f32,
    pub shared_evidence: f32,
}

impl Default for CorrelationWeights {
    fn default() -> Self {
        Self {
            temporal: 0.15,
            identity: 0.25,
            host: 0.25,
            network: 0.15,
            attack_stage: 0.15,
            shared_evidence: 0.20,
        }
    }
}

impl CorrelationWeights {
    fn total(&self) -> f32 {
        self.temporal
            + self.identity
            + self.host
            + self.network
            + self.attack_stage
            + self.shared_evidence
    }
}

#[derive(Debug, Clone)]
pub struct CorrelationConfig {

    pub window: Duration,

    pub min_link_score: f32,
    pub weights: CorrelationWeights,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            window: Duration::minutes(60),
            min_link_score: 0.30,
            weights: CorrelationWeights::default(),
        }
    }
}


#[derive(Debug, Clone, Serialize)]
pub struct Cluster {
    pub signal_ids: Vec<String>,
    pub links: Vec<Link>,

    pub cohesion: f32,
    pub shared_entities: Vec<EntityRef>,

    pub reasons: Vec<String>,
    pub peak_severity: Severity,
}

impl Cluster {
    pub fn len(&self) -> usize {
        self.signal_ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signal_ids.is_empty()
    }
}

pub struct Correlator {
    config: CorrelationConfig,
}

impl Default for Correlator {
    fn default() -> Self {
        Self::new(CorrelationConfig::default())
    }
}

impl Correlator {
    pub fn new(config: CorrelationConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &CorrelationConfig {
        &self.config
    }


    pub fn link(
        &self,
        a: &SecuritySignal,
        entities_a: &[EntityRef],
        b: &SecuritySignal,
        entities_b: &[EntityRef],
    ) -> Option<Link> {
        let weights = &self.config.weights;
        let mut factors: Vec<FactorMatch> = Vec::new();


        let gap = (b.timestamp - a.timestamp).abs();
        if gap > self.config.window {
            return None;
        }
        let window_secs = self.config.window.num_seconds().max(1) as f32;
        let closeness = 1.0 - (gap.num_seconds() as f32 / window_secs);
        factors.push(FactorMatch {
            factor: LinkFactor::Temporal,
            label: LinkFactor::Temporal.label().to_string(),
            strength: closeness,
            contribution: closeness * weights.temporal,
            detail: format!("{} minutes apart", gap.num_minutes()),
        });

        let shared = shared_entities(entities_a, entities_b);

        let identity: Vec<&EntityRef> = shared
            .iter()
            .filter(|e| matches!(e.kind, EntityKind::User | EntityKind::Account))
            .collect();
        if !identity.is_empty() {
            factors.push(FactorMatch {
                factor: LinkFactor::Identity,
                label: LinkFactor::Identity.label().to_string(),
                strength: 1.0,
                contribution: weights.identity,
                detail: format!(
                    "both involve {}",
                    identity
                        .iter()
                        .map(|e| e.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }

        let hosts: Vec<&EntityRef> = shared
            .iter()
            .filter(|e| {
                matches!(
                    e.kind,
                    EntityKind::Host
                        | EntityKind::Server
                        | EntityKind::Database
                        | EntityKind::Device
                        | EntityKind::CloudResource
                )
            })
            .collect();
        if !hosts.is_empty() {
            factors.push(FactorMatch {
                factor: LinkFactor::Host,
                label: LinkFactor::Host.label().to_string(),
                strength: 1.0,
                contribution: weights.host,
                detail: format!(
                    "both touch {}",
                    hosts
                        .iter()
                        .map(|e| e.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }

        let addresses: Vec<&EntityRef> = shared
            .iter()
            .filter(|e| matches!(e.kind, EntityKind::Ip | EntityKind::Domain))
            .collect();
        if !addresses.is_empty() {
            factors.push(FactorMatch {
                factor: LinkFactor::Network,
                label: LinkFactor::Network.label().to_string(),
                strength: 1.0,
                contribution: weights.network,
                detail: format!(
                    "shared network path via {}",
                    addresses
                        .iter()
                        .map(|e| e.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }

        let shared_evidence: Vec<&String> = a
            .evidence_event_ids
            .iter()
            .filter(|id| b.evidence_event_ids.contains(id))
            .collect();
        if !shared_evidence.is_empty() {
            factors.push(FactorMatch {
                factor: LinkFactor::SharedEvidence,
                label: LinkFactor::SharedEvidence.label().to_string(),
                strength: 1.0,
                contribution: weights.shared_evidence,
                detail: format!("{} shared evidence event(s)", shared_evidence.len()),
            });
        }


        if let (Some(first), Some(second)) = (a.primary_tactic(), b.primary_tactic()) {
            let (earlier, later) = if a.timestamp <= b.timestamp {
                (first, second)
            } else {
                (second, first)
            };
            if later.stage_order() > earlier.stage_order() {
                factors.push(FactorMatch {
                    factor: LinkFactor::AttackStage,
                    label: LinkFactor::AttackStage.label().to_string(),
                    strength: 1.0,
                    contribution: weights.attack_stage,
                    detail: format!("{} then {}", earlier.label(), later.label()),
                });
            }
        }


        if !factors.iter().any(|f| f.factor.is_substantive()) {
            return None;
        }

        let score = factors.iter().map(|f| f.contribution).sum::<f32>() / weights.total();
        if score < self.config.min_link_score {
            return None;
        }

        Some(Link {
            from_signal: a.signal_id.clone(),
            to_signal: b.signal_id.clone(),
            score,
            factors,
        })
    }


    pub fn cluster(&self, signals: &[SecuritySignal], resolver: &EntityResolver) -> Vec<Cluster> {
        if signals.is_empty() {
            return Vec::new();
        }

        let resolved: Vec<Vec<EntityRef>> =
            signals.iter().map(|s| resolver.resolve_signal(s)).collect();

        let mut union = DisjointSet::new(signals.len());
        let mut links: Vec<Link> = Vec::new();

        for i in 0..signals.len() {
            for j in (i + 1)..signals.len() {
                if let Some(link) = self.link(&signals[i], &resolved[i], &signals[j], &resolved[j])
                {
                    union.join(i, j);
                    links.push(link);
                }
            }
        }

        let mut groups: HashMap<usize, Vec<usize>> = HashMap::new();
        for index in 0..signals.len() {
            groups.entry(union.root(index)).or_default().push(index);
        }

        let mut clusters: Vec<Cluster> = groups
            .into_values()
            .map(|members| self.build_cluster(&members, signals, &resolved, &links))
            .collect();


        clusters.sort_by(|a, b| {
            b.peak_severity
                .cmp(&a.peak_severity)
                .then_with(|| b.len().cmp(&a.len()))
                .then_with(|| {
                    b.cohesion
                        .partial_cmp(&a.cohesion)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        });
        clusters
    }

    fn build_cluster(
        &self,
        members: &[usize],
        signals: &[SecuritySignal],
        resolved: &[Vec<EntityRef>],
        links: &[Link],
    ) -> Cluster {
        let ids: HashSet<&str> = members
            .iter()
            .map(|&i| signals[i].signal_id.as_str())
            .collect();

        let cluster_links: Vec<Link> = links
            .iter()
            .filter(|l| ids.contains(l.from_signal.as_str()) && ids.contains(l.to_signal.as_str()))
            .cloned()
            .collect();

        let cohesion = if cluster_links.is_empty() {
            0.0
        } else {
            cluster_links.iter().map(|l| l.score).sum::<f32>() / cluster_links.len() as f32
        };


        let mut counts: HashMap<&EntityRef, usize> = HashMap::new();
        for &index in members {
            for entity in &resolved[index] {
                *counts.entry(entity).or_insert(0) += 1;
            }
        }
        let mut shared_entities: Vec<EntityRef> = counts
            .into_iter()
            .filter(|(_, count)| *count > 1 || members.len() == 1)
            .map(|(entity, _)| entity.clone())
            .collect();
        shared_entities.sort();

        let mut reasons: Vec<String> = Vec::new();
        let mut seen_factors: HashSet<LinkFactor> = HashSet::new();
        for link in &cluster_links {
            for factor in &link.factors {
                if seen_factors.insert(factor.factor) {
                    reasons.push(format!("{}: {}", factor.label, factor.detail));
                }
            }
        }

        let peak_severity = members
            .iter()
            .map(|&i| signals[i].severity)
            .max()
            .unwrap_or(Severity::Info);

        let mut signal_ids: Vec<String> = members
            .iter()
            .map(|&i| signals[i].signal_id.clone())
            .collect();
        signal_ids.sort_by_key(|id| {
            signals
                .iter()
                .find(|s| &s.signal_id == id)
                .map(|s| s.timestamp)
        });

        Cluster {
            signal_ids,
            links: cluster_links,
            cohesion,
            shared_entities,
            reasons,
            peak_severity,
        }
    }
}

fn shared_entities(a: &[EntityRef], b: &[EntityRef]) -> Vec<EntityRef> {
    let right: HashSet<&String> = b.iter().map(|e| &e.id).collect();
    a.iter()
        .filter(|e| right.contains(&e.id))
        .cloned()
        .collect()
}


struct DisjointSet {
    parent: Vec<usize>,
}

impl DisjointSet {
    fn new(size: usize) -> Self {
        Self {
            parent: (0..size).collect(),
        }
    }

    fn root(&mut self, mut index: usize) -> usize {
        while self.parent[index] != index {
            self.parent[index] = self.parent[self.parent[index]];
            index = self.parent[index];
        }
        index
    }

    fn join(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.root(a), self.root(b));
        if ra != rb {
            self.parent[rb] = ra;
        }
    }
}
