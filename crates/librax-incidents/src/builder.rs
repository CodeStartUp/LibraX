use std::collections::{HashMap, HashSet};

use librax_correlation::Cluster;
use librax_enrichment::Inventory;
use librax_entities::EntityResolver;
use librax_graph::AttackGraph;
use librax_mitre::{MitreCatalog, Progression, progression};
use librax_risk::{RiskInputs, assess_blast_radius, assess_risk};
use librax_types::{
    CanonicalEvent, Evidence, Incident, IncidentStatus, Relationship, SecuritySignal, Severity,
};

use crate::unknowns;


const BLAST_HOPS: usize = 2;


const MIN_SIGNALS_FOR_MULTI_STAGE: usize = 2;
const MIN_TACTICS_FOR_MULTI_STAGE: usize = 2;
const LONE_SIGNAL_MIN_CONFIDENCE: f32 = 0.70;


const MULTI_STAGE_THRESHOLD: usize = 5;

pub struct IncidentContext<'a> {
    pub signals: &'a [SecuritySignal],
    pub events: &'a [CanonicalEvent],
    pub resolver: &'a EntityResolver,
    pub inventory: &'a Inventory,
    pub catalog: &'a MitreCatalog,
}


pub struct BuiltIncident {
    pub incident: Incident,
    pub graph: AttackGraph,
    pub progression: Progression,

    pub correlation_reasons: Vec<String>,
    pub unmapped_techniques: Vec<String>,
}


pub struct IncidentBuilder {
    first_number: u64,
    next_number: u64,


    assigned: HashMap<String, String>,
}

impl Default for IncidentBuilder {
    fn default() -> Self {

        Self::starting_at(42)
    }
}

impl IncidentBuilder {
    pub fn starting_at(first_number: u64) -> Self {
        Self {
            first_number,
            next_number: first_number,
            assigned: HashMap::new(),
        }
    }


    fn id_for(&mut self, anchor: &str) -> String {
        if let Some(existing) = self.assigned.get(anchor) {
            return existing.clone();
        }

        let id = format!("INC-{:04}", self.next_number);
        self.next_number += 1;
        self.assigned.insert(anchor.to_string(), id.clone());
        id
    }


    pub fn reset(&mut self) {
        self.assigned.clear();
        self.next_number = self.first_number;
    }


    pub fn build(&mut self, ctx: &IncidentContext<'_>, cluster: &Cluster) -> Option<BuiltIncident> {
        let signals: Vec<SecuritySignal> = ctx
            .signals
            .iter()
            .filter(|s| cluster.signal_ids.contains(&s.signal_id))
            .cloned()
            .collect();

        if signals.is_empty() {
            return None;
        }

        let proposed: Vec<_> = signals.iter().flat_map(|s| s.mitre.clone()).collect();
        let (techniques, unmapped) = ctx.catalog.validate(proposed);
        let prog = progression::analyse(&techniques);

        if !promotable(&signals, &prog) {


            tracing::trace!(
                signals = signals.len(),
                stages = prog.observed_stages,
                "cluster left as signals rather than promoted to an incident"
            );
            return None;
        }


        let cited: HashSet<&str> = signals
            .iter()
            .flat_map(|s| s.evidence_event_ids.iter().map(|id| id.as_str()))
            .collect();
        let events: Vec<CanonicalEvent> = ctx
            .events
            .iter()
            .filter(|e| cited.contains(e.event_id.as_str()))
            .cloned()
            .collect();

        let graph = librax_graph::build(&events, &signals, ctx.resolver, ctx.inventory);

        let risk = assess_risk(&RiskInputs {
            signals: &signals,
            events: &events,
            graph: &graph,
            progression_score: prog.score,
            correlation_cohesion: cluster.cohesion,
        });
        let blast_radius = assess_blast_radius(&graph, ctx.inventory, BLAST_HOPS);

        let evidence = build_evidence(&events, &signals);
        let relationships = build_relationships(&graph);

        let first_seen = signals.iter().map(|s| s.timestamp).min()?;
        let last_seen = signals.iter().map(|s| s.timestamp).max()?;


        let anchor = signals
            .iter()
            .min_by_key(|s| (s.timestamp, s.signal_id.clone()))
            .map(|s| s.signal_id.clone())?;

        let peak_signal_severity = signals
            .iter()
            .map(|s| s.severity)
            .max()
            .unwrap_or(Severity::Info);

        let incident = Incident {
            incident_id: self.id_for(&anchor),
            title: title_for(&signals, &prog),
            status: IncidentStatus::New,
            signals: signals.iter().map(|s| s.signal_id.clone()).collect(),
            evidence,
            entities: cluster.shared_entities.clone(),
            relationships,
            risk,
            blast_radius,
            mitre_techniques: techniques,
            peak_signal_severity,
            unknowns: unknowns::derive(&signals, &events, ctx.inventory, &unmapped),
            first_seen,
            last_seen,
            owner: None,
            notes: Vec::new(),
        };

        Some(BuiltIncident {
            incident,
            graph,
            progression: prog,
            correlation_reasons: cluster.reasons.clone(),
            unmapped_techniques: unmapped,
        })
    }


    pub fn build_all(
        &mut self,
        ctx: &IncidentContext<'_>,
        clusters: &[Cluster],
    ) -> Vec<BuiltIncident> {
        let built: Vec<BuiltIncident> = clusters
            .iter()
            .filter_map(|cluster| self.build(ctx, cluster))
            .collect();

        tracing::debug!(
            clusters = clusters.len(),
            incidents = built.len(),
            left_as_signals = clusters.len() - built.len(),
            "incidents assembled"
        );

        built
    }
}


fn promotable(signals: &[SecuritySignal], prog: &Progression) -> bool {
    if signals.len() >= MIN_SIGNALS_FOR_MULTI_STAGE
        && prog.observed_stages >= MIN_TACTICS_FOR_MULTI_STAGE
    {
        return true;
    }


    signals.len() == 1
        && signals[0].severity >= Severity::High
        && signals[0].confidence >= LONE_SIGNAL_MIN_CONFIDENCE
}

fn title_for(signals: &[SecuritySignal], prog: &Progression) -> String {
    if prog.observed_stages >= MULTI_STAGE_THRESHOLD {
        return "Multi-Stage Healthcare Intrusion".to_string();
    }

    let peak = signals
        .iter()
        .max_by(|a, b| {
            a.severity.cmp(&b.severity).then_with(|| {
                a.confidence
                    .partial_cmp(&b.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        })
        .map(|s| s.title.clone())
        .unwrap_or_else(|| "Security incident".to_string());

    if signals.len() > 1 {
        format!("{peak} (+{} related detections)", signals.len() - 1)
    } else {
        peak
    }
}

fn build_evidence(events: &[CanonicalEvent], signals: &[SecuritySignal]) -> Vec<Evidence> {
    let mut evidence: Vec<Evidence> = events
        .iter()
        .map(|event| Evidence {
            event_id: event.event_id.clone(),
            source_type: event.source_type,
            timestamp: event.timestamp,
            severity: event.severity,
            summary: event.message.clone(),
            cited_by: signals
                .iter()
                .filter(|s| s.evidence_event_ids.contains(&event.event_id))
                .map(|s| s.detector_id.clone())
                .collect(),
        })
        .collect();

    evidence.sort_by_key(|e| e.timestamp);
    evidence
}


fn build_relationships(graph: &AttackGraph) -> Vec<Relationship> {
    graph
        .edges
        .iter()
        .filter_map(|edge| {
            let from = graph.node(&edge.from)?;
            let to = graph.node(&edge.to)?;
            Some(Relationship {
                from: from.entity(),
                relation: edge.relation,
                to: to.entity(),
                confidence: edge.confidence,
                first_seen: edge.first_seen,
                last_seen: edge.last_seen,
                evidence_event_ids: edge.evidence_event_ids.clone(),
            })
        })
        .collect()
}
