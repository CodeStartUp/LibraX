use std::collections::{HashMap, HashSet, VecDeque};

use chrono::{DateTime, Utc};
use librax_enrichment::Platform;
use librax_types::{EntityKind, EntityRef, Exposure, RelationType};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct GraphNode {
    pub id: String,
    pub kind: EntityKind,
    pub kind_label: String,
    pub label: String,
    pub exposure: Exposure,

    pub criticality: Option<u8>,
    pub hospital: Option<String>,


    pub platform: Option<Platform>,
    pub platform_label: Option<String>,

    pub external: bool,
    pub event_count: u64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

impl GraphNode {
    pub fn entity(&self) -> EntityRef {
        EntityRef {
            kind: self.kind,
            id: self.id.clone(),
            name: self.label.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphEdge {
    pub id: String,
    pub from: String,
    pub to: String,
    pub relation: RelationType,
    pub label: String,
    pub confidence: f32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,

    pub evidence_event_ids: Vec<String>,

    pub signal_ids: Vec<String>,

    pub structural: bool,
}


#[derive(Debug, Clone, Serialize)]
pub struct Reach {
    pub node_id: String,
    pub hops: usize,
    pub exposure: Exposure,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AttackGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

impl AttackGraph {
    pub fn node(&self, id: &str) -> Option<&GraphNode> {
        self.nodes.iter().find(|n| n.id == id)
    }

    pub fn edge(&self, id: &str) -> Option<&GraphEdge> {
        self.edges.iter().find(|e| e.id == id)
    }

    pub fn edges_touching(&self, node_id: &str) -> Vec<&GraphEdge> {
        self.edges
            .iter()
            .filter(|e| e.from == node_id || e.to == node_id)
            .collect()
    }


    fn adjacency(&self) -> HashMap<&str, Vec<&str>> {
        let mut map: HashMap<&str, Vec<&str>> = HashMap::new();
        for edge in &self.edges {
            map.entry(&edge.from).or_default().push(&edge.to);
            map.entry(&edge.to).or_default().push(&edge.from);
        }
        map
    }


    pub fn reach_from(&self, origins: &[String], max_hops: usize) -> Vec<Reach> {
        let adjacency = self.adjacency();
        let mut seen: HashSet<&str> = HashSet::new();
        let mut queue: VecDeque<(&str, usize)> = VecDeque::new();
        let mut out: Vec<Reach> = Vec::new();

        for origin in origins {
            if let Some(node) = self.node(origin) {
                seen.insert(&node.id);
                queue.push_back((&node.id, 0));
                out.push(Reach {
                    node_id: node.id.clone(),
                    hops: 0,
                    exposure: Exposure::Confirmed,
                });
            }
        }

        while let Some((current, hops)) = queue.pop_front() {
            if hops >= max_hops {
                continue;
            }
            for &next in adjacency.get(current).into_iter().flatten() {
                if seen.insert(next) {
                    let next_hops = hops + 1;
                    out.push(Reach {
                        node_id: next.to_string(),
                        hops: next_hops,
                        exposure: if next_hops == 1 {
                            Exposure::Reachable
                        } else {
                            Exposure::Potential
                        },
                    });
                    queue.push_back((next, next_hops));
                }
            }
        }

        out
    }


    pub fn confirmed_node_ids(&self) -> Vec<String> {
        self.nodes
            .iter()
            .filter(|n| n.exposure == Exposure::Confirmed)
            .map(|n| n.id.clone())
            .collect()
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }


    pub fn unevidenced_edges(&self) -> Vec<&GraphEdge> {
        self.edges
            .iter()
            .filter(|e| !e.structural && e.evidence_event_ids.is_empty())
            .collect()
    }
}
