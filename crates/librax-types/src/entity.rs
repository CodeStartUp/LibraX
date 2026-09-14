use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The kinds of thing LibraX tracks as a first-class node in the graph.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    User,
    Account,
    Host,
    Ip,
    Domain,
    Process,
    Server,
    Database,
    Device,
    Session,
    Application,
    CloudResource,
    File,
    Incident,
    #[default]
    Unknown,
}

impl EntityKind {
    /// Prefix used to build stable entity keys such as `user:alice.hr`.
    pub fn prefix(self) -> &'static str {
        match self {
            EntityKind::User => "user",
            EntityKind::Account => "account",
            EntityKind::Host => "host",
            EntityKind::Ip => "ip",
            EntityKind::Domain => "domain",
            EntityKind::Process => "process",
            EntityKind::Server => "server",
            EntityKind::Database => "database",
            EntityKind::Device => "device",
            EntityKind::Session => "session",
            EntityKind::Application => "app",
            EntityKind::CloudResource => "cloud",
            EntityKind::File => "file",
            EntityKind::Incident => "incident",
            EntityKind::Unknown => "unknown",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            EntityKind::User => "User",
            EntityKind::Account => "Account",
            EntityKind::Host => "Endpoint",
            EntityKind::Ip => "IP",
            EntityKind::Domain => "Domain",
            EntityKind::Process => "Process",
            EntityKind::Server => "Server",
            EntityKind::Database => "Database",
            EntityKind::Device => "Device",
            EntityKind::Session => "Session",
            EntityKind::Application => "Application",
            EntityKind::CloudResource => "Cloud Resource",
            EntityKind::File => "File",
            EntityKind::Incident => "Incident",
            EntityKind::Unknown => "Unknown",
        }
    }
}

/// A resolved reference to something in the environment.
///
/// `id` is the stable correlation key; `name` is what an analyst reads.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EntityRef {
    pub kind: EntityKind,
    pub id: String,
    pub name: String,
}

impl EntityRef {
    pub fn new(kind: EntityKind, name: impl Into<String>) -> Self {
        let name = name.into();
        let id = format!("{}:{}", kind.prefix(), name.to_lowercase());
        Self { kind, id, name }
    }

    pub fn user(name: impl Into<String>) -> Self {
        Self::new(EntityKind::User, name)
    }

    pub fn host(name: impl Into<String>) -> Self {
        Self::new(EntityKind::Host, name)
    }

    pub fn ip(addr: impl Into<String>) -> Self {
        Self::new(EntityKind::Ip, addr)
    }

    pub fn server(name: impl Into<String>) -> Self {
        Self::new(EntityKind::Server, name)
    }

    pub fn database(name: impl Into<String>) -> Self {
        Self::new(EntityKind::Database, name)
    }

    pub fn process(name: impl Into<String>) -> Self {
        Self::new(EntityKind::Process, name)
    }
}

/// Edge semantics in the evidence graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationType {
    Uses,
    HasIp,
    Executes,
    ConnectsTo,
    AuthenticatesTo,
    LateralMovesTo,
    PrivilegedAccess,
    Accesses,
    Stages,
    ResolvesTo,
    Owns,
    Manages,
    Creates,
    Reaches,
    MemberOf,
    /// Mail delivery from an external sender to a recipient.
    Delivers,
}

impl RelationType {
    /// Uppercase label drawn on the graph edge.
    pub fn label(self) -> &'static str {
        match self {
            RelationType::Uses => "USES",
            RelationType::HasIp => "HAS_IP",
            RelationType::Executes => "EXECUTES",
            RelationType::ConnectsTo => "CONNECTS_TO",
            RelationType::AuthenticatesTo => "AUTHENTICATES_TO",
            RelationType::LateralMovesTo => "LATERAL_MOVES_TO",
            RelationType::PrivilegedAccess => "PRIVILEGED_ACCESS",
            RelationType::Accesses => "ACCESSES",
            RelationType::Stages => "STAGES",
            RelationType::ResolvesTo => "RESOLVES_TO",
            RelationType::Owns => "OWNS",
            RelationType::Manages => "MANAGES",
            RelationType::Creates => "CREATES",
            RelationType::Reaches => "REACHES",
            RelationType::MemberOf => "MEMBER_OF",
            RelationType::Delivers => "DELIVERS",
        }
    }
}

/// An evidence-backed edge. `evidence_event_ids` is mandatory in spirit: an
/// analyst clicking this edge must be able to see the events that justify it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relationship {
    pub from: EntityRef,
    pub relation: RelationType,
    pub to: EntityRef,

    pub confidence: f32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,

    pub evidence_event_ids: Vec<String>,
}

impl Relationship {
    pub fn key(&self) -> String {
        format!("{}|{}|{}", self.from.id, self.relation.label(), self.to.id)
    }
}
