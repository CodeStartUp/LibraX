# LibraX — Rust Enterprise SOC Architecture Specification

Version: 1.0
Language: Rust
Purpose: Hack2Innovate 2026 PS-02 — SOC Alert Correlation & Threat Prioritization

---

## 1. Product Definition

LibraX is a correlation-first SOC platform for high-volume heterogeneous security telemetry.

Core transformation:

    RAW TELEMETRY
        -> INGEST
        -> NORMALIZE
        -> ENRICH
        -> DETECT
        -> RESOLVE ENTITIES
        -> CORRELATE
        -> BUILD EVIDENCE GRAPH
        -> MAP MITRE ATT&CK
        -> SCORE RISK
        -> CALCULATE BLAST RADIUS
        -> CREATE INCIDENT
        -> INVESTIGATE
        -> RECOMMEND / SIMULATE RESPONSE

Target demonstration scale:

- 18 hospital campuses
- 10,000+ endpoints
- 1,000+ servers/devices
- 20,000+ security alerts per hour
- Multiple security and business telemetry sources

The hackathon implementation uses synthetic telemetry to demonstrate enterprise-scale behavior.

---

## 2. Architecture Principle

DO NOT build LibraX as:

    every source -> dashboard

Build:

    many sources
        -> common event model
        -> security signals
        -> cross-domain entity context
        -> evidence-backed attack graph
        -> one explainable incident

The correlation engine should not process every raw network packet.
High-volume network telemetry should be reduced to useful metadata/signals
(flow, DNS, connection, IDS/NDR events) before expensive correlation.

---

## 3. High-Level Architecture

                    ENTERPRISE SECURITY ENVIRONMENT
                              |
       +----------------------+--------------------------+
       |          |           |          |               |
      AD/Entra   EDR       Firewall     VPN            Cloud
       |          |           |          |               |
      PAM       Servers      IDS/NDR    Proxy        Kubernetes
       |          |           |          |               |
      PACS     Database      DNS       Email         Applications
       +----------+-----------+----------+---------------+
                              |
                              v
                     CONNECTOR / COLLECTOR
                              |
                              v
                       EVENT BUS / QUEUE
                    Kafka / Redpanda / NATS
                              |
                              v
                    NORMALIZATION LAYER
                              |
                       Common Event Model
                              |
                              v
                      ENRICHMENT LAYER
                              |
        +---------------------+----------------------+
        |                     |                      |
     Identity               Asset              Threat Intel
        |                     |                      |
        +---------------------+----------------------+
                              |
                              v
                       DETECTION FABRIC
                              |
        +----------+----------+----------+-----------+
        |          |                     |           |
       Rules    Behavior              Network     Identity
                  /Anomaly                         Detection
        +----------+----------+----------+-----------+
                              |
                              v
                    ENTITY RESOLUTION
                              |
                    User / Host / IP / Process
                    Account / Server / DB / Device
                              |
                              v
                    CORRELATION ENGINE
                              |
          +-------------------+-------------------+
          |                   |                   |
      Temporal            Identity            Graph
     Correlation         Correlation        Correlation
          +-------------------+-------------------+
                              |
                              v
                     EVIDENCE GRAPH
                              |
                              v
                 ATT&CK ATTACK PROGRESSION
                              |
                              v
                       RISK ENGINE
                              |
             +----------------+----------------+
             |                |                |
       Threat Confidence  Business Impact  Blast Radius
             +----------------+----------------+
                              |
                              v
                     INCIDENT BUILDER
                              |
                +-------------+-------------+
                |                           |
          SOC INVESTIGATION             SOAR / RESPONSE
                |                           |
        Graph / Timeline             isolate / disable /
        MITRE / Evidence             block / revoke /
        Risk / Unknowns              escalate / simulate
                |
                v
             AI ANALYST
                |
       explain / summarize / recommend

---

## 4. Rust Workspace

Use a Cargo workspace.

librax/
├── Cargo.toml
├── README.md
├── LICENSE
├── .env.example
├── docker-compose.yml
├── docs/
├── configs/
├── data/
├── crates/
├── services/
├── simulator/
├── tests/
└── scripts/

Recommended Rust workspace:

crates/
├── librax-types/
├── librax-config/
├── librax-observability/
├── librax-connectors/
├── librax-normalizer/
├── librax-enrichment/
├── librax-detection/
├── librax-entities/
├── librax-correlation/
├── librax-graph/
├── librax-mitre/
├── librax-risk/
├── librax-incidents/
├── librax-response/
├── librax-storage/
└── librax-ai/

services/
├── librax-api/
├── librax-ingest/
├── librax-detection-worker/
├── librax-correlation-worker/
├── librax-incident-worker/
└── librax-simulator/

---

## 5. Crate Responsibilities

### librax-types

Canonical shared Rust types.

Owns:

- Event
- Alert
- Entity
- Relationship
- Evidence
- Incident
- MitreTechnique
- RiskScore
- BlastRadius
- ResponseAction

This crate must have very few dependencies.

### librax-config

Loads:

- environment variables
- YAML/TOML configuration
- connector configuration
- rules
- scoring weights
- asset criticality

### librax-connectors

Connector SDK.

Interface concept:

    Connector
      -> connect()
      -> health()
      -> collect()
      -> parse()
      -> emit()

Initial connectors:

- Active Directory
- Entra ID
- EDR
- Firewall
- VPN
- PAM
- DNS
- Server
- Database
- PACS
- Cloud

For the hackathon, connectors may read JSON/CSV files or simulated streams.

### librax-normalizer

Converts vendor-specific events into a canonical security event.

Pipeline:

    RawEvent
      -> Parse
      -> Validate
      -> Normalize
      -> CanonicalEvent

Use an OCSF-inspired internal structure.

### librax-enrichment

Adds context:

- identity
- asset metadata
- business owner
- hospital/site
- vulnerability context
- threat intelligence
- IP/domain reputation
- asset criticality

### librax-detection

Produces SecuritySignal objects.

Detectors:

- phishing
- PowerShell
- credential abuse
- abnormal login
- port scan
- lateral movement
- command-and-control
- DDoS
- data staging
- ransomware indicators

Detection must be explainable.

Each signal should include:

- detector_id
- severity
- confidence
- evidence_event_ids
- entities
- MITRE candidate mapping

### librax-entities

Resolves identities and entities.

Examples:

    alice.hr
      -> user:alice.hr
      -> device:HR-PC-23
      -> ip:10.10.2.15
      -> department:HR
      -> hospital:Campus-04

Entity types:

- User
- Account
- Host
- IP
- Domain
- Process
- Server
- Database
- Device
- CloudResource
- Application
- Session

### librax-correlation

Combines signals.

Methods:

1. temporal correlation
2. identity correlation
3. entity correlation
4. rule correlation
5. graph correlation
6. similarity scoring
7. clustering

Example correlation score:

    score =
        time_similarity
      + identity_similarity
      + host_similarity
      + network_similarity
      + attack_stage_similarity
      + shared_evidence

Do not use one signal alone to declare an incident.

### librax-graph

Builds the evidence-backed attack graph.

Node examples:

    User
    Account
    Host
    IP
    Process
    Server
    Database
    File
    Session
    Incident

Edge examples:

    USES
    AUTHENTICATES_TO
    EXECUTES
    CONNECTS_TO
    ACCESSES
    CREATES
    RESOLVES_TO
    OWNS
    MANAGES
    LATERALLY_MOVES_TO

Every relationship should retain evidence_event_ids.

### librax-mitre

Current-version ATT&CK integration.

Responsibilities:

- load machine-readable ATT&CK data
- technique/sub-technique mapping
- tactic mapping
- attack progression
- detection-to-technique links

Do not hard-code old ATT&CK data-source assumptions.

### librax-risk

Calculates separate:

- Threat Confidence
- Business Impact
- Overall Risk
- Blast Radius

Example:

    overall_risk =
        f(
            threat_confidence,
            business_impact,
            attack_progression,
            asset_criticality
        )

The UI must explain the score.

### librax-incidents

Converts correlated signals to a case.

Responsibilities:

- deduplication
- incident clustering
- timeline
- evidence aggregation
- status
- ownership
- analyst notes
- investigation state

### librax-response

SOAR-style response orchestration.

Actions:

- isolate endpoint
- disable account
- revoke session
- block IP/domain
- quarantine file
- kill process
- create case
- notify analyst

For the hackathon use simulation mode, not real production actions.

### librax-storage

Persistence adapters.

Recommended prototype:

- PostgreSQL
- optional graph store abstraction
- object storage for raw events

Do not couple business logic directly to SQL.

### librax-ai

AI operates on already-correlated incidents.

Functions:

- incident summary
- evidence explanation
- risk explanation
- unknowns
- recommended investigation steps
- recommended response playbook

AI must not be the only detection mechanism.

---

## 6. Canonical Event

Core Rust concept:

```rust
pub struct CanonicalEvent {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub category: EventCategory,
    pub activity: String,

    pub principal: Option<EntityRef>,
    pub source: Option<NetworkEndpoint>,
    pub destination: Option<NetworkEndpoint>,

    pub host: Option<EntityRef>,
    pub process: Option<ProcessContext>,

    pub severity: Severity,
    pub raw_reference: Option<String>,
    pub attributes: HashMap<String, Value>,
}
```

The actual implementation can evolve, but ALL sources must converge on this model.

---

## 7. Security Signal

```rust
pub struct SecuritySignal {
    pub signal_id: String,
    pub detector_id: String,
    pub timestamp: DateTime<Utc>,

    pub severity: Severity,
    pub confidence: f32,

    pub entities: Vec<EntityRef>,
    pub evidence_event_ids: Vec<String>,

    pub mitre: Vec<MitreTechniqueRef>,

    pub explanation: String,
}
```

Example:

    detector = "powershell_encoded_command"
    confidence = 0.91
    MITRE = T1059.001
    evidence = [EVT-1023]

---

## 8. Evidence-Backed Relationship

```rust
pub struct Relationship {
    pub from: EntityRef,
    pub relation: RelationType,
    pub to: EntityRef,

    pub confidence: f32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,

    pub evidence_event_ids: Vec<String>,
}
```

The analyst must be able to click an edge and see WHY LibraX believes the relationship exists.

---

## 9. Incident

```rust
pub struct Incident {
    pub incident_id: String,
    pub title: String,

    pub signals: Vec<String>,
    pub evidence: Vec<String>,

    pub threat_confidence: f32,
    pub business_impact: f32,
    pub overall_risk: f32,

    pub blast_radius: BlastRadius,

    pub mitre_techniques: Vec<MitreTechniqueRef>,

    pub status: IncidentStatus,

    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}
```

---

## 10. Main Attack Scenario

The mandatory demonstration scenario is:

    HR phishing
       ->
    VPN / identity anomaly
       ->
    PowerShell
       ->
    command-and-control
       ->
    network discovery
       ->
    credential abuse
       ->
    lateral movement
       ->
    PAM privileged access
       ->
    database access
       ->
    data staging
       ->
    ransomware indicators

The expected output is ONE incident:

    INC-0042
    Multi-Stage Healthcare Intrusion

With:

    Threat Confidence: 94%
    Business Impact: 99%
    Overall Risk: 97%
    Blast Radius: CRITICAL

Values above are demo examples and should be calculated by the actual engine.

---

## 11. Attack Graph

Example:

                    Alice
                      |
                    USES
                      |
                   HR-PC-23
                      |
                  EXECUTES
                      |
                 PowerShell
                      |
                  CONNECTS
                      |
                ATTACKER-IP
                      |
                LATERAL-MOVES
                      |
                  APP-SRV-07
                      |
               PRIVILEGED ACCESS
                      |
                 DB-SRV-02
                      |
                  ACCESSES
                      |
                 PATIENT-DB
                      |
                   STAGES
                      |
                archive.zip

Every edge should expose evidence.

---

## 12. MITRE Layer

ATT&CK is a knowledge layer over detected behavior.

Flow:

    Detection
        ->
    Technique/Sub-technique
        ->
    Tactic
        ->
    Attack progression
        ->
    Incident

Example mappings for the demo must be validated against the current ATT&CK release.

Potential storyline mappings include:

- Phishing
- PowerShell
- Valid Accounts
- Network Discovery
- Remote Services
- Data Staged
- Impact/Ransomware-related behavior

Never claim a technique purely from a keyword; mapping must be based on observed behavior.

---

## 13. Risk Model

Maintain independent components.

    Threat Confidence
        = evidence quality
        + detector confidence
        + cross-source agreement

    Business Impact
        = asset criticality
        + data sensitivity
        + service criticality
        + privilege level

    Attack Progression
        = breadth and sequence of observed attack stages

    Overall Risk
        = normalized combination of the above

The explanation panel must show contributing factors.

Example:

    +20 critical database
    +18 privileged account
    +15 multi-stage progression
    +14 cross-source evidence
    +12 identity correlation
    +10 threat-intel evidence
    +08 abnormal behavior
    -05 known maintenance context

---

## 14. Blast Radius

Graph traversal estimates:

- affected users
- affected endpoints
- affected servers
- critical systems
- PACS/EMR/database assets
- potentially reachable assets

Example:

    Users: 3
    Endpoints: 7
    Servers: 4
    Critical DBs: 2
    PACS: 1
    Potentially reachable: 9

---

## 15. High-Volume Design

Do not send raw packets into correlation.

Use:

    Raw Network Traffic
        ->
    Flow / DNS / Connection Metadata
        ->
    Detection
        ->
    Security Signal
        ->
    Correlation

High-volume processing:

    Source
      ->
    Connector
      ->
    Event Bus
      ->
    Partition
      ->
    Worker
      ->
    Normalize
      ->
    Detect
      ->
    Correlate

Scale workers horizontally.

---

## 16. Source Health

Every connector should publish health:

```text
source_id
last_event_at
events_per_minute
expected_rate
coverage
status
```

Example:

    EDR coverage
    9,871 / 10,482 endpoints
    94.2%

If a source stops sending events, create a visibility warning.

---

## 17. Storage

Prototype:

    PostgreSQL
    local object files
    in-memory graph / NetworkX equivalent

Enterprise target:

    Event Bus
        +
    Search store
        +
    Graph store
        +
    Object storage

Keep storage behind repository traits.

---

## 18. Rust Service Boundaries

### librax-ingest

Receives raw source events.

### librax-detection-worker

Consumes canonical events and creates signals.

### librax-correlation-worker

Consumes signals and maintains correlation windows/graphs.

### librax-incident-worker

Builds/updates incidents and scores.

### librax-api

REST/WebSocket API consumed by frontend.

### librax-simulator

Generates 10,000+ endpoint synthetic environment and attack scenarios.

---

## 19. API Contract

POST /api/v1/events

POST /api/v1/signals

GET  /api/v1/incidents

GET  /api/v1/incidents/{id}

GET  /api/v1/incidents/{id}/timeline

GET  /api/v1/incidents/{id}/graph

GET  /api/v1/incidents/{id}/mitre

GET  /api/v1/incidents/{id}/risk

GET  /api/v1/incidents/{id}/blast-radius

GET  /api/v1/assets

GET  /api/v1/identities

GET  /api/v1/sources/health

POST /api/v1/incidents/{id}/response/simulate

GET  /api/v1/health

---

## 20. Frontend Pages

Dashboard:

- events/sec
- active incidents
- critical incidents
- alert reduction
- source health
- top techniques
- affected assets

Incident page:

- incident title
- risk
- threat confidence
- business impact
- blast radius
- attack graph
- timeline
- MITRE chain
- evidence
- unknowns
- response actions

Data Sources page:

- connector status
- events/min
- coverage
- last event
- errors

---

## 21. Four-Person Build Allocation

Member 1:
    Rust ingestion + connectors + normalization

Member 2:
    detection + correlation + graph

Member 3:
    risk + MITRE + incidents + API

Member 4:
    React dashboard + simulator + integration/demo

Captain:
    integration, architecture, testing, presentation

---

## 22. MVP Order

Build exactly in this order:

1. CanonicalEvent
2. Simulated AD/EDR/Firewall/Server events
3. Normalizer
4. Detection signals
5. Entity resolver
6. Temporal correlation
7. Graph builder
8. Incident builder
9. ATT&CK mapping
10. Risk score
11. Blast radius
12. API
13. Dashboard
14. Demo scenario
15. Response simulation

Do not start with AI.

Do not start with Kafka.

Do not start with a graph database.

First make one attack flow correctly become one incident.

---

## 23. Definition of Done

The MVP is successful when:

    20,000+ simulated events
        ->
    security signals
        ->
    one multi-stage incident
        ->
    visible attack graph
        ->
    MITRE mapping
        ->
    explainable risk score
        ->
    blast radius
        ->
    analyst response recommendation

The judge should be able to see the entire transformation live.

---

## 24. Product Statement

LibraX is not positioned as a replacement for a commercial SIEM.

Position it as:

    "An evidence-driven attack reconstruction and
     threat prioritization layer that converts
     heterogeneous SOC telemetry into explainable
     incidents."

Core differentiator:

    Signals -> Evidence -> Graph -> Attack Story -> Risk -> Response

