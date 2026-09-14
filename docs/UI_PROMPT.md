# LibraX — UI BUILD PROMPT

You are building the frontend for LibraX, an enterprise SOC attack-reconstruction platform.

IMPORTANT:
Do not make this look like a generic admin dashboard.
It should look like a professional 24/7 Security Operations Center.

## Product UX principle

The analyst should understand an incident in under 30 seconds:

    What happened?
    Why is it dangerous?
    What assets/users are affected?
    What evidence proves the correlation?
    Where is the attacker in the attack chain?
    What should I investigate or do next?

The UI is NOT a collection of charts.
The attack graph and incident investigation are the primary experience.

---

# 1. VISUAL STYLE

Theme:

- dark SOC interface
- near-black background
- charcoal cards
- high contrast typography
- restrained red/orange/yellow severity colors
- subtle blue/cyan for neutral system information
- thin borders
- minimal gradients
- dense but readable information
- no glassmorphism overload
- no excessive rounded cards
- no decorative 3D graphics

Overall feeling:

    modern SOC + enterprise security command center

Typography:

- Inter or system sans-serif
- compact headings
- tabular numerals for metrics
- clear hierarchy

Severity:

    CRITICAL = red
    HIGH     = orange
    MEDIUM   = yellow
    LOW      = blue/gray
    INFO     = neutral

---

# 2. GLOBAL APP SHELL

Top bar:

    LIBRAX
    Security Operations Center

    [Live] [18 Hospitals] [10,482 Endpoints]

    Search
    Notifications
    Analyst profile

Left navigation:

    Overview
    Incidents
    Alerts
    Attack Graph
    Threat Hunting
    Assets
    Identities
    MITRE
    Data Sources
    Response
    System Health

Bottom-left:

    Engine status
    Event processing rate
    Data source health

---

# 3. OVERVIEW SCREEN

Purpose:
Give the SOC operator the state of the environment immediately.

Top KPI row:

    EVENTS / SEC
    ACTIVE INCIDENTS
    CRITICAL INCIDENTS
    ENDPOINTS
    DATA SOURCES
    COVERAGE

Example:

    184,320
    37
    4
    10,482
    42
    94.2%

Below KPIs:

LEFT:
Incident priority queue

    CRITICAL  INC-0042  97  Multi-Stage Healthcare Intrusion
    CRITICAL  INC-0039  91  Database Exfiltration
    HIGH      INC-0037  78  Lateral Movement
    HIGH      INC-0034  71  Credential Attack

RIGHT:
Attack activity

A horizontal ATT&CK stage flow:

    Initial Access -> Execution -> Credential ->
    Discovery -> Lateral Movement -> Collection -> Impact

Highlight stages with active incidents.

Bottom:

    Event volume chart
    Source health
    Top affected assets
    Top identities under investigation

---

# 4. INCIDENT LIST

Table columns:

    Risk
    Incident
    Status
    Confidence
    Impact
    Affected Assets
    MITRE Stages
    First Seen
    Last Seen
    Owner

Each row should be clickable.

Use compact density.

Allow filters:

    Severity
    Hospital
    User
    Asset
    MITRE tactic
    Time
    Status

---

# 5. INCIDENT DETAIL — MOST IMPORTANT SCREEN

This is the centerpiece.

Header:

    INC-0042
    MULTI-STAGE HEALTHCARE INTRUSION

    CRITICAL
    Risk 97
    Threat Confidence 94%
    Business Impact 99%

Actions:

    Assign
    Investigate
    Simulate Response
    Close

Under header show a 4-column summary:

    THREAT CONFIDENCE
    94%

    BUSINESS IMPACT
    99%

    BLAST RADIUS
    CRITICAL

    ATT&CK COVERAGE
    7 techniques

---

# 6. INCIDENT GRAPH

Occupy approximately 60% of the main investigation area.

Use a node graph.

Nodes:

    User
    Device
    IP
    Process
    Account
    Server
    Database
    File
    PACS
    Incident

Example visual structure:

                         MALICIOUS IP
                              |
                           CONNECTS
                              |
                           HR-PC-23
                           /       \
                       Alice     PowerShell
                                   |
                                CONNECTS
                                   |
                              APP-SRV-07
                                   |
                              PAM SESSION
                                   |
                              DB-SRV-02
                                   |
                              PATIENT DB
                                   |
                            DATA-STAGED.ZIP

Edges must have relationship labels.

Clicking a node opens its details.

Clicking an edge opens:

    Relationship
    Confidence
    First seen
    Last seen
    Evidence events

Example:

    Alice -> HR-PC-23

    Relation:
    USES

    Confidence:
    99%

    Evidence:
    AD-4624
    EDR-18373

---

# 7. EVIDENCE PANEL

This is a major LibraX differentiator.

When the analyst clicks "Why is this incident correlated?"

show:

    WHY LIBRAX CONNECTED THESE EVENTS

    ✓ Same user
    ✓ Same endpoint
    ✓ Same network path
    ✓ 18-minute time window
    ✓ ATT&CK progression
    ✓ Privileged account involved
    ✓ Critical database involved

Then:

    EVIDENCE

    AD Event 4624
    EDR Event 8812
    Firewall Event FW-11992
    PAM Event PAM-284
    DB Event DB-9921

Every evidence item should be clickable.

---

# 8. RISK EXPLANATION

Do NOT only display:

    97 / 100

Instead show a breakdown:

    OVERALL RISK
    97 / 100

    Threat confidence      +22
    Critical asset         +20
    Attack progression     +18
    Privileged identity    +15
    Cross-source evidence  +12
    Threat intelligence    +10
    Maintenance context    -05

Use a horizontal contribution chart.

Below:

    WHAT IS STILL UNKNOWN?

    ? Confirmed data exfiltration
    ? Full scope of compromised accounts
    ? Confirmed ransomware execution

The system should distinguish known facts from uncertainty.

---

# 9. BLAST RADIUS PANEL

Display:

    Affected users          3
    Endpoints               7
    Servers                 4
    Critical databases      2
    PACS systems            1
    Potentially reachable   9

Add a small relationship diagram:

    Compromised endpoint
            |
       application
            |
       database
        /      \
      DB       PACS

Clearly distinguish:

    CONFIRMED
    REACHABLE
    POTENTIAL

---

# 10. ATT&CK PANEL

Show an attack-chain ribbon:

    Initial Access
          ↓
    Execution
          ↓
    Credential Access
          ↓
    Discovery
          ↓
    Lateral Movement
          ↓
    Collection
          ↓
    Impact

Each stage displays its technique IDs.

Example:

    Execution
    T1059.001
    PowerShell

Clicking a technique opens:

    Technique name
    Evidence
    Detection rule
    Related events
    Confidence

---

# 11. TIMELINE

Below the graph:

    09:01  Spear-phishing detected
    09:04  VPN authentication anomaly
    09:05  PowerShell execution
    09:08  Suspicious outbound connection
    09:12  Internal discovery
    09:17  Credential anomaly
    09:20  Lateral movement
    09:24  PAM privileged session
    09:27  Database access
    09:30  Data staging
    09:32  Ransomware indicators

Use distinct icons per source.

The analyst should be able to filter:

    All
    Identity
    Endpoint
    Network
    Server
    Database

---

# 12. RESPONSE PANEL

Use explicit human approval.

Example:

    RECOMMENDED RESPONSE

    [Simulate Isolate HR-PC-23]
    [Simulate Disable alice.hr]
    [Simulate Revoke VPN Session]
    [Simulate Block malicious IP]
    [Create Investigation Task]

Before execution:

    Risk: 97
    Action confidence: 92%
    Requires analyst approval: YES

After click:

    ACTION SIMULATED
    HR-PC-23 isolation request created.

Never silently execute destructive actions in demo mode.

---

# 13. DATA SOURCE HEALTH

Screen:

    CONNECTOR HEALTH

    AD/Entra          HEALTHY     4,210 evt/min
    EDR               HEALTHY    32,210 evt/min
    Firewall          HEALTHY   120,431 evt/min
    VPN               HEALTHY     8,213 evt/min
    PAM               WARNING        41 evt/min
    PACS              HEALTHY     1,221 evt/min

Show:

    last event
    current rate
    expected rate
    coverage
    error count

If a source is silent:

    BLIND SPOT DETECTED

This is important for a realistic SOC.

---

# 14. THREAT HUNTING

Provide a simple investigation query bar:

    Search user, IP, host, hash, domain, process

Examples:

    "show activity for alice.hr"

    "show all connections from 10.10.2.15"

    "show PowerShell events on HR-PC-23"

Results should show the event timeline and relationships.

Do not build a complicated SIEM query language for the MVP.

---

# 15. SYSTEM HEALTH

Display:

    Event ingestion
    Detection latency
    Correlation latency
    Queue depth
    API health
    Database health
    Source coverage

Example:

    Ingestion latency       84 ms
    Detection latency       42 ms
    Correlation latency     77 ms
    Queue depth              1,482
    Source coverage          94.2%

---

# 16. EMPTY / LOADING / ERROR STATES

Every screen needs clear states.

Loading:

    "Building incident graph..."

No incidents:

    "No active incidents. Monitoring 10,482 endpoints."

Source unavailable:

    "PAM connector has not reported telemetry for 9 minutes."

Never leave blank screens.

---

# 17. RESPONSIVE BEHAVIOR

Primary target:

    1440x900 desktop

Secondary:

    1920x1080

Do not optimize primarily for mobile.

The graph and incident investigation must remain usable on laptop screens.

---

# 18. Component Architecture

Create reusable React components:

    AppShell
    Sidebar
    TopBar
    KPIBar
    IncidentQueue
    IncidentHeader
    RiskScore
    EvidencePanel
    AttackGraph
    Timeline
    MitreChain
    BlastRadius
    ResponsePanel
    SourceHealth
    SeverityBadge
    EntityBadge
    TechniqueBadge

Use one source of truth for incident state.

---

# 19. UX RULES

1. The analyst must never need to open 5 different pages to understand one incident.
2. Evidence is always one click away.
3. Risk score is explainable.
4. Unknowns are explicitly shown.
5. Critical assets are visually distinguishable.
6. The attack graph is the primary investigation visualization.
7. Don't overwhelm users with raw logs unless requested.
8. Use progressive disclosure: summary first, evidence second, raw event last.
9. Keep destructive response actions behind explicit confirmation.
10. Never fabricate evidence in the UI.

---

# 20. Demo Scenario UI

The default landing state should contain a seeded incident:

    INC-0042
    Multi-Stage Healthcare Intrusion

    Risk: 97
    Confidence: 94%
    Impact: 99%
    Blast Radius: CRITICAL

Then the analyst can:

    Open Incident
        ->
    See Graph
        ->
    Click Alice
        ->
    See AD evidence
        ->
    Click PowerShell
        ->
    See EDR evidence
        ->
    Follow path to DB
        ->
    See ATT&CK chain
        ->
    Inspect Risk
        ->
    Inspect Blast Radius
        ->
    Simulate Response

This sequence must work smoothly for the 3–5 minute hackathon demo.
