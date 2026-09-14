# REST & WebSocket API Specification (`services/librax-api`)

The `librax-api` service provides HTTP REST endpoints and WebSocket channels for telemetry ingestion, dashboard metrics, incident lifecycle management, and response containment.

Base URL: `http://localhost:8080/api/v1`

---

## Endpoint Reference

### 1. Ingest Telemetry Batch
```http
POST /api/v1/events
Content-Type: application/json
```
**Request Body:**
```json
[
  {
    "source_type": "active_directory",
    "source_id": "dc-samba-01",
    "payload": "{\"type\":\"Authentication\",\"serviceDescription\":\"Kerberos\",\"clientAddress\":\"ipv4:172.30.0.66\"}"
  }
]
```
**Response:**
```json
{
  "accepted": 1,
  "rejected": 0,
  "unsupported": 0,
  "signals": 1,
  "incidents": 1
}
```

---

### 2. Get SOC Dashboard Overview
```http
GET /api/v1/dashboard
```
**Response:**
```json
{
  "hospitals": 18,
  "endpoints": 10482,
  "assets": 10612,
  "identities": 2639,
  "events_received": 1420,
  "events_retained": 1420,
  "events_per_minute": 24.5,
  "signals_total": 30,
  "signals_by_severity": { "critical": 8, "high": 19, "medium": 3, "low": 0, "info": 0 },
  "incidents_total": 3,
  "incidents_critical": 3,
  "incidents_live": 1,
  "top_incident": {
    "incident_id": "INC-0001",
    "title": "Multi-Stage Active Directory Intrusion",
    "overall_risk": 95.4,
    "severity": "critical",
    "live": true
  },
  "reduction": {
    "events": 1420,
    "signals": 30,
    "incidents": 3,
    "critical_incidents": 3,
    "events_per_incident": 473
  }
}
```

---

### 3. List Incidents
```http
GET /api/v1/incidents
```
**Query Parameters:**
- `severity` (optional): Filter by minimum severity (`critical`, `high`, `medium`, `low`).
- `live_only` (optional): Boolean filter for active incidents.

---

### 4. Get Incident Details
```http
GET /api/v1/incidents/{incident_id}
```
Returns the full incident record, including:
- Correlated signal list with MITRE technique codes.
- Mathematical risk score breakdown.
- Directed graph nodes and edges.
- Structured AI briefing with cited event IDs.
- Available containment playbooks.

---

### 5. Simulate Containment Action
```http
POST /api/v1/actions/{action_id}/simulate
Content-Type: application/json
```
**Request Body:**
```json
{
  "approver": "analyst@librax.security"
}
```
**Response:**
```json
{
  "action": {
    "action_id": "ACT-8841",
    "status": "simulated",
    "result": "[SIMULATED] Would isolate host ws-billing-01 across EDR sensor mesh."
  },
  "narrative": "Containment action verified and simulated.",
  "approved_by": "analyst@librax.security"
}
```

---

### 6. Indicator of Compromise (IOC) Lookup
```http
GET /api/v1/intel/lookup?q={query}
```
Queries MD5, SHA256, IPv4, or domain against internal and global threat feeds.
