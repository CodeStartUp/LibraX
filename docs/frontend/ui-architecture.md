# Frontend Architecture & SOC Interface (`frontend/`)

The LibraX user interface is a high-density, real-time Security Operations Center (SOC) single-page application built with **React 18**, **TypeScript 5.7**, and **Vite 6**.

---

## UI Component Hierarchy

```
frontend/src/
├── App.tsx                    # Shell, Topbar, Routing & Live Telemetry Ticker
├── api.ts                     # Strongly-typed HTTP API Client
├── types.ts                   # TypeScript interfaces matching Rust models
├── hooks.ts                   # useAsync, useInterval & Polling logic
├── index.css                  # Enterprise SOC Design System
└── components/
    ├── Overview.tsx           # Dashboard, Alert Reduction Funnel & Incident Queue
    ├── IncidentDetail.tsx     # Incident Deep-Dive, Briefings, Graph & Containment
    ├── AttackGraph.tsx        # Interactive SVG Directed Graph HUD
    ├── AttackLauncher.tsx     # Threat Scenario Execution Range & Progress
    ├── EventSearch.tsx        # Raw Telemetry Filter & Log Inspector
    ├── Intel.tsx              # IOC Search, File Reputation & Feed Explorer
    ├── Sources.tsx            # Ingest Pipeline Health & Sensor Coverage
    ├── common.tsx             # Panel, SeverityTag, VerdictBadge, Loading, Empty
    └── icons.tsx              # Bespoke SVG Cyber & Entity Icons
```

---

## Key Views & Features

### 1. Alert Reduction Funnel (`Overview.tsx`)
Visualizes the SOC signal reduction metric:
$$\text{Raw Events} \xrightarrow{\text{Detection}} \text{Security Signals} \xrightarrow{\text{Correlation}} \text{Actionable Incidents}$$
Achieves an average **$98.5\%$ noise reduction**, surfacing high-confidence incident packages to human analysts.

### 2. Interactive SVG Attack Graph (`AttackGraph.tsx`)
- Renders the `IncidentGraph` DAG dynamically.
- Color-codes nodes by entity type (User, Host, IP, File) and severity.
- Highlights adversary lateral movement paths and critical clinical assets in real time.

### 3. Transparent AI Briefing Panel (`IncidentDetail.tsx`)
- Renders assertion tags (`[FACT]`, `[INFERENCE]`, `[UNKNOWN]`).
- Includes interactive citation links that allow analysts to click any statement and instantly inspect the raw supporting log in the telemetry drawer.

### 4. Containment Playbook Controls (`IncidentDetail.tsx`)
- Provides one-click simulation for host isolation, credential revocation, and IP blocking.
- Enforces Tier-2 human analyst identity entry for high-impact actions.
