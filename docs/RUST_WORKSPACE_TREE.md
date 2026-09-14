# LibraX Rust Workspace Tree

librax/
├── Cargo.toml
├── README.md
├── LICENSE
├── .env.example
├── docker-compose.yml
│
├── docs/
├── configs/
├── data/
│
├── crates/
│   ├── librax-types/
│   ├── librax-config/
│   ├── librax-observability/
│   ├── librax-connectors/
│   ├── librax-normalizer/
│   ├── librax-enrichment/
│   ├── librax-detection/
│   ├── librax-entities/
│   ├── librax-correlation/
│   ├── librax-graph/
│   ├── librax-mitre/
│   ├── librax-risk/
│   ├── librax-incidents/
│   ├── librax-response/
│   ├── librax-storage/
│   └── librax-ai/
│
├── services/
│   ├── librax-api/
│   ├── librax-ingest/
│   ├── librax-detection-worker/
│   ├── librax-correlation-worker/
│   ├── librax-incident-worker/
│   └── librax-simulator/
│
├── frontend/
├── simulator/
├── mitre/
├── tests/
└── scripts/
