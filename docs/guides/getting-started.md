# Getting Started & Runbook

This guide covers setting up, building, running, and verifying the LibraX platform locally and via Docker.

---

## Prerequisites

- **Rust:** `1.85+` (with `cargo` and `rustc`)
- **Node.js:** `20+` or `22+` (with `npm`)
- **Python:** `3.10+` (for log shipper & MkDocs)
- **Docker & Docker Compose:** Latest Docker Desktop / Engine

---

## 1. Running the Live Attack Lab (Recommended)

To run the complete environment with a real Active Directory Domain Controller, offensive attack runner, log shipper, backend API, and frontend console:

```bash
docker compose -f lab/docker-compose.yml up --build
```

### Accessing Services:
- **Frontend SOC Console:** [http://localhost:3000](http://localhost:3000)
- **Backend REST API:** [http://localhost:8080/api/v1/dashboard](http://localhost:8080/api/v1/dashboard)
- **Documentation Site:** Run `python -m mkdocs serve` (see section 4)

---

## 2. Running Locally (Development Mode)

### Step 1: Start Backend API
```bash
cargo run --bin librax-api
```
The API server starts listening on `http://127.0.0.1:8080`.

### Step 2: Start Frontend Dev Server
```bash
cd frontend
npm install
npm run dev
```
The Vite dev server starts on `http://localhost:3000`.

---

## 3. Running the Test Suite

LibraX maintains an extensive integration and unit test suite across all crates:

```bash
# Run all workspace unit and integration tests
cargo test --workspace

# Test specific detection rules
cargo test -p librax-detection

# Test correlation engine and temporal links
cargo test -p librax-correlation

# Test response playbooks and simulation gates
cargo test -p librax-response
```

---

## 4. Serving Documentation via MkDocs

To serve this complete technical documentation website locally:

```bash
# Install mkdocs and material theme (if not already installed)
python -m pip install mkdocs mkdocs-material

# Start the MkDocs documentation server
python -m mkdocs serve
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser to browse the full interactive documentation.

To build static HTML documentation:
```bash
python -m mkdocs build
```
The static documentation is built to the `site/` directory.
