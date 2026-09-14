# LibraX — Easy Docker Setup

## Goal

Run the hackathon MVP locally with one command:

    docker compose up --build

The default setup is intentionally simple.

## Services

    frontend
    api
    simulator
    postgres
    redis

The event pipeline is kept in-process for the MVP. Do NOT require Kafka for local demo setup.

Optional enterprise mode can later add Kafka/Redpanda and a graph database.

## docker-compose.yml

```yaml
services:

  postgres:
    image: postgres:17
    environment:
      POSTGRES_DB: librax
      POSTGRES_USER: librax
      POSTGRES_PASSWORD: librax
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U librax -d librax"]
      interval: 5s
      timeout: 5s
      retries: 20

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  api:
    build:
      context: .
      dockerfile: services/librax-api/Dockerfile
    environment:
      DATABASE_URL: postgres://librax:librax@postgres:5432/librax
      REDIS_URL: redis://redis:6379
      RUST_LOG: info
    ports:
      - "8080:8080"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_started

  simulator:
    build:
      context: .
      dockerfile: services/librax-simulator/Dockerfile
    environment:
      API_URL: http://api:8080
      RUST_LOG: info
      SIMULATED_ENDPOINTS: 10482
      SIMULATED_HOSPITALS: 18
      EVENTS_PER_SECOND: 250
      ATTACK_SCENARIO: apt_ransomware
    depends_on:
      - api

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    environment:
      VITE_API_URL: http://localhost:8080
    ports:
      - "3000:3000"
    depends_on:
      - api

volumes:
  postgres_data:
```

## Local URLs

Frontend:
    http://localhost:3000

API:
    http://localhost:8080

API health:
    http://localhost:8080/api/v1/health

## Demo flow

On startup:

1. Postgres starts.
2. Redis starts.
3. API starts.
4. Simulator creates the synthetic enterprise.
5. Simulator generates normal noise.
6. Simulator injects the attack scenario.
7. API detects and correlates the signals.
8. Frontend displays the incident.

The demo must work without external accounts or API keys.

## Enterprise mode

The code should keep interfaces ready for:

    Kafka / Redpanda
    OpenSearch
    Neo4j
    Object storage
    Real connectors

But these should be optional and NOT required for the hackathon demo.
