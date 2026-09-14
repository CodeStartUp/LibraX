# Shared build for both Rust services.
#
# The workspace is built once and the wanted binary selected with SERVICE, so
# `api` and `simulator` reuse the same cached dependency layer instead of
# compiling the tree twice.
FROM rust:1.90-slim-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Manifests first, so dependency compilation is cached until they change.
COPY Cargo.toml Cargo.lock ./
COPY crates/librax-ai/Cargo.toml crates/librax-ai/
COPY crates/librax-config/Cargo.toml crates/librax-config/
COPY crates/librax-connectors/Cargo.toml crates/librax-connectors/
COPY crates/librax-correlation/Cargo.toml crates/librax-correlation/
COPY crates/librax-detection/Cargo.toml crates/librax-detection/
COPY crates/librax-enrichment/Cargo.toml crates/librax-enrichment/
COPY crates/librax-entities/Cargo.toml crates/librax-entities/
COPY crates/librax-graph/Cargo.toml crates/librax-graph/
COPY crates/librax-incidents/Cargo.toml crates/librax-incidents/
COPY crates/librax-mitre/Cargo.toml crates/librax-mitre/
COPY crates/librax-normalizer/Cargo.toml crates/librax-normalizer/
COPY crates/librax-response/Cargo.toml crates/librax-response/
COPY crates/librax-risk/Cargo.toml crates/librax-risk/
COPY crates/librax-storage/Cargo.toml crates/librax-storage/
COPY crates/librax-types/Cargo.toml crates/librax-types/
COPY services/librax-api/Cargo.toml services/librax-api/
COPY services/librax-simulator/Cargo.toml services/librax-simulator/

# Placeholder sources, so dependencies compile into a cached layer before any
# real code is copied in. Crates are libraries; the two services are binaries.
RUN set -eux; \
    for dir in crates/*/; do mkdir -p "$dir/src" && : > "$dir/src/lib.rs"; done; \
    for dir in services/*/; do mkdir -p "$dir/src" && echo 'fn main() {}' > "$dir/src/main.rs"; done; \
    cargo build --release --workspace; \
    rm -rf crates/*/src services/*/src

COPY crates crates
COPY services services

# Touch every entry point so cargo rebuilds the real code rather than trusting
# the placeholder timestamps.
RUN find crates services -name '*.rs' -exec touch {} + \
    && cargo build --release --workspace \
    && strip target/release/librax-api target/release/librax-simulator

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --shell /usr/sbin/nologin librax

COPY --from=builder /build/target/release/librax-api /usr/local/bin/librax-api
COPY --from=builder /build/target/release/librax-simulator /usr/local/bin/librax-simulator

USER librax
WORKDIR /home/librax

# Overridden per service in compose.
ENV SERVICE=librax-api
EXPOSE 8080

CMD ["sh", "-c", "exec /usr/local/bin/${SERVICE}"]
