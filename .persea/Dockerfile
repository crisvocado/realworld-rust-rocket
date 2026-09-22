FROM rust:1.75.0-slim-bookworm

WORKDIR /workspace

RUN rm -rf /var/lib/apt/lists/* && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        libssl-dev \
        libpq-dev \
        postgresql-client \
        ca-certificates \
        curl && \
    rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install nightly-2024-01-15 && \
    rustup default nightly-2024-01-15
