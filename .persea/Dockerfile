FROM rust:1.75.0-slim-bookworm

ENV RUSTUP_TOOLCHAIN=nightly-2023-04-17

RUN rm -rf /var/lib/apt/lists/* && \
    apt-get -o Acquire::Retries=3 -o Acquire::http::No-Cache=true update && \
    apt-get -o Acquire::Retries=3 install -y --no-install-recommends \
        build-essential \
        pkg-config \
        libpq-dev \
        libssl-dev && \
    rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install nightly-2023-04-17 && \
    rustup default nightly-2023-04-17

WORKDIR /workspace
