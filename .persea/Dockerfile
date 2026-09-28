FROM rust:1.75.0-slim-bookworm

WORKDIR /workspace

ENV RUSTUP_TOOLCHAIN=nightly-2023-04-17

RUN rm -rf /var/lib/apt/lists/* && \
    apt-get -o Acquire::Retries=3 -o Acquire::http::No-Cache=true update && \
    apt-get -o Acquire::Retries=3 -y --no-install-recommends install \
        build-essential \
        pkg-config \
        libpq-dev \
        libssl-dev \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install nightly-2023-04-17 && \
    rustup default nightly-2023-04-17
