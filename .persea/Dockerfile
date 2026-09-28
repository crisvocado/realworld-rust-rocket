FROM rust:1.75-bookworm

ENV RUSTUP_TOOLCHAIN=nightly-2023-06-01

RUN rm -rf /var/lib/apt/lists/* \
    && apt-get -o Acquire::Retries=3 -o Acquire::http::No-Cache=true update \
    && apt-get -o Acquire::Retries=3 install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        libssl-dev \
        pkg-config \
        postgresql-client \
    && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install nightly-2023-06-01 \
    && rustup default nightly-2023-06-01

WORKDIR /workspace
