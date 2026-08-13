# Raw Glaurung decompiler image for DecBench.
#
# Build with `decbench decompiler-build glaurung`. The backend resolves
# GLAURUNG_REF to an immutable commit before invoking Docker, preventing a
# cached clone layer from silently retaining an older branch tip.

FROM python:3.12-slim-bookworm AS build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        clang \
        curl \
        git \
        libclang-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

ARG RUST_VERSION=1.97.1
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/opt/glaurung/bin:${PATH} \
    UV_PROJECT_ENVIRONMENT=/opt/glaurung

RUN curl -fsSL https://sh.rustup.rs \
        | sh -s -- -y --no-modify-path --profile minimal --default-toolchain "${RUST_VERSION}" \
    && rustc --version

COPY --from=ghcr.io/astral-sh/uv:0.11.1 /uv /uvx /usr/local/bin/

ARG GLAURUNG_REPO=https://github.com/mjbommar/glaurung.git
ARG GLAURUNG_REF=fb4ee6ba5966e0e4a7fe001b523231fc5fcd43f4
RUN git clone "${GLAURUNG_REPO}" /src/glaurung \
    && cd /src/glaurung \
    && git checkout --detach "${GLAURUNG_REF}" \
    && git rev-parse --short HEAD > /src/glaurung.rev

WORKDIR /src/glaurung
RUN uv sync --locked --no-dev --no-editable \
    && glaurung --version

FROM python:3.12-slim-bookworm

ENV PATH=/opt/glaurung/bin:${PATH} \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libgcc-s1 \
        libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 glaurung

COPY --from=build /opt/glaurung /opt/glaurung
COPY --from=build /src/glaurung.rev /opt/glaurung.rev

RUN glaurung --version

USER glaurung
WORKDIR /work
ENTRYPOINT ["glaurung"]
