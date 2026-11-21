# Raw Fission decompiler image for DecBench.
#
# Build with `decbench decompiler-build fission`. The backend resolves
# FISSION_REF to an immutable commit before invoking Docker, preventing a
# cached clone layer from silently retaining an older branch tip.

FROM debian:bookworm-slim AS build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        git \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

ARG RUST_VERSION=1.95.0
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/opt/fission/bin:${PATH}

RUN curl -fsSL https://sh.rustup.rs \
        | sh -s -- -y --no-modify-path --profile minimal --default-toolchain "${RUST_VERSION}" \
    && rustc --version

ARG FISSION_REPO=https://github.com/fission-systems/Fission.git
ARG FISSION_REF=5073a1c63dcf15b57f4506671aa16ac1cc0c47b7
RUN git clone "${FISSION_REPO}" /src/fission \
    && cd /src/fission \
    && git checkout --detach "${FISSION_REF}" \
    && git rev-parse --short HEAD > /src/fission.rev

WORKDIR /src/fission
RUN cargo build --locked --release -p fission-cli --bin fission_cli \
    && mkdir -p /opt/fission/bin /opt/fission/share/fission \
    && cp target/release/fission_cli /opt/fission/bin/fission_cli \
    && cp -R utils/sleigh-specs utils/signatures utils/ghidra-data /opt/fission/share/fission/ \
    && chmod -R a+rX /opt/fission \
    && /opt/fission/bin/fission_cli --version

FROM debian:bookworm-slim

ENV PATH=/opt/fission/bin:${PATH} \
    FISSION_RESOURCE_ROOT=/opt/fission/share/fission

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libgcc-s1 \
        libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 fission

COPY --from=build /opt/fission /opt/fission
COPY --from=build /src/fission.rev /opt/fission.rev

RUN fission_cli --version

USER fission
WORKDIR /work
ENTRYPOINT ["fission_cli"]
