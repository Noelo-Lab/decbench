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
    && /opt/fission/bin/fission_cli --version

# Compile the SLEIGH frontends now, into the image, instead of in every run.
# A container starts with an empty cache, and the runtime cache lives on a
# 64 MiB tmpfs: x86-64 alone is ~27 MiB and a first ARM binary builds all
# eight ARM variants (~80 MiB), so a cold run both repeats seconds of work
# per binary and can overflow the tmpfs. One checked-in fixture per family
# (x86-64, x86, ARM, AArch64) builds every frontend those families use. The
# runtime only reads this directory; a language missing here is compiled in
# memory and the failed cache write is a warning, not an error.
ENV FISSION_SLEIGH_CACHE_DIR=/opt/fission/cache/fission-sleigh
RUN for fixture in \
        crates/fission-dir/testdata/ground_truth_fixture.elf \
        crates/fission-loader/testdata/x86_reloc_object.o \
        crates/fission-loader/testdata/arm_mixed_mode.elf \
        crates/fission-sleigh/testdata/a64_csel_select.so; do \
        /opt/fission/bin/fission_cli --resource-root /opt/fission/share/fission --no-db \
            decomp "$fixture" --all --limit 1 --json --no-header --no-warnings > /dev/null \
        || exit 1; \
    done \
    && ls /opt/fission/cache/fission-sleigh/cache \
    && chmod -R a+rX /opt/fission

FROM debian:bookworm-slim

ENV PATH=/opt/fission/bin:${PATH} \
    FISSION_RESOURCE_ROOT=/opt/fission/share/fission \
    FISSION_SLEIGH_CACHE_DIR=/opt/fission/cache/fission-sleigh

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
