# RetDec decompiler image for decbench.
#
# Build (from repo root or docker/):
#   docker build -f docker/retdec.Dockerfile -t decbench/retdec:latest docker/
#   # or simply:  decbench decompiler-build retdec
#
# Run (decbench does this for you):
#   docker run --rm \
#     -v /path/to/bin:/in/bin:ro -v /tmp/out:/work \
#     decbench/retdec:latest /in/bin -f json -o /work/out.json --cleanup
#
# RetDec writes annotated tokens to /work/out.json and disassembly evidence to
# /work/out.dsm. DecBench reconstructs the exact C text and native provenance.
# A pre-built RetDec release tarball is used to keep the build fast and
# reproducible (building RetDec from source is very slow). Update RETDEC_VERSION
# / RETDEC_URL to bump.

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# RetDec runtime deps. RetDec releases bundle most libraries, but it needs a
# Python 3 and a handful of shared libs at runtime.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        wget \
        xz-utils \
        python3 \
        graphviz \
        upx-ucl \
        libc6 \
    && rm -rf /var/lib/apt/lists/*

# Pinned RetDec release. The official archive is self-contained; extract its
# root directly into /opt/retdec.
ARG RETDEC_VERSION=5.0
ARG RETDEC_URL=https://github.com/avast/retdec/releases/download/v5.0/RetDec-v5.0-Linux-Release.tar.xz

RUN wget -nv -O /tmp/retdec.tar.xz "${RETDEC_URL}" \
    && mkdir -p /opt/retdec \
    && tar -xJf /tmp/retdec.tar.xz -C /opt/retdec \
    && rm /tmp/retdec.tar.xz \
    && test -x /opt/retdec/bin/retdec-decompiler

ENV PATH="/opt/retdec/bin:${PATH}"

WORKDIR /work

# ENTRYPOINT is the decompiler itself; decbench passes:
#   /in/<binary> -f json -o /work/out.json --cleanup
ENTRYPOINT ["retdec-decompiler"]
