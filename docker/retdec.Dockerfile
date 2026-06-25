# RetDec decompiler image for decbench.
#
# Build (from repo root or docker/):
#   docker build -f docker/retdec.Dockerfile -t decbench/retdec:latest docker/
#   # or simply:  decbench decompiler-build retdec
#
# Run (decbench does this for you):
#   docker run --rm \
#     -v /path/to/bin:/in/bin:ro -v /tmp/out:/work \
#     decbench/retdec:latest /in/bin -o /work/out.c
#
# RetDec writes <output>.c (here /work/out.c) which decbench reads back.
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

# Pinned RetDec release. The official GitHub release ships a self-contained
# Linux x86-64 build under /opt/retdec.
ARG RETDEC_VERSION=5.0
ARG RETDEC_URL=https://github.com/avast/retdec/releases/download/v5.0/retdec-v5.0-linux-64b.tar.xz

RUN wget -nv -O /tmp/retdec.tar.xz "${RETDEC_URL}" \
    && mkdir -p /opt \
    && tar -xJf /tmp/retdec.tar.xz -C /opt \
    && rm /tmp/retdec.tar.xz \
    # The tarball extracts to /opt/retdec already.
    && test -x /opt/retdec/bin/retdec-decompiler

ENV PATH="/opt/retdec/bin:${PATH}"

WORKDIR /work

# ENTRYPOINT is the decompiler itself; decbench passes:
#   /in/<binary> -o /work/out.c
ENTRYPOINT ["retdec-decompiler"]
