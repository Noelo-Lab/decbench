# Build (from repo root or docker/):
#   docker build -f docker/r2dec.Dockerfile -t decbench/r2dec:6.2.0 docker/
#   # or simply:  decbench decompiler-build r2dec

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        build-essential \
        meson \
        ninja-build \
        pkg-config \
        python3 \
        python3-pip \
    && rm -rf /var/lib/apt/lists/*

ARG R2_REF=6.2.0
ARG R2DEC_REF=6.2.0
RUN git clone --depth=1 --branch "${R2_REF}" https://github.com/radareorg/radare2 /opt/radare2 \
    && /opt/radare2/sys/install.sh

RUN pip3 install --no-cache-dir r2pipe

RUN git clone --depth=1 --branch "${R2DEC_REF}" https://github.com/wargio/r2dec-js /opt/r2dec-js \
    && cd /opt/r2dec-js \
    && meson setup -Dr2_plugdir="$(r2 -H R2_LIBR_PLUGINS)" b --backend=ninja \
    && ninja -C b \
    && ninja -C b install \
    && r2 -qc "pdd?" -- /bin/ls | grep -qi "decompile"

COPY r2dec-decompile.py /opt/r2dec-decompile.py

WORKDIR /work

ENTRYPOINT ["python3", "/opt/r2dec-decompile.py"]
