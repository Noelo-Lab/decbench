# r2dec (radare2 pseudo-decompiler) image for decbench.
#
# This image is a FALLBACK only. radare2 is installed on the host, so the
# R2DecDecompiler prefers a native r2pipe run; it uses this image only when
# native radare2/r2pipe (and the r2dec plugin) are unavailable.
#
# Build (from repo root or docker/):
#   docker build -f docker/r2dec.Dockerfile -t decbench/r2dec:latest docker/
#   # or simply:  decbench decompiler-build r2dec
#
# Run (decbench's DockerizedDecompiler base does this):
#   docker run --rm \
#     -v /path/to/bin:/in/bin:ro -v /tmp/out:/work \
#     decbench/r2dec:latest /in/bin
# The container prints whole-program pseudo-C to stdout... but decbench's base
# reads /work/out.c, so the helper writes there. The container CMD writes the
# decompiled C to /work/out.c (whole program, function by function).

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

# Build radare2 from source so the dev headers exist and the r2dec plugin can
# compile against them (the host's packaged r2 lacks /usr/include/libr).
ARG R2_REF=master
RUN git clone --depth=1 --branch "${R2_REF}" https://github.com/radareorg/radare2 /opt/radare2 \
    && /opt/radare2/sys/install.sh

# r2pipe for the in-container driver.
RUN pip3 install --no-cache-dir --break-system-packages r2pipe

# Install the r2dec plugin via r2pm (needs the dev headers built above).
RUN r2pm -U \
    && r2pm -ci r2dec

# In-container driver: decompiles every function to /work/out.c.
COPY r2dec-decompile.py /opt/r2dec-decompile.py

WORKDIR /work

# Args: <input binary>  (writes whole-program pseudo-C to /work/out.c)
ENTRYPOINT ["python3", "/opt/r2dec-decompile.py"]
