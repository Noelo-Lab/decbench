# r2dec (radare2's r2dec decompiler, `pdd`) image for decbench.
#
# Selection order (R2DecDecompiler._select_path): native-with-plugin >
# THIS IMAGE > native `pdc`. On hosts whose packaged radare2 lacks the dev
# headers to build the r2dec plugin (no /usr/include/libr — e.g. the dev
# machine), this image IS the benchmark path: it builds radare2 from source so
# the real plugin compiles.
#
# Build (from repo root or docker/):
#   docker build -f docker/r2dec.Dockerfile -t decbench/r2dec:latest docker/
#   # or simply:  decbench decompiler-build r2dec
#
# Run (decbench's R2DecDecompiler._decompile_docker does this):
#   docker run --rm \
#     -v /path/to/bin:/in/bin:ro -v /tmp/out:/work \
#     decbench/r2dec:latest /in/bin /work/out.json [/work/targets.json]
# targets.json (optional) is a JSON list of ELF-file-space addresses to
# restrict to (matched Thumb-bit tolerant); out.json is a JSON list of
# {addr, baddr, name, code} entries — one per function, from radare2's own
# analysis, so it works on fully stripped binaries.

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
# compile against them (the host's packaged r2 lacks /usr/include/libr). Pin to
# a released tag (matches the host's r2 6.0.8) so the r2dec plugin builds against
# a stable API rather than a drifting master.
ARG R2_REF=6.0.8
RUN git clone --depth=1 --branch "${R2_REF}" https://github.com/radareorg/radare2 /opt/radare2 \
    && /opt/radare2/sys/install.sh

# r2pipe for the in-container driver.
RUN pip3 install --no-cache-dir r2pipe

# Install the r2dec plugin (provides the `pdd` command). We build it by hand
# rather than via `r2pm -ci r2dec`: that recipe runs `meson setup ... --wipe`,
# which errors on a not-yet-existent build dir with this meson ("Directory does
# not contain a valid build tree"). A plain `meson setup` + `ninja install`
# against the just-built radare2 dev headers works and drops libcore_pdd.so into
# the SYSTEM plugin dir, so `pdd` is available for any user/HOME the container
# runs as.
RUN git clone --depth=1 --recursive https://github.com/wargio/r2dec-js /opt/r2dec-js \
    && cd /opt/r2dec-js \
    && meson setup -Dr2_plugdir="$(r2 -H R2_LIBR_PLUGINS)" b --backend=ninja \
    && ninja -C b \
    && ninja -C b install \
    && r2 -qc "pdd?" -- /bin/ls | grep -qi "decompile"

# In-container driver: writes address-keyed per-function JSON to /work/out.json.
COPY r2dec-decompile.py /opt/r2dec-decompile.py

WORKDIR /work

# Args: <binary> [out.json] [targets.json]  (defaults: /work/out.json, no filter)
ENTRYPOINT ["python3", "/opt/r2dec-decompile.py"]
