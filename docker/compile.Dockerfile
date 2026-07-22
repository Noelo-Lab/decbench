# Slim COMPILE-ONLY image for the cps (ARM) + malware (ARM/PE) targets.
#
# Decompilation runs on the host; this image only needs the cross/mingw
# toolchains + build deps + decbench's light compile-path deps (NOT angr/ghidra/
# pyjoern/radare2). The repo is MOUNTED at runtime (-v $PWD:/workspace) and
# decbench is imported via PYTHONPATH, so no `pip install -e .` (which would drag
# in the heavy decompiler stack).
#
# Build (from the repo root, so .dockerignore applies):
#         docker build -f docker/compile.Dockerfile -t decbench-compile .
# Use:    docker run --rm -v "$PWD":/workspace -w /workspace -e PYTHONPATH=/workspace \
#           decbench-compile python3 scripts/compile_all.py results/full_run 8 <stems...>
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git wget curl unzip ca-certificates \
    python3 python3-pip python-is-python3 \
    autoconf automake libtool gettext autopoint rsync bison texinfo gperf \
    help2man pkg-config meson ninja-build cmake flex file device-tree-compiler \
    libtool-bin libssl-dev uuid-dev libgnutls28-dev \
    gcc g++ \
    gcc-arm-none-eabi binutils-arm-none-eabi libnewlib-arm-none-eabi \
    libstdc++-arm-none-eabi-newlib \
    gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf \
    gcc-mingw-w64 \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m pip install --break-system-packages --no-cache-dir \
       pydantic toml pyelftools lief rich numpy \
       capstone diff-match-patch \
       pyserial future "empy==3.3.4" jsonschema kconfiglib pymavlink pexpect \
       pyros-genmsg packaging jinja2 pyyaml lxml cerberus \
    && arm-none-eabi-gcc --version | head -1 \
    && i686-w64-mingw32-gcc --version | head -1

# Allow running ./configure as root (needed in Docker).
ENV FORCE_UNSAFE_CONFIGURE=1
WORKDIR /workspace
CMD ["/bin/bash"]
