FROM ubuntu:24.04

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    wget \
    curl \
    unzip \
    python3.12 \
    python3.12-dev \
    python3.12-venv \
    python3-pip \
    python3-full \
    gcc \
    g++ \
    autoconf \
    automake \
    libtool \
    gettext \
    autopoint \
    rsync \
    bison \
    texinfo \
    gperf \
    help2man \
    graphviz \
    graphviz-dev \
    libgraphviz-dev \
    pkg-config \
    meson \
    ninja-build \
    default-jdk \
    && rm -rf /var/lib/apt/lists/*

# Install Ghidra 12
ENV GHIDRA_VERSION=12.0
ENV GHIDRA_INSTALL_DIR=/opt/ghidra_12
RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.0_build/ghidra_12.0_PUBLIC_20251205.zip && \
    unzip ghidra_12.0_PUBLIC_20251205.zip -d /opt && \
    mv /opt/ghidra_12.0_PUBLIC ${GHIDRA_INSTALL_DIR} && \
    rm ghidra_12.0_PUBLIC_20251205.zip

# Install radare2 from source + the r2dec plugin so the `r2dec` backend works
# natively in this image. We build from source (not the apt package) because the
# r2dec plugin must compile against radare2's dev headers (/usr/include/libr),
# which the host's packaged radare2 lacks. With the plugin present, the
# R2DecDecompiler uses the real r2dec commands (pd:d / pdd) instead of falling
# back to radare2's built-in `pdc`.
ARG R2_REF=master
RUN git clone --depth=1 --branch "${R2_REF}" https://github.com/radareorg/radare2 /opt/radare2 \
    && /opt/radare2/sys/install.sh \
    && r2pm -U \
    && r2pm -ci r2dec \
    && r2 -v

# Cross toolchains + build tooling for the CPS / drone / RTOS targets
# (projects/cps/*.toml), which are compiled for real embedded hardware:
#   * arm-none-eabi-gcc  -> bare-metal Cortex-M firmware (RTOS kernels, flight
#                           controllers, autopilots: FreeRTOS/ChibiOS/NuttX,
#                           Betaflight/Crazyflie/ArduPilot/PX4, libopencm3, RIOT)
#   * arm-linux-gnueabihf -> embedded-Linux ARM (e.g. Das U-Boot)
# Plus cmake/flex/dtc/etc. and the Python helpers ArduPilot(waf)/PX4(cmake) need.
# gcc-mingw-w64 cross-compiles the Windows-C malware targets (projects/malware/)
# to PE; unzip extracts theZoo's password-protected source zips. Malware is
# COMPILED, NEVER EXECUTED, and only inside this container (see projects/malware
# /README.md and the is_malware guard in compile_project).
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc-arm-none-eabi binutils-arm-none-eabi libnewlib-arm-none-eabi \
    libstdc++-arm-none-eabi-newlib \
    gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf \
    cmake flex file device-tree-compiler libtool-bin \
    libssl-dev uuid-dev libgnutls28-dev python-is-python3 \
    gcc-mingw-w64 unzip \
    && rm -rf /var/lib/apt/lists/* \
    && python3.12 -m pip install --break-system-packages \
       pyserial future "empy==3.3.4" jsonschema kconfiglib pymavlink \
       pexpect toml numpy pyros-genmsg packaging jinja2 pyyaml lxml cerberus \
       lief pefile \
    && arm-none-eabi-gcc --version | head -1 \
    && arm-linux-gnueabihf-gcc --version | head -1

# Allow running ./configure as root (needed in Docker)
ENV FORCE_UNSAFE_CONFIGURE=1

# Set up working directory
WORKDIR /workspace

# Copy project files into the image
COPY . /workspace/

# Install Python dependencies in a way that persists
# We'll install packages to system Python to avoid venv issues with mounted volumes
RUN python3.12 -m pip install --break-system-packages \
    angr \
    cfgutils \
    pyjoern \
    pyghidra \
    networkx \
    pyelftools \
    rich \
    toml \
    pydantic \
    r2pipe \
    && python3.12 -m pip install --break-system-packages -e .

# Pre-install Joern binaries so they don't need to be downloaded at runtime
RUN python3.12 -m pyjoern --install

# Default command
CMD ["/bin/bash"]

# ---------------------------------------------------------------------------
# Decompiler backends: angr, Ghidra (12.0 above), and **r2dec** (radare2 + the
# r2dec plugin, installed above) all work natively in THIS image. IDA/Binary
# Ninja need their own licensed installs. The heavier RetDec and Reko
# toolchains live in their own images under docker/ (retdec.Dockerfile,
# reko.Dockerfile) — build with `decbench decompiler-build <retdec|reko>`
# (see docker/README.md). docker/r2dec.Dockerfile is kept as a standalone
# fallback but is redundant now that r2dec is built in here.
# ---------------------------------------------------------------------------
