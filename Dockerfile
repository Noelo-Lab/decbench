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
    default-jdk \
    && rm -rf /var/lib/apt/lists/*

# Install Ghidra 12
ENV GHIDRA_VERSION=12.0
ENV GHIDRA_INSTALL_DIR=/opt/ghidra_12
RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.0_build/ghidra_12.0_PUBLIC_20251205.zip && \
    unzip ghidra_12.0_PUBLIC_20251205.zip -d /opt && \
    mv /opt/ghidra_12.0_PUBLIC ${GHIDRA_INSTALL_DIR} && \
    rm ghidra_12.0_PUBLIC_20251205.zip

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
    && python3.12 -m pip install --break-system-packages -e .

# Pre-install Joern binaries so they don't need to be downloaded at runtime
RUN python3.12 -m pyjoern --install

# Default command
CMD ["/bin/bash"]
