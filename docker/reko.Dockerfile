# Reko decompiler image for decbench.
#
# Build (from repo root or docker/):
#   docker build -f docker/reko.Dockerfile -t decbench/reko:latest docker/
#   # or simply:  decbench decompiler-build reko
#
# Run (decbench does this for you):
#   docker run --rm \
#     -v /path/to/bin:/in/bin:ro -v /tmp/out:/work \
#     decbench/reko:latest /in/bin /work/out.c
#
# The image ships /opt/reko/decompile.sh which runs Reko's headless CLI on the
# binary, then consolidates Reko's generated *.c into the requested output path.
#
# Reko is built from source with the .NET SDK. This is a multi-minute build; the
# resulting CLI lives at /opt/reko/decompile (the published "CmdLine" tool).

# ---- build stage: compile Reko with the .NET SDK ---------------------------
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

ARG REKO_REF=master
RUN git clone --depth=1 --branch "${REKO_REF}" https://github.com/uxmal/reko /src/reko

WORKDIR /src/reko/src
# Publish the command-line decompiler (CmdLine) self-contained for linux-x64.
# The project path is stable across recent Reko revisions.
RUN dotnet publish Drivers/CmdLine/CmdLine.csproj \
        -c Release -r linux-x64 --self-contained false \
        -o /opt/reko \
    && ls /opt/reko

# ---- runtime stage ---------------------------------------------------------
FROM mcr.microsoft.com/dotnet/runtime:8.0

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /opt/reko /opt/reko

# Reko's CmdLine entry point. The published binary is named "decompile" in
# recent Reko, but fall back to invoking via dotnet on the DLL if not.
COPY reko-decompile.sh /opt/reko/decompile.sh
RUN chmod +x /opt/reko/decompile.sh

WORKDIR /work

# Args: <input binary> <output .c path>
ENTRYPOINT ["/opt/reko/decompile.sh"]
