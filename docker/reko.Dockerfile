# Reko decompiler image for decbench.
#
# Build (from repo root or docker/):
#   docker build -f docker/reko.Dockerfile -t decbench/reko:latest docker/
#   # or simply:  decbench decompiler-build reko
#
# Run (decbench does this for you):
#   docker run --rm \
#     -v /path/to/bin:/in/bin:ro -v /tmp/out:/work \
#     decbench/reko:latest /in/bin /work/out.c /work/native-provenance.json
#
# The image ships /opt/reko/decompile.sh which runs Reko's headless CLI on the
# binary, consolidates Reko's generated *.c, and emits native variable provenance.
#
# Reko is built from source with the .NET SDK. This is a multi-minute build; the
# resulting CLI lives at /opt/reko/decompile (the published "CmdLine" tool).

# ---- build stage: compile Reko with the .NET SDK ---------------------------
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        git \
        libcapstone-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

ARG REKO_REF=1910021f15b4b40e6f5018f8c55a49fac78b8ebb
RUN git init /src/reko \
    && git -C /src/reko remote add origin https://github.com/uxmal/reko \
    && git -C /src/reko fetch --depth=1 origin "${REKO_REF}" \
    && git -C /src/reko checkout --detach FETCH_HEAD

COPY reko-native-provenance.cs /src/reko/src/Decompiler/NativeVariableProvenance.cs
COPY reko-native-provenance.patch /tmp/reko-native-provenance.patch
RUN git -C /src/reko apply /tmp/reko-native-provenance.patch

WORKDIR /src/reko/src
# Reko's managed projects invoke c2xml during their builds without declaring it
# as a project dependency, so make that generator available first.
RUN dotnet build tools/c2xml/c2xml.csproj \
        -c Release -p:SolutionDir=/src/reko/src/ \
    && dotnet publish Drivers/CmdLine/CmdLine.csproj \
        -c Release -r linux-x64 --self-contained false \
        -p:SolutionDir=/src/reko/src/ \
        -o /opt/reko \
    && git -C /src/reko rev-parse HEAD > /opt/reko/reko.rev \
    && ls /opt/reko
RUN cp -a Drivers/CmdLine/bin/Release/net8.0/linux-x64/. /opt/reko/

# ---- runtime stage ---------------------------------------------------------
FROM mcr.microsoft.com/dotnet/runtime:8.0

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libcapstone4 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /opt/reko /opt/reko

# Reko's CmdLine entry point is resolved by the wrapper across supported
# upstream layouts.
COPY reko-decompile.sh /opt/reko/decompile.sh
RUN chmod +x /opt/reko/decompile.sh

WORKDIR /work

# Args: <input binary> <output .c path> [native provenance JSON path]
ENTRYPOINT ["/opt/reko/decompile.sh"]
