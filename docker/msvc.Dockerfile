# EXPERIMENTAL MSVC (cl.exe under Wine) compile image for Windows/PE targets.
#
# Uses msvc-wine (https://github.com/mstorsjo/msvc-wine): vsdownload.py fetches
# the MSVC Build Tools + Windows SDK from Microsoft's official servers (the
# same manifests the Visual Studio installer uses), install.sh lays out Unix
# wrapper scripts (cl/link/lib/nmake/rc/dumpbin/... in /opt/msvc/bin/<arch>)
# that run the real Windows tools under Wine. LICENSING: the download requires
# accepting the Visual Studio license (--accept-license below) and the
# installed toolchain is NOT redistributable — build this image locally, never
# push it to a registry.
#
# Like compile.Dockerfile this is a COMPILE-ONLY image: decompilation of the
# produced PEs runs on the host (ghidra/ida/binja/angr load PE natively).
# MSVC emits PDB/CodeView debug info, NOT DWARF — see docs/MSVC_SUPPORT.md for
# what that means for the metrics. llvm-pdbutil (llvm package) is included for
# PDB ground-truth inspection.
#
# Build (from the repo root; the MSVC download is several GB — expect 30-60 min):
#         docker build -f docker/msvc.Dockerfile -t decbench-msvc .
# Smoke:  docker run --rm -v "$PWD":/workspace -w /workspace \
#           --user "$(id -u):$(id -g)" decbench-msvc \
#           python3 scripts/msvc_compile_smoke.py /workspace/msvc_smoke_out
#         (running as the host user creates a fresh throwaway Wine prefix on
#         first use — ~10 s one-time; root already has one baked in. GOTCHA:
#         wine refuses a $HOME the uid does not own — e.g. `-e HOME=/tmp` —
#         and msvc-wine's fifo wrappers then HANG instead of failing; the smoke
#         script self-provisions a wine-safe HOME for that reason.)
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    wine wine64 winbind msitools ca-certificates \
    python3 git wget curl unzip file binutils llvm \
    && rm -rf /var/lib/apt/lists/*

# Initialize the (root) wine prefix; wait for wineserver to exit so the
# prefix isn't corrupted mid-write (upstream msvc-wine Dockerfile convention).
RUN $(command -v wine64 || command -v wine || false) wineboot --init && \
    while pgrep wineserver > /dev/null; do sleep 1; done

# Pin msvc-wine for reproducibility of the wrapper layout (the MSVC payload
# itself is whatever Microsoft's manifest currently serves; vsdownload prints
# the exact toolchain version at build time).
ARG MSVC_WINE_REF=514f8ea34842cd6d831804d0e9658d3a32870ae1
RUN git clone https://github.com/mstorsjo/msvc-wine.git /opt/msvc-wine && \
    git -C /opt/msvc-wine checkout --detach "$MSVC_WINE_REF"

# Download MSVC + Windows SDK (x86/x64 only — no arm target libs) and install
# the Unix wrappers. This is the multi-GB layer; on a transient download
# failure just re-run the build (earlier layers are cached).
RUN PYTHONUNBUFFERED=1 /opt/msvc-wine/vsdownload.py --accept-license \
        --architecture x86 x64 --dest /opt/msvc && \
    /opt/msvc-wine/install.sh /opt/msvc && \
    cp /opt/msvc-wine/msvcenv-native.sh /opt/msvc/

# msvc-wine conventions: BIN points at the target-arch wrapper dir; putting it
# on PATH makes cl/link/nmake/rc "just work" (each wrapper execs Wine itself).
ENV BIN=/opt/msvc/bin/x64
ENV PATH=/opt/msvc/bin/x64:$PATH
ENV WINEDEBUG=-all

WORKDIR /workspace
CMD ["/bin/bash"]
