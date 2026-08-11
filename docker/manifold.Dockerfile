# Manifold decompiler image for decbench.
#
# Build:
#   decbench decompiler-build manifold
#
# Prefer that over a bare `docker build`. Docker keys the `git clone` layer on
# the command string, which does not change when the branch moves -- so
#
#   docker build -f docker/manifold.Dockerfile -t decbench/manifold:latest docker/
#
# re-run after manifold gains commits reuses the cached clone and silently
# rebuilds the SAME revision, in about a second. `decompiler-build` resolves
# MANIFOLD_REF to a SHA and passes it as the build arg, so the clone layer is
# invalidated exactly when upstream moved and stays cached when it did not. By
# hand, pass the SHA yourself (`--build-arg MANIFOLD_REF=<sha>`) or --no-cache.
#
# Run (decbench's ManifoldDecompiler._run_docker does this):
#   docker run --rm \
#     -v /path/to/bin:/in/bin:ro -v /tmp/out:/work \
#     decbench/manifold:latest /in/bin /work/out.c
#
# Manifold is whole-binary: one invocation raises the entire program and writes
# it as a single C translation unit, which decbench then splits per function.
# There is no per-function entry point, so there is no targets file (unlike
# r2dec) and `binary_timeout_seconds` is the budget that matters.
#
# Selection order (ManifoldDecompiler._select_path): a NATIVE manifold from
# MANIFOLD_BIN / decompilers.toml / $PATH first, then this image. Native wins so
# a developer can benchmark a working tree without rebuilding; on a host that
# only has Docker, this image is the entire install. MANIFOLD_THREADS reaches
# the container as RAYON_NUM_THREADS, so a parallel driver can stop N containers
# from each grabbing every core.
#
# An image is built from ONE manifold revision, so `manifold@<version>`
# per-version settings apply to the native path only -- a second revision means a
# second image tag, which MANIFOLD_IMAGE selects.
#
# Manifold is a Rust crate built from source. Three build inputs are not obvious:
#
#   * Submodule -- manifold vendors an Ascent fork (ascent-plusplus), so the
#     submodules must be initialized or the crate will not resolve its path deps.
#   * Z3 -- the `z3` crate locates libz3 through pkg-config, and Ubuntu's
#     packaged 4.8 is too old for the bindings in z3-sys 0.11, so a pinned
#     upstream Z3 release is unpacked to /opt/z3 with a hand-written z3.pc.
#     libz3 is linked dynamically, so the runtime stage carries it too; that is
#     the same z3 the published v1 numbers were produced against. Bump
#     Z3_VERSION and Z3_DIST together -- the latter names the glibc the release
#     was built for, which has to match the base image.
#   * Linker -- manifold's own .cargo/config.toml is machine-local and
#     git-ignored, so it is absent from a fresh clone. mold is installed and
#     selected here instead, because linking a ~200 MB binary with bfd is slow.
#
# Rebuilding picks up manifold's latest; pass MANIFOLD_REF to build one specific
# revision instead. Either way, retag if you want to keep the old image around.

# ---- build stage: compile manifold with the Rust toolchain -----------------
FROM ubuntu:24.04 AS build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        unzip \
        build-essential \
        pkg-config \
        clang \
        libclang-dev \
        mold \
    && rm -rf /var/lib/apt/lists/*

# Pinned upstream Z3. The release zip ships bin/libz3.so + include/ but no
# pkg-config file, and z3-sys only emits its link flags when pkg-config finds
# z3, so write the .pc by hand. The glibc-2.39 asset matches ubuntu:24.04.
ARG Z3_VERSION=4.15.4
ARG Z3_DIST=z3-4.15.4-x64-glibc-2.39
RUN curl -fsSL -o /tmp/z3.zip \
        "https://github.com/Z3Prover/z3/releases/download/z3-${Z3_VERSION}/${Z3_DIST}.zip" \
    && unzip -q /tmp/z3.zip -d /tmp \
    && mkdir -p /opt/z3/lib/pkgconfig \
    && mv "/tmp/${Z3_DIST}/include" /opt/z3/include \
    && mv "/tmp/${Z3_DIST}/bin/libz3.so" /opt/z3/lib/libz3.so \
    && rm -rf /tmp/z3.zip "/tmp/${Z3_DIST}" \
    && printf '%s\n' \
        'prefix=/opt/z3' \
        'libdir=${prefix}/lib' \
        'includedir=${prefix}/include' \
        '' \
        'Name: z3' \
        'Description: Z3 SMT solver' \
        "Version: ${Z3_VERSION}" \
        'Libs: -L${libdir} -lz3' \
        'Cflags: -I${includedir}' \
        > /opt/z3/lib/pkgconfig/z3.pc \
    && PKG_CONFIG_PATH=/opt/z3/lib/pkgconfig pkg-config --modversion z3

ENV PKG_CONFIG_PATH=/opt/z3/lib/pkgconfig
ENV LD_LIBRARY_PATH=/opt/z3/lib

# Pinned Rust toolchain. z3-sys 0.11 is edition 2024, so 1.85 is the floor.
ARG RUST_VERSION=1.95.0
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:${PATH}
RUN curl -fsSL https://sh.rustup.rs \
        | sh -s -- -y --no-modify-path --profile minimal --default-toolchain "${RUST_VERSION}" \
    && rustc --version

# Link with mold. manifold's own linker config is git-ignored and so is not in
# the clone; put the equivalent in CARGO_HOME, which a repo config would win
# over if the situation ever changes.
RUN printf '%s\n' \
        '[target.x86_64-unknown-linux-gnu]' \
        'rustflags = ["-C", "link-arg=-fuse-ld=mold"]' \
        > "${CARGO_HOME}/config.toml"

ARG MANIFOLD_REPO=https://github.com/changliu98/manifold
# The branch tip, so a rebuild picks up manifold's latest. Pass a SHA or tag as
# MANIFOLD_REF to freeze a run against one revision; either way the image
# records what it built at /opt/manifold.rev and get_version() reports it, so a
# result always names the exact revision it was scored under.
ARG MANIFOLD_REF=master
# A full clone, not --depth=1, so MANIFOLD_REF can be any revision and not just
# the branch tip. Submodules are initialized by the paths .gitmodules actually
# maps: manifold's tree also carries a gitlink with no .gitmodules entry, and a
# bare `submodule update --init --recursive` aborts on it ("No url found for
# submodule path"), which would make the image build depend on that hygiene.
RUN git clone "${MANIFOLD_REPO}" /src/manifold \
    && cd /src/manifold \
    && git checkout --detach "${MANIFOLD_REF}" \
    && git config -f .gitmodules --get-regexp '^submodule\..*\.path$' \
        | awk '{print $2}' \
        | xargs -r git submodule update --init --recursive -- \
    && test -f ascent-plusplus/ascent/Cargo.toml \
    && git rev-parse --short HEAD > /src/manifold.rev

# Manifold's own [profile.release] is tuned for BUILD speed, not run speed:
# opt-level 0, lto "none", 256 codegen units. That is the right default for a
# working tree you rebuild all day. An image is the opposite case -- built once,
# then run over an entire corpus -- so trade build time for decompile time.
#
# These go through cargo's environment interface rather than a patch, so the
# manifold checkout stays exactly as published and a `manifold` built here is
# the same program, only compiled harder.
#
# Deliberately NOT set: `-C target-cpu=native`. It would bake this builder's ISA
# into the image and SIGILL on any older host that pulls it.
ARG CARGO_PROFILE_RELEASE_OPT_LEVEL=3
ARG CARGO_PROFILE_RELEASE_LTO=thin
ARG CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16
ENV CARGO_PROFILE_RELEASE_OPT_LEVEL=${CARGO_PROFILE_RELEASE_OPT_LEVEL} \
    CARGO_PROFILE_RELEASE_LTO=${CARGO_PROFILE_RELEASE_LTO} \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=${CARGO_PROFILE_RELEASE_CODEGEN_UNITS}

WORKDIR /src/manifold
RUN cargo build --release \
    && strip --strip-unneeded target/release/manifold \
    && cp target/release/manifold /usr/local/bin/manifold

# ---- runtime stage --------------------------------------------------------
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# libz3.so needs only libstdc++/libgcc/libm/libc; name libstdc++ explicitly
# rather than lean on it happening to be in the base image.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /opt/z3/lib/libz3.so /usr/local/lib/libz3.so
COPY --from=build /usr/local/bin/manifold /usr/local/bin/manifold
# The revision the image was built from; ManifoldDecompiler.get_version() reads
# it back, so a dockerized run reports the same `git-<rev>` a native one does.
COPY --from=build /src/manifold.rev /opt/manifold.rev
# manifold with no arguments prints its usage to stderr and exits 1, so this
# asserts the dynamic loader resolved libz3 (a loader error prints instead).
RUN ldconfig && manifold 2>&1 | grep -q "Usage: manifold"

WORKDIR /work

# Args: <input binary> <output .c path>
ENTRYPOINT ["manifold"]
