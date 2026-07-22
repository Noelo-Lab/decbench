# LLM coding-agent decompilers (Codex + Claude Code) in a container.
#
# This image bundles both CLIs plus the *only* binary-inspection tools the
# agents are allowed to use (objdump/readelf/nm/strings/xxd/file). It carries NO
# credentials: the decbench backend (decompilers/llm_dec.py, container mode) runs
# it with the HOST's token dirs bind-mounted read-only and the API-key env vars
# forwarded, so the CLI inside the container "inherits the token from outside".
#
# Build:
#   docker build -f docker/llm-agents.Dockerfile -t decbench/llm-agents:latest docker/
#
# The decbench backend invokes it for you when configured (per-version config or
# env), e.g.:
#   DECBENCH_LLM_DOCKER_IMAGE=decbench/llm-agents:latest \
#     DECBENCH_DECOMPILERS=codex DECBENCH_SAMPLESET_MANIFEST=.../sample_set_manifest.json \
#     python scripts/run_benchmark.py results/full_run
#
# The backend adds, per agent call:
#   docker run --rm -v <workdir>:/work -w /work \
#     -v ~/.codex:/root/.codex:ro -v ~/.claude:/root/.claude:ro \
#     -e ANTHROPIC_API_KEY -e OPENAI_API_KEY -e CODEX_HOME=/root/.codex -e HOME=/root \
#     decbench/llm-agents:latest <codex exec ... | claude -p ...>
#
# To run it by hand for a smoke test:
#   docker run --rm -v ~/.codex:/root/.codex:ro -e CODEX_HOME=/root/.codex \
#     decbench/llm-agents:latest codex --version

FROM node:22-bookworm-slim

# The agents' permitted toolbox: simple disassemblers/inspectors only. No
# decompiler is installed here — that is the whole premise of the LLM backend.
RUN apt-get update && apt-get install -y --no-install-recommends \
        binutils \
        file \
        xxd \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/*

# The two coding-agent CLIs.
RUN npm install -g @openai/codex @anthropic-ai/claude-code \
    && npm cache clean --force

# HOME defaults to /root; the backend mounts ~/.codex and ~/.claude there and
# points CODEX_HOME at the mounted dir. Credentials never live in the image.
ENV HOME=/root \
    CODEX_HOME=/root/.codex

WORKDIR /work
