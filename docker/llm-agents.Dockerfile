# LLM coding-agent CLI image (Claude Code and Kimi Code container mode).
#
# This image bundles two CLIs plus the *only* binary-inspection tools the
# agents are allowed to use (objdump/readelf/nm/strings/xxd/file). It carries NO
# credentials: the decbench backend (decompilers/llm_dec.py, container mode) runs
# it with the HOST's token dirs bind-mounted read-only. Codex requires host
# API-key mode and is not included here.
#
# Build:
#   docker build -f docker/llm-agents.Dockerfile -t decbench/llm-agents:latest docker/
#
# The decbench backend invokes it for you when configured (per-version config or
# env), e.g.:
#   DECBENCH_LLM_DOCKER_IMAGE=decbench/llm-agents:latest \
#     DECBENCH_DECOMPILERS=claude-code DECBENCH_SAMPLESET_MANIFEST=.../sample_set_manifest.json \
#     python scripts/run_benchmark.py results/full_run
#
# The backend adds, per agent call:
#   docker run --rm -v <workdir>:/work -w /work \
#     -v ~/.claude:/root/.claude:ro \
#     -v ~/.kimi-code:/root/.kimi-code:ro \
#     -e ANTHROPIC_API_KEY \
#     -e KIMI_CODE_HOME=/root/.kimi-code -e HOME=/root \
#     decbench/llm-agents:latest <claude -p ... | kimi -p ...>
#
# To run it by hand for a smoke test:
#   docker run --rm decbench/llm-agents:latest claude --version

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

# The three coding-agent CLIs.
RUN npm install -g @anthropic-ai/claude-code @moonshot-ai/kimi-code \
    && npm cache clean --force

# Credentials never live in the image.
ENV HOME=/root \
    KIMI_CODE_HOME=/root/.kimi-code

WORKDIR /work
