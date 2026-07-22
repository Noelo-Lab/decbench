"""Decompiler plugins for DecBench."""

import contextlib

from decbench.decompilers.base import Decompiler, DecompilerConfig
from decbench.decompilers.registry import DecompilerRegistry, register_decompiler

# Import plugin modules so @register_decompiler decorators run.
# declib_dec registers the declib-backed backends under the ``*-declib``
# names (angr-declib, ghidra-declib, ida-declib, binja-declib) so they remain
# available for comparison. The ``raw`` subpackage registers the canonical
# angr/ghidra/ida/binja names with native (declib-free) implementations. Heavy
# decompiler imports happen lazily inside each plugin, so these imports are
# cheap and never fail on a missing backend.
with contextlib.suppress(ImportError):
    from decbench.decompilers import declib_dec  # noqa: F401

with contextlib.suppress(ImportError):
    from decbench.decompilers import raw  # noqa: F401

# Dockerized backends (Reko, RetDec, r2dec). r2dec can also run natively via
# radare2; the others require a built Docker image (see docker/).
with contextlib.suppress(ImportError):
    from decbench.decompilers import dockerized  # noqa: F401

# LLM / coding-agent backends (Codex, Claude Code). They shell out to the
# `codex` / `claude` CLIs; the imports are cheap (heavy work is at call time).
# Meant to run on the `sample-set` slice only — see docs/LLM_DECOMPILERS.md.
with contextlib.suppress(ImportError):
    from decbench.decompilers import llm_dec  # noqa: F401

__all__ = [
    "Decompiler",
    "DecompilerConfig",
    "DecompilerRegistry",
    "register_decompiler",
]
