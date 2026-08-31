"""Known decompilers DecBench cannot run itself.

Some published columns come from an *external submission*: the author scores the
exported sample-set eval kit on their own infrastructure and sends back one
``results.zip``, which ``decbench evalkit ingest`` turns into a column (see
:mod:`decbench.evalkit` and ``docs/decompilers.md`` Part III). There is no
backend to write — DecBench never touches the tool — but the id is still a real,
published decompiler, and until now the registry had no way to say so:
``decbench list-decompilers`` simply did not know the name existed.

Registering these ids here makes them *known but not runnable*. Each one is a
:class:`ExternalDecompiler` whose :meth:`is_available` is permanently ``False``
and whose :meth:`decompile_binary` raises with a pointer to the ingest path, so
every consumer that already gates on ``is_available()`` (the pipeline, the run
drivers, ``list_available``) skips it exactly as it would a tool that is not
installed. ``runnable = False`` is what separates the two cases for a human
reading ``decbench list-decompilers``.

Adding one is a single row in :data:`EXTERNAL_DECOMPILERS`. A tool that *does*
have an in-tree backend does not belong here even when its published numbers came
from a submission (``glaurung`` and ``manifold`` both have real backends).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from decbench.decompilers.base import Decompiler
from decbench.decompilers.registry import register_decompiler

if TYPE_CHECKING:
    from decbench.models.decompilation import DecompilationResult

__all__ = ["EXTERNAL_DECOMPILERS", "ExternalDecompiler", "ExternalSpec"]


@dataclass(frozen=True)
class ExternalSpec:
    """One externally-submitted decompiler: its id, name, homepage and version.

    ``version`` is the string the submitter shipped in their ``results.json``, and
    is what ``decbench evalkit ingest --version`` recorded for the column.
    """

    id: str
    display_name: str
    url: str
    version: str | None = None


class ExternalDecompiler(Decompiler):
    """A decompiler DecBench knows about but can never invoke."""

    runnable = False
    url: str = ""

    def is_available(self) -> bool:
        """Always ``False`` — there is nothing on this host to run."""
        return False

    def get_version(self) -> str | None:
        """The version the submission declared, not a realized one."""
        return self.version

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
        function_names: set[int] | None = None,
        progress_path: Path | None = None,
    ) -> DecompilationResult:
        """Always raises: this column can only arrive through the eval kit."""
        raise RuntimeError(
            f"{self.display_name} cannot be run by DecBench — its results are an "
            f"external submission. Export a kit with `decbench evalkit export`, and "
            f"ingest the returned results.zip with "
            f"`decbench evalkit ingest <zip> <tree> --id {self.name}`."
        )


EXTERNAL_DECOMPILERS: tuple[ExternalSpec, ...] = (
    ExternalSpec(
        id="fission",
        display_name="Fission",
        url="https://github.com/fission-systems/Fission",
        version="0.2.3",
    ),
    ExternalSpec(
        id="ventris",
        display_name="Ventris",
        url="https://reveng.ai/",
        version="decompiler_v8_postpp_brace_fix",
    ),
)


def _register(spec: ExternalSpec) -> type[ExternalDecompiler]:
    """Build and register one :class:`ExternalDecompiler` subclass from ``spec``."""
    cls = type(
        f"{spec.id.replace('-', '_').title()}External",
        (ExternalDecompiler,),
        {
            "name": spec.id,
            "display_name": spec.display_name,
            "url": spec.url,
            "version": spec.version,
            "__doc__": f"{spec.display_name} — external sample-set submission ({spec.url}).",
        },
    )
    register_decompiler(spec.id)(cls)
    return cls


for _spec in EXTERNAL_DECOMPILERS:
    _register(_spec)
