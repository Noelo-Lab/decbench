"""Compiler support for DecBench."""

from decbench.compilers.base import Compiler, CompileResult
from decbench.compilers.gcc import GCCCompiler

__all__ = ["Compiler", "CompileResult", "GCCCompiler"]
