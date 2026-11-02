"""Generic runtime framework: descriptive contracts, never live authority.

This package is the incremental outer layer described by
``docs/superpowers/specs/2026-10-26-generic-runtime-framework-design.md``.  It
reuses the existing source/native authorities, ``ScenarioRunner``/Router/Memory
and the compiled flow evidence consumers.  Importing a module here never starts
RTL, issues a native token or admits an execution.
"""
from __future__ import annotations

__all__ = ["contracts"]
