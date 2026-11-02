"""Code-owned flow kernels for the generic runtime.

A flow kernel is the component-neutral half of one execution flow: it derives
the capability/evidence requirements of a D3 path, lowers directed case
records onto that path, translates real per-case receipts into four-state
evidence and turns actual checker/edge feedback into the next program inputs.
It never owns a session, a runner, a memory or a ledger and it never drives
RTL; the existing ``ScenarioRunner``/``ScenarioSession`` and the existing
compiled flow consumers keep that role.

Only :mod:`myfuzz.runtime.flows.storage` exists today (F2 read-response and
F4 write/readback).  Later flows are created when they are implemented, not as
placeholders.
"""
from __future__ import annotations

__all__ = ["storage"]
