"""Assemble one reset-free CV32E40P and dual PULP GPIO RFuzz session.

The whole online assembly, warm-up contract, saved-bundle authentication and
replay order are the shared dual-source ones: this module only selects the
CV32E40P firmware bootstrap, its decoder and its factory.  No RTL is started
until ``begin``, and the unavailable Ibex-only observation probes are refused
by the factory rather than silently downgraded.

The default checker is the shared witness checker: its rules are keyed by
component name and by the fixed bootstrap/ISR addresses, both of which are
shared verbatim with the Ibex wiring.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from myfuzz.scenario.replay import ReplayComparison
from myfuzz.scenario.session_runtime import OnlineCaseReceipt

from .ibex_pulp_online import (IbexPulpOnlineRuntime,
                               make_pulp_dual_source_online_runtime,
                               replay_pulp_dual_source_online_files)
from myfuzz.scenario.cv32e40p_pulp_dual_source import (
    _validate_cv32e40p_retirement_flags, make_cv32e40p_pulp_dual_source_factory,
    make_cv32e40p_pulp_dual_source_online_decoder,
    make_cv32e40p_pulp_dual_source_stream_bootstrap)


def make_cv32e40p_pulp_online_runtime(
        *, cache_dir: Path, run_id: str, evidence_dir: Path | None = None,
        checker: Callable[[OnlineCaseReceipt], tuple[str, ...]] | None = None,
        feedback_interval: int = 16,
        max_warmup_rounds: int = 1024,
        cpu_retirement: bool = False,
        gpio_consumption: bool = False,
        native_irq_receipts: bool = False) -> IbexPulpOnlineRuntime:
    """Start one real CV32E40P/PULP session; caller feeds RFuzz slots.

    ``cpu_retirement`` and ``native_irq_receipts`` are refused before any
    harness is rendered, because this CPU has no authenticated retirement
    profile and native parsed receipts are an Ibex RVFI observation.
    """
    _validate_cv32e40p_retirement_flags(
        cpu_retirement=cpu_retirement, native_irq_receipts=native_irq_receipts)
    if type(max_warmup_rounds) is not int or max_warmup_rounds < 1:
        raise ValueError("max_warmup_rounds must be positive")
    bootstrap = make_cv32e40p_pulp_dual_source_stream_bootstrap()
    decoder = make_cv32e40p_pulp_dual_source_online_decoder(bootstrap=bootstrap)
    factory = make_cv32e40p_pulp_dual_source_factory(
        Path(cache_dir), cpu_retirement=cpu_retirement,
        gpio_consumption=gpio_consumption, native_irq_receipts=native_irq_receipts)
    return make_pulp_dual_source_online_runtime(
        bootstrap=bootstrap, decoder=decoder, factory=factory, run_id=run_id,
        evidence_dir=evidence_dir, checker=checker,
        feedback_interval=feedback_interval, max_warmup_rounds=max_warmup_rounds)


def replay_cv32e40p_pulp_online_files(*, cache_dir: Path, plan_path: Path,
                                      trace_path: Path) -> ReplayComparison:
    """Replay saved evidence with fresh CV32E40P and GPIO RTL processes.

    A saved bundle whose authenticated identity selects retirement or native
    receipts cannot have been produced by this CPU; the CV32E40P factory
    refuses it instead of replaying with weaker observations.
    """
    return replay_pulp_dual_source_online_files(
        cache_dir=cache_dir, plan_path=plan_path, trace_path=trace_path,
        factory_builder=make_cv32e40p_pulp_dual_source_factory)


__all__ = ["make_cv32e40p_pulp_online_runtime",
           "replay_cv32e40p_pulp_online_files"]
