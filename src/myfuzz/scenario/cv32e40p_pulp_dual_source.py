"""CV32E40P + two PULP GPIO instances on the shared dual-source wiring.

This is the second CPU on the identical long-session testcase: it reuses the
ownership map, MMIO windows, bindings, IRQ pulse policy, boot/ISR firmware
body, online decoder semantics, checker and replay contract of
``ibex_pulp_dual_source`` unchanged.  The CPU is not selected by a name branch
anywhere; the profile and the two declared firmware facts come from
``CV32E40P_STREAM_CPU_PROGRAM``.

Declared differences, all of them visible in that one declaration:

* first fetch: the pinned CV32E40P starts at ``{boot_addr_i[31:2], 2'b0}`` =
  0x10000, so one JAL trampoline word reaches the shared main program at
  0x10080 (Ibex starts at 0x10080 directly);
* ``mtvec`` = 0x10101 selects the vectored entry so machine external cause 11
  enters the shared 0x1012c slot exactly as it does on Ibex, whose mtvec mode
  bits are unused.

Unavailable on this CPU and therefore refused rather than downgraded:

* retirement observation (``--cpu-retirement``): the repository has no
  authenticated RVFI profile or wrapper for CV32E40P, and the pinned core
  artifact exports no ``rvfi_*`` signal;
* native parsed IRQ receipts (``--native-irq-receipts``): they are defined by
  the Ibex RVFI observation contract and require retirement observation.

Every runtime claim still depends on real RTL observation: constructing a
factory renders pinned harnesses and creates sessions, it never starts one.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from .ibex_pulp_dual_source import (  # noqa: F401  (shared wiring, re-exported)
    CV32E40P_STREAM_CPU_PROGRAM, DualSourceCpuProgram, DualSourceStreamBootstrap,
    dual_source_ownership, make_ibex_pulp_dual_source_online_decoder,
    make_pulp_dual_source_factory, make_pulp_dual_source_stream_bootstrap)
from .runner import ScenarioRunner


CV32E40P_CPU_PROFILE = CV32E40P_STREAM_CPU_PROGRAM.profile_path


def _validate_cv32e40p_retirement_flags(*, cpu_retirement: bool,
                                        native_irq_receipts: bool) -> None:
    """Refuse the Ibex-only observation probes on this CPU, before any work.

    The native-receipt message is the same one the Ibex wiring raises, so a
    caller cannot tell the two wirings apart by the reason a missing RVFI
    opt-in fails.  Retirement itself is refused afterwards because it cannot be
    satisfied on CV32E40P in this repository at all.
    """
    if type(cpu_retirement) is not bool:
        raise ValueError('cpu_retirement must be boolean')
    if type(native_irq_receipts) is not bool or (native_irq_receipts and not cpu_retirement):
        raise ValueError('native IRQ receipts require explicit RVFI retirement')
    if cpu_retirement:
        raise ValueError(
            'CV32E40P has no authenticated RVFI retirement profile; '
            'retirement observation is Ibex-only in this repository')


def make_cv32e40p_pulp_dual_source_factory(
        cache_dir: Path, *, cpu_retirement: bool = False,
        gpio_consumption: bool = False,
        native_irq_receipts: bool = False) -> Callable[[], ScenarioRunner]:
    """Render the pinned CV32E40P/PULP harnesses once, then make sessions.

    ``cpu_retirement`` and ``native_irq_receipts`` are rejected explicitly (see
    the module docstring) instead of silently selecting a weaker observation.
    """
    _validate_cv32e40p_retirement_flags(
        cpu_retirement=cpu_retirement, native_irq_receipts=native_irq_receipts)
    return make_pulp_dual_source_factory(
        cache_dir, cpu_profile=CV32E40P_CPU_PROFILE,
        gpio_consumption=gpio_consumption, native_irq_receipts=native_irq_receipts)


def make_cv32e40p_pulp_dual_source_stream_bootstrap(
        *, instruction_start: int = 0x11000, instruction_end: int = 0x2fe00
        ) -> DualSourceStreamBootstrap:
    """The CV32E40P instance of the shared stream firmware."""
    return make_pulp_dual_source_stream_bootstrap(
        program=CV32E40P_STREAM_CPU_PROGRAM, instruction_start=instruction_start,
        instruction_end=instruction_end)


def make_cv32e40p_pulp_dual_source_online_decoder(
        *, bootstrap: DualSourceStreamBootstrap | None = None):
    """The shared online decoder; only the fixed firmware bootstrap differs."""
    if bootstrap is None:
        bootstrap = make_cv32e40p_pulp_dual_source_stream_bootstrap()
    return make_ibex_pulp_dual_source_online_decoder(bootstrap=bootstrap)


__all__ = [
    "CV32E40P_CPU_PROFILE", "CV32E40P_STREAM_CPU_PROGRAM", "DualSourceCpuProgram",
    "DualSourceStreamBootstrap", "dual_source_ownership",
    "make_cv32e40p_pulp_dual_source_factory",
    "make_cv32e40p_pulp_dual_source_online_decoder",
    "make_cv32e40p_pulp_dual_source_stream_bootstrap",
]
