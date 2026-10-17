"""One bounded native/PULP session across cases; explicit begin and full replay.

This source entry has no RFuzz/closed-loop certificate grant. Decoded bytes are
admitted source inputs, not proof of instruction fetch, retirement or terminal
consumption. The actual Runner journal remains the observation source.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from myfuzz.scenario.picorv32_native_online import (
    ROOT, SCHEDULE, make_picorv32_native_online_bootstrap,
    make_picorv32_native_online_decoder, make_picorv32_native_online_factory)
from myfuzz.scenario.session_runtime import ScenarioSession, replay_online_session


@dataclass
class PicoNativeOnlineRuntime:
    session: ScenarioSession
    decoder: object
    factory: object
    max_cases: int
    _begun: bool = field(default=False, init=False)
    _terminal: bool = field(default=False, init=False)
    _case_count: int = field(default=0, init=False)

    def _fail(self, primary):
        self._terminal = True
        try:
            self.session.runner.finalize()
        except BaseException as cleanup:
            primary.add_note(f'native online cleanup failed: {cleanup!r}')

    def begin(self):
        if self._begun or self._terminal:
            raise RuntimeError('native online begins exactly once')
        self._begun = True
        try:
            self.session.begin()
            # Bounded actual CPU/GPIO steps only. Stop on the first actual
            # offered fetch to an unfilled slot; do not clock a guessed PC.
            for _ in range(512):
                if self.session.runner.sessions['cpu'].waiting_instruction_address is not None:
                    return
                receipt = self.session.advance_initial(SCHEDULE)
                if receipt.status != 'running' or receipt.violations:
                    raise RuntimeError('native online bootstrap failed')
            raise RuntimeError('native online bootstrap did not reach declared slots')
        except BaseException as primary:
            self._fail(primary)
            raise

    def submit(self, raw: bytes, *, coverage_hints=None):
        if not self._begun or self._terminal:
            raise RuntimeError('native online requires an active session')
        if self._case_count >= self.max_cases:
            raise ValueError('native online case bound exhausted before admission')
        # Pure decode refusal has no effects; the caller may supply another
        # candidate. Any exception once submit starts permanently stops this
        # runtime, preserving the original attempted plan and actual prefix.
        case = self.decoder.decode(raw, coverage_hints=coverage_hints)
        try:
            receipt = self.session.submit_case(case)
            self.decoder.commit(case)
            self._case_count += 1
            if receipt.status != 'running' or receipt.violations:
                self._terminal = True
                self.session.finish()
            return receipt
        except BaseException as primary:
            self._fail(primary)
            raise

    def finish(self):
        if not self._begun or self._terminal:
            raise RuntimeError('native online finish requires an active session')
        try:
            result = self.session.finish_export()
            self._terminal = True
            return result
        except BaseException as primary:
            self._fail(primary)
            raise

    def replay(self, plan, reference):
        if not self._terminal:
            raise RuntimeError('finish the original session before fresh replay')
        return replay_online_session(plan, self.factory, reference)


def make_picorv32_native_online_runtime(*, cache_dir: Path, base_dir: Path = ROOT,
                                       max_cases: int = 256):
    """Construct only; begin explicitly starts/builds real hardware.

    No per-case pair.runner(), reset, memory replacement or direct GPIO ACCESS
    occurs here. Each case schedules at most128 actual CPU ticks plus128 GPIO
    ticks. Native REQUEST/RESPONSE timeout1024 remains enforced by actual RTL.
    """
    if type(max_cases) is not int or not 1 <= max_cases <= 256:
        raise ValueError('native online max_cases must be within1..256')
    bootstrap = make_picorv32_native_online_bootstrap()
    decoder = make_picorv32_native_online_decoder()
    factory = make_picorv32_native_online_factory(cache_dir=cache_dir, base_dir=base_dir)
    runner = factory()
    session = ScenarioSession(bootstrap.template, runner)
    session.declare_instruction_slots('cpu', bootstrap.instruction_start,
                                      bootstrap.instruction_count)
    session.configure_runtime_paths(decoder.graph, decoder.runtime_contract,
        decoder.runtime_paths, source_ownership=decoder.ownership)
    return PicoNativeOnlineRuntime(session, decoder, factory, max_cases)
