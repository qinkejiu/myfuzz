"""One bounded native/PULP session across cases; explicit begin and full replay.

This source entry has no RFuzz/closed-loop certificate grant. Decoded bytes are
admitted source inputs, not proof of instruction fetch, retirement or terminal
consumption. The actual Runner journal remains the observation source.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from myfuzz.scenario.picorv32_native_online import (
    ROOT, SCHEDULE, PACKET_COUNT, PACKET_BYTES, GPIO_COMPONENT,
    make_picorv32_native_online_bootstrap,
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
    boundary_failure: dict | None = field(default=None, init=False)

    def _require_packet_boundary(self, expected_address, *, phase):
        cpu = self.session.runner.sessions['cpu']
        gpio = self.session.runner.sessions[GPIO_COMPONENT]
        observed = dict(phase=phase, expected_address=expected_address,
            actual_offered_instruction_address=cpu.waiting_instruction_address,
            cpu_pending_responses=cpu.pending_responses,
            router_pending_targets=cpu.router.pending_targets,
            target_pending_responses=gpio.pending_responses,
            target_pending_events=gpio.pending_events,
            local_ticks=dict(self.session.runner.local_ticks))
        if (observed['actual_offered_instruction_address'] != expected_address
                or observed['cpu_pending_responses'] != 0
                or observed['router_pending_targets']
                or observed['target_pending_responses'] != 0
                or observed['target_pending_events'] != 0):
            self.boundary_failure = observed
            raise RuntimeError('native online packet boundary not reached: ' + repr(observed))

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
                    self._require_packet_boundary(self.decoder.instruction_cursor, phase='bootstrap')
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
        # Refuse before decode/admission: an IP input must never change pins
        # while the previous packet is still reading them. The marker names an
        # actual offered fetch, and single-outstanding service must be drained.
        self._require_packet_boundary(self.decoder.instruction_cursor, phase='before_input')
        # Pure decode refusal has no effects; the caller may supply another
        # candidate. Any exception once submit starts permanently stops this
        # runtime, preserving the original attempted plan and actual prefix.
        case = self.decoder.decode(raw, coverage_hints=coverage_hints)
        next_address = self.decoder.instruction_cursor + PACKET_BYTES
        try:
            receipt = self.session.submit_case(case)
            if receipt.status != 'running' or receipt.violations:
                raise RuntimeError('native online case failed before packet boundary')
            # No extra clocks or speculative completion: if128 operations did
            # not reach the next real unfilled fetch, retain the actual prefix
            # and fail permanently without committing the decoder cursor.
            self._require_packet_boundary(next_address, phase='after_case')
            self.decoder.commit(case)
            self._case_count += 1
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
                                       max_cases: int = PACKET_COUNT):
    """Construct only; begin explicitly starts/builds real hardware.

    No per-case pair.runner(), reset, memory replacement or direct GPIO ACCESS
    occurs here. Each case schedules128 CPU and128 GPIO operations; CPU
    operations each advance one tick. Queued GPIO accesses retain their actual
    multi-tick accounting. Native timeout1024 remains enforced by actual RTL.
    """
    if type(max_cases) is not int or not 1 <= max_cases <= PACKET_COUNT:
        raise ValueError(f'native online max_cases must be within1..{PACKET_COUNT}')
    bootstrap = make_picorv32_native_online_bootstrap()
    decoder = make_picorv32_native_online_decoder()
    factory = make_picorv32_native_online_factory(cache_dir=cache_dir, base_dir=base_dir)
    runner = factory()
    session = ScenarioSession(bootstrap.template, runner)
    for address in bootstrap.instruction_slots:
        session.declare_instruction_slots('cpu', address, 1)
    session.configure_runtime_paths(decoder.graph, decoder.runtime_contract,
        decoder.runtime_paths, source_ownership=decoder.ownership)
    return PicoNativeOnlineRuntime(session, decoder, factory, max_cases)
