"""One bounded native/PULP session across cases; explicit begin and full replay.

This source entry has no RFuzz/closed-loop certificate grant. The guarded
session protects direct submit calls and receives executor commit-failure
notification. Fresh reconstruction uses the same guard and explicit observed
process identity comparison; a new actual gate remains required.
Decoded bytes are admitted source inputs, not proof of instruction fetch, retirement or terminal
consumption. The actual Runner journal remains the observation source.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from myfuzz.scenario.picorv32_native_online import (
    ROOT, SCHEDULE, PACKET_COUNT,
    make_picorv32_native_online_bootstrap,
    make_picorv32_native_online_decoder, make_picorv32_native_online_factory)
from myfuzz.scenario.session_runtime import replay_online_session
from myfuzz.scenario.native_packet_session import NativePacketSession


@dataclass
class PicoNativeOnlineRuntime:
    session: NativePacketSession
    decoder: object
    factory: object
    max_cases: int
    _begun: bool = field(default=False, init=False)
    _terminal: bool = field(default=False, init=False)
    _case_count: int = field(default=0, init=False)

    @property
    def boundary_failure(self):
        return self.session.boundary_failure

    def _require_packet_boundary(self, expected_address, *, phase):
        return self.session.require_packet_boundary(expected_address, phase=phase)

    def _fail(self, primary):
        self._terminal = True
        self.session.abort_packet_submission(primary)

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
        try:
            self._require_packet_boundary(self.decoder.instruction_cursor, phase='before_input')
        except BaseException as primary:
            self._fail(primary)
            raise
        # Pure decode refusal has no effects; the caller may supply another
        # candidate. Any exception once submit starts permanently stops this
        # runtime, preserving the original attempted plan and actual prefix.
        case = self.decoder.decode(raw, coverage_hints=coverage_hints)
        try:
            receipt = self.session.submit_case(case)
            # NativePacketSession owns the actual pre/post guard and packet
            # cursor. The directed wrapper owns the decoder commit exactly once.
            self.decoder.commit(case)
            self._case_count = self.session.accepted_packet_count
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
        cpu = self.session.runner.sessions['cpu']
        observer = getattr(cpu, '_native_bus_observer', None)
        execution = None
        if observer is not None:
            from myfuzz.scenario.native_cpu_events import NativeBusObserver
            if (type(observer) is not NativeBusObserver or observer.session is not cpu
                    or observer.failed or observer.pending is not None
                    or cpu.reset_epoch != 0):
                raise ValueError('native reference observation is not complete')
            execution = cpu._execution
        return replay_online_session(plan, self.factory, reference,
            native_max_cases=self.max_cases, native_reference_execution=execution,
            native_source_binding=self.session._native_source_binding_configuration() is not None)


def make_picorv32_native_online_runtime(*, cache_dir: Path, base_dir: Path = ROOT,
                                       max_cases: int = PACKET_COUNT,
                                       native_completion_observation: bool = False,
                                       native_source_binding: bool = False):
    """Construct only; begin explicitly starts/builds real hardware.

    No per-case pair.runner(), reset, memory replacement or direct GPIO ACCESS
    occurs here. Each case schedules128 CPU and128 GPIO operations; CPU
    operations each advance one tick. Queued GPIO accesses retain their actual
    multi-tick accounting. Native timeout1024 remains enforced by actual RTL.
    Explicit native_completion_observation selects passive CPU PRE/POST taps;
    it grants no source-consumption or retirement authority.
    """
    if type(max_cases) is not int or not 1 <= max_cases <= PACKET_COUNT:
        raise ValueError(f'native online max_cases must be within1..{PACKET_COUNT}')
    if type(native_completion_observation) is not bool:
        raise ValueError('native_completion_observation must be boolean')
    if type(native_source_binding) is not bool:
        raise ValueError('native_source_binding must be boolean')
    if native_source_binding and not native_completion_observation:
        raise ValueError('native source binding requires native completion observation')
    bootstrap = make_picorv32_native_online_bootstrap()
    decoder = make_picorv32_native_online_decoder()
    factory = make_picorv32_native_online_factory(cache_dir=cache_dir, base_dir=base_dir,
        native_completion_observation=native_completion_observation)
    runner = factory()
    session = NativePacketSession(bootstrap.template, runner, max_cases=max_cases,
                                 native_source_binding=native_source_binding)
    session.configure_runtime_paths(decoder.graph, decoder.runtime_contract,
        decoder.runtime_paths, source_ownership=decoder.ownership)
    return PicoNativeOnlineRuntime(session, decoder, factory, max_cases)
