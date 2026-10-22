"""Guarded fixed native packets; no source, bus-completion or feedback grant.

The session owns packet position and actual pre/post boundary checks. It never
commits a decoder. The executor notifies this guarded session when a post-submit decoder commit
fails. Explicit source binding records successful selected host input only;
guarded fresh reconstruction retains its saved policy. This class grants no
instruction-bus source consumption, retirement or feedback capability.
"""
from __future__ import annotations
import json

from .batch import BatchSourceEvent
from .picorv32_native_online import (
    CPU_TICKS_PER_CASE, GPIO_COMPONENT, GPIO_INPUT, INSTRUCTION_END,
    INSTRUCTION_START, PACKET_BYTES, PACKET_COUNT, SCHEDULE,
    make_picorv32_native_online_bootstrap,
)
from .session_runtime import OnlineCase, OnlineInstruction, ScenarioSession


NATIVE_SOURCE_COMPLETION_MAX_RAW_SAMPLES = 4096
NATIVE_SOURCE_COMPLETION_MAX_WARMUP_SAMPLES = 512
NATIVE_SOURCE_COMPLETION_MAX_CASES = (
    (NATIVE_SOURCE_COMPLETION_MAX_RAW_SAMPLES
     - NATIVE_SOURCE_COMPLETION_MAX_WARMUP_SAMPLES) // CPU_TICKS_PER_CASE)


def native_packet_source_binding_configuration(max_cases):
    if type(max_cases) is not int or not 1 <= max_cases <= PACKET_COUNT:
        raise ValueError('native source binding max_cases must be within1..96')
    return dict(schema_version='native_packet_source_binding.v1', enabled=True,
        max_cases=max_cases, packet_policy='native_online_packet.v1',
        instruction_start=INSTRUCTION_START, instruction_end=INSTRUCTION_END,
        stride_bytes=PACKET_BYTES, source_binding_schema='native_instruction_source_binding.v1',
        native_completion_observation_required=True, proof_scope='host_instruction_input_bound',
        grants_source_consumption=False, grants_retirement=False)


def native_packet_source_completion_configuration(max_cases):
    if type(max_cases) is not int or not 1 <= max_cases <= NATIVE_SOURCE_COMPLETION_MAX_CASES:
        raise ValueError('native source completion max_cases exceeds frozen raw-sample bound')
    return dict(schema_version='native_packet_source_completion.v1', enabled=True,
        max_cases=max_cases, max_warmup_native_samples=NATIVE_SOURCE_COMPLETION_MAX_WARMUP_SAMPLES,
        max_native_raw_samples=NATIVE_SOURCE_COMPLETION_MAX_RAW_SAMPLES,
        native_samples_per_case=CPU_TICKS_PER_CASE,
        max_completion_objects=256,
        completion_schema_version='native_instruction_bus_completion.v1',
        proof_scope='native_instruction_bus_transfer_completed',
        native_completion_observation_required=True,
        native_source_binding_required=True, grants_source_authority=False)


def packet_boundary_snapshot(runner, expected_address, *, phase):
    """Read actual current offered fetch and pending state; advance nothing."""
    cpu = runner.sessions['cpu']
    gpio = runner.sessions[GPIO_COMPONENT]
    return dict(phase=phase, expected_address=expected_address,
        actual_offered_instruction_address=cpu.waiting_instruction_address,
        cpu_pending_responses=cpu.pending_responses,
        router_pending_targets=tuple(cpu.router.pending_targets),
        target_pending_responses=gpio.pending_responses,
        target_pending_events=gpio.pending_events,
        local_ticks=dict(runner.local_ticks),
        runner_failure_status=runner.failure_status,
        uncertain_transactions=tuple(runner._uncertain_transactions()))


class NativePacketSession(ScenarioSession):
    """Exactly one admitted word and an immutable tail per32-byte packet.

    Case execution uses the inherited actual submit exactly once. Successful
    duplicate case IDs keep the base receipt replay semantics without taking
    another packet or clock. A failed packet can never revive via that cache.
    """

    def __init__(self, template, runner, *, max_cases=PACKET_COUNT,
                 native_completion_observation=False, native_source_binding=False,
                 native_source_completion=False, **kwargs):
        if type(native_completion_observation) is not bool:
            raise ValueError('native_completion_observation must be boolean')
        if type(native_source_binding) is not bool:
            raise ValueError('native_source_binding must be boolean')
        if type(native_source_completion) is not bool:
            raise ValueError('native_source_completion must be boolean')
        if native_source_binding and not native_completion_observation:
            raise ValueError('native source binding requires native completion observation')
        if native_source_completion and not (native_completion_observation and native_source_binding):
            raise ValueError('native source completion requires native completion observation and native source binding')
        if type(max_cases) is not int or not 1 <= max_cases <= PACKET_COUNT:
            raise ValueError('native packet max_cases must be within1..96')
        completion_configuration = (native_packet_source_completion_configuration(max_cases)
                                    if native_source_completion else None)
        if template != make_picorv32_native_online_bootstrap().template:
            raise ValueError('native packet session requires the fixed packet template')
        super().__init__(template, runner, **kwargs)
        self._packet_max_cases = max_cases
        if native_source_binding:
            self._native_source_binding_configuration_json = json.dumps(
                native_packet_source_binding_configuration(max_cases), sort_keys=True,
                separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')
        self._native_source_completion_configuration_json = (
            json.dumps(completion_configuration, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=False, allow_nan=False).encode('utf-8')
            if completion_configuration is not None else None)
        self._packet_cursor = INSTRUCTION_START
        self._packet_accepted_count = 0
        self._packet_terminal = False
        self._packet_cleanup_attempted = False
        self.boundary_failure = None
        self.packet_failure = None
        for address in (*range(INSTRUCTION_START, INSTRUCTION_END, PACKET_BYTES),
                        INSTRUCTION_END):
            super().declare_instruction_slots('cpu', address, 1)

    def _native_source_completion_configuration(self):
        raw = self._native_source_completion_configuration_json
        recorded = (self._manifest_document or {}).get('native_source_completion')
        if raw is None:
            if recorded is not None:
                raise ValueError('native source completion configuration was removed')
            return None
        if type(self) is not NativePacketSession:
            raise ValueError('native source completion requires the code-owned packet session')
        configuration = native_packet_source_completion_configuration(self._packet_max_cases)
        if raw != json.dumps(configuration, sort_keys=True, separators=(',', ':'),
                              ensure_ascii=False, allow_nan=False).encode('utf-8') or (
                self._manifest_document is not None and
                json.dumps(recorded, sort_keys=True, separators=(',', ':'),
                           ensure_ascii=False, allow_nan=False).encode('utf-8') != raw):
            raise ValueError('native source completion configuration drift')
        return configuration

    def _revoke_native_source_completion(self, primary=None):
        if self._native_source_completion_configuration_json is None:
            return
        cpu = self.runner.sessions.get('cpu')
        if cpu is None:
            return
        if getattr(cpu, '_native_source_completion_session', None) is not self:
            return
        try:
            observer = getattr(cpu, '_native_bus_observer', None)
            if observer is not None:
                revoke = getattr(observer, 'revoke_source_completion', None)
                if callable(revoke):
                    revoke()
            cpu._native_source_completion_session = None
        except BaseException as cleanup:
            if primary is None:
                raise
            try:
                primary.add_note('native source completion revocation: ' + repr(cleanup))
            except BaseException:
                pass

    @property
    def packet_cursor(self):
        return self._packet_cursor

    @property
    def accepted_packet_count(self):
        return self._packet_accepted_count

    def declare_instruction_slots(self, component, address, count=1):
        raise ValueError('native packet reservations are code-owned before begin')

    def reset(self, policy):
        raise ValueError('native packet session does not permit inter-case reset')

    def begin(self):
        if self._native_source_binding_configuration() is not None:
            from .native_instruction_source_binding import preflight_source_binding
            preflight_source_binding(self)
        if self._native_source_completion_configuration() is not None:
            cpu = self.runner.sessions.get('cpu')
            observer = getattr(cpu, '_native_bus_observer', None)
            from .native_cpu_events import NativeBusObserver
            if (type(observer) is not NativeBusObserver or observer.session is not cpu
                    or observer.failed or getattr(cpu, '_native_source_completion_session', None) is not None):
                raise ValueError('native source completion requires a fresh owned observer')
            cpu._native_source_completion_session = self
        try:
            return super().begin()
        except BaseException as primary:
            self._revoke_native_source_completion(primary)
            raise

    def require_packet_boundary(self, expected_address, *, phase):
        observed = packet_boundary_snapshot(self.runner, expected_address, phase=phase)
        if (observed['actual_offered_instruction_address'] != expected_address
                or observed['cpu_pending_responses'] != 0
                or observed['router_pending_targets']
                or observed['target_pending_responses'] != 0
                or observed['target_pending_events'] != 0
                or observed['runner_failure_status'] is not None
                or observed['uncertain_transactions']):
            if self.boundary_failure is None:
                self.boundary_failure = observed
            raise RuntimeError('native online packet boundary not reached: ' + repr(observed))
        return observed

    def abort_packet_submission(self, primary):
        """Failure-only notification; never acknowledges decoder success."""
        self._packet_terminal = True
        self._revoke_native_source_bindings(primary)
        self._revoke_native_source_completion(primary)
        self._halted = True
        self._halt_reason = self._halt_reason or 'uncertain_effect'
        if self.packet_failure is None:
            failure = dict(expected_address=self._packet_cursor,
                accepted_packet_count=self._packet_accepted_count,
                error_type=type(primary).__name__)
            for name, read in (
                    ('error_message', lambda: str(primary)[:2048]),
                    ('event_count', lambda: self.runner.event_count),
                    ('local_ticks', lambda: dict(self.runner.local_ticks)),
                    ('before_cleanup', lambda: packet_boundary_snapshot(
                        self.runner, self._packet_cursor, phase='abort_before_cleanup'))):
                try:
                    failure[name] = read()
                except BaseException as collection:
                    failure[name + '_collection_error'] = type(collection).__name__
            self.packet_failure = failure
        if not self._packet_cleanup_attempted:
            self._packet_cleanup_attempted = True
            try:
                self.runner.finalize()
            except BaseException as cleanup:
                try:
                    primary.add_note('native packet cleanup failed: ' + repr(cleanup))
                except BaseException:
                    pass

    def _validate_packet_case(self, case):
        if not isinstance(case, OnlineCase):
            raise ValueError('OnlineCase is required')
        if (len(case.advances) != CPU_TICKS_PER_CASE
                or any(advance.schedule != SCHEDULE for advance in case.advances)):
            raise ValueError('native packet case requires the fixed128-round schedule')
        if isinstance(case.source, OnlineInstruction):
            if (case.support_instructions or case.source.component != 'cpu'
                    or len(case.source.data_hex) != 8):
                raise ValueError('native CPU packet requires one source word only')
            fragment = case.source
            word = int.from_bytes(fragment.data, 'little')
            if (word & 0xfffff) != 0x513 or not 0 <= word >> 20 <= 255:
                raise ValueError('native CPU source must be ADDI x10,x0,u8')
        elif isinstance(case.source, BatchSourceEvent):
            source = case.source
            if ((source.component, source.port, source.bit_offset, source.width)
                    != (GPIO_COMPONENT, GPIO_INPUT, 0, 8)
                    or type(source.value) is not int or not 0 <= source.value <= 255
                    or len(case.support_instructions) != 1):
                raise ValueError('native IP packet requires one pin byte and one support word')
            fragment = case.support_instructions[0]
            if not isinstance(fragment, OnlineInstruction) or fragment.data_hex != '13000000':
                raise ValueError('native IP support must be one fixed NOP')
        else:
            raise ValueError('unsupported native packet source')
        if (fragment.component != 'cpu' or fragment.address != self._packet_cursor
                or len(fragment.data) != 4):
            raise ValueError('native packet needs exactly one four-byte word at current slot')

    def submit_case(self, case, *, source_role='fuzz_source'):
        if self._packet_terminal:
            raise RuntimeError('native packet submission is terminal')
        if not isinstance(case, OnlineCase):
            raise ValueError('OnlineCase is required')
        if case.case_id in self._receipts:
            return super().submit_case(case, source_role=source_role)
        if (not self._begun or self._finished or self._halted
                or self.runner._status != 'running'):
            raise RuntimeError('native packet requires an active session')
        if self._packet_accepted_count >= self._packet_max_cases:
            raise ValueError('native packet count exhausted before admission')
        # Pure malformed candidates do not alter the session or consume a slot.
        self._validate_packet_case(case)
        next_address = self._packet_cursor + PACKET_BYTES
        try:
            self.require_packet_boundary(self._packet_cursor, phase='before_input')
            receipt = super().submit_case(case, source_role=source_role)
            if receipt.status != 'running' or receipt.violations:
                raise RuntimeError('native online case failed before packet boundary')
            self.require_packet_boundary(next_address, phase='after_case')
            self._packet_cursor = next_address
            self._packet_accepted_count += 1
            return receipt
        except BaseException as primary:
            self.abort_packet_submission(primary)
            raise
