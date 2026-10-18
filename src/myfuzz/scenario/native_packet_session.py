"""Guarded fixed native packets; no source, bus-completion or feedback grant.

The session owns packet position and actual pre/post boundary checks. It never
commits a decoder. The executor notifies this guarded session when a post-submit decoder commit
fails. Guarded fresh reconstruction still requires separate integration; this
class alone grants neither safe RFuzz assembly nor a new native result.
"""
from __future__ import annotations

from .batch import BatchSourceEvent
from .picorv32_native_online import (
    CPU_TICKS_PER_CASE, GPIO_COMPONENT, GPIO_INPUT, INSTRUCTION_END,
    INSTRUCTION_START, PACKET_BYTES, PACKET_COUNT, SCHEDULE,
    make_picorv32_native_online_bootstrap,
)
from .session_runtime import OnlineCase, OnlineInstruction, ScenarioSession


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

    def __init__(self, template, runner, *, max_cases=PACKET_COUNT, **kwargs):
        if type(max_cases) is not int or not 1 <= max_cases <= PACKET_COUNT:
            raise ValueError('native packet max_cases must be within1..96')
        if template != make_picorv32_native_online_bootstrap().template:
            raise ValueError('native packet session requires the fixed packet template')
        super().__init__(template, runner, **kwargs)
        self._packet_max_cases = max_cases
        self._packet_cursor = INSTRUCTION_START
        self._packet_accepted_count = 0
        self._packet_terminal = False
        self._packet_cleanup_attempted = False
        self.boundary_failure = None
        self.packet_failure = None
        for address in (*range(INSTRUCTION_START, INSTRUCTION_END, PACKET_BYTES),
                        INSTRUCTION_END):
            super().declare_instruction_slots('cpu', address, 1)

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
