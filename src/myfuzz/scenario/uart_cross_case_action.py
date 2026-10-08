"""Versioned, receipt-driven UART Store to host RAM Load action.

This narrow action reserves consecutive Ibex instruction slots. Its Store
eligibility comes from the live UART-to-RAM certificate, not the declared
CPU_TO_IP path label used to admit instruction mutations. Only RAM lane zero
is source certified; the other loaded bytes remain unknown.
"""

from __future__ import annotations

from copy import deepcopy

from .batch import BatchAdvance
from .session_runtime import OnlineCase, OnlineCaseReceipt, OnlineInstruction


_STORE = 0x0032a023  # sw x3, 0(x5); controlled ISR loaded x3 from UART RDATA
_LOAD = 0x0002a303   # lw x6, 0(x5)
_NOP = 0x00000013


class UartHostRamCrossCaseAction:
    """Admit Store, optional gap cases, then Load against a live writer receipt."""

    schema_version = 'uart_host_ram_cross_case_action.v1'

    def __init__(self, *, path_id: str, instruction_start: int, action_id: str,
                 source_case_id: str = 'uart-fixed-warmup',
                 memory_id: str = 'ram', byte_offset: int = 65536):
        if (not all(type(value) is str and value for value in
                    (path_id, action_id, source_case_id, memory_id))
                or type(instruction_start) is not int or instruction_start < 0
                or instruction_start % 4 or type(byte_offset) is not int
                or byte_offset < 0):
            raise ValueError('invalid UART host RAM cross-case action')
        self.path_id = path_id
        self.instruction_start = instruction_start
        self.action_id = action_id
        self.source_case_id = source_case_id
        self.memory_id = memory_id
        self.byte_offset = byte_offset
        self._cursor = instruction_start
        self._sequence = 0
        self._store_submitted = False
        self._load_submitted = False
        self._writer = None
        self._proof = None

    @property
    def terminated(self) -> bool:
        return self._proof is not None

    @property
    def writer(self) -> dict | None:
        return deepcopy(self._writer)

    @property
    def proof(self) -> dict | None:
        return deepcopy(self._proof)

    def document(self) -> dict:
        return {'schema_version': self.schema_version,
                'scope': 'uart_host_ram_low_byte_retired_load_readback',
                'path_id': self.path_id, 'action_id': self.action_id,
                'instruction_start': self.instruction_start,
                'source_case_id': self.source_case_id,
                'memory_id': self.memory_id, 'byte_offset': self.byte_offset,
                'store_insn': _STORE, 'load_insn': _LOAD,
                'termination_kind': 'uart_memory_readback'}

    def _submit(self, session, kind: str, word: int, ticks: int,
                paired_ticks: int = 0) -> OnlineCaseReceipt:
        if (type(ticks) is not int or not 1 <= ticks <= 2400
                or type(paired_ticks) is not int or not 0 <= paired_ticks <= ticks
                or ticks + paired_ticks > 2400):
            raise ValueError('case CPU ticks outside local case budget')
        case_id = f'{self.action_id}:{kind}:{self._sequence}'
        case = OnlineCase(case_id, 'CPU_TO_IP', self.path_id,
                          OnlineInstruction(f'{case_id}:cpu.online_instruction',
                                            'cpu', self._cursor,
                                            word.to_bytes(4, 'little').hex()),
                          ((BatchAdvance(('uart', 'cpu')),) * paired_ticks
                           + (BatchAdvance(('cpu',)),) * (ticks - paired_ticks)))
        receipt = session.submit_case(case)
        if receipt.case_id != case_id or receipt.status != 'running' or receipt.violations:
            raise RuntimeError('cross-case action admission did not remain running')
        self._cursor += 4
        self._sequence += 1
        return receipt

    def submit_store(self, session, *, ticks: int,
                     paired_ticks: int = 0) -> OnlineCaseReceipt:
        if self._store_submitted or self._load_submitted:
            raise ValueError('Store action already admitted')
        receipt = self._submit(session, 'store', _STORE, ticks, paired_ticks)
        self._store_submitted = True
        self.observe(receipt)
        return receipt

    def submit_gap(self, session, *, ticks: int) -> OnlineCaseReceipt:
        if not self._store_submitted or self._load_submitted:
            raise ValueError('gap requires Store before Load')
        receipt = self._submit(session, 'gap', _NOP, ticks)
        self.observe(receipt)
        return receipt

    def submit_load(self, session, *, ticks: int) -> OnlineCaseReceipt:
        if not self._store_submitted or self._writer is None:
            raise ValueError('Load requires an accepted Store certificate')
        if self._load_submitted:
            raise ValueError('Load action already admitted')
        receipt = self._submit(session, 'load', _LOAD, ticks)
        self._load_submitted = True
        self.observe(receipt)
        return receipt

    def observe(self, receipt: OnlineCaseReceipt) -> None:
        if not isinstance(receipt, OnlineCaseReceipt):
            raise ValueError('live online case receipt required')
        for event in receipt.events:
            kind = event.get('kind')
            if kind in ('cpu_reset', 'uart_reset', 'reset_barrier', 'cpu_flush'):
                self._writer = None
                continue
            if kind == 'memory_write_commit':
                self._writer = None
                continue
            if kind == 'uart_store_memory_match' and self._valid_writer(event):
                self._writer = deepcopy(event)
            if (kind == 'uart_memory_readback' and self._load_submitted
                    and self._valid_proof(event, receipt.case_id)):
                self._proof = deepcopy(event)

    def _valid_writer(self, event: dict) -> bool:
        source = event.get('source_admission')
        version = event.get('byte_version')
        return (event.get('status') == 'accepted'
                and event.get('source_path_certified') is True
                and type(source) is dict
                and source.get('case_id') == self.source_case_id
                and source.get('component') == 'uart'
                and source.get('source_id') == 'uart.external_rx_byte'
                and source.get('role') == 'bootstrap'
                and event.get('memory_id') == self.memory_id
                and event.get('byte_offset') == self.byte_offset
                and type(event.get('generation')) is int
                and type(version) is list and len(version) == 2
                and version[0] == event['generation']
                and type(event.get('store_fullkey')) is dict
                and type(event.get('commit_id')) is str
                and type(event.get('store_retirement_event_id')) is int)

    def _valid_proof(self, event: dict, case_id: str) -> bool:
        writer = self._writer
        observed = event.get('load_observed_case')
        return (writer is not None and event.get('status') == 'accepted'
                and event.get('schema_version') in (None, 'uart_memory_readback.v1')
                and type(observed) is dict and observed.get('case_id') == case_id
                and event.get('source_case_id') == self.source_case_id
                and event.get('store_fullkey') == writer['store_fullkey']
                and event.get('store_retirement_event_id') == writer['store_retirement_event_id']
                and event.get('store_commit_id') == writer['commit_id']
                and event.get('store_byte_version') == writer['byte_version']
                and event.get('memory_id') == self.memory_id
                and event.get('generation') == writer['generation']
                and event.get('byte_offset') == self.byte_offset
                and event.get('byte_value') == writer.get('byte_value')
                and event.get('influenced_bits') == [0, 8]
                and type(event.get('load_retirement_event_id')) is int)
