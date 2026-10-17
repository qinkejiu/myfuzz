"""One-boot external serial descriptor cases for three real DMA directions (S2).

The single input source of a case is its external serial byte stream: four
descriptor bytes followed by ``len`` payload bytes.  The CPU pops those bytes
from the real UART RX FIFO, decodes them, materializes the RAM source words and
writes the real DMA registers; a real native IRQ reaches the real ISR, which
reads the real DMA status/length registers.

S4 installs the declared UART RX FIFO source graph before the first RTL command
(``compile_dma_source_provenance``), admits every external serial byte with a
typed ``SourceAdmission``, and joins the tracker's accepted retention and
read-consumption rows to this case's certified FIFO entries and pops.  A case
claims ``fifo_origin='accepted_uart_fifo_entry'`` only when that join is exact;
otherwise it stays ``unknown`` and names the missing element.  The raw
``uart_frame_validation.fifo_origin`` field is never rewritten.  S3 adds the
declared illegal descriptor: the real ``wbdmac`` takes its bus-error path, the
real native IRQ reaches the CPU, and the ISR records the real status/length/
mcause/counter.  That case is certified as ``environment_error`` (never as a
successful dataflow).  The per-case evidence is a bounded chain over real
journal rows, never a host-signed token.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Callable, Mapping

from myfuzz.local_harness.build import host_source_discovery_scope
from myfuzz.scenario.batch import (BatchAdvance, BatchSourceEvent,
    ScenarioBatchCodec, ScenarioBatchPlan, ScenarioBatchRecorder)
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.dma_runtime_paths import (DmaSourceProvenance,
    NOT_INSTALLED, compile_dma_source_provenance, register_case_admissions)
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.ibex_dma_example import DMA_BASE
from myfuzz.scenario.ibex_dma_uart_descriptor import (
    COMPLETED, CONTROL_KEY, CONTROL_KEY_MASK, DECLARED_DIRECTIONS,
    DESCRIPTOR_WORDS, DEST_WORDS, DESTINATION, DIRECTION_CODES,
    DMA_STATUS_LAYOUT, ILLEGAL_TARGET, ISR_PCS, MAIN, MAX_LENGTH, RESULT,
    SOURCE_RAM, UART_BASE, UART_RDATA, UART_RDATA_OFFSET, UART_RXEMPTY_MASK,
    UART_STATUS_OFFSET, UART_WDATA, UART_WDATA_OFFSET, WITNESS,
    WITNESS_POINTER, descriptor_program, dma_status_fields,
    make_descriptor_runner)
from myfuzz.scenario.replay_normalize import (first_difference_normalized,
    first_replay_difference)
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.uart_fifo_authority import source_authority_evidence

from .dma_uart_rx_runtime import (_capture, _case_boundaries, _close,
    _execution_ids, _fifo_depth_after, _normalize, _poll_schedule, _source_pins)

DIAGNOSTIC_SCHEMA = 'descriptor_dma_diagnostic.v1'
CASE_SCHEMA = 'descriptor_dma_case.v1'
SOURCE_PORT = 'uart_rx_byte'
SOURCE_COMPONENT = 'uart'
ACTION_PREFIX = 'descriptor'
CASE_ID_PREFIX = 'descriptor-case-'
OUTCOMES = ('complete', 'environment_error')
DMA_IRQ_MCAUSE = 0x8000000B
UART_TX_CLOCKS_PER_BIT = 32
UART_TX_FRAME_TICKS = 10 * UART_TX_CLOCKS_PER_BIT
SOURCE_TICKS_PER_BYTE = 1024
TX_DRAIN_MARGIN_TICKS = UART_TX_FRAME_TICKS
# A real CPU writes the COMPLETED word before the store retires and before MRET;
# the case slice must continue a bounded number of poll rounds so the store
# retirement (and, when visible, MRET plus the return to the main loop) is in the
# journal before the case is sealed.
COMPLETION_ROUNDS = 64
# Addresses a host write must never touch; every store there is CPU or DMA.
GUARDED_ADDRESSES = (SOURCE_RAM, SOURCE_RAM + 4 * DEST_WORDS, DESTINATION,
                     DESTINATION + 4 * DEST_WORDS, RESULT, RESULT + 24)
DMA_WRITE_COMPONENTS = ('cpu', 'dma')


class DescriptorCaseRejected(ValueError):
    """A predecessor-free refusal: the case never issued one RTL command."""


class DescriptorFailure(RuntimeError):
    """A post-RTL failure with its original prefix and finalized diagnostics."""

    def __init__(self, result):
        self.result = result
        super().__init__(str(result.error))


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode('utf-8')


def _sha256_hex(document) -> str:
    return hashlib.sha256(_canonical(document)).hexdigest()


def _positive_int(value, name, *, maximum=None):
    if type(value) is not int or value < 1 or (maximum is not None and value > maximum):
        raise ValueError(f'{name} must be an integer in 1..{maximum or "inf"}')
    return value


def _byte(value, name):
    if type(value) is not int or not 0 <= value <= 255:
        raise ValueError(f'{name} must be a serial byte in 0..255')
    return value


def descriptor_windows():
    """The declared windows every pre-RTL check is expressed against."""
    return {
        # Half-open windows.  Scalar fields are checked with width=1.
        'uart_rx_byte': (0, 256),
        'descriptor_direction': (0, len(DECLARED_DIRECTIONS)),
        'descriptor_length': (1, MAX_LENGTH + 1),
        'descriptor_dst_index': (0, DEST_WORDS),
        'uart_rdata': (UART_RDATA, UART_RDATA + 4),
        'uart_wdata': (UART_WDATA, UART_WDATA + 4),
        'source_ram': (SOURCE_RAM, SOURCE_RAM + 4 * DEST_WORDS),
        'destination_ram': (DESTINATION, DESTINATION + 4 * DEST_WORDS),
        'declared_illegal': (ILLEGAL_TARGET, ILLEGAL_TARGET + 4),
    }


def decode_descriptor(source_bytes):
    """Decode the fixed four-byte descriptor exactly as the firmware does."""
    if not isinstance(source_bytes, (tuple, list)) or len(source_bytes) < DESCRIPTOR_WORDS:
        raise ValueError('a descriptor needs at least four serial bytes')
    values = tuple(source_bytes)
    for index, value in enumerate(values):
        _byte(value, f'descriptor byte {index}')
    direction_code = values[0] & 3
    length = (values[1] & 3) + 1
    dst_index = values[2] & 3
    payload = values[3]
    by_code = {code: name for name, code in DIRECTION_CODES.items()}
    direction = by_code[direction_code]
    if len(values) != DESCRIPTOR_WORDS + length:
        raise ValueError('serial stream must be four descriptor bytes plus len payload bytes')
    return dict(direction=direction, direction_code=direction_code,
        length=length, dst_index=dst_index, payload=payload,
        payload_bytes=values[DESCRIPTOR_WORDS:])


def encode_descriptor(direction, dst_index, payload, length):
    """Canonical wire descriptor: high bits zero, payload repeated ``len``."""
    if direction not in DECLARED_DIRECTIONS:
        raise DescriptorCaseRejected('undeclared descriptor direction')
    _byte(payload, 'payload')
    if type(length) is not int or not 1 <= length <= MAX_LENGTH:
        raise DescriptorCaseRejected(f'length must be in 1..{MAX_LENGTH}')
    if type(dst_index) is not int or not 0 <= dst_index < DEST_WORDS:
        raise DescriptorCaseRejected(f'dst_index must be in 0..{DEST_WORDS - 1}')
    code = DIRECTION_CODES[direction]
    return (code, length - 1, dst_index, payload) + (payload,) * length


@dataclass(frozen=True)
class DescriptorCase:
    """One declared external serial descriptor case.

    ``source_bytes`` is the whole case input: descriptor plus payload bytes.
    Every field below is derived from those bytes; a spec that declares a
    different field is refused instead of being silently decoded twice.
    """

    direction: str
    dst_index: int
    payload: int
    length: int
    source_bytes: tuple[int, ...]
    descriptor: dict
    expect: str = 'complete'

    def __post_init__(self):
        if self.direction not in DECLARED_DIRECTIONS:
            raise DescriptorCaseRejected('undeclared descriptor direction')
        if self.expect not in OUTCOMES:
            raise DescriptorCaseRejected('undeclared descriptor outcome')
        expected = 'environment_error' if self.direction == 'ILLEGAL' else 'complete'
        if self.expect != expected:
            raise DescriptorCaseRejected(
                'only the declared illegal direction may carry environment_error')
        if not isinstance(self.source_bytes, tuple):
            raise ValueError('source_bytes must be a tuple of serial bytes')
        for index, value in enumerate(self.source_bytes):
            _byte(value, f'source byte {index}')
        decoded = decode_descriptor(self.source_bytes)
        if (decoded['direction'] != self.direction
                or decoded['dst_index'] != self.dst_index
                or decoded['payload'] != self.payload
                or decoded['length'] != self.length):
            raise ValueError('declared descriptor fields differ from the serial bytes')
        if decoded['payload_bytes'] != (self.payload,) * self.length:
            raise ValueError('every transferred word must equal the payload')
        if not isinstance(self.descriptor, dict) or self.descriptor != {
                'direction': self.direction, 'dst_index': self.dst_index,
                'payload': self.payload, 'length': self.length}:
            raise ValueError('descriptor document differs from the decoded fields')

    # -- constructors ------------------------------------------------------
    @classmethod
    def create(cls, direction, *, dst_index, payload, length):
        source_bytes = encode_descriptor(direction, dst_index, payload, length)
        expect = 'environment_error' if direction == 'ILLEGAL' else 'complete'
        return cls(direction, dst_index, payload, length, source_bytes,
            dict(direction=direction, dst_index=dst_index, payload=payload,
                 length=length), expect)

    @classmethod
    def from_wire(cls, source_bytes):
        decoded = decode_descriptor(tuple(source_bytes))
        direction = decoded['direction']
        expect = 'environment_error' if direction == 'ILLEGAL' else 'complete'
        return cls(direction, decoded['dst_index'], decoded['payload'],
            decoded['length'], tuple(source_bytes),
            dict(direction=direction, dst_index=decoded['dst_index'],
                 payload=decoded['payload'], length=decoded['length']),
            expect)

    # -- declared program --------------------------------------------------
    @property
    def source_count(self) -> int:
        return len(self.source_bytes)

    def action_ids(self, case_index: int) -> tuple[str, ...]:
        _positive_int(case_index, 'case index', maximum=1 << 20)
        return tuple(f'{ACTION_PREFIX}-{case_index}-{slot}'
                     for slot in range(self.source_count))

    def program(self):
        return descriptor_program(self.direction, self.dst_index, self.length)

    def identity(self, firmware_sha256: str) -> str:
        if (not isinstance(firmware_sha256, str) or len(firmware_sha256) != 64
                or any(character not in '0123456789abcdef'
                       for character in firmware_sha256)):
            raise ValueError('firmware identity must be a lowercase sha256 digest')
        return _sha256_hex(dict(schema_version=CASE_SCHEMA,
            direction=self.direction, source_bytes=list(self.source_bytes),
            descriptor=self.descriptor, expect=self.expect,
            firmware_sha256=firmware_sha256))

    # -- pure pre-RTL validation ------------------------------------------
    def validate(self, windows=None):
        """Refuse an unexecutable case without issuing any RTL command."""
        declared = descriptor_windows() if windows is None else windows
        if not isinstance(declared, Mapping):
            raise ValueError('declared windows must be a mapping')
        for name in ('uart_rx_byte', 'descriptor_direction', 'descriptor_length',
                'descriptor_dst_index', 'uart_rdata', 'uart_wdata', 'source_ram',
                'destination_ram', 'declared_illegal'):
            if name not in declared:
                raise DescriptorCaseRejected(f'declared window {name} is missing')
            value = declared[name]
            if (not isinstance(value, tuple) or len(value) != 2
                    or type(value[0]) is not int or type(value[1]) is not int
                    or not 0 <= value[0] <= value[1]):
                raise ValueError(f'declared window {name} is invalid')

        def inside(name, address, width=4):
            low, high = declared[name]
            if not (low <= address and address + width <= high):
                raise DescriptorCaseRejected(
                    f'address {address:#x} is outside the declared {name} window')

        if self.direction not in DECLARED_DIRECTIONS:
            raise DescriptorCaseRejected('undeclared descriptor direction')
        if self.expect not in OUTCOMES:
            raise DescriptorCaseRejected('undeclared descriptor outcome')
        expected = 'environment_error' if self.direction == 'ILLEGAL' else 'complete'
        if self.expect != expected:
            raise DescriptorCaseRejected(
                'only the declared illegal direction may carry environment_error')
        code = DIRECTION_CODES[self.direction]
        inside('descriptor_direction', code, 1)
        inside('descriptor_length', self.length, 1)
        inside('descriptor_dst_index', self.dst_index, 1)
        # The serial stream must equal the canonical encoding: a spec cannot
        # hide a second, differently-masked descriptor in the high bits.
        canonical = encode_descriptor(self.direction, self.dst_index,
            self.payload, self.length)
        if tuple(self.source_bytes) != canonical:
            raise DescriptorCaseRejected(
                'serial descriptor bytes are not the canonical declared encoding')
        decoded = decode_descriptor(self.source_bytes)
        if (decoded['payload_bytes'] != (self.payload,) * self.length
                or decoded['direction_code'] != code):
            raise DescriptorCaseRejected('serial stream does not decode to the declared case')
        program = descriptor_program(self.direction, self.dst_index, self.length)
        if ILLEGAL_TARGET not in range(*declared['declared_illegal']):
            raise DescriptorCaseRejected('the declared illegal master target is missing')
        if self.direction == 'ILLEGAL':
            # The only declared error path: both master addresses are the one
            # declared illegal offset, so the real target environment rejects
            # the first read before any data beat or RAM commit can exist.
            inside('declared_illegal', program['source'])
            inside('declared_illegal', program['destination'])
            if (program['source'] != ILLEGAL_TARGET
                    or program['destination'] != ILLEGAL_TARGET):
                raise DescriptorCaseRejected(
                    'the illegal case must program the declared illegal target')
            inside('destination_ram', program['witness'])
        else:
            for address in program['source_words']:
                if self.direction == 'RX_TO_RAM':
                    inside('uart_rdata', address)
                else:
                    inside('source_ram', address)
            for address in program['destination_words']:
                if self.direction == 'RAM_TO_TX':
                    inside('uart_wdata', address)
                else:
                    inside('destination_ram', address)
            for address in program['cpu_source_words']:
                inside('source_ram', address)
            if self.direction == 'RAM_TO_TX':
                inside('source_ram', program['witness'])
            else:
                inside('destination_ram', program['witness'])
            for address in (*program['source_words'], *program['destination_words']):
                if address == ILLEGAL_TARGET:
                    raise DescriptorCaseRejected(
                        'a complete case cannot target the declared illegal offset')
        # Every payload byte is already queued by the spec; nothing is invented.
        if len(self.source_bytes) - DESCRIPTOR_WORDS != self.length:
            raise DescriptorCaseRejected('len exceeds the queued payload bytes')
        return program

    # -- portable documents ------------------------------------------------
    def to_document(self) -> dict:
        return dict(direction=self.direction, dst_index=self.dst_index,
            payload=self.payload, length=self.length,
            source_bytes=list(self.source_bytes), descriptor=dict(self.descriptor),
            expect=self.expect)

    @classmethod
    def from_document(cls, document) -> 'DescriptorCase':
        if not isinstance(document, dict) or set(document) != {
                'direction', 'dst_index', 'payload', 'length', 'source_bytes',
                'descriptor', 'expect'}:
            raise ValueError('saved descriptor case fields are invalid')
        return cls(document['direction'], document['dst_index'], document['payload'],
            document['length'], tuple(document['source_bytes']),
            dict(document['descriptor']), document['expect'])


def assert_plan_matches_cases(plan, cases, *, firmware_sha256=None):
    """Hard anti-fabrication join between the plan and the declared specs."""
    if not isinstance(plan, ScenarioBatchPlan):
        raise ValueError('ScenarioBatchPlan is required')
    sources = [command for command in plan.commands
               if isinstance(command, BatchSourceEvent)]
    expected_values, expected_ids = [], []
    for case_index, case in enumerate(cases, 1):
        if not isinstance(case, DescriptorCase):
            raise ValueError('DescriptorCase is required')
        expected_values.extend(case.source_bytes)
        expected_ids.extend(f'{ACTION_PREFIX}-{case_index}-{slot}'
                            for slot in range(case.source_count))
    actual_values = [command.value for command in sources]
    actual_ids = [command.action_id for command in sources]
    if actual_values != expected_values or actual_ids != expected_ids:
        raise DescriptorCaseRejected('plan source commands differ from the declared cases')
    if any(command.component != SOURCE_COMPONENT or command.port != SOURCE_PORT
           or command.width != 8 or command.bit_offset != 0 for command in sources):
        raise DescriptorCaseRejected('plan contains a non-descriptor source command')
    if firmware_sha256 is not None:
        identities = [case.identity(firmware_sha256) for case in cases]
        if len(set(identities)) != len(identities):
            raise DescriptorCaseRejected('declared case identities are not unique')
    return tuple(expected_ids)


# ---------------------------------------------------------------------------
# Journal extraction and per-case certification
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class CaseWitnesses:
    """Raw rows of one case slice, grouped without judging them."""

    frames: tuple[dict, ...]
    source_injections: tuple[dict, ...]
    cpu_pops: tuple[dict, ...]
    uart_rdata_mmio: tuple[dict, ...]
    uart_status_mmio: tuple[dict, ...]
    dma_mmio: tuple[dict, ...]
    beats: tuple[dict, ...]
    responses: tuple[dict, ...]
    memory_writes: tuple[dict, ...]
    data_responses: tuple[dict, ...]
    retires: tuple[dict, ...]
    external_irq: tuple[dict, ...]
    bound_takes: tuple[dict, ...]
    bound_starts: tuple[dict, ...]
    irq_edges: tuple[dict, ...]
    tick_observations: tuple[dict, ...]
    tick_pushes: tuple[dict, ...]
    # S3 error-path rows.  They are grouped, never reclassified: a rejected
    # master request is not a data beat, and an error response is not an ACK.
    dma_edges: tuple[dict, ...]
    rejections: tuple[dict, ...]
    environment_errors: tuple[dict, ...]
    error_responses: tuple[dict, ...]
    error_irq_edges: tuple[dict, ...]
    dma_rdata_accesses: tuple[dict, ...]
    rows: tuple[dict, ...] = ()


def extract_case_witnesses(rows):
    """Group real journal rows by kind; never reclassify or synthesize."""
    if not isinstance(rows, (tuple, list)):
        raise ValueError('case rows must be a recorded sequence')
    grouped: dict[str, list] = {name: [] for name in (
        'frames', 'source_injections', 'cpu_pops', 'uart_rdata_mmio',
        'uart_status_mmio', 'dma_mmio', 'beats', 'responses', 'memory_writes',
        'data_responses', 'retires', 'external_irq', 'bound_takes',
        'bound_starts', 'irq_edges', 'tick_observations', 'tick_pushes',
        'dma_edges', 'rejections', 'environment_errors', 'error_responses',
        'error_irq_edges', 'dma_rdata_accesses')}
    for event in rows:
        if not isinstance(event, dict):
            raise ValueError('journal records must be objects')
        kind = event.get('kind')
        if kind == 'uart_frame_validation' and event.get('waveform_matched') is True:
            grouped['frames'].append(event)
        elif kind == 'source_injection':
            grouped['source_injections'].append(event)
        elif kind == 'uart_rdata_access':
            transaction = event.get('source_transaction')
            if isinstance(transaction, dict) and transaction.get('channel_id') == 'data':
                event = dict(event, _pop_source='top_level')
                grouped['cpu_pops'].append(event)
            else:
                # A DMA-master or unattributed RDATA access.  On the S3 error
                # path there must be none: a rejected read never pops the FIFO.
                grouped['dma_rdata_accesses'].append(event)
        elif kind == 'mmio_delivery':
            device = event.get('device_id')
            if device == 'uart' and event.get('offset') == UART_RDATA_OFFSET \
                    and event.get('write') is False:
                grouped['uart_rdata_mmio'].append(event)
            elif device == 'uart' and event.get('offset') == UART_STATUS_OFFSET \
                    and event.get('write') is False:
                grouped['uart_status_mmio'].append(event)
            elif device == 'dma':
                grouped['dma_mmio'].append(event)
        elif kind == 'dma_edge':
            grouped['dma_edges'].append(event)
            accepted = event.get('accepted')
            receipt = event.get('environment_error_receipt')
            rejected = isinstance(accepted, dict) and (
                'target_rejection' in accepted or isinstance(receipt, dict))
            if isinstance(accepted, dict) and not rejected:
                grouped['beats'].append(event)
            if rejected:
                grouped['rejections'].append(event)
            if isinstance(receipt, dict):
                grouped['environment_errors'].append(event)
            response = event.get('response')
            if isinstance(response, dict):
                grouped['responses'].append(event)
                if response.get('error') == 1:
                    grouped['error_responses'].append(event)
            payload = event.get('payload') or {}
            physical = (payload.get('observations') or {}).get('physical') or {}
            backend = payload.get('pre_backend') or {}
            pulse = (isinstance(physical, dict)
                     and any(bool(value) for value in physical.values()))
            if (pulse and backend.get('mwb_ack') == 1 and backend.get('mwb_we') == 1
                    and backend.get('mwb_err') == 0):
                grouped['irq_edges'].append(event)
            if pulse and backend.get('mwb_err') == 1:
                grouped['error_irq_edges'].append(event)
        elif kind == 'memory_write':
            grouped['memory_writes'].append(event)
        elif kind == 'data_response':
            grouped['data_responses'].append(event)
        elif kind == 'cpu_retire':
            grouped['retires'].append(event)
        elif kind == 'cpu_external_irq_taken':
            grouped['external_irq'].append(event)
        elif kind == 'cpu_irq_taken':
            if (tuple(event.get('source') or ()) == ('dma', 'irq')
                    and tuple(event.get('target') or ()) == ('cpu', 'irq')):
                grouped['bound_takes'].append(event)
        elif kind == 'source_start':
            if (tuple(event.get('source') or ()) == ('dma', 'irq')
                    and tuple(event.get('target') or ()) == ('cpu', 'irq')):
                grouped['bound_starts'].append(event)
        elif kind == 'uart_tick_observation':
            grouped['tick_observations'].append(event)
            post = event.get('post') or {}
            if (post.get('probe_uart_fifo_wvalid') == 1
                    and post.get('probe_uart_fifo_wready') == 1):
                grouped['tick_pushes'].append(event)
    grouped['cpu_pops'] = _merge_cpu_pops(grouped['cpu_pops'],
        grouped['uart_rdata_mmio'])
    grouped['rows'] = tuple(rows)
    return CaseWitnesses(**{name: tuple(value) for name, value in grouped.items()})


def _merge_cpu_pops(top_level, deliveries):
    """Authoritative CPU RDATA pops from both real journal shapes.

    A routed CPU RDATA read is recorded twice in the real journal: a top-level
    ``uart_rdata_access`` external event and the same access nested as
    ``mmio_delivery.target_uart_access``.  On a step boundary the top-level copy
    can be absent while the nested copy (with its real ``read_capture``) is
    present.  Both are real RTL access facts, so a pop is counted once, keyed by
    its real ``access_id``; a nested-only pop is anchored at the delivery event
    that carried it.  A nested object without a real access id is ignored, which
    leaves the real pop count short and fails certification instead of guessing.
    """
    seen = set()
    merged = []
    for row in top_level:
        access_id = row.get('access_id')
        if isinstance(access_id, str) and access_id:
            seen.add(access_id)
        merged.append(row)
    for delivery in deliveries:
        nested = delivery.get('target_uart_access')
        if not isinstance(nested, dict):
            continue
        if nested.get('kind') != 'uart_rdata_access':
            continue
        access_id = nested.get('access_id')
        if not isinstance(access_id, str) or not access_id or access_id in seen:
            continue
        row = dict(nested, _pop_source='nested',
            event_id=delivery.get('event_id'))
        merged.append(row)
        seen.add(access_id)
    return sorted(merged, key=lambda row: (row.get('event_id') is None,
        row.get('event_id')))


def _one(rows, message):
    if len(rows) != 1:
        raise RuntimeError(message)
    return rows[0]


def _event_id(value, name):
    if type(value) is not int or value < 1:
        raise RuntimeError(f'{name} is missing a real journal event id')
    return value


def _fifo_sample(access, phase, name):
    capture = (access.get('read_capture') or {}).get(phase) or {}
    value = capture.get('probe_uart_fifo_depth')
    if type(value) is not int:
        raise RuntimeError(f'{name} lacks a real UART FIFO {phase} depth probe')
    return capture


def _read_beat_fifo(event, payload, name):
    """One real DMA UART FIFO pop, with pre/post depth and head witnesses."""
    delivery = event['accepted'].get('target_delivery')
    if not isinstance(delivery, dict):
        raise RuntimeError(f'{name} DMA UART read lacks a target delivery')
    access = delivery.get('target_uart_access')
    if not isinstance(access, dict):
        raise RuntimeError(f'{name} DMA UART read lacks a real UART access record')
    if (delivery.get('target_component') != 'uart'
            or delivery.get('offset') != UART_RDATA_OFFSET
            or delivery.get('write') is not False
            or access.get('status') != 'observed'
            or access.get('read_value') != delivery.get('value')
            or access.get('read_value') != payload):
        raise RuntimeError(f'{name} DMA UART read does not pop the declared payload')
    pre = _fifo_sample(access, 'pre', name)
    post = _fifo_sample(access, 'post', name)
    if (pre.get('probe_uart_fifo_rvalid') != 1
            or pre.get('probe_uart_fifo_rdata_re') != 1
            or pre.get('probe_uart_fifo_under_rst') != 0
            or pre.get('probe_uart_fifo_head') != payload):
        raise RuntimeError(f'{name} DMA UART read lacks real FIFO pop proof')
    if post.get('probe_uart_fifo_depth') != pre['probe_uart_fifo_depth'] - 1:
        raise RuntimeError(f'{name} DMA UART pop did not decrement the real FIFO depth')
    return dict(pre_depth=pre['probe_uart_fifo_depth'],
        pre_head=pre['probe_uart_fifo_head'],
        post_depth=post['probe_uart_fifo_depth'],
        read_value=access['read_value'], access_id=access.get('access_id'),
        tick=access.get('local_tick'))


def _cpu_pop_fifo(event, payload, name):
    pre = _fifo_sample(event, 'pre', name)
    post = _fifo_sample(event, 'post', name)
    if (event.get('read_value') != payload
            or event.get('status') != 'observed'
            or event.get('raw_offset') != UART_RDATA_OFFSET
            or pre.get('probe_uart_fifo_rvalid') != 1
            or pre.get('probe_uart_fifo_rdata_re') != 1
            or pre.get('probe_uart_fifo_head') != payload
            or post.get('probe_uart_fifo_depth') != pre['probe_uart_fifo_depth'] - 1):
        raise RuntimeError(f'{name} CPU RDATA read is not a real FIFO pop of the byte')
    return dict(pre_depth=pre['probe_uart_fifo_depth'], pre_head=pre['probe_uart_fifo_head'],
        post_depth=post['probe_uart_fifo_depth'], read_value=event['read_value'],
        access_id=event.get('access_id'), tick=event.get('local_tick'),
        source=event.get('_pop_source', 'top_level'))


def _retire(retires, pc, *, mem_addr=None, wmask=15, wdata=None, rmask=15,
            rdata=None, rs2=None, rd=None):
    matches = [event for event in retires if event.get('pc_rdata') == pc]
    if len(matches) != 1:
        raise RuntimeError(f'ISR PC {pc:#x} lacks exactly one real retirement')
    event = matches[0]
    if mem_addr is not None and event.get('mem_addr') != mem_addr:
        raise RuntimeError(f'ISR PC {pc:#x} retired a different real address')
    if wdata is not None and (event.get('mem_wmask') != wmask
                              or event.get('mem_wdata') != wdata):
        raise RuntimeError(f'ISR PC {pc:#x} retired a different real store')
    if rs2 is not None and event.get('rs2_addr') != rs2:
        raise RuntimeError(f'ISR PC {pc:#x} retired a different store source register')
    if rdata is not None and (event.get('mem_rmask') != rmask
                              or event.get('mem_rdata') != rdata):
        raise RuntimeError(f'ISR PC {pc:#x} retired a different real load')
    if rd is not None and (event.get('rd_addr') != rd
                           or event.get('rd_wdata') != rdata):
        raise RuntimeError(f'ISR PC {pc:#x} retired a different load destination')
    return _event_id(event.get('event_id'), 'ISR retirement')


def _push_depth_chain(observations, pushes, source_bytes):
    """Real RX FIFO push depth, read one tick after the write strobe.

    A pinned ``uart_tick_observation`` samples ``post`` at the push strobe tick
    while the FIFO depth counter still shows the pre-push occupancy; the
    increment is visible on the immediately following tick sample.  Both probes
    are real RTL observations, so the chain requires the following sample to be
    exactly one greater and the chain to stay contiguous.
    """
    positions = {}
    for index, event in enumerate(observations):
        positions.setdefault(event.get('event_id'), index)
    chain = []
    previous = None
    for push, byte in zip(pushes, source_bytes):
        post = push.get('post') or {}
        if (post.get('probe_uart_fifo_wvalid') != 1
                or post.get('probe_uart_fifo_wready') != 1):
            raise RuntimeError('UART RX FIFO push tick lacks real wvalid/wready')
        if post.get('probe_uart_fifo_data') != byte:
            raise RuntimeError('UART RX FIFO push data differs from the declared byte')
        before = post.get('probe_uart_fifo_depth')
        if type(before) is not int or before < 0:
            raise RuntimeError('UART RX FIFO push lacks the real pre-push depth probe')
        position = positions.get(push.get('event_id'))
        if position is None or position + 1 >= len(observations):
            raise RuntimeError('UART RX FIFO push lacks a following real tick sample')
        following = observations[position + 1]
        if (following.get('post') or {}).get('probe_uart_fifo_wvalid') == 1:
            raise RuntimeError('UART RX FIFO push lacks an intervening tick sample')
        after = (following.get('post') or {}).get('probe_uart_fifo_depth')
        if type(after) is not int or after != before + 1:
            raise RuntimeError('UART RX FIFO depth did not increment after the push')
        if previous is not None and before != previous:
            raise RuntimeError('UART RX FIFO depth chain is not contiguous')
        chain.append(dict(tick=push.get('local_tick'), byte=byte,
            depth_before=before, depth_after=after,
            head_after=(following.get('post') or {}).get('probe_uart_fifo_head'),
            following_tick=following.get('local_tick'),
            event_id=push.get('event_id')))
        previous = after
    # The push strobe sample carries the occupancy *before* the write, so the
    # real push stream of one case must be exactly 0..n-1 and empty at start.
    if [item['depth_before'] for item in chain] != list(range(len(chain))):
        raise RuntimeError(
            'UART RX FIFO push depths are not exactly 0..n-1 (stale/repeated/missing push)')
    if chain[-1]['depth_before'] + 1 != len(chain):
        raise RuntimeError('UART RX FIFO push stream does not end at the serial byte count')
    return tuple(chain)


def _assert_no_host_writes(writes):
    for event in writes:
        address = event.get('address')
        if type(address) is not int:
            continue
        if any(
                low <= address < high for low, high in (
                    (SOURCE_RAM, SOURCE_RAM + 4 * DEST_WORDS),
                    (DESTINATION, DESTINATION + 4 * DEST_WORDS),
                    (RESULT, RESULT + 24))):
            if event.get('component') not in DMA_WRITE_COMPONENTS:
                raise RuntimeError('a non-CPU/DMA writer wrote case data')


def _certify_environment_error(witnesses, case, *, case_index, program,
        action_ids, frame_ids, push_chain, push_depths, cpu_pops, cpu_fifo,
        cpu_values, settled_pops, settled, witness_pointer_store, tx_captures):
    """Certify the declared illegal master target against the real journal.

    The only error signal accepted here is a real environment rejection of the
    declared illegal target: one accepted master request carrying
    ``target_rejection='declared_master_target_access'``, its real
    ``environment_error_receipt`` (``error=1``, ``target_effect=false``), the
    real error response (``response.error=1``), the real native IRQ pulse on
    that response edge, the real CPU take, and the real ISR status/length/
    witness/counter stores and retirements.  The status word is recorded as
    measured; only the RTL-declared error/busy/inc bit positions are checked,
    never a pre-baked status value.
    """
    if case.direction != 'ILLEGAL' or case.expect != 'environment_error':
        raise ValueError('an environment-error certificate requires the illegal case')
    if witnesses.irq_edges:
        raise RuntimeError('an environment-error case must not carry a success IRQ pulse')
    tx_captures = tuple(tx_captures)
    if tx_captures:
        raise RuntimeError('an environment-error case must not transmit on the UART pin')
    if witnesses.beats:
        raise RuntimeError('an environment-error case must not accept a data beat')
    accepted_edges = [event for event in witnesses.dma_edges
                      if isinstance(event.get('accepted'), dict)]
    request = _one(accepted_edges,
        'illegal case needs exactly one real accepted master request')
    request_id = _event_id(request.get('event_id'), 'rejected master request')
    accepted = request['accepted']
    if accepted.get('write') is not False:
        raise RuntimeError('the declared illegal target must be read, not written')
    if accepted.get('address') != program['source']:
        raise RuntimeError('rejected master request address differs from the declared target')
    if accepted.get('target_rejection') != 'declared_master_target_access':
        raise RuntimeError('rejected master request is not the declared target rejection')
    if (isinstance(accepted.get('target_delivery'), dict)
            or isinstance(request.get('target_delivery'), dict)):
        raise RuntimeError('an environment-error request must have no target delivery')
    key = accepted.get('transaction')
    if (not isinstance(key, dict) or key.get('channel_id') != 'dma-memory'
            or key.get('source_component') != 'dma'):
        raise RuntimeError('rejected master request lacks the real DMA transaction identity')

    receipt_event = _one(witnesses.environment_errors,
        'illegal case needs exactly one real environment error receipt')
    if receipt_event.get('event_id') != request_id:
        raise RuntimeError('environment error receipt is not the rejected master request')
    receipt = receipt_event['environment_error_receipt']
    expected_receipt = dict(error=1, target_effect=False,
        op='master_environment_error', address=program['source'], write=False,
        byte_enable=15, reason='declared_master_target_access')
    for field, expected in expected_receipt.items():
        if receipt.get(field) != expected:
            raise RuntimeError(f'environment error receipt field {field} is not the declared rejection')
    if receipt.get('source_transaction') != key:
        raise RuntimeError('environment error receipt transaction differs from the real request')

    response_events = [event for event in witnesses.error_responses
                       if (event['response'].get('transaction') or {}) == key]
    response_event = _one(response_events,
        'illegal case needs exactly one real error response for the rejected request')
    response = response_event['response']
    response_id = _event_id(response_event.get('event_id'), 'error response')
    if response.get('error') != 1 or response.get('rdata') != 0:
        raise RuntimeError('real DMA error response is not the declared bus error')
    if response_id <= request_id:
        raise RuntimeError('DMA error response precedes its accepted master request')

    # The error completion edge is the same real edge that carries the native
    # DMA interrupt pulse and inputs i_mwb_err=1 to the controller.
    error_edge = _one(witnesses.error_irq_edges,
        'illegal case needs one real native error IRQ pulse')
    if error_edge.get('event_id') != response_id:
        raise RuntimeError('native DMA error IRQ pulse is not the error response edge')
    edge_backend = (error_edge.get('payload') or {}).get('pre_backend') or {}
    if (edge_backend.get('mwb_err') != 1 or edge_backend.get('mwb_ack') != 0
            or edge_backend.get('mwb_we') != 0):
        raise RuntimeError('native DMA error IRQ edge is not the real bus-error completion')

    # No target was touched and no FIFO entry was popped after the rejection.
    # A routed CPU RDATA external event can be journaled after the case that
    # caused it was sealed; its late top-level copy has no source_transaction
    # and would otherwise look like a DMA master pop.  The boot supplies every
    # access id already counted in an earlier case, so those late copies are
    # excluded by their real access id.  A pop with no id, or with an id outside
    # the settled set, is still a hard failure (never guessed away).
    def settled_late(event):
        access_id = event.get('access_id')
        return (isinstance(access_id, str) and bool(access_id)
                and access_id in settled)

    late_dma_accesses = tuple(event for event in witnesses.dma_rdata_accesses
                              if settled_late(event))
    real_dma_accesses = tuple(event for event in witnesses.dma_rdata_accesses
                              if not settled_late(event))
    if real_dma_accesses:
        raise RuntimeError('an illegal DMA request must not pop the UART RX FIFO')
    protected = ((SOURCE_RAM, SOURCE_RAM + 4 * DEST_WORDS),
                 (DESTINATION, DESTINATION + 4 * DEST_WORDS))
    for event in witnesses.memory_writes:
        address = event.get('address')
        if type(address) is int and any(low <= address < high
                                       for low, high in protected):
            raise RuntimeError('an environment-error case must not commit RAM data')
    pop_ids = [_event_id(event.get('event_id'), 'CPU RDATA pop')
               for event in cpu_pops]
    if max(pop_ids) >= request_id:
        raise RuntimeError('CPU payload drain occurred after the illegal master request')

    start = _one(witnesses.bound_starts, 'error case needs one bound DMA IRQ source start')
    take = _one(witnesses.bound_takes, 'error case needs one bound CPU IRQ take')
    external = _one(witnesses.external_irq, 'error case needs one real external IRQ take')
    if (start.get('source_event_id') != take.get('source_event_id')
            or take.get('cpu_tick') != external.get('local_tick')
            or start.get('source_tick') != error_edge.get('native_local_tick')):
        raise RuntimeError('CPU error take is not joined to the real DMA error pulse tick')
    if not (response_id < start.get('event_id') < external.get('event_id')
            < take.get('event_id')):
        raise RuntimeError('DMA error/IRQ/CPU take order is incomplete')

    # Real ISR reads and stores.  The status word is recorded exactly as read.
    status_delivery = _one([event for event in witnesses.dma_mmio
        if event.get('write') is False and event.get('offset') == 0],
        'error ISR status store lacks a real DMA status MMIO delivery')
    length_delivery = _one([event for event in witnesses.dma_mmio
        if event.get('write') is False and event.get('offset') == 4],
        'error ISR length store lacks a real DMA length MMIO delivery')
    status = status_delivery.get('read_value')
    length_actual = length_delivery.get('read_value')
    if type(status) is not int or not 0 <= status <= 0xFFFFFFFF:
        raise RuntimeError('error ISR status is not a real 32-bit readback')
    status_fields = dma_status_fields(status)
    if status_fields['error'] != 1:
        raise RuntimeError('real DMA error status does not report the declared error bit')
    if status_fields['busy'] != 0:
        raise RuntimeError('real DMA status still reports busy after the error interrupt')
    control_bits = (program['control'] >> 28) & 0x3
    if ((status >> 28) & 0x3) != control_bits:
        raise RuntimeError('real DMA status inc bits differ from the written CONTROL word')
    if type(length_actual) is not int or not 0 <= length_actual <= 0xFFFFFFFF:
        raise RuntimeError('error ISR length read is not a real 32-bit value')
    if length_actual != case.length:
        raise RuntimeError('real DMA length after the read-phase error differs from the programmed length')

    def isr_store(address, value, name):
        matches = [event for event in witnesses.memory_writes
                   if event.get('component') == 'cpu' and event.get('address') == address
                   and event.get('value') == value]
        if len(matches) != 1:
            raise RuntimeError(f'ISR {name} store is missing or duplicated')
        return _event_id(matches[0].get('event_id'), f'ISR {name} store')

    mcause_store = isr_store(RESULT, DMA_IRQ_MCAUSE, 'mcause')
    status_store = isr_store(RESULT + 4, status, 'status')
    length_store = isr_store(RESULT + 8, length_actual, 'length')
    witness_stores = [event for event in witnesses.memory_writes
                      if event.get('component') == 'cpu'
                      and event.get('address') == WITNESS]
    isr_witness_store = _one(witness_stores, 'ISR witness store is missing or duplicated')
    witness_value = isr_witness_store.get('value')
    if type(witness_value) is not int or not 0 <= witness_value <= 0xFFFFFFFF:
        raise RuntimeError('ISR witness read is not a real 32-bit value')
    witness_store_id = _event_id(isr_witness_store.get('event_id'),
        'ISR witness store')
    counter_store = isr_store(COMPLETED, case_index, 'counter')
    status_key = status_delivery.get('source_transaction')
    _one([event for event in witnesses.data_responses
          if event.get('transaction') == status_key and event.get('rdata') == status],
        'DMA error status lacks a real native data response')
    status_load_id = _retire(witnesses.retires, ISR_PCS['isr_status'],
        mem_addr=DMA_BASE, rdata=status, rd=7)
    status_store_id = _retire(witnesses.retires, ISR_PCS['isr_status'] + 4,
        mem_addr=RESULT + 4, wdata=status, rs2=7)
    length_load_id = _retire(witnesses.retires, ISR_PCS['isr_length'],
        mem_addr=DMA_BASE + 4, rdata=length_actual, rd=8)
    length_store_id = _retire(witnesses.retires, ISR_PCS['isr_length'] + 4,
        mem_addr=RESULT + 8, wdata=length_actual, rs2=8)
    pointer_load_id = _retire(witnesses.retires, ISR_PCS['isr_witness_pointer'],
        mem_addr=WITNESS_POINTER, rdata=program['witness'], rd=9)
    witness_load_id = _retire(witnesses.retires, ISR_PCS['isr_witness'],
        mem_addr=program['witness'], rdata=witness_value, rd=9)
    witness_store_retire_id = _retire(witnesses.retires,
        ISR_PCS['isr_witness'] + 4, mem_addr=WITNESS,
        wdata=witness_value, rs2=9)
    counter_load_id = _retire(witnesses.retires, ISR_PCS['isr_counter_load'],
        mem_addr=COMPLETED, rdata=case_index - 1, rd=9)
    counter_store_retire_id = _retire(witnesses.retires,
        ISR_PCS['isr_counter_load'] + 8, mem_addr=COMPLETED,
        wdata=case_index, rs2=9)
    if not (take.get('event_id') < mcause_store
            < status_delivery.get('event_id') <= status_load_id < status_store_id
            < length_load_id < length_store_id < pointer_load_id < witness_load_id
            < witness_store_retire_id < counter_load_id < counter_store_retire_id):
        raise RuntimeError('native error status/length/witness/counter flow is out of order')
    if witness_pointer_store.get('event_id') >= request_id:
        raise RuntimeError('ISR witness pointer must be committed before the illegal start')

    fifo_pops = [dict(kind='cpu', **fifo) for fifo in cpu_fifo]
    depths = [pop['post_depth'] for pop in fifo_pops]
    transaction_summary = dict(
        testcase_id=key.get('testcase_id'),
        source_component=key.get('source_component'),
        source_epoch=key.get('source_epoch'),
        channel_id=key.get('channel_id'),
        source_sequence=key.get('source_sequence'))
    receipt_summary = dict(op=receipt['op'], error=receipt['error'],
        target_effect=receipt['target_effect'], address=receipt['address'],
        write=receipt['write'], value=receipt.get('value'),
        byte_enable=receipt['byte_enable'], reason=receipt['reason'],
        transaction=transaction_summary)
    error_summary = dict(request_event_id=request_id,
        response_event_id=response_id, receipt_event_id=request_id,
        address=program['source'], write=False,
        reason=receipt['reason'], target_effect=False,
        data_beats=0, destination_commits=0, fifo_dma_pops=0,
        no_target_delivery=True, destination_committed=False,
        status=status, status_bits=list(status_fields['bits']),
        status_error=status_fields['error'],
        status_busy=status_fields['busy'],
        status_nread=status_fields['nread'],
        status_blocklen_sub_one=status_fields['blocklen_sub_one'],
        status_inc_s_n=status_fields['inc_s_n'],
        status_inc_d_n=status_fields['inc_d_n'],
        length=length_actual, mcause=DMA_IRQ_MCAUSE, counter=case_index,
        witness=witness_value, witness_pointer=program['witness'])
    return dict(schema_version=CASE_SCHEMA, case_index=case_index,
        spec=case.to_document(), direction=case.direction,
        descriptor=dict(case.descriptor), source_bytes=list(case.source_bytes),
        action_ids=list(action_ids), frame_ids=list(frame_ids),
        program=dict(direction=program['direction'], source=program['source'],
            destination=program['destination'], length=program['length'],
            control=program['control'], witness=program['witness'],
            source_words=list(program['source_words']),
            destination_words=list(program['destination_words']),
            cpu_source_words=list(program['cpu_source_words']),
            attempted_source_words=list(program['attempted_source_words'])),
        outcome='environment_error', completed=False, sealed=True,
        error_path='declared_illegal_master_target',
        environment_error_receipt=receipt_summary,
        environment_error=error_summary,
        no_target_delivery=True, destination_committed=False,
        beats=[], beat_count=0, ram_commits=[],
        cpu_source_versions=[],
        cpu_pop_access_ids=[fifo['access_id'] for fifo in cpu_fifo],
        settled_cpu_access_ids=[event.get('access_id') for event in settled_pops],
        settled_dma_rdata_access_ids=[event.get('access_id')
                                      for event in late_dma_accesses],
        fifo=dict(pushes=len(witnesses.tick_pushes),
            push_depths=list(push_depths),
            push_chain=[dict(item) for item in push_chain],
            pops=fifo_pops, dma_pops=0,
            depth_after=(depths[-1] if depths else None),
            max_depth=(max(push_depths) if push_depths else 0)),
        isr=dict(mcause=DMA_IRQ_MCAUSE, status=status, length=length_actual,
            status_bits=list(status_fields['bits']),
            status_layout={name: list(bounds) for name, bounds
                           in DMA_STATUS_LAYOUT.items()},
            status_nread=status_fields['nread'],
            status_blocklen_sub_one=status_fields['blocklen_sub_one'],
            status_error=status_fields['error'],
            status_busy=status_fields['busy'],
            status_inc_s_n=status_fields['inc_s_n'],
            status_inc_d_n=status_fields['inc_d_n'],
            control_inc_s_n=(program['control'] >> 29) & 1,
            control_inc_d_n=(program['control'] >> 28) & 1,
            payload=None, witness=witness_value, counter=case_index,
            mcause_event_id=mcause_store, status_event_id=status_store,
            length_event_id=length_store, witness_event_id=witness_store_id,
            counter_event_id=counter_store),
        irq=dict(edge_event_id=error_edge.get('event_id'),
            edge_tick=error_edge.get('native_local_tick'), error=True,
            source_start_event_id=start.get('event_id'),
            source_tick=start.get('source_tick'),
            cpu_take_event_id=take.get('event_id'),
            external_event_id=external.get('event_id'),
            external_tick=external.get('local_tick')),
        tx_captures=[], tx_capture_count=0,
        fifo_origin='unknown', source_authority='incomplete',
        proof_grade='bounded_historical_chain')


def _settled_pop_access_ids(evidence):
    """Every real FIFO pop identity of one certified case (CPU and DMA).

    A routed CPU RDATA access can be journaled after its case was sealed, and a
    DMA-master UART pop has the same external ``uart_rdata_access`` shape.  The
    next case must be able to recognise either late copy, so the boot settles
    every ``fifo.pops[].access_id`` in addition to the CPU pop ids.  Ids are
    only collected when they are real nonempty strings; an unidentified pop is
    never guessed into the settled set.
    """
    if not isinstance(evidence, dict):
        raise ValueError('certified case evidence is required')
    ids = set(evidence.get('cpu_pop_access_ids') or ())
    fifo = evidence.get('fifo') or {}
    for pop in fifo.get('pops') or ():
        if isinstance(pop, dict):
            access_id = pop.get('access_id')
            if isinstance(access_id, str) and access_id:
                ids.add(access_id)
    return ids


def _attach_source_authority(evidence, witnesses, case, *, action_ids,
                             frame_ids, source_authority):
    """Join accepted UART FIFO proofs (S4) or keep the case explicitly unknown.

    The join input is this case's certified FIFO order: one admitted entry per
    serial byte and every real pop in FIFO order.  ``source_authority_evidence``
    only says ``accepted_uart_fifo_entry`` when the tracker's accepted retention
    and read-consumption rows agree exactly with those real rows; otherwise the
    case keeps ``unknown`` and names the missing element.  A contradictory
    accepted row raises instead of degrading to unknown.
    """
    if not isinstance(evidence, dict):
        raise ValueError('certified case evidence is required')
    authority = NOT_INSTALLED if source_authority is None else source_authority
    admissions = {row['action_id']: row for row in authority.get('admissions', ())
                  } if authority.get('installed') is True else {}
    entries = tuple(dict(index=index, action_id=action_ids[index],
        admission_id=(admissions[action_ids[index]].get('admission_id')
                      if action_ids[index] in admissions else None),
        frame_id=frame_ids[index], value=case.source_bytes[index])
        for index in range(case.source_count))
    pops = tuple((evidence.get('fifo') or {}).get('pops') or ())
    reads = []
    for index, pop in enumerate(pops):
        access_id = pop.get('access_id')
        read_value = pop.get('read_value')
        if (not isinstance(access_id, str) or not access_id
                or type(read_value) is not int):
            raise RuntimeError('a certified FIFO pop lacks a real access identity')
        kind = pop.get('kind')
        if kind not in ('cpu', 'dma'):
            raise RuntimeError('a certified FIFO pop has an unknown consumer')
        reads.append(dict(access_id=access_id, entry_index=index,
            value=read_value, route='dma_master' if kind == 'dma' else 'router'))
    if len(reads) > len(entries):
        raise RuntimeError('a case popped more FIFO entries than it admitted')
    document = source_authority_evidence(witnesses.rows, entries=entries,
        admissions=authority.get('admissions'), reads=tuple(reads),
        authority=authority)
    evidence.update(fifo_origin=document['fifo_origin'],
        source_authority=document['source_authority'],
        proof_grade=document['proof_grade'],
        source_authority_evidence=document)
    return evidence


def certify_descriptor_case(witnesses, case, *, case_index, tx_captures=(),
                            action_ids=None, settled_access_ids=None,
                            source_authority=None):
    """Join one real journal slice into a completed descriptor case.

    The expected program is derived from the declared case, never read back from
    firmware.  Every join below needs a real journal row; a missing frame, pop,
    master beat, RAM commit, IRQ take or ISR retirement fails the case.
    """
    if not isinstance(witnesses, CaseWitnesses):
        raise ValueError('CaseWitnesses is required')
    if not isinstance(case, DescriptorCase):
        raise ValueError('DescriptorCase is required')
    _positive_int(case_index, 'case_index', maximum=1 << 20)
    program = case.program()
    ids = case.action_ids(case_index) if action_ids is None else tuple(action_ids)
    if len(ids) != case.source_count or len(set(ids)) != len(ids):
        raise ValueError('case action ids must be unique and cover the serial stream')
    tx_captures = tuple(tx_captures)
    settled = (frozenset() if settled_access_ids is None
               else frozenset(settled_access_ids))
    if any(not isinstance(item, str) or not item for item in settled):
        raise ValueError('settled CPU access ids must be nonempty strings')
    accepted_ids = tuple(event.get('action_id') for event in witnesses.frames)
    if accepted_ids != ids:
        raise RuntimeError('case needs one matched native serial frame per descriptor/payload byte')
    frame_bytes = tuple(event.get('byte') for event in witnesses.frames)
    if frame_bytes != case.source_bytes:
        raise RuntimeError('native serial frames differ from the declared bytes')
    frame_ids = tuple(event.get('frame_id') for event in witnesses.frames)
    if len(set(frame_ids)) != len(frame_ids) or any(
            not isinstance(frame_id, str) or not frame_id for frame_id in frame_ids):
        raise RuntimeError('native serial frame identities are missing or duplicated')
    if len(witnesses.source_injections) != case.source_count:
        raise RuntimeError('source injection count differs from the serial stream')
    injected = tuple(event.get('value') for event in witnesses.source_injections)
    if injected != case.source_bytes:
        raise RuntimeError('source injection values differ from the declared bytes')
    _assert_no_host_writes(witnesses.memory_writes)

    # -- real UART FIFO accounting: 4 descriptor + len payload pushes/pops ----
    if len(witnesses.tick_pushes) != case.source_count:
        raise RuntimeError('case needs one real UART RX FIFO push per serial byte')
    push_chain = _push_depth_chain(witnesses.tick_observations,
        witnesses.tick_pushes, case.source_bytes)
    push_depths = tuple(item['depth_after'] for item in push_chain)
    if any(type(depth) is not int or depth < 1 for depth in push_depths):
        raise RuntimeError('UART RX FIFO push lacks a real post-push depth')
    # A routed CPU RDATA external event can be journaled after the case that
    # caused it was sealed, so its access_id may reappear at the start of the next
    # case.  The boot supplies every id already counted in an earlier case and
    # those late copies are excluded; the per-case count stays 4 / 4+len.
    def pop_access_id(event):
        access_id = event.get('access_id')
        if not isinstance(access_id, str) or not access_id:
            raise RuntimeError('CPU RDATA pop lacks a real access id')
        return access_id

    cpu_consumed = DESCRIPTOR_WORDS + (0 if case.direction == 'RX_TO_RAM' else case.length)
    settled_pops = tuple(event for event in witnesses.cpu_pops
                         if pop_access_id(event) in settled)
    cpu_pops = tuple(event for event in witnesses.cpu_pops
                     if pop_access_id(event) not in settled)
    if len(cpu_pops) != cpu_consumed:
        top_level = sum(1 for event in cpu_pops
                        if event.get('_pop_source') == 'top_level')
        raise RuntimeError('CPU must pop exactly the descriptor and drained payload '
            f'bytes ({cpu_consumed} pops; top_level={top_level}, '
            f'nested={len(cpu_pops) - top_level}, '
            f'settled={len(settled_pops)})')
    descriptor = case.source_bytes[:DESCRIPTOR_WORDS]
    drained = case.source_bytes[DESCRIPTOR_WORDS:]
    cpu_values = tuple(event.get('read_value') for event in cpu_pops)
    if cpu_values != descriptor + (drained if case.direction != 'RX_TO_RAM' else ()):
        raise RuntimeError('CPU RDATA pops differ from the decoded descriptor stream')
    cpu_fifo = tuple(_cpu_pop_fifo(event, value, 'descriptor')
                     for event, value in zip(cpu_pops, cpu_values))
    if any(fifo['pre_depth'] < 1 for fifo in cpu_fifo):
        raise RuntimeError('CPU RDATA pop observed an empty real FIFO')

    def delivery_access_id(delivery):
        nested = delivery.get('target_uart_access')
        return nested.get('access_id') if isinstance(nested, dict) else None

    deliveries = tuple(event for event in witnesses.uart_rdata_mmio
                       if delivery_access_id(event) not in settled)
    if tuple(event.get('read_value') for event in deliveries) != cpu_values:
        raise RuntimeError('routed CPU RDATA deliveries differ from the real pops')
    nonempty_status = [event for event in witnesses.uart_status_mmio
                       if type(event.get('read_value')) is int
                       and not event['read_value'] & UART_RXEMPTY_MASK]
    if not nonempty_status:
        raise RuntimeError('CPU never observed a real UART nonempty STATUS')
    if any(event.get('write') is not False for event in witnesses.uart_status_mmio):
        raise RuntimeError('UART STATUS delivery is not a read')
    first_pop = _event_id(cpu_pops[0].get('event_id'), 'CPU RDATA pop')
    if nonempty_status[0].get('event_id') >= first_pop:
        raise RuntimeError('CPU STATUS observation does not precede the real FIFO pop')

    # -- the CPU really wrote the decoded DMA program ------------------------
    dma_writes = [event for event in witnesses.dma_mmio if event.get('write') is True]
    expected_program = ((8, program['source']), (12, program['destination']),
                        (4, program['length']), (0, program['control']))
    actual_program = tuple((event.get('offset'), event.get('write_value'))
                           for event in dma_writes)
    if actual_program != expected_program:
        raise RuntimeError('CPU DMA register writes differ from the decoded descriptor program')
    control_event = dma_writes[-1]
    if (control_event.get('write_value') & CONTROL_KEY_MASK) != CONTROL_KEY << 16:
        raise RuntimeError('CPU CONTROL write lacks the wbdmac start key')
    witness_store = [event for event in witnesses.memory_writes
                     if event.get('component') == 'cpu'
                     and event.get('address') == WITNESS_POINTER]
    _one(witness_store, 'CPU must commit exactly one ISR witness pointer')
    if witness_store[0].get('value') != program['witness']:
        raise RuntimeError('ISR witness pointer differs from the declared program')
    if witness_store[0].get('event_id') >= control_event.get('event_id'):
        raise RuntimeError('witness pointer must be committed before the DMA start')

    if case.expect == 'environment_error':
        evidence = _certify_environment_error(witnesses, case,
            case_index=case_index, program=program, action_ids=ids,
            frame_ids=frame_ids, push_chain=push_chain, push_depths=push_depths,
            cpu_pops=cpu_pops, cpu_fifo=cpu_fifo, cpu_values=cpu_values,
            settled_pops=settled_pops, settled=settled,
            witness_pointer_store=witness_store[0], tx_captures=tx_captures)
        return _attach_source_authority(evidence, witnesses, case,
            action_ids=ids, frame_ids=frame_ids,
            source_authority=source_authority)

    # -- real master beats: read then write for every declared word ----------
    if len(witnesses.beats) != 2 * case.length:
        raise RuntimeError('case needs two real master beats per transferred word')
    beat_rows = []
    sequences = []
    for index in range(case.length):
        read_row = witnesses.beats[2 * index]
        write_row = witnesses.beats[2 * index + 1]
        read = read_row['accepted']
        write = write_row['accepted']
        if read.get('write') is not False or write.get('write') is not True:
            raise RuntimeError('DMA beat order must be one read then one write per word')
        if (read.get('address') != program['source_words'][index]
                or write.get('address') != program['destination_words'][index]):
            raise RuntimeError('DMA beat address differs from the decoded program')
        read_key = read.get('transaction') or {}
        write_key = write.get('transaction') or {}
        if (read_key.get('channel_id') != 'dma-memory'
                or read_key.get('source_component') != 'dma'
                or any(read_key.get(field) != write_key.get(field)
                       for field in ('execution_id', 'testcase_id', 'source_component',
                                     'source_epoch', 'channel_id'))
                or write_key.get('source_sequence') != read_key.get('source_sequence') + 1):
            raise RuntimeError('DMA read/write beats are not adjacent master transactions')
        sequences.extend((read_key['source_sequence'], write_key['source_sequence']))
        if case.direction == 'RX_TO_RAM':
            fifo = _read_beat_fifo(read_row, case.payload, 'FIFO')
            read_data = case.payload
        else:
            if isinstance(read.get('target_delivery'), dict):
                raise RuntimeError('a RAM-sourced DMA read must not touch the UART target')
            responses = [event['response'] for event in witnesses.responses
                         if (event['response'].get('transaction') or {}).get(
                             'source_sequence') == read_key.get('source_sequence')]
            response = _one(responses, 'RAM-sourced DMA read lacks exactly one response')
            read_data = response.get('rdata')
            if read_data != case.payload:
                raise RuntimeError('DMA RAM read data differs from the declared payload')
            fifo = None
        if case.direction == 'RAM_TO_TX':
            delivery = write.get('target_delivery')
            if (not isinstance(delivery, dict)
                    or delivery.get('write') is not True
                    or delivery.get('address') != UART_WDATA
                    or delivery.get('value') != case.payload):
                raise RuntimeError('DMA UART WDATA write lacks a real target delivery')
        else:
            if write.get('value') != case.payload:
                raise RuntimeError('DMA RAM write value differs from the declared payload')
        beat_rows.append(dict(index=index, source_address=read.get('address'),
            destination_address=write.get('address'), value=case.payload,
            read_data=read_data, read_event_id=_event_id(read_row.get('event_id'),
                'DMA read beat'), write_event_id=_event_id(write_row.get('event_id'),
                'DMA write beat'),
            source_sequence=read_key.get('source_sequence'),
            write_sequence=write_key.get('source_sequence'), fifo=fifo))
    if sequences != list(range(sequences[0], sequences[0] + len(sequences))) \
            or len(set(sequences)) != len(sequences):
        raise RuntimeError('DMA master transactions were repeated or reordered')

    # -- real RAM destination commits and versions ---------------------------
    ram_writes = [event for event in witnesses.memory_writes
                  if event.get('component') == 'dma'
                  and event.get('address') in program['destination_words']]
    if case.direction == 'RAM_TO_TX':
        if ram_writes:
            raise RuntimeError('RAM_TO_TX must not commit an undeclared RAM destination')
        ram_commits = ()
    else:
        if len(ram_writes) != case.length:
            raise RuntimeError('case needs one real DMA RAM commit per transferred word')
        ram_commits = tuple(dict(address=event.get('address'), value=event.get('value'),
            version=list(event.get('version') or ()),
            event_id=_event_id(event.get('event_id'), 'DMA RAM commit'))
            for event in ram_writes)
        if tuple(commit['address'] for commit in ram_commits) != program['destination_words']:
            raise RuntimeError('DMA RAM commits differ from the decoded destination words')
        if any(commit['value'] != case.payload for commit in ram_commits):
            raise RuntimeError('DMA RAM commit value differs from the declared payload')
        versions = [commit['version'] for commit in ram_commits]
        if any(not version or type(version[-1]) is not int for version in versions):
            raise RuntimeError('DMA RAM commits lack real memory versions')
        if any(versions[index][-1] >= versions[index + 1][-1]
               for index in range(len(versions) - 1)):
            raise RuntimeError('DMA RAM commit versions are not strictly increasing')
        for index, commit in enumerate(ram_commits):
            # The real journal orders one transferred word as
            # read beat -> memory commit -> write beat (the memory service
            # commits before the master edge event is appended), so the commit
            # is anchored inside its own read interval: after its read beat and
            # before the next word's read beat.  For the last word the IRQ
            # ordering below closes the interval.
            next_read = (beat_rows[index + 1]['read_event_id']
                         if index + 1 < len(beat_rows) else None)
            if not (beat_rows[index]['read_event_id'] < commit['event_id']
                    and (next_read is None or commit['event_id'] < next_read)):
                raise RuntimeError(
                    'DMA RAM commit is not inside its accepted read beat interval')

    # -- CPU materializes the RAM source words before the DMA reads them -----
    cpu_source_writes = [event for event in witnesses.memory_writes
                         if event.get('component') == 'cpu'
                         and event.get('address') in program['cpu_source_words']]
    if case.direction == 'RX_TO_RAM':
        if cpu_source_writes:
            raise RuntimeError('RX_TO_RAM must not write a RAM source word')
        cpu_source_versions = ()
    else:
        if len(cpu_source_writes) != case.length:
            raise RuntimeError('CPU must write one real RAM source word per transferred word')
        if tuple(event.get('address') for event in cpu_source_writes) != \
                program['cpu_source_words']:
            raise RuntimeError('CPU RAM source words differ from the declared program')
        if any(event.get('value') != case.payload for event in cpu_source_writes):
            raise RuntimeError('CPU RAM source word differs from the declared payload')
        cpu_source_versions = tuple(list(event.get('version') or ())
                                    for event in cpu_source_writes)
        if any(event.get('event_id') >= beat_rows[0]['read_event_id']
               for event in cpu_source_writes):
            raise RuntimeError('CPU RAM source words were not committed before the DMA read')

    # -- native IRQ, bound CPU take and the real ISR -------------------------
    irq_edge = _one(witnesses.irq_edges, 'case needs one real DMA completion IRQ edge')
    start = _one(witnesses.bound_starts, 'case needs one bound DMA IRQ source start')
    take = _one(witnesses.bound_takes, 'case needs one bound CPU IRQ take')
    external = _one(witnesses.external_irq, 'case needs one real external IRQ take')
    if (start.get('source_event_id') != take.get('source_event_id')
            or take.get('cpu_tick') != external.get('local_tick')
            or start.get('source_tick') != irq_edge.get('native_local_tick')):
        raise RuntimeError('CPU native take is not joined to the real DMA pulse tick')
    # Real journal order: DMA completion pulse -> bound source window start ->
    # real CPU external take -> bound CPU take.  The source window opens before
    # the CPU samples the external interrupt, so source_start precedes external.
    last_write = (ram_commits[-1]['event_id'] if ram_commits
                  else beat_rows[-1]['write_event_id'])
    if not (last_write < irq_edge.get('event_id') < start.get('event_id')
            < external.get('event_id') < take.get('event_id')):
        raise RuntimeError('DMA completion/IRQ/CPU take order is incomplete')

    def isr_store(address, value, name):
        matches = [event for event in witnesses.memory_writes
                   if event.get('component') == 'cpu' and event.get('address') == address
                   and event.get('value') == value]
        if len(matches) != 1:
            raise RuntimeError(f'ISR {name} store is missing or duplicated')
        return _event_id(matches[0].get('event_id'), f'ISR {name} store')

    mcause_store = isr_store(RESULT, DMA_IRQ_MCAUSE, 'mcause')
    status_delivery = _one([event for event in witnesses.dma_mmio
        if event.get('write') is False and event.get('offset') == 0],
        'ISR status store lacks a real DMA status MMIO delivery')
    length_delivery = _one([event for event in witnesses.dma_mmio
        if event.get('write') is False and event.get('offset') == 4],
        'ISR length store lacks a real DMA length MMIO delivery')
    status = status_delivery.get('read_value')
    length_actual = length_delivery.get('read_value')
    for name, value in (('status', status), ('length', length_actual)):
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise RuntimeError(f'ISR {name} read is not a real 32-bit value')
    if status & (1 << 30):
        raise RuntimeError('a complete case read the real DMA error status bit')
    # wbdmac composes status bit29/bit28 from !cfg_incs/!cfg_incd, i.e. the
    # inc_s_n/inc_d_n bits of the last CONTROL write.  The ISR readback must
    # therefore show the direction mode the CPU really programmed.
    control_bits = (program['control'] >> 28) & 0x3
    status_bits = (status >> 28) & 0x3
    if status_bits != control_bits:
        raise RuntimeError('real DMA status inc bits differ from the written CONTROL word')
    status_store = isr_store(RESULT + 4, status, 'status')
    length_store = isr_store(RESULT + 8, length_actual, 'length')
    payload_store = isr_store(WITNESS, case.payload, 'payload')
    counter_store = isr_store(COMPLETED, case_index, 'counter')
    status_key = status_delivery.get('source_transaction')
    responses = [event for event in witnesses.data_responses
                 if event.get('transaction') == status_key
                 and event.get('rdata') == status]
    _one(responses, 'DMA status lacks a real native data response')
    status_load_id = _retire(witnesses.retires, ISR_PCS['isr_status'],
        mem_addr=DMA_BASE, rdata=status, rd=7)
    status_store_id = _retire(witnesses.retires, ISR_PCS['isr_status'] + 4,
        mem_addr=RESULT + 4, wdata=status, rs2=7)
    length_load_id = _retire(witnesses.retires, ISR_PCS['isr_length'],
        mem_addr=DMA_BASE + 4, rdata=length_actual, rd=8)
    length_store_id = _retire(witnesses.retires, ISR_PCS['isr_length'] + 4,
        mem_addr=RESULT + 8, wdata=length_actual, rs2=8)
    pointer_load_id = _retire(witnesses.retires, ISR_PCS['isr_witness_pointer'],
        mem_addr=WITNESS_POINTER, rdata=program['witness'], rd=9)
    witness_load_id = _retire(witnesses.retires, ISR_PCS['isr_witness'],
        mem_addr=program['witness'], rdata=case.payload, rd=9)
    payload_store_id = _retire(witnesses.retires, ISR_PCS['isr_witness'] + 4,
        mem_addr=WITNESS, wdata=case.payload, rs2=9)
    counter_load_id = _retire(witnesses.retires, ISR_PCS['isr_counter_load'],
        mem_addr=COMPLETED, rdata=case_index - 1, rd=9)
    counter_store_id = _retire(witnesses.retires, ISR_PCS['isr_counter_load'] + 8,
        mem_addr=COMPLETED, wdata=case_index, rs2=9)
    if not (mcause_store < status_delivery.get('event_id') <= status_load_id
            < status_store_id < length_load_id < length_store_id
            < pointer_load_id < witness_load_id < payload_store_id
            < counter_load_id < counter_store_id):
        raise RuntimeError('native DMA status/length/witness/counter flow is out of order')
    if not take.get('event_id') < mcause_store:
        raise RuntimeError('CPU IRQ take must precede the real ISR stores')

    # -- TX serial capture is a real UART pin observation --------------------
    if case.direction == 'RAM_TO_TX':
        if tx_captures != (case.payload,) * case.length:
            raise RuntimeError('UART TX serial capture differs from the declared payload')
    elif tx_captures:
        raise RuntimeError('a non-TX case must not transmit on the UART serial pin')

    if witnesses.rejections or witnesses.environment_errors \
            or witnesses.error_responses:
        raise RuntimeError('a complete case must not contain an environment error')
    fifo_pops = [dict(kind='cpu', **fifo) for fifo in cpu_fifo]
    if case.direction == 'RX_TO_RAM':
        fifo_pops.extend(dict(kind='dma', source='dma-master', **beat['fifo'])
                         for beat in beat_rows)
    depths = [pop['post_depth'] for pop in fifo_pops]
    status_fields = dma_status_fields(status)
    return dict(schema_version=CASE_SCHEMA, case_index=case_index,
        spec=case.to_document(), direction=case.direction,
        descriptor=dict(case.descriptor), source_bytes=list(case.source_bytes),
        action_ids=list(ids), frame_ids=list(frame_ids),
        program=dict(direction=program['direction'], source=program['source'],
            destination=program['destination'], length=program['length'],
            control=program['control'], witness=program['witness'],
            source_words=list(program['source_words']),
            destination_words=list(program['destination_words']),
            cpu_source_words=list(program['cpu_source_words'])),
        beats=beat_rows, beat_count=2 * len(beat_rows),
        ram_commits=list(ram_commits),
        cpu_source_versions=[list(version) for version in cpu_source_versions],
        cpu_pop_access_ids=[fifo['access_id'] for fifo in cpu_fifo],
        settled_cpu_access_ids=[pop_access_id(event) for event in settled_pops],
        fifo=dict(pushes=len(witnesses.tick_pushes),
            push_depths=list(push_depths), push_chain=[dict(item)
                for item in push_chain], pops=fifo_pops,
            depth_after=(depths[-1] if depths else None),
            max_depth=(max(push_depths) if push_depths else 0)),
        isr=dict(mcause=DMA_IRQ_MCAUSE, status=status, length=length_actual,
            status_bits=list(status_fields['bits']),
            status_layout={name: list(bounds) for name, bounds
                           in DMA_STATUS_LAYOUT.items()},
            status_nread=status_fields['nread'],
            status_blocklen_sub_one=status_fields['blocklen_sub_one'],
            status_error=status_fields['error'],
            status_busy=status_fields['busy'],
            status_inc_s_n=status_fields['inc_s_n'],
            status_inc_d_n=status_fields['inc_d_n'],
            control_inc_s_n=(program['control'] >> 29) & 1,
            control_inc_d_n=(program['control'] >> 28) & 1,
            payload=case.payload,
            counter=case_index, mcause_event_id=mcause_store,
            status_event_id=status_store, length_event_id=length_store,
            payload_event_id=payload_store, counter_event_id=counter_store),
        irq=dict(edge_event_id=irq_edge.get('event_id'),
            edge_tick=irq_edge.get('native_local_tick'),
            source_start_event_id=start.get('event_id'),
            source_tick=start.get('source_tick'),
            cpu_take_event_id=take.get('event_id'),
            external_event_id=external.get('event_id'),
            external_tick=external.get('local_tick')),
        tx_captures=list(tx_captures), tx_capture_count=len(tx_captures),
        outcome='complete', completed=True, sealed=True,
        fifo_origin='unknown', source_authority='incomplete',
        proof_grade='bounded_historical_chain')
    return _attach_source_authority(evidence, witnesses, case,
        action_ids=ids, frame_ids=frame_ids, source_authority=source_authority)


# ---------------------------------------------------------------------------
# One supplied boot executing successive descriptor cases
# ---------------------------------------------------------------------------
def _source_ticks_bound(case):
    return SOURCE_TICKS_PER_BYTE * case.source_count + SOURCE_TICKS_PER_BYTE


def _tx_drain_bound(case):
    return UART_TX_FRAME_TICKS * case.length + TX_DRAIN_MARGIN_TICKS


class DescriptorBoot:
    """One native boot that executes successive bounded descriptor cases.

    No method starts native RTL by itself.  A rejected case raises before any
    source command or advance is recorded, so it consumes no RTL.
    """

    def __init__(self, runner: ScenarioRunner, *, budget: ResourceBudget,
                 template: ScenarioGenome, source_pins: dict,
                 source_provenance: DmaSourceProvenance | None = None) -> None:
        if not isinstance(budget, ResourceBudget):
            raise ValueError('ResourceBudget is required')
        if not isinstance(template, ScenarioGenome):
            raise ValueError('ScenarioGenome template is required')
        if not isinstance(source_pins, dict) or not source_pins:
            raise ValueError('host source pins are required')
        if source_provenance is not None and not isinstance(
                source_provenance, DmaSourceProvenance):
            raise ValueError('source provenance must be installed provenance')
        if source_provenance is not None and not getattr(
                runner, 'provenance_enabled', False):
            raise ValueError('installed source provenance requires configured runner provenance')
        self.runner = runner
        self.budget = budget
        self.template = template
        self.source_pins = dict(source_pins)
        self.source_provenance = source_provenance
        self.recorder = ScenarioBatchRecorder(template, runner)
        self.cases: list[dict] = []
        self.phase = 'boot'
        self.case_index = 0
        self.case_start = 0
        self.case_failure: dict | None = None
        self.booted = False
        # CPU routed access ids already counted in an earlier case.  A late
        # top-level uart_rdata_access can land in the next case slice with the
        # same access id, so cross-case dedupe is required.
        self.settled_access_ids: set[str] = set()

    def boot(self) -> None:
        """Wait for the real CPU UART CTRL request before the first waveform."""
        self.recorder.begin()
        self.booted = True
        router = self.runner.sessions['cpu'].router
        for _ in range(512):
            self.recorder.advance(('dma', 'cpu'))
            if 'uart' in router.ready_targets:
                return
        raise RuntimeError('CPU UART initialization exceeded boot bound')

    def run_case(self, case, *, case_index, max_source_ticks=None,
                 max_rounds_per_case=4096, windows=None) -> dict:
        if not self.booted or self.recorder._finished:
            raise RuntimeError('descriptor boot is not active')
        if not isinstance(case, DescriptorCase):
            raise DescriptorCaseRejected('DescriptorCase is required')
        # Every refusal below happens before the first command is recorded.
        case.validate(windows)
        _positive_int(case_index, 'case index', maximum=1 << 20)
        _positive_int(max_rounds_per_case, 'max_rounds_per_case', maximum=8192)
        bound = _source_ticks_bound(case) if max_source_ticks is None else max_source_ticks
        _positive_int(bound, 'max_source_ticks', maximum=1 << 16)
        self.phase, self.case_index = 'source', case_index
        start = self.case_start = self.runner.event_count
        command_start = len(self.recorder.commands)
        ticks_before = dict(self.runner.local_ticks)
        execution_ids = _execution_ids(self.runner)
        action_ids = tuple(f'{ACTION_PREFIX}-{case_index}-{slot}'
                           for slot in range(case.source_count))
        try:
            return self._execute_case(case, case_index, action_ids, start,
                command_start, ticks_before, execution_ids,
                max_source_ticks=bound, max_rounds_per_case=max_rounds_per_case)
        except Exception as exc:
            self.case_failure = self._failure_boundaries(action_ids[0],
                command_start, start, ticks_before, execution_ids)
            raise exc

    def _execute_case(self, case, case_index, action_ids, start, command_start,
                      ticks_before, execution_ids, *, max_source_ticks,
                      max_rounds_per_case):
        runner, recorder = self.runner, self.recorder
        uart = runner.sessions['uart']
        tx_before = len(uart.peer.captured)
        # S4: the external serial bytes are admitted before the first source
        # command.  Registration order is the declared serial order, so a fresh
        # replay that recomputes the same admissions reproduces this prefix.
        admissions = ()
        if self.source_provenance is not None:
            admissions = register_case_admissions(runner,
                self.source_provenance,
                case_id=f'{CASE_ID_PREFIX}{case_index}',
                case_index=case_index, action_ids=action_ids,
                source_bytes=case.source_bytes)
        source_authority = None
        if self.source_provenance is not None:
            source_authority = dict(self.source_provenance.document(),
                admissions=[admission.document() for admission in admissions])
        for action_id, byte in zip(action_ids, case.source_bytes):
            recorder.submit_source_event(BatchSourceEvent(action_id,
                SOURCE_COMPONENT, SOURCE_PORT, byte, width=8))
        wanted = set(action_ids)
        # During the waveform only UART advances: the native TLUL adapter forbids
        # register access overlapping a serial frame.
        for _ in range(max_source_ticks):
            recorder.advance(('uart',))
            ended = {event.get('action_id') for event in uart.source_events
                     if event.get('kind') == 'uart_source_frame_end'
                     and event.get('waveform_matched') and event.get('action_id') in wanted}
            if len(ended) == len(wanted) and uart.register_access_conflict() is None:
                break
        else:
            raise RuntimeError('native serial descriptor frames exceeded source bound')
        self.phase = 'isr'
        poll_cursor = runner.event_count
        for _ in range(max_rounds_per_case):
            recorder.advance(_poll_schedule(runner))
            new_rows = runner.events_since(poll_cursor)
            poll_cursor = runner.event_count
            commits = [event for event in new_rows
                       if event.get('kind') == 'memory_write'
                       and event.get('component') == 'cpu'
                       and event.get('address') == COMPLETED]
            if commits:
                if len(commits) != 1 or commits[0].get('value') != case_index:
                    raise RuntimeError('CPU completed-case counter is not monotonic')
                break
        else:
            raise RuntimeError('CPU ISR completion exceeded per-case bound')
        # The COMPLETED store becomes visible in the journal before the CPU
        # retires it, so the case slice would otherwise end before the ISR store
        # retirement (and MRET).  Continue bounded poll rounds until the real
        # store retirement is journaled; also capture MRET and the return to the
        # main loop when they appear.  A wrong or duplicate COMPLETED store is
        # still a hard failure.
        store_pc = ISR_PCS['isr_counter_load'] + 8
        mret_pc = ISR_PCS['isr_counter_load'] + 12

        def retirement_pcs(rows):
            return {row.get('pc_rdata') for row in rows
                    if row.get('kind') == 'cpu_retire'}

        pcs = retirement_pcs(new_rows)
        saw_store = store_pc in pcs
        saw_mret = mret_pc in pcs
        saw_return = any(MAIN <= pc < ISR_PCS['isr'] for pc in pcs)
        for _ in range(COMPLETION_ROUNDS):
            if saw_store and saw_mret and saw_return:
                break
            recorder.advance(_poll_schedule(runner))
            batch = runner.events_since(poll_cursor)
            poll_cursor = runner.event_count
            commits = [event for event in batch
                       if event.get('kind') == 'memory_write'
                       and event.get('component') == 'cpu'
                       and event.get('address') == COMPLETED]
            if commits:
                if len(commits) != 1 or commits[0].get('value') != case_index:
                    raise RuntimeError('CPU completed-case counter is not monotonic')
            pcs = retirement_pcs(batch)
            saw_store = saw_store or store_pc in pcs
            saw_mret = saw_mret or mret_pc in pcs
            saw_return = saw_return or any(MAIN <= pc < ISR_PCS['isr'] for pc in pcs)
        if not saw_store:
            raise RuntimeError('CPU ISR counter store retirement is missing after COMPLETED')
        self.phase = 'isr_return'
        # RAM_TO_TX: the CPU COMPLETED store only signals DMA/ISR completion.
        # Keep advancing UART alone until the serial pin really captured len bytes.
        if case.direction == 'RAM_TO_TX':
            for _ in range(_tx_drain_bound(case)):
                recorder.advance(('uart',))
                if len(uart.peer.captured) - tx_before >= case.length:
                    break
            else:
                raise RuntimeError('UART TX serial capture exceeded per-case bound')
        self.phase = 'case_check'
        captures = tuple(uart.peer.captured[tx_before:])
        rows = runner.events_since(start)
        certification = dict(case_index=case_index, tx_captures=captures,
            action_ids=action_ids,
            settled_access_ids=self.settled_access_ids)
        if source_authority is not None:
            certification['source_authority'] = source_authority
        evidence = certify_descriptor_case(extract_case_witnesses(rows),
            case, **certification)
        self.settled_access_ids.update(_settled_pop_access_ids(evidence))
        evidence.update(_case_boundaries(commands=recorder.commands, rows=rows,
            command_start=command_start, command_end=len(recorder.commands),
            event_start=start, event_end=runner.event_count,
            ticks_before=ticks_before, ticks_after=dict(runner.local_ticks),
            execution_ids=execution_ids))
        evidence.update(source_start_command=command_start,
            source_end_command=len(recorder.commands),
            source_count=case.source_count)
        return evidence

    def _failure_boundaries(self, action_id, command_start, event_start,
                            ticks_before, execution_ids):
        failure = dict(action_id=action_id, phase=self.phase, complete=False,
            command_start=command_start, command_end=len(self.recorder.commands),
            event_start=event_start, event_end=self.runner.event_count,
            ticks_before=dict(ticks_before),
            ticks_after=dict(self.runner.local_ticks),
            prefix_sha256=None, fifo_depth_after=None)
        try:
            rows = self.runner.events_since(event_start)
            from .dma_uart_rx_runtime import _prefix_digest
            failure['prefix_sha256'] = _prefix_digest(
                self.recorder.commands[command_start:], rows,
                ticks_before, failure['ticks_after'], execution_ids)
            failure['fifo_depth_after'] = _fifo_depth_after(rows)
        except Exception:
            pass
        return failure

    def finish(self, *, phase='complete', case_index=None, error=None):
        captured = _capture(self.recorder, self.runner, self.cases, self.budget,
            phase, self.case_index if case_index is None else case_index,
            error, self.source_pins)
        return DescriptorResult(captured.plan, captured.trace, captured.cases,
            captured.identities, captured.execution_ids, captured.budget,
            captured.phase, captured.case_index, captured.error, captured.events,
            captured.local_ticks, captured.uncertain_status, captured.source_pins)

    def close(self) -> None:
        if not self.recorder._finished:
            _close(self.runner)


@dataclass(frozen=True)
class DescriptorResult:
    """Portable S2 diagnostic bundle; serialized claims convey no authority."""

    plan: ScenarioBatchPlan
    trace: object | None
    cases: tuple[dict, ...]
    identities: dict
    execution_ids: dict
    budget: ResourceBudget
    phase: str
    case_index: int
    error: dict | None
    events: tuple[dict, ...]
    local_ticks: dict
    uncertain_status: dict
    source_pins: dict

    def to_document(self):
        from dataclasses import asdict
        return dict(schema_version=DIAGNOSTIC_SCHEMA,
            plan=json.loads(ScenarioBatchCodec.encode(self.plan)),
            trace=asdict(self.trace) if self.trace is not None else None,
            cases=self.cases, identities=self.identities,
            execution_ids=self.execution_ids, budget=self.budget.to_document(),
            phase=self.phase, case_index=self.case_index, error=self.error,
            events=self.events, local_ticks=self.local_ticks,
            uncertain_status=self.uncertain_status, source_pins=self.source_pins)

    def save_bundle(self, path: Path):
        Path(path).write_text(json.dumps(self.to_document(), sort_keys=True,
            allow_nan=False), encoding='utf-8')

    @classmethod
    def load_bundle(cls, path: Path):
        return cls.from_document(json.loads(Path(path).read_text(encoding='utf-8')))

    @classmethod
    def from_document(cls, document):
        from myfuzz.scenario.replay import ScenarioTrace
        if document.get('schema_version') != DIAGNOSTIC_SCHEMA:
            raise ValueError('unsupported descriptor DMA diagnostic bundle')
        trace = (ScenarioTrace(**document['trace'])
                 if document['trace'] is not None else None)
        return cls(ScenarioBatchCodec.decode(
                json.dumps(document['plan']).encode()), trace,
            tuple(document['cases']), document['identities'],
            document['execution_ids'],
            ResourceBudget.from_document(document['budget']), document['phase'],
            document['case_index'], document['error'], tuple(document['events']),
            document['local_ticks'], document['uncertain_status'],
            document['source_pins'])


def _template(cases, *, max_rounds_per_case):
    steps = 3 * 512
    for case in cases:
        steps += (_source_ticks_bound(case)
                  + 3 * (max_rounds_per_case + COMPLETION_ROUNDS))
        if case.direction == 'RAM_TO_TX':
            steps += _tx_drain_bound(case)
    return ScenarioGenome('descriptor-dma-three-directions', 'IP_TO_CPU',
        'uart-descriptor-dma-ram-tx-cpu-isr', ('dma', 'cpu', 'uart'), steps, ())


def _validate_specs(cases, windows=None):
    specs = tuple(cases)
    if not 1 <= len(specs) <= 16:
        raise ValueError('descriptor boot executes 1..16 cases')
    for index, case in enumerate(specs, 1):
        if not isinstance(case, DescriptorCase):
            raise DescriptorCaseRejected(f'case {index} is not a DescriptorCase')
        case.validate(windows)
    identities = [case.identity('0' * 64) for case in specs]
    if len(set(identities)) != len(identities):
        raise DescriptorCaseRejected('declared cases must be distinct inputs')
    return specs


@host_source_discovery_scope()
def run_descriptor_cases(cases, *, cache_dir: Path,
        budget: ResourceBudget | None = None,
        factory: Callable[[], ScenarioRunner] | None = None,
        max_rounds_per_case: int = 4096,
        windows: Mapping[str, tuple[int, int]] | None = None,
        provenance: bool = True) -> DescriptorResult:
    """Execute all cases in one boot; every refusal precedes any RTL command.

    ``provenance`` installs the declared S4 UART-FIFO source graph and
    admissions on the fresh Runner *before* the first RTL command.  It is on by
    default because a descriptor run without it can never claim source
    authority; disabling it is a diagnostic mode that keeps every case
    ``unknown``.
    """
    if type(provenance) is not bool:
        raise ValueError('provenance must be boolean')
    specs = _validate_specs(cases, windows)
    _positive_int(max_rounds_per_case, 'max_rounds_per_case', maximum=8192)
    source_pins = _source_pins()
    runner = factory() if factory else make_descriptor_runner(cache_dir=cache_dir)
    selected_budget = budget or ResourceBudget(max_wall_time_ms=600000)
    runner.set_resource_budget(selected_budget)
    source_provenance = (compile_dma_source_provenance(runner)
                         if provenance else None)
    template = _template(specs, max_rounds_per_case=max_rounds_per_case)
    boot = DescriptorBoot(runner, budget=selected_budget, template=template,
        source_pins=source_pins, source_provenance=source_provenance)
    try:
        boot.boot()
        for index, spec in enumerate(specs, 1):
            boot.cases.append(boot.run_case(spec, case_index=index,
                max_rounds_per_case=max_rounds_per_case, windows=windows))
        result = boot.finish()
        assert_plan_matches_cases(result.plan, specs)
        for case, spec in zip(result.cases, specs):
            if case.get('outcome') != spec.expect or case.get('sealed') is not True:
                raise RuntimeError(
                    'certified case outcome differs from the declared expectation')
        if (result.error is not None or result.trace is None
                or result.trace.status != 'complete'
                or result.uncertain_status['source_drift']):
            raise DescriptorFailure(result)
        return result
    except DescriptorFailure:
        raise
    except Exception as exc:
        diagnostic = dict(type=type(exc).__name__, message=str(exc),
            command_count=len(boot.recorder.commands), case_start=boot.case_start,
            max_rounds_per_case=max_rounds_per_case,
            requested_cases=[spec.to_document() for spec in specs])
        result = boot.finish(phase=boot.phase, case_index=boot.case_index,
            error=diagnostic)
        raise DescriptorFailure(result) from exc
    finally:
        boot.close()


@host_source_discovery_scope()
def replay_descriptor_cases(reference: DescriptorResult, *, cache_dir: Path,
        budget: ResourceBudget | None = None,
        factory: Callable[[], ScenarioRunner] | None = None) -> DescriptorResult:
    """Fresh reconstruction of the complete recorded command prefix.

    The replay must reproduce the plan, identities, native events, ticks, uncertain
    state and every per-case certificate; any divergence is a hard error.
    """
    return _replay_descriptor_cases(reference, cache_dir=cache_dir,
        budget=budget, factory=factory)


def _source_runs(commands):
    """Maximal contiguous runs of source events: one run per executed case.

    The boot registers every admission of a case immediately before its first
    source command, so a run boundary is exactly an admission-registration
    boundary.  Reconstructing runs (instead of trusting saved case claims) also
    covers a failed case that has no certificate.
    """
    runs, current = [], None
    for index, command in enumerate(commands):
        if isinstance(command, BatchSourceEvent):
            if current is None:
                current = (index, [])
                runs.append(current)
            current[1].append(command)
        else:
            current = None
    return tuple((start, tuple(items)) for start, items in runs)


def _reference_had_provenance(reference):
    """Whether the recorded run installed the S4 source graph (mirror exactly)."""
    for case in reference.cases:
        evidence = case.get('source_authority_evidence')
        if (isinstance(evidence, dict)
                and isinstance(evidence.get('authority'), dict)
                and evidence['authority'].get('installed') is True):
            return True
    return False


def _replay_descriptor_cases(reference, *, cache_dir, budget=None, factory=None):
    if not isinstance(reference, DescriptorResult):
        raise ValueError('DescriptorResult is required')
    if _source_pins() != reference.source_pins:
        raise ValueError('descriptor host source pins differ')
    if budget is not None and budget != reference.budget:
        raise ValueError('replay budget must equal the recorded original budget')
    specs = tuple(DescriptorCase.from_document(case['spec'])
                  for case in reference.cases)
    _validate_specs(specs)
    assert_plan_matches_cases(reference.plan, specs)
    install_provenance = _reference_had_provenance(reference)
    runner = factory() if factory else make_descriptor_runner(cache_dir=cache_dir)
    runner.set_resource_budget(reference.budget)
    source_provenance = (compile_dma_source_provenance(runner)
                         if install_provenance else None)
    if reference.trace is not None:
        from myfuzz.scenario.replay import _install_batch_wall_cut
        _install_batch_wall_cut(runner, reference.trace)
    recorder = ScenarioBatchRecorder(reference.plan.template, runner)
    runs = _source_runs(reference.plan.commands)
    run_starts = {start: items for start, items in runs}
    run_ordinals = {start: ordinal for ordinal, (start, _) in enumerate(runs, 1)}
    case_admissions: dict[int, tuple] = {}
    caught = None
    command_count = 0
    source_starts: dict[int, tuple[int, dict]] = {}
    end_events = end_ticks = None
    try:
        try:
            recorder.begin()
            identities = {name: session.identity_document()
                          for name, session in runner.sessions.items()}
            execution_ids = _execution_ids(runner)
            if identities != reference.identities:
                raise ValueError('fresh native identity documents differ')
            if execution_ids == reference.execution_ids:
                raise ValueError('replay requires fresh native processes and Runner')
            for index, command in enumerate(reference.plan.commands):
                if index in run_starts:
                    # Capture the case boundary before the admissions, exactly
                    # like DescriptorBoot.run_case does for the original run.
                    source_starts[index] = (runner.event_count,
                        dict(runner.local_ticks))
                    if source_provenance is not None:
                        items = run_starts[index]
                        ordinal = run_ordinals[index]
                        case_admissions[ordinal] = register_case_admissions(
                            runner, source_provenance,
                            case_id=f'{CASE_ID_PREFIX}{ordinal}',
                            case_index=ordinal,
                            action_ids=tuple(item.action_id for item in items),
                            source_bytes=tuple(item.value for item in items))
                command_count += 1
                if isinstance(command, BatchSourceEvent):
                    recorder.submit_source_event(command)
                elif isinstance(command, BatchAdvance):
                    recorder.advance(command.schedule)
                else:
                    raise ValueError('unknown batch command')
            end_events, end_ticks = runner.event_count, dict(runner.local_ticks)
        except Exception as exc:
            caught = dict(type=type(exc).__name__, message=str(exc),
                command_count=command_count)
        if caught is not None:
            if (reference.error is None or caught['type'] != reference.error['type']
                    or caught['message'] != reference.error['message']
                    or caught['command_count'] != reference.error['command_count']):
                raise RuntimeError('fresh replay command failure differs from original')
        actual = _capture(recorder, runner, [], reference.budget,
            reference.phase, reference.case_index,
            reference.error if caught is None else {**reference.error, **caught},
            source_pins=reference.source_pins)
        if actual.identities != reference.identities:
            raise RuntimeError('fresh native identity documents differ')
        if actual.local_ticks != reference.local_ticks:
            difference = first_difference_normalized(reference.local_ticks,
                actual.local_ticks)
            raise RuntimeError('fresh replay local ticks differ at '
                f'{difference["path"]}')
        for label, left, right in (
                ('events', reference.events, actual.events),
                ('uncertain state', reference.uncertain_status,
                 actual.uncertain_status)):
            difference = first_replay_difference(left, right,
                reference_execution_ids=reference.execution_ids,
                actual_execution_ids=actual.execution_ids)
            if difference is not None:
                raise RuntimeError(
                    'fresh replay differs from full finalized original prefix '
                    f'({label}) at {difference["path"]}: {difference["reason"]}')
        if ((actual.trace.status if actual.trace else None)
                != (reference.trace.status if reference.trace else None)):
            raise RuntimeError('fresh replay trace status differs')
        assert_plan_matches_cases(actual.plan, specs)
        uart = runner.sessions['uart']
        captured = tuple(uart.peer.captured)
        capture_cursor = 0
        settled_access_ids: set[str] = set()
        cases = []
        for position, (expected_case, spec) in enumerate(zip(reference.cases, specs), 1):
            first = expected_case['source_start_command']
            if first not in source_starts:
                raise RuntimeError('replay did not reach a recorded case boundary')
            event_start, ticks_before = source_starts[first]
            following = (reference.cases[position]['source_start_command']
                         if position < len(reference.cases) else None)
            event_end = (source_starts[following][0] if following is not None
                         else end_events)
            ticks_after = (source_starts[following][1] if following is not None
                           else end_ticks)
            rows = list(actual.events[event_start:event_end])
            tx_length = len(expected_case['tx_captures'])
            tx_captures = captured[capture_cursor:capture_cursor + tx_length]
            capture_cursor += tx_length
            authority = None
            if source_provenance is not None:
                admissions = case_admissions.get(position)
                if admissions is None:
                    raise RuntimeError('replay lost a recorded case admission boundary')
                authority = dict(source_provenance.document(),
                    admissions=[admission.document()
                                for admission in admissions])
            case = certify_descriptor_case(extract_case_witnesses(rows), spec,
                case_index=position, tx_captures=tx_captures,
                action_ids=tuple(expected_case['action_ids']),
                settled_access_ids=settled_access_ids,
                source_authority=authority)
            settled_access_ids.update(_settled_pop_access_ids(case))
            case.update(_case_boundaries(commands=reference.plan.commands, rows=rows,
                command_start=first,
                command_end=(following if following is not None
                             else len(reference.plan.commands)),
                event_start=event_start, event_end=event_end,
                ticks_before=ticks_before, ticks_after=ticks_after,
                execution_ids=actual.execution_ids))
            case.update(source_start_command=first,
                source_end_command=(following if following is not None
                                    else len(reference.plan.commands)),
                source_count=spec.source_count)
            if case != expected_case:
                difference = first_replay_difference(expected_case, case,
                    reference_execution_ids=reference.execution_ids,
                    actual_execution_ids=actual.execution_ids)
                detail = (f' at {difference["path"]}: {difference["reason"]}'
                          if difference is not None else '')
                raise RuntimeError(
                    'replay per-case descriptor evidence differs' + detail)
            cases.append(case)
        if capture_cursor != len(captured):
            raise RuntimeError('replay produced undeclared UART TX captures')
        return DescriptorResult(actual.plan, actual.trace, tuple(cases),
            actual.identities, actual.execution_ids, actual.budget, actual.phase,
            actual.case_index, actual.error, actual.events, actual.local_ticks,
            actual.uncertain_status, actual.source_pins)
    finally:
        if not recorder._finished:
            _close(runner)
