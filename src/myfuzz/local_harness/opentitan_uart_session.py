"""Generated OpenTitan UART target with a measured 8N1 serial peer."""

from __future__ import annotations

from collections import deque
from copy import deepcopy
from dataclasses import asdict, dataclass
import json
from collections.abc import Mapping
from types import MappingProxyType

from myfuzz.scenario.uart_peer import Uart8N1Peer

from .session import GeneratedLocalSession


#: Byte lanes of the 32-bit TL-UL beat this target is addressed with.
_BYTE_LANES = 4


def enabled_write_mask(byte_enable: object) -> int | None:
    """The data bytes one store really writes, or ``None`` for an unknown strobe.

    ``byte_enable`` is the TL-UL ``a_mask`` lane strobe the pinned target
    forwards unchanged (``tlul_adapter_reg.sv`` ``wdata_o = a_data`` /
    ``be_o = a_mask``), so a disabled lane carries no register data.  A byte
    store (``be=1``) writes lane 0 alone; a word store (``be=15``) writes all
    four lanes.
    """
    if (type(byte_enable) is not int
            or not 0 <= byte_enable < 1 << _BYTE_LANES):
        return None
    mask = 0
    for lane in range(_BYTE_LANES):
        if byte_enable >> lane & 1:
            mask |= 0xFF << (8 * lane)
    return mask


@dataclass(frozen=True)
class UartRegisterWrite:
    """One declared writable register of the pinned OpenTitan UART target.

    ``byte_enables`` are the register strobes this target accepts and
    ``accepted_values`` are the register words it accepts for them; an 8-bit
    field such as ``WDATA`` declares the whole byte range instead of a list.
    Only the enabled byte lanes are written by the target, so only they are
    judged against the declared field: ``be=1`` at an 8-bit register accepts any
    32-bit beat because lane 0 alone is written, while ``be=15`` must keep the
    whole word inside the field.

    The declaration is the single authority behind the runtime refusal of
    ``write_register`` and the decoder's pre-RTL candidate gate, so the two
    cannot drift apart.
    """

    offset: int
    name: str
    byte_enables: tuple[int, ...]
    accepted_values: tuple[int, ...] | range

    def written_value(self, value: object, byte_enable: object) -> int | None:
        """The register word this store writes, or ``None`` if it is not one."""
        mask = enabled_write_mask(byte_enable)
        if mask is None or type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            return None
        return value & mask

    def accepts(self, value: object, byte_enable: object) -> bool:
        written = self.written_value(value, byte_enable)
        return written is not None and written in self.accepted_values

    @property
    def declared_values(self) -> list[int]:
        """Bounded JSON-safe description of the accepted register words."""
        if isinstance(self.accepted_values, range):
            return [self.accepted_values.start, self.accepted_values.stop - 1]
        return list(self.accepted_values)


#: Every write ``GeneratedOpentitanUartSession.write_register`` admits, named by
#: the register map of the pinned UART RTL (CTRL 0x10, INTR_ENABLE 0x04, WDATA
#: 0x1c).  The two bootstrap words are the exact values the fixed firmware
#: writes; WDATA is the eight-bit transmit field.  No other register write is
#: declared, so no other one is legal for this target.
UART_REGISTER_WRITES = (
    UartRegisterWrite(0x04, "INTR_ENABLE", (15,), (0x6, 0x2)),
    UartRegisterWrite(0x10, "CTRL", (15,), (0x80000003,)),
    UartRegisterWrite(0x1C, "WDATA", (1, 15), range(0, 256)),
)
UART_REGISTER_WRITES_BY_OFFSET = MappingProxyType(
    {rule.offset: rule for rule in UART_REGISTER_WRITES})


def uart_register_write_supported(offset: object, value: object,
                                  byte_enable: object) -> bool:
    """The one declared write-acceptance predicate of this UART target."""
    rule = (UART_REGISTER_WRITES_BY_OFFSET.get(offset)
            if type(offset) is int else None)
    return (rule is not None and type(byte_enable) is int
            and byte_enable in rule.byte_enables
            and rule.accepts(value, byte_enable))


def uart_register_write_denial(offset: object, value: object,
                               byte_enable: object) -> str | None:
    """Classify a refused write as ``register``, ``byte_enable`` or ``value``.

    The classification is derived from the same declaration as
    :func:`uart_register_write_supported`; it only names which declared field
    refused the write, so a caller can pick its own structured rejection code.
    """
    rule = (UART_REGISTER_WRITES_BY_OFFSET.get(offset)
            if type(offset) is int else None)
    if rule is None:
        return "register"
    if type(byte_enable) is not int or byte_enable not in rule.byte_enables:
        return "byte_enable"
    if not rule.accepts(value, byte_enable):
        return "value"
    return None


class GeneratedOpentitanUartSession(GeneratedLocalSession):
    artifact_kind = 'tlul_uart'

    def __init__(self, artifact, *, base_dir, cache_dir,
                 source: bytes | None = b'', startup_writes: tuple[tuple[int, int, int], ...] = (),
                 read_rx_after_source: bool = False, cpu_routed_mode: bool = False,
                 **kwargs):
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir, **kwargs)
        if self._expected_ready()[3] != self.artifact_kind:
            raise ValueError('generated OpenTitan UART artifact required')
        if source is not None and (not isinstance(source, bytes) or len(source) > 1):
            raise ValueError('UART peer supports at most one source byte')
        if (type(startup_writes) is not tuple or len(startup_writes) > 4
                or any(type(row) is not tuple or len(row) != 3
                       or row not in ((0x10, 0x80000003, 15), (0x04, 0x6, 15),
                                      (0x04, 0x2, 15))
                       and not (type(row[0]) is int and row[0] == 0x1c
                                and type(row[1]) is int and 0 <= row[1] <= 255
                                and type(row[2]) is int and row[2] == 15)
                       for row in startup_writes)):
            raise ValueError('invalid OpenTitan UART startup writes')
        if (type(read_rx_after_source) is not bool
                or read_rx_after_source and source == b''):
            raise ValueError('UART RX read requires a serial source')
        if (type(cpu_routed_mode) is not bool
                or cpu_routed_mode and (source is not None or startup_writes
                                        or read_rx_after_source)):
            raise ValueError('CPU-routed UART requires genome RX and CPU MMIO setup')
        self.source = source
        self.source_mode = 'genome' if source is None else 'constructor'
        self.startup_writes = startup_writes
        self.read_rx_after_source = read_rx_after_source
        self.cpu_routed_mode = cpu_routed_mode
        self.peer = Uart8N1Peer(source or b'', clocks_per_bit=32)
        self._source_provenance = False
        self.source_events: list[dict] = []
        self._started = False
        self._selected_source_byte: int | None = None
        self._rx_read = False
        self._rx_word = 0
        self._samples: deque[dict] = deque()
        self.local_transactions: list[dict[str, int]] = []
        self.uart_events: list[dict] = []
        self._active_uart_access = None
        self._routed_uart_transaction = None
        self._routed_uart_context = None
        if self.uart_fifo_observation_enabled:
            from .opentitan_uart_fifo_contract import uart_fifo_observation_contract
            if json.dumps(self._artifact_document['uart_fifo_observation_contract'], sort_keys=True) != json.dumps(
                    uart_fifo_observation_contract(), sort_keys=True):
                raise ValueError('UART FIFO observation contract mismatch')
            self.enable_source_provenance()
        wait = artifact.runtime_document['effective_max_wait_cycles']
        self.max_local_ticks_per_register_access = 2 * wait + 5
        self.max_local_ticks_per_step = (1 + (len(startup_writes)
            + int(read_rx_after_source)) * self.max_local_ticks_per_register_access)

    def enable_source_provenance(self):
        """Enable source action identities before any waveform is scheduled."""
        if getattr(self, '_source_provenance', False):
            return
        if self._started:
            raise RuntimeError('UART source provenance must precede source scheduling')
        pins = [row['runtime_name'] for row in self._artifact_document['physical_exports']
                if row['physical_port'] == 'cio_rx_i']
        if len(pins) != 1:
            raise ValueError('UART source provenance requires actual cio_rx_i samples')
        self._rx_physical_name = pins[0]
        self._source_provenance = True
        self.source_events = []
        self._source_frames = []
        self._pending_source_actions = []
        self._source_action_ids = set()
        self._source_frame_counter = 0

    @property
    def uart_fifo_observation_enabled(self):
        return 'uart_fifo_observation_contract' in getattr(self, '_artifact_document', {})

    @property
    def routed_register_access_enabled(self):
        return self.uart_fifo_observation_enabled

    def _uart_scope(self, receipt):
        return {'component': self._artifact_document['plan']['instance_id'],
                'reset_epoch': self.reset_epoch, 'command_sequence': receipt.sequence}

    def _uart_physical(self, snapshot):
        raw = snapshot.get('physical', {})
        return {row['runtime_name'] if row['physical_port'].startswith('uart_probe_') else row['physical_port']:
                raw[row['runtime_name']] for row in self._artifact_document['physical_exports']
                if row['runtime_name'] in raw}

    def _record_uart_sample(self, sample, receipt):
        tick = self._tick_base + sample['local_tick']
        scope = self._uart_scope(receipt)
        pre, post = (self._uart_physical(sample[phase]) for phase in ('pre', 'post'))
        receipt_id = {'execution': receipt.execution, 'sequence': receipt.sequence}
        active = [state for state in self._source_frames
                  if state['record']['start_tick'] <= tick < state['record']['end_tick']]
        drive_ref = None
        if len(active) == 1:
            state = active[0]
            frame = state['record']
            drive_ref = {'frame_id': frame['frame_id'], 'action_id': frame['action_id'],
                'admission_id': None, 'receipt_id': receipt_id,
                'bit_index': (tick - frame['start_tick']) // state['clocks_per_bit'],
                'bit_value': pre.get('cio_rx_i'), 'drive_tick': tick}
            state.setdefault('source_drive_refs', []).append(deepcopy(drive_ref))
        self.uart_events.append(deepcopy({'kind': 'uart_tick_observation',
            'schema_version': 'uart_tick_observation.v1', 'component': scope['component'],
            'reset_epoch': self.reset_epoch, 'source_epoch': self.reset_epoch,
            'command_scope': scope, 'receipt_id': receipt_id, 'local_tick': tick,
            'observation_contract': self._artifact_document['uart_fifo_observation_contract'],
            'pre': pre, 'post': post, 'physical_rx_ref': drive_ref,
            'physical_rx_value': pre.get('cio_rx_i'), 'access': self._active_uart_access}))

    def source_provenance_identity(self):
        return {'schema_version': 'uart_source_frames.v1',
                'frame_semantics': 'cio_rx_drive_8n1',
                'clocks_per_bit': self.peer.clocks_per_bit,
                'idle_mark_bits': 17, 'frame_ticks': 10 * self.peer.clocks_per_bit,
                'fifo_origin': 'unknown'}

    def _schedule_source_frame(self, byte, action_id, start):
        self._source_frame_counter += 1
        frame = {'schema_version': 'uart_source_frames.v1',
                 'frame_semantics': 'cio_rx_drive_8n1', 'fifo_origin': 'unknown',
                 'action_id': action_id,
                 'frame_id': f'uart-frame:{self.reset_epoch}:{self._source_frame_counter}',
                 'session_case_id': self._case_id, 'reset_epoch': self.reset_epoch,
                 'port': 'uart_rx_byte', 'bit_offset': 0, 'width': 8,
                 'byte': byte, 'start_tick': start,
                 'end_tick': start + 10 * self.peer.clocks_per_bit}
        self.source_events.append({**frame, 'kind': 'uart_source_frame_admission',
                                   'local_tick': self.local_ticks})
        self._source_frames.append({'record': frame, 'begun': False,
            'clocks_per_bit': self.peer.clocks_per_bit,
            'sample_count': 0, 'mismatch_count': 0, 'bit_witness': []})

    def _observe_source_sample(self, sample, receipt):
        tick = self._tick_base + sample['local_tick']
        receipt_ref = {'execution': getattr(receipt, 'execution', None),
                       'sequence': getattr(receipt, 'sequence', None)}
        for state in list(self._source_frames):
            frame = state['record']
            if frame['start_tick'] <= tick < frame['end_tick']:
                if not state['begun']:
                    self.source_events.append({**frame, 'kind': 'uart_source_frame_begin',
                                               'local_tick': tick})
                    state['begun'] = True
                actual = sample['pre']['physical'].get(self._rx_physical_name)
                post_actual = sample['post']['physical'].get(self._rx_physical_name)
                clocks_per_bit = state['clocks_per_bit']
                slot = (tick - frame['start_tick']) // clocks_per_bit
                expected = (0 if slot == 0 else 1 if slot == 9
                            else (frame['byte'] >> (slot - 1)) & 1)
                state['sample_count'] += 1
                state['mismatch_count'] += int(type(actual) is not int or actual != expected
                    or type(post_actual) is not int or post_actual != expected)
                if (tick - frame['start_tick']) % clocks_per_bit == 0:
                    state['bit_witness'].append({'bit_index': slot,
                        'local_tick': tick, 'expected_level': expected,
                        'actual_pre_level': actual, 'actual_post_level': post_actual,
                        'receipt': receipt_ref})
            if tick >= frame['end_tick'] - 1:
                matched = (state['sample_count'] == frame['end_tick'] - frame['start_tick']
                           and state['mismatch_count'] == 0)
                self.source_events.append({**frame, 'kind': 'uart_source_frame_end',
                    'local_tick': tick, 'sample_count': state['sample_count'],
                    'mismatch_count': state['mismatch_count'],
                    'bit_witness': list(state['bit_witness']), 'waveform_matched': matched})
                if self.uart_fifo_observation_enabled:
                    self.uart_events.append(deepcopy({**frame, 'kind': 'uart_frame_validation',
                        'schema_version': 'uart_frame_validation.v1',
                        'component': self._artifact_document['plan']['instance_id'],
                        'command_scope': self._uart_scope(receipt), 'local_tick': tick,
                        'source_drive_refs': state.get('source_drive_refs', []),
                        'admission_id': None, 'waveform_matched': matched}))
                self._source_frames.remove(state)

    def _cancel_source_frames(self, reason):
        if not getattr(self, '_source_provenance', False):
            return
        for state in self._source_frames:
            self.source_events.append({**state['record'],
                'kind': 'uart_source_frame_cancel', 'local_tick': self.local_ticks,
                'reason': reason, 'sample_count': state['sample_count'],
                'mismatch_count': state['mismatch_count'],
                'bit_witness': list(state['bit_witness'])})
        for byte, action_id in self._pending_source_actions:
            self.source_events.append({'schema_version': 'uart_source_frames.v1',
                'frame_semantics': 'cio_rx_drive_8n1', 'fifo_origin': 'unknown',
                'kind': 'uart_source_frame_cancel', 'action_id': action_id,
                'frame_id': None, 'byte': byte, 'reason': reason,
                'local_tick': self.local_ticks, 'schedule_status': 'pending'})
        self._source_frames.clear()
        self._pending_source_actions.clear()
        self._source_action_ids.clear()

    def identity_document(self):
        return {**super().identity_document(),
                'tlul_uart_service_schema_version': ('generated_tlul_uart_8n1.v4'
                    if self.cpu_routed_mode else 'generated_tlul_uart_8n1.v3'
                    if self.source_mode == 'genome' else 'generated_tlul_uart_8n1.v2'),
                'source_component': self.artifact.plan.request.instance_id,
                'source_hex': (self.source or b'').hex(),
                **({'cpu_routed_mode': True} if self.cpu_routed_mode else {}),
                **({'source_mode': 'genome'} if self.source_mode == 'genome' else {}),
                'startup_writes': [list(row) for row in self.startup_writes],
                'read_rx_after_source': self.read_rx_after_source,
                **({'uart_source_provenance': self.source_provenance_identity()}
                   if self._source_provenance else {}),
                **({'uart_fifo_observation_contract': deepcopy(self._artifact_document['uart_fifo_observation_contract'])}
                   if self.uart_fifo_observation_enabled else {})}

    def begin_case(self, testcase_id):
        super().begin_case(testcase_id)
        self._cancel_source_frames('case_restart')
        self.peer.reset_case()
        if self.source_mode == 'genome':
            self.peer.source = b''
        self._started = False
        self._selected_source_byte = None
        self._rx_read = False
        self._rx_word = 0
        self._samples.clear()
        self.local_transactions.clear()

    def max_transaction_events_for_step(self, inputs: Mapping[str, int]) -> int:
        if not self._started:
            return len(self.startup_writes)
        return int(self.read_rx_after_source and not self._rx_read
                   and self.local_ticks + 1 >= self.peer.source_end_tick + 50)

    @property
    def pending_responses(self):
        return 0

    @property
    def pending_events(self):
        if not self._started:
            return len(self.startup_writes) + (1 if self.source_mode == 'genome'
                                               else len(self.source))
        return (max(0, self.peer.source_end_tick - self.local_ticks)
                + int((self.read_rx_after_source or self.cpu_routed_mode)
                      and not self._rx_read))

    def begin_quiesce(self):
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError('generated OpenTitan UART process is not running')

    def _take(self, reply, *, operation):
        if reply.status != 'result' or reply.payload is None:
            raise RuntimeError('generated OpenTitan UART protocol error: '
                               + str(reply.error_code))
        payload = reply.payload
        samples = payload.get('samples')
        if (not isinstance(samples, list) or not 1 <= len(samples) <=
                self.max_local_ticks_per_register_access
                or len(self._samples) + len(samples) > 65536):
            raise ValueError('invalid UART driver tick evidence')
        if operation == 'STEP_TLUL_UART' and len(samples) != 1:
            raise ValueError('UART step did not advance one tick')
        for sample in samples:
            post = sample['post']
            line = post['uart_tx']
            if type(line) is not int or line not in (0, 1):
                raise ValueError('invalid physical UART TX pin')
            if getattr(self, '_source_provenance', False):
                if self.uart_fifo_observation_enabled:
                    self._record_uart_sample(sample, reply)
                self._observe_source_sample(sample, reply)
            self.peer.observe_tx(sample['local_tick'], line)
            self._samples.append({**sample,
                                  'local_tick': self._tick_base + sample['local_tick']})
        if operation == 'ACCESS_TLUL_UART':
            if type(payload['rdata']) is not int or not 0 <= payload['rdata'] <= 0xffffffff:
                raise ValueError('invalid OpenTitan UART read data')
            if type(payload['error']) is not int or not 0 <= payload['error'] <= 1:
                raise ValueError('invalid OpenTitan UART response')
        return payload

    def drain_tick_samples(self):
        result = list(self._samples)
        self._samples.clear()
        return result

    def step_local(self, inputs: Mapping[str, int]):
        if not isinstance(inputs, Mapping):
            raise ValueError('UART inputs must be a mapping')
        if self.source_mode == 'genome':
            if set(inputs) not in (set(), {'uart_rx_byte'}):
                raise ValueError('UART genome source needs one byte')
            if 'uart_rx_byte' in inputs:
                byte = inputs['uart_rx_byte']
                if type(byte) is not int or not 0 <= byte <= 255:
                    raise ValueError('UART genome source needs one byte')
                if getattr(self, '_source_provenance', False):
                    if not self._started:
                        if not self._pending_source_actions:
                            raise ValueError('UART source provenance requires source admission')
                        self.peer.source = bytes((self._pending_source_actions[0][0],))
                elif not self._started:
                    self.peer.source = bytes((byte,))
                    self._selected_source_byte = byte
                elif self._selected_source_byte != byte:
                    if self.local_ticks < self.peer.source_end_tick:
                        raise ValueError('UART source cannot change after serial frame starts')
                    self.enqueue_rx_byte(byte)
            elif not self._started:
                raise ValueError('UART genome source needs one byte')
        elif inputs:
            raise ValueError('UART peer source is selected at case start')
        if not self._started:
            self._started = True
            for offset, value, be in self.startup_writes:
                self.write_register(offset, value, be=be)
                self.local_transactions.append({'offset': offset, 'write_value': value,
                                                'byte_enable': be})
            # An idle mark lets the OpenTitan 16x RX sampler settle before start.
            self.peer.start_source(self.local_ticks + 17 * self.peer.clocks_per_bit + 1)
            if getattr(self, '_source_provenance', False):
                pending, self._pending_source_actions = self._pending_source_actions, []
                if pending:
                    byte, action_id = pending[0]
                    self._schedule_source_frame(byte, action_id, self.peer.source_start_tick)
                    for byte, action_id in pending[1:]:
                        self.enqueue_rx_byte(byte, action_id=action_id)
        rx = self.peer.drive_rx(self.local_ticks + 1)
        payload = self._take(self.command('STEP_TLUL_UART', (rx,)),
                             operation='STEP_TLUL_UART')
        if (self.read_rx_after_source and not self._rx_read
                and self.local_ticks >= self.peer.source_end_tick + 50):
            self._rx_word = self.read_register(0x18)
            self._rx_read = True
            self.local_transactions.append({'offset': 0x18, 'read_value': self._rx_word,
                                            'byte_enable': 15})
        return {name: value for name, value in payload['observations'].items()
                if name not in ('backend', 'physical')} | {
            'serial_tx_count': len(self.peer.captured),
            'serial_tx_last': self.peer.captured[-1] if self.peer.captured else 0,
            'serial_rx_read': int(self._rx_read), 'serial_rx_word': self._rx_word}

    def enqueue_rx_byte(self, byte: int, *, action_id: str | None = None) -> int:
        """Schedule a later Fuzzer-owned RX byte on this live UART instance.

        The caller records this source action in the testcase stream. The
        resulting waveform and FIFO/IRQ state still come from real UART RTL.
        """
        if type(byte) is not int or not 0 <= byte <= 255:
            raise ValueError('UART RX source needs one byte')
        if (getattr(self, '_source_provenance', False)
                and (not isinstance(action_id, str) or not action_id)):
            raise ValueError('UART source provenance requires action identity')
        if self.source_mode != 'genome':
            raise ValueError('UART RX queue requires a genome-owned source')
        if not self._started or self.peer.source_start_tick is None:
            raise RuntimeError('UART initial source has not started')
        if self.read_rx_after_source and not self._rx_read:
            raise RuntimeError('previous UART RX source has not been read')
        start = (max(self.local_ticks, self.peer.source_end_tick)
                 + 17 * self.peer.clocks_per_bit + 1)
        self.peer.append_source(bytes((byte,)), start)
        if getattr(self, '_source_provenance', False):
            self._schedule_source_frame(byte, action_id, start)
        self._selected_source_byte = byte
        self._rx_read = False
        return start

    def admit_source_event(self, port: str, value: int, *, bit_offset: int,
                           width: int, action_id: str) -> int | None:
        """Turn each new UART source action into exactly one queued RX frame."""
        if (port != 'uart_rx_byte' or bit_offset != 0 or width != 8
                or not isinstance(action_id, str) or not action_id
                or type(value) is not int or not 0 <= value <= 255):
            raise ValueError('invalid UART RX source action')
        if getattr(self, '_source_provenance', False):
            if self.source_mode != 'genome':
                raise ValueError('UART source action requires a genome-owned source')
            if action_id in self._source_action_ids:
                raise ValueError('duplicate UART source action identity')
            if not self._started:
                if self.read_rx_after_source and self._pending_source_actions:
                    raise RuntimeError('previous UART RX source has not been read')
                self._pending_source_actions.append((value, action_id))
                self._source_action_ids.add(action_id)
                return None
            start = self.enqueue_rx_byte(value, action_id=action_id)
            self._source_action_ids.add(action_id)
            return start
        if not self._started:
            return None
        return self.enqueue_rx_byte(value)

    @staticmethod
    def _offset(offset):
        if type(offset) is not int or not 0 <= offset <= 0x30 or offset % 4:
            raise ValueError('invalid OpenTitan UART register offset')

    def register_access_conflict(self) -> dict | None:
        """The same overlap query ``_access`` refuses on, asked in advance.

        The online admission gate calls this *before* the RTL command, so a
        candidate that would hit "TL-UL access during serial source waveform is
        unsupported" is refused as a non-consuming pre-RTL rejection and the
        search session survives.  This method answers the identical predicate
        (``peer.source_overlaps`` over the same horizon) and returns the ticks
        involved instead of raising, so nothing about the guard changes.
        """
        if not self._started:
            return None
        horizon = self.local_ticks + self.max_local_ticks_per_register_access + 1
        if not self.peer.source_overlaps(self.local_ticks, horizon):
            return None
        return {"local_tick": int(self.local_ticks),
                "horizon_tick": int(horizon),
                "source_start_tick": int(self.peer.source_start_tick or 0),
                "source_end_tick": int(self.peer.source_end_tick or 0),
                "max_register_access_ticks":
                    int(self.max_local_ticks_per_register_access),
                "basis": ("peer.source_overlaps over the same horizon _access "
                          "refuses on; queried before any RTL command")}

    def _access(self, write, offset, value, be):
        self._offset(offset)
        if type(value) is not int or not 0 <= value <= 0xffffffff:
            raise ValueError('invalid OpenTitan UART register value')
        if type(be) is not int or not 0 <= be <= 15:
            raise ValueError('invalid OpenTitan UART byte strobe')
        if self.peer.source_overlaps(self.local_ticks,
                self.local_ticks + self.max_local_ticks_per_register_access + 1):
            raise RuntimeError('TL-UL access during serial source waveform is unsupported')
        rx = self.peer.drive_rx(self.local_ticks + 1)
        if self.uart_fifo_observation_enabled:
            self._uart_access_counter = getattr(self, '_uart_access_counter', 0) + 1
            component = self._artifact_document['plan']['instance_id']
            self._active_uart_access = {'access_id': f'uart-access:{component}:{self.reset_epoch}:{self._uart_access_counter}',
                'source_transaction': deepcopy(getattr(self, '_routed_uart_transaction', None)),
                'raw_offset': offset, 'write': bool(write), 'byte_enable': be,
                **deepcopy(getattr(self, '_routed_uart_context', None) or {})}
        try:
            reply = self.command('ACCESS_TLUL_UART', (rx, int(write), offset, value, be))
            payload = self._take(reply, operation='ACCESS_TLUL_UART')
            if self.uart_fifo_observation_enabled and not write and offset == 0x18:
                self._record_uart_read(reply, payload)
        finally:
            self._active_uart_access = None
        pre = [sample['pre']['backend'] for sample in payload['samples']]
        if sum(bool(row['uart_req_valid'] and row['uart_req_ready']) for row in pre) != 1:
            raise RuntimeError('OpenTitan UART beat was not accepted exactly once')
        if payload['error']:
            raise RuntimeError('OpenTitan UART slave response error')
        return payload['rdata']

    def _record_uart_read(self, reply, payload):
        scope = self._uart_scope(reply)
        captures = []
        for sample in payload['samples']:
            pre, post = (self._uart_physical(sample[phase]) for phase in ('pre', 'post'))
            tick = self._tick_base + sample['local_tick']
            captures.append({'pre': pre, 'post': post,
                'actual_receipt_ref': {'command_scope': scope, 'local_tick': tick}})
        requests = [c for c in captures if c['pre'].get('probe_uart_a_accept') == 1
                    and c['pre'].get('probe_uart_reg_rdata_re') == 1]
        responses = [c for c in captures if c['pre'].get('probe_uart_d_accept') == 1]
        observed = len(requests) == len(responses) == 1
        context = deepcopy(self._active_uart_access)
        fact = {**context, 'kind': 'uart_rdata_access', 'schema_version': 'uart_rdata_access.v1',
            'component': scope['component'], 'reset_epoch': self.reset_epoch,
            'source_epoch': self.reset_epoch, 'command_scope': scope,
            'local_tick': captures[-1]['actual_receipt_ref']['local_tick'],
            'read_value': payload['rdata'], 'error': payload['error'],
            'status': 'observed' if observed else 'incomplete'}
        if observed:
            fact.update(request_tick=requests[0]['actual_receipt_ref']['local_tick'],
                response_tick=responses[0]['actual_receipt_ref']['local_tick'],
                read_capture=requests[0], response_capture=responses[0])
        self.uart_events.append(deepcopy(fact))
        self._last_uart_access = deepcopy(fact)

    def routed_register_access(self, source_transaction, *, address, offset, write,
                               value, be, delivery_context):
        from myfuzz.scenario.ledger import TransactionKey
        if not self.uart_fifo_observation_enabled:
            raise ValueError('routed UART observation requires explicit variant')
        if getattr(self, '_routed_uart_transaction', None) is not None:
            raise RuntimeError('nested routed UART access')
        if (type(source_transaction) is not TransactionKey
                or any(type(getattr(source_transaction, name)) is not str
                       or not getattr(source_transaction, name).strip()
                       for name in ('execution_id', 'testcase_id', 'source_component', 'channel_id'))
                or source_transaction.channel_id != 'data'
                or type(source_transaction.source_epoch) is not int
                or not 0 <= source_transaction.source_epoch < 1 << 64
                or type(source_transaction.source_sequence) is not int
                or not 0 < source_transaction.source_sequence < 1 << 64):
            raise ValueError('invalid routed UART transaction identity')
        self._offset(offset)
        if (type(address) is not int or not 0 <= address < 1 << 64
                or address < offset or (address - offset) % 0x1000
                or address + 4 > 1 << 64 or type(write) is not bool
                or type(value) is not int or not 0 <= value <= 0xffffffff
                or type(be) is not int or (be != 15 and not (
                    write and offset == 0x1c and be == 1))):
            raise ValueError('invalid routed UART register shape')
        component = self._artifact_document['plan']['instance_id']
        expected = {'source_transaction': asdict(source_transaction),
                    'device_id': component, 'address': address, 'offset': offset,
                    'write': write, 'value': value, 'be': be}
        if type(delivery_context) is not dict:
            raise ValueError('routed UART delivery context mismatch')
        window_base, window_size = address - offset, None
        if delivery_context:
            actual = deepcopy(delivery_context)
            if set(actual) != set(expected) | {'window_base', 'window_size'}:
                raise ValueError('routed UART delivery context mismatch')
            window_base = actual.pop('window_base')
            window_size = actual.pop('window_size')
            if (type(window_base) is not int or window_base != address - offset
                    or type(window_size) is not int or window_size < 4
                    or window_size % 4 or offset + 4 > window_size
                    or window_base + window_size > 1 << 64):
                raise ValueError('routed UART window context mismatch')
            try:
                matches = json.dumps(actual, sort_keys=True, allow_nan=False) == json.dumps(
                    expected, sort_keys=True, allow_nan=False)
            except (TypeError, ValueError):
                matches = False
            if not matches:
                raise ValueError('routed UART delivery context mismatch')
        context = {'address': address, 'window_base': window_base, 'window_size': window_size,
                   'route_context_mode': 'router' if delivery_context else 'direct',
                   'delivery_context': deepcopy(delivery_context)}
        self._routed_uart_transaction = asdict(source_transaction)
        self._routed_uart_context = context
        try:
            if write:
                self.write_register(offset, value, be=be)
                return {'rdata': 0}
            result = self.read_register(offset)
            observed = deepcopy(getattr(self, '_last_uart_access', None)) if offset == 0x18 else None
            return {'rdata': result, **({'target_uart_access': observed,
                    'target_access_id': observed['access_id']} if observed is not None else {})}
        finally:
            self._routed_uart_transaction = None
            self._routed_uart_context = None

    def write_register(self, offset: int, value: int, *, be: int = 15):
        if not uart_register_write_supported(offset, value, be):
            raise ValueError('unsupported UART register write')
        self._access(True, offset, value, be)

    def read_register(self, offset: int) -> int:
        value = self._access(False, offset, 0, 15)
        if self.cpu_routed_mode and offset == 0x18:
            self._rx_word = value
            self._rx_read = True
        return value

    def end_case(self):
        self._cancel_source_frames('end_case')
        super().end_case()

    def reset_local(self):
        self._cancel_source_frames('reset')
        result = super().reset_local()
        self.peer.reset_case()
        if self.source_mode == 'genome':
            self.peer.source = b''
        self._started = False
        self._selected_source_byte = None
        self._rx_read = False
        self._rx_word = 0
        self._samples.clear()
        self._active_uart_access = None
        self._routed_uart_transaction = None
        self._routed_uart_context = None
        if self.uart_fifo_observation_enabled:
            component = self._artifact_document['plan']['instance_id']
            self.uart_events.append({'kind': 'uart_reset', 'schema_version': 'uart_reset.v1',
                'component': component, 'reset_epoch': self.reset_epoch,
                'source_epoch': self.reset_epoch, 'local_tick': self.local_ticks,
                'physical_reset': True, 'command_scope': {'component': component,
                    'reset_epoch': self.reset_epoch, 'command_sequence': 0},
                'reset_outcome': deepcopy(result)})
        return result
