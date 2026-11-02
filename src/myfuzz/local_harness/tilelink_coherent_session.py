"""Host-side player for the generated TileLink coherent harness.

The generated runtime top puts a ``tl_coherent_memory_adapter`` between the
pinned coherent client and a *backend beat face*: ``m_req_valid/ready/write/
addr/wdata/be`` plus ``m_rsp_valid/ready/rdata/error``.  This session plays the
host side of that face, one 8-byte beat per local tick, so host memory is the
authority for every cached byte and the router is the authority for a declared
device window.

What is real here
-----------------
* ``PersistentMemory`` is the RAM authority: reads and writes go through
  ``MemoryService`` with the beat's real byte enables, so a store is only
  observable after the service recorded it.
* A device access is routed as exactly **one** 4-byte word.  The client's own
  A-channel tap (``a_bits_size``/``a_bits_mask``/``a_bits_address``) says which
  bytes the request is about; a beat that would touch two device words at once
  is refused by name instead of being split into two transactions that would
  fabricate a different evidence chain.
* Instruction slots are host-side and explicit: ``declare_instruction_slots``
  reserves words, ``accept_instructions`` fills them, and a fetch that offers an
  unmaterialized slot is reported through ``waiting_instruction_address``.

What is *not* claimed
---------------------
* No instruction-only hop identity: one shared A/D boundary carries fetches and
  data beats (``myfuzz.integration.cpu_tlul`` publishes that refusal).
* No retirement, no RAM byte version, no cross-case origin.
* F1 (image frozen before the first edge) is not implemented; this session
  declares that explicitly through ``INSTRUCTION_IMAGE_FROZEN_BEFORE_FIRST_EDGE``
  and ``HOST_MEMORY_AUTHORITY`` so a caller can check it instead of assuming.
"""
from __future__ import annotations

import copy

from myfuzz.scenario.contracts import ProtocolEnvironmentError
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.router import DataflowRouter

from .session import GeneratedLocalSession

_BEAT_BYTES = 8
_DEVICE_BEAT_BYTES = 4


class GeneratedTlCoherentSession(GeneratedLocalSession):
    """One real coherent client whose cached memory is the host's."""

    artifact_kind = 'tilelink_coherent_cpu'
    runtime_kind = 'tilelink_coherent_cpu'
    #: The host ``PersistentMemory`` is the RAM authority; the generated adapter
    #: is a pin model and the backend face is what this session answers.
    HOST_MEMORY_AUTHORITY = True
    #: F1 is out of scope: the image is not frozen before the first edge.
    INSTRUCTION_IMAGE_FROZEN_BEFORE_FIRST_EDGE = False
    max_local_ticks_per_step = 1
    max_transaction_events_per_step = 1
    max_mmio_target_accesses_per_step = 0
    #: Every backend beat is answered inline, so nothing is ever queued.
    defer_mmio = False

    def __init__(self, artifact, *, base_dir, cache_dir, memory, router=None, **kwargs):
        if artifact.runtime_document.get('kind') != self.runtime_kind:
            raise ValueError('tilelink coherent session requires its own artifact kind')
        if not isinstance(memory, PersistentMemory):
            raise ValueError('tilelink coherent session requires persistent memory')
        if router is not None and not isinstance(router, DataflowRouter):
            raise ValueError('tilelink coherent router must be a DataflowRouter')
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir, **kwargs)
        self.memory = memory
        self.service = MemoryService(memory, TransactionLedger())
        self.router = router
        self.mmio_read_count = 0
        self.mmio_write_count = 0
        self.native_instruction_fetch_count = 0
        self.accepted_addresses = []
        self.last_samples = ()
        self.runtime_events = []
        self.tilelink_beats = []
        self._pending = None
        self._deferred = None
        self._sequence_memory = 0
        self._slots_declared = False
        self._quiescing = False
        self._a_request = None
        document = artifact.runtime_document
        traces = ((document.get('base_protocol_traces') or {}).get('traces') or [])
        if len(traces) != 1:
            raise ValueError('tilelink coherent artifact declares no tap set')
        # The driver keys the sampled taps by their *runtime port name*
        # (``cpu_tl_trace_a_valid``), not by the declared role, so the mapping is
        # read from the artifact instead of being guessed.
        self._tap = dict(traces[0]['signals'])

    # -- instruction slots -------------------------------------------------
    def declare_instruction_slots(self, address: int, count: int = 1) -> None:
        """Reserve host words for online instruction fragments, before startup."""
        if self.process is not None or self._case_id is not None:
            raise RuntimeError('tilelink instruction slots require pre-start declaration')
        if self._slots_declared:
            raise ValueError('tilelink instruction slots were already declared')
        self.memory.declare_instruction_slots(address, count)
        self._slots_declared = True

    def _offered_backend_request(self):
        """The backend request the adapter is offering at the start of a step.

        The driver samples ``post`` after the edge, so the request the adapter
        raised in the previous step is exactly the one waiting for an answer
        now.  Nothing is inferred from the A taps here: the backend face is what
        this session actually acknowledges.
        """
        if not self.last_samples:
            return None
        backend = self.last_samples[-1]['post'].get('backend') or {}
        if not backend.get('m_req_valid'):
            return None
        return (int(backend['m_req_addr']), bool(backend['m_req_write']))

    @property
    def waiting_instruction_address(self):
        """Fetch the host is holding back because its word has no source yet.

        This is the request the adapter handed over and this session refused to
        answer: no byte was invented, the matching word simply has not been
        materialized.  ``accept_instructions`` releases it.
        """
        if not self._slots_declared or self._deferred is None:
            return None
        return int(self._deferred['address'])

    def accept_instructions(self, address: int, data: bytes, *, source_event_id: str):
        if not self._slots_declared:
            raise ValueError('tilelink instruction slots were not declared')
        return self.service.accept_instructions(address, data,
                                               source_event_id=source_event_id)

    # -- lifecycle ---------------------------------------------------------
    def begin_quiesce(self) -> None:
        self._quiescing = True

    @property
    def pending_responses(self) -> int:
        return int(self._pending is not None)

    def _abort(self) -> None:
        self._pending = None
        self._a_request = None
        super()._abort()

    def end_case(self) -> None:
        self._pending = None
        self._a_request = None
        self.last_samples = ()
        super().end_case()

    def reset_local(self) -> dict[str, object]:
        self._pending = None
        self._a_request = None
        result = super().reset_local()
        self.last_samples = ()
        return result

    # -- the backend beat face --------------------------------------------
    def _device_word(self, address: int, *, write: bool, be: int):
        """The single 4-byte device word this beat is about, or ``None``.

        The span comes from the client's own A-channel tap.  A beat that would
        need two device words is refused: splitting it would emit two router
        transactions for one CPU request and misstate the evidence chain.
        """
        if self.router is None:
            return None
        # A RAM beat needs no A-request identity at all: only a beat that really
        # lands in a declared device window is checked against the client's own
        # request, so an ordinary fetch (which may be accepted during the
        # startup edges, before any sample exists) never depends on it.
        probe = address & ~(_DEVICE_BEAT_BYTES - 1)
        if not self.router.owns(probe):
            return None
        request = self._a_request
        if request is None:
            raise ProtocolEnvironmentError(
                'tilelink device access without an A request at '
                + hex(address))
        size = int(request['size'])
        if size > 2:
            raise ProtocolEnvironmentError(
                'tilelink-device-beat-wider-than-one-word:' + str(1 << size))
        word = int(request['address']) & ~(_DEVICE_BEAT_BYTES - 1)
        if not self.router.owns(word):
            return None
        return word

    def _next_key(self):
        """One transaction key per accepted backend request, never per retry."""
        self._sequence_memory += 1
        return TransactionKey('local-execution', self._case_id,
                              self.artifact.plan.request.instance_id, self.reset_epoch,
                              'memory', self._sequence_memory)

    def _service_beat(self, *, key, address: int, write: bool, be: int, value: int):
        """Answer one backend beat from the router or from host memory."""
        word = self._device_word(address, write=write, be=be)
        if word is None:
            if not write and self.memory.instruction_slot_unmaterialized(address):
                # The adapter already latched this request, so the honest answer
                # is "not yet": hold the response, report the parked fetch and
                # answer on a later tick once the fragment is materialized.
                # The key is allocated once: a retry answers the *same*
                # transaction, so the ledger never sees a skipped sequence.
                self._deferred = dict(key=key, address=address, write=False,
                                      be=be, value=value)
                return None
            if write:
                receipt = self.service.write(key, address, value,
                                             width_bytes=_BEAT_BYTES, byte_enable=be)
                self._record_beat(key, address, write=True, value=value, be=be)
                return int(receipt.value) if hasattr(receipt, 'value') else 0
            snapshot = self.service.read(key, address, width_bytes=_BEAT_BYTES)
            self._record_beat(key, address, write=False, value=int(snapshot.value), be=be)
            return int(snapshot.value)
        # One routed device word.  The client's own byte enable selects which of
        # the four bytes are written; a read returns the whole word in the lanes
        # of its address, exactly as the 32-bit register really answers.
        lane = (word - address) & (_BEAT_BYTES - 1)
        device_be = (be >> lane) & ((1 << _DEVICE_BEAT_BYTES) - 1)
        device_value = (value >> (8 * lane)) & 0xffffffff
        response, error = self.router.transact(
            self.service.ledger, key, address=word, write=bool(write),
            wdata=device_value, be=device_be, beat_bytes=_DEVICE_BEAT_BYTES)
        if error:
            raise ProtocolEnvironmentError('tilelink coherent device returned an error')
        if write:
            self.mmio_write_count += 1
            self._record_beat(key, word, write=True, value=device_value, be=device_be)
            return 0
        self.mmio_read_count += 1
        self._record_beat(key, word, write=False, value=int(response), be=device_be)
        return (int(response) & 0xffffffff) << (8 * lane)

    def _record_beat(self, key, address, *, write, value, be) -> None:
        self.tilelink_beats.append(dict(key=key, address=address, write=write,
                                        value=value, be=be))

    # -- one local tick ----------------------------------------------------
    def step_local(self, inputs):
        if not isinstance(inputs, dict) or inputs:
            raise ValueError('tilelink coherent CPU has no declared external inputs')
        pending = self._pending
        # A fetch that offers a word the host has not materialized yet is held
        # back instead of being answered from an undetermined byte or refused:
        # the executor materializes the fragment, then the very same offer is
        # acknowledged on a later tick.  This is what makes the parked fetch a
        # real observation (``waiting_instruction_address``) rather than a guess.
        if (self._deferred is not None and self._pending is None
                and not self.memory.instruction_slot_unmaterialized(
                    int(self._deferred['address']))):
            # The word exists now: answer the request the adapter is still
            # holding, using the same measured-service path as any other read.
            held, self._deferred = self._deferred, None
            try:
                pending = self._service_beat(key=held['key'], address=held['address'],
                                             write=False, be=held['be'],
                                             value=held['value'])
            except (ValueError, RuntimeError) as error:
                self._abort()
                raise ProtocolEnvironmentError(
                    'tilelink coherent deferred read failed: '
                    + str(error)[:160]) from error
            self._pending = pending
        controls = (int(pending is None and not self._quiescing),
                    int(pending is not None), 0 if pending is None else int(pending), 0)
        receipt = self.command('STEP_TL_COHERENT', controls)
        if receipt.status != 'result' or receipt.new_ticks != 1:
            self._abort()
            raise ProtocolEnvironmentError(
                'tilelink coherent step failed: ' + str(receipt.error_detail))
        payload = receipt.payload
        pre_backend = payload['pre_backend']
        sample = payload['samples'][0]
        names = ('m_req_ready', 'm_rsp_valid', 'm_rsp_rdata', 'm_rsp_error')
        values = (controls[0], controls[1], controls[2], controls[3])
        if any(pre_backend[name] != value for name, value in zip(names, values)):
            raise ProtocolEnvironmentError('tilelink coherent command handshake mismatch')
        if sample['pre']['backend'] != pre_backend:
            raise ProtocolEnvironmentError('tilelink coherent snapshot mismatch')
        self.last_samples = tuple(copy.deepcopy(payload['samples']))
        taps = sample['pre'].get('protocol_taps') or {}
        def tap(role):
            return taps.get(self._tap[role])
        accepted = int(tap('a_valid') == 1 and tap('a_ready') == 1)
        consumed = int(bool(pre_backend['m_rsp_valid'] and pre_backend['m_rsp_ready']))
        if consumed:
            if pending is None:
                raise ProtocolEnvironmentError('tilelink response without a request')
            self._pending = None
        if accepted:
            # The tap form is richer (opcode/size/mask) but only exists once the
            # driver samples edges; the backend face is the authority the host
            # actually answers, so it is what publishes the acceptance.
            self._a_request = dict(address=int(tap('a_bits_address')),
                                   opcode=int(tap('a_bits_opcode')),
                                   size=int(tap('a_bits_size')),
                                   mask=int(tap('a_bits_mask')))
        if pre_backend['m_req_valid'] and pre_backend['m_req_ready']:
            address = int(pre_backend['m_req_addr'])
            value = int(pre_backend['m_req_wdata'])
            be = int(pre_backend['m_req_be'])
            write = bool(pre_backend['m_req_write'])
            try:
                response = self._service_beat(key=self._next_key(), address=address,
                                              write=write, be=be, value=value)
            except (ValueError, RuntimeError) as error:
                self._abort()
                raise ProtocolEnvironmentError(
                    'tilelink coherent backend error without completion: '
                    + str(error)[:200]) from error
            self._pending = response
            self.accepted_addresses.append(address)
            # One acceptance event per request the adapter really handed over,
            # written at the backend face: opcode 0/1 are writes, 4/6 are reads.
            self._runtime_event('tilelink_a_accept', address=address,
                                opcode=0 if write else 4,
                                size=(int(self._a_request['size'])
                                      if self._a_request else None),
                                mask=be, data=value, write=write)
        if consumed:
            self._runtime_event('tilelink_d_complete', value=pending)
        self.memory.advance_step()
        return {'data_req_valid': pre_backend['m_req_valid'],
                'data_req_accepted': int(bool(pre_backend['m_req_valid']
                                              and pre_backend['m_req_ready'])),
                'data_write': pre_backend['m_req_write'],
                'data_addr': pre_backend['m_req_addr'],
                'data_wdata': pre_backend['m_req_wdata'],
                'data_be': pre_backend['m_req_be'],
                'data_rsp_consumed': consumed,
                'data_rsp_rdata': 0 if pending is None else int(pending),
                'data_rsp_source_epoch': self.reset_epoch if consumed else 0,
                'data_rsp_source_sequence': 0,
                'fault': int(pre_backend.get('m_fault', 0)),
                'driver_samples': copy.deepcopy(self.last_samples),
                'protocol_taps': copy.deepcopy(taps)}

    def _runtime_event(self, kind: str, **fields) -> None:
        self.runtime_events.append(dict(
            kind=kind, component=self.artifact.plan.request.instance_id,
            execution_id='local-execution', reset_epoch=self.reset_epoch,
            tick=self.local_ticks, **fields))
