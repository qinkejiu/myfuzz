"""Persistent memory service for the source-pinned no-response-code AXI4-Lite CPU.

An optional :class:`~myfuzz.scenario.router.DataflowRouter` may be supplied so a
CPU beat whose address falls inside a declared device window is served by the
real target instead of local RAM.  Routing is opt-in: without a router this
session behaves exactly as before (RAM/ROM only), so every existing identity and
budget stays unchanged.

The router is addressed by the 32-bit word beat (``address & ~3``), matching the
OBI CPU session's convention, and only one target access is performed per local
step.  The response returned by the target becomes the beat's read response, so
an MMIO read is real device data rather than a synthesised value.

READ DATA GRANULARITY (declared, reviewed policy -- see
``READ_TRANSFER_DECLARATION``)
    AXI4-Lite has no read strobe, so a read transfers the whole addressed word
    and the value sampled on the write-strobe pins during a read carries no lane
    information: the pinned PicoRV32 drives ``wstrb = 0`` there because it only
    asserts ``ARVALID`` while ``mem_wstrb == 0`` (``picorv32.v:2777``).  The
    declared policy is applied at the *router request* boundary -- a read
    presents ``be=15`` exactly like the classic Wishbone CPU session's
    ``sel if write else 15`` -- while every sampled pin stays unchanged:
    ``read_request_be = 0`` here still refuses a read whose sampled request
    strobe is not zero, ``driver_samples[*].pre.protocol_taps`` keeps the real
    ``wstrb`` value of every tick, and the CPU beat records that sampled value.
    A write always presents the sampled ``wstrb``; no write strobe is ever
    invented.

INSTRUCTION FETCH IDENTITY
    This CPU has no instruction-identity port and the generated executor
    deliberately ignores ``ARPROT``.  The fetch flag is only observable on the
    sampled ``arprot`` band tap (bit 2, ``picorv32.v:2779``), so the trace
    declares it (``fetch_observation``) and the gate authenticates that the tap
    is a real admitted ABI wire.  A fetch whose declared instruction word has not
    been materialised is *parked* exactly like the classic Wishbone CPU session
    parks one: the request is accepted once and answered when the bound source
    supplies the word.  A data read that reaches an unfilled instruction slot is
    still a named error, never a silent substitution.
"""
from myfuzz.scenario.contracts import ProtocolEnvironmentError
from myfuzz.scenario.memory import InstructionNotReady, PersistentMemory
from myfuzz.scenario.router import DataflowRouter

from .native_session import GeneratedNativeMemorySession, _QUEUED_RESPONSE

#: The reviewed read-transfer declaration of this CPU bus protocol.  It is a
#: protocol semantic (AXI4-Lite has no read strobe), never an instance special
#: case, and it is the single source the session and the CPU protocol
#: observation reader quote.
READ_TRANSFER_DECLARATION = {
    'schema_version': 'cpu_read_transfer_declaration.v1',
    'protocol': 'axi4-lite',
    'transfer_bytes': 4,
    'granularity': 'whole_addressed_word',
    'statement': ('read transfers the whole addressed word; the sampled wstrb is '
                  '0 because AXI4-Lite has no read strobe'),
    'sampled_read_strobe': 0,
    'sampled_read_strobe_basis': (
        'picorv32.v:2777 mem_axi_arvalid = mem_valid && !mem_wstrb, so the '
        'sampled wstrb is 0 on every accepted AR'),
    'router_request_byte_enable': 15,
    'write_byte_enable_source': 'sampled_write_strobe',
    'sampled_strobe_evidence': (
        'driver_samples[*].pre.protocol_taps[<wstrb tap>] keeps the sampled '
        'value (0 on reads); the CPU beat byte_enable field repeats it and is '
        'never rewritten'),
}

#: The four-lane request a strobe-less read presents to the router (declared
#: above, never a sampled pin value).
FULL_WORD_BYTE_ENABLE = READ_TRANSFER_DECLARATION['router_request_byte_enable']


class GeneratedAxiLiteMemorySession(GeneratedNativeMemorySession):
    artifact_kind = 'axi4_lite_cpu'
    runtime_kind = 'axi4_lite_cpu'
    service_schema = 'generated_axi4_lite_memory_service.v1'
    #: The *sampled* read request strobe of this protocol: always 0.  The
    #: declared whole-word granularity lives in ``READ_TRANSFER_DECLARATION``;
    #: this attribute stays the real pin value so an unexpected non-zero read
    #: strobe is refused instead of reinterpreted.
    read_request_be = READ_TRANSFER_DECLARATION['sampled_read_strobe']
    read_transfer_declaration = READ_TRANSFER_DECLARATION

    def __init__(self, artifact, *, base_dir, cache_dir, memory,
                 router: DataflowRouter | None = None, defer_mmio: bool = True,
                 **kwargs):
        if router is not None and not isinstance(router, DataflowRouter):
            raise ValueError('AXI4-Lite CPU router must be a DataflowRouter')
        if type(defer_mmio) is not bool:
            raise ValueError('AXI4-Lite defer_mmio must be boolean')
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir,
                         memory=memory, **kwargs)
        self.router = router
        #: A routed beat is *accepted* on this CPU's real pins and delivered when
        #: the shared executor steps the declared target, exactly like the AHB
        #: row: the shared MMIO executor joins a queued acceptance to its router
        #: delivery and to the target's own sample, so the inline path has no
        #: acceptance row to join.
        self.defer_mmio = defer_mmio
        self.mmio_write_count = 0
        self.mmio_read_count = 0
        self._axil_observation = None
        self._waiting_fetch = None
        if router is not None:
            # One routed target access per local step; the beat is queued and
            # drained at the target's own step.
            self.max_mmio_target_accesses_per_step = 1

    def identity_document(self):
        identity = super().identity_document()
        identity['axi_lite_service_schema_version'] = identity.pop('native_service_schema_version')
        return identity

    def end_case(self):
        try:
            return super().end_case()
        finally:
            if self.router is not None and self._queued_mmio:
                self.router.cancel_for_ledger(self.service.ledger)
            self._queued_mmio = False

    def begin_case(self, testcase_id):
        super().begin_case(testcase_id)
        self._waiting_fetch = None

    # ------------------------------------------------------------------
    # Declared instruction-fetch identity: the sampled ARPROT[2] tap
    # ------------------------------------------------------------------
    def _protocol_observation(self):
        """The admitted CPU protocol observation contract of this artifact.

        AXI4-Lite has no dedicated instruction-identity pin (the RTL drives
        ``mem_axi_arprot = mem_instr ? 3'b100 : 3'b000``), so the fetch flag is
        only observable through the harness' sampled ``arprot`` tap.  The trace
        declares it (``fetch_observation``); the gate authenticates that the tap
        is a real admitted ABI wire, and only then may a reader use it.  An
        artifact without the declaration is refused instead of assumed.
        """
        if self._axil_observation is None:
            from myfuzz.integration.axil_cpu_protocol_observations import (
                axi4lite_cpu_protocol_observations)
            self._axil_observation = axi4lite_cpu_protocol_observations(
                self._artifact_document)
        return self._axil_observation

    def _sampled_request_is_fetch(self):
        """Is the request being serviced the declared instruction fetch?

        The pinned CPU registers ``mem_addr``/``mem_instr``/``mem_wstrb`` and
        holds them stable until ``mem_ready``, and ``mem_axi_araddr``/
        ``mem_axi_arprot`` are direct assigns of those registers
        (``picorv32.v:2775-2783``), so the sampled ``araddr``/``arprot`` at the
        tick the adapter's request is accepted describe *that* read.  Requiring
        the sampled ``araddr`` to equal the accepted address keeps this a join
        of pins to the request, never a guess.
        """
        if not self.last_samples:
            return False
        pre = (self.last_samples[-1].get('pre') or {})
        backend = pre.get('backend') or {}
        taps = pre.get('protocol_taps') or {}
        observation = self._protocol_observation()
        signals = observation['signals']
        declaration = observation['fetch_observation']
        address = backend.get('m_req_addr')
        if backend.get('m_req_write') or type(address) is not int:
            return False
        if taps.get(signals['araddr']) != address:
            return False
        flag = taps.get(signals[declaration['role']])
        if type(flag) is not int:
            return False
        return bool((flag >> declaration['bit']) & 1)

    def declare_instruction_slots(self, address, count=1):
        """Reserve fetch slots; the fetch identity is the declared ARPROT tap.

        Differs from the generic native session only in *where* the identity
        comes from: this CPU exports no physical instruction marker, so the
        authenticated ``arprot`` observation is the declaration instead.
        """
        if self.process is not None or self._case_id is not None:
            raise RuntimeError('native instruction slots require pre-start declaration')
        self._protocol_observation()
        self.memory.declare_instruction_slots(address, count)
        self._online_instruction_slots = True

    @property
    def waiting_instruction_address(self):
        """No fetch is ever left *offered but unaccepted* on this row.

        The generic native session withholds the adapter's request until the
        declared word exists.  Here the generated AXI4-Lite adapter has already
        accepted the AR (the core holds ``mem_valid`` and waits for ``R``), so a
        fetch that has no word yet is parked *after* acceptance
        (``parked_instruction_address``) and there is never an offered fetch for
        a caller to observe.  ``None`` is the truthful answer for that property's
        documented meaning.
        """
        return None

    @property
    def parked_instruction_address(self):
        """Address of the accepted fetch still waiting for its declared word."""
        waiting = self._waiting_fetch
        return None if waiting is None else waiting[1]

    def _check_native_online_acceptance(self, pre, sample):
        # Same rule as the generic native session, but the fetch identity is the
        # declared ARPROT tap instead of a physical instruction marker.
        if not self._online_instruction_slots:
            return
        if not self._sampled_request_is_fetch():
            return
        if pre['m_req_write'] or (self.router is not None
                                  and self.router.owns(pre['m_req_addr'])):
            raise ProtocolEnvironmentError(
                'AXI4-Lite instruction fetch cannot write or reach MMIO')

    def accept_instructions(self, address, data, *, source_event_id):
        acceptance = super().accept_instructions(
            address, data, source_event_id=source_event_id)
        self._resume_instruction()
        return acceptance

    def _resume_instruction(self):
        """Answer the parked fetch once its declared word is materialised."""
        waiting = self._waiting_fetch
        if waiting is None:
            return
        key, address = waiting
        try:
            snapshot = self.service.read(key, address, width_bytes=4)
        except InstructionNotReady:
            return
        self._waiting_fetch = None
        self._pending = (snapshot.value, key.source_sequence)

    # ------------------------------------------------------------------
    # Beat service
    # ------------------------------------------------------------------
    def _service_accepted_request(self, key, address, write, be, value):
        fetch = self._sampled_request_is_fetch()
        router = self.router
        if router is not None and router.owns(address & ~3):
            if fetch:
                raise ProtocolEnvironmentError(
                    'AXI4-Lite instruction fetch cannot write or reach MMIO')
            # A 32-bit CPU beat: address device windows by the word beat, as the
            # OBI CPU session does, so a byte address inside a window still
            # routes.
            return self._route_mmio(key, address & ~3, write, be, value)
        try:
            return super()._service_accepted_request(key, address, write, be, value)
        except InstructionNotReady:
            if write or not fetch:
                raise ProtocolEnvironmentError(
                    'AXI4-Lite data request reached an unfilled instruction slot')
            # The fetch is accepted once and answered when the bound source
            # materialises the word; no response is produced this tick.
            self._waiting_fetch = (key, address)
            return _QUEUED_RESPONSE

    def _route_mmio(self, key, address, write, be, value):
        # Declared read granularity: a read transfers the whole addressed word,
        # so the routed request presents four lanes even though the sampled
        # strobe is 0 on a read (AXI4-Lite has no read strobe).  A write keeps
        # the sampled strobe.  Nothing is rewritten: the backend ``be`` still has
        # to equal ``read_request_be`` on a read, and the real ``wstrb`` tap
        # stays in ``driver_samples``.
        request_byte_enable = be if write else FULL_WORD_BYTE_ENABLE
        if self.defer_mmio:
            if self._queued_mmio or self._pending is not None:
                raise ValueError('AXI4-Lite routed request already pending')
            self._queued_mmio = True

            def complete(response):
                if not self._queued_mmio:
                    raise ValueError('AXI4-Lite routed callback after cancellation')
                if (type(response) is not tuple or len(response) != 2
                        or type(response[0]) is not int or not 0 <= response[0] < 1 << 32
                        or type(response[1]) is not int or response[1] not in (0, 1)):
                    raise ValueError('AXI4-Lite routed target response malformed')
                self._pending = (response[0], key.source_sequence)
                self._pending_error = response[1]
                self._queued_mmio = False
                if write:
                    self.mmio_write_count += 1
                else:
                    self.mmio_read_count += 1

            try:
                accepted = self.router.enqueue(self.service.ledger, key, address=address,
                    write=bool(write), wdata=value, be=request_byte_enable,
                    beat_bytes=4, callback=complete)
                if accepted is not True:
                    raise ValueError('AXI4-Lite routed request was not newly accepted')
            except BaseException:
                self._queued_mmio = False
                raise
            return _QUEUED_RESPONSE
        response = self.router.transact(self.service.ledger, key, address=address,
            write=bool(write), wdata=value, be=request_byte_enable, beat_bytes=4)
        if type(response) is not tuple or len(response) != 2:
            raise ProtocolEnvironmentError('AXI4-Lite routed target response malformed')
        if write:
            self.mmio_write_count += 1
        else:
            self.mmio_read_count += 1
        return response[0]
