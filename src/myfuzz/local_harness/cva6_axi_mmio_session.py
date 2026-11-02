"""Packed single-port CVA6 session drivable by the generic F2/F4 executor.

The pinned CVA6 top exposes exactly one AXI4 master port
(``processor.memory.unified``, ``axi4/1``, 64-bit data/address, 64-bit user)
and both the instruction and the data side of the core reach it through the
same two packed struct ports.  :class:`~myfuzz.local_harness.cva6_axi4_session.GeneratedCva6Axi4Session`
already serves that port from host RAM and forwards routed MMIO, but the
generic executor (:class:`myfuzz.integration.compiled_mmio.MmioRuntime`) needs
three more things from a CPU session, and none of them can be added to that
module from outside it:

``router=``
    The executor constructs *every* CPU session with ``memory=`` and
    ``router=``, and expects the routed target access of one step to be parked
    until the target is stepped (``defer_mmio=True``).

online instruction slots
    The executor declares fetch slots before startup and supplies their words
    *after* the core has already left reset (``declare_instruction_slots`` /
    ``accept_instructions``), because the fuzz input is only known then.

parked fetch address
    The session has to report the accepted-but-unanswered read through
    ``waiting_instruction_address``.

Truthfulness of the two faces
    The pinned configuration gives this port no user/prot instruction attribute
    (see the module-level evidence in
    :mod:`myfuzz.integration.cva6_axi_mmio`), so this session only ever numbers
    one request channel (``memory``).  It does not label a beat as a fetch
    itself: the fetch identity is the ARID/RID map the *adapter* declares from
    the pinned RTL (``wt_axi_adapter.sv`` arbitrates the I-cache as request 0
    and decodes return id 0 as the I-cache), and without that declaration the
    certificate keeps the data-only refusal.  ``identity_document`` states which
    of the two applies.

The independent F1/F3 memory flows (opt-in)
    ``memory_commit_receipts`` / ``memory_readback_receipts`` are refused by
    default: the shared packed-port session has neither a commit FIFO nor
    writer-aware read receipts.  Only an adapter that declares
    ``memory_receipts_on_unified`` (this row's, see
    ``integration/cva6_axi_mmio.py``) makes the executor ask for them, and then
    this class rebuilds its :class:`~myfuzz.scenario.memory_service.MemoryService`
    over the *same* ledger with ``commit_stream_capacity=256`` and
    ``include_writer_kinds=True``.  Nothing else about the port changes: a store
    is still committed at its real ``awsize`` width and a read is still served
    at its real ``arsize`` width.

Fetch/beat granularity
    ``CVA6ConfigDcacheType = WT`` with ``CachedRegion = 0x8000_0000..0xC000_0000``
    makes any fetch outside that window a *non-cacheable* single-beat access
    (``cva6_icache.sv:139-177``), so a declared instruction window outside the
    cached regions is fetched one 8-byte beat per word and is never cached.
    Each such beat is served only when *every* byte it covers has been
    materialized, so the core stalls exactly at the host's fragment boundary
    instead of executing undetermined bytes.
"""
from __future__ import annotations

import copy
from collections.abc import Mapping

from myfuzz.scenario.contracts import ProtocolEnvironmentError
from myfuzz.scenario.ledger import TransactionKey
from myfuzz.scenario.memory import InstructionNotReady
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.router import DataflowRouter

from .cva6_axi4_fields import CVA6_AXI_STEP_PORTS, CVA6_AXI_WIDTHS
from .cva6_axi4_session import (GeneratedCva6Axi4Session, _beat_address,
                               _check_address, _check_write_strobe)

#: Online-slot service identity: host side only (how a fetch without a
#: materialized word is parked, and which read finally answers it).
ONLINE_SERVICE_SCHEMA = 'cva6_packed_axi4_online_instruction.v1'

#: Why no instruction hop is claimed when the adapter could not re-read the
#: pinned RTL and therefore makes no address-ID declaration.  Repeated verbatim
#: in the session identity, the adapter traces and the certificate so the
#: refusal can never silently disappear, and never used for a row that *does*
#: carry ``instruction_id_map``.
INSTRUCTION_HOP_REFUSAL = (
    'the pinned CVA6 top ties every address-channel user bit to zero '
    '(core/axi_shim.sv:263 ar.user, core/axi_shim.sv:101 aw.user), ties ARPROT '
    'to 3\'b0 (core/axi_shim.sv:258) and has one packed AXI4 master for both '
    'the I$ and the D$ (core/cva6.sv:1512), so no accepted beat carries an '
    'instruction attribute; the fetch hop stays unclaimed')


def _beat_access(address: int, size: int) -> tuple[int, int, int]:
    """``(addressed_byte, lane, width)`` of one aligned AXI4 beat.

    The pinned core drives ``arsize/awsize`` to the real transfer width and
    only ever issues aligned accesses (``_check_address`` refuses the rest),
    so the beat carries exactly ``1 << size`` bytes starting at the addressed
    lane of the 64-bit bus.
    """
    width = 1 << size
    lane = address & 7
    if lane + width > 8 or address % width:
        raise ProtocolEnvironmentError(
            'CVA6 AXI4 beat is not one aligned transfer inside the 64-bit bus')
    return address, lane, width


class GeneratedCva6AxiMmioSession(GeneratedCva6Axi4Session):
    """Serve the real packed CVA6 AXI4 port and the generic executor at once.

    Everything about the AXI4 ABI -- the accepting edges, the response beats,
    the strobe/lane and hold checks, the reset/quiesce protocol and the
    ``driver_samples`` evidence -- stays the shared session's.  This subclass
    only adds the executor's three pieces plus the two journal refinements
    (real per-beat access width, and one measured edge between the read
    journal entry and the edge that consumes the response).
    """

    artifact_kind = 'cva6_packed_axi4_cpu'
    #: Options the generic executor passes only when it also turns on the
    #: independent memory flows (F1/F3).  The two receipt streams are
    #: implemented below; ``physical_tick_samples`` is not, and is refused by
    #: name instead of being accepted and never emitted.
    MEMORY_FLOW_OPTIONS = ('memory_commit_receipts', 'memory_readback_receipts',
                           'physical_tick_samples')

    def __init__(self, artifact, *, base_dir, cache_dir, memory, router=None,
                 defer_mmio=True, command_timeout_seconds=10.0,
                 memory_commit_receipts=False, memory_readback_receipts=False,
                 **options):
        for name, value in (('memory_commit_receipts', memory_commit_receipts),
                            ('memory_readback_receipts', memory_readback_receipts)):
            if type(value) is not bool:
                raise ValueError('packed CVA6 ' + name + ' must be boolean')
        for name, value in options.items():
            if name in self.MEMORY_FLOW_OPTIONS:
                # ``physical_tick_samples`` stays unimplemented on this row: the
                # executor never asks for it here (see
                # integration/compiled_mmio.py), and silently accepting the
                # keyword would advertise a stream this session does not emit.
                raise ValueError(
                    'packed CVA6 does not implement this memory-flow option: '
                    + name)
            raise ValueError('unsupported packed CVA6 MMIO session options: '
                             + ','.join(sorted(options)))
        for name, value in (('router', router),):
            if value is not None and not isinstance(value, DataflowRouter):
                raise ValueError('packed CVA6 ' + name + ' must be a DataflowRouter')
        if type(defer_mmio) is not bool or (defer_mmio and router is None):
            raise ValueError('packed CVA6 defer_mmio requires a router')
        #: Accepted read whose word is not materialized yet, kept as
        #: ``(transaction key, addressed byte)`` so the same "one accepted
        #: request, one later answer" rule and the same ledger key apply.
        self._waiting_fetch = None
        self._declared_slots = 0
        #: Memory-flow switches.  Declared before ``super().__init__`` because
        #: the shared constructor calls the overridden ``_clear``.
        self.memory_commit_receipts_enabled = memory_commit_receipts
        self.memory_readback_receipts_enabled = memory_readback_receipts
        self.memory_read_authority = None
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir,
                         memory=memory, router=router, defer_mmio=defer_mmio,
                         command_timeout_seconds=command_timeout_seconds)
        if memory_commit_receipts or memory_readback_receipts:
            # The shared session built a plain service over ``self.memory`` and a
            # fresh ledger.  Keep both -- the ledger is what makes one accepted
            # request one entry, and it is also this row's MMIO ledger -- and
            # only widen the service's receipt policy.  Nothing in the shared
            # session caches the old object: every read and write goes through
            # ``self.service``.
            self.service = MemoryService(self.memory, self.service.ledger,
                include_writer_kinds=memory_readback_receipts,
                commit_stream_capacity=256 if memory_commit_receipts else None)
        #: One channel means one ledger.  A routed MMIO transaction is one more
        #: transaction of the same monotonic sequence, exactly as the shared
        #: AHB/AXI4-Lite unified rows do (they queue into ``service.ledger``),
        #: so the executor can look a routed delivery up by its beat sequence.
        self.mmio_ledger = self.service.ledger

    # ------------------------------------------------------------------
    # identity
    # ------------------------------------------------------------------
    @property
    def memory_flows_enabled(self) -> bool:
        """Whether this session carries the real F1/F3 receipt streams.

        F1 needs the writer-aware read receipts and F3 needs the commit stream,
        and the executor only ever turns both on together; one alone is not
        enough to run the independent memory flows.  ``False`` is the default,
        so an ordinary F2/F4 run keeps exactly the previous behavior.
        """
        return (self.memory_commit_receipts_enabled
                and self.memory_readback_receipts_enabled)

    def identity_document(self) -> dict[str, object]:
        observation = {}
        if self.memory_commit_receipts_enabled:
            observation['memory_commit_stream'] = {
                'schema_version': 'memory_write_commit_stream.v1', 'capacity': 256}
        if self.memory_readback_receipts_enabled:
            observation['memory_read_issuance'] = {
                'schema_version': 'memory_read_authority.v1', 'capacity': 256}
        missing = ('the unified port numbers one request channel and this session '
                   'was not built with the opt-in receipt streams')
        return {**super().identity_document(), **observation,
                'unified_channel_model': 'single packed AXI4 master; one '
                                         'request channel and one sequence '
                                         'counter, no user/prot instruction '
                                         'attribute (the fetch identity is the '
                                         'declared ARID/RID map, see '
                                         'integration/cva6_axi_mmio.py)',
                'instruction_fetch_identity': {
                    'provable': True,
                    'reason': 'declared by integration/cva6_axi_mmio.py from the '
                              'pinned WT AXI adapter: ar.id carries the arbiter '
                              'index and rid 0 returns to the I-cache',
                    'refusal_without_declaration': INSTRUCTION_HOP_REFUSAL},
                'online_instruction_service': {
                    'schema_version': ONLINE_SERVICE_SCHEMA,
                    'executor_router_keyword': 'router',
                    'parked_fetch': 'acceptance_first_then_withheld_response',
                    'declared_slots': self._declared_slots,
                    'supported_flows': (['F1', 'F2', 'F3', 'F4']
                                        if self.memory_flows_enabled
                                        else ['F2', 'F4']),
                    'refused_flows': ({} if self.memory_flows_enabled
                                      else {'F1': missing, 'F3': missing}),
                }}

    def _clear(self) -> None:
        super()._clear()
        self._waiting_fetch = None

    # ------------------------------------------------------------------
    # online instruction slots
    # ------------------------------------------------------------------
    def declare_instruction_slots(self, address: int, count: int = 1) -> None:
        """Reserve fetch slots before the harness starts."""
        if self.process is not None or self._case_id is not None:
            raise RuntimeError('packed CVA6 instruction slots require '
                               'pre-start declaration')
        self.memory.declare_instruction_slots(address, count)
        self._declared_slots += count

    def accept_instructions(self, address: int, data: bytes, *, source_event_id: str):
        """Materialize one declared word; the parked read answers later.

        The response is deliberately *not* produced here: the resumed read
        happens inside a measured step, so the ``memory_read`` record the
        executor joins sits strictly between the accepted ``AR`` and the edge
        that consumes ``R``.
        """
        return self.service.accept_instructions(
            address, data, source_event_id=source_event_id)

    @property
    def waiting_instruction_address(self):
        """Addressed byte of the accepted read still waiting for its word.

        On this face a read is always *accepted* before its data is needed
        (the session holds ``ARREADY`` high whenever no read is outstanding),
        so the parked address is the truthful answer.  The pinned core issues
        one 8-byte beat per fetched word outside the cached regions
        (``cva6_icache.sv:162``), which is why the reported address is the
        beat's addressed byte and not necessarily the fragment's next word.
        """
        waiting = self._waiting_fetch
        return None if waiting is None else waiting[1]

    @property
    def parked_instruction_address(self):
        """The same address: this face parks *after* the AR handshake."""
        return self.waiting_instruction_address

    # ------------------------------------------------------------------
    # one request channel
    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    # request service
    # ------------------------------------------------------------------
    def _ready_inputs(self, irq_external: int, irq_timer: int) -> dict[str, int]:
        """The shared ready/response edge, with the two journal refinements.

        * an accepted RAM read is served at its *real* transfer width
          (``1 << arsize``) at the addressed byte, not as a whole 8-byte word;
        * a read whose bytes include an unmaterialized instruction slot parks
          instead of failing (the AR is already accepted and the core is
          entitled to wait for ``R``);
        * a read served on this edge withholds ``R`` for exactly one measured
          edge, so ``accepted AR < memory_read < R`` stays strictly ordered.
        """
        state = self._state
        values = {name: 0 for name in CVA6_AXI_STEP_PORTS}
        values['irq_external'] = irq_external
        values['irq_timer'] = irq_timer
        if state['b'] is not None:
            values['axi_bvalid'] = 1
            values['axi_bid'] = state['b']
        read = state['read']
        if read is not None:
            if read['data'] is None and not read.get('mmio', False):
                address = _beat_address(read['addr'], read['index'], read['size'],
                                        read['burst'], read['length'])
                target, lane, width = _beat_access(address, read['size'])
                try:
                    snapshot = self.service.read(read['key'], target,
                                                 width_bytes=width)
                except InstructionNotReady:
                    self._waiting_fetch = (read['key'], target)
                    snapshot = None
                if snapshot is not None:
                    self._waiting_fetch = None
                    read['data'] = snapshot.value << (8 * lane)
                    read['hold_one_edge'] = True
            if read['data'] is not None and not read.pop('hold_one_edge', False):
                values['axi_rvalid'] = 1
                values['axi_rid'] = read['id']
                values['axi_rdata'] = read['data']
                values['axi_rlast'] = int(read['index'] == read['length'] - 1)
        # One transaction in flight at a time.  The pinned core never needs
        # more (max_outstanding = 1 in the declared capabilities), and a single
        # monotonic channel is only reorder-free when the accepting order, the
        # journal order and the ledger order are the same order.
        blocked = (read is not None or self._waiting_fetch is not None
                   or state['write'] is not None or state['b'] is not None
                   or self._queued_mmio or self._queued_mmio_write)
        values['axi_awready'] = int(not self._quiescing and not blocked)
        values['axi_wready'] = int(not self._quiescing and not blocked
                                   and len(state['wbeats']) < 4)
        values['axi_arready'] = int(not self._quiescing and not blocked)
        return values

    def _commit_writes(self) -> None:
        """The shared commit, at the real per-beat width.

        A 64-bit AXI4 write beat carries up to eight byte lanes; the pinned
        core drives ``awsize`` to the real store width and enables only the
        addressed lanes, so the journal entry is the store the core performed
        (e.g. a 32-bit ``SW`` becomes a four-byte write with byte enable 0xF),
        never the whole 64-bit bus word.
        """
        state = self._state
        write = state['write']
        if write is None or not state['wbeats']:
            return
        wdata, wstrb, last = state['wbeats'].pop(0)
        expected_last = write['index'] == write['length'] - 1
        if bool(last) != expected_last:
            raise ProtocolEnvironmentError('CVA6 AXI4 WLAST disagrees with AWLEN')
        address = _beat_address(write['addr'], write['index'], write['size'],
                                write['burst'], write['length'])
        _check_write_strobe(address, write['size'], wstrb)
        self.write_beats += 1
        write['index'] += 1
        if expected_last:
            if state['wbeats']:
                raise ProtocolEnvironmentError('CVA6 AXI4 extra W beat after WLAST')
            state['write'] = None
            self.write_bursts += 1
        if write['length'] != 1:
            raise ProtocolEnvironmentError(
                'CVA6 AXI4 multi-beat write has no per-beat journal identity')
        target, lane, width = _beat_access(address, write['size'])
        mask = (wstrb >> lane) & ((1 << width) - 1)
        if not mask:
            raise ProtocolEnvironmentError('CVA6 AXI4 W beat enables no byte')
        value = (wdata >> (8 * lane)) & ((1 << (8 * width)) - 1)
        if self.router is not None and self.router.owns(target):
            if width != 4 or mask != 0xf:
                raise ProtocolEnvironmentError(
                    'CVA6 AXI4 MMIO supports one aligned 32-bit beat')
            response_id = write['id']

            def complete_mmio_write(_response: tuple[int, int]) -> None:
                state['b'] = response_id

            self._route_mmio(key=write['key'], address=target, write=True,
                             data=value, byte_enable=mask, width=width,
                             callback=complete_mmio_write)
            return
        self.service.write(write['key'], target, value, width_bytes=width,
                           byte_enable=mask)
        if expected_last:
            state['b'] = write['id']

    def _route_mmio(self, *, key: TransactionKey, address: int, write: bool,
                    data: int, byte_enable: int, width: int, callback) -> None:
        """Route one real 4-byte-or-narrower beat to the declared target."""
        if width != 4:
            raise ProtocolEnvironmentError(
                'CVA6 AXI4 MMIO beat is not one 32-bit register access')
        if self.router is None:
            raise ProtocolEnvironmentError(
                'CVA6 AXI4 request targets undeclared MMIO')
        request_byte_enable = byte_enable if write else 0xf
        if self.defer_mmio:
            self._queued_mmio += 1
            if write:
                self._queued_mmio_write = True

            def completed(response: tuple[int, int]) -> None:
                self._queued_mmio -= 1
                if write:
                    self._queued_mmio_write = False
                    self.mmio_write_count += 1
                else:
                    self.mmio_read_count += 1
                callback(response)

            try:
                fresh = self.router.enqueue(self.mmio_ledger, key,
                    address=address, write=write, wdata=data,
                    be=request_byte_enable, beat_bytes=4, callback=completed)
            except BaseException:
                self._queued_mmio -= 1
                if write:
                    self._queued_mmio_write = False
                raise
            if not fresh:
                self._queued_mmio -= 1
                if write:
                    self._queued_mmio_write = False
                raise RuntimeError('duplicate packed CVA6 MMIO acceptance')
            return
        response = self.router.transact(self.mmio_ledger, key,
            address=address, write=write, wdata=data, be=request_byte_enable,
            beat_bytes=4)
        if write:
            self.mmio_write_count += 1
        else:
            self.mmio_read_count += 1
        callback(response)

    # ------------------------------------------------------------------
    # accepted beats
    # ------------------------------------------------------------------
    def _step_local_service(self, inputs: Mapping[str, int]) -> Mapping[str, object]:
        """The shared step, with the per-transaction key of each beat."""
        values = self._ready_inputs(inputs.get('irq_external', 0),
                                    inputs.get('irq_timer', 0))
        receipt = self.command('STEP_CVA6_AXI4',
                               tuple(values[name] for name in CVA6_AXI_STEP_PORTS))
        self._last_axi_receipt = copy.deepcopy({'status': receipt.status,
            'new_ticks': receipt.new_ticks, 'payload': receipt.payload})
        if receipt.status == 'error':
            message = f'{receipt.error_code}: {receipt.error_detail}'
            if receipt.error_code == 'protocol_environment':
                raise ProtocolEnvironmentError(message)
            raise RuntimeError(message)
        payload = receipt.payload
        if (receipt.new_ticks != 1 or not isinstance(payload, dict)
                or payload.get('kind') != self.artifact_kind
                or not isinstance(payload.get('samples'), list)
                or len(payload['samples']) != 1):
            raise ProtocolEnvironmentError('generated CVA6 receipt is not one measured tick')
        pre = payload.get('pre_backend')
        expected = {'axi_' + role for role in CVA6_AXI_WIDTHS}
        if (not isinstance(pre, dict) or set(pre) != expected
                or any(type(value) is not int or not 0 <= value < 1 << CVA6_AXI_WIDTHS[name[4:]]
                       for name, value in pre.items())
                or any(pre[name] != value for name, value in values.items()
                       if name not in ('irq_external', 'irq_timer'))
                or payload['samples'][0].get('pre', {}).get('backend') != pre):
            raise ProtocolEnvironmentError('invalid generated CVA6 backend observation')
        self.last_samples = tuple(copy.deepcopy(payload['samples']))
        self._axi_observer.observe(self.last_samples[0])
        row = {name[4:]: value for name, value in pre.items()}

        def handshake(channel: str) -> bool:
            return bool(row[channel + 'valid'] and row[channel + 'ready'])

        aw, w, b, ar, r = (handshake(channel)
                           for channel in ('aw', 'w', 'b', 'ar', 'r'))
        state = self._state
        if b:
            if state['b'] is None or row['bid'] != state['b'] or row['bresp'] != 0:
                raise ProtocolEnvironmentError('CVA6 AXI4 B response mismatch')
            state['b'] = None
        if r:
            read = state['read']
            if (read is None or row['rid'] != read['id'] or row['rresp'] != 0
                    or row['rlast'] != int(read['index'] == read['length'] - 1)):
                raise ProtocolEnvironmentError('CVA6 AXI4 R response mismatch')
            self.read_beats += 1
            read['index'] += 1
            read['data'] = None
            if read['index'] == read['length']:
                state['read'] = None
                self.read_bursts += 1
        if aw:
            if state['write'] is not None:
                raise ProtocolEnvironmentError('CVA6 AXI4 multiple outstanding AW')
            _check_address(row, 'aw')
            self._is_mmio_burst(row, 'aw')
            state['write'] = dict(addr=row['awaddr'], size=row['awsize'],
                                  burst=row['awburst'], length=row['awlen'] + 1,
                                  id=row['awid'], index=0, key=self._key())
        if w:
            state['wbeats'].append((row['wdata'], row['wstrb'], row['wlast']))
        if ar:
            if state['read'] is not None:
                raise ProtocolEnvironmentError('CVA6 AXI4 multiple outstanding AR')
            _check_address(row, 'ar')
            mmio = self._is_mmio_burst(row, 'ar')
            if row['arlen']:
                raise ProtocolEnvironmentError(
                    'CVA6 AXI4 multi-beat read has no per-beat journal identity')
            state['read'] = dict(addr=row['araddr'], size=row['arsize'],
                                 burst=row['arburst'], length=row['arlen'] + 1,
                                 id=row['arid'], index=0, data=None, mmio=mmio,
                                 key=self._key())
            if mmio:
                address, lane, _width = _beat_access(row['araddr'], row['arsize'])
                response_id = row['arid']

                def complete_mmio_read(response: tuple[int, int]) -> None:
                    current = self._state['read']
                    if current is None or current['id'] != response_id:
                        raise ProtocolEnvironmentError(
                            'CVA6 AXI4 MMIO read response lost its source request')
                    current['data'] = response[0] << (8 * lane)
                    current['hold_one_edge'] = True

                self._route_mmio(key=state['read']['key'], address=address,
                                 write=False, data=0, byte_enable=0xf, width=4,
                                 callback=complete_mmio_read)
        self._commit_writes()
        self.memory.advance_step()
        return {'aw_accepted': int(aw), 'w_accepted': int(w),
                'b_consumed': int(b), 'ar_accepted': int(ar),
                'r_consumed': int(r),
                'araddr': row['araddr'] if ar else 0,
                'awaddr': row['awaddr'] if aw else 0,
                'driver_samples': copy.deepcopy(self.last_samples),
                'physical_observations': copy.deepcopy(payload['observations']['physical'])}
