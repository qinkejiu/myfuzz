"""Reduced dual AXI4 CPU session drivable by the generic F1-F4 executor.

``GeneratedReducedAxiCpuSession`` already serves the pinned VexiiRiscv fetch and
LSU faces from :class:`~myfuzz.scenario.memory.PersistentMemory`, and already
queues LSU MMIO through an opt-in :class:`~myfuzz.scenario.router.DataflowRouter`.
The generic executor
(:class:`~myfuzz.integration.compiled_mmio.MmioRuntime`) needs three more
things from a CPU session, and none of them can be added to that shared module
from outside it:

``router=``
    The executor constructs *every* CPU session with ``memory=`` and
    ``router=``; the shared session names the same object ``mmio_router=``.

online instruction slots
    The executor declares fetch slots before startup and supplies their words
    *after* the core has already left reset (``declare_instruction_slots`` /
    ``accept_instructions``), because the fuzz input is only known then.

parked fetch address
    One case ends at the first unmaterialized slot, so the session has to
    report that slot through ``waiting_instruction_address`` (the shared
    session has no such property).

This subclass adds exactly those three and keeps the shared single-beat service
authoritative for everything else.  It does not re-implement the AXI4 ABI:

* the accepting edge, the response beats, the strobe/lane and hold checks and
  the ``driver_samples`` evidence all stay the shared session's;
* the fetch is *accepted on the real pins first* (this core offers ``ARVALID``
  and waits for ``R``), so a word that does not exist yet is registered at the
  accepting edge: ``ARREADY`` was already high, ``R`` stays low, and the same
  ``MemoryService`` read is repeated once the accepted word arrives.  One
  accepted ``AR`` therefore yields exactly one ledger entry, under the very
  transaction key of that ``AR``.

The fetch face itself is served through the shared session's own
"who serves this request" hook (``queue_mmio``), which is the single place that
hook is asked for *both* faces, so the wrapper adds no second data path.

Memory flows (F1/F3)
    The generic executor turns the independent memory flows on by passing
    ``memory_commit_receipts``, ``memory_readback_receipts`` and
    ``physical_tick_samples``.  This session then:

    * swaps its plain :class:`~myfuzz.scenario.memory_service.MemoryService`
      for one with a bounded commit stream (and writer-kinded read snapshots)
      over the *same* ``PersistentMemory`` and the *same* ledger, so a real LSU
      store is journaled as ``memory_write_commit`` exactly like the shared OBI,
      Wishbone, AHB and AXI4-Lite CPU rows;
    * serves the data face's RAM reads through the runner-installed
      ``memory_read_authority`` (an instruction fetch never is: this face's
      ``i`` channel is AR/R only), so a real F1 ``LW`` becomes an authenticated
      ``memory_read_issuance``;
    * keeps the measured PRE/POST sample of every advance in a bounded tick
      stream drained by the standard Runner hook.

    With all three options off (the default) every one of those is byte for
    byte the previous session: no commit FIFO, no readback authority, no tick
    stream and no extra identity key.

Scope: memory and router service only.  Nothing here claims retirement, IRQ,
storage-version, F5/F6 or search authority, and a real RTL run is still the
only thing that can accept one of these rows.
"""
from __future__ import annotations

import copy

from myfuzz.scenario.contracts import ProtocolEnvironmentError
from myfuzz.scenario.ledger import TransactionKey
from myfuzz.scenario.memory import InstructionNotReady
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.router import DataflowRouter

from .vexii_axi_session import GeneratedReducedAxiCpuSession

#: Online-slot service identity.  It describes the host side only: how a fetch
#: with no word yet is parked, and which read finally answers it.
ONLINE_SERVICE_SCHEMA = 'reduced_dual_axi_online_instruction.v1'


class GeneratedVexiiAxiMmioSession(GeneratedReducedAxiCpuSession):
    """Reduced dual AXI4 session with ``router=`` and online fetch slots.

    Every other behavior -- the measured one-tick step, the observation
    stream, the reset/quiesce protocol, the single-outstanding write join and
    the ``waiting``/``parked`` split -- is the shared session's, unchanged.
    """

    artifact_kind = 'reduced_dual_axi_cpu'
    #: Options the generic executor passes only when it also turns on the
    #: independent memory flows (F1/F3).  They are implemented (see the module
    #: docstring); any *other* unknown option is still refused by name.
    MEMORY_FLOW_OPTIONS = ('memory_commit_receipts', 'memory_readback_receipts',
                           'physical_tick_samples')

    def __init__(self, artifact, *, base_dir, cache_dir, memory,
                 router=None, mmio_router=None, command_timeout_seconds=10.0,
                 memory_commit_receipts=False, memory_readback_receipts=False,
                 physical_tick_samples=False, **options):
        for name, value in (('memory_commit_receipts', memory_commit_receipts),
                            ('memory_readback_receipts', memory_readback_receipts),
                            ('physical_tick_samples', physical_tick_samples)):
            if type(value) is not bool:
                raise ValueError('reduced AXI MMIO ' + name + ' must be boolean')
        if options:
            raise ValueError('unsupported reduced AXI MMIO session options: '
                             + ','.join(sorted(options)))
        for name, value in (('router', router), ('mmio_router', mmio_router)):
            if value is not None and not isinstance(value, DataflowRouter):
                raise ValueError('reduced AXI MMIO ' + name + ' must be a DataflowRouter')
        if router is not None and mmio_router is not None and router is not mmio_router:
            raise ValueError('reduced AXI MMIO router is declared twice')
        #: The accepted fetch whose declared word does not exist yet.  Kept as
        #: ``(transaction key, aligned beat address)`` exactly like the OBI and
        #: AXI4-Lite rows, so the same "one accepted request, one later answer"
        #: rule and the same ledger key apply.
        self._waiting_fetch = None
        self._declared_slots = 0
        #: Set when this step itself materialized the parked word's read.  The
        #: response is withheld for exactly one measured edge, so the
        #: ``memory_read`` record the executor joins is produced strictly
        #: between the accepted AR and the edge that consumes R (a read
        #: produced outside a step would be journaled after that response).
        self._resumed_in_step = False
        #: Memory-flow switches.  Declared before ``super().__init__`` because
        #: the shared constructor calls the overridden ``_clear``.
        self.memory_commit_receipts_enabled = memory_commit_receipts
        self.memory_readback_receipts_enabled = memory_readback_receipts
        self.memory_read_authority = None
        self._physical_tick_samples_enabled = physical_tick_samples
        self._physical_tick_samples: list[dict] = []
        self._last_drained_physical_tick_samples: tuple[dict, ...] = ()
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir,
                         memory=memory,
                         command_timeout_seconds=command_timeout_seconds,
                         mmio_router=mmio_router if router is None else router)
        if memory_commit_receipts or memory_readback_receipts:
            # The shared session built a plain service over ``self.memory`` and
            # a fresh ledger.  Keep both -- the ledger is what makes one
            # accepted request one entry -- and only widen the service's
            # receipt policy.  Nothing in the shared session caches the old
            # object: every read/write goes through ``self.service``.
            self.service = MemoryService(self.memory, self.service.ledger,
                include_writer_kinds=memory_readback_receipts,
                commit_stream_capacity=256 if memory_commit_receipts else None)
        if physical_tick_samples:
            # Only an opted-in session answers the Runner's standard drain hook.
            # Without the option the attribute stays absent, so the Runner's
            # `callable(getattr(session, 'drain_tick_samples'))` branch (which
            # replaces per-step output routing) is never taken.
            self.drain_tick_samples = self._drain_physical_tick_samples

    # ------------------------------------------------------------------
    # identity
    # ------------------------------------------------------------------
    @property
    def memory_flows_enabled(self) -> bool:
        """Whether this session carries the real F1/F3 receipt streams.

        F1 needs the authenticated read issuance and F3 needs the commit
        stream, and the executor only ever turns both on together; one alone is
        not enough to run the independent memory flows.
        """
        return (self.memory_commit_receipts_enabled
                and self.memory_readback_receipts_enabled)

    def identity_document(self):
        observation = {}
        if self.memory_commit_receipts_enabled:
            observation['memory_commit_stream'] = {
                'schema_version': 'memory_write_commit_stream.v1', 'capacity': 256}
        if self.memory_readback_receipts_enabled:
            observation['memory_read_issuance'] = {
                'schema_version': 'memory_read_authority.v1', 'capacity': 256}
        if self._physical_tick_samples_enabled:
            observation['cpu_physical_tick_stream'] = {
                'schema_version': 'cpu_physical_tick_stream.v1',
                'capacity': 256, 'sampling': 'pre_post'}
        missing = ('no memory commit/readback stream'
                   if not self.memory_flows_enabled else None)
        return {**super().identity_document(), **observation,
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

    # ------------------------------------------------------------------
    # online instruction slots
    # ------------------------------------------------------------------
    def declare_instruction_slots(self, address: int, count: int = 1) -> None:
        """Reserve fetch slots before the harness starts.

        The shared session already owns the fetch face; this only records that
        the slots are *online*, i.e. that their words will arrive through
        :meth:`accept_instructions` instead of a preloaded image.
        """
        if self.process is not None or self._case_id is not None:
            raise RuntimeError('reduced AXI instruction slots require pre-start declaration')
        self.memory.declare_instruction_slots(address, count)
        self._declared_slots += count

    def accept_instructions(self, address: int, data: bytes, *, source_event_id: str):
        """Materialize one declared word; the next step answers a parked fetch.

        Returns the memory's own :class:`~myfuzz.scenario.memory.InstructionAcceptance`,
        which is what the generic executor's replay and the
        ``instruction_source`` journal record are built from.

        The response is deliberately *not* produced here: the resumed read must
        happen inside a measured step, so that the actual ``memory_read`` the
        executor joins sits strictly between the accepted AR and the edge that
        consumes R.  A read performed on the host side would be journaled after
        that response and could not be authenticated.
        """
        return self.service.accept_instructions(
            address, data, source_event_id=source_event_id)

    def _resume_instruction(self) -> None:
        """Answer the parked fetch once its declared word is materialized.

        Idempotent: a still-empty slot leaves the park in place, a filled one
        completes the *same* read that was refused at the accepting edge, under
        the same transaction key, and then releases the response.
        """
        waiting = self._waiting_fetch
        if waiting is None:
            return
        key, address = waiting
        try:
            snapshot = self.service.read(key, address, width_bytes=4)
        except InstructionNotReady:
            return
        state = self._state.get('i') if isinstance(self._state, dict) else None
        read = None if state is None else state['read']
        if read is None:
            # The AR that parked this word is gone (a reset or a clear ran in
            # between), so the read has no response to complete.
            raise ProtocolEnvironmentError('parked reduced AXI fetch lost its accepted AR')
        read['data'] = snapshot.value
        self._waiting_fetch = None

    @property
    def waiting_instruction_address(self):
        """Address of the accepted fetch still waiting for its declared word.

        On this face a fetch is always *accepted* before its word is needed
        (the session holds ``ARREADY`` high whenever no read is outstanding),
        so the offered-but-unaccepted case of the OBI row does not exist here
        and the parked address is the truthful answer.
        """
        waiting = self._waiting_fetch
        return None if waiting is None else waiting[1]

    @property
    def parked_instruction_address(self):
        """The same address: this face parks *after* the AR handshake."""
        return self.waiting_instruction_address

    @property
    def transaction_execution_id(self) -> str:
        """Execution id this session stamps on its own transaction keys.

        The shared session numbers every beat under the live launch nonce
        (``self._execution``).  A memory-flow run instead uses the shared
        ``local-execution`` scope, because the F1/F3 evidence the Runner builds
        (commit documents, read issuance, byte-version relations) is hashed
        into reproducible ``evidence_id`` digests: a per-launch nonce inside
        the key would make every one of them process-local and no ``fresh``
        replay could ever match.  The F1/F3 observers compare a case's
        transactions with this declared scope instead of assuming one.
        """
        if self.memory_flows_enabled:
            return 'local-execution'
        return self._execution or 'local-execution'

    def _key(self, prefix):
        """Number one beat, in the scope this session just declared.

        With the memory flows off this is exactly the shared session's
        nonce-keyed row.  With them on the key uses ``local-execution``, the
        same process-free scope every other shared CPU session uses, so the
        commit/readback evidence of this run is replayable byte for byte.
        """
        if not self.memory_flows_enabled:
            return super()._key(prefix)
        if not self._case_id:
            raise RuntimeError('reduced AXI testcase is not running')
        self._sequences[prefix] += 1
        return TransactionKey(self.transaction_execution_id, self._case_id,
                              self.source_component, self.reset_epoch,
                              'instr' if prefix == 'i' else 'data',
                              self._sequences[prefix])

    def _clear(self):
        super()._clear()
        self._waiting_fetch = None
        self._resumed_in_step = False
        self._physical_tick_samples.clear()

    # ------------------------------------------------------------------
    # measured physical tick stream (opt-in)
    # ------------------------------------------------------------------
    def _drain_physical_tick_samples(self):
        """Drain this session's measured PRE/POST samples for the Runner.

        Only bound as an instance attribute when ``physical_tick_samples`` is
        enabled; see ``__init__``.  Each entry is the driver's own sample with
        its per-process tick translated to the session's cumulative tick, the
        same convention the Wishbone and OBI CPU sessions use.
        """
        samples = self._physical_tick_samples
        self._physical_tick_samples = []
        if samples:
            self._last_drained_physical_tick_samples = tuple(copy.deepcopy(samples))
        return samples

    # ------------------------------------------------------------------
    # request service
    # ------------------------------------------------------------------
    def queue_mmio(self, key, prefix, address, write, value, be, callback):
        """Serve a routed request; park a fetch whose slot has no word yet.

        The shared session asks this hook for every read it is about to serve,
        so this is the one seam the wrapper needs:

        * the LSU face (``d``) keeps the shared router behavior unchanged, and
          its RAM read is performed through the runner-installed read
          authority when the memory flows are enabled, so a real F1 ``LW``
          becomes an ``memory_read_issuance`` record;
        * the fetch face (``i``) is answered from RAM only -- an instruction
          fetch may never write or reach declared MMIO -- and a declared slot
          without a source word is parked instead of failing, because the AR is
          already accepted and the core is entitled to wait for ``R``.
        """
        if prefix == 'd' and not write and self.memory_readback_receipts_enabled:
            router = getattr(self, 'mmio_router', None)
            if router is None or not router.owns(address):
                authority = self.memory_read_authority
                if authority is None:
                    raise RuntimeError('memory readback authority is not installed')
                snapshot = authority.read(self.source_component, self.service,
                                          key, address, width_bytes=4)
                callback((snapshot.value, 0))
                return True
            return super().queue_mmio(key, prefix, address, write, value, be,
                                      callback)
        if prefix != 'i':
            return super().queue_mmio(key, prefix, address, write, value, be, callback)
        if write:
            raise ProtocolEnvironmentError('instruction fetch cannot write')
        router = getattr(self, 'mmio_router', None)
        if router is not None and router.owns(address):
            raise ProtocolEnvironmentError('instruction MMIO is unsupported')
        try:
            snapshot = self.service.read(key, address, width_bytes=4)
        except InstructionNotReady:
            self._waiting_fetch = (key, address)
            return True
        callback((snapshot.value, 0))
        return True

    def _step_local_impl(self, inputs):
        if (self._physical_tick_samples_enabled
                and len(self._physical_tick_samples) >= 256):
            raise RuntimeError('CPU physical tick stream capacity exceeded')
        # Resume the parked fetch inside this measured step, so its read is a
        # real event of this edge; ``_ready_inputs`` withholds the response one
        # more edge so acceptance -> read -> response stays strictly ordered.
        self._resumed_in_step = False
        before = self._waiting_fetch
        self._resume_instruction()
        self._resumed_in_step = before is not None and self._waiting_fetch is None
        outputs = super()._step_local_impl(inputs)
        if self._physical_tick_samples_enabled:
            self._physical_tick_samples.extend(
                {**copy.deepcopy(sample),
                 'local_tick': self._tick_base + sample['local_tick']}
                for sample in self.last_samples)
        return outputs

    def _ready_inputs(self):
        values = super()._ready_inputs()
        if self._resumed_in_step:
            for role in ('rvalid', 'rid', 'rdata', 'rlast', 'rresp'):
                name = 'i_' + role
                if name in values:
                    values[name] = 0
        return values

    def online_instruction_document(self):
        """Detached statement of what this host side did, never of the core."""
        return {
            'schema_version': ONLINE_SERVICE_SCHEMA,
            'declared_slots': self._declared_slots,
            'declared_bytes': self._declared_slots * 4,
            'unmaterialized_slots': [
                list(row) for row in self.memory.reserved_instruction_bytes()],
            'parked_fetch_address': self.parked_instruction_address,
            'parked_fetch_transaction': (None if self._waiting_fetch is None
                                         else copy.deepcopy(str(self._waiting_fetch[0]))),
            'fetch_identity': ('the fetch face declares AR/R only, so every '
                               'accepted i-AR is an instruction fetch'),
        }
