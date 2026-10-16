"""Persistent memory service for the AHB-Lite CPU (CVW, CORE-V Wally).

Why this file exists
    CVW's AHB-Lite external bus is the repository's only AHB boundary, and until
    now no session class admitted it: ``_OPERATIONS`` already registered
    ``ahb_lite_cpu``'s ``STEP_MEMORY`` and the generated driver already emitted the
    four-field beat for it, but no session kind existed to drive it.  A P7-E run
    could therefore report D1..D4 green with F1..F4 *executable* while nothing in
    the repository could start the CPU.  "Executable path" and "runnable session"
    are different claims, and only the first was true.

The beat face is the native completion face
    ``src/myfuzz/protocols/rtl/ahb_lite_memory_target.sv`` presents
    ``req_valid/req_ready/req_write/req_addr/req_wdata/req_be`` out and
    ``rsp_valid/rsp_ready/rsp_rdata/rsp_error`` in on channel ``m`` - the same
    shape the native and AXI4-Lite memory sessions already drive.  So this session
    reuses that handshake, its budgets and its observation checks instead of
    reimplementing them.  What differs is the artifact kind, the read byte lanes
    (CVW asserts all four; the AXI4-Lite register bridge asserts none) and the boot
    behaviour below.

Boot: the first fetch arrives before the program does
    CVW fetches from its configured reset vector the moment reset is released, and
    the derived configuration places that vector inside the external region, so the
    first thing the service ever sees is a fetch whose bytes may not exist yet.
    There are three possible answers and only one is honest:

    * refuse it - wrong: it is a legal request from a correctly configured core;
    * answer it with zeros - worse: the core would decode and execute them;
    * hold the transfer until the session supplies the bytes - correct, and exactly
      what AHB-Lite provides for.  The subordinate extends a transfer by keeping
      ``HREADYEXT`` low, which it does for as long as this session withholds the
      response; no error completion is invented.  The driver's own bounded wait is
      what bounds the stall, and the profile's ``max_wait_cycles`` is that bound.

    The mechanism is the repository's existing on-demand instruction supply: the
    address is declared as an instruction slot, reading a declared-but-unfilled
    slot raises ``InstructionNotReady``, and the transfer resumes once
    ``accept_instructions`` fills it.  :meth:`GeneratedAhbMemorySession.step_local`
    is where the resume check lives.
"""
from __future__ import annotations

from myfuzz.scenario.memory import PersistentMemory
from myfuzz.scenario.router import DataflowRouter

from .native_session import GeneratedNativeMemorySession


class GeneratedAhbMemorySession(GeneratedNativeMemorySession):
    """RAM/ROM service for the AHB-Lite CPU, on the native completion face.

    Holds a boot fetch whose bytes the session has not supplied yet instead of
    refusing it or answering it with zeros.
    """

    artifact_kind = 'ahb_lite_cpu'
    runtime_kind = 'ahb_lite_cpu'
    service_schema = 'generated_ahb_lite_memory_service.v1'
    #: CVW's reads assert every byte lane.
    read_request_be = 15

    def __init__(self, artifact, *, base_dir, cache_dir, memory,
                 router: DataflowRouter | None = None, **kwargs):
        # A router is accepted for the same reason the AXI4-Lite session accepts
        # one: a CPU beat whose address falls inside a declared device window must
        # be served by the real target rather than by local RAM.  It is optional,
        # so without one the session is RAM/ROM only.
        if router is not None and not isinstance(router, DataflowRouter):
            raise ValueError('AHB-Lite CPU router must be a DataflowRouter')
        if not isinstance(memory, PersistentMemory):
            raise ValueError('AHB-Lite CPU requires persistent memory')
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir,
                         memory=memory, **kwargs)
        self.router = router
        self.mmio_write_count = 0
        self.mmio_read_count = 0
        # The CPU bootstraps from a configured reset vector, so the session knows
        # the one address it must be ready to hold before the core ever asks for it.
        # Without this the first fetch would be served as ordinary uninitialised RAM
        # (a silent zero, which the core would decode and execute) instead of being
        # held for the program the session is about to supply.
        contract = artifact.runtime_document.get('boot_contract') or {}
        boot_base = contract.get('configured_boot_base')
        if type(boot_base) is not int or boot_base < 0 or boot_base % 4:
            raise ValueError('AHB-Lite CPU requires a configured boot base')
        self.boot_base = boot_base
        self.declare_boot_instruction_slot()
        if router is not None:
            self.max_mmio_target_accesses_per_step = 1

    def identity_document(self):
        identity = super().identity_document()
        identity['ahb_lite_service_schema_version'] = identity.pop(
            'native_service_schema_version')
        return identity

    def declare_boot_instruction_slot(self):
        """Reserve the boot word so an unsupplied program is *held*, not zero-read.

        Declaring the slot is what makes the difference: an undeclared word reads as
        ordinary RAM (a determined zero), while a declared-but-unfilled slot raises
        ``InstructionNotReady`` and is therefore held.  It is idempotent, and it is
        re-established after a reset so a fresh boot gets the same treatment.
        """
        try:
            self.memory.declare_instruction_slots(self.boot_base, 1)
        except ValueError:
            # The word is already determined (the session supplied it, or a previous
            # case materialised it).  That is the healthy steady state, not an error.
            pass

    def reset_local(self):
        result = super().reset_local()
        # A reset cancels every outstanding response, and the boot word must be
        # held again for the next boot.
        self.declare_boot_instruction_slot()
        return result

    def begin_case(self, testcase_id):
        super().begin_case(testcase_id)
        self.declare_boot_instruction_slot()

    def _service_accepted_request(self, key, address, write, be, value):
        router = self.router
        if router is None:
            return self._serve_local(key, address, write, be, value)
        # A 32-bit CPU beat: address device windows by the word beat, as the OBI and
        # AXI4-Lite CPU sessions do, so a byte address inside a window still routes.
        beat_address = address & ~3
        if not router.owns(beat_address):
            return self._serve_local(key, address, write, be, value)
        response = router.transact(self.service.ledger, key, address=beat_address,
                                   write=bool(write), wdata=value, be=be, beat_bytes=4)
        if type(response) is not tuple or len(response) != 2:
            raise ValueError('AHB-Lite routed target response malformed')
        if write:
            self.mmio_write_count += 1
        else:
            self.mmio_read_count += 1
        return response[0]

    def _serve_local(self, key, address, write, be, value):
        """Local RAM/ROM service, on the native completion face.

        An unfilled instruction slot is *not* caught here.  Accepting the beat and
        withholding only the response would not hold the transfer: accepting it
        drives the subordinate into its COMPLETE state, and the subordinate raises
        ``HREADYEXT`` there, so a later response could no longer extend the
        transfer.  The hold therefore has to happen one step earlier, by not
        accepting the beat at all - see :meth:`step_local`.
        """
        return super()._service_accepted_request(key, address, write, be, value)

    def declare_instruction_window(self, address: int, words: int) -> None:
        """Declare `words` consecutive boot-image words as on-demand instruction slots.

        ``PersistentMemory.accept_instructions`` only accepts bytes that sit inside a
        *declared* slot, because that is what distinguishes "an instruction waiting
        for its source" from ordinary RAM bytes.  The constructor declares the reset
        word; a whole boot image needs its whole span declared, so this is the
        supported way for a caller to do that rather than reaching into the memory
        object.  Idempotent, and it refuses a span that is already determined.
        """
        if type(words) is not int or words < 1:
            raise ValueError('instruction window must declare at least one word')
        try:
            self.memory.declare_instruction_slots(address, words)
        except ValueError:
            # Already declared, or already determined by a previous boot.
            pass

    def _boot_word_required(self) -> bool:
        """Is the core asking for a boot word the session has not supplied yet?"""
        address = self.boot_base
        try:
            return self.memory.instruction_slot_unmaterialized(address)
        except ValueError:
            # No region covers the boot base, or it is not 4-byte aligned.  Either
            # way there is nothing to hold for; the ordinary service path will
            # report it.
            return False

    def step_local(self, inputs):
        if self._boot_word_required():
            # Hold the transfer open the only way AHB-Lite allows: keep the
            # subordinate from accepting it.  The base implementation derives
            # ``m_req_ready`` from this flag, so setting it for exactly this call
            # makes the driver drive ``req_ready=0`` for one tick; ``m_req_valid``
            # stays high because the core is still waiting, so the request is
            # retried rather than lost, and no error completion is invented.
            self._quiescing = True
            try:
                return super().step_local(inputs)
            finally:
                self._quiescing = False
        return super().step_local(inputs)
