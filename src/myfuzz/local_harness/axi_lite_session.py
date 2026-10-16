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
"""
from myfuzz.scenario.contracts import ProtocolEnvironmentError
from myfuzz.scenario.memory import PersistentMemory
from myfuzz.scenario.router import DataflowRouter

from .native_session import GeneratedNativeMemorySession


class GeneratedAxiLiteMemorySession(GeneratedNativeMemorySession):
    artifact_kind = 'axi4_lite_cpu'
    runtime_kind = 'axi4_lite_cpu'
    service_schema = 'generated_axi4_lite_memory_service.v1'
    read_request_be = 0

    def __init__(self, artifact, *, base_dir, cache_dir, memory,
                 router: DataflowRouter | None = None, **kwargs):
        if router is not None and not isinstance(router, DataflowRouter):
            raise ValueError('AXI4-Lite CPU router must be a DataflowRouter')
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir,
                         memory=memory, **kwargs)
        self.router = router
        self.mmio_write_count = 0
        self.mmio_read_count = 0
        if router is not None:
            # One routed target access per local step; the beat is serviced
            # inline, so the driver reservation must admit it.
            self.max_mmio_target_accesses_per_step = 1

    def identity_document(self):
        identity = super().identity_document()
        identity['axi_lite_service_schema_version'] = identity.pop('native_service_schema_version')
        return identity

    def _service_accepted_request(self, key, address, write, be, value):
        router = self.router
        if router is None:
            return super()._service_accepted_request(key, address, write, be, value)
        # A 32-bit CPU beat: address device windows by the word beat, as the OBI
        # CPU session does, so a byte address inside a window still routes.
        beat_address = address & ~3
        if not router.owns(beat_address):
            return super()._service_accepted_request(key, address, write, be, value)
        response = router.transact(self.service.ledger, key, address=beat_address,
            write=bool(write), wdata=value, be=be, beat_bytes=4)
        if type(response) is not tuple or len(response) != 2:
            raise ProtocolEnvironmentError('AXI4-Lite routed target response malformed')
        if write:
            self.mmio_write_count += 1
        else:
            self.mmio_read_count += 1
        return response[0]
