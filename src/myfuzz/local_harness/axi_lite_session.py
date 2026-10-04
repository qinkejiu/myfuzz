"""Persistent memory service for the source-pinned no-response-code AXI4-Lite CPU."""
from .native_session import GeneratedNativeMemorySession


class GeneratedAxiLiteMemorySession(GeneratedNativeMemorySession):
    artifact_kind = 'axi4_lite_cpu'
    runtime_kind = 'axi4_lite_cpu'
    service_schema = 'generated_axi4_lite_memory_service.v1'
    read_request_be = 0

    def identity_document(self):
        identity = super().identity_document()
        identity['axi_lite_service_schema_version'] = identity.pop('native_service_schema_version')
        return identity
