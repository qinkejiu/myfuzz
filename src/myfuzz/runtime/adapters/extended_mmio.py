"""Bound target adapters for the extension buses (TL-UL / AXI4-Lite / AHB-Lite).

The observation and register-bank facts live in one module per bus; this
adapter only binds that module to the admitted component and session so the
generic plan compiler can treat every target the same way.
"""
from hashlib import sha256
from importlib import import_module

from ..contracts import canonical_json_bytes
from .apb3_mmio import BoundMmioAdapter

_SPECS = {
    'tlul.mmio.v1': ('myfuzz.local_harness.tlul_register_session',
                     'GeneratedTlulRegisterSession',
                     'myfuzz.integration.target_tlul', 'tlul_mmio_bank_facts'),
    'axi4lite.mmio.v1': ('myfuzz.local_harness.axi4lite_register_session',
                         'GeneratedAxi4LiteRegisterSession',
                         'myfuzz.integration.target_axi4lite',
                         'axi4lite_mmio_bank_facts'),
    'ahb-lite.mmio.v1': ('myfuzz.local_harness.ahb_lite_register_session',
                         'GeneratedAhbLiteRegisterSession',
                         'myfuzz.integration.target_ahb_lite',
                         'ahb_lite_mmio_bank_facts'),
}


class BoundExtendedMmioAdapter(BoundMmioAdapter):
    """One admitted extension target; internal storage stays unknown."""

    def __init__(self, *, adapter_id, component, session, selection,
                 preparation, endpoint_id):
        session_module, session_name, bank_module, bank_name = _SPECS[adapter_id]
        expected = getattr(import_module(session_module), session_name)
        if type(session) is not expected:
            raise ValueError(adapter_id + '-session-required')
        preparation.require_component(component)
        preparation.require_selection(selection)
        artifact = preparation.artifact(component.instance_id)
        preparation.assert_artifact_current(artifact)
        if session.artifact is not artifact:
            raise ValueError(adapter_id + '-artifact-mismatch')
        self.adapter_id = adapter_id
        self.component_instance_id = component.instance_id
        self.endpoint_id = endpoint_id
        self._session = session
        self._artifact = session.artifact
        self._bank = getattr(import_module(bank_module), bank_name)
        self._closed = False
        self.semantic_contract = self._bank(artifact, endpoint_id=endpoint_id)
        if self.semantic_contract.sha256_hex != component.semantic_contract_sha256:
            raise ValueError(adapter_id + '-semantic-mismatch')
        self.binding_sha256 = sha256(canonical_json_bytes(dict(
            component=component.descriptor_sha256(),
            selection=selection.sha256()))).hexdigest()
        self.provider = self

    def assert_current(self):
        if self._closed or self._session.artifact is not self._artifact:
            raise ValueError(self.adapter_id + '-binding-changed')
        if (self._bank(self._artifact, endpoint_id=self.endpoint_id).sha256_hex
                != self.semantic_contract.sha256_hex):
            raise ValueError(self.adapter_id + '-register-map-changed')


def bind_tlul_adapter(**kwargs):
    return BoundExtendedMmioAdapter(adapter_id='tlul.mmio.v1', **kwargs)


def bind_axi4lite_adapter(**kwargs):
    return BoundExtendedMmioAdapter(adapter_id='axi4lite.mmio.v1', **kwargs)


def bind_ahb_lite_adapter(**kwargs):
    return BoundExtendedMmioAdapter(adapter_id='ahb-lite.mmio.v1', **kwargs)
