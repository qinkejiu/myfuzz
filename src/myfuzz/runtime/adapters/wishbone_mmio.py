"""Ordinary Wishbone MMIO target admission, with no storage authority."""
from hashlib import sha256

from myfuzz.integration.wishbone_mmio_target import wishbone_mmio_bank_facts
from myfuzz.local_harness.wishbone_register_session import GeneratedWishboneRegisterSession
from myfuzz.runtime.contracts import canonical_json_bytes

ADAPTER_ID = 'wishbone.mmio.v1'
TEMPLATE = ('target.wishbone', '1', 'word-addressed-registered-ack')
EVIDENCE = ('cross_component_consumption', 'cross_component_source', 'physical_protocol_sample')


def admission_facts(artifact, *, preparation, base_dir):
    from myfuzz.runtime.admission import _template_contract, _verify_artifact_roles, _endpoint_document, _pin
    from myfuzz.local_harness.runtime_renderer import _WISHBONE_TIMER, _shape
    endpoints = [e for e in artifact.plan.binding.endpoints
                 if e.protocol == ('wishbone', 'classic') and e.function == 'mmio_slave']
    if len(endpoints) != 1:
        raise ValueError('one-Wishbone-MMIO-endpoint-required')
    endpoint = endpoints[0]
    template = preparation.declared_endpoint_template(artifact.plan.request.instance_id, endpoint.endpoint_id)
    if tuple(template) != TEMPLATE:
        raise ValueError('Wishbone-MMIO-template-mismatch')
    contract = _template_contract(('wishbone', 'classic'), TEMPLATE, endpoint.function)
    _verify_artifact_roles(artifact, endpoint.endpoint_id, ('wishbone', 'classic'), contract, artifact.plan.profile)
    semantic = wishbone_mmio_bank_facts(artifact, endpoint_id=endpoint.endpoint_id)
    width = artifact.plan.profile.capabilities['address_width']
    shape = {**_WISHBONE_TIMER, 'adr': ('input', width)}
    wires = _shape(endpoint, shape, artifact.structural.abi_document['ports'])
    trace = artifact.runtime_document['base_protocol_trace']
    expected_signals = {role: 'trace_' + role for role in shape}
    expected_widths = {role: size for role, (_, size) in shape.items()}
    backend = artifact.runtime_document.get('backend_ports', [])
    runtime = artifact.runtime_document.get('runtime_ports', [])
    if (trace.get('endpoint_id') != endpoint.endpoint_id or trace.get('signals') != expected_signals
            or trace.get('signal_widths') != expected_widths
            or any(artifact.runtime_sv.count(f'assign trace_{role} = {wires[role]};') != 1
                or sum(row.get('name') == 'trace_'+role and row.get('role') == role
                       and row.get('direction') == 'output' and row.get('width') == expected_widths[role]
                       and row.get('channel') == 'ip_protocol_trace' for row in backend) != 1
                or sum(row.get('name') == 'trace_'+role and row.get('direction') == 'output'
                       and row.get('width') == expected_widths[role] for row in runtime) != 1
                for role in shape)):
        raise ValueError('Wishbone-MMIO-native-trace-mismatch')
    row = _endpoint_document(endpoint_id=endpoint.endpoint_id, role='target',
        protocol=('wishbone','classic'), template=TEMPLATE, semantic_kind='mmio.register-bank.v1',
        operations=('read','write'), data_width=32, address_width=width, address_units='word',
        max_outstanding=1, completion_kind='registered_ack', byte_enable=True,
        evidence_capabilities=EVIDENCE)
    return dict(semantic_contract_sha256=semantic.sha256_hex,endpoints=[row],
        source_verifier=dict(id='wishbone.mmio.admission.v1',version='1',
            implementation_sha256=_pin(('src/myfuzz/runtime/adapters/wishbone_mmio.py',
                                       'src/myfuzz/integration/wishbone_mmio_target.py'))),
        facts={'semantic':semantic,'internal_storage_version':'unknown'})


class BoundWishboneMmioAdapter:
    adapter_id = ADAPTER_ID
    adapter_version = '1'
    software_only = False

    def __init__(self, *, component, session, selection, preparation, endpoint_id):
        if type(session) is not GeneratedWishboneRegisterSession:
            raise ValueError('actual-Wishbone-MMIO-session-required')
        preparation.require_component(component)
        preparation.require_selection(selection)
        artifact = preparation.artifact(component.instance_id)
        preparation.assert_artifact_current(artifact)
        if session.artifact is not artifact:
            raise ValueError('Wishbone-MMIO-artifact-mismatch')
        self.component_instance_id, self.endpoint_id = component.instance_id, endpoint_id
        self._session, self._artifact, self._closed = session, artifact, False
        self.semantic_contract = wishbone_mmio_bank_facts(artifact, endpoint_id=endpoint_id)
        if self.semantic_contract.sha256_hex != component.semantic_contract_sha256:
            raise ValueError('Wishbone-MMIO-semantic-mismatch')
        self.binding_sha256 = sha256(canonical_json_bytes(dict(
            component=component.descriptor_sha256(),selection=selection.sha256()))).hexdigest()
        self.provider = self

    def assert_current(self):
        if self._closed or self._session.artifact is not self._artifact:
            raise ValueError('Wishbone-MMIO-binding-changed')
        if wishbone_mmio_bank_facts(self._artifact,endpoint_id=self.endpoint_id).sha256_hex != self.semantic_contract.sha256_hex:
            raise ValueError('Wishbone-MMIO-register-map-changed')

    def close(self): self._closed = True

    def current(self):
        self.assert_current()
        return dict(internal_storage_version='unknown',cross_case_origin='unknown',reward_eligible=False)


def bind_wishbone_mmio_adapter(**kwargs): return BoundWishboneMmioAdapter(**kwargs)
