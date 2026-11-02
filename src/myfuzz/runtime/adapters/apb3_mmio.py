"""Protocol MMIO admission: register declarations are not storage certificates."""
from dataclasses import asdict,dataclass
from hashlib import sha256
import json
from ..contracts import canonical_json_bytes

KIND='mmio.register-bank.v1'
ADAPTER_ID='apb3.mmio.v1'
TEMPLATE=('target.apb3','1','full-word')
EVIDENCE=('cross_component_consumption','cross_component_source','physical_protocol_sample')


@dataclass(frozen=True)
class RegisterBank:
    document_bytes:bytes
    kind:str=KIND
    @property
    def sha256_hex(self):return sha256(self.document_bytes).hexdigest()
    def document(self):return json.loads(self.document_bytes)


def bank_contract_facts(artifact,*,endpoint_id):
    from myfuzz.local_harness.native_physical_observation import verify_apb_register_trace
    doc=artifact.runtime_document
    endpoints=[e for e in artifact.plan.binding.endpoints if e.endpoint_id==endpoint_id
        and e.protocol==('apb','3') and e.function=='mmio_slave']
    if (doc.get('kind')!='apb3_register_observe' or len(endpoints)!=1
            or doc.get('storage_observation') is not None or doc.get('dynamic_physical_inputs')
            or doc.get('bound_physical_inputs') or verify_apb_register_trace(artifact) is not True):
        raise ValueError('actual-static-APB-MMIO-target-required')
    address=artifact.plan.profile.address
    if address is None or not address.registers:raise ValueError('declared-MMIO-register-map-required')
    registers=[asdict(r) for r in address.registers]
    return RegisterBank(canonical_json_bytes(dict(schema_version='mmio_register_bank.v1',kind=KIND,
        endpoint_id=endpoint_id,protocol=['apb','3'],template=list(TEMPLATE),
        window_size=address.window_size,alignment=address.alignment,registers=registers,
        declaration_scope='configured_register_map_not_internal_RTL_storage_proof',
        internal_storage_version='unknown',cross_case_origin='unknown',reward_eligible=False)))


def admission_facts(artifact,*,preparation,base_dir):
    from ..admission import _template_contract,_verify_artifact_roles,_endpoint_document,_pin
    endpoints=[e for e in artifact.plan.binding.endpoints if e.protocol==('apb','3') and e.function=='mmio_slave']
    if len(endpoints)!=1:raise ValueError('one-APB-MMIO-endpoint-required')
    endpoint=endpoints[0];template=preparation.declared_endpoint_template(artifact.plan.request.instance_id,endpoint.endpoint_id)
    if tuple(template)!=TEMPLATE:raise ValueError('APB-MMIO-template-mismatch')
    contract=_template_contract(('apb','3'),TEMPLATE,endpoint.function)
    _verify_artifact_roles(artifact,endpoint.endpoint_id,('apb','3'),contract,artifact.plan.profile)
    semantic=bank_contract_facts(artifact,endpoint_id=endpoint.endpoint_id)
    identity=dict(id='apb3.mmio.admission.v1',version='1',
        implementation_sha256=_pin(('src/myfuzz/runtime/adapters/apb3_mmio.py',)))
    row=_endpoint_document(endpoint_id=endpoint.endpoint_id,role='target',protocol=('apb','3'),
        template=TEMPLATE,semantic_kind=KIND,operations=('read','write'),data_width=32,address_width=12,
        address_units='byte',max_outstanding=1,completion_kind='setup_access_response',byte_enable=False,
        evidence_capabilities=EVIDENCE)
    return dict(semantic_contract_sha256=semantic.sha256_hex,endpoints=[row],source_verifier=identity,
        facts={'semantic':semantic,'internal_storage_version':'unknown'})


class BoundMmioAdapter:
    adapter_id=ADAPTER_ID
    adapter_version='1'
    software_only=False
    def __init__(self,*,component,session,selection,preparation,endpoint_id):
        from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
        if type(session) is not GeneratedApb3RegisterSession:raise ValueError('actual-APB-MMIO-session-required')
        preparation.require_component(component);preparation.require_selection(selection)
        artifact=preparation.artifact(component.instance_id)
        preparation.assert_artifact_current(artifact)
        if session.artifact!=artifact:raise ValueError('APB-MMIO-artifact-mismatch')
        self.component_instance_id=component.instance_id;self.endpoint_id=endpoint_id
        self._session=session;self._artifact=session.artifact;self._closed=False
        self.semantic_contract=bank_contract_facts(artifact,endpoint_id=endpoint_id)
        if self.semantic_contract.sha256_hex!=component.semantic_contract_sha256:raise ValueError('APB-MMIO-semantic-mismatch')
        self.binding_sha256=sha256(canonical_json_bytes(dict(component=component.descriptor_sha256(),selection=selection.sha256()))).hexdigest()
        self.provider=self
    def assert_current(self):
        if self._closed or self._session.artifact is not self._artifact:raise ValueError('APB-MMIO-binding-changed')
        if bank_contract_facts(self._artifact,endpoint_id=self.endpoint_id).sha256_hex!=self.semantic_contract.sha256_hex:
            raise ValueError('APB-MMIO-register-map-changed')
    def close(self):self._closed=True
    def current(self):
        self.assert_current()
        return dict(internal_storage_version='unknown',cross_case_origin='unknown',reward_eligible=False)


def bind_mmio_adapter(**kwargs):return BoundMmioAdapter(**kwargs)
