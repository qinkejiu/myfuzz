"""Typed causal GPIO register-bank admission and exact live binding.

This is not an apb3_register_observe adapter. The existing compiled channel
owns routed execution and native certificate joins; this bound adapter verifies
the actual causal GPIO session/issuer and offers read-only current tokens.
Direct standalone target transport is deliberately unsupported.
"""
from hashlib import sha256
from dataclasses import dataclass
import json
from pathlib import Path
from myfuzz.local_harness.execution_validation import static_validation
from ..contracts import GenericRuntimeRefused, canonical_json_bytes
from ..semantics.contracts import SemanticContract

GPIO_STORAGE_ADAPTER_ID = 'gpio.causal-storage.v1'
GPIO_TEMPLATE = ('pulp.gpio.causal', '1', 'pulp_gpio_causal_v1')
_ROOT = Path(__file__).resolve().parents[4]
_FILES = ('src/myfuzz/runtime/adapters/gpio_storage.py',
    'src/myfuzz/local_harness/pulp_gpio_probe_contract.py',
    'src/myfuzz/local_harness/gpio_session.py',
    'src/myfuzz/scenario/gpio_register_version.py')


def _pin_uncached():
    return sha256(canonical_json_bytes({p:sha256((_ROOT/p).read_bytes()).hexdigest() for p in _FILES})).hexdigest()


def _pin():
    return static_validation(('gpio_causal_storage_adapter_sources',), _pin_uncached)


def verifier_identity():
    return dict(id='gpio.causal-storage.admission.v1',version='1',implementation_sha256=_pin())


def artifact_contract_facts(artifact, *, base_dir, endpoint_id, template):
    from myfuzz.local_harness.pulp_gpio_probe_contract import (
        verify_pulp_gpio_source_contract, pulp_gpio_observation_contract, pulp_gpio_probe_document)
    if (artifact.runtime_document.get('kind') != 'apb_gpio' or tuple(template) != GPIO_TEMPLATE
            or artifact.runtime_document.get('gpio_observation_contract') != pulp_gpio_observation_contract()):
        raise ValueError('gpio-causal-storage-contract-required')
    verify_pulp_gpio_source_contract(artifact.plan.profile,base_dir=Path(base_dir))
    selected = artifact.runtime_document['selected_template']['contract']
    if tuple(selected.get(k) for k in ('template_id','template_version','variant_id')) != GPIO_TEMPLATE:
        raise ValueError('gpio-causal-storage-template-mismatch')
    endpoints=[e for e in artifact.plan.binding.endpoints if e.endpoint_id == endpoint_id
               and e.protocol == ('apb','3') and e.function == 'mmio_slave']
    if len(endpoints) != 1: raise ValueError('gpio-causal-storage-endpoint-required')
    source=pulp_gpio_probe_document()['source']
    return SemanticContract.freeze(dict(schema_version='semantic_contract.v1',kind='storage.rw.v1',
        source=dict(contract_id='pulp-gpio-causal:GPIOEN',root=source['root'],revision=source['revision'],
            top_module=source['top_module'],files={source['path']:source['sha256']},
            verifier=verifier_identity(),identity_basis='pinned_official_source_and_passive_gpio_probes'),
        endpoint=dict(endpoint_id=endpoint_id,role='target',protocol=['apb','3'],template=list(GPIO_TEMPLATE),semantic_kind='storage.rw.v1'),
        decode=dict(address_width=12,address_units='byte',alignment_bytes=4,mask=124,value=4,
            alias_period_bytes=128,expression='PADDR[6:2] == 1 (GPIOEN only)'),
        operations=[dict(operation=op,width_bits=32,read_mask=0xffffffff,write_mask=0xffffffff if op=='write' else 0,
                        byte_enable=False,value_origin='cpu_transaction_wdata' if op=='write' else 'target_register_read')
                    for op in ('read','write')],
        reset=dict(declared=True,port='HRESETn',polarity='active_low',observed=False,evidence_ref=None,case_begin_is_reset=False),
        side_effects=[dict(kind='stable_storage',scope='GPIOEN word only; pin/IRQ configuration effects excluded')],
        observations=[dict(name='gpio_probe_gpioen',layer='component_semantic_effect',native=True,reference='pulp_gpio_observation.v1')],
        issuer_contract=dict(issuer_id='GpioRegisterVersionAuthority',version='1',implementation_sha256=_pin(),
            token_scope='existing_process_local_single_use',single_use=True,authority=False)))


GPIO_BANK_KIND = 'gpio.register-bank.v1'


@dataclass(frozen=True)
class GpioRegisterBankContract:
    """Two distinct resource contracts, not a claim of whole-IP storage."""
    document_bytes: bytes
    kind: str = GPIO_BANK_KIND

    @property
    def sha256_hex(self): return sha256(self.document_bytes).hexdigest()

    def document(self): return json.loads(self.document_bytes)

    def supports(self, *, register, operation, offset):
        rows=self.document()['registers']
        if register not in rows or type(offset) is not int or not 0 <= offset < 4096 or offset % 4:
            return False
        if register == 'GPIOEN':
            decode=rows[register]['decode']
            return operation in ('read','write') and offset & decode['mask'] == decode['value']
        return operation == 'read' and offset & 124 == 8


def bank_contract_facts(artifact, *, base_dir, endpoint_id, template):
    gpioen=artifact_contract_facts(artifact,base_dir=base_dir,endpoint_id=endpoint_id,template=template).document()
    padin=dict(schema_version='gpio_padin_readonly_contract.v1',kind='gpio.padin.read-only.v1',
        register='PADIN',canonical_offset=8,decode=dict(mask=124,value=8,alias_period_bytes=128),
        width_bits=32,operations=['read'],read_mask=0xffffffff,write_mask=0,
        value_origin='native_synchronizer_latch',version_basis='native_sample_version',
        side_effects=[dict(kind='read_only',scope='native PADIN latch sample; writes and IRQ consumption excluded')],
        observation_contract=artifact.runtime_document['gpio_observation_contract'],
        issuer_contract=dict(issuer_id='GpioRegisterVersionAuthority',register='PADIN',
            version_basis='native_sample_version',token_scope='existing_process_local_single_use',
            single_use=True,authority=False))
    document=dict(schema_version='gpio_register_bank_contract.v1',kind=GPIO_BANK_KIND,
        source=gpioen['source'],endpoint=dict(gpioen['endpoint'],semantic_kind=GPIO_BANK_KIND),
        registers={'GPIOEN':gpioen,'PADIN':padin},
        proof_scope='declared_gpioen_storage_and_native_padin_read_only_resources')
    return GpioRegisterBankContract(canonical_json_bytes(document))


class BoundGpioStorageAdapter:
    software_only=False
    adapter_id=GPIO_STORAGE_ADAPTER_ID
    adapter_version='1'

    def __init__(self, *, component, session, selection, preparation, endpoint_id, semantic, authority):
        self.component_instance_id=component.instance_id
        self.endpoint_id=endpoint_id
        self.semantic_contract=semantic
        self._component,self._session,self._selection,self._preparation=component,session,selection,preparation
        self._artifact=session.artifact
        from myfuzz.local_harness.generated_artifact_admission import _artifact_files
        self._sealed_artifact_bytes=tuple(sorted(_artifact_files(self._artifact).items()))
        self._authority,self._pin,self._closed=authority,_pin(),False
        self.binding_sha256=sha256(canonical_json_bytes(dict(component=component.descriptor_sha256(),
            selection=selection.sha256(),endpoint=endpoint_id,semantic=semantic.sha256_hex))).hexdigest()
        self.provider=self

    def _validate_artifact_bytes(self):
        # Scope exit may occur after preparation cleanup and generated-directory
        # archival. Reauthenticate sealed bytes without querying live grants.
        from myfuzz.local_harness.generated_artifact_admission import _artifact_files
        if tuple(sorted(_artifact_files(self._artifact).items())) != self._sealed_artifact_bytes:
            raise ValueError('gpio-causal-storage-static-artifact-bytes-changed')

    def assert_current(self):
        from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
        from myfuzz.scenario.gpio_register_version import _AUTHORITIES, GpioRegisterVersionAuthority
        if (self._closed or type(self._session) is not GeneratedPulpGpioSession
                or self._session.artifact is not self._artifact or _pin()!=self._pin or _AUTHORITIES.get(self._session) is not self._authority
                or type(self._authority) is not GpioRegisterVersionAuthority
                or self._authority.target is not self._session
                or self.semantic_contract.sha256_hex != self._component.semantic_contract_sha256):
            raise ValueError('gpio-causal-storage-binding-drift')
        self._preparation.require_component(self._component)
        self._preparation.require_selection(self._selection)
        if self._artifact != self._preparation.artifact(self.component_instance_id):
            raise ValueError('gpio-causal-storage-artifact-snapshot-mismatch')
        static_validation(('gpio_storage_artifact',self),self._validate_artifact_bytes)
        self._authority._validate()

    def current(self, *, register='GPIOEN'):
        if register not in ('GPIOEN','PADIN'):
            raise ValueError('gpio-register-outside-declared-bank')
        self.assert_current()
        return self._authority.consume(self._authority.issue(register=register,reset_epoch=self._session.reset_epoch))

    def close(self): self._closed=True

    def prepare(self,*args,**kwargs):
        self.assert_current()
        raise GenericRuntimeRefused('generic-semantic-unsupported','/provider',
            {'reason':'gpio-transport-owned-by-compiled-channel'})
    advance=prepare
    complete=prepare


def bind_gpio_storage_adapter(*,component,session,selection,preparation,endpoint_id):
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    from myfuzz.scenario.gpio_register_version import _AUTHORITIES, GpioRegisterVersionAuthority
    from ..registry import registrations
    preparation.require_component(component)
    preparation.require_selection(selection)
    artifact=preparation.artifact(component.instance_id)
    if type(session) is not GeneratedPulpGpioSession:
        raise ValueError('actual-causal-gpio-session-required')
    from myfuzz.local_harness.runtime_artifact import LocalRuntimeArtifact
    preparation.assert_artifact_current(artifact)
    # The executor owns a private admitted snapshot. Compare every dataclass
    # field, not identity or the compact artifact digest alone.
    if type(session.artifact) is not LocalRuntimeArtifact or session.artifact != artifact:
        raise ValueError('gpio-causal-storage-artifact-snapshot-mismatch')
    row=next(r for r in registrations() if r.adapter_id==GPIO_STORAGE_ADAPTER_ID)
    if (selection.adapter_id!=GPIO_STORAGE_ADAPTER_ID or selection.implementation_sha256!=row.implementation_sha256()
            or selection.component_artifact_sha256!=component.artifact_sha256
            or selection.semantic_contract_sha256!=component.semantic_contract_sha256):
        raise ValueError('gpio-causal-storage-selection-mismatch')
    semantic=bank_contract_facts(session.artifact,base_dir=preparation.inputs.base_dir,endpoint_id=endpoint_id,template=GPIO_TEMPLATE)
    if semantic.sha256_hex!=component.semantic_contract_sha256:
        raise ValueError('gpio-causal-storage-semantic-mismatch')
    authority=_AUTHORITIES.get(session)
    if type(authority) is not GpioRegisterVersionAuthority:
        raise ValueError('installed-gpioen-authority-required')
    result=BoundGpioStorageAdapter(component=component,session=session,selection=selection,
        preparation=preparation,endpoint_id=endpoint_id,semantic=semantic,authority=authority)
    result.assert_current()
    return result
