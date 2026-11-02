"""Read-only registered APB storage producer and live F2 version consumer.

Selection grants no native authority. Only the existing pinned issuer can
resolve pre/post versions; documentary witnesses cannot replace live tokens.
"""
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
import json
from weakref import WeakKeyDictionary
import myfuzz.scenario.apb_storage_register_version as _version_module
from myfuzz.scenario.compiled_paths import compile_paths

from myfuzz.integration.compiled_f2_layout import compile_f2_candidate_layout
from myfuzz.integration.compiled_storage_producer import (
    _apb_template, _endpoint_protocol, _module_source, _probe_binding_document)
from myfuzz.integration.generated_storage_consumer import (
    _join_delivery, _transfer_samples, WITNESS_KEYS, HISTORY_SCOPE)
from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
from myfuzz.local_harness.apb_storage_probe_contract import storage_probe_selection
from myfuzz.local_harness.apb_storage_probe_verification import verified_storage_observation
from myfuzz.local_harness.apb_storage_source_contract import validate_apb_storage_source_contract
from myfuzz.local_harness.native_physical_observation import verify_apb_register_trace
from myfuzz.local_harness.runtime_artifact import LocalRuntimeArtifact
from myfuzz.scenario.apb_storage_register_version import ApbStorageRegisterVersionAuthority


def _json(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)


def _digest(value):
    return sha256(_json(value).encode()).hexdigest()


_BINDINGS=WeakKeyDictionary()


@dataclass(frozen=True,slots=True,eq=False,weakref_slot=True)
class F2ReadProducerBinding:
    document_json: str

    def document(self):
        return json.loads(self.document_json)

    @property
    def digest(self):
        return sha256(self.document_json.encode()).hexdigest()

    @property
    def target_component(self):
        return self.document()['target_component']

    @property
    def row(self):
        return self.document()['row']


def select_f2_read_producer(*,artifacts,compiled_inputs,base_dir=None):
    if compile_paths(compiled_inputs['request']) != compiled_inputs['compiled']:
        raise ValueError('compiled-F2-producer-compiled-mismatch')
    paths=[p for p in compiled_inputs['compiled']['paths'] if p.get('flow_id')=='F2' and p.get('status')=='executable']
    if len(paths)!=1:
        raise ValueError('compiled-F2-producer-path-required')
    path=paths[0]; layout=compile_f2_candidate_layout(path)
    contract=path['execution_contract']
    stream=next(s for s in path['sources'] if s['kind']=='cpu_load_stream')
    access=stream['register_access']; target=access['target_component']
    artifact=artifacts.get(target)
    if not isinstance(artifact,LocalRuntimeArtifact) or base_dir is None:
        raise ValueError('compiled-F2-producer-source-inputs-required')
    doc=artifact.runtime_document
    if doc.get('kind') == 'apb_gpio':
        from .gpio_f2_consumer import gpio_read_producer_document
        document = gpio_read_producer_document(artifact=artifact, access=access,
            contract=contract, layout=layout, compiled=compiled_inputs['compiled'], base_dir=base_dir)
        binding = F2ReadProducerBinding(_json(document))
        _BINDINGS[binding] = binding.document_json
        return binding
    if (doc.get('kind')!='apb3_register_observe' or doc.get('dynamic_physical_inputs')
            or doc.get('bound_physical_inputs') or verify_apb_register_trace(artifact) is not True):
        raise ValueError('compiled-F2-producer-observation-contract-mismatch')
    observation=doc.get('storage_observation')
    if not isinstance(observation,dict) or observation.get('selection')!=storage_probe_selection(artifact.plan):
        raise ValueError('compiled-F2-producer-source-contract-required')
    registered=validate_apb_storage_source_contract(observation.get('source_contract'),artifact.plan.profile,base_dir=base_dir)
    verification=verified_storage_observation(observation,runtime_sv=artifact.runtime_sv,
        wrapper_sha256=(doc.get('structural_build') or {}).get('wrapper_sha256'),base_dir=base_dir)
    reg=registered['register']
    if (reg['name']!=access['register'] or reg['width']!=32 or reg['read_mask']!=0xffffffff
            or reg['canonical_offset']!=access['register_offset']):
        raise ValueError('compiled-F2-producer-register-mismatch')
    document=dict(schema_version='compiled_F2_read_producer_binding.v1',
        row='generic_apb_storage_read_abi',target_component=target,
        target_artifact_digest=doc['artifact_digest'],target_artifact_kind=doc['kind'],
        endpoint_id=access['target_endpoint'],protocol=list(_endpoint_protocol(artifact,access['target_endpoint'])),
        template=_apb_template(artifact,access['target_endpoint']),
        register=dict(name=reg['name'],offset=reg['canonical_offset'],width=32,read_mask=reg['read_mask'],
            address=access['address'],operation='read',byte_enables=[15]),
        source=registered,probe=_probe_binding_document(observation,verification),
        producer=dict(session_source_sha256=_module_source(GeneratedApb3RegisterSession),
            issuer_source_sha256=_module_source(ApbStorageRegisterVersionAuthority),
            session_construction=dict(setup_writes=[],probe_offsets=[],dynamic_inputs=[],bound_inputs=[]),
            grants_reset_prerequisite=False),execution_contract=contract,
        compiled_sha256=_digest(compiled_inputs['compiled']),layout_digest=layout.digest,
        live_authority='not_claimed')
    binding=F2ReadProducerBinding(_json(document))
    _BINDINGS[binding]=binding.document_json
    return binding


def build_f2_read_producer(binding,*,artifact,base_dir,cache_dir,max_cases):
    if type(binding) is not F2ReadProducerBinding or _BINDINGS.get(binding)!=binding.document_json:
        raise ValueError('compiled-F2-producer-binding-required')
    doc=binding.document()
    if doc.get('row') == 'gpio_causal_read_abi':
        from .gpio_f2_consumer import GeneratedPulpGpioSession, GpioRegisterVersionAuthority, check_gpio_read_observation
        if (not isinstance(artifact, LocalRuntimeArtifact)
                or artifact.runtime_document['artifact_digest'] != doc['target_artifact_digest']
                or _module_source(GpioRegisterVersionAuthority) != doc['producer']['issuer_source_sha256']
                or _module_source(GeneratedPulpGpioSession) != doc['producer']['session_source_sha256']
                or _module_source(check_gpio_read_observation) != doc['producer']['consumer_source_sha256']):
            raise ValueError('compiled-F2-producer-binding-mismatch')
        if type(max_cases) is not int or not 1 <= max_cases <= 65528:
            raise ValueError('compiled-F2-producer-budget-invalid')
        target = GeneratedPulpGpioSession(artifact, base_dir=base_dir, cache_dir=cache_dir)
        return target, GpioRegisterVersionAuthority(target, max_writes=max_cases+8, max_tokens=16)
    if (not isinstance(artifact,LocalRuntimeArtifact)
            or artifact.runtime_document['artifact_digest']!=doc['target_artifact_digest']
            or _module_source(ApbStorageRegisterVersionAuthority)!=doc['producer']['issuer_source_sha256']
            or _module_source(GeneratedApb3RegisterSession)!=doc['producer']['session_source_sha256']):
        raise ValueError('compiled-F2-producer-binding-mismatch')
    if type(max_cases) is not int or not 1<=max_cases<=65528:
        raise ValueError('compiled-F2-producer-budget-invalid')
    target=GeneratedApb3RegisterSession(artifact,base_dir=base_dir,cache_dir=cache_dir,
        setup_writes=(),probe_offsets=())
    return target,ApbStorageRegisterVersionAuthority(target,max_writes=max_cases+8,max_samples=65536,max_tokens=16)


_BEFORE=WeakKeyDictionary()


@dataclass(frozen=True,slots=True,eq=False,weakref_slot=True)
class F2ReadVersion:
    _document_json: str

    def document(self):
        return json.loads(self._document_json)


def _authority(authority):
    if type(authority) is not _AUTHORITY_CLASS:
        raise ValueError('compiled-F2-read-authority-required')
    if (ApbStorageRegisterVersionAuthority is not _AUTHORITY_CLASS
            or _version_module.ApbStorageRegisterVersionAuthority is not _AUTHORITY_CLASS
            or ApbStorageRegisterVersionAuthority.issue.__code__ is not _ISSUE
            or ApbStorageRegisterVersionAuthority.consume.__code__ is not _CONSUME):
        raise ValueError('compiled-F2-read-authority-drift')


def capture_f2_read_version(authority,*,register,reset_epoch):
    from .gpio_f2_consumer import GpioRegisterVersionAuthority, capture_gpio_read_version
    if type(authority) is GpioRegisterVersionAuthority:
        return capture_gpio_read_version(authority, register=register, reset_epoch=reset_epoch)
    _authority(authority)
    witness=authority.consume(authority.issue(register=register,reset_epoch=reset_epoch))
    if set(witness)!=WITNESS_KEYS or witness['grants_reset_prerequisite'] is not False:
        raise ValueError('compiled-F2-read-version-shape')
    before=F2ReadVersion(_json(witness))
    _BEFORE[before]=(authority,deepcopy(authority.writes()))
    return before


def check_f2_read_observation(declaration,receipt,*,target_artifact,authority,token,
        before,register,reset_epoch,prior_writes):
    from .gpio_f2_consumer import GpioRegisterVersionAuthority, check_gpio_read_observation
    if type(authority) is GpioRegisterVersionAuthority:
        return check_gpio_read_observation(declaration, receipt, target_artifact=target_artifact,
            authority=authority, token=token, before=before, register=register,
            reset_epoch=reset_epoch, prior_writes=prior_writes)
    _authority(authority)
    if type(before) is not F2ReadVersion or before not in _BEFORE or _BEFORE[before][0] is not authority:
        raise ValueError('compiled-F2-read-live-before-required')
    if type(token) is not object:
        raise ValueError('compiled-F2-read-token-required')
    target=authority.target
    if target.artifact is not target_artifact or target.reset_epoch!=reset_epoch:
        raise ValueError('compiled-F2-read-target-epoch-mismatch')
    pre=before.document(); history=_BEFORE[before][1]
    if pre['register']!=register or pre['reset_epoch']!=reset_epoch or pre['write_count']!=prior_writes:
        raise ValueError('compiled-F2-read-before-mismatch')
    if authority.writes()!=history or _digest(history)!=pre['write_history_sha256']:
        raise ValueError('compiled-F2-read-history-changed')
    doc=target_artifact.runtime_document; observation=doc['storage_observation']
    contract=validate_apb_storage_source_contract(observation['source_contract'],target_artifact.plan.profile,base_dir=target.base_dir)
    verified_storage_observation(observation,runtime_sv=target_artifact.runtime_sv,
        wrapper_sha256=(doc.get('structural_build') or {}).get('wrapper_sha256'),base_dir=target.base_dir)
    if verify_apb_register_trace(target_artifact) is not True:
        raise ValueError('compiled-F2-read-physical-observation-required')
    access=declaration['candidate']['access']; events=receipt.events
    deliveries=[e for e in events if e.get('kind')=='mmio_delivery' and e.get('component')==access['source_component']]
    if len(deliveries)!=1 or deliveries[0].get('write') is not False or deliveries[0].get('read_value')!=pre['value']:
        raise ValueError('compiled-F2-read-delivery-count-or-value')
    delivery=deliveries[0]
    accepted=_join_delivery(events,delivery=delivery,component=access['source_component'],device=access['device_id'],
        address=access['address'],offset=access['register_offset'],write=False)
    raw_pre,raw_post,probes,post_probes=_transfer_samples(events,delivery=delivery,
        component=access['target_component'],signals=doc['base_protocol_trace']['signals'],
        expected_write=False,offset=access['register_offset'],value=pre['value'],reset_epoch=reset_epoch,contract=contract)
    if probes['storage_value']!=pre['value'] or post_probes['storage_value']!=pre['value']:
        raise ValueError('compiled-F2-read-state-changed')
    # Authenticate event samples against actual native command receipts. The
    # issuer separately enforces contiguous command coverage and reduction.
    commands=target.native_reset_observation_commands()
    current=[c for c in commands if c.get('target_epoch')==reset_epoch
        and pre['command_sequence']<c.get('command_sequence',-1)<=target._sequence]
    if [c['command_sequence'] for c in current]!=list(range(pre['command_sequence']+1,target._sequence+1)):
        raise ValueError('compiled-F2-read-command-gap')
    accesses=[]
    for command in current:
        receipt_doc=command.get('parsed_receipt_projection')
        if command.get('status')!='parsed_complete' or not isinstance(receipt_doc,dict):
            raise ValueError('compiled-F2-read-command-incomplete')
        payload=receipt_doc.get('payload') or {}
        if command['operation']=='ACCESS_APB3_REG':
            accesses.append(command)
        elif command['operation']!='STEP_APB3_REG' or command['fields']:
            raise ValueError('compiled-F2-read-unexpected-command')
    if len(accesses)!=1 or accesses[0]['fields']!=[0,access['register_offset'],0,15]:
        raise ValueError('compiled-F2-read-native-command-mismatch')
    native_samples=accesses[0]['parsed_receipt_projection']['payload']['samples']
    native=[r for r in native_samples if r['local_tick']+target._tick_base==raw_pre['local_tick']]
    if (len(native)!=1 or native[0]['pre']['storage_probes']!=probes
            or native[0]['post']['storage_probes']!=post_probes):
        raise ValueError('compiled-F2-read-native-sample-mismatch')
    post=authority.consume(token)
    unchanged=('register','reset_epoch','value','field_version','write_count','write_history_sha256',
        'version_basis','history_scope','artifact_digest','source_contract_digest','probe_digest',
        'producer_source_sha256','build_identity_sha256','pid','execution','grants_reset_prerequisite')
    if set(post)!=WITNESS_KEYS or any(post[k]!=pre[k] for k in unchanged):
        raise ValueError('compiled-F2-read-version-changed')
    if (post['command_sequence']<=pre['command_sequence'] or post['local_tick']<=pre['local_tick']
            or post['local_tick']<raw_post['local_tick'] or post['command_sequence']!=target._sequence
            or post['local_tick']!=target.local_ticks or post['execution']!=target._execution
            or target.process is None or target.process.poll() is not None or post['pid']!=target.process.pid):
        raise ValueError('compiled-F2-read-version-scope')
    ram=[e for e in events if e.get('kind')=='memory_write'
        and e.get('component')==access['source_component']
        and e.get('address')==declaration['result_address']
        and e.get('value')==(pre['value'] ^ 0x5a5)
        and e.get('event_id',0)>delivery['event_id']]
    if len(ram)!=1:
        raise ValueError('compiled-F2-dependent-RAM-missing')
    del _BEFORE[before]
    join=dict(delivery_event=delivery['event_id'],acceptance_event=accepted['event_id'],
        native_APB_event=raw_pre['event_id'],native_post_event=raw_post['event_id'],
        source_transaction=deepcopy(delivery['source_transaction']),write=False,value=pre['value'])
    return dict(schema_version='compiled_F2_read_observation.v1',joins=[join],
        version_before=pre,version_witness=post,RAM_event=ram[0]['event_id'],runtime_admitted=False),post


_AUTHORITY_CLASS=ApbStorageRegisterVersionAuthority
_ISSUE=ApbStorageRegisterVersionAuthority.issue.__code__
_CONSUME=ApbStorageRegisterVersionAuthority.consume.__code__


def stable_f2_read_version(witness):
    from .gpio_f2_consumer import VERSION_SCHEMA, stable_gpio_read_version
    if type(witness) is dict and witness.get('schema_version') == VERSION_SCHEMA:
        return stable_gpio_read_version(witness)
    from .generated_storage_consumer import stable_storage_version
    return stable_storage_version(witness)
