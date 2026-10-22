"""Closed, code-owned storage producer selection for an admitted compiled F4.

Two rows exist and nothing else:

* the existing PULP GPIO causal ABI (unchanged construction and consumers), and
* the source-registered generic APB storage ABI (exact ``GeneratedApb3RegisterSession``
  with empty setup/probe inputs and ``ApbStorageRegisterVersionAuthority``).

Rows name the exact session/issuer classes and consumer functions in code. A
caller document can never supply a factory, method, expression or authority
descriptor, and a component id/profile name never selects a producer. The
registered timer contract is a reviewed source identity/register contract, not
arbitrary same-protocol IP inference.

The returned binding is immutable and is rebuilt from trusted source inputs on
every admission, stability check and fresh prefix. It grants no live token,
certificate, native eligibility, reset prerequisite or storage authority; the
generic row's in-row commit consumer only consumes a token that the native C
issuer actually issued in the same live process.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import inspect
import json
from pathlib import Path
from collections.abc import Mapping
from types import MappingProxyType
import sys

from myfuzz.integration.compiled_candidate_layout import compile_candidate_layout
from myfuzz.integration.generated_register_writer import (
    check_writer_observation, declare_writer)
from myfuzz.integration.generated_storage_consumer import (
    CONSUMER_QUALNAME as APB_COMMIT_CONSUMER,
    RECEIPT_ELEMENTS as APB_RECEIPT_ELEMENTS,
    check_storage_observation, storage_consumer_support)
from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
from myfuzz.local_harness.apb_storage_probe_contract import storage_probe_selection
from myfuzz.local_harness.apb_storage_probe_verification import (
    verified_storage_observation)
from myfuzz.local_harness.apb_storage_source_contract import (
    apb_storage_address_matches, validate_apb_storage_source_contract)
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.local_harness.native_physical_observation import (
    verify_apb_register_trace, verify_native_physical_observation)
from myfuzz.local_harness.pulp_gpio_probe_contract import (
    pulp_gpio_observation_contract, pulp_gpio_probe_document, pulp_gpio_register_map)
from myfuzz.local_harness.runtime_artifact import LocalRuntimeArtifact
from myfuzz.scenario.apb_storage_register_version import ApbStorageRegisterVersionAuthority
from myfuzz.scenario.gpio_register_version import GpioRegisterVersionAuthority

SCHEMA = 'compiled_F4_storage_producer_binding.v1'
ROW_GPIO_CAUSAL = 'gpio_causal_abi'
ROW_GENERIC_APB_STORAGE = 'generic_apb_storage_abi'
ROWS = (ROW_GPIO_CAUSAL, ROW_GENERIC_APB_STORAGE)

_GPIO_TEMPLATE = MappingProxyType(dict(template_id='pulp.gpio.causal',
    template_version='1', variant_id='pulp_gpio_causal_v1'))
_APB_TEMPLATE = MappingProxyType(dict(template_id='target.apb3',
    template_version='1', variant_id='full-word'))
_GPIO_COMMIT_CONSUMER = 'myfuzz.integration.generated_register_writer.check_writer_observation'
_APB_COMMIT_CONSUMER = APB_COMMIT_CONSUMER


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _digest(value):
    return sha256(_json(value).encode()).hexdigest()


def _module_source(class_or_function):
    try:
        path = inspect.getsourcefile(class_or_function)
        if path is None:
            raise OSError('no source file')
        return sha256(Path(path).read_bytes()).hexdigest()
    except (OSError, TypeError) as error:
        raise ValueError('compiled-F4-producer-source-identity-unavailable') from error


def _qualified(value):
    return value.__module__ + '.' + value.__qualname__


def _pin(value):
    code = getattr(value, '__code__', None)
    return (value, code)


# Import-time pins: every producer dependency is captured once, before any
# selection can be requested. A later module/class/function replacement is a
# drift refusal, never a re-baseline.
_DEPENDENCIES = {
    'GeneratedPulpGpioSession': GeneratedPulpGpioSession,
    'GpioRegisterVersionAuthority': GpioRegisterVersionAuthority,
    'GeneratedApb3RegisterSession': GeneratedApb3RegisterSession,
    'ApbStorageRegisterVersionAuthority': ApbStorageRegisterVersionAuthority,
    'pulp_gpio_observation_contract': pulp_gpio_observation_contract,
    'pulp_gpio_probe_document': pulp_gpio_probe_document,
    'pulp_gpio_register_map': pulp_gpio_register_map,
    'verify_native_physical_observation': verify_native_physical_observation,
    'verify_apb_register_trace': verify_apb_register_trace,
    'storage_probe_selection': storage_probe_selection,
    'verified_storage_observation': verified_storage_observation,
    'validate_apb_storage_source_contract': validate_apb_storage_source_contract,
    'apb_storage_address_matches': apb_storage_address_matches,
    'declare_writer': declare_writer,
    'check_writer_observation': check_writer_observation,
    'check_storage_observation': check_storage_observation,
    'storage_consumer_support': storage_consumer_support,
}
_PINNED = MappingProxyType({name: _pin(value) for name, value in _DEPENDENCIES.items()})
_ORIGINS = MappingProxyType({name: value.__module__ for name, value in _DEPENDENCIES.items()})


def _check_pins():
    if (_SELECT_PIN[0] is not select_storage_producer
            or select_storage_producer.__code__ is not _SELECT_PIN[1]
            or _VALIDATE_PIN[0] is not validate_storage_producer_binding
            or validate_storage_producer_binding.__code__ is not _VALIDATE_PIN[1]
            or _BUILD_PIN[0] is not build_storage_producer
            or build_storage_producer.__code__ is not _BUILD_PIN[1]):
        raise ValueError('compiled-F4-producer-selection-drift:entry')
    for name, (value, code) in _PINNED.items():
        current = globals().get(name)
        if current is not value or (code is not None and getattr(value, '__code__', None) is not code):
            raise ValueError('compiled-F4-producer-selection-drift:' + name)
        origin = sys.modules.get(_ORIGINS[name])
        if origin is not None and getattr(origin, value.__qualname__.split('.')[0], None) is not value:
            raise ValueError('compiled-F4-producer-selection-drift:' + name)


@dataclass(frozen=True, slots=True)
class AdmittedStorageProducerBinding:
    """Immutable admitted producer binding; the document is the exact identity."""

    document_json: str

    def __post_init__(self):
        if type(self) is not AdmittedStorageProducerBinding:
            raise ValueError('compiled-F4-producer-binding-required')
        if type(self.document_json) is not str:
            raise ValueError('compiled-F4-producer-binding-required')
        try:
            document = json.loads(self.document_json)
        except (TypeError, ValueError) as error:
            raise ValueError('compiled-F4-producer-binding-required') from error
        if (type(document) is not dict or document.get('schema_version') != SCHEMA
                or document.get('row') not in ROWS
                or document.get('binding_sha256') != _digest(
                    {key: value for key, value in document.items() if key != 'binding_sha256'})):
            raise ValueError('compiled-F4-producer-binding-required')

    @classmethod
    def build(cls, document):
        if type(document) is not dict:
            raise ValueError('compiled-F4-producer-binding-required')
        issued = {key: value for key, value in document.items()
                  if key != 'binding_sha256'}
        issued['binding_sha256'] = _digest(issued)
        return cls(_json(issued))

    def document(self):
        return json.loads(self.document_json)

    @property
    def digest(self):
        return sha256(self.document_json.encode()).hexdigest()

    @property
    def row(self):
        return json.loads(self.document_json)['row']

    @property
    def target_component(self):
        return json.loads(self.document_json)['target_component']


def _endpoint_protocol(artifact, endpoint_id):
    rows = [e for e in artifact.plan.binding.endpoints if e.endpoint_id == endpoint_id]
    if len(rows) != 1 or rows[0].protocol is None:
        raise ValueError('compiled-F4-producer-endpoint-unsupported')
    protocol = tuple(rows[0].protocol)
    if protocol != ('apb', '3'):
        raise ValueError('compiled-F4-producer-endpoint-unsupported')
    return protocol


def _register_access(access, register, offset, width_bytes, profile, read_mask):
    """Recheck the declared D3 register word independently of the producer."""
    window = profile.address.window_size if profile.address is not None else None
    if (access.get('register') != register
            or access.get('operation') != 'write'
            or access.get('value_origin') != 'cpu_transaction_wdata'
            or access.get('register_origin') != 'bound_target_register_commit'
            or access.get('width_bytes') != width_bytes
            or access.get('allowed_byte_enables') != [15]
            or access.get('byte_enable_domain') != 'target_word_lanes'
            or access.get('access_alignment') != 4
            or type(window) is not int
            or access.get('window_size') != window
            or type(access.get('window_base')) is not int
            or not 0 <= access['window_base'] < 1 << 32
            or access['window_base'] + window > 1 << 32
            or type(access.get('register_offset')) is not int
            or not 0 <= access['register_offset'] < window
            or access['register_offset'] % 4
            or access.get('address') != access['window_base'] + access['register_offset']
            or type(access.get('value_mask')) is not int
            or not 1 <= access['value_mask'] < 1 << 32):
        raise ValueError('compiled-F4-producer-register-mismatch')
    if access['register_offset'] != offset:
        raise ValueError('compiled-F4-producer-register-mismatch')
    if type(read_mask) is not int or not 1 <= read_mask < 1 << 32:
        raise ValueError('compiled-F4-producer-register-mismatch')
    return dict(name=register, offset=offset, width=width_bytes * 8,
        write_mask=access['value_mask'], read_mask=read_mask,
        address=access['address'],
        window_base=access['window_base'], window_size=window,
        byte_enables=[15], operation='write',
        value_origin='cpu_transaction_wdata')


def _probe_binding_document(observation, verification):
    """Project the observation identity; verified flags require evidence."""
    probe = dict(schema_version=observation['schema_version'],
        digest=observation['digest'],
        source_contract_digest=observation['source_contract']['digest'],
        sample_group=observation['sample_group'],
        port_names=sorted(row['name'] for row in observation['ports']),
        hierarchy_verified=observation['hierarchy_verified'],
        native_verified=observation['native_verified'],
        reset_authority=False, version_authority=False, source_authority=False)
    if verification is not None:
        probe['hierarchy_evidence'] = verification
    return probe


def _bound_input(path, target_component, endpoint_id, register):
    rows = path.get('bound_inputs')
    if (not isinstance(rows, list) or len(rows) != 1
            or not isinstance(rows[0], dict) or rows[0].get('kind') != 'ip_register_commit'
            or rows[0].get('component') != target_component
            or rows[0].get('endpoint_id') != endpoint_id
            or rows[0].get('input_id') !=
            f'{target_component}.{endpoint_id}.register.{register}.value'):
        raise ValueError('compiled-F4-producer-bound-input-mismatch')
    return dict(input_id=rows[0]['input_id'], kind='ip_register_commit',
        component=target_component, endpoint_id=endpoint_id)


def _candidate(path, stream, layout, external_pins):
    return dict(source_id=stream['source_id'], kind='cpu_mmio_stream',
        packed_bits=sum(slice_.width for slice_ in layout.slices),
        bit_length=layout.bit_length, byte_length=layout.byte_length,
        layout_digest=layout.digest,
        external_pin_sources=sorted(source['source_id'] for source in external_pins))


def _gpio_document(*, artifacts, compiled_inputs, path, image, stream, access, layout,
                   target_endpoint, base_dir):
    target_component = access['target_component']
    artifact = artifacts[target_component]
    document = artifact.runtime_document
    if (document.get('kind') != 'apb_gpio'
            or document.get('gpio_observation_contract') != pulp_gpio_observation_contract()):
        raise ValueError('compiled-F4-producer-observation-contract-mismatch')
    try:
        verified = verify_native_physical_observation(artifact)
    except ValueError as error:
        raise ValueError('compiled-F4-producer-observation-contract-mismatch') from error
    if verified is not True:
        raise ValueError('compiled-F4-producer-observation-contract-mismatch')
    if access.get('register') != 'GPIOEN':
        raise ValueError('compiled-F4-producer-register-mismatch')
    protocol = _endpoint_protocol(artifact, target_endpoint)
    register_map = pulp_gpio_register_map()
    entry = register_map['registers'].get(str(access.get('register_offset')))
    if (not isinstance(entry, dict) or entry.get('name') != 'GPIOEN'
            or entry.get('semantics') != 'overwrite'):
        raise ValueError('compiled-F4-producer-register-mismatch')
    register = _register_access(access, 'GPIOEN', 4, 4, artifact.plan.profile,
        0xffffffff)
    probe_document = pulp_gpio_probe_document()
    producer = dict(
        session_class=_qualified(GeneratedPulpGpioSession),
        session_source_sha256=_module_source(GeneratedPulpGpioSession),
        issuer_class=_qualified(GpioRegisterVersionAuthority),
        issuer_source_sha256=_module_source(GpioRegisterVersionAuthority),
        session_construction=dict(setup_writes=[], probe_offsets=[],
            dynamic_inputs=[], bound_inputs=[]),
        commit_consumer=_GPIO_COMMIT_CONSUMER,
        commit_consumer_source_sha256=_module_source(check_writer_observation),
        write_declaration=_qualified(declare_writer),
        write_declaration_source_sha256=_module_source(declare_writer),
        version_issuance='GpioRegisterVersionAuthority.issue/consume/writes',
        live_token_scope='existing_gpio_process_local_single_use',
        grants_reset_prerequisite=False, native_eligibility='existing_unchanged')
    producer['producer_digest'] = _digest(producer)
    return dict(schema_version=SCHEMA, row=ROW_GPIO_CAUSAL,
        target_component=target_component,
        target_artifact_kind='apb_gpio',
        target_artifact_digest=document['artifact_digest'],
        endpoint_id=target_endpoint, protocol=list(protocol),
        template=dict(_GPIO_TEMPLATE),
        executor_template=dict(document.get('selected_template', {}).get('contract') or {}),
        register=register, decode=dict(decode=register_map['decode'],
            alias_period_bytes=register_map['alias_period_bytes'],
            decoded_word=(register['offset'] >> 2) & 31,
            semantics=entry['semantics']),
        source=dict(closure_kind='artifact_carried_source_verification',
            profile_path=artifact.plan.request.profile_path,
            profile_fingerprint=artifact.plan.profile.profile_fingerprint,
            source_verification_sha256=_digest(artifact.source_verification),
            reviewed_source=dict(probe_document['source']),
            source_closure={probe_document['source']['path']:
                            probe_document['source']['sha256']}),
        probe=dict(schema_version=probe_document['schema_version'],
            digest=_digest(probe_document),
            observation_contract=pulp_gpio_observation_contract(),
            sample_group='pin_events', hierarchy_verified=False,
            native_verified=False, source_authority=False),
        producer=producer,
        bound_input=_bound_input(path, target_component, target_endpoint, 'GPIOEN'),
        prerequisite=dict(allowed_kinds=['ip_register_version'],
            expected=dict(kind='ip_register_version', subject=dict(
                component=target_component, register='GPIOEN', reset_epoch=0))),
        candidate=_candidate(path, stream, layout,
            [s for s in path['sources'] if s['kind'] == 'external_pin']),
        live_authority='not_claimed',
        runtime_commit_join='gpio_causal_existing_consumer')


def _apb_template(artifact, endpoint_id):
    policies = artifact.plan.request.tuning.document().get('endpoint_policies', [])
    rows = [row for row in policies if isinstance(row, dict)
            and row.get('endpoint_id') == endpoint_id]
    if len(rows) != 1:
        raise ValueError('compiled-F4-producer-template-unsupported')
    row = rows[0]
    if ({key: row.get(key) for key in ('template_id', 'template_version', 'variant_id')}
            != dict(_APB_TEMPLATE) or row.get('max_outstanding') != 1):
        raise ValueError('compiled-F4-producer-template-unsupported')
    return dict(_APB_TEMPLATE)


def _generic_apb_document(*, artifacts, compiled_inputs, path, image, stream, access,
                          layout, target_endpoint, base_dir):
    target_component = access['target_component']
    artifact = artifacts[target_component]
    document = artifact.runtime_document
    if not isinstance(artifact, LocalRuntimeArtifact):
        raise ValueError('compiled-F4-producer-artifact-required')
    if document.get('kind') != 'apb3_register_observe':
        raise ValueError('compiled-F4-producer-unsupported')
    if document.get('dynamic_physical_inputs') or document.get('bound_physical_inputs'):
        raise ValueError('compiled-F4-producer-input-producer-unsupported')
    external_pins = [s for s in path['sources'] if s['kind'] == 'external_pin']
    if external_pins:
        raise ValueError('compiled-F4-producer-external-pin-unsupported')
    template = _apb_template(artifact, target_endpoint)
    try:
        verified = verify_apb_register_trace(artifact)
    except ValueError as error:
        raise ValueError('compiled-F4-producer-observation-contract-mismatch') from error
    if verified is not True:
        raise ValueError('compiled-F4-producer-observation-contract-mismatch')
    selection = storage_probe_selection(artifact.plan)
    observation = document.get('storage_observation')
    if (not isinstance(observation, dict) or selection is None
            or observation.get('schema_version') != 'apb_storage_probe.v1'
            or observation.get('scope') != 'generated_expression_source_mapped'
            or observation.get('sample_group') != 'storage_probes'
            or observation.get('selection') != selection
            or any(observation.get(key) is not False for key in (
                'reset_authority', 'version_authority',
                'source_authority'))):
        raise ValueError('compiled-F4-producer-observation-contract-mismatch')
    if base_dir is None:
        raise ValueError('compiled-F4-producer-source-inputs-required')
    try:
        registered = validate_apb_storage_source_contract(
            observation.get('source_contract'), artifact.plan.profile, base_dir=base_dir)
    except ValueError as error:
        raise ValueError('compiled-F4-producer-observation-contract-mismatch') from error
    try:
        verification = verified_storage_observation(observation,
            runtime_sv=artifact.runtime_sv,
            wrapper_sha256=(document.get('structural_build') or {}).get(
                'wrapper_sha256'),
            base_dir=base_dir)
    except ValueError as error:
        raise ValueError('compiled-F4-producer-observation-contract-mismatch') from error
    contract_id = registered['contract_id']
    if (selection.get('contract_id') != contract_id
            or selection.get('register') != registered['register']['name']
            or access.get('register') != registered['register']['name']):
        raise ValueError('compiled-F4-producer-register-mismatch')
    contract = registered['register']
    if (type(contract.get('width')) is not int or contract['width'] != 32
            or type(contract.get('canonical_offset')) is not int
            or type(contract.get('write_mask')) is not int
            or type(contract.get('read_mask')) is not int):
        raise ValueError('compiled-F4-producer-register-mismatch')
    register = _register_access(access, contract['name'], contract['canonical_offset'],
        4, artifact.plan.profile, contract['read_mask'])
    if (register['write_mask'] != contract['write_mask']
            or access['value_mask'] != contract['write_mask']
            or register['width'] != contract['width']):
        raise ValueError('compiled-F4-producer-register-mismatch')
    decode = registered['decode']
    if apb_storage_address_matches(registered, access['register_offset']) is not True:
        raise ValueError('compiled-F4-producer-decode-mismatch')
    protocol = _endpoint_protocol(artifact, target_endpoint)
    producer = dict(
        session_class=_qualified(GeneratedApb3RegisterSession),
        session_source_sha256=_module_source(GeneratedApb3RegisterSession),
        issuer_class=_qualified(ApbStorageRegisterVersionAuthority),
        issuer_source_sha256=_module_source(ApbStorageRegisterVersionAuthority),
        session_construction=dict(setup_writes=[], probe_offsets=[],
            dynamic_inputs=[], bound_inputs=[]),
        commit_consumer=_APB_COMMIT_CONSUMER,
        commit_consumer_source_sha256=_module_source(check_storage_observation),
        commit_consumer_receipt_elements=list(APB_RECEIPT_ELEMENTS),
        write_declaration=_qualified(declare_writer),
        write_declaration_source_sha256=_module_source(declare_writer),
        version_issuance='ApbStorageRegisterVersionAuthority.issue/consume/writes',
        live_token_scope='actual_initial_samples_required_not_claimed',
        grants_reset_prerequisite=False, native_eligibility='not_claimed')
    producer['producer_digest'] = _digest(producer)
    return dict(schema_version=SCHEMA, row=ROW_GENERIC_APB_STORAGE,
        target_component=target_component,
        target_artifact_kind='apb3_register_observe',
        target_artifact_digest=document['artifact_digest'],
        endpoint_id=target_endpoint, protocol=list(protocol),
        template=template,
        executor_template=dict(document.get('selected_template', {}).get('contract') or {}),
        register=register, decode=dict(decode=decode['expression'],
            address_width=decode['address_width'], mask=decode['mask'],
            value=decode['value'], alias_period_bytes=decode['alias_period_bytes'],
            raw_address_alias_count=decode['raw_address_alias_count'],
            aligned_word_alias_count=decode['aligned_word_alias_count'],
            host_alignment_bytes=decode['host_alignment_bytes'],
            ignored_address_bits=list(decode['ignored_address_bits'])),
        source=dict(closure_kind='registered_reviewed_source_contract',
            contract_id=contract_id, contract_digest=registered['digest'],
            root=registered['source']['root'],
            revision=registered['source']['revision'],
            top_module=registered['source']['top_module'],
            profile_fingerprint=artifact.plan.profile.profile_fingerprint,
            source_verification_sha256=_digest(artifact.source_verification),
            source_closure=dict(registered['source']['files'])),
        probe=_probe_binding_document(observation, verification),
        producer=producer,
        bound_input=_bound_input(path, target_component, target_endpoint,
                                 contract['name']),
        prerequisite=dict(allowed_kinds=['ip_register_version'],
            expected=dict(kind='ip_register_version', subject=dict(
                component=target_component, register=contract['name'], reset_epoch=0))),
        candidate=_candidate(path, stream, layout, []),
        live_authority='not_claimed',
        runtime_commit_join='generic_apb_storage_commit_consumer')


def select_storage_producer(*, artifacts, compiled_inputs, base_dir=None):
    """Select one closed producer row from trusted declarations, or refuse."""
    _check_pins()
    if (not isinstance(compiled_inputs, dict)
            or set(compiled_inputs) != {'request', 'compiled', 'ownership', 'physical_port_map'}
            or not isinstance(artifacts, Mapping) or not artifacts
            or not isinstance(compiled_inputs['compiled'], dict)):
        raise ValueError('compiled-F4-producer-input-required')
    request = compiled_inputs['request']
    compiled = compiled_inputs['compiled']
    paths = [path for path in compiled.get('paths', ())
             if path.get('flow_id') == 'F4' and path.get('status') == 'executable']
    if len(paths) != 1:
        raise ValueError('compiled-F4-producer-path-unsupported')
    path = paths[0]
    try:
        layout = compile_candidate_layout(path)
    except ValueError as error:
        raise ValueError('compiled-F4-producer-source-shape-unsupported') from error
    sources = {kind: [s for s in path.get('sources', ()) if s.get('kind') == kind]
               for kind in ('instruction_image', 'cpu_mmio_stream')}
    if any(len(rows) != 1 for rows in sources.values()):
        raise ValueError('compiled-F4-producer-source-shape-unsupported')
    image = sources['instruction_image'][0]
    stream = sources['cpu_mmio_stream'][0]
    access = stream.get('register_access')
    cpu = getattr(request, 'cpu', None)
    devices = getattr(request, 'devices', ())
    if (not isinstance(access, dict) or cpu is None
            or image.get('component') != cpu.instance_id
            or access.get('source_component') != cpu.instance_id
            or access.get('source_endpoint') != stream.get('endpoint_id')
            or len(devices) != 1
            or getattr(devices[0], 'instance_id', None) != access.get('target_component')):
        raise ValueError('compiled-F4-producer-topology-unsupported')
    target_component = access['target_component']
    target_endpoint = access.get('target_endpoint')
    if type(target_endpoint) is not str or not target_endpoint:
        raise ValueError('compiled-F4-producer-endpoint-unsupported')
    artifact = artifacts.get(target_component)
    if getattr(artifact, 'plan', None) is None or not isinstance(
            getattr(artifact, 'runtime_document', None), dict):
        raise ValueError('compiled-F4-producer-artifact-required')
    if artifact.plan.request.instance_id != target_component:
        raise ValueError('compiled-F4-producer-artifact-instance-mismatch')
    kind = artifact.runtime_document.get('kind')
    if kind == 'apb_gpio':
        document = _gpio_document(artifacts=artifacts, compiled_inputs=compiled_inputs,
            path=path, image=image, stream=stream, access=access, layout=layout,
            target_endpoint=target_endpoint, base_dir=base_dir)
    elif kind == 'apb3_register_observe':
        document = _generic_apb_document(artifacts=artifacts,
            compiled_inputs=compiled_inputs, path=path, image=image, stream=stream,
            access=access, layout=layout, target_endpoint=target_endpoint,
            base_dir=base_dir)
    else:
        raise ValueError('compiled-F4-producer-unsupported')
    return AdmittedStorageProducerBinding.build(document)


def validate_storage_producer_binding(binding, *, artifacts, compiled_inputs, base_dir=None):
    """Rebuild from trusted inputs; a stale/foreign/tampered binding refuses."""
    _check_pins()
    if type(binding) is not AdmittedStorageProducerBinding:
        raise ValueError('compiled-F4-producer-binding-required')
    expected = select_storage_producer(artifacts=artifacts,
        compiled_inputs=compiled_inputs, base_dir=base_dir)
    if binding.document_json != expected.document_json:
        raise ValueError('compiled-F4-producer-binding-mismatch')
    return binding


def build_storage_producer(binding, *, artifact, base_dir, cache_dir, max_cases):
    """Construct the exact code-owned session and issuer of the selected row.

    Construction is mechanical: it neither starts a process nor issues a token.
    Callers remain responsible for the rows' live admission requirements.
    """
    _check_pins()
    if type(binding) is not AdmittedStorageProducerBinding:
        raise ValueError('compiled-F4-producer-binding-required')
    document = binding.document()
    if (not isinstance(artifact, LocalRuntimeArtifact)
            or artifact.runtime_document.get('artifact_digest')
            != document.get('target_artifact_digest')
            or artifact.runtime_document.get('kind') != document.get('target_artifact_kind')):
        raise ValueError('compiled-F4-producer-artifact-binding-mismatch')
    if type(max_cases) is not int or not 1 <= max_cases <= 65528:
        raise ValueError('compiled-F4-producer-budget-invalid')
    if document['row'] == ROW_GPIO_CAUSAL:
        target = GeneratedPulpGpioSession(artifact, base_dir=base_dir, cache_dir=cache_dir)
        authority = GpioRegisterVersionAuthority(target, max_writes=max_cases + 8)
        return target, authority
    if document['row'] == ROW_GENERIC_APB_STORAGE:
        support = storage_consumer_support(binding=binding,
            artifacts={document['target_component']: artifact})
        if support['complete'] is not True:
            missing = ','.join(row['element'] for row in support['refusals'])
            raise ValueError(
                'compiled-F4-producer-receipt-join-incomplete:' + missing)
        target = GeneratedApb3RegisterSession(artifact, base_dir=base_dir,
            cache_dir=cache_dir, setup_writes=(), probe_offsets=())
        authority = ApbStorageRegisterVersionAuthority(target,
            max_writes=max_cases + 8, max_samples=65536, max_tokens=16)
        return target, authority
    raise ValueError('compiled-F4-producer-unsupported')


_BINDING_TYPE = AdmittedStorageProducerBinding
_SELECT_PIN = (select_storage_producer, select_storage_producer.__code__)
_VALIDATE_PIN = (validate_storage_producer_binding, validate_storage_producer_binding.__code__)
_BUILD_PIN = (build_storage_producer, build_storage_producer.__code__)
