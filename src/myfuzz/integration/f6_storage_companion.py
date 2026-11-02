"""Source admission for optional storage targets in the shared F6 runner."""
from pathlib import Path

from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
from myfuzz.local_harness.apb_storage_source_contract import validate_apb_storage_source_contract
from myfuzz.local_harness.apb_storage_probe_verification import verified_storage_observation
from myfuzz.local_harness.apb_storage_probe_contract import storage_probe_selection
from myfuzz.local_harness.native_physical_observation import verify_apb_register_trace
from myfuzz.scenario.compiled_paths import PathCompileRequest
from .compiled_storage_producer import _module_source


def _require(condition, reason):
    if not condition:
        raise ValueError('compiled-F6-assembly-companion-' + reason)


def _companion_document(name, artifact, window, source):
    return dict(schema_version='compiled_F6_storage_companion.v1',
        component=name, artifact_digest=artifact.runtime_document['artifact_digest'],
        profile_fingerprint=artifact.plan.profile.profile_fingerprint,
        window=dict(device_id=name, base=window.base, size=window.size, endpoint=window.endpoint_id),
        register=source['register']['name'], source_contract=source,
        session_source_sha256=_module_source(GeneratedApb3RegisterSession),
        storage_operations='not_claimed_by_assembly')


def _mmio_companion_document(name, artifact, window, source):
    from myfuzz.runtime.adapters.apb3_mmio import bank_contract_facts
    bank = bank_contract_facts(artifact, endpoint_id=window.endpoint_id)
    return dict(schema_version='compiled_F6_mmio_companion.v1',
        component=name, artifact_digest=artifact.runtime_document['artifact_digest'],
        profile_fingerprint=artifact.plan.profile.profile_fingerprint,
        window=dict(device_id=name, base=window.base, size=window.size, endpoint=window.endpoint_id),
        register=source['register'], source_contract=source, semantic_bank_sha256=bank.sha256_hex,
        session_source_sha256=_module_source(GeneratedApb3RegisterSession),
        storage_operations='unknown', cross_case_origin='unknown', reward_eligible=False)


def _irq_companion_document(name, artifact, window, source):
    return dict(schema_version='compiled_F6_declared_irq_companion.v1', component=name,
        artifact_digest=artifact.runtime_document['artifact_digest'],
        profile_fingerprint=artifact.plan.profile.profile_fingerprint,
        window=dict(device_id=name, base=window.base, size=window.size, endpoint=window.endpoint_id),
        source_contract=source, storage_operations='unknown', cross_case_origin='unknown',
        reward_eligible=False)


def companion_artifact_documents(*, contract, artifacts, request, base_dir):
    pair = {contract['cpu']['instance_id'], contract['dma']['instance_id']}
    extra = set(artifacts) - pair
    if not extra:
        return {}
    _require(type(request) is PathCompileRequest, 'request-required')
    _require(set(artifacts) == {request.cpu.instance_id, *(row.instance_id for row in request.devices)},
        'artifact-set')
    documents = {}
    resource = contract['memory']['resource']
    for name in sorted(extra):
        artifact = artifacts[name]
        component = request.device(name)
        _require(component is not None and artifact.plan.request.instance_id == name
            and component.profile == artifact.plan.profile, 'profile-owner')
        doc = artifact.runtime_document
        declared_irq = contract['program_contract'].get('declared_irq', {})
        if name == declared_irq.get('component'):
            windows = [w for w in request.wiring.windows if w.target_instance == name]
            _require(len(windows) == 1 and windows[0].device_id == name, 'window-required')
            window = windows[0]
            _require(not (window.base < resource['base'] + resource['size']
                and resource['base'] < window.base + window.size), 'window-overlaps-RAM')
            _require(doc.get('kind') == 'apb3_register_observe'
                and verify_apb_register_trace(artifact) is True, 'observation-contract')
            _require(artifact.plan.profile.profile_fingerprint == declared_irq['source']['profile_fingerprint'],
                'declared-IRQ-profile')
            documents[name] = _irq_companion_document(name, artifact, window, declared_irq)
            continue
        if doc.get('kind')=='apb_gpio':
            from .f6_gpio_companion import gpio_companion_document
            windows=[w for w in request.wiring.windows if w.target_instance==name]
            _require(len(windows)==1 and windows[0].device_id==name,'window-required')
            window=windows[0]
            _require(not (window.base<resource['base']+resource['size'] and resource['base']<window.base+window.size),'window-overlaps-RAM')
            documents[name]=gpio_companion_document(name,artifact,window,base_dir=base_dir)
            continue
        layout = contract['program_contract'].get('shared_slots', {})
        if name == layout.get('component') and layout.get('observation_mode') == 'bus':
            from .shared_mmio_companion import shared_mmio_source
            windows = [w for w in request.wiring.windows if w.target_instance == name]
            _require(len(windows) == 1 and windows[0].device_id == name, 'window-required')
            window = windows[0]
            _require(not (window.base < resource['base'] + resource['size']
                and resource['base'] < window.base + window.size), 'window-overlaps-RAM')
            source = shared_mmio_source(request, layout)
            _require(source['digest'] == layout['source_contract_digest'], 'mmio-contract')
            documents[name] = _mmio_companion_document(name, artifact, window, source)
            continue
        _require(doc.get('kind') == 'apb3_register_observe'
            and not doc.get('dynamic_physical_inputs') and not doc.get('bound_physical_inputs')
            and verify_apb_register_trace(artifact) is True, 'observation-contract')
        observation = doc.get('storage_observation')
        _require(isinstance(observation, dict)
            and observation.get('selection') == storage_probe_selection(artifact.plan), 'source-contract')
        source = validate_apb_storage_source_contract(observation.get('source_contract'),
            artifact.plan.profile, base_dir=Path(base_dir))
        verified_storage_observation(observation, runtime_sv=artifact.runtime_sv,
            wrapper_sha256=(doc.get('structural_build') or {}).get('wrapper_sha256'), base_dir=Path(base_dir))
        windows = [window for window in request.wiring.windows if window.target_instance == name]
        _require(len(windows) == 1 and windows[0].device_id == name, 'window-required')
        window = windows[0]
        _require(not (window.base < resource['base'] + resource['size']
            and resource['base'] < window.base + window.size), 'window-overlaps-RAM')
        _require(component.endpoint(window.endpoint_id).protocol == ('apb', '3'), 'endpoint-protocol')
        documents[name] = _companion_document(name, artifact, window, source)
    return documents


def validate_companion_build_documents(documents, *, artifacts, wiring):
    """Associate saved metadata to actual artifact values, never live owners."""
    from myfuzz.local_harness.apb_storage_source_contract import _require_registered_document, _verify_profile
    for name, document in documents.items():
        artifact = artifacts[name]
        if document.get('schema_version') == 'compiled_F6_declared_irq_companion.v1':
            source = document['source_contract']
            windows = [row for row in wiring.windows if row.target_instance == name]
            _require(len(windows) == 1 and source['component'] == name
                and source['source']['profile_fingerprint'] == artifact.plan.profile.profile_fingerprint
                and document == _irq_companion_document(name, artifact, windows[0], source),
                'build-declared-IRQ-document')
            continue
        if document.get('schema_version') == 'compiled_F6_mmio_companion.v1':
            from hashlib import sha256
            import json
            source = document['source_contract']
            body = {k:v for k,v in source.items() if k != 'digest'}
            _require(source['digest'] == sha256(json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
                and source['component'] == name and source['profile_fingerprint'] == artifact.plan.profile.profile_fingerprint,
                'build-mmio-source')
            windows = [row for row in wiring.windows if row.target_instance == name]
            _require(len(windows) == 1 and document == _mmio_companion_document(name, artifact, windows[0], source),
                'build-mmio-document')
            continue
        if document.get('schema_version')=='compiled_F6_gpio_companion.v1':
            from .f6_gpio_companion import gpio_companion_document
            windows=[row for row in wiring.windows if row.target_instance==name]
            _require(len(windows)==1,'build-window')
            _require(document==gpio_companion_document(name,artifact,windows[0],base_dir=Path(__file__).resolve().parents[3]),'build-document')
            continue
        observation = artifact.runtime_document.get('storage_observation', {})
        source = observation.get('source_contract')
        _require_registered_document(source)
        _verify_profile(artifact.plan.profile, source)
        _require(artifact.runtime_document.get('kind') == 'apb3_register_observe'
            and observation.get('selection') == storage_probe_selection(artifact.plan)
            and verify_apb_register_trace(artifact) is True, 'build-artifact')
        windows = [row for row in wiring.windows if row.target_instance == name]
        _require(len(windows) == 1 and windows[0].device_id == name, 'build-window')
        _require(document == _companion_document(name, artifact, windows[0], source), 'build-document')


def validate_companion_sessions(*, documents, artifacts, sessions):
    for name, document in documents.items():
        local = sessions.get(name)
        if document.get('schema_version')=='compiled_F6_gpio_companion.v1':
            from .f6_gpio_companion import validate_gpio_companion_session
            validate_gpio_companion_session(document,artifacts[name],local)
            continue
        _require(type(local) is GeneratedApb3RegisterSession
            and local.artifact is artifacts[name], 'session-owner')
        _require(not local.setup_writes and not local.probe_offsets, 'hidden-setup')
        _require(local.identity_document()['runtime_artifact'] == artifacts[name].runtime_document,
            'session-artifact')
