"""Profile-declared observation of real CPU external-IRQ decision ports.

The profile author describes source semantics. A pinned source and passive
physical observations do not independently prove that description; RVFI
interrupt markers never establish external-source attribution.
"""
import hashlib
from pathlib import Path
import re

_PORT = re.compile(r'[A-Za-z_][A-Za-z0-9_]*\Z')
_HASH = re.compile(r'[0-9a-f]{64}\Z')
SCHEMA = 'profile_native_irq_receipts.v1'


def profile_irq_contract(profile):
    doc = profile.evidence.get('native_irq_observation')
    if (type(doc) is not dict or set(doc) != {'schema_version', 'input_port',
            'masked_port', 'taken_port', 'source_semantics', 'source_files'}
            or doc.get('schema_version') != 'profile_native_irq_observation.v1'
            or doc.get('source_semantics') != 'machine_external_cause_only'
            or profile.cpu is None):
        raise ValueError('invalid-profile-native-IRQ-observation')
    names = [doc['input_port'], doc['masked_port'], doc['taken_port']]
    if (any(type(name) is not str or not _PORT.fullmatch(name) or name.startswith('rvfi_')
            for name in names) or len(set(names)) != 3):
        raise ValueError('invalid-profile-native-IRQ-ports')
    sources = doc['source_files']
    if (type(sources) is not dict or not sources
            or any(type(path) is not str or path not in profile.source.files
                or type(digest) is not str or not _HASH.fullmatch(digest)
                for path, digest in sources.items())):
        raise ValueError('invalid-profile-native-IRQ-source-files')
    return dict(schema_version=SCHEMA, profile_id=profile.component_id,
        input_port=doc['input_port'], input_width=1, sampling='pre_post_rising',
        wire_schema_version='local_driver.v1',
        source=dict(root=profile.source.source_root, revision=profile.source.revision,
                    sha256=dict(sources)),
        decision_probes={'irq_masked_pre':doc['masked_port'], 'irq_taken_pre':doc['taken_port']},
        notification_widths={'rvfi_valid':1},
        notification_semantics='no_post_irq_notification_or_RVFI_source_attribution',
        context_semantics='planned_binding_refs_never_source_authority',
        generic_irq_entry_origin='unknown', retirement_authority='pc_insn_order_only',
        retirement_diversion_fields=[], retirement_diversion_scope='unobservable',
        retirement_receipt=dict(schema_version='cpu_retire.v2', phase='post', rvfi_fields=4,
            scope='complete_parsed_STEP_CPU_receipt',
            tick_fields=['tick_before','tick_after','new_ticks','local_tick_base']),
        startup_reset_receipt=dict(schema_version='cpu_native_startup.v1',
            source='authenticated_startup_ready',initial_csr_origin='unknown'))


def verify_profile_irq_source(profile, *, base_dir):
    from .source_lock import verify_local_source_lock
    contract = profile_irq_contract(profile)
    root = Path(base_dir).resolve()
    verification = verify_local_source_lock(profile, base_dir=root)
    for relative, digest in contract['source']['sha256'].items():
        source = root / profile.source.source_root / relative
        if source.is_symlink() or hashlib.sha256(source.read_bytes()).hexdigest() != digest:
            raise ValueError('profile-native-IRQ-source-mismatch:' + relative)
    return verification


def validate_profile_irq_contract(contract):
    """Enforce the closed observation shape, including unknown attribution."""
    from types import SimpleNamespace
    try:
        source = contract['source']; probes = contract['decision_probes']
        description = dict(schema_version='profile_native_irq_observation.v1',
            input_port=contract['input_port'], masked_port=probes['irq_masked_pre'],
            taken_port=probes['irq_taken_pre'], source_semantics='machine_external_cause_only',
            source_files=source['sha256'])
        profile = SimpleNamespace(component_id=contract['profile_id'], cpu=object(),
            evidence={'native_irq_observation': description},
            source=SimpleNamespace(source_root=source['root'], revision=source['revision'],
                                   files=tuple(source['sha256'])))
        if contract != profile_irq_contract(profile):
            raise ValueError('invalid-profile-native-IRQ-contract')
    except (KeyError, TypeError, AttributeError):
        raise ValueError('invalid-profile-native-IRQ-contract') from None


def profile_irq_probe_outputs(contract, exports):
    """Use only uniquely exposed real 1-bit top-level decision outputs."""
    rows = {}
    for probe, port in contract['decision_probes'].items():
        matches = [row for row in exports if row.get('physical_port') == port
                   and row.get('direction') == 'output' and row.get('width') == 1
                   and row.get('disposition') == 'observe']
        if len(matches) != 1:
            raise ValueError('profile-native-IRQ-decision-port-missing:' + port)
        rows[probe] = matches[0]['runtime_name']
    return rows


def verify_profile_irq_artifact(artifact, *, base_dir):
    from .runtime_artifact import LocalRuntimeArtifact
    if type(artifact) is not LocalRuntimeArtifact or artifact.runtime_document.get('kind') != 'obi_cpu':
        raise ValueError('profile-native-IRQ-OBI-artifact-required')
    profile = artifact.plan.profile
    verified = verify_profile_irq_source(profile, base_dir=base_dir)
    doc = artifact.runtime_document
    if (doc.get('source_verification') != verified
            or hashlib.sha256(artifact.runtime_sv.encode()).hexdigest() != doc.get('runtime_sv_sha256')):
        raise ValueError('profile-native-IRQ-artifact-source-mismatch')
    contract = profile_irq_contract(profile)
    exports = doc['physical_exports']
    rvfi = {'rvfi_valid':1, 'rvfi_order':64, 'rvfi_insn':32, 'rvfi_pc_rdata':32}
    observed = {row.get('physical_port'):row.get('width') for row in exports
                if row.get('direction')=='output' and row.get('disposition')=='observe'
                and isinstance(row.get('physical_port'),str)
                and row['physical_port'].startswith('rvfi_')}
    if observed != rvfi:
        raise ValueError('profile-native-IRQ-limited-retirement-exports-required')
    sources = profile_irq_probe_outputs(contract, exports)
    for probe, source in sources.items():
        rows = [row for row in exports if row.get('physical_port') == probe
                and row.get('runtime_name') == 'probe_'+probe
                and row.get('direction') == 'output' and row.get('width') == 1]
        if len(rows) != 1 or f'assign probe_{probe} = {source};' not in artifact.runtime_sv:
            raise ValueError('profile-native-IRQ-decision-probe-mismatch:' + probe)
    rows = [row for row in exports if row.get('physical_port') == contract['input_port']
        and row.get('direction') == 'input' and row.get('width') == 1
        and row.get('endpoint_id') == profile.cpu.irq_entry_endpoint
        and row.get('role') == profile.cpu.irq_entry_role]
    if len(rows) != 1:
        raise ValueError('profile-native-IRQ-input-port-mismatch')
    return rows[0]['runtime_name']
