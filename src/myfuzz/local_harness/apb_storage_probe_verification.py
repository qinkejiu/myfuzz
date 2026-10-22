"""Evidence-bound hierarchy/native verification for registered APB probes.

The registered APB storage source contract describes one reviewed expression.
It does not, by itself, prove that the expression resolves to a live variable
in an elaborated model.  This module consumes a committed native proof: the
exact generated runtime was elaborated by Verilator, a native model was built,
and the ten ``storage_*`` ports were sampled across reset, writes and a read.

The proof is bound by digest to:

* the exact probe ports (names, widths, expressions),
* the reviewed source-contract digest, source bytes and parameters,
* the generated runtime SV bytes and wrapper bytes.

A missing, stale or tampered proof leaves the prospective flags false.  A
document that already claims verification is refused unless the proof validates.
Nothing here issues reset, version or source authority.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

PROOF_SCHEMA = 'apb_storage_probe_hierarchy_proof.v1'
PROOF_STATUS = 'verified'
EVIDENCE_SCHEMA = 'apb_storage_hierarchy_evidence.v1'
PROOF_RELATIVE = 'docs/reports/evidence/verilog-probe-pulp-apb-timer/proof.json'
TIMER_CONTRACT = 'pulp-apb-timer.ctrl0.source.v1'
SPI_CONTRACT = 'pulp-apb-spi.spicmd.source.v1'
_PROOF_REFERENCES = {
    TIMER_CONTRACT: PROOF_RELATIVE,
    SPI_CONTRACT: 'docs/reports/evidence/verilog-probe-pulp-apb-spi/proof.json',
}
_SPI_CHECK_NAMES = (
    'ten_probe_ports_declared', 'expression_resolves_elaboration',
    'unbound_expression_refused', 'reset_value_zero', 'spicmd_write_commits',
    'wrong_register_write_does_not_commit', 'readback_matches_storage_prdata',
    'all_ten_ports_sample_live',
)


_CHECK_NAMES = (
    'ten_probe_ports_declared',
    'expression_resolves_elaboration',
    'unbound_expression_refused',
    'reset_value_zero',
    'timer0_write_commits',
    'timer1_write_does_not_commit',
    'readback_matches_storage_prdata',
    'all_ten_ports_sample_live',
)
_PROOF_KEYS = {
    'schema_version', 'status', 'probe_binding_digest', 'expression', 'ports',
    'runtime_sv_sha256', 'wrapper_sha256', 'source', 'parameters', 'verilator',
    'commands',
    'negative_controls', 'samples', 'sample_digest', 'checks', 'inputs',
    'proof_digest',
}
_EVIDENCE_KEYS = {
    'schema_version', 'reference', 'proof_digest', 'binding_digest',
    'runtime_sv_sha256', 'wrapper_sha256', 'verilator', 'sample_digest',
}
_SAMPLE_KEYS = {
    'cycle', 'value', 'paddr', 'psel', 'penable', 'pwrite', 'pwdata',
    'prdata', 'pready', 'pslverr', 'reset',
}


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      allow_nan=False)


def _digest(value):
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _sha256_text(text):
    return hashlib.sha256(text.encode()).hexdigest()


def _is_sha256(value):
    return (type(value) is str and len(value) == 64
            and all(c in '0123456789abcdef' for c in value))


def _proof_reference(probe):
    try:
        contract_id = probe['source_contract']['contract_id']
        if probe['selection']['contract_id'] != contract_id:
            raise ValueError('apb-storage-proof-contract-mismatch')
        return _PROOF_REFERENCES[contract_id]
    except (KeyError, TypeError) as error:
        raise ValueError('apb-storage-proof-contract-unsupported') from error


def proof_path(base_dir, probe=None):
    reference = PROOF_RELATIVE if probe is None else _proof_reference(probe)
    return Path(base_dir).absolute() / reference


def probe_binding_digest(probe):
    """Digest of the exact hierarchy expression, ports and source identity."""
    if type(probe) is not dict:
        raise ValueError('apb-storage-probe-binding-shape')
    contract = probe.get('source_contract')
    if (not isinstance(contract, dict)
            or not isinstance(contract.get('source'), dict)
            or not isinstance(contract.get('parameters'), dict)
            or not isinstance(contract.get('storage_expression'), dict)
            or type(contract['storage_expression'].get('expression')) is not str
            or not _is_sha256(contract.get('digest'))
            or type(probe.get('ports')) is not list or not probe['ports']):
        raise ValueError('apb-storage-probe-binding-shape')
    return _digest(dict(
        schema_version=probe.get('schema_version'), scope=probe.get('scope'),
        selection=probe.get('selection'), sample_group=probe.get('sample_group'),
        ports=probe['ports'], source_contract_digest=contract['digest'],
        source=contract['source'], parameters=contract['parameters']))


def _verify_source(source, base_dir):
    if (not isinstance(source, dict) or type(source.get('root')) is not str
            or not isinstance(source.get('files'), dict) or not source['files']):
        raise ValueError('apb-storage-proof-source-shape')
    root = Path(base_dir).absolute() / source['root']
    if Path(source['root']).is_absolute() or '..' in Path(source['root']).parts:
        raise ValueError('apb-storage-proof-source-shape')
    for name, expected in source['files'].items():
        if type(name) is not str or not _is_sha256(expected):
            raise ValueError('apb-storage-proof-source-shape')
        path = root / name
        if any(part.is_symlink() for part in (path, *path.parents)):
            raise ValueError('apb-storage-proof-source-symlink')
        try:
            raw = path.read_bytes()
        except OSError as error:
            raise ValueError('apb-storage-proof-source-unavailable') from error
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('apb-storage-proof-source-bytes-changed')


def _verify_samples(samples, sample_digest):
    if not isinstance(samples, list) or not samples:
        raise ValueError('apb-storage-proof-samples-shape')
    for row in samples:
        if type(row) is not dict or set(row) != _SAMPLE_KEYS:
            raise ValueError('apb-storage-proof-samples-shape')
        if any(type(row[key]) is not int or row[key] < 0 for key in _SAMPLE_KEYS):
            raise ValueError('apb-storage-proof-samples-shape')
    if sample_digest != _digest(samples):
        raise ValueError('apb-storage-proof-samples-digest')
    if (not any(row['reset'] == 1 for row in samples)
            or any(row['value'] != 0 for row in samples if row['reset'] == 1)
            or not any(row['reset'] == 0 for row in samples)):
        raise ValueError('apb-storage-proof-reset-sample')
    if not any(row['psel'] == 1 and row['penable'] == 1 for row in samples):
        raise ValueError('apb-storage-proof-access-sample')
    if not any(row['psel'] == 1 and row['penable'] == 1 and row['pwrite'] == 1
               and row['pwdata'] != 0 for row in samples):
        raise ValueError('apb-storage-proof-write-sample')
    if not any(row['psel'] == 1 and row['penable'] == 1 and row['pwrite'] == 0
               for row in samples):
        raise ValueError('apb-storage-proof-read-sample')
    if any(row['pready'] not in (0, 1) or row['pslverr'] not in (0, 1)
           for row in samples):
        raise ValueError('apb-storage-proof-ready-sample')
    if len({row['value'] for row in samples}) < 2 or not any(
            row['value'] != 0 for row in samples):
        raise ValueError('apb-storage-proof-storage-sample')


def validate_native_proof(proof, *, probe, runtime_sv, wrapper_sha256,
                          base_dir):
    """Validate a committed proof against the exact probe/runtime/wrapper.

    Returns the evidence reference to embed in a verified observation.  Raises
    ``ValueError`` on any stale, mismatched or malformed proof; callers that
    only generate artifacts may treat that refusal as "unverified" rather than
    claiming a verified binding.
    """
    reference = _proof_reference(probe)
    spi = probe['source_contract']['contract_id'] == SPI_CONTRACT
    keys = _PROOF_KEYS | {'evidence_bundle'} if spi else _PROOF_KEYS
    if type(proof) is not dict or set(proof) != keys:
        raise ValueError('apb-storage-proof-shape')
    if (proof.get('schema_version') != PROOF_SCHEMA
            or proof.get('status') != PROOF_STATUS):
        raise ValueError('apb-storage-proof-schema')
    body = {key: value for key, value in proof.items() if key != 'proof_digest'}
    if not _is_sha256(proof.get('proof_digest')) or proof['proof_digest'] != _digest(body):
        raise ValueError('apb-storage-proof-digest')
    if type(probe) is not dict or type(runtime_sv) is not str:
        raise ValueError('apb-storage-proof-binding-shape')
    binding = probe_binding_digest(probe)
    if proof.get('probe_binding_digest') != binding:
        raise ValueError('apb-storage-proof-binding-mismatch')
    try:
        expected_expression = probe['source_contract'][
            'storage_expression']['expression']
    except (KeyError, TypeError) as error:
        raise ValueError('apb-storage-proof-binding-shape') from error
    if (proof.get('ports') != probe['ports']
            or proof.get('expression') != expected_expression):
        raise ValueError('apb-storage-proof-expression-mismatch')
    contract = probe['source_contract']
    if (proof.get('source') != contract['source']
            or proof.get('parameters') != contract['parameters']):
        raise ValueError('apb-storage-proof-source-mismatch')
    _verify_source(contract['source'], base_dir)
    if (proof.get('runtime_sv_sha256') != _sha256_text(runtime_sv)
            or not _is_sha256(wrapper_sha256)
            or proof.get('wrapper_sha256') != wrapper_sha256):
        raise ValueError('apb-storage-proof-generated-bytes-mismatch')
    verilator = proof.get('verilator')
    if (not isinstance(verilator, dict)
            or set(verilator) != {'version', 'top_module'}
            or type(verilator['version']) is not str or not verilator['version']
            or type(verilator['top_module']) is not str
            or not verilator['top_module']):
        raise ValueError('apb-storage-proof-verilator-shape')
    if not isinstance(proof.get('commands'), dict) or not proof['commands']:
        raise ValueError('apb-storage-proof-commands-shape')
    inputs = proof.get('inputs')
    if (not isinstance(inputs, dict) or not inputs
            or any(type(name) is not str or not name
                   or not _is_sha256(value)
                   for name, value in inputs.items())):
        raise ValueError('apb-storage-proof-inputs-shape')
    controls = proof.get('negative_controls')
    if (not isinstance(controls, list) or not controls
            or any(not isinstance(row, dict)
                   or row.get('refused') is not True
                   or not isinstance(row.get('mutation'), str)
                   or type(row.get('exit_code')) is not int
                   or row['exit_code'] == 0 for row in controls)):
        raise ValueError('apb-storage-proof-negative-controls')
    if spi and {row['mutation'] for row in controls} != {
            'unknown-instance-name', 'unknown-register-name', 'wrong-register-expression'}:
        raise ValueError('apb-storage-proof-spi-negative-controls')
    checks = proof.get('checks')
    names = _SPI_CHECK_NAMES if spi else _CHECK_NAMES
    if (not isinstance(checks, dict) or set(checks) != set(names)
            or any(checks[name] is not True for name in names)):
        raise ValueError('apb-storage-proof-checks')
    _verify_samples(proof.get('samples'), proof.get('sample_digest'))
    if spi:
        measured_checks = spi_sample_checks(proof['samples'])
        if not all(measured_checks.values()):
            raise ValueError('apb-storage-proof-spi-samples')
        _verify_spi_bundle(proof, base_dir, reference)
    return dict(schema_version=EVIDENCE_SCHEMA, reference=reference,
                proof_digest=proof['proof_digest'], binding_digest=binding,
                runtime_sv_sha256=proof['runtime_sv_sha256'],
                wrapper_sha256=proof['wrapper_sha256'],
                verilator=copy.deepcopy(verilator),
                sample_digest=proof['sample_digest'])


def _load_proof(base_dir, probe=None):
    path = proof_path(base_dir, probe)
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ValueError('apb-storage-proof-unavailable') from error
    try:
        proof = json.loads(raw)
    except (TypeError, ValueError) as error:
        raise ValueError('apb-storage-proof-json') from error
    if type(proof) is not dict:
        raise ValueError('apb-storage-proof-shape')
    return proof


def attach_native_proof(probe, *, runtime_sv, wrapper_sha256, base_dir):
    """Return a verified copy of ``probe`` when the committed proof binds it.

    No proof, a stale proof or a malformed proof leaves the prospective flags
    exactly as generated.  A caller-supplied expression or evidence reference
    can never extend the registry or manufacture this transition.
    """
    if not isinstance(probe, dict):
        raise ValueError('apb-storage-probe-shape')
    document = copy.deepcopy(probe)
    try:
        proof = _load_proof(base_dir, probe)
        evidence = validate_native_proof(
            proof, probe=probe, runtime_sv=runtime_sv,
            wrapper_sha256=wrapper_sha256, base_dir=base_dir)
    except (KeyError, TypeError, ValueError):
        # Fail closed: an unbound expression is better than a false claim.
        return document
    document['hierarchy_verified'] = True
    document['native_verified'] = True
    document['hierarchy_evidence'] = evidence
    document.pop('digest', None)
    document['digest'] = _digest(document)
    return document


def verified_storage_observation(observation, *, runtime_sv, wrapper_sha256,
                                 base_dir):
    """Return evidence for a verified observation; ``None`` for prospective.

    A prospective observation must carry no evidence.  A verified observation
    must carry a valid evidence reference and both flags true.  Anything else
    is refused rather than downgraded.
    """
    if not isinstance(observation, dict):
        raise ValueError('apb-storage-observation-shape')
    hierarchy = observation.get('hierarchy_verified')
    native = observation.get('native_verified')
    if type(hierarchy) is not bool or type(native) is not bool:
        raise ValueError('apb-storage-observation-flags')
    if not hierarchy and not native:
        if 'hierarchy_evidence' in observation:
            raise ValueError('apb-storage-observation-evidence-without-flags')
        return None
    if not (hierarchy and native):
        raise ValueError('apb-storage-observation-flag-mismatch')
    reference = observation.get('hierarchy_evidence')
    if (not isinstance(reference, dict) or set(reference) != _EVIDENCE_KEYS
            or reference.get('schema_version') != EVIDENCE_SCHEMA
            or reference.get('reference') != _proof_reference(observation)):
        raise ValueError('apb-storage-observation-evidence-shape')
    try:
        proof = _load_proof(base_dir, observation)
        evidence = validate_native_proof(
            proof, probe=observation, runtime_sv=runtime_sv,
            wrapper_sha256=wrapper_sha256, base_dir=base_dir)
    except (KeyError, TypeError) as error:
        raise ValueError('apb-storage-observation-evidence-shape') from error
    for key in ('proof_digest', 'binding_digest', 'runtime_sv_sha256',
                'wrapper_sha256', 'verilator', 'sample_digest'):
        if reference.get(key) != evidence[key]:
            raise ValueError('apb-storage-observation-evidence-mismatch')
    return evidence


def spi_sample_checks(samples):
    """Derive SPI checks from ordered physical samples, never proof booleans."""
    _verify_samples(samples, _digest(samples))
    if any(set(row) != _SAMPLE_KEYS for row in samples):
        raise ValueError('apb-storage-proof-spi-samples')
    if any(row['cycle'] >= following['cycle'] for row, following in zip(samples, samples[1:])):
        raise ValueError('apb-storage-proof-spi-sample-order')
    for row in samples:
        if (row['value'] >= 1 << 32 or row['pwdata'] >= 1 << 32
                or row['prdata'] >= 1 << 32 or row['paddr'] >= 4096
                or any(row[k] not in (0, 1) for k in ('reset','psel','penable','pwrite'))):
            raise ValueError('apb-storage-proof-spi-sample-width')
    released = [r for r in samples if r['reset'] == 0]
    accesses = [(i, r) for i, r in enumerate(samples) if r['psel'] and r['penable']]
    allowed = bool(accesses) and all(r['paddr'] in (8,12) and r['pready']==1
        and r['pslverr']==0 and r['reset']==0 for _,r in accesses)
    writes = [(i,r) for i,r in accesses if r['pwrite'] and r['paddr']==8]
    wrong = [(i,r) for i,r in accesses if r['pwrite'] and r['paddr']==12]
    reads = [(i,r) for i,r in accesses if not r['pwrite'] and r['paddr']==8]
    commits = []
    readbacks = []
    for i, row in writes:
        # The first sample after ACCESS is the post-edge storage result.
        commits.append(i+1 < len(samples) and samples[i+1]['value']==row['pwdata'])
        next_write = next((j for j,_ in writes if j>i), len(samples))
        readbacks.append(any(i<j<next_write and r['prdata']==row['pwdata']
            and r['value']==row['pwdata'] for j,r in reads))
    unmoved = bool(wrong) and all(i+1<len(samples)
        and samples[i+1]['value']==row['value'] for i,row in wrong)
    return dict(
        reset_value_zero=bool(released) and released[0]['value']==0,
        spicmd_write_commits=allowed and len(writes)>=2 and all(commits)
            and len({r['pwdata'] for _,r in writes})>=2,
        wrong_register_write_does_not_commit=unmoved,
        readback_matches_storage_prdata=bool(writes) and all(readbacks),
        all_ten_ports_sample_live=allowed and len({r['value'] for r in samples})>=3
            and bool(reads) and bool(wrong))


def _verify_spi_bundle(proof, base_dir, reference):
    binding = proof.get('evidence_bundle')
    if (not isinstance(binding, dict) or set(binding)!={'reference','sha256'}
            or binding['reference']!='bundle.json' or not _is_sha256(binding['sha256'])):
        raise ValueError('apb-storage-proof-bundle-shape')
    directory = (Path(base_dir)/reference).parent
    def read(name):
        if (type(name) is not str or Path(name).is_absolute()
                or '..' in Path(name).parts):
            raise ValueError('apb-storage-proof-bundle-path')
        path = directory/name
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError('apb-storage-proof-bundle-symlink')
        try:
            return path.read_bytes()
        except OSError as error:
            raise ValueError('apb-storage-proof-bundle-unavailable') from error
    raw = read(binding['reference'])
    if hashlib.sha256(raw).hexdigest()!=binding['sha256']:
        raise ValueError('apb-storage-proof-bundle-digest')
    try:
        bundle = json.loads(raw)
    except ValueError as error:
        raise ValueError('apb-storage-proof-bundle-json') from error
    required = {'runtime.sv','wrapper.sv','samples.json','invocations.json',
                'tool_versions.json','native_binary.sha256'}
    if (not isinstance(bundle,dict) or set(bundle)!={'schema_version','files'}
            or bundle['schema_version']!='apb_storage_probe_bundle.v1'
            or not isinstance(bundle['files'],dict) or not required<=set(bundle['files'])):
        raise ValueError('apb-storage-proof-bundle-shape')
    for name, expected in bundle['files'].items():
        if not _is_sha256(expected) or hashlib.sha256(read(name)).hexdigest()!=expected:
            raise ValueError('apb-storage-proof-bundle-file-digest')
    if (bundle['files']['runtime.sv']!=proof['runtime_sv_sha256']
            or bundle['files']['wrapper.sv']!=proof['wrapper_sha256']
            or json.loads(read('samples.json'))!=proof['samples']):
        raise ValueError('apb-storage-proof-bundle-binding')
