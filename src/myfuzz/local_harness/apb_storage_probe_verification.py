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


def proof_path(base_dir):
    return Path(base_dir).absolute() / PROOF_RELATIVE


def probe_binding_digest(probe):
    """Digest of the exact hierarchy expression, ports and source identity."""
    if type(probe) is not dict:
        raise ValueError('apb-storage-probe-binding-shape')
    contract = probe.get('source_contract')
    if (not isinstance(contract, dict)
            or not isinstance(contract.get('source'), dict)
            or not isinstance(contract.get('parameters'), dict)
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
    if type(proof) is not dict or set(proof) != _PROOF_KEYS:
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
    if (proof.get('ports') != probe['ports']
            or proof.get('expression')
            != probe['source_contract']['storage_expression']['expression']):
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
    checks = proof.get('checks')
    if (not isinstance(checks, dict) or set(checks) != set(_CHECK_NAMES)
            or any(checks[name] is not True for name in _CHECK_NAMES)):
        raise ValueError('apb-storage-proof-checks')
    _verify_samples(proof.get('samples'), proof.get('sample_digest'))
    return dict(schema_version=EVIDENCE_SCHEMA, reference=PROOF_RELATIVE,
                proof_digest=proof['proof_digest'], binding_digest=binding,
                runtime_sv_sha256=proof['runtime_sv_sha256'],
                wrapper_sha256=proof['wrapper_sha256'],
                verilator=copy.deepcopy(verilator),
                sample_digest=proof['sample_digest'])


def _load_proof(base_dir):
    path = proof_path(base_dir)
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
    if not proof_path(base_dir).is_file():
        return document
    try:
        proof = _load_proof(base_dir)
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
            or reference.get('reference') != PROOF_RELATIVE):
        raise ValueError('apb-storage-observation-evidence-shape')
    proof = _load_proof(base_dir)
    evidence = validate_native_proof(
        proof, probe=observation, runtime_sv=runtime_sv,
        wrapper_sha256=wrapper_sha256, base_dir=base_dir)
    for key in ('proof_digest', 'binding_digest', 'runtime_sv_sha256',
                'wrapper_sha256', 'verilator', 'sample_digest'):
        if reference.get(key) != evidence[key]:
            raise ValueError('apb-storage-observation-evidence-mismatch')
    return evidence
