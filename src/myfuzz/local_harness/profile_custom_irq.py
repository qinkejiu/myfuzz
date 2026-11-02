"""Profile-declared custom IRQ ABI and physical observation binding.

The profile describes ABI semantics; pinning RTL bytes does not prove that
semantic description. EOI is a CPU output, not proof of a particular source
or retirement of any instruction.
"""
import hashlib
from pathlib import Path
import re


def verify_custom_irq_source(profile, *, base_dir):
    """Validate profile ABI and source bytes; never claim runtime execution."""
    from .source_lock import verify_local_source_lock
    doc = profile.evidence.get('custom_irq_abi')
    fields = {'schema_version', 'abi', 'input_port', 'eoi_port', 'trap_port',
              'width', 'handler_address', 'retirq_encoding', 'source_files'}
    if (profile.cpu is None or type(doc) is not dict
            or set(doc) != fields or doc['schema_version'] != 'custom_irq_abi.v1'
            or doc['abi'] != 'picorv32_custom0' or doc['width'] != 32
            or any(type(doc[k]) is not int or not 0 <= doc[k] <= 0xffffffff
                   for k in ('handler_address', 'retirq_encoding'))
            or any(type(doc[k]) is not str or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', doc[k])
                   for k in ('input_port', 'eoi_port', 'trap_port'))
            or len({doc[k] for k in ('input_port', 'eoi_port', 'trap_port')}) != 3):
        raise ValueError('invalid-custom-IRQ-ABI')
    sources = doc['source_files']
    if (type(sources) is not dict or not sources or any(
            path not in profile.source.files or type(digest) is not str
            or not re.fullmatch(r'[0-9a-f]{64}', digest) for path, digest in sources.items())):
        raise ValueError('invalid-custom-IRQ-source')
    verified = verify_local_source_lock(profile, base_dir=base_dir)
    for path, digest in sources.items():
        source = Path(base_dir) / profile.source.source_root / path
        if source.is_symlink() or hashlib.sha256(source.read_bytes()).hexdigest() != digest:
            raise ValueError('custom-IRQ-source-mismatch')
    return verified


def verify_custom_irq_artifact(artifact, *, base_dir):
    profile = artifact.plan.profile
    if artifact.runtime_document.get('kind') != 'wishbone_cpu':
        raise ValueError('custom-IRQ-Wishbone-artifact-required')
    verified = verify_custom_irq_source(profile, base_dir=base_dir)
    doc = profile.evidence['custom_irq_abi']
    runtime = artifact.runtime_document
    if (runtime.get('source_verification') != verified or
            hashlib.sha256(artifact.runtime_sv.encode()).hexdigest() != runtime.get('runtime_sv_sha256')):
        raise ValueError('custom-IRQ-artifact-mismatch')
    exports = runtime['physical_exports']
    bindings = {}
    for role, direction, width in (('input_port', 'input', 32), ('eoi_port', 'output', 32),
                                   ('trap_port', 'output', 1)):
        matches = [r for r in exports if r.get('physical_port') == doc[role]
                   and r.get('direction') == direction and r.get('width') == width
                   and r.get('bit_lo') == 0]
        if role == 'input_port':
            matches = [r for r in matches if r.get('endpoint_id') == profile.cpu.irq_entry_endpoint
                       and r.get('role') == profile.cpu.irq_entry_role]
        else:
            matches = [r for r in matches if r.get('disposition') == 'observe']
        if len(matches) != 1:
            raise ValueError('custom-IRQ-physical-port-mismatch:' + doc[role])
        bindings[role] = matches[0]['runtime_name']
    return {**doc, 'bindings':bindings, 'source_attribution':'unknown',
            'retirement':'unknown', 'machine_external_take':'unsupported'}


def observe_custom_irq(contract, sample, expected_irq):
    bindings = contract['bindings']
    result = {'schema_version':'custom_irq_observation.v1',
              'local_tick':sample['local_tick'], 'source_attribution':'unknown',
              'retirement':'unknown', 'machine_external_take':'unsupported'}
    for phase in ('pre', 'post'):
        physical = sample[phase]['physical']
        for role, prefix, width in (('input_port','irq',32), ('eoi_port','eoi',32), ('trap_port','trap',1)):
            value = physical.get(bindings[role])
            if type(value) is not int or not 0 <= value < 1 << width:
                raise ValueError('invalid-custom-IRQ-physical-sample')
            result[prefix+'_'+phase] = value
        if result['irq_'+phase] != expected_irq:
            raise ValueError('custom-IRQ-input-sample-mismatch')
    return result
