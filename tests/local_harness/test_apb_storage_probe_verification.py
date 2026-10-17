"""Pure proof plumbing for the registered APB storage hierarchy probes.

The native Verilator build that *creates* the committed proof is opt-in via
``MYFUZZ_NATIVE_VERILATOR=1``.  The default tests only check that the proof is
digest-bound, that a verified observation cannot exist without it, and that a
stale/tampered proof leaves the prospective flags false.
"""
import json
from hashlib import sha256
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
COMMITTED_PROOF = ROOT / ('docs/reports/evidence/'
                          'verilog-probe-pulp-apb-timer/proof.json')


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))
def _digest(value):
    return sha256(_json(value).encode()).hexdigest()
def _text_sha(value):
    return sha256(value.encode()).hexdigest()


def _source_contract():
    from myfuzz.local_harness.apb_storage_source_contract import (
        _registered_document)
    return _registered_document()


def _probe(contract, expression=None):
    expression = expression or contract['storage_expression']['expression']
    ports = [
        dict(name='storage_value', direction='output', width=32,
             role='value', expression=expression),
        dict(name='storage_reset', direction='output', width=1,
             role='reset', expression='reset'),
        dict(name='storage_paddr', direction='output', width=12,
             role='paddr', expression='link_lh_p_2_11_0'),
        dict(name='storage_psel', direction='output', width=1,
             role='psel', expression='link_lh_p_6_0_0'),
        dict(name='storage_penable', direction='output', width=1,
             role='penable', expression='link_lh_p_3_0_0'),
        dict(name='storage_pwrite', direction='output', width=1,
             role='pwrite', expression='link_lh_p_9_0_0'),
        dict(name='storage_pwdata', direction='output', width=32,
             role='pwdata', expression='link_lh_p_8_31_0'),
        dict(name='storage_prdata', direction='output', width=32,
             role='prdata', expression='link_lh_p_4_31_0'),
        dict(name='storage_pready', direction='output', width=1,
             role='pready', expression='link_lh_p_5_0_0'),
        dict(name='storage_pslverr', direction='output', width=1,
             role='pslverr', expression='link_lh_p_7_0_0'),
    ]
    probe = dict(
        schema_version='apb_storage_probe.v1',
        scope='generated_expression_source_mapped',
        selection=dict(contract_id=contract['contract_id'],
                       endpoint_id='timer.bus', register='TIMER0_CTRL'),
        source_contract=contract, sample_group='storage_probes', ports=ports,
        hierarchy_verified=False, native_verified=False,
        reset_authority=False, version_authority=False, source_authority=False)
    probe['digest'] = _digest(probe)
    return probe


def _case(tmp_path):
    from myfuzz.local_harness.apb_storage_probe_verification import (
        PROOF_RELATIVE, probe_binding_digest)
    contract = _source_contract()
    probe = _probe(contract)
    runtime = ('module local_runtime_probe_test (\n'
               '  output logic [31:0] storage_value\n);\n'
               f"  assign storage_value = {probe['ports'][0]['expression']};\n"
               'endmodule\n')
    wrapper = 'module local_peripheral; endmodule\n'
    proof = json.loads(COMMITTED_PROOF.read_text())
    proof.pop('proof_digest')
    proof.update(
        probe_binding_digest=probe_binding_digest(probe),
        expression=probe['ports'][0]['expression'], ports=probe['ports'],
        runtime_sv_sha256=_text_sha(runtime),
        wrapper_sha256=_text_sha(wrapper),
        source=contract['source'], parameters=contract['parameters'])
    proof['proof_digest'] = _digest(proof)
    base = tmp_path / 'base'
    (base / PROOF_RELATIVE).parent.mkdir(parents=True)
    (base / PROOF_RELATIVE).write_text(json.dumps(proof), encoding='utf-8')
    for name in contract['source']['files']:
        source = ROOT / contract['source']['root'] / name
        destination = base / contract['source']['root'] / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    return base, probe, runtime, wrapper, proof


def test_committed_proof_is_digest_bound_and_names_the_expression():
    from myfuzz.local_harness.apb_storage_probe_verification import (
        probe_binding_digest)
    proof = json.loads(COMMITTED_PROOF.read_text())
    body = {key: value for key, value in proof.items()
            if key != 'proof_digest'}
    assert proof['proof_digest'] == _digest(body)
    assert proof['schema_version'] == 'apb_storage_probe_hierarchy_proof.v1'
    assert proof['status'] == 'verified'
    contract = _source_contract()
    assert proof['expression'] == contract['storage_expression']['expression']
    assert proof['source'] == contract['source']
    assert proof['parameters'] == contract['parameters']
    assert proof['probe_binding_digest'] == probe_binding_digest(_probe(contract))
    assert proof['samples']
    assert all(proof['checks'].values())
    assert all(row['refused'] for row in proof['negative_controls'])


def test_attach_requires_a_bound_proof_and_verifies(tmp_path):
    from myfuzz.local_harness.apb_storage_probe_verification import (
        attach_native_proof, verified_storage_observation)
    base, probe, runtime, wrapper, _ = _case(tmp_path)
    attached = attach_native_proof(
        probe, runtime_sv=runtime, wrapper_sha256=_text_sha(wrapper),
        base_dir=base)
    assert attached['hierarchy_verified'] is True
    assert attached['native_verified'] is True
    assert attached['hierarchy_evidence']['reference'].endswith('proof.json')
    evidence = verified_storage_observation(
        attached, runtime_sv=runtime, wrapper_sha256=_text_sha(wrapper),
        base_dir=base)
    assert evidence['binding_digest'] == attached['hierarchy_evidence']['binding_digest']
    # A prospective observation carries no evidence and validates as None.
    assert verified_storage_observation(
        probe, runtime_sv=runtime, wrapper_sha256=_text_sha(wrapper),
        base_dir=base) is None


@pytest.mark.parametrize('mismatch', ('runtime', 'wrapper', 'expression', 'binding'))
def test_stale_proof_leaves_prospective_flags_false(tmp_path, mismatch):
    from myfuzz.local_harness.apb_storage_probe_verification import (
        attach_native_proof)
    base, probe, runtime, wrapper, _ = _case(tmp_path)
    if mismatch == 'runtime':
        runtime = runtime + '// changed\n'
    elif mismatch == 'wrapper':
        wrapper = wrapper + '// changed\n'
    elif mismatch == 'expression':
        probe = _probe(_source_contract(), expression="u_dut.other.regs_q[1]")
    else:
        proof = json.loads((base / 'docs/reports/evidence/'
                            'verilog-probe-pulp-apb-timer/proof.json').read_text())
        proof['probe_binding_digest'] = '0' * 64
        proof['proof_digest'] = _digest(
            {key: value for key, value in proof.items()
             if key != 'proof_digest'})
        (base / 'docs/reports/evidence/'
         'verilog-probe-pulp-apb-timer/proof.json').write_text(
             json.dumps(proof), encoding='utf-8')
    attached = attach_native_proof(
        probe, runtime_sv=runtime, wrapper_sha256=_text_sha(wrapper),
        base_dir=base)
    assert attached['hierarchy_verified'] is False
    assert attached['native_verified'] is False
    assert 'hierarchy_evidence' not in attached


def test_missing_proof_leaves_prospective_flags_false(tmp_path):
    from myfuzz.local_harness.apb_storage_probe_verification import (
        attach_native_proof)
    base, probe, runtime, wrapper, _ = _case(tmp_path)
    (base / 'docs/reports/evidence/'
     'verilog-probe-pulp-apb-timer/proof.json').unlink()
    attached = attach_native_proof(
        probe, runtime_sv=runtime, wrapper_sha256=_text_sha(wrapper),
        base_dir=base)
    assert attached['hierarchy_verified'] is False
    assert attached['native_verified'] is False
    assert 'hierarchy_evidence' not in attached


@pytest.mark.parametrize('mutation', (
    'flag_mismatch', 'evidence_missing', 'evidence_digest',
    'evidence_reference', 'evidence_retarget'))
def test_claimed_verification_without_valid_evidence_refused(tmp_path, mutation):
    from myfuzz.local_harness.apb_storage_probe_verification import (
        attach_native_proof, verified_storage_observation)
    base, probe, runtime, wrapper, _ = _case(tmp_path)
    attached = attach_native_proof(
        probe, runtime_sv=runtime, wrapper_sha256=_text_sha(wrapper),
        base_dir=base)
    assert attached['hierarchy_verified'] is True
    if mutation == 'flag_mismatch':
        attached['native_verified'] = False
    elif mutation == 'evidence_missing':
        attached.pop('hierarchy_evidence')
    elif mutation == 'evidence_digest':
        attached['hierarchy_evidence']['proof_digest'] = '0' * 64
    elif mutation == 'evidence_reference':
        attached['hierarchy_evidence']['reference'] = 'elsewhere.json'
    else:
        attached['hierarchy_evidence']['runtime_sv_sha256'] = '0' * 64
    with pytest.raises(ValueError):
        verified_storage_observation(
            attached, runtime_sv=runtime, wrapper_sha256=_text_sha(wrapper),
            base_dir=base)


@pytest.mark.skipif(os.environ.get('MYFUZZ_NATIVE_VERILATOR') != '1',
                    reason='set MYFUZZ_NATIVE_VERILATOR=1 for the bounded '
                           'Verilator build + live-sample proof')
def test_native_verilator_proof_reproduces_committed_evidence(tmp_path):
    cache = ROOT / '.superpowers/cache-verilog-probe-pytest'
    try:
        result = subprocess.run(
            [sys.executable, str(ROOT / 'scripts/verify_apb_storage_probe.py'),
             '--cache-dir', str(cache), '--lock-wait', '1',
             '--proof-out', str(tmp_path / 'proof.json')],
            cwd=ROOT, capture_output=True, text=True, timeout=900)
    finally:
        shutil.rmtree(cache, ignore_errors=True)
    if 'heavy-worker-lock-busy' in result.stderr:
        pytest.skip('heavy-worker lock is held by another bounded build')
    assert result.returncode == 0, result.stderr
    produced = json.loads((tmp_path / 'proof.json').read_text())
    committed = json.loads(COMMITTED_PROOF.read_text())
    assert produced == committed
