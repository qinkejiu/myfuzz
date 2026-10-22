"""PULP SPI proof selection, physical sample controls, and bounded native replay."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

from tests.local_harness.test_apb_storage_probe_verification import _probe, _digest

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = 'docs/reports/evidence/verilog-probe-pulp-apb-spi/proof.json'
CONTRACT_ID = 'pulp-apb-spi.spicmd.source.v1'
VALUE_ONE, VALUE_TWO = 0xa5c30001, 0x13572468


def _samples():
    def row(**kw):
        return dict(cycle=0, value=0, paddr=0, psel=0, penable=0, pwrite=0,
                    pwdata=0, prdata=0, pready=1, pslverr=0, reset=0, **kw)
    rows = [row() for _ in range(14)]
    rows[0]['reset'] = 1
    rows[2].update(paddr=12, psel=1, penable=1, pwrite=1, pwdata=0x5a5a5a5a)
    rows[4].update(paddr=8, psel=1, penable=1, pwrite=1, pwdata=VALUE_ONE)
    for r in rows[5:9]: r['value'] = VALUE_ONE
    rows[6].update(paddr=8, psel=1, penable=1, pwrite=0, prdata=VALUE_ONE)
    rows[8].update(paddr=12, psel=1, penable=1, pwrite=1, pwdata=0xdeadbeef)
    rows[9].update(value=VALUE_ONE)
    rows[10].update(value=VALUE_ONE, paddr=8, psel=1, penable=1, pwrite=1, pwdata=VALUE_TWO)
    for r in rows[11:]: r['value'] = VALUE_TWO
    rows[12].update(paddr=8, psel=1, penable=1, prdata=VALUE_TWO)
    for i, r in enumerate(rows): r['cycle'] = i + 1
    return rows


def _case(tmp_path):
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.local_harness.apb_storage_source_contract import select_apb_storage_source_contract
    from myfuzz.local_harness.apb_storage_probe_verification import probe_binding_digest
    profile = load_component_profile(ROOT/'configs/peripherals/pulp_spi/local_component_profile.json')
    contract = select_apb_storage_source_contract(profile, base_dir=ROOT,
        selection=dict(contract_id=CONTRACT_ID, register='SPICMD'))
    probe = _probe(contract)
    probe['selection'].update(endpoint_id='spi.bus', register='SPICMD')
    runtime = 'assign storage_value = ' + contract['storage_expression']['expression'] + ';\n'
    wrapper = 'module local_spi; endmodule\n'
    proof = json.loads((ROOT/'docs/reports/evidence/verilog-probe-pulp-apb-timer/proof.json').read_text())
    proof.update(probe_binding_digest=probe_binding_digest(probe), expression=probe['ports'][0]['expression'],
        ports=probe['ports'], source=contract['source'], parameters=contract['parameters'],
        runtime_sv_sha256=hashlib.sha256(runtime.encode()).hexdigest(),
        wrapper_sha256=hashlib.sha256(wrapper.encode()).hexdigest(), samples=_samples(),
        checks={name: True for name in ('ten_probe_ports_declared','expression_resolves_elaboration',
            'unbound_expression_refused','reset_value_zero','spicmd_write_commits',
            'wrong_register_write_does_not_commit','readback_matches_storage_prdata','all_ten_ports_sample_live')})
    proof['negative_controls'] = [dict(mutation=name,exit_code=1,refused=True)
        for name in ('unknown-instance-name','unknown-register-name','wrong-register-expression')]
    proof['sample_digest'] = _digest(proof['samples'])
    base = tmp_path/'base'
    directory = (base/REFERENCE).parent
    directory.mkdir(parents=True)
    files = {'runtime.sv':runtime, 'wrapper.sv':wrapper, 'samples.json':json.dumps(proof['samples']),
             'invocations.json':'[]', 'tool_versions.json':'{}', 'native_binary.sha256':'0'*64}
    for name, content in files.items(): (directory/name).write_text(content)
    bundle = dict(schema_version='apb_storage_probe_bundle.v1', files={name:hashlib.sha256(content.encode()).hexdigest() for name,content in files.items()})
    (directory/'bundle.json').write_text(json.dumps(bundle))
    proof['evidence_bundle'] = dict(reference='bundle.json', sha256=hashlib.sha256((directory/'bundle.json').read_bytes()).hexdigest())
    for name in contract['source']['files']:
        dest = base/contract['source']['root']/name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT/contract['source']['root']/name, dest)
    _save(directory/'proof.json', proof)
    return base, probe, runtime, proof


def _save(path, proof):
    proof['proof_digest'] = _digest({k:v for k,v in proof.items() if k!='proof_digest'})
    path.write_text(json.dumps(proof))


def _assert_prospective_artifact(artifact):
    from myfuzz.local_harness.renderer import _sha
    observation = artifact['storage_observation']
    assert observation['hierarchy_verified'] is False
    assert observation['native_verified'] is False
    assert 'hierarchy_evidence' not in observation
    assert observation['digest'] == _digest({k:v for k,v in observation.items() if k!='digest'})
    assert artifact['artifact_digest'] == _sha({k:v for k,v in artifact.items() if k!='artifact_digest'})


def test_spi_generation_archives_prospective_artifact_even_with_existing_proof(tmp_path, monkeypatch):
    import importlib.util
    import myfuzz.local_harness as harness
    spec = importlib.util.spec_from_file_location('task2_spi_generation_tool', ROOT/'scripts/verify_apb_storage_probe.py')
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    directory = (ROOT/REFERENCE).parent
    document = json.loads((directory/'artifact.json').read_text())
    # Model the renderer attaching an existing proof, regardless of whether
    # the committed artifact is already prospective after regeneration.
    observation = document['storage_observation']
    observation.update(hierarchy_verified=True, native_verified=True,
        hierarchy_evidence={'proof_digest':'a'*64})
    observation['digest'] = _digest({k:v for k,v in observation.items() if k!='digest'})
    document['artifact_digest'] = _digest({k:v for k,v in document.items() if k!='artifact_digest'})
    artifact = SimpleNamespace(runtime_document=document, runtime_sv=(directory/'runtime.sv').read_text())
    structural = SimpleNamespace(wrapper_sv=(directory/'wrapper.sv').read_text())
    plan = SimpleNamespace(profile=object())
    monkeypatch.setattr(harness, 'plan_local_harness', lambda *a, **kw: plan)
    monkeypatch.setattr(harness, 'render_local_harness', lambda *a, **kw: structural)
    monkeypatch.setattr(harness, 'verify_local_source_lock', lambda *a, **kw: {})
    monkeypatch.setattr(harness, 'render_local_runtime', lambda *a, **kw: artifact)
    output = tmp_path/'generated'
    tool._generate_spi(output)
    archived = json.loads((output/'artifact.json').read_text())
    _assert_prospective_artifact(archived)
    assert document['storage_observation']['hierarchy_verified'] is True
    assert archived['runtime_sv_sha256'] == document['runtime_sv_sha256']
    assert archived['storage_probe_ports'] == document['storage_probe_ports']


def test_spi_evidence_publication_replaces_bundle_before_proof(tmp_path, monkeypatch):
    import importlib.util
    spec = importlib.util.spec_from_file_location('task2_spi_publish_tool', ROOT/'scripts/verify_apb_storage_probe.py')
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    staged = tmp_path/'staged'
    staged.mkdir()
    destination = tmp_path/'published'
    destination.mkdir()
    out = destination/'custom-proof.json'
    out.write_text('old proof')
    contents = {'artifact.json':b'prospective artifact', 'bundle.json':b'new bundle',
        'proof.sha256':b'new digest', 'proof.json':b'new proof', 'inputs/source.sv':b'source'}
    for name, raw in contents.items():
        path = staged/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    replacements = []
    original_replace = Path.replace
    def record_replace(source, target):
        if Path(target) != out:
            assert out.read_text() == 'old proof'
        else:
            assert (destination/'bundle.json').read_bytes() == contents['bundle.json']
        replacements.append(Path(target).relative_to(destination).as_posix())
        return original_replace(source, target)
    monkeypatch.setattr(Path, 'replace', record_replace)
    tool._publish_spi_evidence(staged, out)
    assert replacements[-2:] == ['bundle.json','custom-proof.json']
    for name, raw in contents.items():
        assert (out if name=='proof.json' else destination/name).read_bytes() == raw


def test_spi_proof_attaches_at_closed_contract_path(tmp_path):
    from myfuzz.local_harness.apb_storage_probe_verification import attach_native_proof, verified_storage_observation
    base, probe, runtime, proof = _case(tmp_path)
    attached = attach_native_proof(probe, runtime_sv=runtime, wrapper_sha256=proof['wrapper_sha256'], base_dir=base)
    assert attached['native_verified'] is True
    assert attached['hierarchy_evidence']['reference'] == REFERENCE
    assert verified_storage_observation(attached, runtime_sv=runtime, wrapper_sha256=proof['wrapper_sha256'], base_dir=base)


@pytest.mark.parametrize('mutation', ['missing','runtime','wrapper','expression','source','address',
    'missing_wrong_register','missing_wrong_register_control','wrong_register_moves','readback','reset','constant','bundle','cross_pair'])
def test_spi_proof_refuses_stale_or_unmeasured_claims(tmp_path, mutation):
    from myfuzz.local_harness.apb_storage_probe_verification import validate_native_proof, attach_native_proof
    base, probe, runtime, proof = _case(tmp_path)
    path = base/REFERENCE
    if mutation == 'missing':
        path.unlink()
        assert not attach_native_proof(probe, runtime_sv=runtime, wrapper_sha256=proof['wrapper_sha256'], base_dir=base)['native_verified']
        return
    if mutation == 'runtime': runtime += '// stale'
    elif mutation == 'wrapper': proof['wrapper_sha256'] = '0'*64
    elif mutation == 'expression': proof['expression'] = 'u_component.u_dut.u_axiregs.spi_addr'
    elif mutation == 'source': (base/proof['source']['root']/next(iter(proof['source']['files']))).write_text('changed')
    elif mutation == 'address':
        for r in proof['samples']:
            if r['paddr']==8: r['paddr']=4
    elif mutation == 'missing_wrong_register': proof['samples'] = [r for r in proof['samples'] if r['paddr']!=12]
    elif mutation == 'missing_wrong_register_control': proof['negative_controls'] = proof['negative_controls'][:2]
    elif mutation == 'wrong_register_moves': proof['samples'][9]['value'] = 0xdeadbeef
    elif mutation == 'readback': proof['samples'][6]['prdata'] = 5
    elif mutation == 'reset': proof['samples'][0]['value'] = 1
    elif mutation == 'constant':
        for r in proof['samples']: r['value'] = 0
    elif mutation == 'bundle': (path.parent/'runtime.sv').write_text('changed')
    else:
        proof = json.loads((ROOT/'docs/reports/evidence/verilog-probe-pulp-apb-timer/proof.json').read_text())
    proof['sample_digest'] = _digest(proof['samples'])
    _save(path, proof)
    semantic_mutations = {'address','missing_wrong_register','wrong_register_moves','readback','reset','constant'}
    if mutation in semantic_mutations:
        (path.parent/'samples.json').write_text(json.dumps(proof['samples']))
        bundle = json.loads((path.parent/'bundle.json').read_text())
        bundle['files']['samples.json'] = hashlib.sha256((path.parent/'samples.json').read_bytes()).hexdigest()
        (path.parent/'bundle.json').write_text(json.dumps(bundle))
        proof['evidence_bundle']['sha256'] = hashlib.sha256((path.parent/'bundle.json').read_bytes()).hexdigest()
        _save(path, proof)
        # Semantic negatives must present a coherent sidecar bundle, so a
        # stale samples.json cannot supply an unrelated refusal.
        assert json.loads((path.parent/'samples.json').read_text()) == proof['samples']
        bundle = json.loads((path.parent/'bundle.json').read_text())
        assert all(hashlib.sha256((path.parent/name).read_bytes()).hexdigest()==digest
            for name,digest in bundle['files'].items())
        assert hashlib.sha256((path.parent/'bundle.json').read_bytes()).hexdigest()==proof['evidence_bundle']['sha256']
    expected = {'reset':'apb-storage-proof-reset-sample',
        'constant':'apb-storage-proof-storage-sample'}
    failed_checks = {'address':'spicmd_write_commits',
        'missing_wrong_register':'wrong_register_write_does_not_commit',
        'wrong_register_moves':'wrong_register_write_does_not_commit',
        'readback':'readback_matches_storage_prdata'}
    if mutation in failed_checks:
        from myfuzz.local_harness.apb_storage_probe_verification import spi_sample_checks
        assert spi_sample_checks(proof['samples'])[failed_checks[mutation]] is False
    refusal = expected.get(mutation, 'apb-storage-proof-spi-samples') if mutation in semantic_mutations else None
    with pytest.raises(ValueError, match=refusal):
        validate_native_proof(proof, probe=probe, runtime_sv=runtime,
            wrapper_sha256=hashlib.sha256(b'module local_spi; endmodule\n').hexdigest(), base_dir=base)


def test_spi_physical_sample_checks_require_exact_commits():
    from myfuzz.local_harness.apb_storage_probe_verification import spi_sample_checks
    assert all(spi_sample_checks(_samples()).values())


def test_committed_spi_evidence_binds_generated_bytes():
    from myfuzz.local_harness.apb_storage_probe_verification import attach_native_proof, verified_storage_observation
    directory = (ROOT/REFERENCE).parent
    proof = json.loads((directory/'proof.json').read_text())
    artifact = json.loads((directory/'artifact.json').read_text())
    _assert_prospective_artifact(artifact)
    runtime = (directory/'runtime.sv').read_text()
    wrapper_sha256 = hashlib.sha256((directory/'wrapper.sv').read_bytes()).hexdigest()
    attached = attach_native_proof(artifact['storage_observation'],
        runtime_sv=runtime, wrapper_sha256=wrapper_sha256, base_dir=ROOT)
    evidence = verified_storage_observation(attached, runtime_sv=runtime,
        wrapper_sha256=wrapper_sha256, base_dir=ROOT)
    assert evidence['proof_digest'] == proof['proof_digest']
    assert evidence['reference'] == REFERENCE
    request = json.loads((directory/'request.json').read_text())
    assert request['schema_version']=='local_harness.v2'
    assert request['profile_path']=='configs/peripherals/pulp_spi/local_component_profile.json'
    assert request['tuning']['endpoint_policies'][0]['variant_id']=='full-word'
    samples = proof['samples']
    assert all(r['value']==0 for r in samples if r['reset'])
    writes = [(i,r) for i,r in enumerate(samples) if r['psel'] and r['penable'] and r['pwrite']]
    assert {r['paddr'] for _,r in writes}=={8,12}
    for i,r in writes:
        assert samples[i+1]['value']==(r['pwdata'] if r['paddr']==8 else r['value'])
    reads = [r for r in samples if r['psel'] and r['penable'] and not r['pwrite']]
    assert {r['prdata'] for r in reads}=={VALUE_ONE,VALUE_TWO}
    assert all(r['prdata']==r['value'] for r in reads)
    assert proof['samples'][-1]['value'] == VALUE_TWO
    assert not any(r['psel'] and r['pwrite'] and r['paddr'] not in (8,12) for r in proof['samples'])


@pytest.mark.skipif(os.environ.get('MYFUZZ_NATIVE_VERILATOR')!='1', reason='bounded native build is opt in')
def test_spi_native_proof_replay(tmp_path):
    from myfuzz.local_harness.apb_storage_probe_verification import attach_native_proof, verified_storage_observation
    cache = ROOT/'.superpowers/cache-verilog-probe-spi-pytest'
    base = tmp_path/'base'
    proof_out = base/REFERENCE
    result = subprocess.run([sys.executable, str(ROOT/'scripts/verify_apb_storage_probe.py'),
        '--contract-id',CONTRACT_ID,'--cache-dir',str(cache),'--lock-wait','1',
        '--proof-out',str(proof_out)], cwd=ROOT, capture_output=True,text=True,timeout=900)
    if 'heavy-worker-lock-busy' in result.stderr: pytest.skip('heavy-worker lock is held')
    assert result.returncode==0, result.stderr
    proof = json.loads(proof_out.read_text())
    artifact = json.loads((proof_out.parent/'artifact.json').read_text())
    _assert_prospective_artifact(artifact)
    for name in proof['source']['files']:
        destination = base/proof['source']['root']/name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT/proof['source']['root']/name, destination)
    runtime = (proof_out.parent/'runtime.sv').read_text()
    wrapper_sha256 = hashlib.sha256((proof_out.parent/'wrapper.sv').read_bytes()).hexdigest()
    attached = attach_native_proof(artifact['storage_observation'], runtime_sv=runtime,
        wrapper_sha256=wrapper_sha256, base_dir=base)
    evidence = verified_storage_observation(attached, runtime_sv=runtime,
        wrapper_sha256=wrapper_sha256, base_dir=base)
    assert evidence['proof_digest'] == proof['proof_digest']
    committed = json.loads((ROOT/REFERENCE).read_text())
    for key in ('samples','checks','probe_binding_digest','runtime_sv_sha256','wrapper_sha256','source'):
        assert proof[key]==committed[key]


def test_proof_cache_cleanup_refuses_symlinked_parent(tmp_path, monkeypatch):
    import importlib.util
    spec = importlib.util.spec_from_file_location('task2_probe_tool', ROOT/'scripts/verify_apb_storage_probe.py')
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    monkeypatch.setattr(tool, 'ROOT', tmp_path)
    (tmp_path/'.superpowers').mkdir()
    outside = tmp_path/'outside'
    outside.mkdir()
    (tmp_path/'.superpowers/redirect').symlink_to(outside, target_is_directory=True)
    target = outside/'cache-verilog-probe-spi-test'
    target.mkdir()
    (target/'preserved').write_text('keep')
    with pytest.raises(tool.VerificationError):
        tool._clean_cache(tmp_path/'.superpowers/redirect/cache-verilog-probe-spi-test')
    assert (target/'preserved').read_text()=='keep'


def test_spi_evidence_preserves_generation_tool_invocations():
    directory = (ROOT/REFERENCE).parent
    records = json.loads((directory/'generation_invocations.json').read_text())
    assert records
    assert any(Path(arg).name=='verilator' for r in records for arg in r['argv'])
    assert all(type(r['exit_code']) is int and r['exit_code']==0 for r in records)
