"""Gate preparation checks: source archives and exact negative commands, no RTL."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tarfile
import pytest

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT/'.superpowers/sdd/compiled-f2-rfuzz-entry-20261023/gates/run_gate.py'


def supervisor():
    spec=importlib.util.spec_from_file_location('f2_gate_supervisor_unit',PATH)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('mode, control', (
    ('f2-refusal-registration','wrong-registration'), ('f2-refusal-shape','incompatible-shape')))
def test_negative_commands_use_frozen_exact_declarations(tmp_path, mode, control):
    mod=supervisor()
    declarations=json.loads((mod.GATES/'inputs/negative-control-declarations.json').read_bytes())
    expected=declarations['expected_refusals'][control]
    argv, env, timeout, code=mod.command(SimpleNamespace(mode=mode,expected_refusal_code=None),tmp_path/'result')
    assert code == expected['exit_code'] == 1
    assert argv[argv.index('--compose')+1] == str(ROOT/expected['fixture'])
    assert argv[argv.index('--ip')+1] == expected['profile']
    assert argv[argv.index('--executor')+1] == 'compiled-f2-rfuzz'
    with pytest.raises(ValueError,match='frozen declaration'):
        mod.command(SimpleNamespace(mode=mode,expected_refusal_code='unrelated'),tmp_path/'bad')


def test_archive_materializes_symlinks_and_pins_same_byte_retarget(tmp_path, monkeypatch):
    mod=supervisor();monkeypatch.setattr(mod,'ROOT',tmp_path)
    (tmp_path/'first.sv').write_bytes(b'actual source bytes\n')
    (tmp_path/'second.sv').write_bytes(b'actual source bytes\n')
    link=tmp_path/'linked.sv';link.symlink_to('first.sv')
    byte_map={'linked.sv':mod.digest(link)}
    before=mod.source_origins(byte_map)
    mod.archive_regular_inputs(tmp_path/'inputs.tar.gz',byte_map)
    with tarfile.open(tmp_path/'inputs.tar.gz') as archive:
        members=archive.getmembers()
        assert len(members)==1 and members[0].isfile()
        assert archive.extractfile(members[0]).read()==link.read_bytes()
    link.unlink();link.symlink_to('second.sv')
    assert mod.digest(link)==byte_map['linked.sv']
    assert mod.source_origins(byte_map)!=before


def test_renamed_fixture_prepares_real_f2_sources_with_registered_endpoint_abi(tmp_path, monkeypatch):
    """Logical instance renames preserve actual registered protocol endpoint IDs."""
    from hashlib import sha256
    from myfuzz.integration.compiled_execution_files import prepare_compiled_execution_files
    from myfuzz.integration.compiled_f2 import CompiledF2Runtime
    calls = []
    def native_forbidden(*args, **kwargs):
        calls.append('constructor')
        raise AssertionError('rename preparation must not construct native runtime')
    monkeypatch.setattr(CompiledF2Runtime, '__init__', native_forbidden)
    fixture = PATH.parent / 'inputs/renamed'
    config = ROOT / 'configs/scenarios/compiled-f4-obi-apb-timer'
    artifacts, inputs, support = prepare_compiled_execution_files(
        base_dir=ROOT, compose_path=fixture/'compose.json',
        capability_paths=(config/'test_capability.json',),
        supplement_path=config/'execution_supplement.json',
        generated_dir=tmp_path/'generated', flow='F2')
    assert calls == []
    assert support['execution_supported'] == 1 and support['runtime_admitted'] is False
    assert set(artifacts) == {'core_probe', 'target_probe'}
    assert inputs['request'].cpu.instance_id == 'core_probe'
    assert inputs['request'].cpu_data_endpoint_id == 'processor.data'
    assert inputs['request'].cpu_instruction_endpoint_id == 'processor.instruction'
    path = next(p for p in inputs['compiled']['paths'] if p['flow_id'] == 'F2' and p['status'] == 'executable')
    assert path['execution_contract']['source_component'] == 'core_probe'
    assert path['execution_contract']['source_endpoint'] == 'processor.data'
    assert path['execution_contract']['target_component'] == 'target_probe'
    assert path['execution_contract']['target_endpoint'] == 'timer.bus'
    image = next(s for s in path['sources'] if s['kind'] == 'instruction_image')
    assert image['component'] == 'core_probe' and image['endpoint_id'] == 'processor.instruction'
    assert all(r.component_instance == 'core_probe' for r in inputs['request'].wiring.resources)
    for component, profile_path in (
            ('core_probe','configs/cpus/ibex_obi_local/component_profile.json'),
            ('target_probe','configs/peripherals/pulp_timer/component_profile.json')):
        profile = json.loads((ROOT/profile_path).read_bytes())
        request_path = fixture/'requests'/('processor.json' if component == 'core_probe' else 'peripheral.json')
        assert json.loads(request_path.read_bytes())['profile_path'] == profile_path
        document = artifacts[component].runtime_document
        assert document['plan']['instance_id'] == component
        assert document['plan']['component_id'] == profile['component_id']
        assert document['structural_build']['source_revision'] == profile['source']['revision']
        assert document['structural_build']['source_files'] == [
            profile['source']['root']+'/'+name for name in profile['source']['files']]
        templates = document['selected_template']['executor']['protocol_templates']
        expected = ({('processor.data','cpu.obi','1','read-write'),
                     ('processor.instruction','cpu.obi','1','read-only')}
                    if component == 'core_probe' else {('timer.bus','target.apb3','1','full-word')})
        assert {(row['binding']['endpoint_id'],row['contract']['template_id'],
                 row['contract']['template_version'],row['contract']['variant_id']) for row in templates} == expected
    assert {e['endpoint_id'] for e in json.loads((ROOT/'configs/cpus/ibex_obi_local/component_profile.json').read_bytes())['endpoints']} == {
        'processor.data','processor.instruction','processor.interrupts'}
    proof = dict(constructor_called=False,execution_supported=support['execution_supported'],
        runtime_admitted=support['runtime_admitted'],path_id=path['path_id'],
        instance_ids=sorted(artifacts),cpu_endpoint_abi=['processor.data','processor.instruction','processor.interrupts'],
        artifact_digests={name:a.runtime_document['artifact_digest'] for name,a in artifacts.items()},
        compose_sha256=sha256((fixture/'compose.json').read_bytes()).hexdigest())
    print('RENAMED_PREPARED_SOURCE_EVIDENCE '+json.dumps(proof,sort_keys=True))
