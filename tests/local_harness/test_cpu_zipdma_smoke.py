import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('cpu_zipdma_smoke', ROOT / 'scripts/run_cpu_zipdma_smoke.py')
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


def test_firmware_uses_real_cpu_stores_and_loads():
    code = smoke.firmware(0x10000)
    words = [int.from_bytes(code[i:i + 4], 'little') for i in range(0, len(code), 4)]
    # Four control writes, four RAM readbacks, four result stores and marker.
    assert sum(w & 0x7f == 0x23 for w in words) == 10
    assert sum(w & 0x7f == 0x03 for w in words) == 4
    assert words[-1] == 0x0000006f


def test_master_evidence_requires_real_aligned_reads_writes_and_select():
    events = [dict(address=0x11000 + 4*i, write=False, sel=15, data=i) for i in range(4)]
    events += [dict(address=0x12000 + 4*i, write=True, sel=15, data=i) for i in range(4)]
    assert smoke.check_master_events(events)
    events[0]['sel'] = 3
    assert not smoke.check_master_events(events)


def test_retirement_evidence_requires_matching_pc_instruction_and_no_trap():
    expected = smoke.expected_retirements(0x10000)
    rows = [{'kind': 'cpu_retire', 'component': 'cpu', 'pc_rdata': x['pc'],
             'insn': x['insn'], 'trap': 0, 'event_id': i + 1}
            for i, x in enumerate(expected)]
    assert smoke.retirement_evidence(rows, expected)['status'] == 'observed'
    assert smoke.retirement_evidence([], expected)['status'] == 'unknown'
    rows[0]['insn'] ^= 4
    assert smoke.retirement_evidence(rows, expected)['status'] == 'mismatch'
    del rows[-1]['trap']
    assert smoke.retirement_evidence(rows[1:], expected[1:])['status'] == 'unknown'


def test_irq_evidence_distinguishes_delivery_and_cpu_input_from_acceptance():
    events = [
        {'kind': 'dataflow_delivery', 'source': ('dma', 'irq'),
         'target': ('cpu', 'irq'), 'value': 1, 'event_id': 2},
        {'component': 'cpu', 'local_tick': 8, 'inputs': {'irq': 1}, 'event_id': 3},
    ]
    evidence = smoke.irq_evidence(events)
    assert evidence['delivery_status'] == evidence['cpu_input_status'] == 'observed_high'
    assert evidence['cpu_interrupt_acceptance'] == 'unknown'
    assert smoke.irq_evidence([])['cpu_input_status'] == 'unknown'


def test_cli_uses_repository_relative_profile_without_build(monkeypatch, tmp_path, capsys):
    import sys
    from myfuzz.scenario import ibex_pulp_dual_source

    received = []
    artifact = object()
    def fake_artifact(profile, component):
        received.append((profile, component))
        return artifact
    def fake_execute(actual, binary, cache, max_steps):
        assert actual is artifact
        assert binary == tmp_path / 'dma'
        assert cache == tmp_path / 'cache'
        assert max_steps == 2000
        return {'status': 'verified'}
    monkeypatch.setattr(ibex_pulp_dual_source, '_artifact', fake_artifact)
    monkeypatch.setattr(smoke, 'execute', fake_execute)
    monkeypatch.setattr(sys, 'argv', ['smoke', '--binary', str(tmp_path / 'dma'),
                                     '--cache', str(tmp_path / 'cache'),
                                     '--output', str(tmp_path / 'result.json')])
    smoke.main()
    assert received == [('configs/cpus/cv32e20/component_profile.json', 'cpu')]
    assert 'verified' in capsys.readouterr().out
    assert (tmp_path / 'result.json').is_file()


def test_dma_build_record_matches_actual_binary_and_sources(tmp_path):
    import hashlib
    binary = tmp_path / 'dma'
    binary.write_bytes(b'test binary')
    sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    profile = {'source_revision': 'rev', 'sources': {'a.v': 'abc'}}
    record = {'status': 'verified', 'binary_sha256': sha, 'source_revision': 'rev',
              'source_sha256': {'a.v': 'abc'}, 'driver_sha256': 'driver'}
    receipt = smoke.dma_build_evidence(binary, profile, 'driver', record)
    assert receipt['comparison'] == 'matching'
    assert receipt['binary_sha256'] == sha
    assert smoke.dma_build_evidence(binary, profile, 'driver', None)['comparison'] == 'unknown'
    record['binary_sha256'] = 'wrong'
    assert smoke.dma_build_evidence(binary, profile, 'driver', record)['comparison'] == 'mismatch'


def test_process_identity_records_cpu_receipt_and_actual_exit():
    class Proc:
        pid = 23
        def poll(self): return 0
    class Cpu:
        def built_executable_receipt_document(self): return {'binary_sha256': 'cpu'}
        def built_executable_launch_observations(self):
            return ({'pid': 22, 'returncode': 0, 'reaped': True},)
    class Dma:
        def execution_identity(self): return {'pid': 23, 'binary_sha256': 'dma'}
    result = smoke.process_evidence(Cpu(), Dma(), Proc())
    assert result['cpu']['build_receipt']['binary_sha256'] == 'cpu'
    assert result['cpu']['launches'][0]['returncode'] == 0
    assert result['zipdma']['identity']['pid'] == 23
    assert result['zipdma']['returncode'] == 0
