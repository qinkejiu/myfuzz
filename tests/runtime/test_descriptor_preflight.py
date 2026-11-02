from pathlib import Path
from dataclasses import replace

from myfuzz.runtime.generic_campaign import load_descriptor
from myfuzz.runtime.descriptor_preflight import inspect_descriptor


ROOT = Path(__file__).resolve().parents[2]


def test_i2c_descriptor_reports_static_support_without_runtime_admission(tmp_path):
    descriptor = load_descriptor(
        ROOT / 'configs/scenarios/compiled-f2-f4-obi-apb-i2c-ibex/generic_scenario.json',
        base_dir=ROOT,
    )
    report = inspect_descriptor(descriptor, base_dir=ROOT, generated_dir=tmp_path / 'generated')
    assert report['preparation'] == 'complete'
    assert list(report['flows']) == ['F1', 'F2', 'F3', 'F4', 'F5', 'F6']
    for flow in ('F2', 'F4'):
        row = report['flows'][flow]
        assert row['declared'] is True
        assert row['static_support']['execution_supported'] == 1
        assert row['runtime_admission'] == 'not_checked'
    for flow in ('F1', 'F3', 'F5', 'F6'):
        row = report['flows'][flow]
        assert row['declared'] is False
        assert row['reason'] == 'flow-not-declared-by-descriptor'
        assert row['runtime_admission'] == 'not_checked'
    assert report['native_executed'] is False


def test_failed_preparation_keeps_every_declared_flow_unassessed(tmp_path):
    descriptor = load_descriptor(
        ROOT / 'configs/scenarios/compiled-f2-f4-obi-apb-i2c-ibex/generic_scenario.json',
        base_dir=ROOT,
    )
    descriptor = replace(descriptor, compose=ROOT / 'configs/does-not-exist.json')
    report = inspect_descriptor(descriptor, base_dir=ROOT, generated_dir=tmp_path / 'generated')
    assert report['preparation'] == 'refused'
    assert report['refusal']['code'] == 'generic-source-unverified'
    for flow in ('F2', 'F4'):
        assert report['flows'][flow]['reason'] == 'preparation-refused'
        assert report['flows'][flow]['runtime_admission'] == 'not_checked'
        assert 'static_support' not in report['flows'][flow]


def test_declared_f4_f2_records_are_validated_with_the_runtime_declarations(tmp_path):
    """The report validates the descriptor's own candidates, not just support."""
    descriptor = load_descriptor(
        ROOT / 'configs/scenarios/compiled-f2-f4-obi-apb-i2c-ibex/generic_scenario.json',
        base_dir=ROOT,
    )
    report = inspect_descriptor(descriptor, base_dir=ROOT, generated_dir=tmp_path / 'generated')
    assert report['preparation'] == 'complete'
    f4 = report['flows']['F4']['candidates']
    f2 = report['flows']['F2']['candidates']
    assert [row['record'] for row in f4] == list(descriptor.f4_records)
    assert [row['record'] for row in f2] == list(descriptor.f2_records)
    assert all(row['ok'] for row in f4 + f2)
    assert [row['value'] for row in f4] == [int.from_bytes(bytes.fromhex(raw), 'little')
                                           for raw in descriptor.f4_records]
    assert report['native_executed'] is False
