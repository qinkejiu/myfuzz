"""Descriptor validation for the data-driven generic campaign path."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from myfuzz.runtime.generic_campaign import (GenericScenarioRefused,
                                             load_descriptor)

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('executor', ['compiled_mmio_obi_apb', 'compiled_mmio'])
def test_protocol_mmio_mixed_records_do_not_require_storage_executor(tmp_path, executor):
    from myfuzz.runtime.generic_campaign import select_case_records
    descriptor = load_descriptor(_write(tmp_path, flow_ids=['F2', 'F4'],
        executors={flow: executor for flow in ('F2', 'F4')},
        f2_records=['08100040']), base_dir=tmp_path)
    assert select_case_records(descriptor, flow='mixed',
        records=['F4:55000000', 'F2:08100040']) == (
            ('F4', '55000000'), ('F2', '08100040'))
    with pytest.raises(GenericScenarioRefused):
        select_case_records(descriptor, flow='mixed', records=['F3:55000000'])


def _write(base: Path, **overrides) -> Path:
    root = base / "scenario"
    root.mkdir(parents=True, exist_ok=True)
    for name in ("compose.json", "supplement.json", "capability.json"):
        (root / name).write_text("{}\n")
    document = {
        "schema_version": "generic_scenario_descriptor.v1",
        "scenario_id": "unit-row",
        "root": "scenario",
        "compose": "compose.json",
        "supplement": "supplement.json",
        "capability": "capability.json",
        "flow_ids": ["F4"],
        "executors": {"F4": "compiled_f4_wishbone"},
        "f4_records": ["55000000", "2a000000"],
        "f2_records": None,
        "rounds": 8,
    }
    document.update(overrides)
    path = base / "descriptor.json"
    path.write_text(json.dumps(document) + "\n")
    return path


def test_valid_descriptor_resolves_members_and_records(tmp_path):
    descriptor = load_descriptor(_write(tmp_path), base_dir=tmp_path)
    assert descriptor.scenario_id == "unit-row"
    assert descriptor.flow_ids == ("F4",)
    assert descriptor.records("F4") == ["55000000", "2a000000"]
    assert descriptor.executor("F4") == "compiled_f4_wishbone"
    assert descriptor.compose.is_file()


@pytest.mark.parametrize("field,value", [
    ("schema_version", "generic_scenario_descriptor.v0"),
    ("flow_ids", ["F9"]),
    ("flow_ids", ["F4", "F4"]),
    ("executors", {"F4": ""}),
    ("executors", {"F2": "compiled_f2_obi_apb"}),
    ("rounds", 0),
    ("rounds", True),
    ("f4_records", []),
    ("f4_records", ["xyz"]),
    ("f4_records", ["550"]),
])
def test_invalid_descriptor_fields_are_refused(tmp_path, field, value):
    with pytest.raises(GenericScenarioRefused):
        load_descriptor(_write(tmp_path, **{field: value}), base_dir=tmp_path)


def test_unknown_keys_are_refused(tmp_path):
    path = _write(tmp_path)
    document = json.loads(path.read_text())
    document["extra"] = 1
    path.write_text(json.dumps(document) + "\n")
    with pytest.raises(GenericScenarioRefused):
        load_descriptor(path, base_dir=tmp_path)


def test_paths_outside_base_or_missing_are_refused(tmp_path):
    outside = tmp_path.parent / "outside-compose.json"
    outside.write_text("{}\n")
    with pytest.raises(GenericScenarioRefused):
        load_descriptor(_write(tmp_path, root=".."), base_dir=tmp_path)
    path = _write(tmp_path, compose="missing.json")
    with pytest.raises(GenericScenarioRefused):
        load_descriptor(path, base_dir=tmp_path)


def test_repository_wishbone_descriptor_loads():
    path = ROOT / "configs/scenarios/compiled-f4-obi-wb-uart-setup/generic_scenario.json"
    descriptor = load_descriptor(path, base_dir=ROOT)
    assert descriptor.scenario_id == "wishbone-uart"
    assert descriptor.flow_ids == ("F4",)
    assert descriptor.executor("F4") == "compiled_f4_wishbone"
    assert descriptor.records("F4") == ["55000000", "2a000000", "78563412"]


def test_repository_apb_descriptors_load_with_file_records():
    timer = load_descriptor(
        ROOT / "configs/scenarios/compiled-f4-obi-apb-timer/generic_scenario.json",
        base_dir=ROOT)
    assert timer.flow_ids == ("F2", "F4")
    assert timer.executor("F2") == "compiled_f2_obi_apb"
    assert timer.records("F2") == ["04100040"]
    spi = load_descriptor(
        ROOT / "configs/scenarios/compiled-f4-obi-apb-spi-cv32e40p/generic_scenario.json",
        base_dir=ROOT)
    assert spi.records("F2") == ["08100040"]
    assert spi.executor("F4") == "compiled_f4_obi_apb"
    renamed = load_descriptor(
        ROOT / "configs/scenarios/generic-storage-contracts/renamed-timer/generic_scenario.json",
        base_dir=ROOT)
    assert renamed.flow_ids == ("F4",)
    assert renamed.records("F4") == ["55000000", "aa000000", "78563412"]


@pytest.mark.parametrize('flows', [
    ['F1', 'F2', 'F3', 'F4', 'F6'],
    ['F1', 'F2', 'F3', 'F4', 'F5', 'F6'],
])
def test_shared_slot_descriptor_selects_each_declared_flow(tmp_path, flows):
    from myfuzz.runtime.generic_campaign import select_case_records
    records = {'F1': '13000000', 'F2': '20100040', 'F3': '55000000',
               'F4': '55000000', 'F5': '0000000100000000', 'F6': '0110c00008000000'}
    values = {flow.lower() + '_records': [records[flow]] for flow in flows}
    descriptor = load_descriptor(_write(tmp_path, shared_slots=True,
        capability=['capability.json'], flow_ids=flows,
        executors={flow: 'compiled_f6_cpu_dma' for flow in flows}, **values), base_dir=tmp_path)
    for flow in flows:
        assert select_case_records(descriptor, flow=flow) == ((flow, records[flow]),)
        assert select_case_records(descriptor, flow=flow,
            records=[flow + ':' + records[flow]]) == ((flow, records[flow]),)
    assert select_case_records(descriptor, flow='mixed',
        records=[flow + ':' + records[flow] for flow in flows]) == tuple(
            (flow, records[flow]) for flow in flows)
    with pytest.raises(GenericScenarioRefused):
        select_case_records(descriptor, flow='F1', records=['F4:55000000'])
