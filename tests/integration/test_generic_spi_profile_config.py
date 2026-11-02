"""New APB IP configuration reuses the public CPU-independent MMIO runtime."""
import json
from pathlib import Path

import pytest

from myfuzz.runtime.generic_campaign import load_descriptor, select_case_records

ROOT = Path(__file__).resolve().parents[2]
SCENARIOS = (
    'compiled-f2-f4-obi-apb-spi-mmio-ibex',
    'compiled-f2-f4-axil-apb-spi-mmio-picorv32',
)


@pytest.mark.parametrize('name', SCENARIOS)
def test_spi_declares_public_mmio_and_same_register(name):
    directory = ROOT / 'configs/scenarios' / name
    descriptor = load_descriptor(directory / 'generic_scenario.json', base_dir=ROOT)
    assert descriptor.executors == {'F2': 'compiled_mmio', 'F4': 'compiled_mmio'}
    records = json.loads((directory / 'acceptance_sequence.json').read_text())
    assert records == ['F4:55000000', 'F2:08100040', 'F4:aa000000', 'F2:08100040']
    assert select_case_records(descriptor, flow='mixed', records=records) == tuple(
        tuple(row.split(':')) for row in records)
    compose = json.loads((directory / 'compose.json').read_text())
    assert compose['devices'][0]['bus_endpoint'] == 'spi.bus'
    capability = json.loads(descriptor.capability.read_text())
    assert capability['register_semantics'][0]['register'] == 'SPICMD'
