import importlib.util
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('generated_zipdma_smoke', ROOT / 'scripts/run_generated_zipdma_smoke.py')
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


def test_validate_requires_actual_master_select_and_order():
    beats = [dict(address=0x100+4*i, write=False, byte_enable=15) for i in range(4)]
    beats += [dict(address=0x200+4*i, write=True, byte_enable=15) for i in range(4)]
    assert smoke.verify_result([1,2,3,4], beats, 0x180, 1, 0)
    beats[-1]['byte_enable'] = 5
    with pytest.raises(RuntimeError, match='master'):
        smoke.verify_result([1,2,3,4], beats, 0x180, 1, 0)
    with pytest.raises(RuntimeError, match='partial'):
        smoke.verify_result([1,2,3,4], beats[:-1] + [dict(address=0x20c,write=True,byte_enable=15)], 0x100, 1, 0)


def test_control_select_comes_from_real_pre_backend():
    events = [{'payload': {'pre_backend': {'swb_cyc': 1, 'swb_stb': 1,
                'swb_we': 1, 'swb_adr': 1, 'swb_sel': 1, 'swb_dat_w': 0x80}}}]
    assert smoke.control_select_observed(events, offset=4, value=0x80, select=1)
    assert not smoke.control_select_observed(events, offset=4, value=0x80, select=15)
