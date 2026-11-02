"""CV32E40P source-backed boot fetch and legal fixed-firmware registers."""
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]


def test_real_cv32e40p_artifact_derives_boot_and_32_register_firmware():
    from myfuzz.composition.component_profile import elaboration_mode_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from myfuzz.scenario.ibex_pulp_dual_source import _artifact
    from myfuzz.integration.shared_irq_firmware import (
        build_irq_firmware, expected_boot_fetch, irq_firmware_register_count)
    with elaboration_mode_scope('direct'), execution_validation_scope():
        artifact = _artifact(
            'configs/cpus/cv32e40p_rvfi_local/component_profile.json', 'cpu')
        runtime = SimpleNamespace(artifacts={'cpu': artifact}, cpu_id='cpu',
                                  base_dir=ROOT)
        assert expected_boot_fetch(runtime) == 0x10000
        assert artifact.runtime_document['boot_contract']['configured_boot_base'] == 0x10000
        assert irq_firmware_register_count(artifact.plan.profile) == 32
        firmware = build_irq_firmware(image_start=0x10000, image_end=0x40000,
            first_fetch=0x10000, gpio_base=0x40001000, pin=8, register_count=32)
        assert firmware['first_fetch'] == 0x10000
        # The prediction follows the real pinned IF stage formula for any
        # aligned configured base, and refuses a non-aligned one.
        from myfuzz.integration.cpu_boot_contract import source_backed_boot_fetch
        profile = artifact.plan.profile
        assert source_backed_boot_fetch(profile, base_dir=ROOT,
            configured_boot_base=0x20000) == 0x20000
        with pytest.raises(ValueError, match='aligned RV32'):
            source_backed_boot_fetch(profile, base_dir=ROOT,
                configured_boot_base=0x10002)


def test_cv32e40p_boot_strategy_is_bound_to_the_pinned_if_stage():
    from myfuzz.integration.cpu_boot_contract import _BOOT_STRATEGIES
    from hashlib import sha256
    rows = [row for row in _BOOT_STRATEGIES
            if row[0] == 'external_designs/cv32e40p/rtl/cv32e40p_if_stage.sv']
    assert len(rows) == 1
    path, digest, mask, bits = rows[0]
    assert (mask, bits) == (0xFFFFFFFC, 0)
    assert sha256((ROOT / path).read_bytes()).hexdigest() == digest
