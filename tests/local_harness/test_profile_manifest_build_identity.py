"""Real generated CPU artifact must build from its profile-local manifest."""
from pathlib import Path
from unittest.mock import patch

import pytest

from myfuzz.composition.component_profile import elaboration_mode_scope
from myfuzz.local_harness.build import LocalHarnessBuildError, local_build_identity
from myfuzz.local_harness.execution_validation import execution_validation_scope
from myfuzz.scenario.ibex_pulp_dual_source import _artifact

ROOT = Path(__file__).resolve().parents[2]
PROFILE = 'configs/cpus/cv32e20_profile_only/component_profile.json'


def test_profile_manifest_build_identity_pins_profile_and_every_closure_input():
    with elaboration_mode_scope('direct'), execution_validation_scope():
        artifact = _artifact(PROFILE, 'cpu')
        identity = local_build_identity(artifact, base_dir=ROOT)
        inputs = {row['path']: row['sha256'] for row in identity['inputs']}
        manifest = artifact.plan.profile.evidence['local_source_manifest']
        closure = manifest['elaboration_closures'][artifact.plan.profile.component_id]
        assert PROFILE in inputs
        assert 'configs/soc/sources.lock.json' not in inputs
        for row in closure['closure_files']:
            assert inputs[f"{row['root']}/{row['path']}"] == row['sha256']


def test_profile_manifest_build_identity_rejects_changed_source():
    with elaboration_mode_scope('direct'), execution_validation_scope():
        artifact = _artifact(PROFILE, 'cpu')
        source = (ROOT / 'third_party/cv32e20_upstream_reference/rtl/cve2_if_stage.sv').resolve()
        original_read = Path.read_bytes

        def changed(path):
            raw = original_read(path)
            return raw + b'\n// changed\n' if path.resolve() == source else raw

        with patch.object(Path, 'read_bytes', changed):
            with pytest.raises((ValueError, LocalHarnessBuildError)):
                local_build_identity(artifact, base_dir=ROOT)
