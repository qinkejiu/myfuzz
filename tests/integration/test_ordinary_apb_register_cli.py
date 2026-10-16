"""Saved register CLI exposes fresh association evidence without changing legacy output."""
import io
import json
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

from tests.integration.test_register_capability_cli import cli_module


def test_cli_exposes_actual_fresh_association_snapshot_and_replay_mismatch():
    module = cli_module()
    evidence = dict(schema_version='ordinary_apb_access_evidence_state.v1',
        status='incomplete', reason='missing_actual_delivery',
        counts=dict(records=1, pending=0, cpu_delivery_confirmed=0), records=[])
    result = SimpleNamespace(matches=False, verification_scope=('register_program_reconstruction',),
        ordinary_apb_access_evidence=evidence,
        comparison=SimpleNamespace(first_difference=3, difference_context={'expected': 'x', 'actual': 'y'},
            actual_trace=SimpleNamespace(events=({},), semantic_sha256='a' * 64)))
    output = io.StringIO()
    with patch.object(module, 'replay_ibex_pulp_register_files', return_value=result), redirect_stdout(output):
        assert module.main(['replay-register-programs', '--cache-dir', 'cache', '--run-dir', 'saved']) == 2
    document = json.loads(output.getvalue())
    assert document['ordinary_apb_access_evidence'] == evidence
    assert document['matches'] is False
    assert 'capability_preflight' not in document
