"""Dual-source native IRQ receipt selection stays explicit and replayable."""
from pathlib import Path
import hashlib
import json
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

import pytest

from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_factory
from myfuzz.integration import ibex_pulp_online as online
from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_receipt_contract


def test_pin8_factory_requires_rvfi_and_boolean_native_receipt_optin():
    for value in (None, 0, 1, 'yes'):
        with pytest.raises(ValueError):
            make_ibex_pulp_dual_source_factory(
                Path('/tmp/pin8-native-no-start'), cpu_retirement=True,
                native_irq_receipts=value)
    with pytest.raises(ValueError):
        make_ibex_pulp_dual_source_factory(
            Path('/tmp/pin8-native-no-start'), native_irq_receipts=True)


def test_pin8_factory_exposes_authenticated_native_receipts_only_when_selected():
    disabled = make_ibex_pulp_dual_source_factory(
        Path('/tmp/pin8-native-no-start'), cpu_retirement=True)()
    enabled = make_ibex_pulp_dual_source_factory(
        Path('/tmp/pin8-native-no-start'), cpu_retirement=True,
        native_irq_receipts=True)()
    assert not disabled.sessions['cpu'].native_irq_receipts_enabled
    assert enabled.sessions['cpu'].native_irq_receipts_enabled
    assert 'cpu_native_irq_receipt_contract' in enabled.sessions['cpu'].identity_document()


def test_pin8_runtime_forwards_native_receipt_optin_before_start():
    session = Mock()
    session.begin.side_effect = RuntimeError('stop before RTL')
    with patch.object(online, 'ScenarioSession', return_value=session), patch.object(
            online, 'make_ibex_pulp_dual_source_factory', return_value=Mock(return_value=Mock())) as factory:
        with pytest.raises(RuntimeError, match='stop before RTL'):
            online.make_ibex_pulp_online_runtime(
                cache_dir=Path('/tmp/pin8-native-no-start'), run_id='test',
                cpu_retirement=True, native_irq_receipts=True)
    assert factory.call_args.kwargs['native_irq_receipts'] is True
    for value, cpu in ((1, True), (None, True), (True, False)):
        with patch.object(online, 'make_ibex_pulp_dual_source_factory') as factory:
            with pytest.raises(ValueError):
                online.make_ibex_pulp_online_runtime(
                    cache_dir=Path('/tmp/pin8-native-no-start'), run_id='test',
                    cpu_retirement=cpu, native_irq_receipts=value)
            factory.assert_not_called()


def test_pin8_saved_native_mode_uses_only_verified_manifest():
    with TemporaryDirectory() as directory:
        root = Path(directory)
        document = {'runner': {'sessions': {'cpu': {'identity': {
            'cpu_observation_schema_version': 'ibex_rvfi_observation.v1',
            'cpu_native_irq_receipt_contract': ibex_irq_receipt_contract()}}}}}
        raw = json.dumps(document).encode()
        path = root / 'online_session_manifest.json'
        path.write_bytes(raw)
        verified = {'artifacts': {'online_session_manifest.json': hashlib.sha256(raw).hexdigest()}}
        assert online._saved_pin8_native_irq_mode(root, verified) is True
        document['runner']['sessions']['cpu']['identity'].pop('cpu_native_irq_receipt_contract')
        legacy = json.dumps(document).encode()
        path.write_bytes(legacy)
        assert online._saved_pin8_native_irq_mode(root, {
            'artifacts': {'online_session_manifest.json': hashlib.sha256(legacy).hexdigest()}}) is False
        with pytest.raises(ValueError):
            online._saved_pin8_native_irq_mode(root, verified)
        document['runner']['sessions']['cpu']['identity'][
            'cpu_native_irq_receipt_contract'] = {'schema_version': 'forged'}
        bad = json.dumps(document).encode()
        path.write_bytes(bad)
        with pytest.raises(ValueError):
            online._saved_pin8_native_irq_mode(root, {
                'artifacts': {'online_session_manifest.json': hashlib.sha256(bad).hexdigest()}})
        document['runner']['sessions']['cpu']['identity'][
            'cpu_native_irq_receipt_contract'] = None
        null = json.dumps(document).encode()
        path.write_bytes(null)
        with pytest.raises(ValueError):
            online._saved_pin8_native_irq_mode(root, {
                'artifacts': {'online_session_manifest.json': hashlib.sha256(null).hexdigest()}})
        for malformed_identity in ([], ''):
            document['runner']['sessions']['cpu']['identity'] = malformed_identity
            malformed = json.dumps(document).encode()
            path.write_bytes(malformed)
            with pytest.raises(ValueError):
                online._saved_pin8_native_irq_mode(root, {
                    'artifacts': {'online_session_manifest.json': hashlib.sha256(malformed).hexdigest()}})


def test_pin8_cli_forwards_native_receipt_optin():
    import importlib.util
    from contextlib import redirect_stdout
    from io import StringIO

    script = Path(__file__).resolve().parents[2] / 'scripts/run_ibex_pulp_online.py'
    spec = importlib.util.spec_from_file_location('_pin8_native_cli', script)
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    with TemporaryDirectory() as directory:
        output = Path(directory) / 'new-run'
        result = Mock(output_dir=output, tests=1, statuses={}, elapsed_seconds=1,
                      effective_search_seconds=1)
        with patch.object(cli, 'make_ibex_pulp_online_runtime', return_value=Mock()) as runtime, patch.object(
                cli, 'run_scenario_rfuzz_live', return_value=result), redirect_stdout(StringIO()):
            assert cli.main(['run', '--client-binary', '/tmp/client', '--cache-dir',
                             '/tmp/cache', '--output', str(output), '--cpu-retirement',
                             '--native-irq-receipts']) == 0
        assert runtime.call_args.kwargs['native_irq_receipts'] is True


def test_pin8_fresh_replay_selects_native_receipts_from_saved_manifest():
    with TemporaryDirectory() as directory:
        root = Path(directory)
        plan = root / 'online_plan.json'
        plan.write_text('{}')
        trace = root / 'online_final_trace.json'
        trace.write_text(json.dumps({
            'genome_sha256': '0' * 64, 'status': 'complete', 'events': [],
            'local_ticks': {}, 'semantic_sha256': '0' * 64,
            'manifest_sha256': '0' * 64}))
        manifest = {'runner': {'sessions': {'cpu': {'identity': {
            'cpu_observation_schema_version': 'ibex_rvfi_observation.v1',
            'cpu_native_irq_receipt_contract': ibex_irq_receipt_contract()}}}}}
        raw = json.dumps(manifest).encode()
        (root / 'online_session_manifest.json').write_bytes(raw)
        verified = {'artifacts': {'online_session_manifest.json': hashlib.sha256(raw).hexdigest()}}
        with patch.object(online, '_verify_online_run_identity', return_value=verified), patch.object(
                online, '_saved_cpu_retirement_mode', return_value=True), patch.object(
                online, '_saved_gpio_consumption_mode', return_value=False), patch.object(
                online, 'make_ibex_pulp_dual_source_factory', return_value=Mock()) as factory, patch.object(
                online, 'replay_online_session', return_value='matched'):
            assert online.replay_ibex_pulp_online_files(
                cache_dir=root / 'cache', plan_path=plan, trace_path=trace) == 'matched'
        assert factory.call_args.kwargs['native_irq_receipts'] is True
