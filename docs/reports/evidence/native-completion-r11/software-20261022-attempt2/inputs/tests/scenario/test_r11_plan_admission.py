"""Pure software admission tests; no controller execution or native gate."""
import copy
import hashlib
import importlib.util
import inspect
import json
from pathlib import Path

import pytest


PATH = Path(__file__).resolve().parents[2] / 'scripts/task5_native_completion_r11/r11-one-shot-controller.v1.py'


@pytest.fixture
def admission(tmp_path):
    spec = importlib.util.spec_from_file_location('r11_plan_admission', PATH)
    controller = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(controller)
    operation = tmp_path / 'operation'
    (operation / 'control').mkdir(parents=True)
    run_id = 'a' * 64
    workspace = str(tmp_path)
    evidence = str(tmp_path / 'evidence')
    run = {'gate_run_id': run_id, 'cwd': str(operation / 'project'),
           'output': evidence, 'cache_dir': str(operation / 'native-cache'),
           'heavy_lock': workspace + '/.superpowers/heavy-worker.lock',
           'requested_gate_flags': list(controller.FLAGS),
           'requested_gates': list(controller.GATES)}
    run['argv'] = ['python3', '-B', str(operation) + '/' + controller.INPUTS['gate_script'],
                   '--output', evidence, '--cache-dir', run['cache_dir'],
                   '--heavy-lock', run['heavy_lock'], '--gate-run-id', run_id,
                   *controller.FLAGS]
    assert controller.validate_run(run, str(operation), evidence, workspace) == run_id
    intent = {'run': run, 'claims': dict(controller.CLAIMS),
              'acceptance_matrix': copy.deepcopy(controller.ACCEPTANCE_MATRIX),
              'gate_started': False, 'gate_executed': False}
    frozen = {key: {'sha256': hashlib.sha256(key.encode()).hexdigest()}
              for key in ('intent', 'controller', 'controller_receipt', 'plan')}
    frozen['intent']['sha256'] = controller.digest(controller.canonical(intent))
    plan = {'run': copy.deepcopy(run), 'intent': copy.deepcopy(intent),
            'gate_run_id': run_id, 'intent_sha256': frozen['intent']['sha256'],
            'controller_sha256': frozen['controller']['sha256'],
            'controller_receipt_sha256': frozen['controller_receipt']['sha256'],
            'claims': dict(controller.CLAIMS),
            'acceptance_matrix': copy.deepcopy(controller.ACCEPTANCE_MATRIX),
            'gate_started': False, 'gate_executed': False}
    return controller, operation, run, run_id, intent, plan, frozen


def check(admission):
    controller, operation, run, run_id, intent, plan, frozen = admission
    # Re-encode and reseal the actual modified plan bytes, not a stale digest.
    raw = controller.canonical(plan)
    (operation / 'control' / 'run-plan.v1.json').write_bytes(raw)
    frozen['plan']['sha256'] = controller.digest(raw)
    parsed = json.loads(raw)
    return controller.plan_identity_check(parsed, intent, {}, run, run_id, frozen)


def test_valid_plan_identity_admitted_without_claim(admission):
    check(admission)
    assert not (admission[1] / 'control' / 'claim.v1.json').exists()


@pytest.mark.parametrize('numeric', [0, 0.0], ids=['integer-zero', 'float-zero'])
@pytest.mark.parametrize('location', ['intent', 'plan', 'nested-intent'])
@pytest.mark.parametrize('field', ['coverage_guided_search', 'formal_p6_complete',
                                 'retirement_authority', 'source_authority',
                                 'gate_started', 'gate_executed'])
def test_resealed_numeric_identity_refused_by_preclaim_validator(admission, field, location, numeric):
    controller, operation, _, _, intent, plan, frozen = admission
    document = {'intent': intent, 'plan': plan, 'nested-intent': plan['intent']}[location]
    target = document['claims'] if field in controller.CLAIMS else document
    target[field] = numeric
    if location == 'intent':
        # Keep the copy and byte pin synchronized so rejection cannot be caused
        # merely by mismatched intent copies or stale identity digests.
        plan['intent'] = copy.deepcopy(intent)
        intent_raw = controller.canonical(intent)
        (operation / 'control' / 'intent.v1.json').write_bytes(intent_raw)
        frozen['intent']['sha256'] = controller.digest(intent_raw)
        plan['intent_sha256'] = frozen['intent']['sha256']
        assert controller.exact_value(plan['intent'], intent)
    elif location == 'nested-intent':
        original = intent['claims'] if field in controller.CLAIMS else intent
        assert original[field] is False
        # Ordinary Python comparison admits this mutated full copy.
        assert plan['intent'] == intent
        assert not controller.exact_value(plan['intent'], intent)
    else:
        original = intent['claims'] if field in controller.CLAIMS else intent
        assert original[field] is False
        assert controller.exact_value(plan['intent'], intent)
    with pytest.raises(controller.Refusal, match='^plan:intent-identity$'):
        check(admission)
    assert not (operation / 'control' / 'claim.v1.json').exists()


def test_execute_source_calls_validator_before_exclusive_claim(admission):
    # Source order evidence complements pure validation; execute is never run.
    source = inspect.getsource(admission[0].execute)
    run_validation = source.index('run_id = validate_run(')
    admission_call = source.index('plan_identity_check(')
    claim_write = source.index('write_json(opfd, OUTPUTS["claim"], claim)')
    assert run_validation < admission_call < claim_write
