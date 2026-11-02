"""Captured native original receipts plus a labelled synthetic fresh audit.

These are software build-association controls, never fresh native evidence.
"""
from copy import deepcopy
from hashlib import sha256
import json
import pytest

from tests.integration.test_compiled_f6_contract import ROOT


@pytest.fixture(scope='module')
def captured():
    from myfuzz.local_harness import load_local_harness_request, plan_local_harness
    from myfuzz.local_harness.renderer import render_local_harness
    from myfuzz.local_harness.runtime_artifact import LocalRuntimeArtifact
    directory = ROOT / 'research/input-strategy-audit-20261027/runs/three-component-20261028/f6-storage-support-schedulefix'
    path = directory / 'prefix.json'
    if not path.is_file():
        pytest.skip('captured three-component native original is unavailable')
    prefix = json.loads(path.read_text())
    # Rehydrate captured bytes as documentary artifact values. Current renderer
    # output may have changed; do not request or issue a live provider grant.
    artifacts = {}
    for name in prefix['artifact_digests']:
        saved = directory/'generated'/name
        request = load_local_harness_request(json.loads((saved/'request.json').read_text()))
        plan = plan_local_harness(request, base_dir=ROOT)
        structural = render_local_harness(plan)
        assert structural.wrapper_sv == (saved/'wrapper.sv').read_text()
        assert structural.abi_document == json.loads((saved/'abi.json').read_text())
        artifacts[name] = LocalRuntimeArtifact(plan, structural,
            json.loads((saved/'source_verification.json').read_text()),
            (saved/'runtime.sv').read_text(), (saved/'driver.cpp').read_text(),
            json.loads((saved/'artifact.json').read_text()))
    original = prefix['original_build']
    fresh = deepcopy(original)
    for name, row in fresh['execution_audit']['identities'].items():
        row['pid'] += 1000000
        row['execution_nonce'] = 'synthetic-fresh-'+name
    return dict(artifacts=artifacts, execution_binding=prefix['execution_binding'],
        original=original, fresh=fresh)


def test_shared_join_keeps_all_native_original_component_receipts(captured):
    from myfuzz.integration.compiled_f6_build_join import build_compiled_f6_build_join, verify_compiled_f6_build_join
    args = deepcopy(captured)
    joined = build_compiled_f6_build_join(**args)
    verify_compiled_f6_build_join(joined, **args)
    assert joined['status'] == 'complete'
    assert set(joined['artifact_digests']) == {'cpu', 'dma', 'peripheral'}
    assert joined['original']['receipts']['peripheral'] == args['original']['receipts']['peripheral']


@pytest.mark.parametrize('mutation', ['undeclared_extra', 'source_contract', 'window',
    'missing_receipt', 'missing_preparation', 'unreaped_companion', 'reused_nonce'])
def test_shared_join_refuses_incomplete_or_rebound_companion(captured, mutation):
    from myfuzz.integration.compiled_f6_build_join import build_compiled_f6_build_join
    args = deepcopy(captured)
    binding = args['execution_binding']
    if mutation == 'undeclared_extra':
        binding['issuer_contracts'].pop('shared_companions')
    elif mutation == 'source_contract':
        binding['issuer_contracts']['shared_companions']['peripheral']['source_contract']['register']['name'] = 'FOREIGN'
    elif mutation == 'window':
        binding['issuer_contracts']['shared_companions']['peripheral']['window']['base'] += 4096
    elif mutation == 'missing_receipt':
        args['fresh']['receipts'].pop('peripheral')
    elif mutation == 'missing_preparation':
        args['fresh']['preparation_observations'].pop('peripheral')
    elif mutation == 'unreaped_companion':
        args['fresh']['execution_audit']['exits']['peripheral']['reaped'] = False
    else:
        args['fresh']['execution_audit']['identities']['peripheral']['execution_nonce'] = args['original']['execution_audit']['identities']['peripheral']['execution_nonce']
    binding['binding_sha256'] = sha256(json.dumps({key: value for key, value in binding.items()
        if key != 'binding_sha256'}, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
    with pytest.raises(ValueError):
        build_compiled_f6_build_join(**args)
