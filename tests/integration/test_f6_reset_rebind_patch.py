"""Gates for the prepared owner-file patch (``owner-reset-rebind.patch``).

The original patch remains historical. Two kinds of gate live here:

* before a rebind implementation is present, the patch must still apply; after
  the implementation lands, check its public surface instead;
* behaviour gates run when the current implementation provides the rebind API.

Nothing here is a native run.
"""
from __future__ import annotations

import inspect
import subprocess
from pathlib import Path

import pytest

from myfuzz.integration.compiled_f6 import CompiledF6Runtime
from myfuzz.integration import shared_f6_slots

ROOT = Path(__file__).resolve().parents[2]
PATCH = ROOT / 'runs/reset-continuation-20261030/owner-reset-rebind.patch'
APPLIED = hasattr(CompiledF6Runtime, 'rebind_reset_epoch')
SKIP = pytest.mark.skipif(not APPLIED, reason='owner patch not applied')


def test_the_prepared_patch_is_available_or_its_rebind_surface_is_present():
    assert PATCH.is_file()
    if APPLIED:
        assert callable(CompiledF6Runtime.rebind_reset_epoch)
        assert callable(shared_f6_slots.rebind_slot_scope)
        return
    result = subprocess.run(['git', 'apply', '--check', str(PATCH)], cwd=ROOT,
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def test_the_prepared_patch_still_declares_every_hunk_and_invariant():
    text = PATCH.read_text(encoding='utf-8')
    added = '\n'.join(line[1:] for line in text.splitlines()
                       if line.startswith('+') and not line.startswith('+++'))
    assert 'a/src/myfuzz/integration/compiled_f6.py' in text
    assert 'a/src/myfuzz/integration/shared_f6_slots.py' in text
    # the owner's own rebind entry point and the declared entry target
    for marker in ('def rebind_reset_epoch(',
                   'compiled-F6-reset-rebind-identity-mismatch',
                   'compiled-F6-reset-rebind-slot',
                   'compiled-F6-epoch-program-unbound',
                   'def _bootstrap_to_first_slot(self, *, entry_address=None):',
                   # the guarded, append-only one-shot scope release
                   'def rebind_slot_scope(runtime):',
                   'declared-reset-rebind-required', 'measured-reset-required',
                   "state['scope'] = None"):
        assert marker in text
    # and it never rewrites the admitted contract, program, binding or image
    for forbidden in ('self.contract = ', 'self.program = ',
                      'self.execution_binding = ', 'initial_image_sha256 = '):
        assert forbidden not in added


def test_the_report_names_the_third_owner_decision_it_cannot_take():
    report = (ROOT / 'runs/reset-continuation-20261030/README.md').read_text(encoding='utf-8')
    for phrase in ('compiled_f6.py', 'shared_f6_slots.py',
                   'compiled-F6-epoch-program-unbound',
                   'runtime_path_admission', 'initial_image_sha256'):
        assert phrase in report


# --------------------------------------------------------------------------- #
# The patched surface (active only after the owners apply the patch)
# --------------------------------------------------------------------------- #

@SKIP
def test_the_rebind_entry_point_declares_its_exact_arguments():
    parameters = inspect.signature(CompiledF6Runtime.rebind_reset_epoch).parameters
    assert list(parameters) == ['self', 'reset_policy', 'barrier_event_id',
                                'expected_epoch', 'next_slot']
    assert all(parameters[name].kind is inspect.Parameter.KEYWORD_ONLY
               for name in ('reset_policy', 'barrier_event_id', 'expected_epoch',
                            'next_slot'))


@SKIP
def test_the_bootstrap_can_be_targeted_at_the_declared_entry():
    parameters = inspect.signature(CompiledF6Runtime._bootstrap_to_first_slot).parameters
    assert list(parameters) == ['self', 'entry_address']
    assert parameters['entry_address'].default is None


@SKIP
def test_the_one_shot_scope_release_is_refused_outside_the_declared_rebind():
    with pytest.raises(ValueError) as raised:
        shared_f6_slots.rebind_slot_scope(object(), barrier_event_id=1, next_slot=1)
    assert str(raised.value) == 'shared-F4-F6-declared-reset-rebind-required'


@SKIP
def test_the_rebind_refuses_a_slot_that_is_not_a_later_epoch_entry():
    runtime = object.__new__(CompiledF6Runtime)
    runtime.contract = {'program_contract': {'slot_count': 8}}
    for slot in (0, 8, -1, True, 1.0):
        with pytest.raises(ValueError) as raised:
            runtime.rebind_reset_epoch(reset_policy='warm_all', barrier_event_id=1,
                                       expected_epoch=1, next_slot=slot)
        assert str(raised.value) == 'compiled-F6-reset-rebind-slot'
