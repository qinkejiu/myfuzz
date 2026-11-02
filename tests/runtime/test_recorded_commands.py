"""One exporter joins component recordings to actual execution identities."""
from copy import deepcopy

import pytest

from tests.runtime.test_generic_f6_entry import _trace_inputs


def export(rows, executions, *, audited=True):
    from myfuzz.runtime.recorded_commands import recorded_command_documents
    return recorded_command_documents(rows, executions=executions,
                                      scope='F6', audited=audited)


def test_export_matches_both_phases_without_reordering_or_completing_records():
    identities, rows = _trace_inputs()
    rows[0]['complete'] = False
    result = export(list(reversed(rows)), dict(zip(('original', 'fresh'), identities)))
    assert result['original']['sessions']['cpu']['complete'] is False
    assert result['fresh']['sessions']['dma']['records'] == rows[3]['records']
    assert result['original']['schema_version'] == 'local_command_trace.v1'


@pytest.mark.parametrize('bad', ['missing', 'duplicate', 'nonce_reuse', 'component',
    'binary', 'build', 'pid', 'artifact', 'invalid_nonce', 'invalid_digest',
    'incoherent_components', 'nonboolean_complete', 'missing_identity',
    'missing_pid', 'missing_artifact'])
def test_audited_export_refuses_ambiguous_or_mismatched_identity(bad):
    identities, rows = _trace_inputs()
    if bad == 'missing':
        rows.pop()
    elif bad == 'duplicate':
        rows.append(deepcopy(rows[0]))
    elif bad == 'nonce_reuse':
        identities[1]['cpu']['execution_nonce'] = identities[0]['cpu']['execution_nonce']
    elif bad == 'component':
        identities[0]['cpu']['component'] = 'foreign'
    elif bad in ('binary', 'build'):
        rows[0]['identity'][{'binary':'binary_sha256', 'build':'build_digest'}[bad]] = 'f' * 64
    elif bad == 'pid':
        rows[0]['identity']['pid'] += 1
    elif bad == 'artifact':
        identities[0]['cpu']['artifact_digest'] = 'a' * 64
        rows[0]['identity']['artifact_digest'] = 'b' * 64
    elif bad == 'invalid_nonce':
        identities[0]['cpu']['execution_nonce'] = 'bad'
    elif bad == 'invalid_digest':
        identities[0]['cpu']['binary_sha256'] = 'bad'
    elif bad == 'incoherent_components':
        identities[1].pop('dma')
    elif bad == 'nonboolean_complete':
        rows[0]['complete'] = 1
    elif bad == 'missing_identity':
        rows[0]['identity'] = None
    elif bad == 'missing_pid':
        rows[0]['identity'].pop('pid')
    elif bad == 'missing_artifact':
        identities[0]['cpu']['artifact_digest'] = 'a' * 64
    with pytest.raises(ValueError):
        export(rows, dict(zip(('original', 'fresh'), identities)))


def test_nonce_only_export_does_not_invent_audited_build_evidence():
    row = dict(component='pin', identity={'execution_nonce':'a'*32}, complete=True, records=[])
    result = export([row], {'original':{'pin':{'execution_nonce':'a'*32}}}, audited=False)
    assert result['original']['sessions']['pin']['identity'] == row['identity']
