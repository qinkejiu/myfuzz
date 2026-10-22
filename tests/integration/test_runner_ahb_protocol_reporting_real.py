"""Opt-in real AHB target boundary proof through the ordinary Runner journal.

The Caliptra wrapper ties hold and bus error low. This fixture can prove
completed requests, accepts and responses, but cannot exercise positive wait,
error or in-flight reset cancellation. It makes no CPU, DMA or digest claim.
"""

from dataclasses import asdict
import gzip
import json
import os
from pathlib import Path
import traceback

import pytest

from myfuzz.local_harness.ahb_lite_register_session import GeneratedAhbLiteRegisterSession
from myfuzz.scenario.event_journal import EventJournal
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner
from tests.local_harness.test_ahb_register_target import ROOT, artifact


CASE_ID = 'caliptra-sha256-ahb-runner-boundary'
SETUP = ((0x80, 0x61626380),)
PROBES = (0, 4, 0x18)


def _write_gzip(path, document):
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, 'wt', encoding='utf-8') as stream:
        json.dump(document, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')


def _ownership(runtime):
    assert runtime['dynamic_physical_inputs'] == []
    assert runtime['bound_physical_inputs'] == []
    fields, owners = [], []
    for row in runtime['fixed_physical_inputs']:
        port = row['endpoint_id'] + '.' + row['role']
        width = row['width']
        fields.append(InputField('sha', port, width))
        owners.append(InputOwner('sha', port, 0, width, 'fixed', 'profile_constant'))
    return compile_ownership(tuple(fields), tuple(owners))


def _report_checks(report, journal, expected):
    assert report['schema_version'] == 'runner_protocol_trace_set_report.v1'
    assert report['proof_scope'] == 'protocol_boundary_only'
    assert report['cursor'] == len(journal)
    assert set(report['endpoints']) == {'sha256.bus'}
    endpoint = report['endpoints']['sha256.bus']
    evidence, coverage = endpoint['evidence'], endpoint['coverage']
    assert evidence['proof_scope'] == 'protocol_boundary_only'
    assert evidence['journal_integrity'] is True
    assert evidence['last_event_id'] == len(journal)
    assert evidence['runtime_contract_sha256'] == expected['artifact_digest']
    assert evidence['counts'] == {'verified': expected['accesses'], 'pending': 0}
    assert evidence['diagnostics'] == ({} if expected['accesses'] == 4 else {'reset': 1})
    assert coverage['cursor'] == len(journal)
    assert coverage['pending_count'] == 0
    assert coverage['diagnostics'] == {}
    assert coverage['counts']['event:sha256.bus:transaction_request'] == expected['accesses']
    assert coverage['counts']['event:sha256.bus:transaction_accept'] == expected['accesses']
    assert coverage['counts']['event:sha256.bus:transaction_response'] == expected['accesses']
    assert coverage['counts']['transaction:sha256.bus:read'] == expected['reads']
    assert coverage['counts']['transaction:sha256.bus:write'] == expected['writes']
    assert coverage['counts']['response:sha256.bus:ok'] == expected['accesses']
    return endpoint


def _completed_chains(journal, endpoint, signals, *, epochs):
    by_id = {row['event_id']: row for row in journal}
    assert list(by_id) == list(range(1, len(journal) + 1))
    pre = [row for row in journal if row.get('kind') == 'local_tick_sample'
           and row['phase'] == 'pre']
    ticks = [row['local_tick'] for row in pre]
    assert ticks == sorted(set(ticks))
    assert {row['reset_epoch'] for row in pre} == set(epochs)
    for previous, following in zip(epochs, epochs[1:]):
        assert max(row['local_tick'] for row in pre if row['reset_epoch'] == previous) < min(
            row['local_tick'] for row in pre if row['reset_epoch'] == following)
    projected = [row for row in journal if row.get('schema_version') == 'ip_base_event.v1'
                 and row.get('endpoint_id') == 'sha256.bus']
    assert {kind: sum(row['event_type'] == kind for row in projected)
            for kind in ('transaction_request', 'transaction_accept',
                         'transaction_response')} == {
                             'transaction_request': 4 * len(epochs),
                             'transaction_accept': 4 * len(epochs),
                             'transaction_response': 4 * len(epochs)}
    assert all(row['event_type'] in ('transaction_request', 'transaction_accept',
                                     'transaction_response') for row in projected)
    certificates = endpoint['evidence']['certificates']
    assert len(certificates) == 4 * len(epochs)
    assert len({certificate['request_raw_event_id'] for certificate in certificates}) == len(certificates)
    assert len({certificate['response_raw_event_id'] for certificate in certificates}) == len(certificates)
    expected_accesses = ((0x80, True, 0x61626380), (0, False, 0x61327368),
                         (4, False, 0x35362d32), (0x18, False, None))
    for epoch_index, epoch in enumerate(epochs):
        for index, (offset, write, value) in enumerate(expected_accesses):
            certificate = certificates[4 * epoch_index + index]
            request = by_id[certificate['request_event_id']]
            accept = by_id[certificate['accept_event_id']]
            response = by_id[certificate['response_event_id']]
            request_raw = by_id[certificate['request_raw_event_id']]
            accept_raw = by_id[certificate['accept_raw_event_id']]
            response_raw = by_id[certificate['response_raw_event_id']]
            assert certificate['outcome'] == 'ok'
            assert certificate['transaction_key'] is None
            assert certificate['identity_gap'] == 'protocol_has_no_transaction_id'
            assert [row['event_type'] for row in (request, accept, response)] == [
                'transaction_request', 'transaction_accept', 'transaction_response']
            assert all(row['reset_epoch'] == epoch for row in
                       (request, accept, response, request_raw, accept_raw, response_raw))
            assert all(row['kind'] == 'local_tick_sample' and row['phase'] == 'pre'
                       for row in (request_raw, accept_raw, response_raw))
            assert request_raw['event_id'] == accept_raw['event_id']
            assert request['raw_event_refs'] == [request_raw['event_id']]
            assert accept['raw_event_refs'] == [accept_raw['event_id']]
            assert response['raw_event_refs'] == [response_raw['event_id']]
            assert request['payload']['address'] == offset
            assert request['payload']['direction'] == ('write' if write else 'read')
            assert request['payload']['hsize'] == 2
            assert accept['payload']['address'] == offset
            assert response['payload']['address'] == offset
            assert response['payload']['direction'] == ('write' if write else 'read')
            assert response['payload']['error'] is False
            pins = {role: request_raw['outputs']['backend'][name]
                    for role, name in signals.items()}
            data = {role: response_raw['outputs']['backend'][name]
                    for role, name in signals.items()}
            assert (pins['haddr'], pins['hwrite'], pins['hsize'], pins['hsel'],
                    pins['hreadyin'], pins['htrans']) == (offset, int(write), 2, 1, 1, 2)
            assert data['hreadyout'] == 1 and data['hresp'] == 0
            assert data['htrans'] == 0
            observed = data['hwdata'] if write else data['hrdata']
            assert response['payload']['value'] == observed
            if value is not None:
                assert observed == value
            else:
                assert observed & 1, 'real SHA256 status must report ready'
            assert request_raw['local_tick'] < response_raw['local_tick']
    return certificates


def _run_once(label, generated, cache, evidence_dir):
    session = GeneratedAhbLiteRegisterSession(generated, base_dir=ROOT, cache_dir=cache,
        setup_writes=SETUP, probe_offsets=PROBES)
    runner = ScenarioRunner(sessions={'sha': session},
        ownership=_ownership(generated.runtime_document), bindings=())
    runner.enable_event_journal(chunk_size=8)
    assert isinstance(runner._events._records, EventJournal)
    result = {'label': label, 'actions': [], 'processes': [], 'reports': {},
              'journal': [], 'runner_identity': runner.identity_document(),
              'session_identity': session.identity_document()}
    handles = result['processes']
    launched = []
    primary = None
    try:
        runner.begin_test(CASE_ID)
        launched.append(session.process)
        handles.append({'epoch': 0, 'pid': session.process.pid,
                        'execution': session._execution})
        for index in range(2):
            outputs = dict(runner.step('sha'))
            result['actions'].append({'kind': 'step', 'index': index,
                                      'outputs': outputs})
            if index == 0:
                assert outputs['reg_000'] == 0x61327368
                assert outputs['reg_004'] == 0x35362d32
                assert outputs['reg_018'] & 1
            else:
                assert not any(key.startswith('reg_') for key in outputs)
        before = runner.protocol_trace_set_reports()['sha']
        result['reports']['before_reset'] = before
        _report_checks(before, list(runner.events), dict(
            artifact_digest=generated.runtime_document['artifact_digest'],
            accesses=4, reads=3, writes=1))
        assert launched[0].poll() is None
        reset = runner.reset_all('warm_all')
        handles[0]['returncode'] = launched[0].poll()
        launched.append(session.process)
        handles.append({'epoch': 1, 'pid': session.process.pid,
                        'execution': session._execution})
        result['actions'].append({'kind': 'reset', 'result': asdict(reset)})
        assert handles[0]['returncode'] == 0
        assert session.process is not launched[0]
        outputs = dict(runner.step('sha'))
        result['actions'].append({'kind': 'step', 'index': 2, 'outputs': outputs})
        assert outputs['reg_000'] == 0x61327368
        assert outputs['reg_004'] == 0x35362d32
        assert outputs['reg_018'] & 1
    except BaseException as error:
        primary = error
    finally:
        try:
            if runner._status in ('running', 'quiescing', 'failed'):
                runner.finalize()
        except BaseException as cleanup:
            if primary is None:
                primary = cleanup
            else:
                primary.add_note('Runner finalize failed: ' + repr(cleanup))
        finally:
            for index, handle in enumerate(launched):
                handles[index]['returncode'] = handle.poll()
            result['journal'] = list(runner.events)
            result['runner_status'] = runner._status
            result['failure_status'] = runner.failure_status
            try:
                result['reports']['final'] = runner.protocol_trace_set_reports().get('sha')
            except BaseException as reporting:
                result['report_failure'] = repr(reporting)
                if primary is None:
                    primary = reporting
                else:
                    primary.add_note('Final report failed: ' + repr(reporting))
            finally:
                runner._events._records.close()
    if primary is not None:
        result['failure'] = ''.join(traceback.format_exception(primary))
        _write_gzip(evidence_dir / (label + '.failure.json.gz'), result)
        raise primary
    _write_gzip(evidence_dir / (label + '.json.gz'), result)
    return result


@pytest.mark.skipif(os.environ.get('MYFUZZ_AHB_PROTOCOL_REAL') != '1',
                    reason='explicit real AHB Runner protocol gate')
def test_real_ahb_target_runner_protocol_reporting_and_fresh_replay(tmp_path):
    evidence_dir = Path(os.environ.get('MYFUZZ_AHB_PROTOCOL_EVIDENCE',
                                       str(tmp_path / 'evidence')))
    cache = Path(os.environ.get('MYFUZZ_AHB_PROTOCOL_CACHE', str(tmp_path / 'cache')))
    generated = artifact()
    _write_gzip(evidence_dir / 'artifact.json.gz', generated.runtime_document)
    summary = {'schema_version': 'real_ahb_runner_protocol_gate.v1',
               'proof_scope': 'protocol_boundary_only',
               'unsupported_by_fixture': ['positive_wait', 'response_error',
                                          'in_flight_reset_cancellation'],
               'runs': []}
    try:
        runs = []
        for label in ('first', 'fresh'):
            run = _run_once(label, generated, cache, evidence_dir)
            runs.append(run)
            journal = run['journal']
            endpoint = _report_checks(run['reports']['final'], journal, dict(
                    artifact_digest=generated.runtime_document['artifact_digest'],
                    accesses=8, reads=6, writes=2))
            _completed_chains(journal, endpoint,
                              generated.runtime_document['base_protocol_trace']['signals'],
                              epochs=(0, 1))
            assert run['runner_status'] == 'finalized'
            assert run['failure_status'] is None
            barriers = [row for row in journal if row.get('kind') == 'reset_barrier']
            assert len(barriers) == 1 and barriers[0]['policy'] == 'warm_all'
            assert barriers[0]['cancelled_responses'] == {'sha': 0}
            assert barriers[0]['pending_responses_before_reset'] == {'sha': 0}
            assert barriers[0]['pending_events_before_reset'] == {}
            assert barriers[0]['pending_events_after_reset'] == {}
            assert len(run['processes']) == 2
            assert all(handle['returncode'] == 0 for handle in run['processes'])
            assert len({handle['execution'] for handle in run['processes']}) == 2
            assert len({handle['pid'] for handle in run['processes']}) == 2
            summary['runs'].append({'label': label, 'journal_events': len(journal),
                                    'verified': 8, 'processes': run['processes']})
        first, fresh = runs
        assert first['actions'] == fresh['actions']
        assert first['journal'] == fresh['journal']
        assert first['reports'] == fresh['reports']
        assert first['runner_identity'] == fresh['runner_identity']
        assert first['session_identity'] == fresh['session_identity']
        assert len({handle['execution'] for run in runs
                    for handle in run['processes']}) == 4
        assert len({handle['pid'] for run in runs
                    for handle in run['processes']}) == 4
        summary['status'] = 'passed'
    except BaseException:
        summary['status'] = 'failed'
        summary['failure'] = traceback.format_exc()
        _write_gzip(evidence_dir / 'validation.failure.json.gz',
                    {'summary': summary, 'runs': runs if 'runs' in locals() else []})
        raise
    finally:
        _write_gzip(evidence_dir / 'summary.json.gz', summary)
