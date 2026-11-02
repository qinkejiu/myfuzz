"""Identity-only observation uses actual fake-driver process handles."""
import pytest
from myfuzz.local_harness.session import record_local_commands
import test_session as session_fixtures


@pytest.fixture
def driver():
    fixture = session_fixtures.GeneratedSessionTests('runTest')
    fixture.setUp()
    try:
        yield fixture
    finally:
        fixture.doCleanups()


@pytest.mark.parametrize('capture', [0,1,None,'false'])
def test_capture_records_requires_strict_boolean(capture):
    with pytest.raises(ValueError,match='capture'):
        with record_local_commands(capture_records=capture):
            pass


def test_identity_only_records_actual_executions_without_payloads(driver):
    session = driver.make_session()
    with record_local_commands(capture_records=False) as trace:
        session.begin_case('first')
        first_process = session.process
        first_nonce = session._execution
        first, = trace.export_executions()
        assert first['pid'] == first_process.pid
        assert first['execution_nonce'] == first_nonce
        assert first['exit_code'] is None and first['reaped'] is False
        session.command('STEP_GPIO',(1,))
        assert trace.for_session(session) == ()
        assert trace.complete_for(session) is False
        assert trace.export_sessions()[0]['records'] == []
        assert trace.export_sessions()[0]['complete'] is False
        session.end_case()
        session.begin_case('second')
        second_process = session.process
        second_nonce = session._execution
        session.command('STEP_GPIO',(2,))
        session.end_case()
    rows = trace.export_executions()
    assert [row['execution_nonce'] for row in rows] == [first_nonce,second_nonce]
    assert [row['pid'] for row in rows] == [first_process.pid,second_process.pid]
    assert all(row['reaped'] is True and row['exit_code'] == 0 for row in rows)
    assert all(row['artifact_digest'] == 'a'*64 and row['binary_sha256'] for row in rows)
    assert all('command' not in row and 'reply' not in row for row in rows)
    rows[0]['pid'] = -1
    assert trace.export_executions()[0]['pid'] == first_process.pid


def test_default_capture_keeps_wire_records_and_exports_process_exit(driver):
    session = driver.make_session()
    with record_local_commands() as trace:
        session.begin_case('default')
        session.command('STEP_GPIO',(3,))
        session.end_case()
    assert trace.complete_for(session) is True
    assert len(trace.for_session(session)) == 1
    assert trace.export_executions()[0]['exit_code'] == 0


def test_identity_export_reports_actual_nonzero_process_exit(driver):
    session = driver.make_session()
    with record_local_commands(capture_records=False) as trace:
        session.begin_case('killed')
        process = session.process
        process.terminate()
        process.wait(timeout=2)
    execution, = trace.export_executions()
    assert execution['reaped'] is True
    assert execution['exit_code'] == process.returncode != 0


def test_restarted_session_keeps_each_process_exit_independent(driver):
    session = driver.make_session()
    with record_local_commands(capture_records=False) as trace:
        session.begin_case('terminated')
        first = session.process
        first.terminate()
        first.wait(timeout=2)
        session.end_case()
        session.begin_case('normal')
        second = session.process
        session.end_case()
    rows = trace.export_executions()
    assert [row['pid'] for row in rows] == [first.pid,second.pid]
    assert [row['exit_code'] for row in rows] == [first.returncode,0]
    assert first.returncode != 0
