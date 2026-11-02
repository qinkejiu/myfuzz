import pytest
from myfuzz.integration.compiled_f6 import CompiledF6Runtime, f6_topology_validation_scope, _TOPOLOGY_VALIDATION_MODE
from tests.integration.test_compiled_f6_runtime import _finish_gate_shell


def test_scope_is_explicit_and_restores_on_error():
    assert _TOPOLOGY_VALIDATION_MODE.get()=='boundary'
    with pytest.raises(RuntimeError):
        with f6_topology_validation_scope('legacy'):
            assert _TOPOLOGY_VALIDATION_MODE.get()=='legacy'
            raise RuntimeError('failure')
    assert _TOPOLOGY_VALIDATION_MODE.get()=='boundary'
    with pytest.raises(ValueError):
        with f6_topology_validation_scope('unknown'):pass


@pytest.mark.parametrize('prior',(False,True))
def test_finish_static_gate_runs_before_cleanup_and_preserves_primary(monkeypatch,prior):
    original=ValueError('execution first') if prior else None
    runtime=_finish_gate_shell(monkeypatch,primary=original)
    calls=[]
    from myfuzz.scenario import f6_execution_binding
    boundary=ValueError('static metadata drift')
    def full(*a,**kw):
        assert not runtime._session_finish_called
        calls.append('full')
        raise boundary
    monkeypatch.setattr(f6_execution_binding,'validate_f6_execution_binding',full)
    finish=runtime.session.finish
    def cleanup():calls.append('cleanup');return finish()
    runtime.session.finish=cleanup
    with pytest.raises(ValueError) as raised:CompiledF6Runtime._finish_once(runtime)
    assert raised.value is (original if prior else boundary)
    assert calls==['full','cleanup']
    assert runtime._finish_document['completed'] is False
    assert runtime._finish_document['status']=='partial'
