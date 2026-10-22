"""Shared build diagnostics preserve authority failures and primary errors."""
import importlib
import importlib.util
from types import SimpleNamespace
import pytest


def module():
    name='myfuzz.integration.compiled_process_audit'
    assert importlib.util.find_spec(name) is not None,'shared build process audit missing'
    return importlib.import_module(name)


def test_failed_export_retains_previous_and_primary():
    mod=module()
    class Bad:
        def build_audit_snapshot(self,**kwargs):raise ValueError('receipt pin changed')
    owner=Bad();error=RuntimeError('native command failed')
    saved=mod.diagnostic_build_snapshot(owner,previous={'receipts':{'cpu':{'digest':'old'}}},error=error)
    assert saved['receipts']['cpu']['digest']=='old'
    assert saved['unavailable']['snapshot']['error']=='receipt pin changed'
    assert 'receipt pin changed' in '\n'.join(error.__notes__)


def test_construction_cleanup_preserves_failure_and_partial_audit():
    mod=module();seen=[]
    class Runtime:
        @mod.capture_build_construction
        def __init__(self,*,build_audit_sink):
            self._build_sessions={'cpu':SimpleNamespace(end_case=lambda:seen.append('closed'))}
            raise RuntimeError('primary')
        def build_audit_snapshot(self,**kwargs):return {'partial':True}
    with pytest.raises(RuntimeError,match='primary'):
        Runtime(build_audit_sink=lambda snapshot:seen.append(snapshot))
    assert seen==['closed',{'partial':True}]


def test_f4_uses_focused_shared_mixin():
    mod=module()
    from myfuzz.integration.compiled_f4 import CompiledF4Runtime
    assert issubclass(CompiledF4Runtime,mod.BuiltProcessAudit)
    assert CompiledF4Runtime._audit_schema=='compiled_F4_execution_audit.v1'
