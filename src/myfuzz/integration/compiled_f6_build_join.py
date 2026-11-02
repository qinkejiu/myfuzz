"""Fixed compiled-F6 build and process-identity join API.

Build snapshots carry the actual build receipts for the selected CPU and DMA
artifacts. This join does not grant F6 dataflow, IRQ/ISR, or fresh-replay
capability by itself.
"""
from .compiled_build_join import (
    built_receipt_sha256, validate_built_receipts,
    build_compiled_build_join, verify_compiled_build_join)


SCHEMA = 'compiled_F6_build_join.v1'


def build_compiled_f6_build_join(*, artifacts, execution_binding,
        original, fresh, error=None):
    """Build the F6 typed CPU/DMA process join from original/fresh snapshots."""
    from myfuzz.scenario.f6_execution_binding import (
        CompiledF6ExecutionBinding)

    binding = (None if execution_binding is None else
        (execution_binding.document() if type(execution_binding) is CompiledF6ExecutionBinding
         else execution_binding))
    if binding is None:
        if error is None:
            raise ValueError('compiled-F6-build-join-binding-required')
        return build_compiled_build_join(flow='F6', artifacts=artifacts,
            execution_binding=None, compiled_document_sha256=None,
            runtime_path_id=None, logical_path_id=None, original=original,
            fresh=fresh, error=error, runtime_path_ids=None,
            runtime_path_admission=None,
            runtime_path_admission_sha256=None, selected_path_sha256=None)

    binding = CompiledF6ExecutionBinding(binding).document()
    admission = binding['runtime_path_admission']
    return build_compiled_build_join(flow='F6', artifacts=artifacts,
        execution_binding=binding,
        compiled_document_sha256=binding['compiled_document_sha256'],
        runtime_path_id=None, logical_path_id=binding['path_id'],
        original=original, fresh=fresh, error=error,
        runtime_path_ids=list(admission['runtime_path_ids']),
        runtime_path_admission=admission,
        runtime_path_admission_sha256=binding['runtime_path_admission_sha256'],
        selected_path_sha256=binding['selected_path_sha256'])


def verify_compiled_f6_build_join(document, *, artifacts,
        execution_binding, original, fresh):
    """Verify saved F6 build-join bytes against the same bound inputs."""
    return verify_compiled_build_join(document, flow='F6', artifacts=artifacts,
        execution_binding=execution_binding, original=original, fresh=fresh)

