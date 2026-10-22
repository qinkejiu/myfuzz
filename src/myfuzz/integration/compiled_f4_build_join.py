"""Fixed F4 build-join API; cross-flow bindings refuse validation."""
from .compiled_build_join import (
    built_receipt_sha256, validate_built_receipts, build_compiled_build_join,
    verify_compiled_build_join, verify_compiled_build_material)

SCHEMA = 'compiled_F4_build_join.v1'


def build_compiled_f4_build_join(*, artifacts, execution_binding,
        compiled_document_sha256, runtime_path_id, logical_path_id,
        original, fresh, error=None):
    return build_compiled_build_join(flow='F4', artifacts=artifacts,
        execution_binding=execution_binding, compiled_document_sha256=compiled_document_sha256,
        runtime_path_id=runtime_path_id, logical_path_id=logical_path_id,
        original=original, fresh=fresh, error=error)


def verify_compiled_f4_build_join(document, *, artifacts,
        execution_binding, original, fresh):
    return verify_compiled_build_join(document, flow='F4', artifacts=artifacts,
        execution_binding=execution_binding, original=original, fresh=fresh)


def verify_compiled_f4_build_material(document, *, harness_set, manifest, prefix, replay):
    return verify_compiled_build_material(document, flow='F4', harness_set=harness_set,
        manifest=manifest, prefix=prefix, replay=replay)
