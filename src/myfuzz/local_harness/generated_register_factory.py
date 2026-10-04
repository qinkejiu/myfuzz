"""Create register-observation sessions and input ownership from admitted artifacts."""
from __future__ import annotations

from collections.abc import Mapping

from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership

from .apb3_register_session import GeneratedApb3RegisterSession
from .request import LocalHarnessRequestV2
from .tlul_session_factory import create_generated_tlul_session
from .wishbone_register_session import GeneratedWishboneRegisterSession


_KINDS = frozenset(('tlul_register_observe', 'apb3_register_observe',
                    'wishbone_register_observe'))


def _document(artifact):
    document = getattr(artifact, 'runtime_document', None)
    plan = getattr(artifact, 'plan', None)
    if (not isinstance(document, dict) or document.get('kind') not in _KINDS
            or document.get('driver_status') != 'generated' or plan is None
            or not isinstance(plan.request, LocalHarnessRequestV2)):
        raise ValueError('generated v2 register artifact required')
    return document


def create_generated_register_session(artifact, *, base_dir, cache_dir):
    """Select the local register service by artifact kind, never component name."""
    kind = _document(artifact)['kind']
    if kind == 'tlul_register_observe':
        return create_generated_tlul_session(artifact, base_dir=base_dir,
                                             cache_dir=cache_dir)
    cls = (GeneratedApb3RegisterSession if kind == 'apb3_register_observe'
           else GeneratedWishboneRegisterSession)
    return cls(artifact, base_dir=base_dir, cache_dir=cache_dir)


def compile_generated_register_ownership(artifacts: Mapping[str, object]):
    """Compile the physical input owners of independent register harnesses.

    Serial peers own an abstract frame source rather than a physical pin, so
    callers must use the peer's scenario input contract for those artifacts.
    """
    if not isinstance(artifacts, Mapping) or not artifacts:
        raise ValueError('at least one generated register artifact required')
    fields = []
    owners = []
    for component_id, artifact in artifacts.items():
        if type(component_id) is not str or not component_id:
            raise ValueError('component id must be a nonempty string')
        document = _document(artifact)
        if document.get('serial_peer') is not None:
            raise ValueError('serial peer requires abstract frame source ownership')
        names = set()
        for key, kind, producer in (
                ('fixed_physical_inputs', 'fixed', 'profile_constant'),
                ('dynamic_physical_inputs', 'source', 'source_id'),
                ('bound_physical_inputs', 'bound', 'producer_ref')):
            rows = document.get(key)
            if not isinstance(rows, list):
                raise ValueError('generated register input ownership is missing')
            for row in rows:
                if not isinstance(row, dict):
                    raise ValueError('invalid generated register input ownership')
                name = row.get('input_name') or (
                    str(row.get('endpoint_id')) + '.' + str(row.get('role')))
                width = row.get('width')
                if (name in names or type(width) is not int or not 1 <= width <= 64):
                    raise ValueError('overlapping or invalid generated register input')
                names.add(name)
                reference = producer if kind == 'fixed' else row.get(producer)
                if type(reference) is not str or not reference:
                    raise ValueError('generated register input lacks owner identity')
                fields.append(InputField(component_id, name, width))
                owners.append(InputOwner(component_id, name, 0, width, kind,
                                         reference))
    return compile_ownership(tuple(fields), tuple(owners))
