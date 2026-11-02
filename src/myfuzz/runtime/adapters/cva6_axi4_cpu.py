"""Certified execution surface of the packed single-port CVA6 AXI4 CPU.

The admission verifier (:func:`myfuzz.runtime.admission._cva6_cpu_endpoints`)
and the bound MMIO CPU adapter both recompute this document from the generated
artifact alone, so a plan can only be bound to the artifact it was admitted
from.  The declared wire template is the composition's own
``('cpu.axi4', '1', 'single-beat-id')`` triple, whose contract already refuses
bursts, lock, atomics and outstanding parallelism -- exactly what this core's
pinned configuration declares (``capabilities.bursts = false``).

What this row cannot certify is stated, not omitted: the port carries no
instruction/data identity, so the certified surface names the data chain only
(see ``INSTRUCTION_HOP_REFUSAL`` in ``integration/cva6_axi_mmio.py``).
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json

CVA6_CPU_PROTOCOL = ('axi4', '1')
CVA6_CPU_TEMPLATE = ('cpu.axi4', '1', 'single-beat-id')
CVA6_CPU_SEMANTIC_KIND = 'cpu.axi4.v1'
#: A read completes on R and a write on B; the channels are independent.
CVA6_CPU_COMPLETION = 'independent_channels_response'
CVA6_CPU_KIND = 'cva6_packed_axi4_cpu'
_FILES = ('src/myfuzz/runtime/adapters/cva6_axi4_cpu.py',
          'src/myfuzz/integration/cva6_axi_mmio.py',
          'src/myfuzz/integration/native_mmio_data_hops.py',
          'src/myfuzz/local_harness/cva6_axi_mmio_session.py',
          'src/myfuzz/local_harness/cva6_axi4_session.py',
          'src/myfuzz/local_harness/cva6_axi4_fields.py',
          'src/myfuzz/scenario/full_axi_events.py')


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                             allow_nan=False).encode()).hexdigest()


def cva6_axi4_cpu_surface_document(artifact):
    """Derive the certified packed-AXI4 CPU execution surface of one artifact."""
    from ...local_harness.cva6_axi4_fields import CVA6_AXI_SHAPE
    document = artifact.runtime_document
    if document.get('kind') != CVA6_CPU_KIND:
        raise ValueError('packed CVA6 artifact required')
    capabilities = artifact.plan.profile.capabilities
    wanted = (64, 64, 4, 64, True, True, False, 1)
    if tuple(capabilities.get(key) for key in (
            'address_width', 'data_width', 'id_width', 'user_width',
            'byte_enable', 'error_response', 'bursts',
            'max_outstanding')) != wanted:
        raise ValueError('packed CVA6 declared width/completion capabilities changed')
    rows = document.get('backend_ports')
    if not isinstance(rows, list) or not rows:
        raise ValueError('packed CVA6 native backend ports required')
    by_role = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('packed CVA6 backend port shape')
        by_role[row.get('role')] = row
    if set(by_role) != set(CVA6_AXI_SHAPE):
        raise ValueError('packed CVA6 backend role set changed')
    roles = {}
    for role, (direction, width) in CVA6_AXI_SHAPE.items():
        row = by_role[role]
        if (row.get('name') != 'axi_' + role or row.get('channel') != 'axi'
                or row.get('direction') != direction or row.get('width') != width):
            raise ValueError('packed CVA6 backend role shape changed: ' + role)
        roles[role] = (direction, width, row['name'])
    boot = document.get('boot_contract') or {}
    base = boot.get('configured_boot_base')
    if type(base) is not int or not 0 <= base < 1 << 64 or base % 4:
        raise ValueError('packed CVA6 configured boot base required')
    from ...integration.cva6_axi_mmio import INSTRUCTION_HOP_REFUSAL
    bound = [row for row in artifact.plan.binding.endpoints
             if row.protocol and tuple(row.protocol) == CVA6_CPU_PROTOCOL
             and row.function == 'memory_master']
    if len(bound) != 1:
        raise ValueError('exactly one packed CVA6 AXI4 memory master required')
    return dict(
        schema_version='cva6_axi4_cpu_execution_surface.v1',
        kind=CVA6_CPU_SEMANTIC_KIND,
        instance_id=artifact.plan.request.instance_id,
        endpoint_id=bound[0].endpoint_id,
        protocol=list(CVA6_CPU_PROTOCOL), template=list(CVA6_CPU_TEMPLATE),
        function='memory_master',
        roles=[[role, *roles[role][:2]] for role in sorted(roles)],
        signals={role: roles[role][2] for role in sorted(roles)},
        boot_contract=deepcopy(boot),
        source_sha256=_digest(artifact.source_verification),
        profile_fingerprint=artifact.plan.profile.profile_fingerprint,
        artifact_sha256=document['artifact_digest'],
        address_width=64, data_width=64, native_data_width=64,
        register_data_width=32, address_units='byte',
        byte_enable_width=roles['wstrb'][1], max_outstanding=1,
        completion_kind=CVA6_CPU_COMPLETION,
        write_channels=['aw', 'w', 'b'], read_channels=['ar', 'r'],
        channel_model='unified', instruction_identity=None,
        instruction_hop_refusal=INSTRUCTION_HOP_REFUSAL,
        supported_flows=['F2', 'F4'], refused_flows=['F1', 'F3'],
        instruction_retirement='unknown', internal_storage_version='unknown')


def verifier_identity():
    """Code-owned identity of the admission verifier for this row."""
    from ..admission import _pin
    return {'id': 'cva6.axi4.cpu.admission.v1', 'version': '1',
            'implementation_sha256': _pin(('src/myfuzz/runtime/admission.py',
                                           *_FILES))}


class BoundCva6Axi4CpuAdapter:
    """The bound packed-AXI4 CPU adapter of one admitted artifact."""

    def __init__(self, component, session, selection, surface, implementation_pin):
        self.component_instance_id = component.instance_id
        self.endpoint_id = surface['endpoint_id']
        self.adapter_id = 'cva6.axi4.cpu.v1'
        self.adapter_version = '1'
        self.protocol = CVA6_CPU_PROTOCOL
        self.template = CVA6_CPU_TEMPLATE
        self.semantic_kind = CVA6_CPU_SEMANTIC_KIND
        self.address_units = 'byte'
        self.completion_kind = CVA6_CPU_COMPLETION
        self.implementation_sha256 = implementation_pin
        self.channel_model = 'unified'
        self.instruction_granule = 8
        self.surface = surface
        self.surface_sha256 = _digest(surface)
        self.instruction_hop_refusal = surface['instruction_hop_refusal']
        self.supported_flows = list(surface['supported_flows'])
        self.refused_flows = list(surface['refused_flows'])
        self.session = session
        self.binding_sha256 = _digest(dict(
            component=component.artifact_sha256,
            semantic=component.semantic_contract_sha256,
            selection=selection.sha256(), session_object=id(session),
            implementation_sha256=implementation_pin))

    @property
    def drives_cpu(self):
        return False

    def assert_current(self):
        if _digest(self.surface) != self.surface_sha256:
            raise ValueError('packed CVA6 surface changed after binding')

    def close(self):
        return None

    def documentary(self):
        return {'schema_version': 'cva6_axi4_cpu_adapter_binding.v1',
                'component_instance_id': self.component_instance_id,
                'endpoint_id': self.endpoint_id,
                'adapter_id': self.adapter_id,
                'adapter_version': self.adapter_version,
                'implementation_sha256': self.implementation_sha256,
                'protocol': list(self.protocol),
                'template': list(self.template),
                'semantic_kind': self.semantic_kind,
                'channel_model': self.channel_model,
                'instruction_granule': self.instruction_granule,
                'surface_sha256': self.surface_sha256,
                'instruction_hop_refusal': self.instruction_hop_refusal,
                'supported_flows': self.supported_flows,
                'refused_flows': self.refused_flows,
                'binding_sha256': self.binding_sha256}


def bind_cva6_axi4_cpu_adapter(*, component, session, selection, preparation=None,
                               endpoint_id=None):
    """Bind the packed CVA6 CPU adapter to the admitted artifact and session.

    The bound adapter recomputes the very surface the admission verifier issued
    (same pure function of the same artifact) and refuses a session that is not
    the packed CVA6 wrapper this row declares.
    """
    from ..contracts import GenericRuntimeRefused
    from ..registry import registrations
    if session.__class__.__name__ != 'GeneratedCva6AxiMmioSession':
        raise GenericRuntimeRefused('generic-binding-drift', '/cva6_axi4_cpu',
                                    {'reason': 'exact-wrapper-session-required'})
    if session.artifact.plan.request.instance_id != component.instance_id:
        raise GenericRuntimeRefused('generic-binding-drift', '/cva6_axi4_cpu',
                                    {'reason': 'session-instance'})
    surface = cva6_axi4_cpu_surface_document(session.artifact)
    if (_digest(surface) != component.semantic_contract_sha256
            or surface['artifact_sha256'] != component.artifact_sha256):
        raise GenericRuntimeRefused('generic-binding-drift', '/cva6_axi4_cpu',
                                    {'reason': 'surface'})
    rows = [r for r in registrations() if r.adapter_id == selection.adapter_id]
    limits = None
    for row in rows:
        if row.adapter_id == 'cva6.axi4.cpu.v1':
            limits = row.implementation_sha256()
    if selection.adapter_id != 'cva6.axi4.cpu.v1' or limits is None \
            or selection.implementation_sha256 != limits:
        raise GenericRuntimeRefused('generic-binding-drift', '/cva6_axi4_cpu',
                                    {'reason': 'selection'})
    return BoundCva6Axi4CpuAdapter(component, session, selection, surface,
                                   limits)
