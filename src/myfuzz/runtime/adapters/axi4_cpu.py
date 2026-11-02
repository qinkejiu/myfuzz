"""Full AXI4 CPU ABI binding over the generated reduced single-beat session.

The bound row is the pinned VexiiRiscv full-AXI4 CPU: separate fetch (AR/R) and
LSU (AW/W/B/AR/R) channels, 32-bit address and data, 1-bit ID, and no
LEN/BURST/LOCK/QOS pins at all.  The one session that can drive it is
``local_harness.vexii_axi_mmio_session.GeneratedVexiiAxiMmioSession``: the
generated session plus the executor's ``router=`` keyword, the online
instruction slots and the parked fetch address.

Nothing here grants retirement, IRQ, storage-version, F5/F6 or search
authority.  Every capability string restates a fact of the generated harness or
of the bound session; the ones this row cannot observe are named as such.
"""
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from myfuzz.local_harness.vexii_axi_mmio_session import (
    GeneratedVexiiAxiMmioSession)

from ..contracts import (AdapterSelection, VerifiedComponent,
                         GenericRuntimeRefused, canonical_json_bytes)

CPU_ADAPTER_ID = 'axi4.cpu.v1'
CPU_ADAPTER_VERSION = '1'
CPU_PROTOCOL = ('axi4', '1')
CPU_TEMPLATE_DATA = ('cpu.axi4-reduced', '1', 'data-single')
CPU_TEMPLATE_FETCH = ('cpu.axi4-reduced', '1', 'fetch-single')
CPU_SEMANTIC_KIND = 'cpu.axi4.v1'
#: A read completes on R and a write on B; the two channels are independent.
CPU_COMPLETION = 'independent_channels_response'
#: The LSU face roles the generated data endpoint must really carry.
CPU_DATA_ROLES = ('awid', 'awaddr', 'awsize', 'awcache', 'awprot', 'awvalid',
                  'wdata', 'wstrb', 'wlast', 'wvalid', 'bready',
                  'arid', 'araddr', 'arsize', 'arcache', 'arprot', 'arvalid',
                  'rready', 'awready', 'wready', 'bid', 'bresp', 'bvalid',
                  'arready', 'rid', 'rdata', 'rresp', 'rlast', 'rvalid')
#: The fetch face roles: AR/R only, so neither face can be mistaken for the
#: other and no instruction attribute has to be invented.
CPU_FETCH_ROLES = ('arid', 'araddr', 'arsize', 'arcache', 'arprot', 'arvalid',
                   'rready', 'arready', 'rid', 'rdata', 'rresp', 'rlast',
                   'rvalid')
#: Roles the pinned reduced ABI has no pin for.  A profile that declares one is
#: a different AXI4 configuration (bursts/locks/QoS or a write-data ID), not
#: this adapter's, so it is refused instead of being silently widened.
CPU_ABSENT_ROLES = ('awlen', 'arlen', 'awburst', 'arburst', 'awlock', 'arlock',
                    'awqos', 'arqos', 'wid', 'wuser', 'ruser', 'awuser',
                    'aruser', 'buser', 'awregion', 'arregion', 'awatop',
                    'wid_meta')
CPU_DATA_FUNCTIONS = frozenset({'data_memory_master', 'memory_master'})
CPU_FETCH_FUNCTIONS = frozenset({'instruction_memory_master'})
_ROLE_WIDTHS = {
    'awvalid': 1, 'awready': 1, 'awid': 1, 'awaddr': 32, 'awsize': 3,
    'awcache': 4, 'awprot': 3,
    'wvalid': 1, 'wready': 1, 'wdata': 32, 'wstrb': 4, 'wlast': 1,
    'bvalid': 1, 'bready': 1, 'bid': 1, 'bresp': 2,
    'arvalid': 1, 'arready': 1, 'arid': 1, 'araddr': 32, 'arsize': 3,
    'arcache': 4, 'arprot': 3,
    'rvalid': 1, 'rready': 1, 'rid': 1, 'rdata': 32, 'rresp': 2, 'rlast': 1,
}
#: What the bound session can and cannot observe.  Every value restates a fact
#: of the generated harness/executor, never a capability claim.
CPU_CAPABILITY_LIMITS = {
    'mmio_beats': 'supported:routed_LSU_beat_queued_at_the_CPU_and_drained_at_the_declared_target',
    'ram_read_write': 'supported:persistent_memory_service_on_both_faces',
    'deferred_mmio': 'supported:queued_acceptance_joined_at_the_declared_target_step',
    'byte_enable': 'write_only:sampled_wstrb_on_the_LSU_face_reads_transfer_the_whole_addressed_word',
    'instruction_identity': 'declared:the_fetch_face_carries_AR_R_only_so_every_accepted_i_AR_is_a_fetch',
    'instruction_slots': 'supported:declared_fetch_slot_parked_after_acceptance_until_the_bound_source_materialises_it',
    'instruction_retirement': 'unknown:no_rvfi_port_in_this_generated_slice',
    'native_IRQ': 'unsupported:every_interrupt_input_is_held_at_zero_in_this_slice',
    'error_response': 'observed:rresp_and_bresp_are_real_pins_and_any_nonzero_status_fails_closed',
    'storage_version': 'unsupported:no_storage_provider_on_this_boundary',
    'F1': 'supported:independent_RAM_image_reads_through_the_generic_memory_flows',
    'F2': 'supported:routed_register_read_returns_the_actual_device_value',
    'F3': 'supported:independent_RAM_image_writes_through_the_generic_memory_flows',
    'F4': 'supported:routed_register_write_then_readback',
    'F5': 'unsupported:no_IRQ_or_pin_delivery_route',
    'F6': 'unsupported:no_shared_slot_or_DMA_provider',
}
_ROOT = Path(__file__).resolve().parents[4]
_FILES = ('src/myfuzz/runtime/adapters/axi4_cpu.py',
          'src/myfuzz/integration/cpu_axi4.py',
          'src/myfuzz/local_harness/vexii_axi_mmio_session.py',
          'src/myfuzz/local_harness/vexii_axi_session.py',
          'src/myfuzz/local_harness/vexii_axi_fields.py',
          'src/myfuzz/local_harness/session.py',
          'src/myfuzz/scenario/reduced_axi_events.py')
_MODULE_DIGESTS = {name: sha256((_ROOT / name).read_bytes()).hexdigest()
                   for name in _FILES}
_CLASS = GeneratedVexiiAxiMmioSession
_METHODS = {name: (getattr(_CLASS, name), getattr(_CLASS, name).__code__)
            for name in ('step_local', '_step_local_impl', 'begin_case',
                         'reset_local', 'accept_instructions',
                         'declare_instruction_slots', '_resume_instruction',
                         'queue_mmio', 'identity_document')}


def _digest(value):
    return sha256(canonical_json_bytes(value)).hexdigest()


def _require(value, reason):
    if not value:
        raise GenericRuntimeRefused('generic-binding-drift', '/axi4_cpu',
                                    {'reason': reason})


def _executor_rows(document):
    selected = document.get('selected_template')
    executor = selected.get('executor') if isinstance(selected, dict) else None
    binding = executor.get('binding') if isinstance(executor, dict) else None
    if not isinstance(binding, dict) or not isinstance(binding.get('endpoints'), list):
        raise ValueError('AXI4 generated executor binding required')
    return binding


def reduced_axi_cpu_data_endpoint(artifact):
    """The single declared AXI4 LSU endpoint of one artifact."""
    document = artifact.runtime_document
    if not isinstance(document, dict) or document.get('kind') != 'reduced_dual_axi_cpu':
        raise ValueError('reduced dual AXI4 CPU artifact required')
    rows = [endpoint for endpoint in artifact.plan.binding.endpoints
            if tuple(endpoint.protocol) == CPU_PROTOCOL
            and endpoint.function in CPU_DATA_FUNCTIONS]
    if len(rows) != 1:
        raise ValueError('one AXI4 CPU data endpoint required')
    return rows[0]


def reduced_axi_cpu_fetch_endpoint(artifact):
    """The single declared AXI4 fetch endpoint, or ``None`` when unified."""
    rows = [endpoint for endpoint in artifact.plan.binding.endpoints
            if tuple(endpoint.protocol) == CPU_PROTOCOL
            and endpoint.function in CPU_FETCH_FUNCTIONS]
    if len(rows) > 1:
        raise ValueError('ambiguous AXI4 CPU fetch endpoint')
    return rows[0] if rows else None


def _declared_roles(artifact, endpoint_id):
    rows = [row for row in _executor_rows(artifact.runtime_document)['endpoints']
            if isinstance(row, dict) and row.get('endpoint_id') == endpoint_id]
    if len(rows) != 1:
        raise ValueError('one declared endpoint row required')
    declared = {}
    for row in rows[0].get('roles') or ():
        role = row.get('role')
        if type(role) is not str or not role or role in declared:
            raise ValueError('unique declared role required')
        if role in CPU_ABSENT_ROLES:
            raise ValueError('role not present on this reduced AXI4 CPU: ' + role)
        declared[role] = [row.get('direction'), row.get('width'),
                          row.get('physical_port')]
    return declared


def _verify_face(declared, required, label):
    missing = [role for role in required if role not in declared]
    if missing:
        raise ValueError('incomplete AXI4 ' + label + ' ABI: ' + ','.join(missing))
    extra = sorted(set(declared) - set(required))
    if extra:
        raise ValueError('undeclared role not in this AXI4 ' + label + ' ABI: '
                         + ','.join(extra))
    for role, width in _ROLE_WIDTHS.items():
        if role in declared and declared[role][1] != width:
            raise ValueError('declared role width changed: ' + role)
    for role in required:
        if declared[role][0] not in ('input', 'output'):
            raise ValueError('declared role direction changed: ' + role)


def reduced_axi_cpu_roles(artifact, endpoint_id):
    """Measured role/width/direction rows of the declared LSU endpoint."""
    declared = _declared_roles(artifact, endpoint_id)
    _verify_face(declared, CPU_DATA_ROLES, 'data')
    if declared['wdata'][1] != declared['rdata'][1]:
        raise ValueError('AXI4 read/write data widths differ')
    if declared['wstrb'][1] != declared['wdata'][1] // 8:
        raise ValueError('AXI4 strobe width is not data_width/8')
    if declared['awaddr'][1] != declared['araddr'][1]:
        raise ValueError('AXI4 write/read address widths differ')
    return declared


def reduced_axi_cpu_surface_document(artifact):
    """Derive the certified full AXI4 CPU execution surface of one artifact.

    A pure function of the generated artifact: the declared endpoint rows, their
    measured role rows, the template contract, the profile's declared facts and
    the boot contract.  It is the same document the admission verifier pins and
    the bound adapter recomputes, so a plan can only be bound to the artifact it
    was admitted from.
    """
    document = artifact.runtime_document
    endpoint = reduced_axi_cpu_data_endpoint(artifact)
    roles = reduced_axi_cpu_roles(artifact, endpoint.endpoint_id)
    fetch = reduced_axi_cpu_fetch_endpoint(artifact)
    fetch_roles = None
    if fetch is not None:
        fetch_roles = _declared_roles(artifact, fetch.endpoint_id)
        _verify_face(fetch_roles, CPU_FETCH_ROLES, 'fetch')
    # The artifact's own ``selected_template`` is the *generated executor*
    # contract (``local.generated.reduced_dual_axi_cpu``), not the wire
    # template: the wire template is admitted per endpoint by the harness set
    # and is checked against ``preparation.declared_endpoint_template`` by the
    # admission verifier.  Here only the declared executor scope is pinned, so
    # this document stays a pure function of the artifact and its constants.
    contract = document['selected_template'].get('contract') or {}
    if (contract.get('scope'), contract.get('dut_semantics_verified')) != (
            'generated_executor_only', False):
        raise ValueError('AXI4 generated executor contract changed')
    if not str(contract.get('template_id') or '').startswith('local.generated.'):
        raise ValueError('AXI4 generated executor contract kind changed')
    capabilities = artifact.plan.profile.capabilities
    facts = _executor_rows(document).get('declared_profile_facts')
    if not isinstance(facts, dict):
        raise ValueError('AXI4 declared profile facts required')
    wanted = (32, 32, True, 1)
    if (capabilities.get('address_width'), capabilities.get('data_width'),
            capabilities.get('byte_enable'),
            capabilities.get('max_outstanding')) != wanted:
        raise ValueError('AXI4 declared widths/completion capabilities changed')
    if (facts.get('address_width'), facts.get('data_width'),
            facts.get('byte_enable'),
            facts.get('max_outstanding')) != wanted:
        raise ValueError('AXI4 declared profile facts changed')
    if capabilities.get('bursts') is not False:
        raise ValueError('AXI4 CPU must declare no burst behavior')
    if capabilities.get('single_beat_reduced_axi') is not True:
        raise ValueError('reduced single-beat AXI4 admission required')
    boot = document.get('boot_contract') or {}
    base = boot.get('configured_boot_base')
    if type(base) is not int or not 0 <= base < 1 << 32 or base % 4:
        raise ValueError('AXI4 configured boot base required')
    return dict(
        schema_version='axi4_cpu_execution_surface.v1', kind=CPU_SEMANTIC_KIND,
        instance_id=artifact.plan.request.instance_id,
        endpoint_id=endpoint.endpoint_id,
        protocol=list(CPU_PROTOCOL), template=list(CPU_TEMPLATE_DATA),
        executor_contract=deepcopy(contract),
        function=endpoint.function,
        roles=[[role, *roles[role][:2]] for role in sorted(roles)],
        signals={role: roles[role][2] for role in sorted(roles)},
        fetch_endpoint_id=None if fetch is None else fetch.endpoint_id,
        fetch_template=None if fetch is None else list(CPU_TEMPLATE_FETCH),
        fetch_roles=None if fetch_roles is None else [
            [role, *fetch_roles[role][:2]] for role in sorted(fetch_roles)],
        fetch_signals=None if fetch_roles is None else {
            role: fetch_roles[role][2] for role in sorted(fetch_roles)},
        boot_contract=deepcopy(boot),
        source_sha256=_digest(artifact.source_verification),
        profile_fingerprint=artifact.plan.profile.profile_fingerprint,
        artifact_sha256=document['artifact_digest'],
        address_width=32, data_width=32, address_units='byte',
        byte_enable_width=roles['wstrb'][1], max_outstanding=1,
        completion_kind=CPU_COMPLETION,
        write_channels=['aw', 'w', 'b'], read_channels=['ar', 'r'],
        instruction_identity='declared_fetch_face_ar_only',
        instruction_retirement='unknown', native_IRQ='unsupported',
        first_fetch_observation='accepted_i_AR_address',
        error_observed=True,
        absent_roles=sorted(CPU_ABSENT_ROLES),
        capability_limits=dict(CPU_CAPABILITY_LIMITS))


@dataclass(frozen=True)
class ReducedAxiCpuAbiFacts:
    endpoint_id: str
    boot_base: int
    address_width: int = 32
    data_width: int = 32
    address_units: str = 'byte'
    protocol: tuple = CPU_PROTOCOL
    template: tuple = CPU_TEMPLATE_DATA

    def document(self):
        from dataclasses import asdict
        return asdict(self)


class ReducedAxiCpuDriver:
    """Describe the admitted CPU; Runner remains the sole execution coordinator."""

    def __init__(self, session, artifact, surface, implementation_pin):
        self._session, self._artifact = session, artifact
        self._surface = canonical_json_bytes(surface)
        self._implementation_pin = implementation_pin
        self._closed = False
        self.facts = ReducedAxiCpuAbiFacts(
            surface['endpoint_id'], surface['boot_contract']['configured_boot_base'])

    def assert_current(self):
        from ..registry import registrations
        _require(not self._closed, 'closed')
        _require(all(sha256((_ROOT / name).read_bytes()).hexdigest() == digest
                     for name, digest in _MODULE_DIGESTS.items()), 'module-source')
        _require(type(self._session) is _CLASS
                 and self._session.artifact is self._artifact, 'session-owner')
        _require(all(name not in vars(self._session)
                     and getattr(_CLASS, name) is method
                     and method.__code__ is code
                     for name, (method, code) in _METHODS.items()),
                 'session-method')
        rows = [row for row in registrations() if row.adapter_id == CPU_ADAPTER_ID]
        _require(len(rows) == 1
                 and rows[0].implementation_sha256() == self._implementation_pin,
                 'implementation')
        _require(canonical_json_bytes(
                     reduced_axi_cpu_surface_document(self._artifact)) == self._surface,
                 'artifact-ABI')

    def program_slots(self):
        """The bound session owns real online instruction slots."""
        self.assert_current()
        return {'instruction.boot': dict(
            kind='online_instruction_slots', boot_base=self.facts.boot_base,
            declare_slots='declare_instruction_slots',
            accept='accept_instructions',
            parked_fetch='waiting_instruction_address',
            parked_fetch_semantics='accepted_AR_then_withheld_R',
            first_fetch_verification='accepted_fetch_face_AR_observation',
            endpoints=[self.facts.endpoint_id, self._surface_fetch_endpoint()],
            instruction_identity='declared_fetch_face_ar_only',
            address_width=32, instr_width=32, address_units='byte',
            supported_flows=['F1', 'F2', 'F3', 'F4'],
            # F1/F3 run through the executor's independent memory flows; it is
            # these three session options that make the real write-commit and
            # read-issuance streams exist at all.
            memory_flow_options=['memory_commit_receipts',
                                 'memory_readback_receipts',
                                 'physical_tick_samples'],
            source='generated_session_declared_slots')}

    def _surface_fetch_endpoint(self):
        import json
        return json.loads(self._surface.decode('utf-8'))['fetch_endpoint_id']

    def local_step_map(self):
        self.assert_current()
        return dict(schema_version='axi4_cpu_local_step_map.v1',
                    max_local_ticks_per_step=self._session.max_local_ticks_per_step,
                    max_transaction_events_per_step=self._session.max_transaction_events_per_step,
                    mmio_service='queued_routed_target_response',
                    defer_mmio=True,
                    pending_responses=self._session.pending_responses,
                    max_mmio_target_accesses_per_step=self._session.max_mmio_target_accesses_per_step,
                    read_byte_enable='zero_transfers_the_whole_addressed_word',
                    error_observation='rresp_and_bresp_reject_any_nonzero_status',
                    address_units='byte', completion_kind=CPU_COMPLETION,
                    channels=dict(fetch=['ar', 'r'], data=['aw', 'w', 'b', 'ar', 'r']))

    def close(self):
        self._closed = True


class BoundReducedAxiCpuAdapter:
    def __init__(self, component, session, selection, surface, implementation_pin):
        self.component_instance_id = component.instance_id
        self.endpoint_id = surface['endpoint_id']
        self.adapter_id = CPU_ADAPTER_ID
        self.adapter_version = CPU_ADAPTER_VERSION
        self.protocol = CPU_PROTOCOL
        self.template = CPU_TEMPLATE_DATA
        self.semantic_kind = CPU_SEMANTIC_KIND
        self.address_units = 'byte'
        self.completion_kind = CPU_COMPLETION
        self.implementation_sha256 = implementation_pin
        self.driver = ReducedAxiCpuDriver(session, artifact=session.artifact,
                                          surface=surface,
                                          implementation_pin=implementation_pin)
        self.abi_facts = self.driver.facts
        self.binding_sha256 = _digest(dict(
            component=component.artifact_sha256,
            semantic=component.semantic_contract_sha256,
            selection=selection.sha256(), session_object=id(session),
            implementation_sha256=implementation_pin))

    @property
    def drives_cpu(self):
        return False

    @property
    def program_slots(self):
        return self.driver.program_slots()

    @property
    def local_step_map(self):
        return self.driver.local_step_map()

    def assert_current(self):
        self.driver.assert_current()

    def close(self):
        self.driver.close()


def bind_reduced_axi_cpu_adapter(*, component, session, selection,
                                 preparation=None, endpoint_id=None):
    from ..registry import registrations
    _require(type(component) is VerifiedComponent
             and type(selection) is AdapterSelection, 'typed-component-selection')
    _require(type(session) is _CLASS,
             'exact-GeneratedVexiiAxiMmioSession-required')
    _require(session.artifact.plan.request.instance_id == component.instance_id,
             'session-class')
    rows = [r for r in registrations() if r.adapter_id == CPU_ADAPTER_ID]
    _require(len(rows) == 1, 'registration')
    pin = rows[0].implementation_sha256()
    _require(selection.adapter_id == CPU_ADAPTER_ID
             and selection.adapter_version == CPU_ADAPTER_VERSION
             and selection.implementation_sha256 == pin
             and selection.component_artifact_sha256 == component.artifact_sha256
             and selection.semantic_contract_sha256
             == component.semantic_contract_sha256, 'selection')
    try:
        surface = reduced_axi_cpu_surface_document(session.artifact)
    except ValueError as error:
        raise GenericRuntimeRefused('generic-binding-drift', '/axi4_cpu',
            {'reason': 'artifact-ABI', 'detail': str(error)[:160]}) from error
    _require(component.artifact_sha256 == surface['artifact_sha256']
             and component.semantic_contract_sha256 == _digest(surface), 'surface')
    endpoints = [e for e in component.endpoints() if e['role'] == 'cpu']
    _require(len(endpoints) == 1, 'one-cpu-endpoint-required')
    endpoint = endpoints[0]
    _require(endpoint['endpoint_id'] == surface['endpoint_id']
             and tuple(endpoint['protocol']) == CPU_PROTOCOL
             and endpoint['semantic_kind'] == CPU_SEMANTIC_KIND
             and tuple(endpoint['template']) == CPU_TEMPLATE_DATA
             and endpoint['address_width'] == 32 and endpoint['data_width'] == 32
             and endpoint['address_units'] == 'byte'
             and endpoint['completion_kind'] == CPU_COMPLETION
             and endpoint['byte_enable'] is True, 'descriptor-ABI')
    if endpoint_id is not None:
        _require(endpoint_id == surface['endpoint_id'], 'declared-endpoint')
    result = BoundReducedAxiCpuAdapter(component, session, selection, surface, pin)
    result.assert_current()
    return result


def verifier_identity():
    """Code-owned identity of the admission verifier for this row."""
    from ..admission import _pin
    return {'id': 'axi4.cpu.admission.v1', 'version': '1',
            'implementation_sha256': _pin(('src/myfuzz/runtime/admission.py',
                                           *_FILES))}
