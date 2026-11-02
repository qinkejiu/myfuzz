"""CPU-side adapter facts for the TileLink coherent client (A/B/C/D/E).

The generated runtime top already publishes, in its own artifact document, the
per-role tap names, their widths, the five-channel view and the declared refusal
of an instruction-only hop.  This module reads those facts; it derives nothing
about the RTL and it never renames a channel.

Two honesty rules are encoded here:

* the instruction hop is refused *by name*.  One shared A/D boundary carries
  instruction fetches and data beats, so a fetch has no native channel identity;
  ``INSTRUCTION_HOP_REFUSAL`` quotes that with file:line, and the hop checkers
  consume it instead of claiming an instruction hop.
* the client is a single-outstanding ready/valid master: one A message is in
  flight at a time, so every completed beat is keyed by its own measured
  sequence, never by an assumed pipeline depth.
"""
from __future__ import annotations

from myfuzz.local_harness.tilelink_coherent_fields import INSTRUCTION_HOP_REFUSAL
from myfuzz.runtime.registry import TL_COHERENT_CPU_ADAPTER_ID

PROTOCOL = 'tilelink-coherent'
KIND = 'tilelink_coherent_cpu'
TRACE_PROTOCOL = 'tilelink-coherent'
#: Beat channels this adapter consumes.  ``data`` is the coherent A/D boundary;
#: there is deliberately no ``instr`` channel (see the refusal above).
DATA_CHANNEL = 'data'


def tl_coherent_traces(artifact):
    """The declared tap map, widths, channel view and the hop refusal."""
    document = artifact.runtime_document
    if document.get('kind') != KIND:
        raise ValueError('tilelink-coherent-traces-kind')
    traces = (document.get('base_protocol_traces') or {}).get('traces')
    if not isinstance(traces, list) or len(traces) != 1:
        raise ValueError('tilelink-coherent-traces-required')
    trace = traces[0]
    if trace.get('protocol') != TRACE_PROTOCOL:
        raise ValueError('tilelink-coherent-trace-protocol')
    signals = trace.get('signals')
    widths = trace.get('signal_widths')
    if not isinstance(signals, dict) or not isinstance(widths, dict) or not signals:
        raise ValueError('tilelink-coherent-trace-signals')
    for role in ('a_valid', 'a_ready', 'a_bits_address', 'a_bits_size',
                 'a_bits_mask', 'd_valid', 'd_ready', 'd_bits_data'):
        if role not in signals:
            raise ValueError('tilelink-coherent-trace-missing:' + role)
    channels = trace.get('channels')
    if not isinstance(channels, dict) or set(channels) != set('abcde'):
        raise ValueError('tilelink-coherent-trace-channels')
    refusal = trace.get('instruction_hop_refusal')
    if refusal != INSTRUCTION_HOP_REFUSAL:
        raise ValueError('tilelink-coherent-trace-refusal')
    return {
        'schema_version': 'cpu_native_traces.v1',
        'protocol': TRACE_PROTOCOL,
        'endpoint_id': trace.get('endpoint_id'),
        'signals': dict(signals),
        'signal_widths': dict(widths),
        'channels': channels,
        'data_channel': DATA_CHANNEL,
        'channel_model': 'unified',
        'instruction_hop_refusal': refusal,
    }


def tl_coherent_policy(artifact):
    """Declared error behaviour: the denial bit is observed, never fabricated."""
    kind = artifact.runtime_document.get('kind')
    if kind != KIND:
        raise ValueError('tilelink-coherent-policy-kind')
    return {'error_response': True,
            'denial_signal': 'd_bits_denied',
            'fault_signal': 'm_fault',
            'backend_error_policy': 'terminate_without_completion'}


def native_tl_beats(events, cpu, traces):
    """Pair measured A acceptances with measured D completions, in order.

    Only events the session itself recorded are consumed: an acceptance carries
    the request (address/write/size/mask) and a completion the response data.
    A completion without an acceptance, or two acceptances without a completion,
    is a protocol error rather than a guessed pairing.
    """
    pending = []
    completed = {}
    sequence = 0
    for event in events:
        if event.get('component') != cpu:
            continue
        kind = event.get('kind')
        if kind == 'tilelink_a_accept':
            pending.append(event)
        elif kind == 'tilelink_d_complete':
            if not pending:
                raise ValueError('tilelink-completion-without-acceptance')
            acceptance = pending.pop(0)
            sequence += 1
            # Write-ness comes from the declared A opcode: 0/1 are
            # PutFullData/PutPartialData, 4/6/7 are Get/Acquire*, which are
            # reads.  An explicit flag, when a caller supplies one, wins.
            opcode = acceptance.get('opcode')
            write = (bool(acceptance['write']) if 'write' in acceptance
                     else opcode in (0, 1))
            completed[(DATA_CHANNEL, sequence)] = dict(
                acceptance_event=acceptance['event_id'],
                response_event=event['event_id'],
                address=acceptance['address'],
                write=write,
                opcode=acceptance.get('opcode'),
                size=acceptance.get('size'),
                byte_enable=int(acceptance.get('mask', 0xff)),
                value=int(acceptance.get('data', 0)),
                rdata=int(event.get('value', 0)),
            )
    if pending:
        raise ValueError('tilelink-acceptance-without-completion')
    return completed


def first_accepted_request(events, cpu):
    """(event_id, address) of every accepted A request, in measured order."""
    return [(event['event_id'], int(event['address'])) for event in events
            if event.get('kind') == 'tilelink_a_accept' and event.get('component') == cpu]


# ---------------------------------------------------------------------------
# Admission surface and binding factory
# ---------------------------------------------------------------------------
TL_CPU_PROTOCOL = ('tilelink-coherent', '1')
TL_CPU_TEMPLATE = ('cpu.tilelink-coherent', '1',
                   'coherent-ab-cd-e-single-outstanding')
TL_CPU_SEMANTIC_KIND = 'cpu.tilelink-coherent.v1'
TL_CPU_COMPLETION = 'independent_channels_response'
TL_CPU_IMPLEMENTATION_FILES = (
    'src/myfuzz/runtime/adapters/tilelink_cpu.py',
    'src/myfuzz/integration/cpu_tlul.py',
    'src/myfuzz/local_harness/tilelink_coherent_session.py',
    'src/myfuzz/local_harness/tilelink_coherent_fields.py',
    'src/myfuzz/local_harness/session.py',
)


def _digest(document):
    from hashlib import sha256
    from myfuzz.runtime.contracts import canonical_json_bytes
    return sha256(canonical_json_bytes(document)).hexdigest()


def tl_coherent_cpu_surface_document(artifact):
    """The admitted execution surface of one generated coherent client.

    Only declared facts are copied: the artifact's own tap map, the profile's
    declared widths, the configured boot base and the endpoint's real role
    shapes.  ``max_outstanding`` records the *harness's* accepted depth (one)
    next to the profile's declared issue depth, because those are two different
    facts and the tolerance for the difference is a contract limit
    (``master_backpressure_tolerated``), not an assumption.
    """
    document = artifact.runtime_document
    if document.get('kind') != KIND:
        raise ValueError('tilelink coherent artifact required')
    traces = tl_coherent_traces(artifact)
    endpoint_id = traces['endpoint_id']
    rows = [row for row in artifact.plan.binding.endpoints
            if row.endpoint_id == endpoint_id]
    if len(rows) != 1 or tuple(rows[0].protocol) != TL_CPU_PROTOCOL:
        raise ValueError('tilelink coherent endpoint required')
    if len(rows[0].fields) != 39:
        raise ValueError('tilelink coherent 39-role endpoint required')
    boot = document.get('boot_contract') or {}
    base = boot.get('configured_boot_base')
    if type(base) is not int or not 0 <= base < 1 << 32 or base % 4:
        raise ValueError('tilelink coherent configured boot base required')
    capabilities = artifact.plan.profile.capabilities
    if (capabilities.get('data_width'), capabilities.get('address_width'),
            capabilities.get('byte_enable'), capabilities.get('error_response')) != (
            64, 32, True, True):
        raise ValueError('tilelink coherent declared widths/capabilities changed')
    issue_depth = capabilities.get('max_outstanding')
    if type(issue_depth) is not int or issue_depth < 1:
        raise ValueError('tilelink coherent declared issue depth required')
    return {
        'schema_version': 'tilelink_coherent_cpu_execution_surface.v1',
        'kind': TL_CPU_SEMANTIC_KIND,
        'instance_id': artifact.plan.request.instance_id,
        'endpoint_id': endpoint_id,
        'protocol': list(TL_CPU_PROTOCOL),
        'template': list(TL_CPU_TEMPLATE),
        'roles': {field.role: [field.direction, field.width]
                  for field in rows[0].fields},
        'signals': dict(traces['signals']),
        'signal_widths': dict(traces['signal_widths']),
        'channels': traces['channels'],
        'instruction_hop_refusal': traces['instruction_hop_refusal'],
        'boot_contract': dict(boot),
        'source_sha256': _digest(artifact.source_verification),
        'profile_fingerprint': artifact.plan.profile.profile_fingerprint,
        'artifact_sha256': document['artifact_digest'],
        'data_width': 64,
        'address_width': 32,
        'address_units': 'byte',
        'byte_enable_width': 8,
        'max_outstanding': 1,
        'declared_master_outstanding': issue_depth,
        'completion_kind': TL_CPU_COMPLETION,
        'instruction_identity': 'unsupported_single_shared_a_d_boundary',
        'instruction_retirement': 'unknown',
        'native_IRQ': 'unsupported',
    }


class BoundTlCoherentCpuAdapter:
    """The admitted coherent CPU as the coordinator sees it.

    The driver surface is deliberately small: the coordinator owns pacing, and
    this object only publishes the identities it was bound with plus the ABI
    facts the runtime path already declared.  ``assert_current`` re-renders the
    surface and refuses if the session's artifact changed underneath the
    binding, so a stale handle can never step the harness.
    """

    def __init__(self, component, session, selection, surface, pin):
        self.component_instance_id = component.instance_id
        self.endpoint_id = surface['endpoint_id']
        self.adapter_id = TL_COHERENT_CPU_ADAPTER_ID
        self.adapter_version = '1'
        self.protocol = TL_CPU_PROTOCOL
        self.template = TL_CPU_TEMPLATE
        self.semantic_kind = TL_CPU_SEMANTIC_KIND
        self.address_units = 'byte'
        self.data_width = surface['data_width']
        self.address_width = surface['address_width']
        self.implementation_sha256 = pin
        self.component_artifact_sha256 = component.artifact_sha256
        self.semantic_contract_sha256 = component.semantic_contract_sha256
        self.abi_facts = {key: surface[key] for key in (
            'endpoint_id', 'protocol', 'template', 'data_width', 'address_width',
            'address_units', 'byte_enable_width', 'max_outstanding',
            'completion_kind', 'boot_contract', 'instruction_hop_refusal')}
        self.surface_sha256 = _digest(surface)
        self.binding_sha256 = _digest(dict(
            component=component.artifact_sha256,
            semantic=component.semantic_contract_sha256,
            selection=selection.sha256(), session_object=id(session),
            implementation_sha256=pin))
        self._component = component
        self._session = session
        self._selection = selection

    def assert_current(self):
        surface = tl_coherent_cpu_surface_document(self._session.artifact)
        document_digest = self._session.artifact.runtime_document.get('artifact_digest')
        if (_digest(surface) != self.surface_sha256
                or document_digest != self._component.artifact_sha256):
            raise ValueError('tilelink coherent adapter binding drifted')

    def close(self):
        self._session = None


def bind_tl_coherent_cpu_adapter(*, component, session, selection, preparation,
                                 endpoint_id=None):
    """Bind the admitted coherent CPU to its real session; refuse drift."""
    from myfuzz.runtime.contracts import (AdapterSelection, GenericRuntimeRefused,
                                          VerifiedComponent)
    from myfuzz.runtime.registry import (TL_COHERENT_CPU_ADAPTER_ID,
                                         registrations)

    def _require(value, reason):
        if not value:
            raise GenericRuntimeRefused('generic-binding-drift', '/adapter',
                                        {'adapter_id':
                                         TL_COHERENT_CPU_ADAPTER_ID,
                                         'reason': reason})
    _require(type(component) is VerifiedComponent
             and type(selection) is AdapterSelection, 'typed-component-selection')
    _require(session.artifact.plan.request.instance_id == component.instance_id,
             'session-instance')
    rows = [row for row in registrations()
            if row.adapter_id == TL_COHERENT_CPU_ADAPTER_ID]
    _require(len(rows) == 1, 'registration')
    pin = rows[0].implementation_sha256()
    _require(selection.adapter_id == TL_COHERENT_CPU_ADAPTER_ID
             and selection.adapter_version == '1'
             and selection.implementation_sha256 == pin
             and selection.component_artifact_sha256 == component.artifact_sha256
             and selection.semantic_contract_sha256
             == component.semantic_contract_sha256, 'selection')
    surface = tl_coherent_cpu_surface_document(session.artifact)
    _require(component.artifact_sha256 == surface['artifact_sha256']
             and component.semantic_contract_sha256 == _digest(surface), 'surface')
    endpoints = [row for row in component.endpoints() if row['role'] == 'cpu']
    _require(len(endpoints) == 1
             and endpoints[0]['endpoint_id'] == surface['endpoint_id']
             and tuple(endpoints[0]['protocol']) == TL_CPU_PROTOCOL
             and endpoints[0]['semantic_kind'] == TL_CPU_SEMANTIC_KIND
             and tuple(endpoints[0]['template']) == TL_CPU_TEMPLATE
             and endpoints[0]['data_width'] == 64
             and endpoints[0]['address_width'] == 32
             and endpoints[0]['address_units'] == 'byte', 'descriptor-ABI')
    _require(endpoint_id is None or endpoint_id == surface['endpoint_id'],
             'declared-endpoint')
    bound = BoundTlCoherentCpuAdapter(component, session, selection, surface, pin)
    bound.assert_current()
    return bound
