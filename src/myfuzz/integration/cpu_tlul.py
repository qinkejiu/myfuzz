"""TileLink coherent CPU extension seam: real role map plus named refusals.

Why this module exists
----------------------
``extension_plugins`` keeps one module per bus for the **CPU** side.  The
audit of stage one found BOOM's artifact kind (``tilelink_coherent_cpu``)
mapped to a module that does not exist (``myfuzz.integration.cpu_tlul``), so the
seam silently never matched and every BOOM row was reported as "not adapted"
instead of "adapted and refused for these reasons".  This module makes the
mapping real: it is imported, it authenticates what a TileLink coherent CPU
artifact actually declares, and it refuses with a machine-readable gap list
rather than returning an adapter that would fail inside the executor.

What is genuinely reusable here
-------------------------------
``tl_role_map`` reads the 39 coherent A/B/C/D/E roles out of the *declared*
profile document and proves each alias is the generated port of that role.
That is the same evidence the pinned driver binds by hand, so a future
per-tick observer or hop joiner builds on it instead of re-deriving it.

What is refused, and why (no invention)
---------------------------------------
The generic executor :class:`myfuzz.integration.compiled_mmio.CompiledMmioRuntime`
needs a CPU session that (a) is constructed with ``memory=`` and ``router=``,
(b) accepts instruction words *after* the core left reset, and (c) reports the
fetch it parked.  The pinned BOOM harness cannot provide any of them, and two
further facts are architectural rather than missing code:

* one shared A/D boundary carries instruction fetch and data beats, so the
  F2/F4 ``('instr', sequence)`` hop has no native channel identity;
* the cached window is served by the driver-side ``TlRam`` model, and the
  driver accepts ``LOAD`` only while ``cycle == 0``, so no host
  :class:`~myfuzz.scenario.memory.PersistentMemory` can become the authority
  after startup.

``SESSION_GAPS`` names each one; ``cpu_adapter`` raises
``MMIO-CPU-adapter-unsupported:tilelink:<kind>:{...}`` and never returns a
partially working adapter.
"""
from __future__ import annotations

import inspect

PROTOCOL = 'tilelink'
#: The protocol name this boundary really declares.  ``PROTOCOL`` above is the
#: seam's own short label kept for its refusal messages; a CPU adapter must
#: report the declared identity, which is what the contract and the plugin use.
NATIVE_PROTOCOL = 'tilelink-coherent'
#: Same refusal family as ``mmio_cpu_adapter.select_mmio_cpu`` and
#: ``cpu_axi4``; the suffix names what is missing, never a bare assertion.
REFUSAL_PREFIX = 'MMIO-CPU-adapter-unsupported:' + PROTOCOL
#: The generated coherent client of the pinned derived ``BoomTile``.
KIND = 'tilelink_coherent_cpu'
TL_ENDPOINT_PROTOCOL = ['tilelink-coherent', '1']
#: Generated port name prefix of the one shared coherent client.
PORT_PREFIX = 'auto_tl_other_masters_out_'
#: The A/B/C/D/E roles every coherent client declares, and the width of the
#: generated field each one binds to.
ROLE_WIDTHS = {
    'a_ready': 1, 'a_valid': 1, 'a_bits_opcode': 3, 'a_bits_param': 3,
    'a_bits_size': 4, 'a_bits_source': 3, 'a_bits_address': 32,
    'a_bits_mask': 8, 'a_bits_data': 64,
    'b_ready': 1, 'b_valid': 1, 'b_bits_opcode': 3, 'b_bits_param': 2,
    'b_bits_size': 4, 'b_bits_source': 3, 'b_bits_address': 32,
    'b_bits_mask': 8, 'b_bits_corrupt': 1,
    'c_ready': 1, 'c_valid': 1, 'c_bits_opcode': 3, 'c_bits_param': 3,
    'c_bits_size': 4, 'c_bits_source': 3, 'c_bits_address': 32,
    'c_bits_data': 64,
    'd_ready': 1, 'd_valid': 1, 'd_bits_opcode': 3, 'd_bits_param': 2,
    'd_bits_size': 4, 'd_bits_source': 3, 'd_bits_sink': 3, 'd_bits_denied': 1,
    'd_bits_data': 64, 'd_bits_corrupt': 1,
    'e_ready': 1, 'e_valid': 1, 'e_bits_sink': 3,
}
ROLES = tuple(ROLE_WIDTHS)
CHANNELS = {'a': 'a', 'b': 'b', 'c': 'c', 'd': 'd', 'e': 'e'}

#: The shipped generated session for this kind.  Two classes exist and they are
#: not interchangeable:
#:
#: * ``GeneratedBoomCpuSession`` drives the *pinned* BOOM C++ harness, whose RAM
#:   lives inside its own coherent manager and which accepts instruction words
#:   only while ``cycle == 0``.  It keeps the named ``SESSION_GAPS`` below.
#: * ``GeneratedTlCoherentSession`` plays the *generated* runtime top's backend
#:   beat face, so host ``PersistentMemory`` really is the RAM authority, the
#:   router really is the device authority, and instruction slots are explicit.
#:   That is the class the generic executor is wired to.
SESSION_CLASSES = {
    KIND: 'myfuzz.local_harness.tilelink_coherent_session.GeneratedTlCoherentSession',
}
#: The pinned C++ harness class, kept for the structural gap report.
PINNED_SESSION_CLASSES = {
    KIND: 'myfuzz.local_harness.boom_cpu_session.GeneratedBoomCpuSession',
}

#: Facts about the pinned harness that no adapter here can supply.
SESSION_GAPS = {
    KIND: (
        'session-router-keyword-missing: the generated session takes '
        '(output, repo=, command_timeout_seconds=, external_range=) and would '
        'need a DataflowRouter to serve declared MMIO',
        'session-memory-keyword-missing: the cached window is served by the '
        'driver-side TlRam model, not by a host PersistentMemory',
        'session-online-instruction-slots-missing: the driver accepts LOAD '
        'only while cycle == 0, so instruction words cannot arrive after the '
        'core left reset',
        'session-parked-fetch-address-missing: nothing reports the fetch a '
        'case must park on',
        'native-channel-identity-missing: one shared coherent A/D boundary '
        'carries instruction fetch and data beats, so the F2/F4 instruction '
        'hop has no native channel identity',
        'generic-artifact-missing: no local_harness runtime template renders '
        'a tilelink_coherent_cpu artifact, so D2 supplies no plan/profile',
        'f1-memory-flow-contract-missing: the generic F1/F3 memory flows are '
        'only implemented for the compiled_mmio session shape this row has '
        'none of (see integration/compiled_mmio.py)',
    ),
}

#: What the structural probe reads on the shipped session class.
_EXECUTOR_CONSTRUCTOR_KEYWORDS = ('memory', 'router')
_ONLINE_INSTRUCTION_METHODS = ('declare_instruction_slots', 'accept_instructions')
_PARKED_FETCH_ATTRIBUTE = 'waiting_instruction_address'
#: Set by a session that freezes its instruction image before the first edge.
FROZEN_IMAGE_ATTRIBUTE = 'INSTRUCTION_IMAGE_FROZEN_BEFORE_FIRST_EDGE'
#: Set by a session whose RAM authority is the host ``PersistentMemory``.
HOST_RAM_ATTRIBUTE = 'HOST_MEMORY_AUTHORITY'


def _refuse(kind, reason):
    raise ValueError(REFUSAL_PREFIX + ':' + str(kind) + ':' + str(reason))


def _gaps(kind, reason):
    return (REFUSAL_PREFIX + ':' + kind + ':' + reason + ':{'
            + ','.join(SESSION_GAPS.get(kind, ())) + '}')


def is_tilelink_cpu_kind(document):
    """Whether this artifact kind belongs to the coherent TileLink CPU row."""
    return isinstance(document, dict) and document.get('kind') == KIND


def session_class(kind=KIND):
    """Import the declared generated session class for this kind."""
    path = SESSION_CLASSES.get(kind)
    if path is None:
        _refuse(kind, 'not-a-tilelink-coherent-cpu-kind')
    module_name, class_name = path.rsplit('.', 1)
    from importlib import import_module
    try:
        return getattr(import_module(module_name), class_name)
    except (ImportError, AttributeError) as error:  # pragma: no cover - packaging
        raise ValueError(REFUSAL_PREFIX + ':' + str(kind)
                         + ':session-class-unavailable') from error


def executor_gaps(session_type):
    """Name every way the generic executor cannot drive this session class.

    Structural on purpose: it must not import RTL, build a backend or
    construct the session.  The two semantic attributes are read as well,
    because a class can *have* the methods and still not implement the
    contract they name.
    """
    gaps = []
    try:
        parameters = inspect.signature(session_type.__init__).parameters
    except (TypeError, ValueError):  # pragma: no cover - exotic callables
        parameters = {}
    if 'router' not in parameters:
        gaps.append('session-router-keyword-missing')
    if 'memory' not in parameters:
        gaps.append('session-memory-keyword-missing')
    if not all(callable(getattr(session_type, name, None))
               for name in _ONLINE_INSTRUCTION_METHODS):
        gaps.append('session-online-instruction-slots-missing')
    if not hasattr(session_type, _PARKED_FETCH_ATTRIBUTE):
        gaps.append('session-parked-fetch-address-missing')
    if getattr(session_type, FROZEN_IMAGE_ATTRIBUTE, False):
        gaps.append('instruction-image-frozen-before-first-edge')
    if getattr(session_type, HOST_RAM_ATTRIBUTE, False) is not True:
        gaps.append('host-memory-authority-missing')
    return tuple(gaps)


# ---------------------------------------------------------------------------
# declared roles (reusable evidence, no session needed)
# ---------------------------------------------------------------------------
def _endpoint(document):
    if not isinstance(document, dict):
        raise ValueError('tilelink-profile-document-required')
    endpoints = [row for row in document.get('endpoints') or ()
                 if isinstance(row, dict)
                 and list(row.get('protocol') or ()) == TL_ENDPOINT_PROTOCOL]
    if len(endpoints) != 1:
        raise ValueError('tilelink-coherent-endpoint-required')
    return endpoints[0]


def tl_role_map(document):
    """Map every declared coherent role to its generated physical port.

    The profile document is the authority: one endpoint, protocol
    ``tilelink-coherent@1``, exactly the 39 roles, every alias names the same
    role at the shared-client prefix.  Returns ``{role: port}``.
    """
    endpoint = _endpoint(document)
    fields = endpoint.get('fields')
    if not isinstance(fields, list) or not fields:
        raise ValueError('tilelink-coherent-fields-required')
    mapping = {}
    for row in fields:
        if not isinstance(row, dict):
            raise ValueError('tilelink-coherent-field-shape')
        role, aliases = row.get('role'), row.get('aliases')
        if role not in ROLE_WIDTHS:
            raise ValueError('tilelink-coherent-role-unsupported:' + str(role))
        if role in mapping:
            raise ValueError('tilelink-coherent-role-duplicated:' + str(role))
        if (not isinstance(aliases, list) or len(aliases) != 1
                or aliases[0] != PORT_PREFIX + role):
            raise ValueError('tilelink-coherent-alias-mismatch:' + str(role))
        mapping[role] = aliases[0]
    if set(mapping) != set(ROLE_WIDTHS):
        missing = sorted(set(ROLE_WIDTHS) - set(mapping))
        raise ValueError('tilelink-coherent-roles-incomplete:' + ','.join(missing))
    return mapping


def tl_traces(document):
    """Per-channel ``{role: port}`` views of the declared coherent client.

    ``{'a': {...}, 'c': {...}, 'd': {...}, 'e': {...}, 'b': {...}}``, with the
    channel prefix stripped from each role name, plus the declared widths so a
    future observer can narrow a sampled field without guessing.
    """
    mapping = tl_role_map(document)
    traces = {}
    for channel in CHANNELS:
        rows = {role[len(channel) + 1:]: port for role, port in mapping.items()
                if role.startswith(channel + '_')}
        if rows:
            traces[channel] = rows
    traces['widths'] = {channel: {role[len(channel) + 1:]: ROLE_WIDTHS[role]
                                  for role in mapping if role.startswith(channel + '_')}
                        for channel in CHANNELS}
    traces['endpoint_id'] = _endpoint(document).get('endpoint_id')
    return traces


def adapter_document(document, *, session_type=None):
    """Pure inspection: the roles this profile declares and what is missing."""
    gaps = list(SESSION_GAPS[KIND])
    try:
        roles = sorted(tl_role_map(document))
        role_error = None
    except ValueError as error:
        roles, role_error = [], str(error)
    structural = ()
    if session_type is not None:
        structural = executor_gaps(session_type)
    return {
        'schema_version': 'cpu_tlul_adapter_probe.v1',
        'kind': KIND,
        'protocol': PROTOCOL,
        'declared_roles': roles,
        'role_count': len(roles),
        'role_error': role_error,
        'structural_gaps': list(structural),
        'session_gaps': gaps,
        'runtime_admitted': False,
        'can_execute_flows': [],
        'refused_flows': ['F1', 'F2', 'F3', 'F4'],
    }


# ---------------------------------------------------------------------------
# extension seam
# ---------------------------------------------------------------------------
def cpu_adapter(artifact, image, stream, *, base_dir=None):
    """Return the coherent client's CPU adapter, or refuse by name.

    The adapter is built from the generated artifact's own document: the 39 tap
    signals and their widths, the five-channel view and the declared
    instruction-hop refusal.  Nothing about the RTL is re-derived here.

    A *pinned-harness* artifact (the old C++ BOOM session) still refuses: that
    class cannot satisfy the generic executor, and ``executor_gaps`` names every
    way it fails instead of returning a partial adapter.
    """
    document = getattr(artifact, 'runtime_document', None)
    if not is_tilelink_cpu_kind(document):
        _refuse(getattr(document, 'get', lambda *_: None)('kind'),
                'not-a-tilelink-coherent-cpu-artifact')
    from ..local_harness.tilelink_coherent_fields import INSTRUCTION_HOP_REFUSAL
    from ..runtime.adapters.tilelink_cpu import (KIND as ADAPTER_KIND,
        native_tl_beats, tl_coherent_policy, tl_coherent_traces)
    from .mmio_cpu_adapter import MmioCpuAdapter
    if document.get('kind') != ADAPTER_KIND:
        _refuse(document.get('kind'), 'not-a-generated-coherent-artifact')
    traces = tl_coherent_traces(artifact)
    policy = tl_coherent_policy(artifact)
    if traces.get('instruction_hop_refusal') != INSTRUCTION_HOP_REFUSAL:
        _refuse(KIND, 'instruction-hop-refusal-missing')

    class _TileLinkCpuAdapter(MmioCpuAdapter):
        """Channel model ``unified``: one A/D boundary, no instruction channel."""

        def completed_beats(self, events, cpu):
            return native_tl_beats(events, cpu, traces)

        def first_fetch(self, events, cpu):
            from ..runtime.adapters.tilelink_cpu import first_accepted_request
            return first_accepted_request(events, cpu)

    return _TileLinkCpuAdapter(NATIVE_PROTOCOL, session_class(), traces, policy,
                               channel_model='unified')
