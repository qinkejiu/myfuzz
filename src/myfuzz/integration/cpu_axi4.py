"""Full AXI4 (not Lite) CPU rows for the protocol-neutral F1-F4 executor.

This module is the extension seam named by
``integration/extension_plugins._CPU_MODULES`` for the four artifact kinds
``reduced_dual_axi_cpu``, ``reduced_dual_axi_irq_cpu``, ``axi4_cpu`` and
``cva6_packed_axi4_cpu``.  It does three separate things, and never mixes
them up:

1. **Native trace mapping.**  ``traces`` is built from the artifact's own
   ``backend_ports`` rows (role/direction/width/name) and cross-checked
   against the generated session's declared ABI shape.  Every AXI4 role is
   named by its real per-tick sample key (``i_arvalid``, ``d_awaddr``, ...),
   never by a reconstructed guess: there is no ``protocol_taps`` group on a
   full AXI4 CPU row, so the session's own ``driver_samples`` pre/post
   ``backend`` rows are the only physical evidence that exists.

2. **Passive native reading.**  ``first_fetch`` / ``completed_beats`` replay
   the generated session's saved per-tick samples through that session's own
   authenticated observer.  For the reduced dual AXI row that observer is
   ``scenario.reduced_axi_events.ReducedAxiObserver`` -- the exact parser the
   live session already runs -- so address/id/LAST/response-status/hold and
   single-outstanding checks are the session's, not a second opinion.
   Reconstructed transactions carry the real journal ``event_id`` of the
   accepting and completing samples, so the existing F2/F3/F4 joins keep
   working unchanged.  Nothing is issued, materialized or inferred here.

3. **A named executor gate.**  An adapter can only be selected when the
   session class the executor would really construct is *actually
   constructible and drivable* by the generic executor
   (``compiled_mmio.MmioRuntime``): ``memory=`` plus a real ``router=``
   keyword, the online instruction-slot interface
   (``declare_instruction_slots`` / ``accept_instructions``) and the parked
   fetch property ``waiting_instruction_address`` used to end a case at the
   next unmaterialized slot, and no mandatory external step input.  A row
   that fails any of these is refused by name here, with the missing pieces
   in ``AXI4_KIND_GAPS``, instead of being advertised as supported and then
   failing inside the executor.  ``cpu_adapter`` is therefore allowed to
   answer ``None`` / raise the repository's existing
   ``MMIO-CPU-adapter-unsupported`` refusal: that is the truthful answer.

4. **One shipped wrapper row.**  ``reduced_dual_axi_cpu`` (VexiiRiscv) has the
   pieces the shared generated session lacked -- the ``router=`` keyword, the
   online instruction slots and the parked fetch address -- in
   ``local_harness.vexii_axi_mmio_session``, a subclass that adds only those
   three (see ``SESSION_WRAPPERS``).  That row is therefore *admitted*: the
   adapter's ``session_type`` is the wrapper, ``protocol`` is ``axi4`` and
   ``channel_model`` is ``split`` (separate fetch and data request channels
   with their own sequence counters, which is how the session numbers its
   transactions).  The other three kinds keep their named refusal and their
   own gap list, because no wrapper here can supply what they miss.

Scope: observation only.  No retirement, IRQ, storage-version, F5/F6 or
search authority is created, and no AXI4 CPU row is claimed to have run: an
admitted row is only *drivable*, never *proven*.
"""
from __future__ import annotations

import inspect
from dataclasses import dataclass

from .mmio_cpu_adapter import MmioCpuAdapter

PROTOCOL = 'axi4'
#: Same refusal family as ``mmio_cpu_adapter.select_mmio_cpu`` and
#: ``axil_cpu_protocol_observations``; the suffix names what is missing.
REFUSAL_PREFIX = 'MMIO-CPU-adapter-unsupported:' + PROTOCOL
TRACE_SCHEMA = 'cpu_axi4_native_traces.v1'
READ_TRANSFER = {
    'granularity': 'whole_addressed_word',
    'sampled_read_strobe': 0,
    'basis': ('AXI4 has no read strobe: the beat records the sampled WSTRB '
              'unchanged (0 on a read) and the routed request presents the '
              'declared whole-word access at the router boundary'),
}
#: Every artifact kind this seam owns, mapped to the generated session class
#: that would have to drive it.  Imported lazily so that an absent Verilator
#: toolchain never breaks ``import myfuzz.integration.cpu_axi4``.
SESSION_CLASSES = {
    'reduced_dual_axi_cpu':
        'myfuzz.local_harness.vexii_axi_session.GeneratedReducedAxiCpuSession',
    'reduced_dual_axi_irq_cpu':
        'myfuzz.local_harness.vexii_axi_session.GeneratedReducedAxiIrqCpuSession',
    'axi4_cpu':
        'myfuzz.local_harness.axi4_cpu_session.GeneratedAxi4CpuSession',
    'cva6_packed_axi4_cpu':
        'myfuzz.local_harness.cva6_axi4_session.GeneratedCva6Axi4Session',
}
#: Artifact kind -> the shipped session *subclass* that adds exactly the pieces
#: the generic executor needs and that the generated session itself does not
#: have.  A row listed here is admitted; a row that is not listed keeps its
#: named refusal and its own entry in ``AXI4_KIND_GAPS``.
SESSION_WRAPPERS = {
    # The wrapper takes ``router=`` (and ``mmio_router=``), declares online
    # instruction slots, parks a fetch whose declared word does not exist yet
    # and reports that address through ``waiting_instruction_address``.
    'reduced_dual_axi_cpu':
        'myfuzz.local_harness.vexii_axi_mmio_session.GeneratedVexiiAxiMmioSession',
    # The packed CVA6 wrapper takes ``router=``, declares online instruction
    # slots, parks the accepted read whose 8-byte beat is not materialized yet
    # and reports that address through ``waiting_instruction_address``.  It
    # numbers one request channel (``memory``) because the port has no
    # instruction attribute, and it carries the data-only F2/F4 evidence.
    'cva6_packed_axi4_cpu':
        'myfuzz.local_harness.cva6_axi_mmio_session.GeneratedCva6AxiMmioSession',
}
#: Shape-level gaps: facts about the SHIPPED session that no adapter here can
#: supply.  A kind in ``SESSION_WRAPPERS`` has no entry, because a subclass
#: supplies them; the remaining rows each name what is still missing.
AXI4_KIND_GAPS = {
    'reduced_dual_axi_irq_cpu': (
        'session-requires-external-step-inputs: every step needs an irq bit '
        'the generic F1-F4 driver never supplies',
        'session-router-keyword-missing: the IRQ subclass re-declares only '
        '**kwargs, so neither memory= nor router= is visible to this gate '
        '(its parent names the same object mmio_router=)',
        'session-online-instruction-slots-missing',
        'session-parked-fetch-address-missing',
    ),
    'axi4_cpu': (
        'native-observer-missing: the session keeps no authenticated per-tick '
        'AXI4 observation, so no existing parser can be reused',
        'session-router-keyword-missing: no router/deferred MMIO at all',
        'session-online-instruction-slots-missing',
        'session-parked-fetch-address-missing',
    ),
    'cva6_packed_axi4_cpu': (
        # Admitted with a *declared* scope, not a silent one: the wrapper in
        # ``SESSION_WRAPPERS`` supplies the router keyword, the online slots and
        # the parked read.  The identity the RTL does not drive is named here.
        'native-instruction-user-attribute-absent: core/axi_shim.sv:263,101 tie '
        'every address-channel user bit to zero and core/axi_shim.sv:258 ties '
        "ar.prot to 3'b0, so nothing on this port names a fetch except the read "
        'ID that core/cache_subsystem/wt_axi_adapter.sv:159 stamps from the '
        'arbiter index and :597,638 decode again on the return path; the fetch '
        'hop is only certified when integration/cva6_axi_mmio.py re-reads those '
        'anchors and declares instruction_id_map, and the row stays data-only '
        'otherwise',
        'native-fetch-beat-is-8-bytes: core/cache_subsystem/'
        'cva6_icache_axi_wrapper.sv:86-87 issues one 8-byte non-cacheable beat '
        'per fetched word, reported as the 8-byte granule it was (two 32-bit '
        'words) and never restated as a 4-byte word read',
    ),
}
#: What the probe below checks on the shipped session class.
_EXECUTOR_CONSTRUCTOR_KEYWORDS = ('memory', 'router')
_ONLINE_INSTRUCTION_METHODS = ('declare_instruction_slots', 'accept_instructions')
_PARKED_FETCH_ATTRIBUTE = 'waiting_instruction_address'
_RESET_KINDS = frozenset({'reset_barrier', 'cpu_reset'})


def _refuse(kind, reason):
    """The one named refusal of this row; never a bare assertion."""
    raise ValueError(REFUSAL_PREFIX + ':' + str(kind) + ':' + str(reason))


def _gaps(kind, reason):
    return REFUSAL_PREFIX + ':' + kind + ':' + reason + ':{' + ','.join(
        AXI4_KIND_GAPS.get(kind, ())) + '}'


def is_axi4_cpu_kind(document):
    """Whether this artifact kind belongs to the full AXI4 CPU rows here."""
    return isinstance(document, dict) and document.get('kind') in SESSION_CLASSES


def session_class(kind):
    """Import the declared generated session class for one AXI4 CPU kind."""
    return _import_session_class(kind, SESSION_CLASSES, 'session-class-unavailable')


def executor_session_class(kind):
    """The class the generic executor would really construct for this kind.

    That is the shipped wrapper in ``SESSION_WRAPPERS`` when one exists (the
    wrapper adds the executor keywords and the online fetch surface), and the
    shipped generated class otherwise -- the same class the named refusal then
    reports gaps for.
    """
    if kind in SESSION_WRAPPERS:
        return _import_session_class(kind, SESSION_WRAPPERS,
                                     'executor-wrapper-unavailable')
    return session_class(kind)


def _import_session_class(kind, table, reason):
    path = table.get(kind)
    if path is None:
        _refuse(kind, 'not-a-full-axi4-cpu-kind')
    module_name, class_name = path.rsplit('.', 1)
    from importlib import import_module
    try:
        return getattr(import_module(module_name), class_name)
    except (ImportError, AttributeError) as error:  # pragma: no cover - packaging
        raise ValueError(REFUSAL_PREFIX + ':' + str(kind) + ':' + reason) from error


def executor_gaps(session_type, *, requires_step_inputs=False):
    """Name every way the generic executor cannot drive this session class.

    The check is structural on purpose: it must not import RTL, build a
    backend or construct the session.  A missing ``router=`` keyword is read
    from the real ``__init__`` signature; the online instruction-slot methods
    and the parked fetch property are read from the class object.
    """
    gaps = []
    try:
        parameters = inspect.signature(session_type.__init__).parameters
    except (TypeError, ValueError):  # pragma: no cover - exotic callables
        parameters = {}
    missing = [name for name in _EXECUTOR_CONSTRUCTOR_KEYWORDS if name not in parameters]
    if 'router' in missing:
        gaps.append('session-router-keyword-missing')
    if 'memory' in missing:
        gaps.append('session-memory-keyword-missing')
    if not all(callable(getattr(session_type, name, None))
               for name in _ONLINE_INSTRUCTION_METHODS):
        gaps.append('session-online-instruction-slots-missing')
    if not hasattr(session_type, _PARKED_FETCH_ATTRIBUTE):
        gaps.append('session-parked-fetch-address-missing')
    if requires_step_inputs:
        gaps.append('session-requires-external-step-inputs')
    return tuple(gaps)


# ---------------------------------------------------------------------------
# native trace mapping
# ---------------------------------------------------------------------------

def _reduced_shapes():
    """The generated reduced dual AXI role shapes, from the session's module."""
    from ..local_harness.vexii_axi_fields import SHAPES
    return SHAPES


def _backend_rows(document):
    rows = document.get('backend_ports')
    if not isinstance(rows, list) or not rows:
        _refuse(document.get('kind'), 'no-native-backend-ports')
    result = {}
    for row in rows:
        if not isinstance(row, dict):
            _refuse(document.get('kind'), 'backend-port-shape')
        name, role = row.get('name'), row.get('role')
        if type(name) is not str or type(role) is not str or not name or not role:
            _refuse(document.get('kind'), 'backend-port-shape')
        result[name] = row
    return result


def reduced_axi_traces(artifact):
    """Map every reduced dual AXI4 role to its measured sample key.

    The artifact's own ``backend_ports`` rows are the authority for the names;
    the generated session's declared ``SHAPES`` are the authority for the
    role/direction/width set of each channel.  A disagreement (a widened
    address, a missing response pin, an extra role) is refused instead of
    being silently re-mapped, because the beat reader below only understands
    the exact reduced single-beat ABI.
    """
    document = getattr(artifact, 'runtime_document', None)
    if not isinstance(document, dict):
        _refuse(None, 'artifact-runtime-document-required')
    kind = document.get('kind')
    if kind not in ('reduced_dual_axi_cpu', 'reduced_dual_axi_irq_cpu'):
        _refuse(kind, 'not-a-reduced-dual-axi-kind')
    shapes = _reduced_shapes()
    rows = _backend_rows(document)
    traces = {
        'schema_version': TRACE_SCHEMA,
        'protocol': PROTOCOL,
        'sample_group': 'driver_samples.pre/post.backend',
        'variant': 'reduced_dual_single_beat',
        'channels': {'instr': 'i', 'data': 'd'},
        'observation': {
            'schema_version': 'reduced_axi_observation.v1',
            'variant': 'reduced_dual_single_beat.v1',
            'authority': 'observation_only',
            'parser': 'scenario.reduced_axi_events.ReducedAxiObserver',
            'sampling': 'pre_acceptance_post_hold_only',
            'response_status': {'0': 'okay',
                                '1': 'exclusive_response_unsupported',
                                '2': 'slave_error', '3': 'decode_error'},
            'absent_roles': sorted(['arlen', 'arburst', 'arlock', 'arqos',
                                    'awlen', 'awburst', 'awlock', 'awqos']),
            'instruction_channel': ('the fetch face declares AR/R only, so '
                                    'every accepted i-AR is an instruction '
                                    'fetch; nothing is classified from data'),
        },
        'read_transfer': dict(READ_TRANSFER),
    }
    for channel in ('instr', 'data'):
        prefix = traces['channels'][channel]
        shape = shapes[prefix]
        mapping = {}
        for role, (direction, width) in shape.items():
            name = prefix + '_' + role
            row = rows.get(name)
            if row is None:
                _refuse(kind, 'native-role-missing:' + name)
            if (row.get('role') != role or row.get('channel') != prefix
                    or row.get('direction') != direction or row.get('width') != width):
                _refuse(kind, 'native-role-shape:' + name)
            mapping[role] = name
        traces[channel] = mapping
    return traces


def error_policy(artifact, traces):
    """State exactly which pins observe a response and what is refused.

    A full AXI4 CPU has real ``rresp``/``bresp`` status pins, so the policy is
    the existing "observe the native response code" row, restricted to the
    single okay completion the shipped sessions already enforce.  A declared
    profile without ``error_response`` contradicts that boundary and is
    refused rather than widened.
    """
    document = getattr(artifact, 'runtime_document', None) or {}
    profile = getattr(getattr(artifact, 'plan', None), 'profile', None)
    capabilities = getattr(profile, 'capabilities', None)
    declared = capabilities.get('error_response') if isinstance(capabilities, dict) else None
    if declared is False:
        raise ValueError(REFUSAL_PREFIX + ':' + str(document.get('kind'))
                         + ':declared-error-capability-contradiction')
    return {
        'schema_version': 'compiled_F4_axi4_cpu_error_policy.v1',
        'protocol': PROTOCOL,
        'variant': traces['variant'],
        'native_error_observation': True,
        'error_roles': {'read': 'rresp', 'write': 'bresp'},
        'native_error_pins': {channel: {'read': traces[channel].get('rresp'),
                                        'write': traces[channel].get('bresp')}
                              for channel in ('instr', 'data')},
        'response_status': dict(traces['observation']['response_status']),
        'accepted_status': 'okay_only',
        'backend_error_policy': 'refuse_any_nonzero_response_status_before_any_join',
        'mmio_target_error': 'refused_at_the_generated_route_callback_never_injected',
        'max_outstanding': 1,
        'declared_error_capability': declared,
    }


# ---------------------------------------------------------------------------
# passive native reading
# ---------------------------------------------------------------------------

def _step_samples(events, component, kind):
    """Yield ``(event, sample)`` for this component's measured AXI4 edges.

    Only the session's own per-step evidence is consumed: one ``driver_samples``
    entry for the same local tick, whose ``pre``/``post`` backend rows carry the
    full declared AXI4 role set.  A missing or doubled sample is a named
    refusal, never a skipped tick (skipping would shift every sequence number).
    The sample's role set is authenticated by the session's own observer when
    it is replayed; this reader only insists on one measured edge per event.
    """
    for event in events:
        if not isinstance(event, dict):
            continue
        if event.get('component') != component:
            continue
        if event.get('kind') in _RESET_KINDS:
            # The same measured-reset convention ``collect_native_obi_beats``
            # already consumes: a reset marker ends the open case, so sequence
            # numbers and outstanding context restart with the session's own.
            yield event, None
            continue
        outputs = event.get('outputs')
        if not isinstance(outputs, dict):
            continue
        samples = outputs.get('driver_samples')
        if samples is None:
            continue
        tick = event.get('local_tick')
        if type(tick) is not int:
            _refuse(kind, 'native-sample-tick')
        if (not isinstance(samples, (list, tuple)) or len(samples) != 1
                or not isinstance(samples[0], dict)
                or samples[0].get('local_tick') != tick):
            _refuse(kind, 'native-sample-shape')
        yield event, samples[0]


#: Reported handshake output of each AXI4 channel, as the generated session
#: names it (``<face>_<channel>_accepted`` / ``<face>_<channel>_consumed``).
_REPORTED_CHANNELS = (('ar', '_accepted'), ('aw', '_accepted'), ('w', '_accepted'),
                      ('r', '_consumed'), ('b', '_consumed'))


def _cross_check_step_outputs(event, sample, kind, traces):
    """Cross-check the session's reported handshakes against the real pins.

    Every pin is looked up through the declared trace mapping -- ``d_awvalid``
    on the data face, ``i_arvalid`` on the fetch face -- never through a
    reconstructed role name: the two faces do not carry the same channels (the
    fetch face is AR/R only), and the generated session still reports the other
    three channels as zero for it.  A report on a channel the face has no pin
    for must be zero, and a declared pin missing from the measured row is a
    named refusal rather than an assumed value.
    """
    outputs = event.get('outputs') or {}
    pre = (sample.get('pre') or {}).get('backend')
    if not isinstance(pre, dict):
        return
    for name in ('instr', 'data'):
        mapping = traces[name]
        prefix = traces['channels'][name]
        for channel, suffix in _REPORTED_CHANNELS:
            key = prefix + '_' + channel + suffix
            if key not in outputs:
                continue
            roles = (channel + 'valid', channel + 'ready')
            if any(role not in mapping for role in roles):
                # This face has no such channel at all (fetch is AR/R only).
                if outputs[key] != 0:
                    _refuse(kind, 'native-handshake-report:' + key)
                continue
            signals = (mapping[roles[0]], mapping[roles[1]])
            if any(signal not in pre for signal in signals):
                _refuse(kind, 'native-handshake-signal:' + key)
            if outputs[key] != int(bool(pre[signals[0]] and pre[signals[1]])):
                _refuse(kind, 'native-handshake-report:' + key)


def _channel_id(prefix, traces):
    return 'instr' if prefix == traces['channels']['instr'] else 'data'


def _beat(transaction, *, write, value, byte_enable, rdata, response_event):
    return {
        'sequence': transaction['sequence'],
        'channel': transaction['channel'],
        'channel_prefix': transaction['channel_prefix'],
        'address': transaction['address'],
        'size': transaction['size'],
        'id': transaction['id'],
        'write': int(write),
        'value': value,
        'byte_enable': byte_enable,
        'rdata': rdata,
        'acceptance_event': transaction['acceptance_event'],
        'response_event': response_event,
        'native_reference': transaction['reference'],
        'source': 'reduced_axi_observer',
    }


def replay_reduced_axi(events, component, traces):
    """Reconstruct ``(completed, fetches)`` from the session's own observer.

    ``completed`` is keyed ``(channel, sequence)`` exactly like every other
    native CPU row (``channel`` is ``instr``/``data``), and every entry carries
    the real journal event ids of its accepting pre edge and its completing
    response edge.  ``fetches`` is the accepted instruction-fetch list
    ``[(event_id, address)]`` in acceptance order.
    """
    from ..scenario.reduced_axi_events import ReducedAxiObserver
    if not isinstance(traces, dict) or traces.get('schema_version') != TRACE_SCHEMA:
        raise ValueError(REFUSAL_PREFIX + ':native-trace-required')
    kind = 'reduced_dual_axi'
    observer = ReducedAxiObserver(component_id=component)
    observer.begin_scope(execution_id='saved-native',
                         testcase_id='saved-native', reset_epoch=0)
    sequences = {'i': 0, 'd': 0}
    reads = {'i': None, 'd': None}
    aw_pending = {'i': None, 'd': None}
    w_pending = {'i': None, 'd': None}
    joined = {'i': None, 'd': None}
    completed = {}
    fetches = []
    for event, sample in _step_samples(events, component, kind):
        if sample is None:
            observer.end_scope()
            observer.begin_scope(execution_id='saved-native',
                                 testcase_id='saved-native', reset_epoch=0)
            reads = {p: None for p in reads}
            aw_pending = {p: None for p in aw_pending}
            w_pending = {p: None for p in w_pending}
            joined = {p: None for p in joined}
            sequences = {p: 0 for p in sequences}
            continue
        _cross_check_step_outputs(event, sample, kind, traces)
        event_id = event['event_id']
        start = len(observer.events)
        observer.observe(sample)
        for row in observer.events[start:]:
            event_kind = row.get('kind')
            prefix = row.get('endpoint_id')
            if event_kind == 'reduced_axi_accept':
                payload = row['payload']
                if row['channel'] == 'ar':
                    sequences[prefix] += 1
                    reads[prefix] = {
                        'sequence': sequences[prefix],
                        'channel': _channel_id(prefix, traces),
                        'channel_prefix': prefix,
                        'address': payload['araddr'],
                        'size': payload['arsize'],
                        'id': payload['arid'],
                        'acceptance_event': event_id,
                        'reference': row['raw_event_refs'][0],
                    }
                    if prefix == traces['channels']['instr']:
                        fetches.append((event_id, payload['araddr']))
                elif row['channel'] == 'aw':
                    aw_pending[prefix] = {'address': payload['awaddr'],
                                          'size': payload['awsize'],
                                          'id': payload['awid'],
                                          'aw_event': event_id}
                elif row['channel'] == 'w':
                    w_pending[prefix] = {'wdata': payload['wdata'],
                                         'wstrb': payload['wstrb']}
            elif event_kind == 'reduced_axi_write_join':
                aw, w = aw_pending[prefix], w_pending[prefix]
                if aw is None or w is None:
                    _refuse(kind, 'native-write-join-without-context')
                sequences[prefix] += 1
                joined[prefix] = {
                    'sequence': sequences[prefix],
                    'channel': _channel_id(prefix, traces),
                    'channel_prefix': prefix,
                    'address': aw['address'],
                    'size': aw['size'],
                    'id': row['native_id'],
                    'acceptance_event': event_id,
                    'reference': row['raw_event_refs'][0],
                    'value': w['wdata'],
                    'byte_enable': w['wstrb'],
                }
                aw_pending[prefix] = w_pending[prefix] = None
            elif event_kind == 'reduced_axi_complete' and row['channel'] == 'r':
                read = reads[prefix]
                if read is None:
                    _refuse(kind, 'native-r-without-accepted-ar')
                reads[prefix] = None
                payload = row['payload']
                completed[(read['channel'], read['sequence'])] = _beat(
                    read, write=0, value=0, byte_enable=0,
                    rdata=payload['rdata'], response_event=event_id)
            elif event_kind == 'reduced_axi_complete' and row['channel'] == 'b':
                write = joined[prefix]
                if write is None:
                    _refuse(kind, 'native-b-without-accepted-aw')
                joined[prefix] = None
                payload = row['payload']
                completed[(write['channel'], write['sequence'])] = _beat(
                    write, write=1, value=write['value'],
                    byte_enable=write['byte_enable'], rdata=0,
                    response_event=event_id)
    return completed, fetches


# ---------------------------------------------------------------------------
# adapter rows
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Axi4MmioCpuAdapter(MmioCpuAdapter):
    """A ``MmioCpuAdapter`` whose readers are the AXI4 native replay above.

    ``executor_gaps`` is the machine-readable list produced by
    :func:`executor_gaps` for the bound session class, so a caller can tell
    "the parser is ready, the session is not" from one object.
    """
    executor_gaps: tuple = ()

    def first_fetch(self, events, cpu):
        return replay_reduced_axi(events, cpu, self.traces)[1]

    def completed_beats(self, events, cpu):
        return replay_reduced_axi(events, cpu, self.traces)[0]


def _parse_adapter(artifact, kind, session_type):
    """The parse-complete adapter bound to one concrete session class."""
    traces = reduced_axi_traces(artifact)
    policy = error_policy(artifact, traces)
    gaps = executor_gaps(
        session_type,
        requires_step_inputs=(kind == 'reduced_dual_axi_irq_cpu'))
    # ``split`` is the session's real numbering, not a protocol name test: the
    # fetch face and the LSU face have their own channel id (``instr``/``data``)
    # and their own sequence counter.
    # ``executor_gaps`` is a keyword on purpose: the base adapter's field list
    # grows (a newer row added an opt-in receipt flag), and a positional call
    # would silently write the gap tuple into whichever field came next.
    return Axi4MmioCpuAdapter(PROTOCOL, session_type, traces, policy, 4, 'split',
                              executor_gaps=gaps)


def _reduced_kind(artifact):
    """The one reduced dual AXI4 kind this module can parse, or a refusal."""
    document = getattr(artifact, 'runtime_document', None)
    if not isinstance(document, dict):
        _refuse(None, 'artifact-runtime-document-required')
    kind = document.get('kind')
    if kind not in SESSION_CLASSES:
        _refuse(kind, 'not-a-full-axi4-cpu-kind')
    if kind not in ('reduced_dual_axi_cpu', 'reduced_dual_axi_irq_cpu'):
        _refuse(kind, 'no-reusable-native-axi4-parser:' + ';'.join(
            AXI4_KIND_GAPS.get(kind, ())))
    return kind


def axi4_cpu_adapter(artifact, image=None, stream=None, *, base_dir=None):
    """Build the parse-complete adapter for a reduced dual AXI4 CPU artifact.

    The bound ``session_type`` is the *shipped generated* class, and
    ``executor_gaps`` states what the generic executor would still miss on it.
    Use :func:`executor_cpu_adapter` for the class the executor would really
    construct (the wrapper, when this kind has one).
    """
    kind = _reduced_kind(artifact)
    return _parse_adapter(artifact, kind, session_class(kind))


def executor_cpu_adapter(artifact, image=None, stream=None, *, base_dir=None):
    """Build the adapter the generic executor would actually run.

    Same traces and policy as :func:`axi4_cpu_adapter`; the difference is only
    which class is bound and, therefore, which gaps remain.
    """
    kind = _reduced_kind(artifact)
    return _parse_adapter(artifact, kind, executor_session_class(kind))


def cpu_adapter(artifact, image, stream, *, base_dir=None):
    """The extension seam: return a usable adapter, or refuse by name.

    Returning a parse-complete adapter whose session the generic executor
    cannot construct would advertise ``supported`` protocol paths that then
    fail inside ``MmioRuntime``.  So the executor gate is applied here to the
    class the executor would really construct, and a row that still needs
    session work raises the repository's existing
    ``MMIO-CPU-adapter-unsupported:<protocol>:<kind>:<gaps>`` refusal, which
    ``compiled_mmio.mmio_support`` already turns into a named ``unsupported``
    document.  ``AXI4_KIND_GAPS`` lists the same pieces for a report.
    """
    document = getattr(artifact, 'runtime_document', None)
    if not isinstance(document, dict) or document.get('kind') not in SESSION_CLASSES:
        return None
    kind = document['kind']
    if kind == 'cva6_packed_axi4_cpu':
        # The packed single-port row has its own reader (one request channel,
        # 8-byte non-cacheable fetch beats, no instruction attribute at all) and
        # its own wrapper session; see ``integration/cva6_axi_mmio.py``.
        from .cva6_axi_mmio import cva6_mmio_cpu_adapter
        return cva6_mmio_cpu_adapter(artifact, image, stream, base_dir=base_dir)
    adapter = executor_cpu_adapter(artifact, image, stream, base_dir=base_dir)
    if adapter.executor_gaps:
        raise ValueError(_gaps(kind, ','.join(adapter.executor_gaps)))
    return adapter


def native_cpu_protocol(runtime_document):
    """The real native CPU protocol of one of these artifacts."""
    document = runtime_document if isinstance(runtime_document, dict) else {}
    if document.get('kind') not in SESSION_CLASSES:
        raise ValueError(REFUSAL_PREFIX + ':native-protocol-required')
    return PROTOCOL
