"""The packed single-port CVA6 AXI4 row for the generic F2/F4 executor.

The pinned CVA6 top (``cva6_packed_axi4_cpu``) has exactly one AXI4 master and
both the instruction side and the data side of the core reach it, so the two
things this module must be honest about are *what a beat can be told apart
from* and *what the executor may therefore claim*:

Instruction/data identity -- **not on user/prot, but on the AXI ID**
    * ``core/axi_shim.sv:263`` ``axi_req_o.ar.user = '0`` and
      ``core/axi_shim.sv:101`` ``axi_req_o.aw.user = '0``: no address-channel
      user bit is ever nonzero or derived from the requester.
    * ``core/axi_shim.sv:258`` ``axi_req_o.ar.prot = 3'b0``: the AXI4
      instruction-protection bit -- the identity the shipped AXI4-Lite row
      *does* use (``mem_axi_arprot = mem_instr ? 3'b100 : 3'b000``) -- is tied
      to zero, so ``arprot[2]`` carries no information here.
    * ``core/load_store_unit.sv:374`` ``data_wuser = '0`` and
      ``core/cache_subsystem/cva6_icache_axi_wrapper.sv:157,164`` (read user
      output left open, write user input tied to zero): the only user bits the
      core could have filled are constant as well, and
      ``cv64a6_imafdc_sv39_config_pkg.sv:35,37`` pins ``DataUserEn = 0``.
    * ``core/cva6.sv:1512,1591,1643``: the I$ and the D$ are wired to the very
      same ``noc_req_o``/``noc_resp_i`` pair -- there is no second port.

    The identity this port *does* drive is the read ID:
    ``core/cache_subsystem/wt_axi_adapter.sv:115`` makes the round-robin
    arbiter's ``arb_req = {dcache…, icache…}`` (the I-cache is the LSB),
    ``:138`` exposes the winning index as ``arb_idx`` and ``:159`` stamps it
    into ``axi_rd_id_in = {{Cva6Cfg.AxiIdWidth-1{1'b0}}, arb_idx}``; on the
    return path ``:597`` decodes ``axi_rd_id_out == 0`` as the I-cache and
    ``:638`` decodes ``axi_rd_id_out[0]`` as the D-cache (``:255`` reserves
    ``axi_rd_id_in[1]`` for AMO).  The shim passes that ID through unchanged
    (``core/axi_shim.sv:257`` ``axi_req_o.ar.id = rd_id_i``), so at this
    boundary **ARID/RID 0 is an instruction fetch and ARID/RID 1 is data**.

    That identity is a *property of this pinned configuration* (I-cache in the
    arbiter, ``CVA6ConfigDcacheType = config_pkg::WT``) and is not a general
    claim about AXI4 or about other CVA6 builds: :func:`cva6_instruction_identity`
    reads those two RTL files and only declares ``instruction_id_map`` when
    every anchor is still there.  A row without that declaration stays
    data-only: it never labels a beat as a fetch and never certifies an
    instruction hop (``instruction_hop_refusal``).

Fetch granularity -- **one 8-byte non-cacheable beat per fetched word**
    The build is ``WT`` (``cv64a6_imafdc_sv39_config_pkg.sv:72``) with a
    single cached region (``CachedRegionAddrBase = 0x8000_0000``), so a fetch
    outside that region is a *non-cacheable* access
    (``core/cache_subsystem/cva6_icache.sv:139-141``): one beat
    (``cva6_icache_axi_wrapper.sv:86`` ``axi_rd_blen = nc ? 0 : ...``), at the
    word-aligned address ``{tag, vaddr[..:3], 3'b0}``
    (``cva6_icache.sv:162``), ``arsize = clog2(AxiDataWidth/8) = 3``
    (``cva6_icache_axi_wrapper.sv:87``).  The instruction window declared by
    the scenario (``0x1_0000``) is exactly such an execute-but-uncached region
    (``cv64a6_imafdc_sv39_config_pkg.sv:140-144``), so the core is never
    caching instruction lines during a campaign and no stale-line hazard can
    hide a host-materialized word.  Because one beat covers *two* words, this
    row asks the executor for an 8-byte instruction granule
    (``instruction_granule=8``), and the certificate never claims a 4-byte
    instruction read that the bus never performed.

Scope: observation only.  No retirement, IRQ, storage-version, cross-case
origin, F5/F6 or search authority is created here, and an admitted row is only
*drivable* -- the real RTL run is what accepts a certificate.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from .mmio_cpu_adapter import MmioCpuAdapter
from ..local_harness.cva6_axi_mmio_session import (GeneratedCva6AxiMmioSession,
                                                  INSTRUCTION_HOP_REFUSAL)

TRACE_SCHEMA = 'cva6_packed_axi4_native_traces.v1'
PROTOCOL = 'axi4'
IDENTITY_SCHEMA = 'cva6_axi4_instruction_identity.v1'

_REFUSAL_PREFIX = 'MMIO-CPU-adapter-unsupported:axi4:cva6_packed_axi4_cpu'


def _refuse(reason):
    raise ValueError(_REFUSAL_PREFIX + ':' + reason)


#: Repository-relative sources of the fetch-identity declaration.  Both are the
#: pinned upstream files: the configuration package that selects the
#: write-through I-cache and the WT AXI adapter that stamps ``arb_idx`` into
#: ``ar.id`` and decodes it again on the return path.
_CVA6_RTL = 'third_party/cva6_upstream_reference/'
_CONFIG_PKG = _CVA6_RTL + 'core/include/cv64a6_imafdc_sv39_config_pkg.sv'
_AXI_ADAPTER = _CVA6_RTL + 'core/cache_subsystem/wt_axi_adapter.sv'

#: ``(path, marker)`` pairs that must all still be present for the ID
#: declaration below to be made.  The marker is matched literally against one
#: line, so the reported line number is the line that was actually read.
_IDENTITY_ANCHORS = (
    (_CONFIG_PKG, 'CVA6ConfigAxiIdWidth = 4;'),
    (_CONFIG_PKG, 'CVA6ConfigDcacheType = config_pkg::WT;'),
    (_AXI_ADAPTER, 'assign arb_req = {'),
    (_AXI_ADAPTER, "axi_rd_id_in = {{CVA6Cfg.AxiIdWidth-1{1'b0}}, arb_idx};"),
    (_AXI_ADAPTER, 'axi_rd_valid && axi_rd_id_out == 0'),
    (_AXI_ADAPTER, 'axi_rd_valid && axi_rd_id_out[0]'),
)


def _read_anchor(path, marker):
    """``(line_number, text, sha256)`` of the first line containing ``marker``."""
    root = Path(__file__).resolve().parents[3]
    target = root / path
    try:
        raw = target.read_bytes()
    except OSError:
        return None
    text = raw.decode('utf-8', errors='replace')
    for number, line in enumerate(text.splitlines(), start=1):
        if marker in line:
            return {'path': path, 'line': number, 'text': line.strip(),
                    'sha256': sha256(raw).hexdigest()}
    return None


def cva6_instruction_identity():
    """Declare the ARID/RID fetch identity of this pinned configuration.

    Returns the declaration document, or ``None`` when any anchor is missing
    (a re-pinned or re-configured core): the caller then keeps the data-only
    refusal instead of guessing.  The declaration is read from the pinned RTL
    here and can only ever be *consumed* by
    :mod:`myfuzz.integration.native_mmio_data_hops`; nothing in that module
    opens a hop without this map.
    """
    anchors = []
    for path, marker in _IDENTITY_ANCHORS:
        found = _read_anchor(path, marker)
        if found is None:
            return None
        anchors.append(found)
    # ``assign arb_req = {dcache…, icache…}`` is the proof that the I-cache is
    # the *least* significant arbitration input, i.e. index 0.
    arbiter_line = anchors[2]['line']
    id_in_line = anchors[3]['line']
    icache_line = anchors[4]['line']
    dcache_line = anchors[5]['line']
    return {
        'schema_version': IDENTITY_SCHEMA,
        'kind': 'pinned_wt_axi_adapter_arbiter_index',
        'instruction_id_map': {'arid': 0, 'rid': 0, 'granule_bytes': 8, 'rsize': 3},
        'identity_role': 'arid',
        'reported_roles': ['arid', 'rid', 'araddr', 'arsize', 'rdata'],
        'arbiter_index': {'icache': 0, 'dcache': 1, 'amo_bit': 1},
        'basis': anchors,
        'scope': ('this pinned cv64a6_imafdc_sv39 WT configuration only: '
                  + _AXI_ADAPTER + ':' + str(arbiter_line) + ' puts the I-cache '
                  'at arbiter input 0 and the D-cache at input 1, '
                  + _AXI_ADAPTER + ':' + str(id_in_line) + ' stamps the winning '
                  'index into ar.id, and the return path decodes rid 0 as the '
                  'I-cache (' + _AXI_ADAPTER + ':' + str(icache_line) + ') and '
                  'rid[0]=1 as the D-cache (' + _AXI_ADAPTER + ':'
                  + str(dcache_line) + '); this is not a claim about AXI4 in '
                  'general or about any other CVA6 configuration'),
        'not_claimed': [
            'no user or protection identity: ar.user is tied to zero '
            '(core/axi_shim.sv:263) and ar.prot to 3\'b0 (core/axi_shim.sv:258), '
            'so the declaration rests on the ID alone',
            'AMO reads set ar.id[1] (wt_axi_adapter.sv:255) and are therefore '
            'never reported as an instruction hop',
            'instruction retirement, DUT-internal storage version and cross-case '
            'origin stay unknown',
        ],
        'arbiter_assign_line': arbiter_line,
    }


def cva6_axi_mmio_traces(artifact, *, base_dir=None):
    """Map every packed AXI4 role to the measured sample key that carries it.

    The artifact's own ``backend_ports`` rows are the authority for the names
    and shapes; the session's declared ``CVA6_AXI_SHAPE`` is the authority for
    the role set.  A disagreement is refused instead of re-mapped.
    """
    from ..local_harness.cva6_axi4_fields import CVA6_AXI_SHAPE
    document = getattr(artifact, 'runtime_document', None)
    if not isinstance(document, dict) or document.get('kind') != 'cva6_packed_axi4_cpu':
        _refuse('not-a-packed-cva6-artifact')
    rows = document.get('backend_ports')
    if not isinstance(rows, list) or not rows:
        _refuse('no-native-backend-ports')
    by_name = {}
    for row in rows:
        if not isinstance(row, dict):
            _refuse('backend-port-shape')
        by_name[row.get('name')] = row
    mapping = {}
    for role, (direction, width) in CVA6_AXI_SHAPE.items():
        name = 'axi_' + role
        row = by_name.get(name)
        if row is None:
            _refuse('native-role-missing:' + name)
        if (row.get('role') != role or row.get('channel') != 'axi'
                or row.get('direction') != direction or row.get('width') != width):
            _refuse('native-role-shape:' + name)
        mapping[role] = name
    boot = document.get('boot_contract') or {}
    identity = cva6_instruction_identity()
    traces = {
        'schema_version': TRACE_SCHEMA,
        'protocol': PROTOCOL,
        'variant': 'cva6_packed_single_port_axi4',
        'sample_group': 'driver_samples.pre.backend',
        # One request channel: instruction fetches and data beats share the
        # port and are numbered under the same 'memory' channel id.
        'channels': {'memory': 'axi'},
        'memory': mapping,
        'observation': {
            'schema_version': 'cva6_packed_axi4_observation.v1',
            'authority': 'observation_only',
            'parser': 'scenario.full_axi_events.BoundedFullAxiObserver',
            'sampling': 'pre_acceptance_post_hold_only',
            'response_status': {'0': 'okay', '1': 'exclusive_response_unsupported',
                                '2': 'slave_error', '3': 'decode_error'},
            'instruction_channel': None,
            'instruction_identity': (INSTRUCTION_HOP_REFUSAL if identity is None
                                     else identity),
        },
        'boot_contract': dict(boot) if isinstance(boot, dict) else {},
    }
    if identity is None:
        # No pinned source to declare from: the row keeps the data-only scope.
        traces['instruction_hop_refusal'] = INSTRUCTION_HOP_REFUSAL
    else:
        # Declared, and only ever *consumed* as a declaration: the hop reader
        # refuses any row that does not carry this map.
        traces['instruction_id_map'] = dict(identity['instruction_id_map'])
        traces['instruction_identity'] = identity
    return traces


def _samples(events, component, traces):
    """Yield ``(event, measured-sample)`` for this component's real edges.

    Only the session's own per-edge evidence is consumed: one ``driver_samples``
    entry for the same local tick.  A reset marker restarts the beat numbering,
    exactly like the reduced AXI4 and OBI readers.
    """
    for event in events:
        if not isinstance(event, dict) or event.get('component') != component:
            continue
        if event.get('kind') in ('reset_barrier', 'cpu_reset'):
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
            _refuse('native-sample-tick')
        if (not isinstance(samples, (list, tuple)) or len(samples) != 1
                or not isinstance(samples[0], dict)
                or samples[0].get('local_tick') != tick):
            _refuse('native-sample-shape')
        yield event, samples[0]


def _beat_access(address, size):
    width = 1 << size
    lane = address & 7
    if lane + width > 8 or address % width:
        _refuse('native-beat-shape')
    return address, lane, width


def replay_cva6_axi(events, component, traces):
    """Reconstruct ``(completed, reads)`` from the session's saved samples.

    ``completed`` is keyed ``('data', sequence)`` -- the unified channel the
    session numbers -- and every entry carries the real journal event id of the
    edge that accepted the request and of the edge that completed it.  ``reads``
    is the list of accepted read addresses in acceptance order; the core gives
    them no instruction attribute, so the name says read, not fetch.
    """
    if not isinstance(traces, dict) or traces.get('schema_version') != TRACE_SCHEMA:
        _refuse('native-trace-required')
    mapping = traces['memory']
    kinds = ('ar', 'aw', 'w', 'b', 'r')
    sequence = 0
    read = None
    write = None
    wbeats = []
    joined = None
    completed = {}
    reads = []
    for event, sample in _samples(events, component, traces):
        if sample is None:
            sequence = 0
            read = write = joined = None
            wbeats = []
            continue
        event_id = event['event_id']
        pre = (sample.get('pre') or {}).get('backend')
        if not isinstance(pre, dict):
            _refuse('native-sample-backend')
        row = {}
        for role, name in mapping.items():
            value = pre.get(name)
            if type(value) is not int or value < 0:
                _refuse('native-sample-role:' + name)
            row[role] = value

        def handshake(channel):
            return bool(row[channel + 'valid'] and row[channel + 'ready'])

        if handshake('b'):
            if joined is None:
                _refuse('native-b-without-accepted-write')
            sequence_of, beat = joined
            if row['bresp'] != 0:
                _refuse('native-write-response-status')
            completed[('data', sequence_of)] = {**beat, 'response_event': event_id}
            joined = None
        if handshake('r'):
            if read is None:
                _refuse('native-r-without-accepted-read')
            if row['rresp'] != 0:
                _refuse('native-read-response-status')
            lane = read['lane']
            width = read['width']
            completed[('data', read['sequence'])] = {
                'sequence': read['sequence'], 'channel': 'memory',
                'address': read['address'], 'size': read['size'], 'id': read['id'],
                'write': 0, 'value': 0, 'byte_enable': 0,
                'rdata': (row['rdata'] >> (8 * lane)) & ((1 << (8 * width)) - 1),
                # The response ID the core's own R beat carried.  The session
                # already refuses ``rid != ar.id``; keeping the measured value
                # lets a reader check an address-ID declaration against the
                # return path instead of trusting the request side twice.
                'rid': row['rid'],
                'acceptance_event': read['acceptance_event'],
                'response_event': event_id,
                'native_reference': read['native_reference'],
            }
            read = None
        if handshake('aw'):
            if write is not None:
                _refuse('native-multiple-outstanding-aw')
            address, lane, width = _beat_access(row['awaddr'], row['awsize'])
            sequence += 1
            write = {'sequence': sequence, 'address': address, 'size': row['awsize'],
                     'id': row['awid'], 'lane': lane, 'width': width,
                     'native_reference': {'aw_event': event_id}}
        if handshake('w'):
            wbeats.append((event_id, row['wdata'], row['wstrb'], row['wlast']))
        if handshake('ar'):
            if read is not None:
                _refuse('native-multiple-outstanding-ar')
            address, lane, width = _beat_access(row['araddr'], row['arsize'])
            sequence += 1
            read = {'sequence': sequence, 'address': address, 'size': row['arsize'],
                    'id': row['arid'], 'lane': lane, 'width': width,
                    'acceptance_event': event_id,
                    'native_reference': {'ar_event': event_id}}
            reads.append((event_id, address))
        # The session commits a beat at the end of the edge that accepted it, so
        # the write's own journal entry belongs to that same edge.
        if write is not None and wbeats:
            w_event, wdata, wstrb, last = wbeats.pop(0)
            lane, width = write['lane'], write['width']
            mask = (wstrb >> lane) & ((1 << width) - 1)
            value = (wdata >> (8 * lane)) & ((1 << (8 * width)) - 1)
            joined = (write['sequence'], {
                'sequence': write['sequence'], 'channel': 'memory',
                'address': write['address'], 'size': write['size'],
                'id': write['id'], 'write': 1, 'value': value,
                'byte_enable': mask, 'rdata': 0,
                'acceptance_event': w_event,
                'native_reference': write['native_reference']})
            if not last:
                _refuse('native-multi-beat-write-unsupported')
            write = None
    return completed, reads


@dataclass(frozen=True)
class Cva6MmioCpuAdapter(MmioCpuAdapter):
    """The packed CVA6 AXI4 row: one request channel, ID-mapped fetch identity.

    ``traces['instruction_id_map']`` is present only when
    :func:`cva6_instruction_identity` could re-read the pinned RTL; without it
    the row keeps the data-only scope and refuses the fetch hop by name.
    """

    def first_fetch(self, events, cpu):
        """The first accepted read of this core, as the executor's bootstrap.

        The pinned renderer ties ``boot_addr_i`` to the profile's declared
        reset vector, so the core's very first read is the fetch of its reset
        vector and its address is what the executor needs to place the first
        online fragment.  This list is a read list, not a fetch-hop proof: an
        instruction hop is only ever built from the accepted-AR / R response
        pair whose IDs the declared ``instruction_id_map`` names.
        """
        return replay_cva6_axi(events, cpu, self.traces)[1]

    def completed_beats(self, events, cpu):
        return replay_cva6_axi(events, cpu, self.traces)[0]


def cva6_mmio_cpu_adapter(artifact, image, stream, *, base_dir=None):
    """Build the parse-complete adapter for the packed CVA6 AXI4 artifact."""
    traces = cva6_axi_mmio_traces(artifact)
    profile = getattr(getattr(artifact, 'plan', None), 'profile', None)
    capabilities = getattr(profile, 'capabilities', None)
    declared = capabilities.get('error_response') if isinstance(capabilities, dict) else None
    if declared is False:
        raise ValueError(_REFUSAL_PREFIX + ':declared-error-capability-contradiction')
    policy = {
        'schema_version': 'compiled_F4_cva6_packed_axi4_error_policy.v1',
        'protocol': PROTOCOL,
        'variant': traces['variant'],
        'native_error_observation': True,
        'error_roles': {'read': 'rresp', 'write': 'bresp'},
        'native_error_pins': {'memory': {'read': traces['memory'].get('rresp'),
                                         'write': traces['memory'].get('bresp')}},
        'response_status': dict(traces['observation']['response_status']),
        'accepted_status': 'okay_only',
        'backend_error_policy': 'refuse_any_nonzero_response_status_before_any_join',
        'mmio_target_error': 'refused_at_the_generated_route_callback_never_injected',
        'max_outstanding': 1,
        'declared_error_capability': declared,
    }
    # The granule is the *beat* a non-cacheable fetch covers, not the 4-byte
    # instruction word: the core never issues a 4-byte fetch on this port.
    return Cva6MmioCpuAdapter(PROTOCOL, GeneratedCva6AxiMmioSession,
        traces, policy, 8, 'unified',
        # Opt-in, declared here and nowhere else: this wrapper implements the
        # host-RAM commit stream and the writer-aware read receipts even though
        # its port numbers one request channel (see
        # local_harness/cva6_axi_mmio_session.py).  Every other unified row
        # keeps F1/F3 off.
        memory_receipts_on_unified=True)
