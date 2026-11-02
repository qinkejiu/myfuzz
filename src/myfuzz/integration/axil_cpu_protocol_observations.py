"""AXI4-Lite CPU protocol observation: authenticate, then read real sampled pins.

The F2/F4 MMIO executor joins every routed beat to a *native CPU protocol*
witness (``integration/mmio_cpu_adapter.MmioCpuAdapter.first_fetch`` /
``completed_beats``).  For the pinned PicoRV32 AXI4-Lite CPU that witness can
only come from the harness' own per-tick pin samples:

* the generated ``axi4_lite_processor_memory_adapter.sv`` samples ``AWPROT`` and
  ``ARPROT`` and deliberately ignores them ("AWPROT and ARPROT are accepted and
  ignored, the same policy the AXI4 adapter applies to its protection
  sidebands"), and its memory service call carries only
  ``(address, write, be, value)``;
* the CPU's AXI4-Lite master pins -- including ``arprot``, whose bit 2 is the
  instruction-fetch flag (``picorv32.v:2779``) -- are exported by the harness as
  positional sideband taps (``protocol_tap_ports``) and sampled every tick in
  ``driver_samples[*].pre/.post.protocol_taps``.

``axi4lite_cpu_protocol_observations`` authenticates that observation contract
and names exactly what is missing when it is absent or wrong.
``collect_axi4lite_cpu_beats`` / ``collect_axi4lite_cpu_fetches`` are the
reviewed readers over those taps: they reconstruct the real read/write
transactions (two independent AXI4-Lite channels, at most one outstanding each)
and refuse, by name, every shape they cannot derive from sampled pins.  They
never invent a beat, a fetch, a width or a fallback, and they grant no
retirement, IRQ, storage-version or F5/F6 authority.

The read data granularity is a *declared* protocol semantic, not a special case:
``READ_TRANSFER_DECLARATION`` (in ``local_harness/axi_lite_session.py``) states
that a read transfers the whole addressed word and that the sampled ``wstrb`` is
0 because AXI4-Lite has no read strobe.  A beat therefore records the sampled
strobe unchanged (0 on reads) and the routed request presents the declared
four-lane access at the router boundary.

The refusal classification is the existing one used by
``integration/mmio_cpu_adapter.select_mmio_cpu`` and by
``local_harness/compiled_execution_projection.py``: a ``ValueError`` whose text
starts with ``MMIO-CPU-adapter-unsupported:``.  The suffix names the missing or
contradictory observation so a report can state it verbatim.
"""
from __future__ import annotations

AXIL_PROTOCOL = "axi4-lite"
TRACE_SCHEMA = "ip_protocol_trace.v1"
REFUSAL_PREFIX = "MMIO-CPU-adapter-unsupported:" + AXIL_PROTOCOL
#: Prefix of every beat/reader refusal (same classification family as the other
#: native CPU rows: ``compiled-F2-...`` / ``MMIO-AHB-...``).
STEP_PREFIX = "MMIO-AXI4-Lite"

#: The admitted endpoint roles of this CPU, with the direction the *CPU* drives.
#: Mirrors ``runtime_renderer._AXI_LITE``; a trace that disagrees is refused.
SHAPE = {
    "awvalid": ("output", 1), "awready": ("input", 1), "awaddr": ("output", 32),
    "awprot": ("output", 3), "wvalid": ("output", 1), "wready": ("input", 1),
    "wdata": ("output", 32), "wstrb": ("output", 4), "bvalid": ("input", 1),
    "bready": ("output", 1), "arvalid": ("output", 1), "arready": ("input", 1),
    "araddr": ("output", 32), "arprot": ("output", 3), "rvalid": ("input", 1),
    "rready": ("output", 1), "rdata": ("input", 32),
}
WIDTHS = {role: width for role, (_, width) in SHAPE.items()}
#: Every field a CPU protocol trace row of this protocol must carry, exactly.
TRACE_FIELDS = frozenset({"schema_version", "protocol", "endpoint_id",
                          "clock_domain", "signals", "signal_widths",
                          "sample_group", "boundary", "fetch_observation"})
TRACE_GROUP_FIELDS = frozenset({"schema_version", "sampling", "sample_group",
                                "traces"})
TAP_FIELDS = frozenset({"name", "direction", "width", "role", "endpoint_id",
                        "source_wire"})
FETCH_FIELDS = frozenset({"role", "bit", "asserted", "qualified_by", "basis"})
#: The pinned CPU's own RTL statement of the fetch flag; quoted, never derived.
FETCH_BASIS = "picorv32.v:2779 mem_axi_arprot = mem_instr ? 3'b100 : 3'b000"


class AxilProtocolObservationRefused(ValueError):
    """A named, auditable refusal; ``reason`` is the machine-readable suffix."""

    def __init__(self, reason: str, detail=None):
        self.reason = reason
        self.detail = detail
        super().__init__(REFUSAL_PREFIX + ":" + reason)


def _refuse(code: str, **detail) -> None:
    """Refuse by name; ``detail`` may itself carry a finer ``reason`` key."""
    raise AxilProtocolObservationRefused(code, detail or None)


def _trace_group(document: dict):
    group = document.get("base_protocol_traces")
    if type(group) is not dict:
        _refuse("no_cpu_protocol_trace",
                artifact_kind=document.get("kind"),
                requires="a per-tick CPU protocol trace; this runtime kind "
                         "declares no base_protocol_traces at all")
    if (set(group) != TRACE_GROUP_FIELDS
            or group.get("schema_version") != "ip_protocol_trace_set.v1"
            or group.get("sampling") != "pre_post"
            or group.get("sample_group") != "protocol_taps"
            or type(group.get("traces")) is not list):
        _refuse("trace_group_shape", fields=sorted(group))
    return group["traces"]


def _single_endpoint(traces) -> str:
    """The artifact declares exactly one CPU protocol trace for this protocol."""
    rows = [row for row in traces if type(row) is dict]
    if len(rows) != 1:
        _refuse("trace_shape", reason="one-trace-per-endpoint",
                matches=len(rows),
                requires="one admitted AXI4-Lite CPU protocol trace")
    endpoint_id = rows[0].get("endpoint_id")
    if type(endpoint_id) is not str or not endpoint_id:
        _refuse("trace_shape", reason="endpoint-id-required")
    return endpoint_id


def _trace_row(traces, endpoint_id: str) -> dict:
    rows = [row for row in traces
            if type(row) is dict and row.get("endpoint_id") == endpoint_id]
    if not rows:
        _refuse("no_cpu_protocol_trace", endpoint_id=endpoint_id,
                traces=[row.get("endpoint_id") for row in traces
                        if type(row) is dict])
    if len(rows) != 1:
        _refuse("trace_shape", reason="one-trace-per-endpoint", endpoint_id=endpoint_id,
                matches=len(rows))
    row = rows[0]
    # ``fetch_observation`` is required for observability but is reported by its
    # own reason code, so a row without it is shape-valid and fetch-incomplete.
    missing = TRACE_FIELDS - set(row) - {"fetch_observation"}
    unexpected = set(row) - TRACE_FIELDS
    if missing or unexpected:
        _refuse("trace_shape", reason="field-set", endpoint_id=endpoint_id,
                missing=sorted(missing), unexpected=sorted(unexpected))
    if (row.get("schema_version") != TRACE_SCHEMA
            or row.get("protocol") != AXIL_PROTOCOL
            or row.get("boundary") != "cpu_physical_abi"
            or row.get("sample_group") != "protocol_taps"
            or type(row.get("clock_domain")) is not str
            or not row.get("clock_domain")):
        _refuse("trace_shape", reason="protocol-or-boundary",
                endpoint_id=endpoint_id, protocol=row.get("protocol"),
                boundary=row.get("boundary"), schema_version=row.get("schema_version"))
    signals, widths = row.get("signals"), row.get("signal_widths")
    if (type(signals) is not dict or type(widths) is not dict
            or set(signals) != set(SHAPE) or set(widths) != set(SHAPE)
            or len(set(signals.values())) != len(SHAPE)
            or any(type(name) is not str or not name for name in signals.values())
            or widths != {role: width for role, (_, width) in SHAPE.items()}):
        _refuse("trace_shape", reason="role-set-or-widths", endpoint_id=endpoint_id,
                missing=sorted(set(SHAPE) - set(signals or ())),
                unexpected=sorted(set(signals or ()) - set(SHAPE)),
                expected_widths={role: width for role, (_, width) in SHAPE.items()},
                actual_widths=widths)
    return row


def _tap_binding(document: dict, row: dict) -> list:
    """Every sampled role must be a real sideband tap of a real admitted ABI row."""
    endpoint_id = row["endpoint_id"]
    signals = row["signals"]
    taps = document.get("protocol_tap_ports")
    if type(taps) is not list or not taps:
        _refuse("trace_shape", reason="declared-tap-ports-required",
                endpoint_id=endpoint_id)
    abi = (document.get("structural_abi") or {}).get("ports")
    if type(abi) is not list:
        _refuse("trace_shape", reason="structural-abi-required")
    bound = []
    for role, (direction, width) in sorted(SHAPE.items()):
        matches = [tap for tap in taps if type(tap) is dict
                   and tap.get("name") == signals[role]]
        if len(matches) != 1:
            _refuse("trace_shape", reason="tap-port-missing", role=role,
                    name=signals[role], matches=len(matches))
        tap = matches[0]
        if set(tap) != TAP_FIELDS:
            _refuse("trace_shape", reason="tap-field-set", role=role,
                    fields=sorted(tap))
        if (tap.get("role") != role or tap.get("endpoint_id") != endpoint_id
                or tap.get("direction") != "output" or tap.get("width") != width):
            _refuse("trace_shape", reason="tap-does-not-carry-this-role", role=role,
                    tap={key: tap.get(key) for key in
                         ("role", "endpoint_id", "direction", "width")})
        owners = [item for item in abi if type(item) is dict
                  and item.get("role") == role
                  and item.get("endpoint_id") == endpoint_id]
        if len(owners) != 1:
            _refuse("trace_shape", reason="abi-owner-missing", role=role,
                    matches=len(owners))
        owner = owners[0]
        if (owner.get("direction"), owner.get("width"), owner.get("disposition")) != (
                direction, width, "functional"):
            _refuse("trace_shape", reason="abi-owner-disagrees-with-role",
                    role=role,
                    owner={key: owner.get(key) for key in
                           ("direction", "width", "disposition")},
                    expected=[direction, width, "functional"])
        if tap.get("source_wire") != "link_" + str(owner.get("wrapper_name")):
            _refuse("trace_shape", reason="tap-is-not-the-admitted-wire", role=role,
                    source_wire=tap.get("source_wire"),
                    admitted="link_" + str(owner.get("wrapper_name")))
        bound.append({"role": role, "tap": tap["name"], "width": width,
                      "source_wire": tap["source_wire"]})
    return bound


def _fetch_observation(row: dict) -> dict:
    """The fetch flag must be declared by the trace, never guessed by a reader.

    ``arprot`` is a real 3-bit output of this CPU and bit 2 is the fetch flag in
    the pinned RTL, but the *generated executor ignores it*; only a sampled
    sideband tap makes it observable.  A trace without this declaration (or with
    a different role/bit) is refused instead of being interpreted.
    """
    declaration = row.get("fetch_observation")
    if type(declaration) is not dict:
        _refuse("no_fetch_observation", reason="absent-or-not-an-object",
                requires="the trace must declare which sampled role/bit carries "
                         "the instruction-fetch identity",
                arprot_sampled="arprot" in row["signals"])
    if set(declaration) != FETCH_FIELDS:
        _refuse("no_fetch_observation", reason="field-set",
                missing=sorted(FETCH_FIELDS - set(declaration)),
                unexpected=sorted(set(declaration) - FETCH_FIELDS))
    qualified = declaration.get("qualified_by")
    if (declaration.get("role") != "arprot" or declaration.get("bit") != 2
            or declaration.get("asserted") != "instruction_fetch"
            or type(qualified) is not list or qualified != ["arvalid", "arready"]
            or type(declaration.get("basis")) is not str
            or not declaration.get("basis")):
        _refuse("no_fetch_observation", reason="fetch-declaration-unsupported",
                declaration=declaration)
    return dict(declaration)


def _read_transfer() -> dict:
    """The declared read data granularity of this protocol row.

    Quoted from the bound session's single declaration so the reader, the
    session and any report cannot drift apart.
    """
    from ..local_harness.axi_lite_session import READ_TRANSFER_DECLARATION
    declaration = dict(READ_TRANSFER_DECLARATION)
    if (declaration.get('protocol') != AXIL_PROTOCOL
            or declaration.get('granularity') != 'whole_addressed_word'
            or declaration.get('transfer_bytes') != 4
            or declaration.get('sampled_read_strobe') != 0
            or declaration.get('router_request_byte_enable') != 15
            or type(declaration.get('statement')) is not str
            or not declaration['statement']):
        _refuse("read_transfer_declaration_unsupported",
                declaration=declaration)
    return declaration


def axi4lite_cpu_protocol_observations(document, *, endpoint_id=None) -> dict:
    """Authenticated CPU protocol observation contract of one artifact document.

    Pure function of the artifact document; it grants no execution authority and
    starts nothing.  A wrong or partial trace is refused with a named reason
    instead of being repaired.  ``endpoint_id`` defaults to the single declared
    trace endpoint, which is what a bound session can know without the compiled
    stream.
    """
    if type(document) is not dict:
        _refuse("no_cpu_protocol_trace", requires="artifact runtime document")
    if endpoint_id is not None and (type(endpoint_id) is not str or not endpoint_id):
        _refuse("no_cpu_protocol_trace", requires="declared endpoint id")
    traces = _trace_group(document)
    if endpoint_id is None:
        endpoint_id = _single_endpoint(traces)
    row = _trace_row(traces, endpoint_id)
    bound = _tap_binding(document, row)
    fetch = _fetch_observation(row)
    return {
        "schema_version": "axi4lite_cpu_protocol_observations.v1",
        "protocol": AXIL_PROTOCOL,
        "endpoint_id": endpoint_id,
        "clock_domain": row["clock_domain"],
        "sample_group": row["sample_group"],
        "boundary": row["boundary"],
        "signals": dict(row["signals"]),
        "roles": [[row["signals"][role], role, width] for role, (_, width) in
                  sorted(SHAPE.items())],
        "tap_ports": bound,
        "fetch_observation": fetch,
        "read_transfer": _read_transfer(),
        "authority": "sampled_pin_reader_no_retirement_no_irq_no_storage_version",
    }


# ---------------------------------------------------------------------------
# Witness readers over the sampled taps
# ---------------------------------------------------------------------------

def _pin(taps: dict, role: str, name: str, *, error_prefix: str) -> int:
    """One sampled role by its admitted tap name, range-checked by role width."""
    value = taps.get(name)
    width = WIDTHS[role]
    if type(value) is not int or not 0 <= value < 1 << width:
        raise ValueError(error_prefix + '-native-CPU-sample-missing-tap:' + role)
    return value


def _native_steps(events, cpu, signals, *, error_prefix):
    """Yield ``(event, selected pre protocol taps, pre backend)`` per CPU step.

    Exactly one ``driver_samples`` row per step, on the step's own local tick,
    carrying the sampled protocol taps -- the same strictness the OBI and AHB
    readers apply to their own samples.
    """
    for event in events:
        if not isinstance(event, dict) or event.get('component') != cpu:
            continue
        if 'outputs' not in event or 'local_tick' not in event:
            continue
        outputs = event['outputs']
        samples = outputs.get('driver_samples')
        if samples is None:
            continue
        if (not isinstance(samples, (list, tuple)) or len(samples) != 1
                or not isinstance(samples[0], dict)
                or samples[0].get('local_tick') != event['local_tick']):
            raise ValueError(error_prefix + '-native-CPU-sample-shape')
        pre = samples[0].get('pre')
        if not isinstance(pre, dict):
            raise ValueError(error_prefix + '-native-CPU-sample-shape')
        taps = pre.get('protocol_taps')
        backend = pre.get('backend')
        if not isinstance(taps, dict) or not isinstance(backend, dict):
            raise ValueError(error_prefix + '-native-CPU-sample-shape')
        yield (event,
               {role: _pin(taps, role, name, error_prefix=error_prefix)
                for role, name in signals.items()},
               backend)


def _accepted(backend: dict) -> bool:
    return bool(backend.get('m_req_valid')) and bool(backend.get('m_req_ready'))


def _axi4lite_read_identity(taps, backend, signals, declaration, error_prefix):
    """The read the adapter is issuing, joined to the CPU's own held pins.

    The pinned PicoRV32 registers ``mem_addr``/``mem_instr``/``mem_wstrb`` and
    holds them stable until ``mem_ready``; ``mem_axi_araddr``/``mem_axi_arprot``
    are direct assigns of those registers (``picorv32.v:2775-2783``).  The
    sampled ``araddr`` must equal the address the generated adapter presents, so
    this is a join, never a guess.  ``byte_enable`` stays the sampled strobe (0
    for AXI4-Lite reads): the declared whole-word semantics are never written
    back into a pin sample.
    """
    address = backend.get('m_req_addr')
    if type(address) is not int or address % 4 or taps['araddr'] != address:
        raise ValueError(error_prefix + '-native-read-request-mismatch')
    return dict(address=address, arprot=taps['arprot'],
                fetch=bool((taps['arprot'] >> declaration['bit']) & 1),
                sampled_wstrb=taps['wstrb'], byte_enable=taps['wstrb'],
                value=None)


def _replay_axi4lite_cpu_pins(events, cpu, observation, *, error_prefix=STEP_PREFIX):
    """Reconstruct the real AXI4-Lite transactions from sampled pins.

    The generated ``axi4_lite_processor_memory_adapter`` accepts at most one AR
    (read) or one AW+W (write) transaction at a time and never both in the same
    cycle, so the pin-level transactions have a total order.  Each pin
    transaction is joined to the *one* memory-backend request it produced: the
    adapter captures ``araddr``/``awaddr``/``wdata``/``wstrb`` and presents them
    unchanged.  That backend acceptance is the session's own transaction, so it
    identifies the beat (``acceptance_event``); the sampled AXI4-Lite pins are
    the witness that the request is the CPU's and which channel it is.

    ``instruction_fetch`` is only ever the trace's own declared ``arprot`` bit:
    at an observed ``arvalid && arready`` handshake, or -- for the single
    transaction the driver's unsampled reset window already accepted -- on the
    CPU's held address/protection pins at the adapter's request.  Every beat
    records which of the two qualified it.  Read byte enables stay the sampled
    value (0 for AXI4-Lite); the declared whole-word semantics live in
    ``read_transfer`` and are never written back into a pin sample.
    """
    signals = observation['signals']
    declaration = observation['fetch_observation']
    transfer = observation['read_transfer']
    sequence = 0
    pin_writes = []         # complete AW+W transactions not yet issued
    aw = None
    w = None
    handshake = None        # an accepted AR not yet joined to a backend request
    pending = None
    completed = {}
    for event, taps, backend in _native_steps(events, cpu, signals,
                                              error_prefix=error_prefix):
        event_id = event['event_id']
        # --- sampled address/read channel -----------------------------------
        if taps['arvalid'] and taps['arready']:
            if handshake is not None or (pending is not None and not pending['write']):
                raise ValueError(error_prefix + '-native-overlapping-read')
            if taps['araddr'] % 4:
                raise ValueError(error_prefix + '-unaligned-read')
            if taps['wstrb'] != transfer['sampled_read_strobe']:
                raise ValueError(error_prefix + '-read-strobe-not-declared')
            handshake = dict(address=taps['araddr'], arprot=taps['arprot'],
                fetch=bool((taps['arprot'] >> declaration['bit']) & 1),
                request_event=event_id)
        # --- sampled write channels (independent AXI4-Lite channels) ---------
        if taps['awvalid'] and taps['awready']:
            if aw is not None:
                raise ValueError(error_prefix + '-native-overlapping-write-address')
            aw = dict(address=taps['awaddr'], awprot=taps['awprot'],
                      request_event=event_id)
        if taps['wvalid'] and taps['wready']:
            if w is not None:
                raise ValueError(error_prefix + '-native-overlapping-write-data')
            w = dict(value=taps['wdata'], byte_enable=taps['wstrb'],
                     request_event=event_id)
        if aw is not None and w is not None:
            if pin_writes or (pending is not None and pending['write']):
                raise ValueError(error_prefix + '-native-overlapping-write')
            pin_writes.append(dict(address=aw['address'], awprot=aw['awprot'],
                value=w['value'], byte_enable=w['byte_enable'],
                request_event=w['request_event'],
                address_event=aw['request_event']))
            aw = w = None
        # --- the single backend request this transaction produced ------------
        if _accepted(backend):
            if pending is not None:
                raise ValueError(error_prefix + '-native-outstanding-overlap')
            if backend.get('m_req_write'):
                if not pin_writes:
                    raise ValueError(error_prefix + '-native-unowned-write-request')
                transaction = pin_writes.pop(0)
                if (backend.get('m_req_addr') != transaction['address']
                        or backend.get('m_req_wdata') != transaction['value']
                        or backend.get('m_req_be') != transaction['byte_enable']):
                    raise ValueError(error_prefix + '-native-write-request-mismatch')
                channel = 'data'
                qualified_by = 'aw_w_handshake'
            else:
                if backend.get('m_req_be') != transfer['sampled_read_strobe']:
                    raise ValueError(error_prefix + '-native-read-strobe-mismatch')
                transaction = _axi4lite_read_identity(taps, backend, signals,
                                                      declaration, error_prefix)
                if handshake is not None:
                    if (handshake['address'] != transaction['address']
                            or handshake['fetch'] != transaction['fetch']):
                        raise ValueError(error_prefix + '-native-read-request-mismatch')
                    qualified_by = 'ar_handshake'
                    handshake = None
                else:
                    # The driver's reset window consumes the first bus
                    # transaction without sampling it: only the CPU's held pins
                    # can qualify that one, and the beat says so.
                    qualified_by = 'held_pins_after_reset_window'
                channel = 'instr' if transaction['fetch'] else 'data'
            sequence += 1
            pending = dict(transaction, sequence=sequence, channel=channel,
                write=bool(backend.get('m_req_write')),
                acceptance_event=event_id, qualified_by=qualified_by)
        # --- sampled response channels --------------------------------------
        if taps['rvalid'] and taps['rready']:
            if pending is None or pending['write']:
                raise ValueError(error_prefix + '-native-unowned-read-response')
            completed[(pending['channel'], pending['sequence'])] = dict(pending,
                response_event=event_id, rdata=taps['rdata'])
            pending = None
            handshake = None
        if taps['bvalid'] and taps['bready']:
            if pending is None or not pending['write']:
                raise ValueError(error_prefix + '-native-unowned-write-response')
            completed[('data', pending['sequence'])] = dict(pending,
                response_event=event_id, rdata=None)
            pending = None
    return completed


def collect_axi4lite_cpu_beats(events, *, cpu, observation, error_prefix=STEP_PREFIX):
    """Completed CPU beats of this session, keyed ``(channel, sequence)``.

    ``channel`` is ``instr`` for a read whose declared ``arprot[2]`` says fetch
    and ``data`` for every other beat, matching the unified ``memory``
    transaction channel of the generated session.
    """
    return _replay_axi4lite_cpu_pins(events, cpu, observation,
                                     error_prefix=error_prefix)


def collect_axi4lite_cpu_fetches(events, *, cpu, observation,
                                 error_prefix=STEP_PREFIX):
    """Instruction fetches as ``(event_id, address)`` pairs, in acceptance order.

    An observed ``arvalid && arready`` handshake with the declared ``arprot[2]``
    bit is the witness.  The driver's reset window consumes the very first bus
    transaction without sampling it, so that one -- and only one per session --
    is qualified by the CPU's held address/protection pins at the adapter's
    request; the corresponding beat records which rule qualified it.
    """
    signals = observation['signals']
    declaration = observation['fetch_observation']
    transfer = observation['read_transfer']
    fetches = []
    emitted = False
    for event, taps, backend in _native_steps(events, cpu, signals,
                                              error_prefix=error_prefix):
        event_id = event['event_id']
        if taps['arvalid'] and taps['arready']:
            if taps['wstrb'] != transfer['sampled_read_strobe']:
                raise ValueError(error_prefix + '-read-strobe-not-declared')
            emit = bool((taps['arprot'] >> declaration['bit']) & 1)
            if emit:
                fetches.append((event_id, taps['araddr']))
            emitted = emit
        elif (backend.get('m_req_valid') and not backend.get('m_req_write')
                and not emitted and taps['araddr'] == backend.get('m_req_addr')
                and (taps['arprot'] >> declaration['bit']) & 1):
            fetches.append((event_id, taps['araddr']))
            emitted = True
        if taps['rvalid'] and taps['rready']:
            emitted = False
    return fetches


def select_axi4lite_cpu_protocol(artifact, image, stream):
    """The ``axi4-lite`` row of the MMIO CPU adapter.

    Mirrors ``integration/mmio_cpu_adapter.select_mmio_cpu``'s signature and
    refusal classification.  It authenticates the observation contract of the
    admitted artifact, then returns the adapter built on the reviewed readers
    above; nothing about the witness is assumed.
    """
    from .mmio_cpu_adapter import MmioCpuAdapter
    from ..local_harness.axi_lite_session import GeneratedAxiLiteMemorySession
    if type(stream) is not dict or type(image) is not dict:
        _refuse("no_cpu_protocol_trace", requires="compiled image and stream rows")
    access = stream.get("register_access") or {}
    endpoint_id = access.get("source_endpoint") or image.get("endpoint_id")
    document = getattr(artifact, "runtime_document", None)
    observations = axi4lite_cpu_protocol_observations(document,
                                                      endpoint_id=endpoint_id)
    return MmioCpuAdapter('axi4-lite', GeneratedAxiLiteMemorySession,
        dict(observation=observations, signals=observations['signals'],
             endpoint_id=observations['endpoint_id'],
             fetch_observation=observations['fetch_observation'],
             read_transfer=observations['read_transfer']),
        dict(mode='fail_stop_no_error_pin', native_error_observation=False,
             error_observation='unsupported:no_bresp_or_rresp_pin'),
        channel_model='unified')

