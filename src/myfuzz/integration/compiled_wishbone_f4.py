"""Execute the selected compiled F4 through generated classic Wishbone RTL.

Sibling of :mod:`myfuzz.integration.compiled_f4` (executor id
``compiled_f4_obi_apb``) for the G8.1 classic Wishbone row (executor id
``compiled_f4_wishbone``).  The APB/OBI module is OBI/APB-specific in ways that
are load-bearing rather than cosmetic (an ``error_response`` capability, OBI
``protocol_taps`` roles, ``apb-storage:`` receipt ids), so this row is a
sibling module instead of a flag: nothing here falls back to an APB or OBI
checker, and no APB/OBI artifact can be admitted by this executor.

The admitted chain is exactly:

* one RV32I instruction image (``instruction_image``, the CPU's writable RAM
  region) with online instruction slots materialised by the case's declared
  code, and
* one closed storage producer row (``generic_wishbone_storage_abi``):
  ``GeneratedWishboneRegisterSession`` driven by the CPU's real classic
  Wishbone master through the Router, with a live
  ``WishboneStorageRegisterVersionAuthority`` token joined to the CPU data
  acceptance, the Router delivery, the native pre/post/ACK ``storage_probes``
  samples and the CPU readback/RAM write.

There is no error observation in this row: the pinned PicoRV32 classic master
has no ``err`` (and no ``stall``) pin, and a target trace that claims an
``err`` role is refused rather than forged.
"""
from __future__ import annotations

from collections.abc import Sequence
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import sys

from myfuzz.local_harness.build import host_source_discovery_scope
from myfuzz.local_harness.compiled_artifact_admission import (
    admit_compiled_artifacts, _difference)
from myfuzz.local_harness.generated_execution_admission import (
    GeneratedExecutionRefused)
from myfuzz.scenario.compiled_paths import (
    compile_paths, compiled_document_sha256)
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.session_runtime import (
    BoundOnlineInstruction, OnlineCase, ScenarioSession)
from myfuzz.scenario.batch import BatchAdvance

from .compiled_candidate_layout import compile_candidate_layout
from .compiled_f4_runtime_path import admit_compiled_f4_runtime_path
from .compiled_f4 import (
    _ACCESS_SEQUENCE, _PROCESS_LOCAL_EXECUTION, _check_fresh_identities,
    _closure, _compare_prefixes, _digest, _f4_edges, _input_identity,
    _layout_document, _semantic_canonical)
from .compiled_f4_build_join import built_receipt_sha256, validate_built_receipts
from .compiled_process_audit import (
    BuiltProcessAudit, capture_build_construction as _capture_build_construction,
    diagnostic_build_snapshot as _diagnostic_build_snapshot)
from .compiled_storage_producer import (
    ROW_GENERIC_WISHBONE_STORAGE, build_storage_producer, select_storage_producer)
from .generated_wishbone_storage_consumer import (
    check_wishbone_storage_observation, stable_wishbone_storage_version,
    wishbone_storage_consumer_support)
from .wishbone_register_writer import declare_wishbone_writer

EXECUTOR_ID = 'compiled_f4_wishbone'
CHAIN_SCHEMA = 'compiled_F4_wishbone_chain.v1'
PREFIX_SCHEMA = 'compiled_F4_wishbone_prefix.v1'
EXACT_HOPS_SCHEMA = 'compiled_F4_wishbone_exact_hops.v1'
BINDING_SCHEMA = 'compiled_F4_wishbone_execution_binding.v1'
CPU_POLICY_SCHEMA = 'compiled_F4_wishbone_cpu_policy.v1'
CHECKER_SCHEMA = 'compiled_F4_wishbone_checker.v1'
PROOF_SCOPE = ('selected_F4_image_consumption_native_wishbone_route_native_'
               'wishbone_storage_and_CPU_readback_RAM')
WISHBONE_CPU_TEMPLATE = ('cpu.wishbone', '1', 'no-err-stall')
TARGET_TEMPLATE = ('target.wishbone', '1', 'word-addressed-registered-ack')
WISHBONE_PROTOCOL = ('wishbone', 'classic')
CPU_ARTIFACT_KIND = 'wishbone_cpu'
TARGET_ARTIFACT_KIND = 'wishbone_register_observe'
BACKEND_CHANNEL = 'wb'
#: Request/response roles of the measured classic master backend.
REQUIRED_CPU_ROLES = ('cyc', 'stb', 'we', 'adr', 'dat_w', 'sel', 'ack', 'dat_r')
#: ``stall`` is a target-side input in this row: the pinned master has no such
#: port, so it is only ever *observed* (and must then be 0), never invented.
OPTIONAL_CPU_ROLES = ('stall',)
FORBIDDEN_CPU_ROLES = ('err',)
CHANNELS = ('instr', 'data')
REQUIRED_ASSERTIONS = (
    'protocol_checker.receipt_violations',
    'cross_component.declared_edge_hops',
    'cross_component.chain_certificate_hops',
)
READBACK_ASSERTION = 'cross_component.readback_ram_write_hop'
def _wishbone_target_access_id(value):
    """Normalise only the process-local execution segment of a routed id."""
    prefix = 'wishbone-storage:'
    if type(value) is not str or not value.startswith(prefix):
        return value
    execution, separator, sequence = value[len(prefix):].rpartition(':')
    if not separator or not execution or _ACCESS_SEQUENCE.fullmatch(sequence) is None:
        return value
    return prefix + _PROCESS_LOCAL_EXECUTION + ':' + sequence


def _project_wishbone_process_local(value):
    if isinstance(value, dict):
        return {key: (_wishbone_target_access_id(item)
                      if key == 'target_access_id'
                      else _project_wishbone_process_local(item))
                for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_project_wishbone_process_local(item) for item in value]
    return value


def wishbone_normalized_semantic_sha256(status, events, ticks):
    """Semantic hash of the real chain minus process-local routed access ids.

    Byte-for-byte the sibling of
    :func:`myfuzz.integration.compiled_f4.normalized_semantic_sha256`; only the
    execution segment of ``wishbone-storage:<execution>:<n>`` ids is replaced
    with the same stable placeholder.  Every other field, the sequence suffix,
    the local ticks and the status still participate.
    """
    if (type(status) is not str or not isinstance(ticks, dict)
            or any(type(key) is not str or type(value) is not int
                   for key, value in ticks.items())
            or not isinstance(events, Sequence)
            or isinstance(events, (str, bytes, bytearray))):
        raise ValueError('compiled-F4-wishbone-semantic-hash-input-required')
    digest = sha256()
    digest.update(b'{"events":[')
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise ValueError('compiled-F4-wishbone-semantic-hash-input-required')
        if index:
            digest.update(b',')
        digest.update(_semantic_canonical(
            _project_wishbone_process_local(event)))
    digest.update(b'],"local_ticks":')
    digest.update(_semantic_canonical(ticks))
    digest.update(b',"status":')
    digest.update(_semantic_canonical(status))
    digest.update(b'"}')
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# closed CPU/target facts (never a caller flag)
# ---------------------------------------------------------------------------

def _require(condition, code):
    if not condition:
        raise ValueError('compiled-F4-wishbone-' + code)


def _endpoint_roles(executor_binding):
    """The single declared classic master endpoint and its role rows."""
    endpoints = executor_binding.get('endpoints')
    _require(isinstance(endpoints, list) and len(endpoints) == 1,
             'CPU-endpoint-shape-unsupported')
    endpoint = endpoints[0]
    roles = endpoint.get('roles')
    _require(isinstance(roles, list) and roles, 'CPU-endpoint-shape-unsupported')
    table = {}
    for row in roles:
        _require(isinstance(row, dict)
                 and type(row.get('role')) is str
                 and type(row.get('physical_port')) is str
                 and row.get('direction') in ('input', 'output')
                 and type(row.get('width')) is int and row['width'] > 0,
                 'CPU-endpoint-shape-unsupported')
        _require(row['role'] not in table, 'CPU-endpoint-shape-unsupported')
        table[row['role']] = row
    _require(not (set(FORBIDDEN_CPU_ROLES) & set(table)),
             'error-observation-unsupported')
    _require(set(REQUIRED_CPU_ROLES) <= set(table),
             'native-CPU-trace-required')
    _require(set(table) <= set(REQUIRED_CPU_ROLES) | set(OPTIONAL_CPU_ROLES),
             'CPU-endpoint-shape-unsupported')
    return endpoint, table


def _wishbone_cpu_policy(artifact, image, stream):
    """Derive the error-free classic-Wishbone CPU facts from declarations."""
    from myfuzz.local_harness.template_contracts import select_template_contract

    document = artifact.runtime_document
    profile = artifact.plan.profile
    _require(document.get('kind') == CPU_ARTIFACT_KIND,
             'CPU-artifact-kind-required')
    error = profile.capabilities.get('error_response')
    _require(type(error) is bool, 'explicit-error-capability-required')
    _require(error is False, 'error-observation-unsupported')
    marker = document.get('instruction_identity_observation')
    _require(type(marker) is str and marker, 'instruction-identity-port-required')
    # The session's marker is the runtime name of the declared physical
    # instruction-identity export; both must name the same 1-bit output pin.
    marker_exports = [row for row in document.get('physical_exports', ())
                      if isinstance(row, dict)
                      and row.get('runtime_name') == marker]
    _require(len(marker_exports) == 1
             and marker_exports[0].get('direction') == 'output'
             and marker_exports[0].get('width') == 1
             and marker_exports[0].get('physical_port')
             == profile.capabilities.get('instruction_identity_port'),
             'instruction-identity-port-required')
    endpoints = {endpoint.endpoint_id: endpoint
                 for endpoint in artifact.plan.binding.endpoints}
    image_endpoint = image['endpoint_id']
    data_endpoint = stream['register_access']['source_endpoint']
    # One unified master: the instruction image and the MMIO stream share the
    # exact same physical endpoint.  Anything else is a different row.
    _require(image_endpoint == data_endpoint, 'CPU-endpoint-shape-unsupported')
    endpoint = endpoints.get(image_endpoint)
    _require(endpoint is not None and endpoint.protocol is not None
             and tuple(endpoint.protocol) == WISHBONE_PROTOCOL,
             'CPU-protocol-unsupported')
    contracts = [select_template_contract(endpoint, profile.capabilities,
        template_id=WISHBONE_CPU_TEMPLATE[0],
        template_version=WISHBONE_CPU_TEMPLATE[1],
        variant_id=WISHBONE_CPU_TEMPLATE[2]).document()]
    selected = document.get('selected_template')
    executor = selected.get('executor') if isinstance(selected, dict) else None
    _require(isinstance(executor, dict), 'CPU-policy-contract-mismatch')
    binding = executor.get('binding')
    _require(isinstance(binding, dict), 'CPU-policy-contract-mismatch')
    facts = binding.get('declared_profile_facts')
    _require(isinstance(facts, dict), 'CPU-policy-contract-mismatch')
    if (executor.get('protocol_templates') != contracts
            or facts.get('error_response') is not False
            or facts.get('address_units') != 'byte'
            or facts.get('max_outstanding') != 1
            or facts.get('address_width') != profile.capabilities.get('address_width')
            or facts.get('data_width') != profile.capabilities.get('data_width')
            or any(role in facts for role in FORBIDDEN_CPU_ROLES)
            or document.get('adapter_sources') != []):
        raise ValueError('compiled-F4-wishbone-CPU-policy-contract-mismatch')
    return dict(schema_version=CPU_POLICY_SCHEMA, protocol='wishbone',
        template=dict(template_id=WISHBONE_CPU_TEMPLATE[0],
            template_version=WISHBONE_CPU_TEMPLATE[1],
            variant_id=WISHBONE_CPU_TEMPLATE[2]),
        endpoint_id=image_endpoint, address_units='byte',
        max_outstanding=1, native_error_observation=False,
        error_capability=False, stall_pin=False,
        instruction_identity_observation=marker,
        adapter_sources=[], selected_contracts=contracts)


def _target_trace(artifact):
    """The one declared classic Wishbone target trace; never an error claim."""
    _require(artifact.runtime_document.get('kind') == TARGET_ARTIFACT_KIND,
             'target-artifact-kind-required')
    trace = artifact.runtime_document.get('base_protocol_trace')
    _require(isinstance(trace, dict), 'target-protocol-unsupported')
    _require(trace.get('protocol') == 'wishbone',
             'target-protocol-unsupported')
    signals = trace.get('signals')
    _require(isinstance(signals, dict) and signals,
             'target-protocol-unsupported')
    _require('err' not in signals, 'error-role-unsupported')
    _require(set(signals) == set(REQUIRED_CPU_ROLES) | {'stall'},
             'target-protocol-unsupported')
    widths = trace.get('signal_widths')
    _require(isinstance(widths, dict) and set(widths) == set(signals),
             'target-protocol-unsupported')
    _require(all(type(value) is int and value > 0 for value in widths.values()),
             'target-protocol-unsupported')
    return trace


def _target_template(artifact, endpoint_id):
    """Re-derive the target request tuning; a caller flag is never trusted."""
    policies = artifact.plan.request.tuning.document().get('endpoint_policies', [])
    rows = [row for row in policies if isinstance(row, dict)
            and row.get('endpoint_id') == endpoint_id]
    _require(len(rows) == 1, 'endpoint-template-unsupported')
    row = rows[0]
    triple = (row.get('template_id'), row.get('template_version'),
              row.get('variant_id'))
    _require(triple == TARGET_TEMPLATE, 'endpoint-template-unsupported')
    _require(row.get('max_outstanding') == 1,
             'endpoint-template-unsupported')
    return dict(template_id=TARGET_TEMPLATE[0],
                template_version=TARGET_TEMPLATE[1],
                variant_id=TARGET_TEMPLATE[2], max_outstanding=1)


def wishbone_cpu_traces(cpu_artifact, image, stream):
    """Map every classic Wishbone role to the measured CPU backend port.

    The names come from the artifact's own ``backend_ports`` rows of the
    declared ``wb`` channel and are cross-checked against the declared endpoint
    ABI (role, direction and width).  One unified master carries both channels,
    so both share these signal names; the channel of a beat is the session's
    measured ``instruction_identity_observation`` decision, never a guess.
    """
    policy = _wishbone_cpu_policy(cpu_artifact, image, stream)
    document = cpu_artifact.runtime_document
    ports = document.get('backend_ports')
    _require(isinstance(ports, list) and ports, 'native-CPU-trace-required')
    rows = [row for row in ports if isinstance(row, dict)
            and row.get('channel') == BACKEND_CHANNEL]
    _require(rows, 'native-CPU-trace-required')
    by_role = {}
    for row in rows:
        role = row.get('role')
        _require(type(role) is str and type(row.get('name')) is str,
                 'native-CPU-trace-required')
        _require(role not in by_role, 'native-CPU-trace-required')
        by_role[role] = row
    _require(not (set(FORBIDDEN_CPU_ROLES) & set(by_role)),
             'error-observation-unsupported')
    selected = document.get('selected_template')
    executor = selected.get('executor') if isinstance(selected, dict) else None
    _require(isinstance(executor, dict), 'native-CPU-trace-required')
    endpoint, declared = _endpoint_roles(executor.get('binding'))
    abi = cpu_artifact.structural.abi_document.get('ports')
    _require(isinstance(abi, list), 'native-CPU-trace-required')
    abi_by_port = {}
    for row in abi:
        if not isinstance(row, dict):
            continue
        abi_by_port.setdefault(row.get('physical_port'), []).append(row)
    roles = {}
    for role in REQUIRED_CPU_ROLES:
        row = by_role.get(role)
        _require(row is not None, 'native-CPU-trace-required')
        declared_role = declared.get(role)
        _require(declared_role is not None, 'native-CPU-trace-required')
        _require(row.get('direction') == declared_role['direction']
                 and row.get('width') == declared_role['width'],
                 'native-CPU-trace-required')
        # The declared endpoint ABI must carry exactly that physical pin.
        physical = abi_by_port.get(declared_role['physical_port'])
        _require(isinstance(physical, list) and len(physical) == 1
                 and physical[0].get('direction') == declared_role['direction']
                 and physical[0].get('width') == declared_role['width']
                 and physical[0].get('endpoint_id') == endpoint.get('endpoint_id'),
                 'native-CPU-trace-required')
        roles[role] = row['name']
    if 'stall' in by_role:
        declared_stall = declared.get('stall')
        _require(declared_stall is not None
                 and by_role['stall'].get('width') == 1
                 and by_role['stall'].get('direction') == 'input',
                 'native-CPU-trace-required')
        roles['stall'] = by_role['stall']['name']
    _require(policy['instruction_identity_observation'] ==
             cpu_artifact.runtime_document['instruction_identity_observation'],
             'native-CPU-trace-required')
    return {channel: dict(roles) for channel in CHANNELS}


# ---------------------------------------------------------------------------
# per-step native beats
# ---------------------------------------------------------------------------

def _step_outputs(event):
    outputs = event.get('outputs')
    return outputs if isinstance(outputs, dict) else None


def _integer(outputs, name, limit):
    value = outputs.get(name)
    if type(value) is not int or not 0 <= value <= limit:
        raise ValueError('compiled-F4-wishbone-native-CPU-output-range')
    return value


def wishbone_native_beats(events, component, traces, *, require_resolved=True):
    """Yield the session's own validated acceptances and responses, in order.

    Only the generated CPU session's per-step semantics are consumed: an
    acceptance exists when ``data_req_accepted``/``instr_req_accepted`` is 1 and
    a response when ``data_rsp_consumed``/``instr_rsp_consumed`` is 1.  Every
    acceptance must carry exactly one measured ``driver_samples`` pre phase for
    that same local tick, whose backend values must equal the reported fields.
    A stalled accept, an overlap, an unowned response, an unresolvable
    outstanding beat, a non-integer or out-of-range output and any ``err`` or
    non-zero ``stall`` observation are named refusals.
    """
    _require(isinstance(traces, dict) and set(traces) == set(CHANNELS),
             'native-CPU-trace-required')
    for channel in CHANNELS:
        signals = traces[channel]
        _require(isinstance(signals, dict)
                 and set(REQUIRED_CPU_ROLES) <= set(signals)
                 and not (set(FORBIDDEN_CPU_ROLES) & set(signals)),
                 'native-CPU-trace-required')
    pending = {channel: None for channel in CHANNELS}
    sequence = {channel: 0 for channel in CHANNELS}
    for event in events:
        if not isinstance(event, dict) or event.get('component') != component:
            continue
        outputs = _step_outputs(event)
        if outputs is None:
            continue
        samples = outputs.get('driver_samples')
        if samples is None:
            continue
        tick = event.get('local_tick')
        if (type(tick) is not int or not isinstance(samples, (list, tuple))
                or len(samples) != 1 or not isinstance(samples[0], dict)
                or samples[0].get('local_tick') != tick):
            raise ValueError('compiled-F4-wishbone-native-CPU-sample-shape')
        pre = samples[0].get('pre')
        post = samples[0].get('post')
        if not isinstance(pre, dict) or not isinstance(post, dict):
            raise ValueError('compiled-F4-wishbone-native-CPU-sample-shape')
        backend = pre.get('backend')
        if not isinstance(backend, dict):
            raise ValueError('compiled-F4-wishbone-native-CPU-sample-shape')
        # Measured level checks: never invent an error or a stalled accept.
        for channel in CHANNELS:
            signals = traces[channel]
            values = {}
            for role in REQUIRED_CPU_ROLES:
                name = signals[role]
                value = backend.get(name)
                if type(value) is not int or value < 0:
                    raise ValueError(
                        'compiled-F4-wishbone-native-CPU-sample-shape')
                values[role] = value
            stall_name = signals.get('stall')
            if stall_name is not None:
                if backend.get(stall_name) != 0:
                    raise ValueError(
                        'compiled-F4-wishbone-native-CPU-stall-observed')
            if 'err' in backend:
                raise ValueError(
                    'compiled-F4-wishbone-native-CPU-error-observation')
            if channel == 'instr':
                accepted = _integer(outputs, 'instr_req_accepted', 1)
                valid = _integer(outputs, 'instr_req_valid', 1)
                consumed = _integer(outputs, 'instr_rsp_consumed', 1)
                address = _integer(outputs, 'instr_addr', 0xffffffff)
                write = values['we']
                value = values['dat_w']
                byte_enable = values['sel']
                if accepted:
                    _require(valid == 1
                             and values['cyc'] == 1 and values['stb'] == 1,
                             'native-CPU-acceptance-level-mismatch')
                    _require(address == values['adr'],
                             'native-CPU-acceptance-address-mismatch')
                    _require(write == 0,
                             'native-CPU-instruction-write-unsupported')
            else:
                accepted = _integer(outputs, 'data_req_accepted', 1)
                valid = _integer(outputs, 'data_req_valid', 1)
                consumed = _integer(outputs, 'data_rsp_consumed', 1)
                address = _integer(outputs, 'data_addr', 0xffffffff)
                write = _integer(outputs, 'data_write', 1)
                value = _integer(outputs, 'data_wdata', 0xffffffff)
                byte_enable = _integer(outputs, 'data_be', 15)
                if accepted:
                    _require(valid == 1
                             and values['cyc'] == 1 and values['stb'] == 1,
                             'native-CPU-acceptance-level-mismatch')
                    _require(address == values['adr']
                             and write == values['we']
                             and value == values['dat_w']
                             and byte_enable == values['sel'],
                             'native-CPU-acceptance-level-mismatch')
            rdata = values['dat_r']
            if consumed:
                _require(valid == 1, 'native-CPU-response-without-request')
                if channel == 'data':
                    _require(_integer(outputs, 'data_rsp_rdata', 0xffffffff)
                             == rdata, 'native-CPU-response-data-mismatch')
                    _require(_integer(outputs, 'data_rsp_source_epoch', 0xffff)
                             == 0, 'native-CPU-response-epoch-mismatch')
                    reported = _integer(outputs,
                                        'data_rsp_source_sequence', 0xffffffff)
                    owned = pending['data']
                    _require(owned is not None
                             and reported == owned['sequence'],
                             'native-CPU-response-unowned')
                else:
                    _require(pending['instr'] is not None,
                             'native-CPU-response-unowned')
            if accepted:
                _require(pending[channel] is None,
                         'native-outstanding-overlap')
                sequence[channel] += 1
                pending[channel] = dict(event_id=event['event_id'],
                    acceptance_event=event['event_id'],
                    channel=channel, sequence=sequence[channel],
                    address=address, write=write, value=value,
                    byte_enable=byte_enable, kind='acceptance',
                    local_tick=tick)
                yield dict(pending[channel])
            if consumed:
                owned = pending[channel]
                _require(owned is not None, 'native-CPU-response-unowned')
                pending[channel] = None
                yield dict(event_id=event['event_id'], channel=channel,
                           sequence=owned['sequence'], rdata=rdata,
                           kind='response', local_tick=tick)
    if require_resolved and any(row is not None for row in pending.values()):
        raise ValueError('compiled-F4-wishbone-native-outstanding-unresolved')


def wishbone_outstanding_beats(events, component, traces):
    """Beats accepted by the journal that no response has consumed yet."""
    _completed, pending = _scan_beats(events, component, traces)
    return [dict(row) for row in pending.values() if row is not None]


def _scan_beats(events, component, traces):
    """Split the validated beat stream into completions and leftovers."""
    pending = {channel: None for channel in CHANNELS}
    completed = {}
    for beat in wishbone_native_beats(events, component, traces,
                                      require_resolved=False):
        channel = beat['channel']
        if beat['kind'] == 'acceptance':
            pending[channel] = beat
            continue
        accepted = pending[channel]
        if accepted is None or accepted['sequence'] != beat['sequence']:
            raise ValueError('compiled-F4-wishbone-native-response-unowned')
        completed[(channel, beat['sequence'])] = dict(accepted,
            response_event=beat['event_id'], rdata=beat['rdata'])
        pending[channel] = None
    return completed, pending


def _beats(events, component, traces):
    """All completed beats of the journal, keyed by channel and sequence."""
    return _scan_beats(events, component, traces)[0]


# ---------------------------------------------------------------------------
# exact native hops
# ---------------------------------------------------------------------------

def check_wishbone_f4_exact_hops(*, events, declaration, image, stream, traces,
                                 address, source_event_id, joins,
                                 declared_edges, instruction_snapshots,
                                 ram_event_id, proof_scope=None):
    """Consume the narrow F4 chain: image versions, native Wishbone, RAM.

    A consumed fetch is not instruction retirement: this row declares
    consumption only.  The classic master permits exactly one outstanding beat
    per channel, so every response consumes the exact outstanding acceptance.
    """
    _require(isinstance(declaration, dict), 'declaration-required')
    _require(isinstance(joins, (list, tuple)) and len(joins) == 2,
             'route-join-required')
    _require(isinstance(instruction_snapshots, (list, tuple))
             and len(instruction_snapshots) == 8,
             'instruction-snapshot-required')
    cpu = image['component']
    access = stream['register_access']
    code = bytes.fromhex(declaration['code_hex'])
    by_id = {}
    for event in events:
        if not isinstance(event, dict) or 'event_id' not in event:
            raise ValueError('compiled-F4-wishbone-event-identity-required')
        if event['event_id'] in by_id:
            raise ValueError('compiled-F4-wishbone-duplicate-event-identity')
        by_id[event['event_id']] = event
    sources = [event for event in events
               if event.get('kind') == 'instruction_source'
               and event.get('component') == cpu
               and event.get('source_event_id') == source_event_id
               and event.get('address') == address
               and event.get('data_hex') == code.hex()]
    _require(len(sources) == 1, 'instruction-source-missing')
    from myfuzz.scenario.edge_provenance import _transaction_key
    route_transaction = by_id[joins[0]['delivery_event']]['source_transaction']
    _require(_transaction_key(route_transaction) is not None,
             'transaction-malformed')
    source = sources[0]
    completed = _beats(events, cpu, traces)
    instruction_hops = []
    for offset in range(0, 32, 4):
        rows = [event for event in events
                if event.get('kind') == 'memory_read'
                and event.get('component') == cpu
                and event.get('address') == address + offset
                and event.get('transaction', {}).get('channel_id') == 'instr'
                and isinstance(event.get('writer_event_ids'), (list, tuple))
                and tuple(event['writer_event_ids']) == (source_event_id,) * 4
                and event.get('data_hex') == code[offset:offset + 4].hex()]
        _require(len(rows) == 1, 'instruction-version-hop-missing')
        read = rows[0]
        transaction = read['transaction']
        snapshot = instruction_snapshots[offset // 4]
        _require(read['data_hex'] == snapshot.data.hex()
                 and read['byte_offset'] == snapshot.byte_offset
                 and [list(v) for v in read['versions']]
                 == [list(v) for v in snapshot.versions]
                 and tuple(read['writer_event_ids']) == snapshot.writer_event_ids
                 and snapshot.writer_kinds == ('INSTRUCTION_SOURCE',) * 4,
                 'instruction-authoritative-version-mismatch')
        _require(_transaction_key(transaction) is not None
                 and all(transaction[key] == route_transaction[key]
                         for key in ('execution_id', 'testcase_id',
                                     'source_component', 'source_epoch')),
                 'instruction-transaction-mismatch')
        beat = completed.get(('instr', transaction['source_sequence']))
        _require(read.get('memory_id') == image['port']
                 and read.get('generation') == source['generation']
                 and read.get('width_bytes') == 4
                 and len(read.get('versions', [])) == 4
                 and all(type(v) in (list, tuple) and len(v) == 2
                         and all(type(n) is int and n >= 0 for n in v)
                         and v[0] == source['generation'] and v[1] >= 1
                         for v in read['versions'])
                 and all(v == read['versions'][0] for v in read['versions'])
                 and beat is not None
                 and beat['address'] == address + offset
                 and beat['rdata'] == int.from_bytes(
                     code[offset:offset + 4], 'little')
                 and beat['acceptance_event'] <= read['producer_event_id']
                 < beat['response_event'],
                 'native-instruction-consumption-missing')
        instruction_hops.append(dict(beat, source_event=source['event_id'],
            memory_read_event=read['event_id'], versions=read['versions']))
    data_hops = []
    for join in joins:
        delivery = by_id[join['delivery_event']]
        accept = by_id[join['acceptance_event']]
        transaction = delivery['source_transaction']
        beat = completed.get(('data', transaction['source_sequence']))
        # Exactly one CPU acceptance of this exact transaction may precede the
        # delivery; the Router's own record is the join, never a lookalike.
        matching = [event for event in events
                    if event.get('kind') == 'mmio_acceptance'
                    and event.get('component') == cpu
                    and event.get('source_transaction') == transaction
                    and event.get('address') == access['address']
                    and event.get('write') is bool(delivery['write'])
                    and event.get('event_id', 0) < delivery['event_id']]
        _require(len(matching) == 1
                 and matching[0]['event_id'] == accept['event_id'],
                 'native-data-acceptance-count')
        _require(_transaction_key(transaction) is not None
                 and all(transaction[key] == route_transaction[key]
                         for key in ('execution_id', 'testcase_id',
                                     'source_component', 'source_epoch'))
                 and transaction.get('source_component') == cpu
                 and transaction.get('source_epoch') == 0
                 and transaction.get('channel_id') == 'data'
                 and accept.get('component') == cpu
                 and accept.get('device_id') == access['device_id']
                 and delivery.get('device_id') == access['device_id']
                 and delivery.get('offset') == access['register_offset']
                 and beat is not None
                 and beat['acceptance_event'] == accept['producer_event_id']
                 and beat['address'] == access['address']
                 and beat['write'] == int(delivery['write'])
                 and (not delivery['write']
                      or (beat['value'] == declaration['candidate']['value']
                          and beat['byte_enable'] == 15))
                 and (delivery['write']
                      or beat['rdata'] == declaration['candidate']['value'])
                 and delivery.get('byte_enable') == 15
                 and accept['event_id'] < delivery['event_id']
                 < beat['response_event'],
                 'native-data-route-hop-missing')
        native = {key: beat[key] for key in (
            'channel', 'sequence', 'event_id', 'address', 'write', 'value',
            'byte_enable', 'acceptance_event', 'response_event', 'rdata',
            'local_tick')}
        data_hops.append(dict(join, native_acceptance_event=beat['acceptance_event'],
            native_response_event=beat['response_event'], native_wishbone=native))
    # The SW and LW fetches must precede their actual data requests.
    _require(instruction_hops[4]['response_event']
             < data_hops[0]['native_acceptance_event']
             and instruction_hops[5]['response_event']
             < data_hops[1]['native_acceptance_event'],
             'instruction-data-order')
    result_address = declaration.get('result_address')
    candidate = declaration.get('candidate')
    value = candidate.get('value') if isinstance(candidate, dict) else None
    memory_range = image.get('range')
    _require(isinstance(memory_range, (list, tuple)) and len(memory_range) == 2
             and all(type(bound) is int for bound in memory_range)
             and 0 <= memory_range[0] <= memory_range[1] < 1 << 32
             and type(result_address) is int
             and result_address >= memory_range[0]
             and result_address + 3 <= memory_range[1]
             and result_address % 4 == 0
             and type(value) is int and 0 <= value <= 0xffffffff
             and type(ram_event_id) is int,
             'result-RAM-hop-missing')
    ram_event = by_id.get(ram_event_id)
    _require(isinstance(ram_event, dict)
             and ram_event.get('kind') == 'memory_write'
             and ram_event.get('component') == cpu
             and ram_event.get('memory_id') == image.get('port')
             and ram_event.get('address') == result_address
             and ram_event.get('value') == value
             and ram_event.get('byte_enable') == 15
             and ram_event.get('width_bytes') == 4
             and type(ram_event.get('generation')) is int
             and ram_event['generation'] >= 0
             and type(ram_event.get('byte_offset')) is int
             and ram_event['byte_offset'] == result_address - memory_range[0],
             'result-RAM-hop-missing')
    version = ram_event.get('version')
    _require(isinstance(version, (list, tuple)) and len(version) == 2
             and all(type(item) is int and item >= 0 for item in version)
             and version[0] == ram_event['generation'] and version[1] >= 1,
             'result-RAM-version-mismatch')
    transaction = ram_event.get('transaction')
    _require(_transaction_key(transaction) is not None,
             'result-RAM-transaction-mismatch')
    read_transaction = data_hops[1]['source_transaction']
    _require(transaction.get('channel_id') == 'data'
             and transaction.get('source_component') == cpu
             and transaction.get('source_epoch') == 0
             and all(transaction.get(key) == read_transaction.get(key)
                     for key in ('execution_id', 'testcase_id',
                                 'source_component', 'source_epoch'))
             and transaction.get('source_sequence')
             == read_transaction.get('source_sequence', -1) + 1,
             'result-RAM-transaction-mismatch')
    ram_beat = completed.get(('data', transaction['source_sequence']))
    read_beat = data_hops[1]['native_wishbone']
    _require(ram_beat is not None
             and ram_beat['write'] == 1
             and ram_beat['address'] == result_address
             and ram_beat['value'] == value
             and ram_beat['byte_enable'] == 15
             and ram_event.get('producer_event_id') == ram_beat['acceptance_event']
             and read_beat['response_event'] < ram_beat['acceptance_event']
             and ram_beat['acceptance_event'] < ram_event_id
             < ram_beat['response_event'],
             'result-RAM-native-hop-missing')
    ram_write_hop = dict(memory_write_event=ram_event_id,
        producer_event_id=ram_event['producer_event_id'],
        memory_id=ram_event['memory_id'], generation=ram_event['generation'],
        byte_offset=ram_event['byte_offset'],
        width_bytes=ram_event['width_bytes'], address=ram_event['address'],
        value=ram_event['value'], byte_enable=ram_event['byte_enable'],
        version=list(version), transaction=deepcopy(transaction),
        native_acceptance_event=ram_beat['acceptance_event'],
        native_response_event=ram_beat['response_event'],
        native_wishbone={key: ram_beat[key] for key in (
            'channel', 'sequence', 'event_id', 'address', 'write', 'value',
            'byte_enable', 'acceptance_event', 'response_event', 'rdata',
            'local_tick')})
    return dict(schema_version=EXACT_HOPS_SCHEMA,
        proof_scope=proof_scope or PROOF_SCOPE,
        instruction_hops=instruction_hops, data_hops=data_hops,
        ram_write_hop=ram_write_hop,
        edges=[dict(edge, status='certified',
                    hops=(instruction_hops
                          if edge['relation'] == 'persistent_state'
                          else data_hops)) for edge in declared_edges])


# ---------------------------------------------------------------------------
# pure admission
# ---------------------------------------------------------------------------

def admit_wishbone_f4(*, artifacts, compiled_inputs, base_dir=None):
    """Pure exact D2/D3/ownership admission; returns the selected F4 path."""
    return _admit_wishbone_f4(artifacts=artifacts,
        compiled_inputs=compiled_inputs, base_dir=base_dir)[0]


def wishbone_admission(*, artifacts, compiled_inputs, base_dir=None):
    """Admission plus the rebuilt producer binding and the parsed layout."""
    path, binding = _admit_wishbone_f4(artifacts=artifacts,
        compiled_inputs=compiled_inputs, base_dir=base_dir)
    return dict(path=path, producer_binding=binding,
                layout=compile_candidate_layout(path))


def _admit_wishbone_f4(*, artifacts, compiled_inputs, base_dir=None):
    """Admission plus the immutable producer binding rebuilt from source inputs."""
    if (not isinstance(compiled_inputs, dict)
            or set(compiled_inputs) != {'request', 'compiled', 'ownership',
                                        'physical_port_map'}):
        raise GeneratedExecutionRefused(
            'compiled-F4-wishbone-runtime-input-required', '/compiled_inputs')
    admission = admit_compiled_artifacts(artifacts=artifacts, **compiled_inputs)
    if admission['status'] != 'compatible':
        raise GeneratedExecutionRefused(
            'compiled-F4-wishbone-runtime-input-refused', '/compiled_inputs',
            admission)
    request = compiled_inputs['request']
    compiled = compiled_inputs['compiled']
    # Composition-level fixed inputs have an explicit owner in D3 flows; this
    # executor binds none of them.  The shared wiring rule keeps its own name.
    wiring = getattr(request, 'wiring', None)
    typed_fixed = getattr(wiring, 'fixed_inputs', None)
    if type(typed_fixed) is not tuple:
        raise GeneratedExecutionRefused(
            'compiled-rfuzz-wiring-fixed-inputs-invalid',
            '/request/wiring/fixed_inputs',
            {'requires': 'a typed tuple of composition fixed inputs'})
    wiring_document = getattr(wiring, 'document', None)
    if not isinstance(wiring_document, dict):
        raise GeneratedExecutionRefused(
            'compiled-rfuzz-wiring-fixed-inputs-invalid',
            '/request/wiring/document',
            {'requires': 'the parsed wiring document'})
    raw_fixed = wiring_document.get('fixed_inputs', [])
    if type(raw_fixed) is not list:
        raise GeneratedExecutionRefused(
            'compiled-rfuzz-wiring-fixed-inputs-invalid',
            '/request/wiring/document/fixed_inputs',
            {'requires': 'a list of composition fixed inputs'})
    if typed_fixed or raw_fixed:
        raise GeneratedExecutionRefused(
            'compiled-rfuzz-fixed-input-unsupported',
            '/request/wiring/fixed_inputs',
            {'requires': 'compiled F4 does not bind composition wiring constants',
             'rows': list(typed_fixed) + list(raw_fixed)})
    selected = [path for path in compiled['paths']
                if path['flow_id'] == 'F4' and path['status'] == 'executable']
    _require(len(selected) == 1, 'executable-required')
    path = selected[0]
    # The declared candidate layout must compile before anything is admitted.
    compile_candidate_layout(path)
    _require(all(source['kind'] in {'instruction_image', 'cpu_mmio_stream',
                                    'external_pin'} for source in path['sources']),
             'source-kind-unsupported')
    sources = {kind: [source for source in path['sources']
                      if source['kind'] == kind]
               for kind in ('instruction_image', 'cpu_mmio_stream')}
    _require(all(len(rows) == 1 for rows in sources.values()),
             'source-shape-unsupported')
    image = sources['instruction_image'][0]
    stream = sources['cpu_mmio_stream'][0]
    access = stream['register_access']
    cpu = request.cpu
    _require(image['component'] == cpu.instance_id
             and access['source_component'] == cpu.instance_id
             and len(request.devices) == 1
             and request.devices[0].instance_id == access['target_component'],
             'topology-unsupported')
    _require(cpu.profile.cpu.xlen == 32
             and 'I' in {extension.upper()
                         for extension in cpu.profile.cpu.extensions},
             'RV32I-required')
    # Explicit artifact kinds: an OBI/APB artifact is refused here, never
    # handed to the sibling APB admission or checker.
    cpu_artifact = artifacts[cpu.instance_id]
    _require(isinstance(getattr(cpu_artifact, 'runtime_document', None), dict)
             and cpu_artifact.runtime_document.get('kind') == CPU_ARTIFACT_KIND,
             'CPU-artifact-kind-required')
    target_artifact = artifacts[access['target_component']]
    _require(getattr(target_artifact, 'runtime_document', None) is not None
             and target_artifact.runtime_document.get('kind')
             == TARGET_ARTIFACT_KIND,
             'target-artifact-kind-required')
    _wishbone_cpu_policy(cpu_artifact, image, stream)
    _target_trace(target_artifact)
    _target_template(target_artifact, access['target_endpoint'])
    wishbone_cpu_traces(cpu_artifact, image, stream)
    _f4_edges(compiled, image, access)
    resources = [resource for resource in request.wiring.resources
                 if resource.component_instance == cpu.instance_id]
    result = image['range'][1] - 3
    _require(not any(resource.base is None or resource.size is None
                     or resource.read is None or resource.write is None
                     or resource.initialization_policy != 'preload'
                     for resource in resources)
             and any(resource.resource_id == image['port']
                     and resource.read is True and resource.write is True
                     and resource.base <= result
                     and result + 4 <= resource.base + resource.size
                     for resource in resources),
             'writable-image-result-resource-required')
    _require_no_external_pins(path)
    binding = select_storage_producer(artifacts=artifacts,
        compiled_inputs=compiled_inputs, base_dir=base_dir)
    _require(binding.row == ROW_GENERIC_WISHBONE_STORAGE,
             'producer-row-unsupported')
    document = binding.document()
    _require(document.get('target_component') == access['target_component']
             and document.get('endpoint_id') == access['target_endpoint']
             and document.get('target_artifact_kind') == TARGET_ARTIFACT_KIND
             and document.get('protocol') == list(WISHBONE_PROTOCOL)
             and document.get('template') == {
                 'template_id': TARGET_TEMPLATE[0],
                 'template_version': TARGET_TEMPLATE[1],
                 'variant_id': TARGET_TEMPLATE[2]},
             'producer-binding-mismatch')
    _require(document.get('candidate', {}).get('external_pin_sources') == [],
             'external-pin-unsupported')
    support = wishbone_storage_consumer_support(binding=binding,
        artifacts=artifacts)
    if support['complete'] is not True:
        missing = ','.join(row['element'] for row in support['refusals'])
        raise ValueError('compiled-F4-wishbone-receipt-join-incomplete:'
                         + missing)
    expected_pre = [binding.document()['prerequisite']['expected']]
    _require([dict(kind=row['kind'], subject=row['subject'])
              for row in path['prerequisites']] == expected_pre,
             'prerequisite-unsupported')
    _require(path['seed'] is None
             and path['termination_observation']['kind'] == 'consumption'
             and {assertion['expectation_id']
                  for assertion in path['assertions']} == set(REQUIRED_ASSERTIONS),
             'checker-or-seed-unsupported')
    _require(len(path['bound_inputs']) == 1
             and path['bound_inputs'][0]['kind'] == 'ip_register_commit',
             'bound-producer-unsupported')
    for rule in path['constraints']['rules']:
        parameters = dict(rule.get('parameters', []))
        _require(rule['primitive'] == 'reachable_window'
                 and rule['phase'] == 'runtime'
                 and rule['category'] == 'environment_hard'
                 and rule['owner'] == 'cpu'
                 and rule['checker'] == 'soc_structure_audit.controller_mmio'
                 and parameters == {'base': access['window_base'],
                                    'size': access['window_size'],
                                    'request_sources': (access['device_id'],),
                                    'bus_owner': 'cpu'}
                 and not rule['fields'] and not rule['read_set']
                 and not rule['write_set'] and not rule.get('raw_bits')
                 and not rule.get('applies_in_modes')
                 and rule['state_bits'] == 0 and rule['budget'] == 1
                 and rule['failure_class'] == 'constraint_conflict'
                 and rule['basis'] == 'soc_plan.address_map.windows',
                 'constraint-rule-unsupported')
    _require(not request.wiring.deliveries, 'deliveries-unsupported')
    _require(not any(owner['kind'] == 'bound'
                     for owner in compiled_inputs['ownership'].document()['owners']),
             'physical-binding-unsupported')
    return deepcopy(path), binding


def _require_no_external_pins(path):
    """This row owns no external pin: the CPU drives the only physical input."""
    _require(not [source for source in path.get('sources', ())
                  if isinstance(source, dict)
                  and source.get('kind') == 'external_pin'],
             'external-pin-unsupported')


def _private_admission_snapshot(artifacts, inputs, base_dir):
    """Copy admitted data, including independent immutable profile proxies."""
    from collections.abc import Mapping
    from dataclasses import fields, is_dataclass
    from types import MappingProxyType

    issued_identity = _input_identity(inputs, artifacts)
    memo = {}
    visited = set()

    def proxies(value):
        if id(value) in visited:
            return
        visited.add(id(value))
        if isinstance(value, Mapping):
            for key, item in value.items():
                proxies(key)
                proxies(item)
            if isinstance(value, MappingProxyType):
                memo[id(value)] = MappingProxyType(deepcopy(dict(value), memo))
        elif is_dataclass(value) and not isinstance(value, type):
            for field in fields(value):
                proxies(getattr(value, field.name))
        elif isinstance(value, (list, tuple, set, frozenset)):
            for item in value:
                proxies(item)

    proxies(artifacts)
    proxies(inputs)
    private_artifacts = deepcopy(dict(artifacts), memo)
    private_inputs = deepcopy(inputs, memo)
    if _input_identity(private_inputs, private_artifacts) != issued_identity:
        raise ValueError(
            'compiled-F4-wishbone-private-reconstruction-mismatch')
    _admit_wishbone_f4(artifacts=private_artifacts,
        compiled_inputs=private_inputs, base_dir=base_dir)
    return private_artifacts, private_inputs


def _artifact_execution_identity(artifact):
    from myfuzz.local_harness.generated_artifact_admission import _artifact_files

    profile = artifact.plan.profile
    source = profile.source
    generated_files = {name: sha256(contents).hexdigest()
                       for name, contents in sorted(_artifact_files(artifact).items())}
    return dict(instance_id=artifact.plan.request.instance_id,
        component_id=profile.component_id,
        artifact_kind=artifact.runtime_document.get('kind'),
        artifact_digest=artifact.runtime_document.get('artifact_digest'),
        generated_files_sha256=generated_files,
        generated_artifact_bytes_sha256=_digest(generated_files),
        profile_fingerprint=profile.profile_fingerprint,
        source_root=source.source_root, source_revision=source.revision,
        source_top_module=source.top_module,
        source_verification_sha256=_digest(artifact.source_verification))


@dataclass(frozen=True, slots=True)
class WishboneF4ExecutionBinding:
    """Detached identity for one admitted Wishbone compiled-F4 contract.

    Descriptive only: runtime admission still rebuilds the current compiled
    path and source producer before use.
    """

    document_json: str

    def __post_init__(self):
        if type(self) is not WishboneF4ExecutionBinding or \
                type(self.document_json) is not str:
            raise ValueError(
                'compiled-F4-wishbone-execution-binding-required')
        try:
            document = json.loads(self.document_json)
        except (TypeError, ValueError) as error:
            raise ValueError(
                'compiled-F4-wishbone-execution-binding-required') from error
        if (type(document) is not dict
                or document.get('schema_version') != BINDING_SCHEMA
                or document.get('protocol') != 'wishbone'
                or document.get('binding_sha256') != _digest(
                    {key: value for key, value in document.items()
                     if key != 'binding_sha256'})):
            raise ValueError(
                'compiled-F4-wishbone-execution-binding-required')

    @classmethod
    def build(cls, document):
        if type(document) is not dict:
            raise ValueError(
                'compiled-F4-wishbone-execution-binding-required')
        issued = {key: value for key, value in document.items()
                  if key != 'binding_sha256'}
        issued['binding_sha256'] = _digest(issued)
        return cls(json.dumps(issued, sort_keys=True, separators=(',', ':')))

    def document(self):
        return json.loads(self.document_json)

    @property
    def digest(self):
        return self.document()['binding_sha256']


def _execution_binding_document(*, artifacts, compiled_inputs, path, layout,
                                producer_binding, base_dir,
                                source_closure=None, compiled_sha256=None,
                                cpu_traces=None, runtime_path_admission=None,
                                built_receipts=None):
    """The same facts as the APB binding minus ``cpu_error_policy``.

    There is no error observation in this row, so no error policy document
    exists to record; the measured classic-Wishbone trace contract and an
    explicit ``protocol='wishbone'`` marker take its place.
    """
    request = compiled_inputs['request']
    image = next(source for source in path['sources']
                 if source['kind'] == 'instruction_image')
    stream = next(source for source in path['sources']
                  if source['kind'] == 'cpu_mmio_stream')
    access = stream['register_access']
    cpu_id = request.cpu.instance_id
    target_id = access['target_component']
    producer = producer_binding.document()
    windows = [window for window in request.wiring.windows
               if window.device_id == access['device_id']]
    if len(windows) != 1:
        raise ValueError('compiled-F4-wishbone-execution-window-ambiguous')
    window = windows[0]
    if (window.target_instance != target_id
            or window.base != access['window_base']
            or window.size != access['window_size']):
        raise ValueError('compiled-F4-wishbone-execution-window-mismatch')
    cpu_artifact = artifacts[cpu_id]
    cpu_traces = (wishbone_cpu_traces(cpu_artifact, image, stream)
                  if cpu_traces is None else cpu_traces)
    cpu_identity = dict(instance_id=cpu_id,
        profile_fingerprint=cpu_artifact.plan.profile.profile_fingerprint,
        xlen=cpu_artifact.plan.profile.cpu.xlen,
        extensions=list(cpu_artifact.plan.profile.cpu.extensions),
        runtime_kind=cpu_artifact.runtime_document.get('kind'),
        protocol='wishbone',
        error_observation=False,
        stall_observation=False,
        wishbone_trace_contract=cpu_traces,
        wishbone_trace_contract_sha256=_digest(cpu_traces))
    source = producer.get('source', {})
    target = dict(component=target_id,
        artifact_kind=producer.get('target_artifact_kind'),
        endpoint_id=producer.get('endpoint_id'),
        protocol=producer.get('protocol'),
        template=producer.get('template'),
        window=dict(device_id=window.device_id,
            target_instance=window.target_instance,
            base=window.base, size=window.size,
            register_address=access['address'],
            register_offset=access['register_offset']),
        source_contract_id=source.get('contract_id'),
        source_contract_digest=source.get('contract_digest'),
        producer_binding_sha256=producer_binding.digest)
    assertions = deepcopy(path['assertions'])
    prerequisites = deepcopy(path['prerequisites'])
    admission = (admit_compiled_f4_runtime_path(request=request,
        compiled=compiled_inputs['compiled'], path=path)
        if runtime_path_admission is None else runtime_path_admission)
    admission.validate_cached_identity()
    body = dict(schema_version=BINDING_SCHEMA, protocol='wishbone',
        path_id=path['path_id'],
        runtime_path_id=admission.runtime_path_id,
        runtime_contract_sha256=admission.prepared.contract.identity_sha256,
        runtime_path_admission=admission.document(),
        runtime_path_admission_sha256=admission.digest,
        selected_path_sha256=_digest(path),
        compiled_document_sha256=(compiled_document_sha256(
            compiled_inputs['compiled']) if compiled_sha256 is None
            else compiled_sha256),
        request_sha256=_digest(request.document),
        artifact_identities={name: _artifact_execution_identity(artifacts[name])
                             for name in sorted(artifacts)},
        cpu=cpu_identity,
        candidate_layout=_layout_document(layout),
        target=target,
        producer_binding=producer,
        prerequisites=prerequisites,
        prerequisites_sha256=_digest(prerequisites),
        assertions=assertions,
        assertions_sha256=_digest(assertions),
        ownership_sha256=_digest(compiled_inputs['ownership'].document()),
        physical_port_map_sha256=_digest(sorted(
            (list(key), value)
            for key, value in compiled_inputs['physical_port_map'].items())),
        executor_source_closure_sha256=_digest(
            _closure(base_dir) if source_closure is None else source_closure))
    if built_receipts is not None:
        validate_built_receipts(artifacts, built_receipts)
        body['built_executable_receipts'] = deepcopy(built_receipts)
        body['built_executable_receipts_sha256'] = built_receipt_sha256(
            built_receipts)
    return body


def derive_wishbone_f4_execution_binding(*, artifacts, compiled_inputs,
                                         base_dir=None):
    """Re-admit inputs and derive their canonical execution identity."""
    path, producer_binding = _admit_wishbone_f4(artifacts=artifacts,
        compiled_inputs=compiled_inputs, base_dir=base_dir)
    layout = compile_candidate_layout(path)
    body = _execution_binding_document(artifacts=artifacts,
        compiled_inputs=compiled_inputs, path=path, layout=layout,
        producer_binding=producer_binding, base_dir=base_dir)
    return WishboneF4ExecutionBinding.build(body)


# ---------------------------------------------------------------------------
# the live executor
# ---------------------------------------------------------------------------

#: The shipped Wishbone CPU session is used unchanged: online instruction
#: slots, the waiting fetch and the canonical read payload live in the session
#: module, because the adapter and the authority both require that exact class.
_CPU_SESSION = None
_CPU_SESSION_REQUIRED = ('declare_instruction_slots', 'accept_instructions',
                         'waiting_instruction_address', 'step_local', '_serve')


def _online_cpu_session_class():
    """Return the shipped ``GeneratedWishboneCpuSession``, pinned.

    No subclass is constructed: an exact-class boundary (adapter binding,
    version authority) must see the real session.  Instead the module, the
    class and the five methods this executor depends on are captured once and
    every later call revalidates them, so a replaced or edited session is a
    named drift refusal rather than a silent re-baseline.
    """
    from myfuzz.local_harness import wishbone_cpu_session as module
    from myfuzz.local_harness.wishbone_cpu_session import (
        GeneratedWishboneCpuSession)

    global _CPU_SESSION
    if _CPU_SESSION is None:
        pins = {}
        for name in _CPU_SESSION_REQUIRED:
            value = vars(GeneratedWishboneCpuSession).get(name)
            if value is None:
                raise ValueError('compiled-F4-wishbone-CPU-session-drift')
            pins[name] = (value, getattr(value, '__code__', None))
        _CPU_SESSION = (module, GeneratedWishboneCpuSession, pins)
    module_pin, class_pin, pins = _CPU_SESSION
    if (sys.modules.get(module_pin.__name__) is not module_pin
            or not isinstance(class_pin, type)
            or generated_cpu_session_identity(module_pin) is not class_pin
            or GeneratedWishboneCpuSession is not class_pin
            or any(vars(class_pin).get(name) is not value
                   or (code is not None
                       and getattr(value, '__code__', None) is not code)
                   for name, (value, code) in pins.items())):
        raise ValueError('compiled-F4-wishbone-CPU-session-drift')
    return class_pin


def generated_cpu_session_identity(module):
    return getattr(module, 'GeneratedWishboneCpuSession', None)


class WishboneF4Runtime(BuiltProcessAudit):
    """One continuous testcase with live prerequisites and fresh prefix replay."""

    _audit_error_prefix = 'compiled-F4-wishbone'
    _audit_schema = 'compiled_F4_wishbone_execution_audit.v1'

    @host_source_discovery_scope()
    @_capture_build_construction
    def __init__(self, *, artifacts, compiled_inputs, base_dir, cache_dir,
                 run_id='compiled-f4-wishbone', rounds_per_case=128,
                 max_cases=64, expected_built_receipts=None,
                 build_audit_sink=None, defer_begin=False):
        self.path = admit_wishbone_f4(artifacts=artifacts,
            compiled_inputs=compiled_inputs, base_dir=Path(base_dir))
        self.layout = compile_candidate_layout(self.path)
        self._replay_identities = []
        if any(type(value) is not int or not 1 <= value <= 65536
               for value in (rounds_per_case, max_cases)):
            raise ValueError('compiled-F4-wishbone-budget-invalid')
        if type(defer_begin) is not bool:
            raise ValueError('compiled-F4-wishbone-defer-begin-invalid')
        self._caller_inputs = compiled_inputs
        self._caller_artifacts = artifacts
        self._input_digest = _input_identity(compiled_inputs, artifacts)
        self.artifacts, self.inputs = _private_admission_snapshot(
            artifacts, compiled_inputs, Path(base_dir))
        compiled_inputs = self.inputs
        artifacts = self.artifacts
        self.base_dir = Path(base_dir)
        self.cache_dir = Path(cache_dir)
        self.run_id = run_id
        self.runtime_path_admission = admit_compiled_f4_runtime_path(
            request=compiled_inputs['request'],
            compiled=compiled_inputs['compiled'], path=self.path)
        self.producer_binding = select_storage_producer(artifacts=artifacts,
            compiled_inputs=compiled_inputs, base_dir=self.base_dir)
        if self.producer_binding.row != ROW_GENERIC_WISHBONE_STORAGE:
            raise ValueError('compiled-F4-wishbone-producer-row-unsupported')
        self.row = self.producer_binding.row
        self.register_name = self.producer_binding.document()['register']['name']
        support = wishbone_storage_consumer_support(
            binding=self.producer_binding, artifacts=artifacts)
        if support['complete'] is not True:
            missing = ','.join(row['element'] for row in support['refusals'])
            raise ValueError(
                'compiled-F4-wishbone-receipt-join-incomplete:' + missing)
        self.receipt_elements = support
        self.rounds = rounds_per_case
        self.max_cases = max_cases
        self.records = []
        self.finished = False
        self.attempts = []
        self._failed_attempt = None
        self.closure = _closure(base_dir)
        self.compiled_digest = compiled_document_sha256(
            compiled_inputs['compiled'])
        request = compiled_inputs['request']
        self.cpu_id = request.cpu.instance_id
        self.stream = next(source for source in self.path['sources']
                           if source['kind'] == 'cpu_mmio_stream')
        self.access = self.stream['register_access']
        self.target_id = self.access['target_component']
        image = next(source for source in self.path['sources']
                     if source['kind'] == 'instruction_image')
        self.declared_edges = _f4_edges(compiled_inputs['compiled'], image,
                                        self.access)
        self.image = image
        self.policy = _wishbone_cpu_policy(artifacts[self.cpu_id], image,
                                          self.stream)
        self.target_trace = _target_trace(artifacts[self.target_id])
        self.traces = wishbone_cpu_traces(artifacts[self.cpu_id], image,
                                         self.stream)
        self.start = image['range'][0]
        self.cursor = None
        self.first_fetch = None
        self.end = image['range'][1] + 1
        self.result = self.end - 4
        resources = [resource for resource in request.wiring.resources
                     if resource.component_instance == self.cpu_id]
        if (any(resource.base is None or resource.size is None
                or resource.read is None or resource.write is None
                for resource in resources)
                or any(resource.initialization_policy != 'preload'
                       for resource in resources)):
            raise ValueError('compiled-F4-wishbone-memory-resource-unsupported')
        if not any(resource.resource_id == image['port']
                   and resource.read is True and resource.write is True
                   and resource.base <= self.result
                   and self.result + 4 <= resource.base + resource.size
                   for resource in resources):
            raise ValueError(
                'compiled-F4-wishbone-writable-image-result-resource-required')
        memory = PersistentMemory(regions=tuple(
            MemoryRegion(resource.resource_id, resource.base, resource.size,
                readable=resource.read, writable=resource.write)
            for resource in resources), initialization_seed=0,
            max_initialized_bytes=sum(resource.size for resource in resources))
        target, self.authority = build_storage_producer(self.producer_binding,
            artifact=self.artifacts[self.target_id], base_dir=self.base_dir,
            cache_dir=self.cache_dir, max_cases=max_cases)
        windows = tuple(DeviceWindow(window.device_id, window.base,
            window.size, target) for window in request.wiring.windows)
        if any(window.target_instance != self.target_id
               for window in request.wiring.windows):
            raise ValueError('compiled-F4-wishbone-router-target-unsupported')
        cpu = _online_cpu_session_class()(artifacts[self.cpu_id],
            base_dir=self.base_dir, cache_dir=self.cache_dir, memory=memory,
            router=DataflowRouter(windows), defer_mmio=True)
        self.runner = ScenarioRunner(
            sessions={self.cpu_id: cpu, self.target_id: target},
            ownership=compiled_inputs['ownership'], bindings=())
        self._build_sessions = dict(self.runner.sessions)
        for name, local in sorted(self._build_sessions.items()):
            local.configure_built_executable_receipt()
            local.prepare_local()
        self._built_receipts = {
            name: local.validate_built_executable_receipt()
            for name, local in sorted(self._build_sessions.items())}
        validate_built_receipts(self.artifacts, self._built_receipts)
        if (expected_built_receipts is not None
                and _semantic_canonical(expected_built_receipts)
                != _semantic_canonical(self._built_receipts)):
            raise ValueError(
                'compiled-F4-wishbone-built-receipt-identity-mismatch')
        body = _execution_binding_document(artifacts=artifacts,
            compiled_inputs=compiled_inputs, path=self.path, layout=self.layout,
            producer_binding=self.producer_binding, base_dir=self.base_dir,
            source_closure=self.closure, compiled_sha256=self.compiled_digest,
            cpu_traces=self.traces,
            runtime_path_admission=self.runtime_path_admission,
            built_receipts=self._built_receipts)
        self.execution_binding = WishboneF4ExecutionBinding.build(body)
        template = ScenarioGenome(run_id, 'CPU_TO_IP',
            self.runtime_path_admission.runtime_path_id,
            tuple(self.runner.sessions), rounds_per_case * max_cases * 2, ())
        self._pending = None
        self._checked = None
        self._measured_initial = False
        self.session = ScenarioSession(template, self.runner,
            checker=self._check_receipt, checker_configuration_only=True)
        # Retain exact source bytes; every future slot stays unmaterialized.
        self.session.declare_instruction_slots(self.cpu_id, self.start,
            (self.result - self.start) // 4)
        prepared = self.runtime_path_admission.prepared
        self.session.configure_runtime_paths(prepared.graph, prepared.contract,
            prepared.runtime_paths, source_ownership=compiled_inputs['ownership'],
            instruction_image_bindings=(
                self.runtime_path_admission.instruction_binding,))
        self._deferred_begin = bool(defer_begin)
        self._begun = False
        if not defer_begin:
            self.begin()

    # -- lifecycle --------------------------------------------------------
    def begin(self):
        """Begin the single native session; the constructor does this unless deferred."""
        if self._begun:
            raise ValueError('compiled-F4-wishbone-already-begun')
        try:
            self._stable()
            self.session.begin()
            self._native_processes = {
                name: session.process
                for name, session in self.runner.sessions.items()}
            self._process_identities = self._validated_build_process_identities()
            startup_build = _diagnostic_build_snapshot(self)
            if self._build_audit_sink is not None:
                self._build_audit_sink(startup_build)
            self.session.advance_initial((self.target_id,))
            # The Wishbone storage issuer has no bootstrap token to consume: a
            # version witness only exists after the first *measured* access.
            # One ordinary read of the declared word measures that initial
            # state (value 0x19, write_count 0) without a routed context, so
            # the first case's pre-state is a real, single-use token.
            self._measure_initial_state()
            # Observe and stall the native first fetch before materialising
            # any instruction byte.
            for _ in range(self.rounds):
                self._stable()
                bootstrap = self.session.advance_initial((self.cpu_id,))
                # The accepted first fetch is deliberately left unanswered
                # until the case's code materialises its slot.
                accepted = [beat for beat in wishbone_native_beats(
                    bootstrap.events, self.cpu_id, self.traces,
                    require_resolved=False)
                    if beat['kind'] == 'acceptance'
                    and beat['channel'] == 'instr']
                if accepted:
                    self.cursor = accepted[0]['address']
                    self.first_fetch = dict(address=self.cursor,
                        event_id=accepted[0]['event_id'])
                    break
            if (self.cursor is None or self.cursor % 4
                    or not self.start <= self.cursor < self.result):
                raise ValueError(
                    'compiled-F4-wishbone-first-fetch-outside-image')
            self._begun = True
        except BaseException as error:
            if self.session._begun and not self.session._finished:
                try:
                    self.session.finish()
                except BaseException as cleanup:
                    error.add_note(
                        'compiled-F4-wishbone session cleanup: ' + repr(cleanup))
            if getattr(self, '_build_audit_sink', None) is not None:
                try:
                    self._build_audit_sink(_diagnostic_build_snapshot(
                        self, closed=True, error=error))
                except BaseException as audit_error:
                    error.add_note(
                        'compiled-F4-wishbone partial build audit: '
                        + repr(audit_error))
            raise

    def _measure_initial_state(self):
        """Measure the declared word once so a pre-state token can exist."""
        if self._measured_initial:
            return
        target = self.runner.sessions[self.target_id]
        target.read_register(self.access['register_offset'])
        self._measured_initial = True

    # -- per case ---------------------------------------------------------
    def _issue_register_version(self, *, reset_epoch):
        return self.authority.issue(register=self.register_name,
            reset_epoch=reset_epoch)

    def _check_receipt(self, receipt):
        if receipt.violations:
            self._checked = None
            return tuple(receipt.violations)
        if self._pending is None:
            return tuple(receipt.violations)
        _flow, declaration, before, prior = self._pending
        try:
            observed, commit, after = self._check_chain(receipt, declaration,
                                                       before, prior)
            self._checked = (observed, commit, after)
            return tuple(receipt.violations)
        except ValueError as error:
            self._checked = None
            return (str(error),)

    def _check_chain(self, receipt, declaration, before, prior):
        token = self._issue_register_version(reset_epoch=before['reset_epoch'])
        observed, commit, after = check_wishbone_storage_observation(
            declaration, receipt,
            target_artifact=self.artifacts[self.target_id],
            authority=self.authority, token=token,
            register=self.register_name, reset_epoch=before['reset_epoch'],
            before=before, prior_writes=prior)
        self._check_outstanding()
        memory = self.runner.sessions[self.cpu_id].memory
        instruction_snapshots = [
            memory.read(self.cursor + offset, 4,
                transaction_id=f'compiled-F4-wishbone-check:'
                               f'{len(self.records)}:{offset}')
            for offset in range(0, 32, 4)]
        exact = check_wishbone_f4_exact_hops(events=self.runner.events_since(0),
            declaration=declaration, image=self.image, stream=self.stream,
            traces=self.traces, address=self.cursor,
            source_event_id=self.image['source_id'] + f':{len(self.records)}',
            joins=observed['joins'], declared_edges=self.declared_edges,
            instruction_snapshots=instruction_snapshots,
            ram_event_id=observed['RAM_event'])
        exact['assertions'] = [
            dict(expectation_id='protocol_checker.receipt_violations',
                 status='passed',
                 evidence=dict(violations=list(receipt.violations))),
            dict(expectation_id='cross_component.declared_edge_hops',
                 status='passed',
                 evidence=dict(edge_ids=[[edge['rule_index'],
                     edge['prerequisite_index']] for edge in exact['edges']],
                     relations=[edge['relation'] for edge in exact['edges']],
                     prerequisites=[edge['prerequisite']
                                    for edge in exact['edges']],
                     targets=[edge['target'] for edge in exact['edges']])),
            dict(expectation_id='cross_component.chain_certificate_hops',
                 status='passed',
                 evidence=dict(instruction_source=self.image['source_id'],
                     commit_tick=commit['tick'],
                     data_transactions=[hop['source_transaction']
                                        for hop in exact['data_hops']])),
            dict(expectation_id=READBACK_ASSERTION, status='passed',
                 evidence=dict(
                     memory_write_event=exact['ram_write_hop']['memory_write_event'],
                     transaction=exact['ram_write_hop']['transaction'],
                     address=exact['ram_write_hop']['address'],
                     value=exact['ram_write_hop']['value']))]
        observed['exact_hops'] = exact
        return observed, commit, after

    def _check_outstanding(self):
        """The only unresolved beat is the measured waiting fetch, or none.

        A stall is a real accepted fetch whose word the next case materialises;
        every other accepted beat must have been consumed by its response, so a
        lost or duplicated response can never be silently tolerated.
        """
        outstanding = wishbone_outstanding_beats(self.runner.events_since(0),
            self.cpu_id, self.traces)
        waiting = getattr(self.runner.sessions[self.cpu_id],
                          'waiting_instruction_address', None)
        if (len(outstanding) > 1
                or any(beat['channel'] != 'instr' for beat in outstanding)
                or (outstanding and (type(waiting) is not int
                                     or outstanding[0]['address'] != waiting))):
            raise ValueError(
                'compiled-F4-wishbone-native-outstanding-unresolved')

    def _decode_candidate(self, raw):
        issued = compile_candidate_layout(self.path)
        if issued != self.layout:
            raise ValueError('compiled-F4-wishbone-layout-identity-changed')
        return issued.decode(raw)

    def submit(self, raw, flow=None):
        """Submit one candidate; this executor has exactly one flow."""
        if flow is not None and flow != 'F4':
            raise ValueError('compiled-F4-wishbone-flow-unsupported')
        return self._submit_f4(raw)

    @host_source_discovery_scope()
    def _submit_f4(self, raw):
        """Decode the declared candidate slice before executing any source."""
        self._stable()
        if self._failed_attempt is not None:
            raise ValueError('compiled-F4-wishbone-failed-attempt:'
                             + self._failed_attempt)
        values = self._decode_candidate(raw)
        if len(self.records) >= self.max_cases:
            raise ValueError('compiled-F4-wishbone-case-budget-exhausted')
        value = values[self.stream['source_id']]
        declaration = declare_wishbone_writer(self.inputs['request'],
            self.inputs['compiled'], source_id=self.stream['source_id'],
            value=value, result_address=self.result)
        code = bytes.fromhex(declaration['code_hex'])
        if self.cursor + len(code) > self.result:
            raise ValueError('compiled-F4-wishbone-slot-exhausted')
        external = [source for source in self.path['sources']
                    if source['kind'] == 'external_pin']
        if external:
            raise ValueError('compiled-F4-wishbone-external-pin-unsupported')
        self._measure_initial_state()
        target = self.runner.sessions[self.target_id]
        before = self.authority.consume(self._issue_register_version(
            reset_epoch=target.reset_epoch))
        prerequisite = stable_wishbone_storage_version(before)
        prior = len(self.authority.writes())
        index = len(self.records)
        case_id = f'{self.run_id}:{index}'
        case = OnlineCase(case_id, 'CPU_TO_IP',
            self.runtime_path_admission.runtime_path_id,
            BoundOnlineInstruction(self.image['source_id'] + f':{index}',
                self.cpu_id, self.cursor, code.hex(),
                self.runtime_path_admission.instruction_binding.source_id),
            tuple(BatchAdvance(tuple(self.runner.sessions))
                  for _ in range(self.rounds)))
        self._stable()
        self._pending = ('F4', declaration, before, prior)
        self._checked = None
        try:
            receipt = self.session.submit_case(case)
            if receipt.violations or self._checked is None \
                    or receipt.status != 'running':
                raise ValueError('compiled-F4-wishbone-protocol-checker-failed:'
                                 + str(receipt.violations))
            observed, commit, after = self._checked
            certificate = dict(schema_version=CHAIN_SCHEMA, status='certified',
                path_id=self.path['path_id'],
                source_id=self.stream['source_id'],
                bound_input_id=self.path['bound_inputs'][0]['input_id'],
                case_id=case_id,
                instruction_source_id=self.image['source_id'],
                instruction_address=self.cursor,
                instruction_sha256=sha256(code).hexdigest(),
                prerequisite=prerequisite, commit=commit,
                postcondition=after, joins=observed['joins'],
                token=deepcopy(observed['token']),
                first_fetch=self.first_fetch,
                exact_hops=observed['exact_hops'],
                assertions=observed['exact_hops']['assertions'],
                execution_binding_sha256=self.execution_binding.digest,
                runtime_path_id=self.runtime_path_admission.runtime_path_id,
                runtime_path_admission_sha256=self.runtime_path_admission.digest,
                runtime_admitted=True)
            record = dict(raw=raw.hex(), value=value, source_values=values,
                          certificate=certificate)
            self.records.append(record)
            self.cursor += len(code)
            return deepcopy(certificate)
        except BaseException:
            self._failed_attempt = f'{self.run_id}:{index}'
            raise
        finally:
            self._pending = None
            self._checked = None

    # -- identity ---------------------------------------------------------
    def _stable(self, *, allow_finished=False):
        if self.finished and not allow_finished:
            raise ValueError('compiled-F4-wishbone-runtime-finished')
        if (_input_identity(self._caller_inputs, self._caller_artifacts)
                != self._input_digest
                or _input_identity(self.inputs, self.artifacts)
                != self._input_digest):
            raise ValueError('compiled-F4-wishbone-input-identity-changed')
        if _wishbone_cpu_policy(self.artifacts[self.cpu_id], self.image,
                self.stream) != self.policy:
            raise ValueError('compiled-F4-wishbone-CPU-policy-changed')
        if _target_trace(self.artifacts[self.target_id]) != self.target_trace:
            raise ValueError('compiled-F4-wishbone-target-trace-changed')
        if compile_candidate_layout(self.path) != self.layout:
            raise ValueError('compiled-F4-wishbone-layout-identity-changed')
        path, binding = _admit_wishbone_f4(artifacts=self.artifacts,
            compiled_inputs=self.inputs, base_dir=self.base_dir)
        if path != self.path:
            raise ValueError('compiled-F4-wishbone-admission-changed')
        if (type(binding) is not type(self.producer_binding)
                or binding.document_json != self.producer_binding.document_json):
            raise ValueError('compiled-F4-wishbone-producer-binding-changed')
        admission = getattr(self, 'runtime_path_admission', None)
        if admission is None:
            raise ValueError('compiled-F4-wishbone-runtime-path-admission-removed')
        admission.validate_cached_identity()
        if (self.session.runtime_contract != admission.prepared.contract
                or self.session.runtime_path_document['declaration']
                != admission.prepared.document()
                or self.session.instruction_image_binding_documents
                != (admission.instruction_binding.document(),)):
            raise ValueError('compiled-F4-wishbone-runtime-path-session-changed')
        current_closure = _closure(self.base_dir)
        if (current_closure != self.closure
                or compiled_document_sha256(self.inputs['compiled'])
                != self.compiled_digest
                or _difference(compile_paths(self.inputs['request']),
                               self.inputs['compiled']) is not None):
            raise ValueError('compiled-F4-wishbone-source-identity-changed')
        current_body = _execution_binding_document(artifacts=self.artifacts,
            compiled_inputs=self.inputs, path=path,
            layout=compile_candidate_layout(path),
            producer_binding=binding, base_dir=self.base_dir,
            source_closure=current_closure,
            compiled_sha256=self.compiled_digest, cpu_traces=self.traces,
            runtime_path_admission=admission,
            built_receipts=self._validated_built_receipts())
        if WishboneF4ExecutionBinding.build(current_body).document_json \
                != self.execution_binding.document_json:
            raise ValueError('compiled-F4-wishbone-execution-binding-changed')

    def online_identity_configuration(self):
        return dict(schema_version=CHECKER_SCHEMA,
            path_id=self.path['path_id'],
            compiled_sha256=self.compiled_digest,
            assertions=self.path['assertions'],
            candidate_layout=_layout_document(self.layout),
            producer_binding=self.producer_binding.document(),
            producer_row=self.producer_binding.row,
            execution_binding=self.execution_binding.document(),
            execution_binding_sha256=self.execution_binding.digest)

    def feedback(self):
        return dict(cases=len(self.records), certified=len(self.records),
            distinct_values=len({record['value'] for record in self.records}),
            changed_versions=sum(
                record['certificate']['commit']['before'] != record['value']
                for record in self.records))

    @host_source_discovery_scope()
    def finish(self):
        if not self.finished:
            try:
                self._stable()
            finally:
                self.trace = self.session.finish()
                self.finished = True
        self._stable(allow_finished=True)
        if any(row['returncode'] != 0
               for row in self.execution_audit()['exits'].values()):
            raise ValueError('compiled-F4-wishbone-native-exit-failed')
        semantic_hash = wishbone_normalized_semantic_sha256(self.trace.status,
            self.trace.events, self.trace.local_ticks)
        return dict(schema_version=PREFIX_SCHEMA, run_id=self.run_id,
            compiled_sha256=self.compiled_digest, source_files=self.closure,
            artifact_digests={name: artifact.runtime_document['artifact_digest']
                              for name, artifact in self.artifacts.items()},
            rounds_per_case=self.rounds, max_cases=self.max_cases,
            records=deepcopy(self.records),
            candidate_layout=_layout_document(self.layout),
            producer_binding=self.producer_binding.document(),
            execution_binding=self.execution_binding.document(),
            execution_binding_sha256=self.execution_binding.digest,
            runtime_path_admission=self.execution_binding.document().get(
                'runtime_path_admission'),
            online_plan=json.loads(self.session.encode_plan()),
            semantic_hash=semantic_hash, feedback=self.feedback())

    @host_source_discovery_scope()
    def replay(self, plan, *, audit_sink=None):
        """Reexecute every candidate in a fresh process, checking live state."""
        self._stable(allow_finished=True)
        expected = self.finish()
        if _difference(expected, plan) is not None:
            raise ValueError('compiled-F4-wishbone-prefix-mismatch')
        envelope = dict(
            scope='full_fresh_prefix_real_RTL_and_live_register_prerequisites',
            original_execution_audit=self.execution_audit(),
            original_build=_diagnostic_build_snapshot(self))
        try:
            fresh = type(self)(artifacts=self.artifacts,
                compiled_inputs=self.inputs, base_dir=self.base_dir,
                cache_dir=self.cache_dir, run_id=self.run_id,
                rounds_per_case=self.rounds, max_cases=self.max_cases,
                expected_built_receipts=self._built_receipts,
                build_audit_sink=lambda snapshot: envelope.update(
                    fresh_build=snapshot))
        except BaseException as error:
            envelope.update(error_type=type(error).__name__, error=str(error),
                startup_partial_trace_available=False)
            if audit_sink is not None:
                try:
                    audit_sink(deepcopy(envelope))
                except BaseException as export_error:
                    error.add_note(
                        'compiled-F4-wishbone replay export: '
                        + repr(export_error))
            raise
        primary_error = None
        try:
            identities = fresh.execution_audit()['identities']
            _check_fresh_identities(
                [self._process_identities] + self._replay_identities, identities)
            self._replay_identities.append(deepcopy(identities))
            envelope['fresh_build'] = _diagnostic_build_snapshot(fresh,
                previous=envelope.get('fresh_build'))
            for record in plan['records']:
                fresh.submit(bytes.fromhex(record['raw']))
            actual = fresh.finish()
            envelope.update(_compare_prefixes(expected, actual),
                            actual_prefix=actual)
            return envelope
        except BaseException as error:
            primary_error = error
            envelope.update(error_type=type(error).__name__, error=str(error))
            raise
        finally:
            secondary_errors = []
            if not fresh.finished:
                try:
                    fresh.finish()
                except BaseException as error:
                    secondary_errors.append(error)
                    envelope['cleanup_failure'] = dict(
                        error_type=type(error).__name__, error=str(error))
            for key, capture in (
                    ('fresh_build', lambda: _diagnostic_build_snapshot(fresh,
                        previous=envelope.get('fresh_build'),
                        error=primary_error)),
                    ('execution_audit', fresh.execution_audit),
                    ('actual_events',
                     lambda: list(fresh.runner.events_since(0)))):
                try:
                    envelope[key] = capture()
                except BaseException as error:
                    secondary_errors.append(error)
                    envelope.setdefault('audit_failures', []).append(
                        dict(stage=key, error_type=type(error).__name__,
                             error=str(error)))
            if audit_sink is not None:
                try:
                    audit_sink(deepcopy(envelope))
                except BaseException as error:
                    secondary_errors.append(error)
            if primary_error is not None:
                for error in secondary_errors:
                    primary_error.add_note(
                        'compiled-F4-wishbone replay cleanup/audit: '
                        + repr(error))
            elif secondary_errors:
                primary = secondary_errors[0]
                for error in secondary_errors[1:]:
                    primary.add_note(
                        'compiled-F4-wishbone replay cleanup/audit: '
                        + repr(error))
                raise primary
