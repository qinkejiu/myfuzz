"""F1/F3 instruction-image paths over an existing persistent session."""
from __future__ import annotations

from dataclasses import dataclass

from myfuzz.runtime.contracts import GenericRuntimeRefused, require_identifier
from myfuzz.runtime.flows.storage import LoweredCase, _require_hex_record
from myfuzz.scenario.rv32i_sources import validate_instruction_bytes
from myfuzz.scenario.compiled_paths import compile_paths, compiled_document_sha256
from myfuzz.scenario.dependency import DependencyEdge, DependencyGraph, DependencyPath
from myfuzz.scenario.instruction_image_binding import InstructionImageSourceBinding
from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract, RuntimePathContract


# Versioned typed action token. This formerly rejected word is NOT executed as
# LW x0,0(x0): it lowers to a load at the declared reserved RAM scratch word.
RAM_READ_TOKEN = bytes.fromhex('03200000')
MEMORY_ACTION_GRAMMAR = 'bounded_memory_record.v2'


def lower_memory_code(runtime, raw, *, flow):
    """Preserve legacy instructions/stores; add one bounded DUT RAM load."""
    from myfuzz.scenario.rv32i_sources import (
        MmioWindow, fragment_bytes, mmio_access_fragment, mmio_write_fragment)
    if flow not in ('F1', 'F3') or type(raw) is not bytes or len(raw) != 4:
        raise ValueError('memory-case-shape')
    if flow == 'F1' and raw != RAM_READ_TOKEN:
        validate_instruction_bytes(raw, isa=getattr(runtime, 'instruction_isa', None))
        if int.from_bytes(raw, 'little') & 0x7f in (0x03, 0x23):
            raise ValueError('memory-case-f1-memory-operation')
        return raw, 'instruction', None
    binding = runtime.memory_bindings[flow]
    address = runtime.result - 4
    if (type(address) is not int or address % 4
            or binding.readable is not True or binding.writable is not True
            or not binding.base <= address <= binding.base + binding.size - 4):
        raise ValueError('memory-case-scratch-outside-declared-ram')
    windows = (MmioWindow(binding.base, binding.size),)
    if flow == 'F1':
        code = mmio_access_fragment('LW', address, windows=windows,
                                    base_register=1, data_register=2)
        return fragment_bytes(code), 'ram_read_word', address
    code = mmio_write_fragment('SW', address, int.from_bytes(raw, 'little'),
        windows=windows, base_register=1, data_register=2)
    return fragment_bytes(code), 'ram_store_word', address


def install_memory_feedback(runner, *, cpu_id, runtime_contract_sha256,
                            channel_id=None):
    """Pin opt-in callbacks before begin; no read, write, or stepping occurs.

    ``channel_id`` is the native channel the CPU numbers its own data beats on
    and defaults to the shared ``data`` channel.  A ``unified`` port that
    declares ``memory_receipts_on_unified`` numbers fetches and data together
    under ``memory``, so the commit authority has to be told: it authenticates a
    commit by the channel id of the real issued transaction and would otherwise
    refuse every commit of that row.
    """
    from myfuzz.scenario.ibex_pulp_dual_source import install_host_ram_commit_journal
    cpu = runner.sessions[cpu_id]
    channels = None if channel_id is None else {cpu_id: channel_id}
    install_host_ram_commit_journal(runner, component=cpu_id, service=cpu.service,
                                    channel_ids=channels)
    runner.configure_memory_dependency_evidence(
        runtime_contract_sha256=runtime_contract_sha256,
        max_records=4096, max_writer_versions=4096, max_event_gap=65536,
        channel_ids=channels)


@dataclass(frozen=True)
class MemoryFlowContext:
    plan_sha256: str
    path_id: str
    flow_id: str
    source_id: str
    instruction_isa: object = None

    def document(self):
        document = {'schema_version': 'generic_memory_flow_context.v1',
                'plan_sha256': self.plan_sha256, 'path_id': self.path_id,
                'flow_id': self.flow_id, 'source_id': self.source_id}
        if self.instruction_isa is not None:
            document['instruction_isa'] = {'xlen': self.instruction_isa.xlen,
                'extensions': list(self.instruction_isa.extensions)}
            if 'C' in self.instruction_isa.extensions:
                document['instruction_isa']['instruction_alignment'] = self.instruction_isa.instruction_alignment
        return document


class MemoryFlowKernel:
    """Closed single-word F1/F3 inputs; capture never invents evidence."""
    kernel_id = 'memory.kernel.v1'

    def prepare(self, bound_plan, path_id):
        matches = [row for row in bound_plan.plan.document().get('paths', ())
                   if row.get('path_id') == path_id and row.get('flow_id') in ('F1', 'F3')]
        if len(matches) != 1:
            raise GenericRuntimeRefused('generic-plan-mismatch', '/path_id')
        path = matches[0]
        kind = 'instruction_image' if path['flow_id'] == 'F1' else 'cpu_store_stream'
        sources = [row for row in path['sources'] if row.get('kind') == kind
                   and row.get('origin') == 'fuzzable']
        if len(sources) != 1:
            raise GenericRuntimeRefused('generic-source-unverified', '/path/sources')
        sessions = getattr(bound_plan, 'sessions', {})
        cpu = sessions.get(sources[0].get('component'))
        isa = getattr(getattr(cpu, 'memory', None), 'instruction_isa', None)
        return MemoryFlowContext(bound_plan.plan_sha256, path_id, path['flow_id'], sources[0]['source_id'], isa)

    def lower(self, context, case):
        if type(case) is not dict or set(case) != {'testcase_id', 'path_id', 'source_id', 'raw_records_hex'}:
            raise GenericRuntimeRefused('generic-case-shape', '/case')
        require_identifier(case['testcase_id'], '/case/testcase_id')
        if case['path_id'] != context.path_id or case['source_id'] != context.source_id:
            raise GenericRuntimeRefused('generic-source-unverified', '/case/source_id')
        rows = case['raw_records_hex']
        if type(rows) is not list or not rows:
            raise GenericRuntimeRefused('generic-case-shape', '/case/raw_records_hex')
        records = tuple(_require_hex_record(row, '/case/raw_records_hex') for row in rows)
        if any(len(raw) != 4 for raw in records):
            raise GenericRuntimeRefused('generic-case-shape', '/case/raw_records_hex')
        if context.flow_id == 'F1':
            for raw in records:
                validate_instruction_bytes(raw, isa=context.instruction_isa)
                if raw != RAM_READ_TOKEN and int.from_bytes(raw, 'little') & 0x7f in (0x03, 0x23):
                    raise GenericRuntimeRefused('generic-case-shape', '/case/raw_records_hex',
                                                {'reason': 'F1-memory-operation-unsupported'})
        return LoweredCase(case['testcase_id'], context.path_id, context.source_id,
                           context.flow_id, 4, records)

    def capture(self, context, receipt):
        # Raw observations remain in the per-case receipt; no fact is promoted
        # to retirement or a committed-memory proof by this kernel.
        return ()

    def feedback(self, context, claims):
        return ()


def _native_memory_beats(events, *, cpu, traces, error_policy, cpu_adapter):
    """Reconstruct completed CPU beats through the selected native protocol."""
    if cpu_adapter is not None and cpu_adapter.protocol != 'obi':
        return cpu_adapter.completed_beats(events,cpu)
    from myfuzz.integration.native_obi_hops import collect_native_obi_beats
    return collect_native_obi_beats(events,cpu=cpu,traces=traces,error_policy=error_policy)


def _observe_f3_write(*, events, receipt, cpu, address, value, memory_id,
                      memory_base, memory_generation, traces, error_policy, transaction_scope,
                      cpu_adapter=None):
    """Observe a case-local RAM write on a complete physical CPU beat.

    This is a data-port observation, not a retired-instruction/source proof.
    Beat sequence numbers are reconstructed from the entire session prefix.
    """
    from myfuzz.scenario.edge_provenance import _transaction_key

    if (type(receipt.event_start) is not int or type(receipt.event_end) is not int
            or not 0 <= receipt.event_start <= receipt.event_end <= len(events)):
        return None
    ids = [event.get('event_id') for event in events]
    if any(type(item) is not int for item in ids) or len(set(ids)) != len(ids):
        return None
    try:
        beats = _native_memory_beats(events,cpu=cpu,traces=traces,
                                     error_policy=error_policy,cpu_adapter=cpu_adapter)
    except (KeyError, TypeError, ValueError):
        return None
    matches = []
    transaction_channel=('memory' if cpu_adapter is not None
        and getattr(cpu_adapter,'channel_model','split')=='unified' else 'data')
    for event in events[receipt.event_start:receipt.event_end]:
        transaction = event.get('transaction')
        version = event.get('version')
        observed = event.get('provenance', {}).get('observed_case', {})
        if (event.get('kind') != 'memory_write' or event.get('component') != cpu
                or event.get('address') != address or event.get('value') != value
                or event.get('width_bytes') != 4 or event.get('byte_enable') != 15
                or event.get('memory_id') != memory_id
                or event.get('byte_offset') != address - memory_base
                or type(event.get('generation')) is not int or event['generation'] != memory_generation
                or not isinstance(version, (tuple, list)) or len(version) != 2
                or any(type(item) is not int for item in version)
                or version[0] != event['generation'] or version[1] < 1
                or _transaction_key(transaction) is None
                or transaction['source_component'] != cpu or transaction['channel_id'] != transaction_channel
                or any(transaction.get(key) != transaction_scope.get(key)
                       for key in ('execution_id', 'testcase_id', 'source_component', 'source_epoch'))
                or observed.get('case_id') != receipt.case_id):
            continue
        beat = beats.get(('data', transaction['source_sequence']))
        if (beat is None or beat['address'] != address or beat['write'] != 1
                or beat['value'] != value or beat['byte_enable'] != 15
                or event.get('producer_event_id') != beat['acceptance_event']
                or not beat['acceptance_event'] < event['event_id'] < beat['response_event']):
            continue
        # Both ends of the observation must belong to this submitted case.
        case_ids = set(ids[receipt.event_start:receipt.event_end])
        if beat['acceptance_event'] not in case_ids or beat['response_event'] not in case_ids:
            continue
        matches.append({'memory_write_event': event['event_id'],
                        'acceptance_event': beat['acceptance_event'],
                        'response_event': beat['response_event'],
                        'transaction': dict(transaction)})
    return matches[0] if len(matches) == 1 else None


def observe_ram_read_documentary(*, events, receipt, cpu, address, memory_id,
        memory_base, memory_generation, traces, error_policy, report, cpu_adapter=None):
    """Join historical byte certificates to a completed physical DUT read.

    Pure documentary projection: the caller must obtain report from its actual
    installed provider. Saved reports do not grant authority or policy credit.
    """
    from myfuzz.scenario.edge_provenance import _transaction_key
    if (report.get('journal_integrity') is not True
            or type(receipt.event_start) is not int or type(receipt.event_end) is not int
            or not 0 <= receipt.event_start <= receipt.event_end <= len(events)):
        return None
    try:
        beats = _native_memory_beats(events,cpu=cpu,traces=traces,
                                     error_policy=error_policy,cpu_adapter=cpu_adapter)
        case_events = events[receipt.event_start:receipt.event_end]
        case_ids = {event['event_id'] for event in case_events}
        matches = []
        for read in case_events:
            tx = read.get('fullkey')
            if (read.get('kind') != 'memory_read_issuance'
                    or read.get('component') != cpu or read.get('address') != address
                    or read.get('memory_id') != memory_id
                    or read.get('generation') != memory_generation
                    or read.get('byte_offset') != address - memory_base
                    or read.get('width_bytes') != 4 or _transaction_key(tx) is None
                    or tx['channel_id'] != 'data' or tx['source_component'] != cpu):
                continue
            beat = beats.get(('data', tx['source_sequence']))
            if (beat is None or beat['write'] != 0 or beat['address'] != address
                    or beat['rdata'] != read['value']
                    or beat['acceptance_event'] not in case_ids
                    or beat['response_event'] not in case_ids
                    or not beat['acceptance_event'] <= read['producer_event_id'] < beat['response_event']):
                continue
            relations = []
            for lane in range(4):
                rows = [c for c in report['certificates']
                    if c['proof_scope'] == 'memory_byte_version' and c['validity'] == 'historical'
                    and c['component'] == cpu and c['memory_id'] == memory_id
                    and c['generation'] == memory_generation
                    and c['byte_offset'] == address - memory_base + lane
                    and c['read_event_id'] == read['event_id']
                    and c['read_transaction'] == tx
                    and c['byte_version'] == read['versions'][lane]
                    and c['writer_event_id'] == read['writer_event_ids'][lane]
                    and c['value'] == (read['value'] >> (8 * lane)) & 255]
                if len(rows) != 1:
                    break
                relations.append(dict(rows[0]))
            if len(relations) == 4:
                protocol=cpu_adapter.protocol if cpu_adapter is not None else 'obi'
                matches.append(dict(status='observed', proof_scope=f'historical_dut_{protocol}_read_host_ram_versions',
                    memory_kind='modeled_host_persistent_memory', source_origin='unknown',
                    retirement='unknown', reward_eligible=False, native_authority=False,
                    grants_prerequisites=False, memory_read_event=read['event_id'],
                    acceptance_event=beat['acceptance_event'], response_event=beat['response_event'],
                    byte_relations=relations))
        return matches[0] if len(matches) == 1 else None
    except (KeyError, TypeError, ValueError, IndexError):
        return None


def observe_ram_read_physical(*, events, receipt, cpu, address, memory_id,
        memory_base, memory_generation, traces, error_policy, transaction_scope, cpu_adapter=None):
    """Observe a case-local completed CPU read of host RAM, without writer proof."""
    from myfuzz.scenario.edge_provenance import _transaction_key
    if (type(receipt.event_start) is not int or type(receipt.event_end) is not int
            or not 0 <= receipt.event_start <= receipt.event_end <= len(events)):
        return None
    ids = [event.get('event_id') for event in events]
    if any(type(item) is not int for item in ids) or len(set(ids)) != len(ids):
        return None
    try:
        beats = _native_memory_beats(events, cpu=cpu, traces=traces,
                                     error_policy=error_policy, cpu_adapter=cpu_adapter)
        case_events = events[receipt.event_start:receipt.event_end]
        case_ids = {event['event_id'] for event in case_events}
        channel = ('memory' if cpu_adapter is not None
                   and getattr(cpu_adapter, 'channel_model', 'split') == 'unified' else 'data')
        matches = []
        for read in case_events:
            tx = read.get('transaction')
            observed = read.get('provenance', {}).get('observed_case', {})
            value = read.get('value')
            if (read.get('kind') != 'memory_read' or read.get('component') != cpu
                    or read.get('address') != address or read.get('memory_id') != memory_id
                    or type(read.get('generation')) is not int or read['generation'] != memory_generation
                    or read.get('byte_offset') != address - memory_base or read.get('width_bytes') != 4
                    or type(value) is not int or not 0 <= value < (1 << 32)
                    or _transaction_key(tx) is None or tx['channel_id'] != channel
                    or tx['source_component'] != cpu or observed.get('case_id') != receipt.case_id
                    or any(tx.get(key) != transaction_scope.get(key)
                           for key in ('execution_id', 'testcase_id', 'source_component', 'source_epoch'))):
                continue
            beat = beats.get(('data', tx['source_sequence']))
            producer = read.get('producer_event_id')
            if (beat is None or beat['write'] != 0 or beat['address'] != address
                    or beat['rdata'] != value or beat['acceptance_event'] not in case_ids
                    or beat['response_event'] not in case_ids or type(producer) is not int
                    or not beat['acceptance_event'] <= producer < read['event_id'] < beat['response_event']):
                continue
            protocol = cpu_adapter.protocol if cpu_adapter is not None else 'obi'
            matches.append(dict(status='observed', proof_scope=f'completed_dut_{protocol}_host_ram_read',
                memory_kind='modeled_host_persistent_memory', source_origin='unknown',
                retirement='unknown', reward_eligible=False, native_authority=False,
                grants_prerequisites=False, memory_read_event=read['event_id'],
                acceptance_event=beat['acceptance_event'], response_event=beat['response_event'],
                transaction=dict(tx), address=address, value=value))
        return matches[0] if len(matches) == 1 else None
    except (KeyError, TypeError, ValueError, IndexError):
        return None


def _declared_max_wait(cpu):
    """The CPU's own declared wait bound, or None when not readable."""
    artifact = getattr(cpu, 'artifact', None)
    document = getattr(artifact, 'runtime_document', None)
    declared = document.get('effective_max_wait_cycles') if isinstance(document, dict) else None
    if type(declared) is not int:
        request = getattr(getattr(artifact, 'plan', None), 'request', None)
        declared = getattr(request, 'max_wait_cycles', None)
    return declared if type(declared) is int and declared > 0 else None


def fragment_boundary_park(cpu, address, *, component, rounds, settle=None):
    """Stop one case shortly after its first unmaterialized instruction slot.

    A case advances one host tick at a time, so the host's intentional fetch
    stall would otherwise be charged to the protocol checker for every
    remaining round.  The predicate never stops before ``address`` and never
    counts a park that already existed before this case was submitted.  The
    small settle window keeps the case's target transaction and dependent RAM
    write inside the case; it stays below the CPU's declared wait bound so the
    host's own hold is still not reported as a DUT violation.  ``evidence``
    reports the park that really happened (or its absence); it never infers
    one from the request.
    """
    if type(address) is not int or address < 0 or address % 4:
        raise ValueError('instruction-boundary-address-invalid')
    if type(rounds) is not int or rounds < 1:
        raise ValueError('instruction-boundary-rounds-invalid')
    if settle is None:
        bound = _declared_max_wait(cpu)
        settle = min(max(1, bound - 4), 12) if bound is not None else 1
    if type(settle) is not int or settle < 1:
        raise ValueError('instruction-boundary-settle-invalid')
    stale = cpu.waiting_instruction_address
    observed = []
    stopped = []

    def stop_after_advance(index):
        if type(index) is not int or not 0 <= index < rounds:
            return False
        parked = cpu.waiting_instruction_address
        if parked != address or parked == stale:
            return False
        observed.append(index)
        if len(observed) < settle:
            return False
        stopped.append(index)
        return True

    def evidence(receipt):
        parked = cpu.waiting_instruction_address
        tick = dict(getattr(receipt, 'local_ticks_after', None) or {}).get(component)
        if stopped:
            reason = 'fragment_end_instruction_fetch'
        elif type(parked) is not int:
            reason = 'no_instruction_fetch_park'
        elif parked == address:
            reason = 'pre_submission_instruction_park'
        else:
            reason = 'instruction_fetch_elsewhere'
        return {'address': parked if type(parked) is int else None,
                'expected_address': address,
                'tick': tick if type(tick) is int else None,
                'settle_advances': settle,
                'park_observations': len(observed),
                'stopped_after_advance': stopped[0] if stopped else None,
                'reason': reason}

    return stop_after_advance, evidence


def _live_transaction_scope(runtime):
    """Transaction scope the live CPU really stamps on its own beats.

    The four shared CPU sessions number their transactions under the
    ``local-execution`` literal.  A generated session that keys them with its
    own launch nonce declares that through ``transaction_execution_id``; the
    F1/F3 observers then compare a case's transactions with the live session's
    *actual* scope instead of a hardcoded one.  Every other field comes from
    the bound runtime, so the comparison is never widened.
    """
    cpu = runtime.runner.sessions[runtime.cpu_id]
    execution_id = getattr(cpu, 'transaction_execution_id', None)
    if type(execution_id) is not str or not execution_id:
        execution_id = 'local-execution'
    return {'execution_id': execution_id,
            'testcase_id': runtime.session.template.testcase_id,
            'source_component': runtime.cpu_id,
            'source_epoch': cpu.reset_epoch}


def submit_memory_case(runtime, raw, *, flow, testcase_id=None):
    """Submit one instruction fragment to the runtime's existing session."""
    from myfuzz.scenario.batch import BatchAdvance
    from myfuzz.scenario.rv32i_sources import MmioWindow, fragment_bytes, mmio_write_fragment
    from myfuzz.scenario.session_runtime import BoundOnlineInstruction, OnlineCase
    if flow not in ('F1', 'F3') or type(raw) is not bytes or len(raw) != 4:
        raise ValueError('memory-case-shape')
    runtime._stable()
    if len(runtime.records) >= runtime.max_cases:
        raise ValueError('memory-case-budget-exhausted')
    code, operation, ram_address = lower_memory_code(runtime, raw, flow=flow)
    # Leave the CPU to stall at the next unmaterialized slot between cases.
    code += b'\x13\x00\x00\x00' * 4
    adapter=getattr(runtime,'cpu_adapter',None)
    if adapter is not None:
        # A wider instruction fetch can cover a partially supplied fragment.
        # Use the same protocol-declared padding as the F2/F4 slot compiler.
        from hashlib import sha256
        declaration=adapter.prepare_declaration(dict(code_hex=code.hex(),code_sha256=sha256(code).hexdigest()),
            address=runtime.cursor)
        code=bytes.fromhex(declaration['code_hex'])
    if runtime.cursor + len(code) > runtime.result - 4:
        raise ValueError('memory-case-slot-exhausted')
    binding = runtime.memory_bindings[flow]
    index = len(runtime.records)
    case_id = testcase_id or f'{runtime.run_id}:{index}'
    source_id = f'{binding.source_id}:{index}'
    case = OnlineCase(case_id, 'CPU_TO_IP', binding.path_id,
        BoundOnlineInstruction(source_id, runtime.cpu_id, runtime.cursor, code.hex(), binding.source_id),
        tuple(BatchAdvance(tuple(runtime.runner.sessions)) for _ in range(runtime.rounds)))
    # The case ends where the CPU parks on this fragment's first unmaterialized
    # slot, so host-caused wait cycles stay within the declared budget.
    stop_after_advance, park_evidence = fragment_boundary_park(
        runtime.runner.sessions[runtime.cpu_id], runtime.cursor + len(code),
        component=runtime.cpu_id, rounds=runtime.rounds)
    runtime._stable()
    receipt = runtime.session.submit_case(case, stop_after_advance=stop_after_advance)
    if receipt.violations or receipt.status != 'running':
        raise ValueError('memory-case-session-failed')
    transaction_scope = _live_transaction_scope(runtime)
    observation = None
    if flow == 'F3':
        observation = _observe_f3_write(events=runtime.runner.events_since(0), receipt=receipt,
            cpu=runtime.cpu_id, address=runtime.result - 4, value=int.from_bytes(raw, 'little'),
            memory_id=runtime.image['port'], memory_base=runtime.image['range'][0],
            memory_generation=runtime.runner.sessions[runtime.cpu_id].memory.generation,
            traces=runtime.traces, error_policy=runtime.error_policy,
            cpu_adapter=getattr(runtime,'cpu_adapter',None),
            transaction_scope=transaction_scope)
    read_observation = physical_read = None
    if operation == 'ram_read_word':
        from myfuzz.scenario.memory_dependency_evidence import MemoryDependencyEvidenceConsumer
        provider = runtime.runner._memory_dependency_consumer
        if type(provider) is MemoryDependencyEvidenceConsumer:
            read_observation = observe_ram_read_documentary(
                events=runtime.runner.events_since(0), receipt=receipt, cpu=runtime.cpu_id,
                address=ram_address, memory_id=runtime.image['port'],
                memory_base=runtime.image['range'][0],
                memory_generation=runtime.runner.sessions[runtime.cpu_id].memory.generation,
                traces=runtime.traces, error_policy=runtime.error_policy,
                cpu_adapter=getattr(runtime,'cpu_adapter',None),
                report=MemoryDependencyEvidenceConsumer.report(provider))
        if read_observation is None:
            physical_read = observe_ram_read_physical(
                events=runtime.runner.events_since(0), receipt=receipt, cpu=runtime.cpu_id,
                address=ram_address, memory_id=runtime.image['port'],
                memory_base=runtime.image['range'][0],
                memory_generation=runtime.runner.sessions[runtime.cpu_id].memory.generation,
                traces=runtime.traces, error_policy=runtime.error_policy,
                cpu_adapter=getattr(runtime, 'cpu_adapter', None),
                transaction_scope=transaction_scope)
    result = {'schema_version': 'compiled_memory_case.v1', 'status': 'submitted',
              'flow_id': flow, 'case_id': case_id, 'instruction_source_id': source_id,
              'action_grammar': MEMORY_ACTION_GRAMMAR, 'operation': operation,
              'ram_address': ram_address,
              'instruction_address': runtime.cursor, 'instruction_hex': code.hex(),
              'memory_read': 'observed' if read_observation or physical_read else 'unknown',
              'memory_read_observation': read_observation,
              'retirement': 'unknown',
              'instruction_to_store_causality': 'unknown',
              'memory_store': 'observed' if observation else 'unknown',
              'memory_store_scope': 'case_during_cpu_data_write' if observation else 'unknown',
              'memory_write_event': observation['memory_write_event'] if observation else None,
              'memory_store_observation': observation,
              'instruction_boundary_park': park_evidence(receipt)}
    if physical_read is not None:
        result['memory_read_physical_observation'] = physical_read
    runtime.records.append({'raw': raw.hex(), 'flow': flow, 'certificate': result})
    runtime.cursor += len(code)
    return result


def prepare_memory_paths(*, request, compiled):
    """Recompile and bind F1/F3 image paths without starting a session."""
    if compiled_document_sha256(compile_paths(request)) != compiled_document_sha256(compiled):
        raise ValueError('memory-path-compiled-identity-changed')
    graph = DependencyGraph.from_edge_document(compiled['runtime_dependency_graph'])
    contract = RuntimePathContract.from_document(compiled['runtime_path_contract'])
    selected = []
    bindings = []
    for flow, expected_edges in (('F1', 1), ('F3', 2)):
        rows = [row for row in compiled['paths']
                if row['flow_id'] == flow and row['status'] == 'executable']
        if len(rows) != 1:
            raise ValueError('memory-path-one-executable-required:' + flow)
        row = rows[0]
        images = [source for source in row['sources']
                  if source['kind'] == 'instruction_image' and source['origin'] == 'fuzzable']
        stores = [source for source in row['sources'] if source['kind'] == 'cpu_store_stream']
        if len(images) != 1 or (flow == 'F3' and (len(stores) != 1 or stores[0]['origin'] != 'fuzzable')):
            raise ValueError('memory-path-source-required:' + flow)
        image = images[0]
        resources = [r for r in request.wiring.resources
                     if r.resource_id == image['port'] and r.component_instance == image['component']]
        if len(resources) != 1:
            raise ValueError('memory-path-resource-required:' + flow)
        resource = resources[0]
        if (resource.component_instance != request.cpu.instance_id
                or resource.read is not True or resource.write is not True
                or resource.execute is not True or resource.initialization_policy != 'preload'
                or type(resource.base) is not int or type(resource.size) is not int or resource.size < 16
                or image['range'] != [resource.base, resource.base + resource.size - 1]
                or image['width'] != resource.size * 8):
            raise ValueError('memory-path-resource-mismatch:' + flow)
        # ``stores[0]['width']`` is the CPU's *declared* data width, i.e. the
        # widest store its data port can issue (32 for the 32-bit rows, 64 for a
        # 64-bit port such as the packed CVA6).  The F3 fragment itself always
        # lowers to one 32-bit store, and ``_observe_f3_write`` requires exactly
        # that on the beat (``width_bytes == 4`` and ``byte_enable == 0xf``), so
        # a wider port is admitted here while the measured store stays 4 bytes.
        if flow == 'F3' and (stores[0]['component'] != request.cpu.instance_id
                or stores[0]['range'] != image['range']
                or type(stores[0]['width']) is not int
                or stores[0]['width'] < 32 or stores[0]['width'] % 8
                or stores[0]['alignment'] != 4):
            raise ValueError('memory-path-store-source-mismatch')
        identity = row['runtime_path_identity']
        if type(identity) is not dict or identity.get('direction') != row['direction'] or row['direction'] != 'CPU_TO_IP':
            raise ValueError('memory-path-runtime-identity-required:' + flow)
        path = DependencyPath(row['target']['node'], tuple(identity['source_ids']),
                              tuple(DependencyEdge(**edge) for edge in identity['edges']))
        runtime_id = graph.path_identity(path, direction=row['direction'])
        if (runtime_id != identity['path_id'] or len(path.source_ids) != 1
                or len(path.edges) != expected_edges
                or any(edge.kind != 'PERSISTENT_STATE_RULE' for edge in path.edges)):
            raise ValueError('memory-path-runtime-identity-mismatch:' + flow)
        declarations = {(edge.rule_index, edge.prerequisite_index): edge for edge in contract.edges}
        for edge in path.edges:
            declared = declarations[(edge.rule_index, edge.prerequisite_index)]
            if (declared.relation, declared.resource_component, declared.resource_id) != (
                    'persistent_state', resource.component_instance, resource.resource_id):
                raise ValueError('memory-path-resource-edge-mismatch:' + flow)
        binding = InstructionImageSourceBinding(path_id=runtime_id, direction=row['direction'],
            source_id=path.source_ids[0], logical_source_id=image['source_id'],
            component=image['component'], memory_id=image['port'], base=resource.base,
            size=resource.size, readable=True, writable=True)
        selected.append((row['direction'], path))
        bindings.append(binding)
    prepared = PreparedRuntimePathContract(graph, contract, tuple(selected))
    for binding in bindings:
        binding.validate_prepared(prepared)
    return prepared, tuple(bindings)
