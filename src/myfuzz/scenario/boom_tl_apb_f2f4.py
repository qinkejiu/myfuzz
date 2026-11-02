"""BOOM RV64 coherent TileLink to a real APB3 IP: directed F2/F4 campaign.

Scope and honesty
-----------------
The generic executor (:mod:`myfuzz.integration.compiled_mmio`) cannot drive
this CPU; see :mod:`myfuzz.integration.cpu_tlul` for the machine-checked gap
list.  This module is **not** that executor and never claims its admission: it
runs the pinned BOOM harness through the *standard* :class:`ScenarioRunner`
scheduler, the standard :class:`DataflowRouter`, and a real generated PULP
APB3 target session, and records what the real RTL actually did.

What is proven per case
-----------------------
* one accepted CPU TileLink A beat toward the declared uncached page
  (``opcode``/``size``/``mask``/``data`` from the pin trace),
* the router's delivery of that accepted request to the real IP session,
* the IP session's own recorded APB access (offset/write/value/readback),
* the CPU's accepted D beat carrying the read value back,
* the CPU's own dependent store of that value into its native RAM, observed
  as the session's ``ram_<addr>`` output,
* for F4, the read value equals the written value (register is ``rw``).

What is deliberately *not* claimed
----------------------------------
No instruction retirement, no RAM byte version, no cross-case provenance, no
DUT-internal correctness, no ``compiled_mmio`` admission, and no claim that
the flows share one process: the pinned BOOM harness freezes its instruction
image before the first measured edge, so every case is its own native process.

Two flows, two record shapes
----------------------------
``F4`` record = 4-byte little-endian value written to the register; the CPU
then reads the same register back and stores the readback.

``F2`` record = 4-byte little-endian *address* of the register (the same
shape ``compiled_mmio`` admits); the value the CPU reads is established by the
target session's declared ``setup_writes`` before the core's first edge,
because a per-case process cannot inherit a previous case's write.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import sys
from pathlib import Path

from .genome import ScenarioGenome

from .router import DataflowRouter, DeviceWindow
from .runner import ScenarioRunner

#: Pinned uncached page of the generated BOOM harness (``boom_cpu_driver.cpp``
#: accepts ``EXTERNAL`` only inside ``0x4000..0x5000``; the profile README
#: records these as "legal uncached locations in the emitted map").
WINDOW_BASE = 0x4000
WINDOW_SIZE = 0x1000
#: PULP APB I2C ``PRESCALER``: offset 0, 32-bit, ``rw``, write/read mask
#: ``0xffff`` (``test_capability.json`` of the sibling OBI descriptor).
REGISTER = 'PRESCALER'
REGISTER_OFFSET = 0
REGISTER_ADDRESS = WINDOW_BASE + REGISTER_OFFSET
REGISTER_WRITE_MASK = 0xffff
#: Native RAM word the CPU stores its dependent result into.  Unaligned to the
#: uncached page on purpose: the harness RAM model serves it directly.
RESULT = 0x3000
PROGRAM_BASE = 0x80000000
PROGRAM_BYTES = 256
#: ScenarioRunner component name of the real generated APB3 target.
TARGET_COMPONENT = 'i2c'
#: ScenarioRunner component name of the real BOOM CPU session.
CPU_COMPONENT = 'cpu'
F2_XOR_CONSTANT = 0x5a5
F2_PROFILE = 'configs/peripherals/pulp_i2c/component_profile.json'
#: Artifact kind of the pinned generated CPU session (its own declared kind).
CPU_ARTIFACT_KIND = 'tilelink_coherent_cpu'
#: F2 source values, in campaign order.  Each one is written by the declared
#: target-side ``setup_writes`` before the core's first edge, because a
#: per-case native process cannot inherit a previous case's register write.
F2_SOURCE_VALUES = (0x0055, 0x00aa, 0x1234, 0x4321, 0xbeef, 0x7fff)


# ---------------------------------------------------------------------------
# RV64 instruction encoding (the emitted words are legal RV64I; the operands
# are 32-bit bus addresses so the 4-byte RV32 subset applies unchanged)
# ---------------------------------------------------------------------------
def _lui(rd, immediate):
    return (immediate & 0xfffff) << 12 | rd << 7 | 0x37


def _addi(rd, rs1, immediate):
    return (immediate & 0xfff) << 20 | rs1 << 15 | rd << 7 | 0x13


def _lw(rd, rs1, immediate=0):
    return (immediate & 0xfff) << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x03


def _sw(rs2, rs1, immediate=0):
    value = immediate & 0xfff
    return ((value >> 5) << 25) | rs2 << 20 | rs1 << 15 | 2 << 12 | ((value & 31) << 7) | 0x23


def _xori(rd, rs1, immediate):
    return (immediate & 0xfff) << 20 | rs1 << 15 | 4 << 12 | rd << 7 | 0x13


FENCE_IORW = 0x0ff0000f
JAL_SELF = 0x0000006f
NOP = 0x00000013


def _split(address):
    low = ((address & 0xfff) + 0x800) % 0x1000 - 0x800
    return ((address - low) >> 12) & 0xfffff, low


def _address_setup(rd, address):
    high, low = _split(address)
    return [_lui(rd, high), _addi(rd, rd, low)]


def _image(words):
    """Pad to whole 64-byte lines, exactly like the pinned directed images."""
    if len(words) * 4 > PROGRAM_BYTES:
        raise ValueError('BOOM program image too long')
    words = list(words) + [NOP] * (PROGRAM_BYTES // 4 - len(words))
    return b''.join(word.to_bytes(4, 'little') for word in words)


def f4_program(address, value, result_address=RESULT):
    """``SW`` the value, order it, ``LW`` the same word, store the readback."""
    value &= REGISTER_WRITE_MASK
    words = (_address_setup(1, address) + _address_setup(2, value)
             + [_sw(2, 1), FENCE_IORW, _lw(3, 1)]
             + _address_setup(4, result_address) + [_sw(3, 4), JAL_SELF])
    return _image(words)


def f2_program(address, xor_constant=F2_XOR_CONSTANT, result_address=RESULT):
    """``LW`` the register, XOR the constant, store the result into RAM."""
    words = (_address_setup(1, address) + [_lw(3, 1), _xori(3, 3, xor_constant)]
             + _address_setup(4, result_address) + [_sw(3, 4), JAL_SELF])
    return _image(words)


# ---------------------------------------------------------------------------
# real generated target
# ---------------------------------------------------------------------------
def target_artifact(repo: Path):
    """Render the real PULP APB I2C local-harness artifact (no process)."""
    from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
                                      render_local_harness, render_local_runtime,
                                      verify_local_source_lock)
    from myfuzz.local_harness.driver_renderer import render_local_driver
    request = load_local_harness_request(json.loads(
        (repo / 'configs/peripherals/pulp_i2c/shared_target_request.json').read_text()))
    plan = plan_local_harness(request, base_dir=repo)
    runtime = render_local_runtime(
        plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=repo), base_dir=repo)
    return render_local_driver(runtime, base_dir=repo)


def target_ownership(artifact, component_id: str):
    """Declare exactly the target's own physical inputs, from the artifact.

    The real generated target validates the Runner's bit owners against its
    own ``dynamic``/``bound``/``fixed`` input rows, so the declaration is read
    from those rows instead of being guessed.  A dynamic (fuzzable) input would
    need a fuzzed value and is refused here: this campaign drives none.
    """
    from .ownership import InputField, InputOwner, compile_ownership
    document = artifact.runtime_document
    if document.get('dynamic_physical_inputs'):
        raise ValueError('BOOM-directed-target-has-fuzzable-inputs')
    fields, owners = [], []
    for row in document.get('bound_physical_inputs') or ():
        fields.append(InputField(component_id, row['input_name'], row['width']))
        owners.append(InputOwner(component_id, row['input_name'], 0, row['width'],
                                 'bound', row['producer_ref']))
    for row in document.get('fixed_physical_inputs') or ():
        name = row['endpoint_id'] + '.' + row['role']
        fields.append(InputField(component_id, name, row['width']))
        owners.append(InputOwner(component_id, name, 0, row['width'],
                                 'fixed', 'profile_constant'))
    return compile_ownership(tuple(fields), tuple(owners))


@dataclass(frozen=True)
class CasePlan:
    """One directed case: the flow, its fuzz-visible record, and its image."""

    flow: str
    raw: bytes
    setup_value: int
    program_sha256: str
    image: bytes

    @property
    def expected_readback(self):
        return self.setup_value & REGISTER_WRITE_MASK

    @property
    def expected_result(self):
        if self.flow == 'F2':
            return self.expected_readback ^ F2_XOR_CONSTANT
        return self.expected_readback


def plan_f4(raw: bytes, *, address=REGISTER_ADDRESS) -> CasePlan:
    """F4: the record is the written value; the readback must equal it."""
    if type(raw) is not bytes or len(raw) != 4:
        raise ValueError('BOOM-F4-record-shape')
    value = int.from_bytes(raw, 'little')
    if value > REGISTER_WRITE_MASK:
        raise ValueError('BOOM-F4-value-exceeds-declared-write-mask')
    image = f4_program(address, value)
    return CasePlan('F4', raw, value, sha256(image).hexdigest(), image)


def plan_f2(raw: bytes, *, source_value: int, address=REGISTER_ADDRESS) -> CasePlan:
    """F2: the record is the declared register address; setup presets a value."""
    if type(raw) is not bytes or len(raw) != 4:
        raise ValueError('BOOM-F2-record-shape')
    if int.from_bytes(raw, 'little') != address:
        raise ValueError('BOOM-F2-record-address-mismatch')
    if type(source_value) is not int or not 0 <= source_value <= REGISTER_WRITE_MASK:
        raise ValueError('BOOM-F2-source-value')
    image = f2_program(address)
    return CasePlan('F2', raw, source_value, sha256(image).hexdigest(), image)


# ---------------------------------------------------------------------------
# one real-RTL case
# ---------------------------------------------------------------------------
def _rows(events, kind):
    return [row for row in events if row.get('kind') == kind]


def run_case(*, repo: Path, cpu_output: Path, cache_dir: Path, plan: CasePlan,
             artifact, case_id: str, max_edges: int = 20000) -> dict:
    """Boot the real RV64 core, let it talk to the real IP, and record facts."""
    import time
    from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
    from myfuzz.local_harness.boom_scenario_session import GeneratedBoomScenarioSession
    if plan.flow not in ('F2', 'F4'):
        raise ValueError('BOOM-directed-flow')
    if type(max_edges) is not int or not 1 <= max_edges <= 250000:
        raise ValueError('BOOM-directed-edge-bound')
    repo = repo.resolve()
    target = None
    cpu = None
    router = None
    started = time.time()
    error = None
    outputs = {}
    edges = 0
    try:
        target = GeneratedApb3RegisterSession(
            artifact, base_dir=repo, cache_dir=cache_dir,
            setup_writes=((REGISTER_OFFSET, plan.setup_value),)
            if plan.flow == 'F2' else ())
        router = DataflowRouter((DeviceWindow(TARGET_COMPONENT, WINDOW_BASE,
                                             WINDOW_SIZE, target),))
        cpu = GeneratedBoomScenarioSession(
            cpu_output, repo=repo, router=router, program=plan.image,
            source_component=CPU_COMPONENT, observed_ram_addresses=(RESULT,))
        runner = ScenarioRunner(
            sessions={CPU_COMPONENT: cpu, TARGET_COMPONENT: target},
            ownership=target_ownership(artifact, TARGET_COMPONENT), bindings=())
        runner.begin_test(case_id)
        for edge in range(max_edges):
            outputs = runner.step(CPU_COMPONENT)
            runner.step(TARGET_COMPONENT)
            edges = edge + 1
            observed = outputs.get(f'ram_{RESULT:x}')
            if (observed is not None and observed & 0xffffffff == plan.expected_result
                    and outputs.get('drained') == 1
                    and not router.pending_targets and not cpu.pending_responses
                    and not cpu.mmio_ledger.unresolved_keys):
                break
        else:
            raise TimeoutError('BOOM directed case exceeded its edge bound')
        # Snapshot the live native identity and journals before finalize drops
        # the native process handle.
        snapshot = {
            'execution_id': cpu._native.execution_id,
            'runtime_events': list(cpu.runtime_events),
            'source_events': list(cpu.source_events),
            'coherent_report': cpu.coherent_report(),
            'local_ticks': cpu.local_ticks,
            'deliveries': list(router.deliveries),
            'transactions': list(target.local_transactions),
            'reset_epoch': cpu.reset_epoch,
            'runner_events': list(runner.events),
        }
        runner.finalize()
    except BaseException as exc:  # noqa: BLE001 - the failure is the evidence
        error = {'type': type(exc).__name__, 'message': str(exc)[:400]}
        for session in (cpu, target):
            try:
                if session is not None:
                    session.end_case()
            except BaseException:
                pass
        snapshot = None
    wall = round(time.time() - started, 2)
    if error is not None:
        return {'case_id': case_id, 'flow': plan.flow, 'raw': plan.raw.hex(),
                'status': 'failed', 'error': error, 'wall_seconds': wall,
                'edges': edges}
    return _certificate(plan=plan, case_id=case_id, snapshot=snapshot,
                        outputs=outputs, edges=edges, wall=wall)


def _native_rows(snapshot):
    """Every accepted A/C/D/E beat, unwrapped from the stream record."""
    rows = []
    for row in snapshot['runtime_events']:
        if row.get('kind') != 'coherent_accepted_raw':
            continue
        native = row.get('native_event')
        if not isinstance(native, dict):
            continue
        rows.append({**native,
                     'stream_event_id': row.get('raw_event_id', row.get('event_id')),
                     'local_tick': row.get('local_tick')})
    return rows


def _transfer_rows(snapshot, kind):
    return [row for row in snapshot['runner_events'] if row.get('kind') == kind]


def _apb_samples(snapshot):
    """Real APB pre samples where the IP saw a selected, enabled transfer."""
    rows = []
    for row in snapshot['runner_events']:
        if (row.get('kind') != 'local_tick_sample'
                or row.get('component') != TARGET_COMPONENT
                or row.get('phase') != 'pre'):
            continue
        backend = (row.get('outputs') or {}).get('backend') or {}
        if backend.get('trace_psel') != 1 or backend.get('trace_penable') != 1:
            continue
        rows.append({name: backend[name] for name in (
            'trace_paddr', 'trace_pwrite', 'trace_pwdata', 'trace_prdata',
            'trace_pready', 'trace_pslverr')} | {
            'event_id': row.get('event_id'),
            'producer_event_id': row.get('producer_event_id'),
            'local_tick': row.get('local_tick')})
    return rows


def _certificate(*, plan, case_id, snapshot, outputs, edges, wall):
    """Join the accepted A beat, the router delivery, the APB access and D."""
    native = _native_rows(snapshot)
    accepted_a = [row for row in native if row.get('channel') == 'A'
                  and row.get('address') == REGISTER_ADDRESS]
    accepted_d = [row for row in native if row.get('channel') == 'D'
                  and row.get('external') is True]
    result_stores = [row for row in native if row.get('channel') == 'A'
                     and row.get('opcode') in (0, 1)
                     and row.get('address') == RESULT]
    acceptances = _transfer_rows(snapshot, 'mmio_acceptance')
    deliveries = _transfer_rows(snapshot, 'mmio_delivery')
    samples = _apb_samples(snapshot)
    expected_transfers = 2 if plan.flow == 'F4' else 1
    transfers = min(len(accepted_a), len(acceptances), len(deliveries))
    joins = []
    for index in range(transfers):
        delivery = deliveries[index]
        physical = [row for row in samples if row.get('producer_event_id')
                    == delivery.get('producer_event_id')]
        joins.append({
            'source_sequence': delivery.get('source_sequence'),
            'native_A': {key: accepted_a[index].get(key) for key in
                         ('opcode', 'param', 'size', 'mask', 'source', 'address', 'data')},
            'native_A_stream_event_id': accepted_a[index].get('stream_event_id'),
            'acceptance_event_id': acceptances[index].get('event_id'),
            'acceptance_order': acceptances[index].get('acceptance_order'),
            'delivery_event_id': delivery.get('event_id'),
            'delivery_order': delivery.get('delivery_order'),
            'write': delivery.get('write'),
            'write_value': delivery.get('write_value'),
            'read_value': delivery.get('read_value'),
            'target_physical_event_ids': [row['event_id'] for row in physical],
            'target_physical': [{key: row[key] for key in (
                'event_id', 'trace_paddr', 'trace_pwrite', 'trace_pwdata',
                'trace_prdata', 'trace_pready', 'trace_pslverr')} for row in physical],
            'native_D_stream_event_id': (accepted_d[index].get('stream_event_id')
                                         if index < len(accepted_d) else None),
            'native_D_data': (accepted_d[index].get('data')
                              if index < len(accepted_d) else None),
        })
    read_value = next((join['read_value'] for join in joins
                       if join['write'] is False), None)
    observed_ram = outputs.get(f'ram_{RESULT:x}')
    fields = {
        'schema_version': 'boom_tl_apb_directed_case.v1',
        'case_id': case_id,
        'flow_id': plan.flow,
        'executor': 'directed_standard_runner_router',
        'compiled_mmio_admitted': False,
        'generic_router_admitted': False,
        'status': 'observed',
        'raw_record': plan.raw.hex(),
        'register': REGISTER,
        'register_address': REGISTER_ADDRESS,
        'window': [WINDOW_BASE, WINDOW_SIZE],
        'cpu_artifact_kind': CPU_ARTIFACT_KIND,
        'cpu_execution_id': snapshot['execution_id'],
        'cpu_reset_epoch': snapshot['reset_epoch'],
        'program_sha256': plan.program_sha256,
        'program_bytes': len(plan.image),
        'setup_value': plan.setup_value if plan.flow == 'F2' else None,
        'expected_readback': plan.expected_readback,
        'expected_result': plan.expected_result,
        'joins': joins,
        'hops': len(joins),
        'transfers_expected': expected_transfers,
        'read_value': read_value,
        'result_value': plan.expected_result,
        'ram_result': None if observed_ram is None else observed_ram & 0xffffffff,
        'result_stores': [
            {'stream_event_id': row.get('stream_event_id'),
             'opcode': row.get('opcode'), 'size': row.get('size'),
             'mask': row.get('mask'), 'address': row.get('address'),
             'data': row.get('data')}
            for row in result_stores],
        'target_physical_transfers': len(samples),
        'target_physical_matched': sum(len(join['target_physical']) for join in joins),
        'cpu_edges': edges,
        'cpu_local_ticks': snapshot['local_ticks'],
        'coherent_report': snapshot['coherent_report'],
        'structural_ok': not snapshot['coherent_report'].get('structural_error'),
        'instruction_boundary_park': None,
        'park_scope': ('not_applicable: the pinned BOOM harness freezes its '
                       'instruction image before the first measured edge'),
        'internal_storage_version': 'unknown',
        'cross_case_origin': 'unknown',
        'isa_retirement_authority': False,
        'reward_eligible': False,
        'wall_seconds': wall,
    }
    fields['case_pass'] = _case_pass(fields, accepted_d, result_stores,
                                     fields['target_physical_matched'],
                                     expected_transfers)
    return fields


def _case_pass(certificate, accepted_d, result_stores, physical_count,
               expected_transfers):
    """Require the whole chain; a completed schedule alone is not a pass."""
    joins = certificate['joins']
    if certificate['structural_ok'] is not True:
        return False
    if len(joins) != expected_transfers or physical_count != expected_transfers:
        return False
    if len(result_stores) != 1 or len(accepted_d) != expected_transfers:
        return False
    if certificate['ram_result'] != certificate['expected_result']:
        return False
    if certificate['read_value'] != certificate['expected_readback']:
        return False
    for join in joins:
        if len(join['target_physical']) != 1:
            return False
        physical = join['target_physical'][0]
        if physical['trace_paddr'] != REGISTER_OFFSET or physical['trace_pready'] != 1:
            return False
        if physical['trace_pslverr'] != 0:
            return False
        if join['write']:
            if (physical['trace_pwrite'] != 1
                    or physical['trace_pwdata'] != certificate['expected_readback']):
                return False
        else:
            if physical['trace_pwrite'] != 0:
                return False
            if physical['trace_prdata'] != join['read_value']:
                return False
            if join['native_D_data'] is None:
                return False
    if certificate['flow_id'] == 'F4':
        write, read = joins
        if not write['write'] or read['write']:
            return False
        if read['read_value'] != (write['write_value'] & REGISTER_WRITE_MASK):
            return False
    store = result_stores[0]
    if store['size'] != 2 or store['mask'] != 0x0f or store['opcode'] not in (0, 1):
        return False
    return (store['data'] & 0xffffffff) == certificate['expected_result']


# ---------------------------------------------------------------------------
# campaign
# ---------------------------------------------------------------------------
def run_campaign(*, repo: Path, cpu_output: Path, cache_dir: Path, flow: str,
                 records, output: Path, max_edges: int = 20000,
                 scenario_id: str = 'boom-tl-apb-i2c-directive') -> dict:
    """Run every record as its own real native process and export evidence."""
    if flow not in ('F2', 'F4'):
        raise ValueError('BOOM-directed-flow')
    if type(records) not in (list, tuple) or not records:
        raise ValueError('BOOM-directed-records')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    artifact = target_artifact(repo)
    cases = []
    for index, raw in enumerate(records):
        if type(raw) is bytes and len(raw) != 4:
            raise ValueError('BOOM-directed-record-shape')
        if flow == 'F4':
            plan = plan_f4(raw)
        else:
            # The F2 record is the declared register address; the source value
            # comes from this campaign's declared setup table, never the record.
            plan = plan_f2(raw, source_value=F2_SOURCE_VALUES[index % len(F2_SOURCE_VALUES)])
        case_id = f'{scenario_id}:{flow}:{index}'
        print(json.dumps({'case': case_id, 'starting': True}), file=sys.stderr, flush=True)
        case = run_case(repo=repo, cpu_output=cpu_output, cache_dir=cache_dir,
                        plan=plan, artifact=artifact, case_id=case_id,
                        max_edges=max_edges)
        (output / f'case-{index}.json').write_text(json.dumps(case, indent=2) + '\n')
        cases.append(case)
    report = {'schema_version': 'boom_tl_apb_directed_campaign.v1',
              'scenario_id': scenario_id, 'flow_id': flow,
              'case_count': len(cases),
              'passing_cases': sum(1 for case in cases if case.get('case_pass')),
              'all_cases_pass': all(case.get('case_pass') for case in cases),
              'total_wall_seconds': round(sum(case['wall_seconds'] for case in cases), 2),
              'executor': 'directed_standard_runner_router',
              'compiled_mmio_admitted': False,
              'cases': cases}
    (output / f'{flow.lower()}-campaign.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


#: F2 source values, in campaign order.  Each is written by the declared
#: target-side ``setup_writes`` before the core's first edge.
F2_SOURCE_VALUES = (0x0055, 0x00aa, 0x1234, 0x4321, 0xbeef, 0x7fff)


def normalize_cases(report):
    """Drop per-process scope and wall clock; keep every observed field."""
    scope = {'cpu_execution_id', 'wall_seconds', 'cpu_local_ticks'}
    rows = []
    for case in report['cases']:
        rows.append({key: value for key, value in case.items()
                     if key not in scope and key != 'coherent_report'})
    return rows


def compare_fresh(original, fresh):
    """Byte-level comparison after dropping per-process scope."""
    left, right = normalize_cases(original), normalize_cases(fresh)
    if len(left) != len(right):
        return {'matches': False, 'reason': 'case-count'}
    for index, (a, b) in enumerate(zip(left, right)):
        if a != b:
            difference = {key: [a.get(key), b.get(key)]
                          for key in sorted(set(a) | set(b)) if a.get(key) != b.get(key)}
            return {'matches': False, 'reason': 'case-field', 'index': index,
                    'difference': difference}
    return {'matches': True}
