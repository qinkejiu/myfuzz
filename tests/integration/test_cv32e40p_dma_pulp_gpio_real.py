"""CV32E40P → ZipCPU wbdmac → PULP PADOUT → ISR native gates.

The software D3/D4 test is local and does not start RTL processes. Native
positive/fresh and wrong-offset runs are opt-in with
``MYFUZZ_CV32_PULP_DMA_REAL=1``.
"""
from __future__ import annotations

from dataclasses import asdict, is_dataclass, replace
import gzip
import hashlib
import json
import os
from collections.abc import Mapping
from types import MappingProxyType
from pathlib import Path

import pytest

from myfuzz.scenario.cv32e40p_dma_pulp_gpio_example import (
    DMA_BASE, ISR, MAIN, PADOUT_ADDRESS, RESULT, SOURCE, SOURCE_VALUE,
    cv32e40p_dma_pulp_gpio_images,
)
from myfuzz.scenario.cv32e40p_dma_pulp_gpio_runner import (
    make_cv32e40p_dma_pulp_gpio_runner,
)
from myfuzz.scenario.ibex_dma_pulp_gpio_example import GPIO_BASE
from myfuzz.scenario.pulp_gpio_dma_paths import (
    GPIO_PADOUT_OFFSET, PulpGpioD4RouteAdmission,
    prepare_pulp_gpio_dma_runtime_paths,
)
from myfuzz.scenario.replay_normalize import (
    first_gpio_dma_replay_difference,
    normalize_gpio_dma_execution_identities,
)


ROOT = Path(__file__).resolve().parents[2]
RAM_BASE = 0x20000
RAM_SIZE = 0x20000
ROM_BASE = 0x10000
ROM_SIZE = 0x8000
GPIO_SIZE = 0x1000
TESTCASE_ID = 'cv32e40p-wbdmac-pulp-padout-isr'
MAX_ROUNDS = 2000
ROUND = ('dma', 'cpu', 'gpio')


def _plain(value):
    if is_dataclass(value):
        return _plain(asdict(value))
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    return value


def _record_cpu_bus_step(component, outputs, capture):
    if component == 'cpu':
        capture.append(_plain(outputs))
    return outputs


def _save_json(root, name, value):
    root.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(_plain(value), sort_keys=True,
        separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')
    (root / (name + '.json.gz')).write_bytes(gzip.compress(payload, mtime=0))


def _settings(tmp_path):
    cache = Path(os.environ.get('MYFUZZ_CV32_PULP_DMA_CACHE',
        tmp_path / 'cache'))
    evidence = Path(os.environ.get('MYFUZZ_CV32_PULP_DMA_EVIDENCE',
        tmp_path / 'evidence'))
    cache.mkdir(parents=True, exist_ok=True)
    evidence.mkdir(parents=True, exist_ok=True)
    return cache, evidence


def _observe_provider_call(gpio, calls, operation):
    """Count actual provider method entry without changing its pinned method."""
    import sys

    prior_profile = sys.getprofile()
    provider_code = type(gpio).dma_master_target_access.__code__

    def profile(frame, event, arg):
        if (event == 'call' and frame.f_code is provider_code
                and frame.f_locals.get('self') is gpio):
            local = frame.f_locals
            calls.append({
                'source_transaction': _plain(local.get('source_transaction')),
                'address': local.get('address'),
                'offset': local.get('offset'),
                'write': local.get('write'),
                'value': local.get('value'),
                'byte_enable': local.get('byte_enable'),
            })
        if prior_profile is not None:
            prior_profile(frame, event, arg)

    sys.setprofile(profile)
    try:
        return operation()
    finally:
        sys.setprofile(prior_profile)


def _d3_material(root, *, cpu_profile=(
        'configs/cpus/cv32e40p/component_profile.json')):
    from tests.integration.test_p7b_p7c_dma_route_intent import (
        _generate_pulp_gpio_dma_route_d2_d3,
    )

    d2_wiring, request, compiled = _generate_pulp_gpio_dma_route_d2_d3(
        root / 'd3',
        cpu_profile=cpu_profile,
        rom_base=ROM_BASE, rom_size=ROM_SIZE,
        ram_base=RAM_BASE, ram_size=RAM_SIZE)
    # D4's public binder consumes wiring, the prepared DMA graph, and endpoint
    # links; CPU profile identity is carried by the D3 compile request. Pin it
    # here so a sibling CPU's valid wiring cannot be paired with this runner.
    if request.cpu.profile.component_id != 'cv32e40p':
        raise ValueError('D3 CPU profile must match the CV32E40P runner')
    return d2_wiring, request, compiled


def _install_d4(fixture, d3_wiring):
    from unittest.mock import patch

    from myfuzz.scenario.dma_intent_topology_binding import (
        bind_dma_intent_topology,
    )
    from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract
    from tests.integration.test_p7b_p7c_dma_route_intent import (
        _pulp_d4_declaration, _select_dma_read_write_routes,
    )

    runner = fixture.runner
    cpu, dma, gpio = (runner.sessions[name] for name in ('cpu', 'dma', 'gpio'))
    assert cpu.memory is dma.memory_service.memory
    assert gpio.routed_register_access_enabled is True
    assert dma.master_targets[0].endpoint is gpio

    paths = prepare_pulp_gpio_dma_runtime_paths(runner,
        gpio_base=GPIO_BASE, gpio_size=GPIO_SIZE,
        memory_component='cpu', resource_id='ram',
        image_id='dma_payload', image_address=SOURCE)
    declaration = _pulp_d4_declaration(
        d3_wiring, paths.prepared, fixture.dma_endpoint_links)
    assert declaration._prepared_runtime_paths is paths.prepared

    bound_objects = []
    original_bind = PreparedRuntimePathContract.bind

    def bind_spy(prepared, *args, **kwargs):
        bound_objects.append(prepared)
        return original_bind(prepared, *args, **kwargs)

    with patch.object(PreparedRuntimePathContract, 'bind', bind_spy):
        bound = bind_dma_intent_topology(declaration, runner,
            artifact_links=fixture.dma_endpoint_links)
    assert bound_objects == [paths.prepared]
    bound.validate_topology()
    assert bound.document()['tier'] == 'topology_bound'

    read_route, write_route = _select_dma_read_write_routes(paths.prepared)
    admission = PulpGpioD4RouteAdmission(paths.admission, bound,
        path_id=paths.path_id, read_route=read_route,
        write_route=write_route)
    dma.configure_dma_route_admission(admission)
    paths = replace(paths, compiled=bound.runtime_compilation)
    d4_evidence = {
        'binding': bound.document(),
        'bind_count': len(bound_objects),
        'same_prepared_object': bound_objects[0] is paths.prepared,
        'prepared_sha256': paths.prepared.contract.identity_sha256,
        'path_id': paths.path_id,
        'read_route': read_route.document(),
        'write_route': write_route.document(),
        'admission': admission.identity_document(),
    }
    return paths, bound, admission, d4_evidence


def _pad_native_rom(memory, *, destination):
    """Initialize unused ROM bytes so CV32 speculative fetches stay defined."""
    images = cv32e40p_dma_pulp_gpio_images(
        destination_address=destination)
    limit = ROM_BASE + ROM_SIZE
    occupied = sorted((address, address + len(data))
        for address, data in images.items()
        if ROM_BASE <= address < limit)
    padding = []
    cursor = ROM_BASE
    for start, end in occupied:
        if cursor < start:
            size = start - cursor
            data = bytes.fromhex('13000000') * (size // 4)
            memory.preload(cursor, data)
            padding.append({'address': cursor, 'size': size,
                'sha256': hashlib.sha256(data).hexdigest(),
                'instruction': 'addi x0,x0,0'})
        cursor = end
    if cursor < limit:
        size = limit - cursor
        data = bytes.fromhex('13000000') * (size // 4)
        memory.preload(cursor, data)
        padding.append({'address': cursor, 'size': size,
            'sha256': hashlib.sha256(data).hexdigest(),
            'instruction': 'addi x0,x0,0'})
    return padding


def test_cv32_pulp_d3_d4_binds_exact_memory_gpio_and_rejects_mutated_padout(tmp_path):
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    from myfuzz.local_harness.wishbone_dma_scenario_session import (
        GeneratedWishboneDmaScenarioSession,
    )
    from myfuzz.scenario.ledger import TransactionKey

    _d2_wiring, request, compiled = _d3_material(tmp_path)
    assert request.cpu.profile.component_id == 'cv32e40p'
    resources = {row['resource_id']: row
        for row in request.wiring.document['resources']}
    assert {key: (row['component_instance'], row['base'], row['size'],
                  row['read'], row['write'], row['execute'])
            for key, row in resources.items()} == {
        'rom0': ('cpu', ROM_BASE, ROM_SIZE, True, False, True),
        'ram': ('cpu', RAM_BASE, RAM_SIZE, True, True, False),
    }
    f6, = [row for row in compiled['paths'] if row['flow_id'] == 'F6']
    assert f6['status'] == 'unsupported'
    assert f6['reason']['code'] == 'dma-route-live-topology-binding-required'
    assert f6['runtime_path_identity'] is None
    assert not any(edge.get('kind') == 'DMA_MASTER_TRANSFER'
        for edge in compiled['runtime_dependency_graph']['edges'])

    fixture = make_cv32e40p_dma_pulp_gpio_runner(cache_dir=tmp_path / 'cache')
    try:
        runner = fixture.runner
        cpu, dma, gpio = (runner.sessions[name]
            for name in ('cpu', 'dma', 'gpio'))
        assert type(cpu) is GeneratedCve2Session
        assert type(dma) is GeneratedWishboneDmaScenarioSession
        assert type(gpio) is GeneratedPulpGpioSession
        assert cpu.artifact.plan.profile.component_id == 'cv32e40p'
        assert cpu.memory is dma.memory_service.memory
        assert cpu.memory.identity_document()['regions'] == [
            {'memory_id': 'rom0', 'base': ROM_BASE, 'size': ROM_SIZE,
                'aliases': (), 'readable': True, 'writable': False},
            {'memory_id': 'ram', 'base': RAM_BASE, 'size': RAM_SIZE,
                'aliases': (), 'readable': True, 'writable': True},
        ]
        rom_padding = _pad_native_rom(cpu.memory, destination=PADOUT_ADDRESS)
        source_images = cv32e40p_dma_pulp_gpio_images(
            destination_address=PADOUT_ADDRESS)
        terminal_jal = ROM_BASE + len(source_images[MAIN]) - 4
        assert cpu.memory.read(terminal_jal, 4,
            transaction_id='cv32-pulp-terminal-jal').value == 0x0000006F
        sequential_fetch = terminal_jal + 4
        assert cpu.memory.read(sequential_fetch, 4,
            transaction_id='cv32-pulp-sequential-nop').value == 0x00000013
        assert cpu.memory.read(ISR, 4,
            transaction_id='cv32-pulp-isr-overlay').value == int.from_bytes(
                source_images[ISR][:4], 'little')
        assert rom_padding and any(row['address'] <= sequential_fetch <
            row['address'] + row['size'] for row in rom_padding)
        with pytest.raises(ValueError, match='read-only memory'):
            cpu.memory.validate_write(sequential_fetch, 0, width_bytes=4,
                byte_enable=15)
        assert cpu.memory.read(SOURCE, 4,
            transaction_id='cv32-pulp-d3-source').value == SOURCE_VALUE
        assert gpio.routed_register_access_enabled is True
        assert dma.master_targets[0].endpoint is gpio
        assert dma.master_targets[0].writable_offsets == (GPIO_PADOUT_OFFSET,)

        paths, bound, admission, evidence = _install_d4(
            fixture, request.wiring)
        assert paths.image_address == SOURCE
        assert bound.runtime_compilation.document()['contract_sha256'] == \
            paths.prepared.contract.identity_sha256
        assert [(route.key, route.target_kind, route.target_component,
                 route.target_id, route.base, route.size, route.operation)
                for route in bound.runtime_compilation.dma_master_routes] == [
            ((0, 0), 'persistent_memory', 'cpu', 'ram',
                RAM_BASE, RAM_SIZE, 'read'),
            ((2, 0), 'peripheral', 'gpio', 'gpio',
                GPIO_BASE, GPIO_SIZE, 'write'),
        ]
        assert evidence['bind_count'] == 1
        assert evidence['same_prepared_object'] is True
        assert dma._dma_route_admission is admission

        provider_calls = []
        wrong_key = TransactionKey('cv32-d4-run', 'cv32-d4-wrong-offset',
            'dma', 0, 'dma-memory', 1)
        with pytest.raises(ValueError):
            _observe_provider_call(gpio, provider_calls, lambda:
                admission.accepted(wrong_key,
                    address=PADOUT_ADDRESS + 4, write=True,
                    value=SOURCE_VALUE, byte_enable=15, target=gpio))
        assert admission.route_matches == []
        assert admission.state == 'expect_read'
        assert provider_calls == []
        assert gpio.gpio_events == []
        assert runner._irq_pulses[next(iter(runner.bindings))].events == []
    finally:
        for session in fixture.runner.sessions.values():
            session.end_case()


def test_wrong_cpu_profile_d3_is_rejected_before_cv32_native_runner(tmp_path):
    with pytest.raises(ValueError,
            match='D3 CPU profile must match the CV32E40P runner'):
        _d3_material(tmp_path, cpu_profile=(
            'configs/cpus/ibex_obi_local/component_profile.json'))


def test_mutated_cv32_profile_fingerprint_is_rejected_before_native_execution(tmp_path):
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.scenario.compiled_paths import (
        compile_paths, load_path_compile_request,
    )
    from myfuzz.scenario.dma_intent_topology_binding import DmaIntentBindingError

    d2_wiring, original_request, _compiled = _d3_material(tmp_path)
    profile = json.loads((ROOT / (
        'configs/cpus/cv32e40p/component_profile.json')).read_text(
            encoding='utf-8'))
    profile['description'] += ' Same-component fingerprint mismatch test.'
    mutated_profile = tmp_path / 'cv32e40p-mutated-profile.json'
    mutated_profile.write_text(json.dumps(profile), encoding='utf-8')
    mutated_fingerprint = load_component_profile(profile).profile_fingerprint
    # D2 local harness requests require a configs/ relative path. D3 accepts
    # the copied profile directly; carry its fingerprint into the RAM owner
    # binding so D3 compilation is valid and D4 sees the actual contradiction.
    for binding in d2_wiring['dma_master_route_bindings']:
        if binding['route_id'] == 'route.ram-read':
            binding['target']['owner_profile_fingerprint'] = mutated_fingerprint
    mutated_wiring = tmp_path / 'mutated-wiring.json'
    mutated_wiring.write_text(json.dumps(d2_wiring), encoding='utf-8')
    compile_document = _plain(original_request.document)
    compile_document['cpu']['profile'] = str(mutated_profile)
    compile_document['wiring'] = {'source': str(mutated_wiring)}
    compile_path = tmp_path / 'mutated-path-compile-request.json'
    compile_path.write_text(json.dumps(compile_document), encoding='utf-8')
    request = load_path_compile_request(compile_path, base_dir=ROOT)
    compiled = compile_paths(request)
    assert request.cpu.profile.component_id == 'cv32e40p'
    assert request.cpu.profile.profile_fingerprint == mutated_fingerprint
    assert next(row for row in compiled['paths']
        if row['flow_id'] == 'F6')['status'] == 'unsupported'

    fixture = make_cv32e40p_dma_pulp_gpio_runner(cache_dir=tmp_path / 'cache')
    try:
        runner = fixture.runner
        cpu = runner.sessions['cpu']
        assert cpu.artifact.plan.profile.component_id == 'cv32e40p'
        assert request.cpu.profile.profile_fingerprint != \
            cpu.artifact.plan.profile.profile_fingerprint
        assert all(session.process is None
            for session in runner.sessions.values())
        assert cpu.local_ticks == runner.local_ticks['cpu'] == 0
        with pytest.raises(DmaIntentBindingError) as rejected:
            _install_d4(fixture, request.wiring)
        assert rejected.value.code == 'dma-binding-template-mismatch'
        assert rejected.value.pointer == '/route_links/1/endpoint_link/target'
        assert all(session.process is None
            for session in runner.sessions.values())
        assert cpu.local_ticks == runner.local_ticks['cpu'] == 0
    finally:
        for session in reversed(tuple(fixture.runner.sessions.values())):
            session.end_case()


def test_cpu_step_capture_accepts_scenario_runner_mapping_output():
    captured = []
    output = MappingProxyType({'data_req_accepted': 1,
        'data_addr': DMA_BASE, 'data_wdata': SOURCE})
    assert _record_cpu_bus_step('cpu', output, captured) is output
    assert captured == [{'data_req_accepted': 1,
        'data_addr': DMA_BASE, 'data_wdata': SOURCE}]


def _execution_ids(runner):
    result = {name: session._execution
        for name, session in runner.sessions.items()}
    result['runner'] = runner.execution_id
    return result


def _append_heartbeat(path, *, phase, round_index, schedule, marker,
                      runner, process_handles, provider_calls):
    row = {
        'schema_version': 'cv32_pulp_dma_schedule_heartbeat.v1',
        'testcase_id': TESTCASE_ID,
        'phase': phase,
        'round_index': round_index,
        'schedule_steps': len(schedule),
        'marker': marker,
        'component_local_ticks': dict(runner.local_ticks),
        'pending_responses': runner._pending_responses(),
        'pending_target_requests': runner._pending_target_requests(),
        'runner_event_count': runner.event_count,
        'component_event_counts': {
            'cpu': len(runner.sessions['cpu'].cpu_events),
            'dma': len(runner.sessions['dma'].events),
            'gpio_provider_receipts': len([row for row in
                runner.sessions['gpio'].gpio_events
                if row.get('kind') == 'gpio_target_receipt']),
            'gpio_provider_calls': len(provider_calls),
        },
        'processes': {
            name: {'pid': None if process is None else process.pid,
                   'returncode': None if process is None else process.poll()}
            for name, process in process_handles.items()},
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(row, sort_keys=True,
            separators=(',', ':')) + '\n')
        stream.flush()


def _assert_schedule_heartbeat_complete(evidence):
    rows = [json.loads(line) for line in Path(
        evidence['schedule_heartbeat_path']).read_text(
            encoding='utf-8').splitlines() if line]
    assert rows and (rows[0]['phase'], rows[0]['round_index'],
        rows[0]['schedule_steps']) == ('after_host_setup', 0, 0)
    rounds = evidence['completed_rounds']
    assert rounds > 0 and len(evidence['schedule']) == rounds * len(ROUND)
    expected = list(range(10, rounds + 1, 10))
    if not expected or expected[-1] != rounds:
        expected.append(rounds)
    actual = [row['round_index'] for row in rows if row['phase'] == 'round']
    assert actual == expected
    assert all(row['schedule_steps'] == row['round_index'] * len(ROUND)
        for row in rows[1:])
    assert rows[-1]['marker'] == evidence['result'][4]


def _run_native_case(cache_dir, evidence_dir, d3_wiring, *,
        destination=PADOUT_ADDRESS, schedule_prefix=None, phase='first'):
    fixture = make_cv32e40p_dma_pulp_gpio_runner(cache_dir=cache_dir,
        destination_address=destination)
    runner = fixture.runner
    cpu, dma, gpio = (runner.sessions[name]
        for name in ('cpu', 'dma', 'gpio'))
    rom_padding = []
    try:
        rom_padding = _pad_native_rom(cpu.memory, destination=destination)
        paths, bound, admission, d4_evidence = _install_d4(
            fixture, d3_wiring)
    except BaseException:
        for session in reversed(tuple(runner.sessions.values())):
            session.end_case()
        raise

    provider_calls = []
    native_pre_samples = []
    original_command = dma.command

    def capture_native_pre(op, fields):
        receipt = original_command(op, fields)
        if op == 'STEP_WB_DMA':
            native_pre_samples.append(_plain(receipt.payload['pre_backend']))
        return receipt

    if destination != PADOUT_ADDRESS:
        dma.command = capture_native_pre

    schedule = []
    cpu_bus_steps = []
    failure = None
    process_handles = {}
    heartbeat_path = evidence_dir / (
        f'schedule-heartbeat-{phase}-{os.getpid()}.jsonl')
    if heartbeat_path.exists():
        heartbeat_path.unlink()
    evidence = {}
    run_error = None
    testcase_id = TESTCASE_ID if destination == PADOUT_ADDRESS else \
        TESTCASE_ID + '-wrong-offset'
    try:
        runner.begin_test(testcase_id)
        process_handles = {name: session.process
            for name, session in runner.sessions.items()}
        _append_heartbeat(heartbeat_path,
            phase='after_host_setup', round_index=0, schedule=schedule,
            marker=None, runner=runner, process_handles=process_handles,
            provider_calls=provider_calls)

        def step(component):
            nonlocal failure
            try:
                if component == 'dma':
                    outputs = _observe_provider_call(gpio, provider_calls,
                        lambda: runner.step(component))
                else:
                    outputs = runner.step(component)
                _record_cpu_bus_step(component, outputs, cpu_bus_steps)
            except Exception as error:
                failure = {'type': type(error).__name__, 'message': str(error)}
                raise
            return outputs

        if schedule_prefix is not None:
            component_schedule = tuple(schedule_prefix)
            if (not component_schedule
                    or len(component_schedule) > len(ROUND) * MAX_ROUNDS
                    or len(component_schedule) % len(ROUND)
                    or any(component not in runner.sessions
                           for component in component_schedule)):
                raise ValueError('invalid recorded CV32 replay schedule')
            for index, component in enumerate(component_schedule):
                schedule.append(component)
                try:
                    step(component)
                except Exception:
                    _append_heartbeat(heartbeat_path,
                        phase='step_failure',
                        round_index=(len(schedule) + len(ROUND) - 1) // len(ROUND),
                        schedule=schedule, marker=None, runner=runner,
                        process_handles=process_handles,
                        provider_calls=provider_calls)
                    break
                if (index + 1) % len(ROUND) == 0:
                    round_index = (index + 1) // len(ROUND)
                    marker = cpu.memory.read(RESULT + 16, 4,
                        transaction_id=f'cv32-marker-{phase}-{round_index}').value
                    pending = runner._pending_target_requests()
                    terminal = (marker in (1, 0xffffffff)
                        and cpu.pending_responses == 0
                        and dma.pending_responses == 0
                        and not pending.get('dma', 0)
                        and not pending.get('gpio', 0))
                    if (round_index % 10 == 0 or terminal
                            or index + 1 == len(component_schedule)
                            or round_index == MAX_ROUNDS):
                        _append_heartbeat(heartbeat_path,
                            phase='round', round_index=round_index,
                            schedule=schedule, marker=marker, runner=runner,
                            process_handles=process_handles,
                            provider_calls=provider_calls)
        else:
            for round_index in range(1, MAX_ROUNDS + 1):
                for component in ROUND:
                    schedule.append(component)
                    try:
                        step(component)
                    except Exception:
                        _append_heartbeat(heartbeat_path,
                            phase='step_failure', round_index=round_index,
                            schedule=schedule, marker=None, runner=runner,
                            process_handles=process_handles,
                            provider_calls=provider_calls)
                        break
                if failure is not None:
                    break
                marker = cpu.memory.read(RESULT + 16, 4,
                    transaction_id=f'cv32-marker-{phase}-{round_index}').value
                pending = runner._pending_target_requests()
                terminal = (marker in (1, 0xffffffff)
                    and cpu.pending_responses == 0
                    and dma.pending_responses == 0
                    and not pending.get('dma', 0)
                    and not pending.get('gpio', 0))
                if (round_index % 10 == 0 or terminal
                        or round_index == MAX_ROUNDS):
                    _append_heartbeat(heartbeat_path,
                        phase='round', round_index=round_index,
                        schedule=schedule, marker=marker, runner=runner,
                        process_handles=process_handles,
                        provider_calls=provider_calls)
                if terminal:
                    break

        result = [cpu.memory.read(RESULT + offset, 4,
            transaction_id=f'cv32-result-{phase}-{offset}').value
            for offset in (0, 4, 8, 12, 16)]
        process_ids = {name: None if process is None else process.pid
            for name, process in process_handles.items()}
        binding, = runner.bindings
        router_deliveries = [{**row,
            'source_transaction': _plain(row['source_transaction'])}
            for row in cpu.router.deliveries]
        evidence = {
            'schema_version': 'cv32_wbdmac_pulp_gpio_isr_run.v1',
            'testcase_id': testcase_id,
            'source_address': SOURCE,
            'source_value': SOURCE_VALUE,
            'destination_address': destination,
            'schedule': list(schedule),
            'round_bound': MAX_ROUNDS,
            'completed_rounds': len(schedule) // len(ROUND),
            'failure': failure,
            'result': result,
            'gpio_probe_value': next((event.get('outputs', {}).get('gpio_out')
                for event in reversed(list(runner.events))
                if event.get('component') == 'gpio'), None),
            'provider_call_count': len(provider_calls),
            'native_pre_samples': native_pre_samples,
            'cpu_bus_steps': cpu_bus_steps,
            'process_ids': process_ids,
            'schedule_heartbeat_path': str(heartbeat_path),
            'path': paths.document(),
            'rom_padding': rom_padding,
            'd4_binding': d4_evidence,
            'ownership': runner.ownership.document(),
            'events': list(runner.events),
            'cpu_events': list(cpu.cpu_events),
            'cpu_memory': list(cpu.service.events),
            'dma_events': list(dma.events),
            'dma_memory': list(dma.memory_service.events),
            'gpio_events': list(gpio.gpio_events),
            'irq_events': list(runner._irq_pulses[binding].events),
            'router_deliveries': router_deliveries,
            'identities': {name: session.identity_document()
                for name, session in runner.sessions.items()},
            'execution_ids': _execution_ids(runner),
            'admission_state': admission.state,
            'route_matches': admission.route_matches,
            'admission_identity': admission.identity_document(),
        }
    except BaseException as error:
        run_error = error
        partial_result = []
        for offset in (0, 4, 8, 12, 16):
            try:
                partial_result.append(cpu.memory.read(offset + RESULT, 4,
                    transaction_id=f'cv32-failure-{phase}-{offset}').value)
            except BaseException:
                partial_result.append(None)
        binding = runner.bindings[0] if runner.bindings else None
        current_processes = {name: process_handles.get(name, session.process)
            for name, session in runner.sessions.items()}
        evidence = {
            'schema_version': 'cv32_wbdmac_pulp_gpio_isr_failure.v1',
            'testcase_id': testcase_id,
            'source_address': SOURCE,
            'source_value': SOURCE_VALUE,
            'destination_address': destination,
            'schedule': list(schedule),
            'round_bound': MAX_ROUNDS,
            'completed_rounds': len(schedule) // len(ROUND),
            'failure': {'type': type(error).__name__, 'message': str(error)},
            'result': partial_result,
            'provider_call_count': len(provider_calls),
            'provider_calls': provider_calls,
            'native_pre_samples': native_pre_samples,
            'cpu_bus_steps': cpu_bus_steps,
            'process_ids': {name: None if process is None else process.pid
                for name, process in current_processes.items()},
            'schedule_heartbeat_path': str(heartbeat_path),
            'path': paths.document(),
            'rom_padding': rom_padding,
            'd4_binding': d4_evidence,
            'events': list(runner.events),
            'cpu_events': list(cpu.cpu_events),
            'cpu_memory': list(cpu.service.events),
            'dma_events': list(dma.events),
            'dma_memory': list(dma.memory_service.events),
            'gpio_events': list(gpio.gpio_events),
            'irq_events': ([] if binding is None else
                list(runner._irq_pulses[binding].events)),
            'router_deliveries': [{**row,
                'source_transaction': _plain(row['source_transaction'])}
                for row in cpu.router.deliveries],
            'identities': {name: session.identity_document()
                for name, session in runner.sessions.items()},
            'execution_ids': _execution_ids(runner),
            'admission_state': admission.state,
            'route_matches': admission.route_matches,
            'admission_identity': admission.identity_document(),
        }
    finally:
        try:
            cpu.end_case()
        finally:
            try:
                dma.end_case()
            finally:
                gpio.end_case()
    evidence['process_returncodes'] = {
        name: None if process is None else process.returncode
        for name, process in {
            **process_handles,
            **{name: session.process for name, session in runner.sessions.items()
               if name not in process_handles},
        }.items()}
    if run_error is not None:
        evidence['runner_exception'] = {
            'type': type(run_error).__name__, 'message': str(run_error)}
        _save_json(evidence_dir, phase + '-failure', evidence)
        raise run_error
    _save_json(evidence_dir, phase, evidence)
    return evidence


def _semantic_payload(evidence):
    return {key: evidence[key] for key in (
        'schema_version', 'testcase_id', 'source_address', 'source_value',
        'destination_address', 'schedule', 'round_bound', 'completed_rounds',
        'failure', 'result', 'gpio_probe_value', 'provider_call_count',
        'cpu_bus_steps', 'path', 'rom_padding', 'd4_binding', 'ownership', 'events',
        'cpu_events', 'cpu_memory', 'dma_events', 'dma_memory',
        'gpio_events', 'irq_events', 'router_deliveries', 'identities',
        'admission_state', 'route_matches', 'admission_identity',
        'process_returncodes')}


def _assert_positive(evidence):
    assert evidence['failure'] is None
    assert evidence['result'] == [0x8000000B, 0, SOURCE_VALUE,
        SOURCE_VALUE, 1]
    assert evidence['provider_call_count'] == 1
    assert evidence['process_returncodes'] == {
        'cpu': 0, 'dma': 0, 'gpio': 0}
    assert evidence['admission_state'] == 'complete'
    assert evidence['d4_binding']['bind_count'] == 1
    assert evidence['d4_binding']['same_prepared_object'] is True

    cpu_writes = [row for row in evidence['cpu_bus_steps']
        if row.get('data_req_accepted') == 1 and row.get('data_write') == 1
        and DMA_BASE <= row.get('data_addr', -1) < DMA_BASE + 16]
    assert [(row['data_addr'], row['data_wdata'], row['data_be'])
        for row in cpu_writes] == [
            (DMA_BASE + 8, SOURCE, 15),
            (DMA_BASE + 12, PADOUT_ADDRESS, 15),
            (DMA_BASE + 4, 1, 15),
            (DMA_BASE, 0x0FED0001, 15),
        ]
    router_writes = [(row['offset'], row['write_value'])
        for row in evidence['router_deliveries']
        if row['device_id'] == 'dma' and row['write']]
    assert router_writes == [
        (8, SOURCE), (12, PADOUT_ADDRESS), (4, 1), (0, 0x0FED0001)]

    accepted = [row['accepted'] for row in evidence['dma_events']
        if type(row.get('accepted')) is dict]
    assert [(row['address'], row['write']) for row in accepted] == [
        (SOURCE, False), (PADOUT_ADDRESS, True)]
    read_key, write_key = (row['transaction'] for row in accepted)
    assert read_key != write_key
    assert read_key['source_component'] == write_key['source_component'] == 'dma'
    assert (read_key['source_sequence'], write_key['source_sequence']) == (1, 2)
    for key in (read_key, write_key):
        assert key['execution_id'] == evidence['execution_ids']['dma']
        assert key['testcase_id'] == evidence['testcase_id']
    assert accepted[1]['value'] == SOURCE_VALUE

    memory_reads = [row for row in evidence['dma_memory']
        if row.get('kind') == 'memory_read' and row.get('address') == SOURCE]
    assert len(memory_reads) == 1
    assert memory_reads[0]['width_bytes'] == 4
    assert memory_reads[0]['transaction'] == read_key
    assert memory_reads[0]['value'] == SOURCE_VALUE
    assert accepted[0]['byte_enable'] == 15
    responses = [row['response'] for row in evidence['dma_events']
        if type(row.get('response')) is dict]
    response_by_key = {json.dumps(row['transaction'], sort_keys=True): row
        for row in responses}
    read_response = response_by_key[json.dumps(read_key, sort_keys=True)]
    write_response = response_by_key[json.dumps(write_key, sort_keys=True)]
    assert (read_response['rdata'], read_response['error']) == (SOURCE_VALUE, 0)
    assert (write_response['error'], write_response['rdata']) == (0, 0)

    matches = {tuple(row['edge_key']): row for row in evidence['route_matches']}
    assert set(matches) == {(0, 0), (2, 0)}
    assert matches[(0, 0)]['transaction'] == read_key
    assert matches[(2, 0)]['transaction'] == write_key
    assert matches[(0, 0)]['route_sha256'] == \
        evidence['d4_binding']['read_route']['identity_sha256']
    assert matches[(2, 0)]['route_sha256'] == \
        evidence['d4_binding']['write_route']['identity_sha256']

    target = accepted[1]['target_delivery']
    assert target['source_transaction'] == write_key
    assert (target['target_component'], target['address'], target['offset'],
        target['value'], target['byte_enable']) == (
            'gpio', PADOUT_ADDRESS, GPIO_PADOUT_OFFSET, SOURCE_VALUE, 15)
    provider = target['target_provider_receipt']
    assert provider['source_transaction'] == write_key
    assert provider['status'] == 'observed'
    assert provider['target_effect']['post_probe_value'] == SOURCE_VALUE
    provider_id = provider['target_access_id']
    for kind in ('target_request', 'gpio_apb_access', 'target_response'):
        rows = [row for row in evidence['gpio_events']
            if row.get('kind') == kind and row.get('access_id') == provider_id]
        assert len(rows) == 1
        assert rows[0]['source_transaction'] == write_key

    deliveries = evidence['router_deliveries']
    readback = [row for row in deliveries
        if row['device_id'] == 'gpio' and row['offset'] == GPIO_PADOUT_OFFSET
        and not row['write']]
    assert len(readback) == 1 and readback[0]['read_value'] == SOURCE_VALUE
    assert evidence['result'][2:4] == [SOURCE_VALUE, SOURCE_VALUE]

    irq = next(row for row in evidence['events']
        if row.get('kind') == 'source_start'
        and tuple(row.get('source', ())) == ('dma', 'irq')
        and tuple(row.get('target', ())) == ('cpu', 'irq'))
    irq_input = next(row for row in evidence['events']
        if row.get('kind') == 'cpu_irq_input'
        and tuple(row.get('source', ())) == ('dma', 'irq')
        and tuple(row.get('target', ())) == ('cpu', 'irq')
        and row.get('source_event_id') == irq['source_event_id']
        and row.get('value') == 1)
    irq_source = next(row for row in evidence['events']
        if row.get('component') == 'dma'
        and type(row.get('outputs')) is dict
        and row['outputs'].get('irq') == 1
        and row.get('local_tick') == irq['source_tick'])
    cpu_steps = [row for row in evidence['events']
        if row.get('component') == 'cpu' and type(row.get('outputs')) is dict]
    irq_ack = next(row for row in cpu_steps
        if row.get('event_id', 0) > irq_input['cpu_step_event_id']
        and row.get('inputs', {}).get('irq') == 1
        and row['outputs'].get('irq_ack_o') == 1
        and row['outputs'].get('irq_id_o') == 11)
    trap_fetch = next(row for row in cpu_steps
        if row.get('event_id', 0) > irq_ack['event_id']
        and row['outputs'].get('instr_req_accepted') == 1
        and row['outputs'].get('instr_addr') == ISR)
    assert irq_source['event_id'] < irq['event_id'] < irq_input['event_id']
    assert irq['source_event_id'] == irq_input['source_event_id']
    assert irq_input['event_id'] < irq_ack['event_id'] < trap_fetch['event_id']
    assert evidence['result'][0] == 0x8000000B
    assert _plain([row['outputs'] for row in cpu_steps]) == evidence['cpu_bus_steps']

    # CPU source sequences count every accepted data request, including stores.
    # Join MMIO delivery keys and the real RAM receipt to consumed OBI replies.
    data_requests = [(index, row) for index, row in
        enumerate(evidence['cpu_bus_steps'])
        if row.get('data_req_accepted') == 1]
    isr_reads = [(sequence, index, row)
        for sequence, (index, row) in enumerate(data_requests, start=1)
        if row.get('data_write') == 0]
    assert [(row['data_addr'], row['data_be'])
        for _sequence, _index, row in isr_reads] == [
            (DMA_BASE, 15), (PADOUT_ADDRESS, 15), (SOURCE, 15)]
    source_reads = [row for row in evidence['cpu_memory']
        if row.get('kind') == 'memory_read' and row.get('address') == SOURCE]
    assert len(source_reads) == 1
    source_read = source_reads[0]
    assert (source_read['memory_id'], source_read['width_bytes'],
        source_read['value']) == ('ram', 4, SOURCE_VALUE)
    cpu_isr_read_joins = []
    for (sequence, request_index, request), expected_value in zip(
            isr_reads, (0, SOURCE_VALUE, SOURCE_VALUE), strict=True):
        assert cpu_steps[request_index]['event_id'] > trap_fetch['event_id']
        if request['data_addr'] == SOURCE:
            receipt = source_read
            transaction = receipt['transaction']
        else:
            receipts = [row for row in evidence['router_deliveries']
                if row['address'] == request['data_addr'] and not row['write']]
            assert len(receipts) == 1
            receipt = receipts[0]
            assert (receipt['beat_bytes'], receipt['byte_enable'],
                receipt['read_value']) == (4, 15, expected_value)
            transaction = receipt['source_transaction']
        assert (transaction['source_component'], transaction['channel_id'],
            transaction['testcase_id'], transaction['source_epoch'],
            transaction['source_sequence']) == (
                'cpu', 'data', evidence['testcase_id'], 0, sequence)
        responses = [(index, row) for index, row in
            enumerate(evidence['cpu_bus_steps'])
            if row.get('data_rsp_consumed') == 1
            and (row['data_rsp_source_epoch'], row['data_rsp_source_sequence'])
                == (transaction['source_epoch'], transaction['source_sequence'])]
        assert len(responses) == 1
        response_index, response = responses[0]
        assert request_index < response_index
        assert response['data_rsp_rdata'] == expected_value
        cpu_isr_read_joins.append({
            'transaction': transaction,
            'request_step_index': request_index,
            'request': request,
            'receipt': receipt,
            'response_step_index': response_index,
            'response': response,
        })

    result_stores = [row for row in evidence['cpu_memory']
        if row.get('kind') == 'memory_write'
        and row.get('address') in (RESULT, RESULT + 4, RESULT + 8,
                                   RESULT + 12, RESULT + 16)]
    assert [(row['address'], row['value']) for row in result_stores] == [
        (RESULT, 0x8000000B), (RESULT + 4, 0),
        (RESULT + 8, SOURCE_VALUE), (RESULT + 12, SOURCE_VALUE),
        (RESULT + 16, 1)]
    assert evidence['gpio_probe_value'] == SOURCE_VALUE

    return {
        'schema_version': 'cv32_pulp_dma_typed_transaction_joins.v2',
        'cpu_dma_register_writes': cpu_writes,
        'cpu_isr_read_joins': cpu_isr_read_joins,
        'dma_read_transaction': read_key,
        'dma_write_transaction': write_key,
        'ram_read': memory_reads[0],
        'dma_responses': [read_response, write_response],
        'route_matches': [matches[(0, 0)], matches[(2, 0)]],
        'gpio_provider_receipt': provider,
        'dma_irq_source_event_id': irq_source['event_id'],
        'dma_irq_binding_event_id': irq['event_id'],
        'cpu_irq_input_event_id': irq_input['event_id'],
        'cpu_irq_ack_event_id': irq_ack['event_id'],
        'cv32_direct_trap_fetch_event_id': trap_fetch['event_id'],
        'isr_mcause_store': result_stores[0],
        'success_marker_store': result_stores[-1],
    }


@pytest.mark.skipif(os.environ.get('MYFUZZ_CV32_PULP_DMA_REAL') != '1',
    reason='explicit native CV32E40P/DMA/PULP GPIO gate')
def test_real_cv32_dma_pulp_gpio_irq_isr_and_typed_fresh_replay(tmp_path):
    cache, evidence_dir = _settings(tmp_path)
    _d2_wiring, request, compiled = _d3_material(tmp_path)
    assert request.cpu.profile.component_id == 'cv32e40p'
    assert next(row for row in compiled['paths']
        if row['flow_id'] == 'F6')['status'] == 'unsupported'
    d3_wiring = request.wiring

    reference = _run_native_case(cache, evidence_dir, d3_wiring,
        phase='first')
    fresh = _run_native_case(cache, evidence_dir, d3_wiring,
        schedule_prefix=reference['schedule'], phase='fresh')
    _save_json(evidence_dir, 'reference', reference)
    _save_json(evidence_dir, 'fresh', fresh)
    typed_joins = _assert_positive(reference)
    fresh_typed_joins = _assert_positive(fresh)
    _save_json(evidence_dir, 'typed-joins', typed_joins)
    _save_json(evidence_dir, 'fresh-typed-joins', fresh_typed_joins)
    _assert_schedule_heartbeat_complete(reference)
    _assert_schedule_heartbeat_complete(fresh)
    assert reference['identities'] == fresh['identities']
    assert reference['schedule'] == fresh['schedule']
    assert len(reference['schedule']) <= len(ROUND) * MAX_ROUNDS
    assert set(reference['execution_ids']) == {'cpu', 'dma', 'gpio', 'runner'}
    assert all(type(pid) is int and pid > 0
        for pid in reference['process_ids'].values())
    assert all(type(pid) is int and pid > 0
        for pid in fresh['process_ids'].values())
    assert set(reference['process_ids'].values()).isdisjoint(
        set(fresh['process_ids'].values()))
    for role in reference['execution_ids']:
        assert reference['execution_ids'][role] != fresh['execution_ids'][role]
    difference = first_gpio_dma_replay_difference(
        _semantic_payload(reference), _semantic_payload(fresh),
        reference_execution_ids=reference['execution_ids'],
        actual_execution_ids=fresh['execution_ids'])
    normalized_reference = normalize_gpio_dma_execution_identities(
        _semantic_payload(reference), reference['execution_ids'])
    normalized_fresh = normalize_gpio_dma_execution_identities(
        _semantic_payload(fresh), fresh['execution_ids'])
    comparison = {
        'schema_version': 'cv32_pulp_dma_typed_fresh_replay.v1',
        'equal': difference is None,
        'difference': difference,
        'reference_schedule_steps': len(reference['schedule']),
        'fresh_schedule_steps': len(fresh['schedule']),
        'normalized_reference_sha256': hashlib.sha256(json.dumps(
            normalized_reference, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest(),
        'normalized_fresh_sha256': hashlib.sha256(json.dumps(
            normalized_fresh, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest(),
        'normalizer': 'typed CPU/DMA/GPIO/Runner field-level execution identity rules',
    }
    (evidence_dir / 'comparison.json').write_text(json.dumps(comparison,
        sort_keys=True, indent=2), encoding='utf-8')
    assert difference is None, difference


@pytest.mark.skipif(os.environ.get('MYFUZZ_CV32_PULP_DMA_REAL') != '1',
    reason='explicit native wrong-offset CV32E40P/PULP refusal gate')
def test_real_cv32_dma_wrong_padout_offset_refuses_before_provider(tmp_path):
    cache, evidence_dir = _settings(tmp_path)
    _d2_wiring, request, compiled = _d3_material(tmp_path)
    assert request.cpu.profile.component_id == 'cv32e40p'
    assert next(row for row in compiled['paths']
        if row['flow_id'] == 'F6')['status'] == 'unsupported'
    wrong = _run_native_case(cache, evidence_dir, request.wiring,
        destination=PADOUT_ADDRESS + 4, phase='wrong-offset')
    _save_json(evidence_dir, 'wrong-offset-refusal', wrong)
    assert wrong['failure'] is not None
    assert wrong['failure']['type'] == 'ValueError'
    assert 'route match' in wrong['failure']['message'].lower()
    assert wrong['provider_call_count'] == 0
    assert wrong['admission_state'] == 'expect_write'
    attempted = [row for row in wrong['native_pre_samples']
        if row.get('mwb_cyc') == 1 and row.get('mwb_stb') == 1
        and row.get('mwb_we') == 1
        and (row.get('mwb_adr', -1) << 2) == PADOUT_ADDRESS + 4]
    assert len(attempted) == 1
    assert attempted[0].get('mwb_dat_w') == SOURCE_VALUE
    assert not any(row.get('kind') in (
        'target_request', 'target_response', 'gpio_apb_access')
        for row in wrong['gpio_events'])
    assert wrong['result'][4] == 0
    assert wrong['irq_events'] == []
    assert not any(row.get('kind') in ('source_start', 'cpu_irq_input')
        and tuple(row.get('source', ())) == ('dma', 'irq')
        and tuple(row.get('target', ())) == ('cpu', 'irq')
        for row in wrong['events'])
    assert not any(row.get('component') == 'dma'
        and type(row.get('outputs')) is dict
        and row['outputs'].get('irq') == 1 for row in wrong['events'])
    assert wrong['process_returncodes'] == {
        'cpu': 0, 'dma': 0, 'gpio': 0}
