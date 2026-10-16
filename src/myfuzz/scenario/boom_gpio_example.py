"""Bounded directed BOOM/PULP GPIO simulation; not standard runner admission.

No expected result is preloaded. BOOM executes SW/LW against the generated
GPIO, branches on its returned value, and writes its result into native RAM.
"""
from __future__ import annotations

import copy
from dataclasses import asdict, dataclass
from pathlib import Path

from myfuzz.local_harness import (
    load_local_harness_request, plan_local_harness, render_local_harness,
    render_local_runtime, verify_local_source_lock,
)
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.boom_cpu_session import GeneratedBoomCpuSession
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from .ledger import TransactionKey, TransactionLedger
from .router import DataflowRouter, DeviceWindow

GPIO_BASE = 0x4000
PADOUT = GPIO_BASE + 12
RESULT = 0x3000
GPIO_PROFILE = 'configs/peripherals/pulp_gpio_causal_local/component_profile.json'


def _addi(rd, rs, value):
    return (value & 0xfff) << 20 | rs << 15 | rd << 7 | 0x13


def _sw(rs, base, offset):
    return ((offset >> 5) & 127) << 25 | rs << 20 | base << 15 | 2 << 12 | (offset & 31) << 7 | 0x23


def _bne(rs1, rs2, offset):
    return ((offset >> 12) & 1) << 31 | ((offset >> 5) & 63) << 25 | rs2 << 20 | rs1 << 15 | 1 << 12 | ((offset >> 1) & 15) << 8 | ((offset >> 11) & 1) << 7 | 0x63


def boom_gpio_program() -> bytes:
    """Write 53, order the read, then store the CPU readback and branch result."""
    words = [
        0x000040b7,                 # lui x1, 4: zero-positive GPIO address
        _addi(2, 0, 53),
        _sw(2, 1, 12),             # PADOUT, high word of the 64-bit TL beat
        0x0ff0000f,                # fence iorw, iorw
        12 << 20 | 1 << 15 | 2 << 12 | 3 << 7 | 3,  # lw x3,12(x1)
        0x00003237,                # lui x4,3: native uncached result RAM
        _sw(3, 4, 0),
        _bne(3, 2, 16),
        _addi(5, 0, 1), _sw(5, 4, 4), 0x0000006f,
        _addi(5, 0, -1), _sw(5, 4, 4), 0x0000006f,
    ]
    # Whole instruction cache lines are initialized before execution starts.
    words.extend([0x00000013] * (64 - len(words)))
    return b''.join(word.to_bytes(4, 'little') for word in words)


def _gpio_artifact(repo: Path):
    request = load_local_harness_request({
        'schema_version': 'local_harness.v2', 'profile_path': GPIO_PROFILE,
        'instance_id': 'gpio', 'reset_assert_ticks': 8, 'reset_release_ticks': 8,
        'max_wait_cycles': 16,
        'tuning': {'raw_tick_stream': [{'sampling': 'pre_post'}]},
    })
    plan = plan_local_harness(request, base_dir=repo)
    runtime = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=repo), base_dir=repo)
    return render_local_driver(runtime, base_dir=repo)


def _validate_request(request: dict):
    """Reject unsupported TL shapes before the GPIO target can act."""
    widths = {'opcode': 3, 'param': 3, 'size': 4, 'source': 16,
              'address': 32, 'mask': 8, 'data': 64,
              'request_sequence': 64, 'reset_epoch': 64}
    if not isinstance(request, dict) or request.get('channel') != 'A':
        raise ValueError('accepted TileLink A request required')
    for field, width in widths.items():
        value = request.get(field)
        if type(value) is not int or not 0 <= value < 1 << width:
            raise ValueError('invalid external TileLink field: ' + field)
    # This directed firmware uses aligned full 32-bit words exclusively. The
    # lane mask is required for reads too, before any register effect occurs.
    if (request['opcode'] not in (0, 1, 4) or request['param'] != 0
            or request['size'] != 2 or request['address'] != PADOUT
            or request['address'] % 4 or request['mask'] != 0xf0
            or request['request_sequence'] < 1):
        raise ValueError('unsupported BOOM GPIO transfer shape')


@dataclass
class BoomGpioDiagnostic:
    cpu: GeneratedBoomCpuSession
    gpio: GeneratedPulpGpioSession
    router: DataflowRouter
    ledger: TransactionLedger

    def close(self):
        try:
            self.cpu.close()
        finally:
            self.gpio.end_case()

    def run(self, *, testcase_id: str = 'boom-gpio-directed', max_edges: int = 20000):
        """Run a finite real RTL pair and return observations, failing closed.

        This diagnostic loop is deliberately separate from ScenarioRunner. A
        target access occurs on a router drain after CPU A acceptance, then its
        one D response remains pending until BOOM accepts it on a later edge.
        """
        if type(max_edges) is not int or not 1 <= max_edges <= 250000:
            raise ValueError('invalid diagnostic edge bound')
        if self.router.deliveries or self.ledger.unresolved_keys:
            raise RuntimeError('a diagnostic pair can run only once')
        self.cpu.begin_case(testcase_id)
        self.gpio.begin_case(testcase_id)
        self.cpu.load_program(boom_gpio_program())
        raw_cpu, physical_gpio, correlations = [], [], []
        active = None
        handled = set()
        result_writes = []
        for _ in range(max_edges):
            observation = self.cpu.step_local({})
            raw_cpu.append(copy.deepcopy(observation))
            for event in observation['accepted_events']:
                if event['channel'] == 'D' and event.get('external') is True:
                    if active is None or active.get('d_accepted') is not None:
                        raise RuntimeError('unexpected/duplicate external D acceptance')
                    request = active['request']
                    if (event.get('source') != request['source']
                            or event.get('size') != request['size']
                            or event.get('opcode') != (1 if request['opcode'] == 4 else 0)
                            or event.get('data') != active['response_data']):
                        raise RuntimeError('external D response identity/data mismatch')
                    active['d_accepted'] = copy.deepcopy(event)
                    active['d_cpu_edge'] = self.cpu.ticks
                    active = None
                if (event['channel'] == 'A' and event.get('address') in (RESULT, RESULT + 4)
                        and event.get('opcode') in (0, 1)):
                    if event.get('size') != 2 or event.get('mask') != (15 << (event['address'] & 7)):
                        raise RuntimeError('invalid CPU result store shape')
                    result_writes.append(copy.deepcopy(event))
            request = observation['external_request']
            if request is not None:
                _validate_request(request)
                token = (request['reset_epoch'], request['request_sequence'])
                if token not in handled:
                    if active is not None:
                        raise RuntimeError('multiple outstanding external requests')
                    handled.add(token)
                    key = TransactionKey(self.cpu.execution_id, testcase_id,
                        'boom', request['reset_epoch'], 'coherent-A-uncached',
                        request['request_sequence'])
                    record = {'source_transaction': asdict(key),
                              'request': copy.deepcopy(request),
                              'a_cpu_edge': self.cpu.ticks, 'd_accepted': None}
                    active = record
                    correlations.append(record)

                    def complete(response, *, record=record, request=copy.deepcopy(request)):
                        data, error = response
                        if error != 0:
                            raise RuntimeError('GPIO target returned an error')
                        record['response_data'] = data
                        self.cpu.respond_external(source=request['source'],
                            size=request['size'], data=data,
                            request_sequence=request['request_sequence'],
                            reset_epoch=request['reset_epoch'])

                    self.router.enqueue(self.ledger, key,
                        address=request['address'], write=request['opcode'] != 4,
                        wdata=request['data'], be=request['mask'], beat_bytes=8,
                        callback=complete)
                    if not self.router.drain_one('gpio'):
                        raise RuntimeError('GPIO router did not deliver accepted request')
                    physical_gpio.extend(self.gpio.drain_tick_samples())
            # RAM receives these bytes only from accepted CPU result writes.
            # No expected result is ever loaded into either environment.
            word = self.cpu.read64(RESULT)
            if word >> 32:
                if not observation['drained']:
                    continue
                value, marker = word & 0xffffffff, word >> 32
                if marker != 1 or value != 53:
                    raise RuntimeError('BOOM reported GPIO readback failure')
                if (len(correlations) != 2 or active is not None
                        or any(row['d_accepted'] is None for row in correlations)
                        or self.ledger.unresolved_keys or self.router.pending_targets
                        or len(result_writes) != 2):
                    raise RuntimeError('incomplete CPU/GPIO causal chain')
                writes, reads = correlations
                if (writes['request']['opcode'] not in (0, 1)
                        or writes['request']['data'] >> 32 & 0xffffffff != 53
                        or reads['request']['opcode'] != 4
                        or reads['response_data'] >> 32 & 0xffffffff != 53):
                    raise RuntimeError('directed GPIO write/read chain mismatch')
                access_rows = [event for event in self.gpio.gpio_events
                               if event.get('kind') == 'gpio_apb_access']
                if len(access_rows) != 2 or any(row.get('status') != 'observed' for row in access_rows):
                    raise RuntimeError('GPIO physical APB access evidence missing')
                return {
                    'schema_version': 'boom_gpio_directed_diagnostic.v1',
                    'diagnostic_only': True, 'generic_runner_admitted': False,
                    'cpu_identity': self.cpu.identity_document(),
                    'gpio_identity': self.gpio.identity_document(),
                    'cpu_edges': self.cpu.ticks, 'cpu_readback': value,
                    'cpu_success_marker': marker, 'result_ram_address': RESULT,
                    'cpu_events': raw_cpu, 'gpio_physical_samples': physical_gpio,
                    'gpio_events': copy.deepcopy(self.gpio.gpio_events),
                    'correlations': correlations,
                    'router_deliveries': [
                        {**row, 'source_transaction': asdict(row['source_transaction'])}
                        for row in self.router.deliveries],
                    'cpu_result_writes': result_writes,
                }
        raise TimeoutError('BOOM GPIO diagnostic exceeded its CPU edge bound')


def make_boom_gpio_chain(*, repo: Path, cpu_output: Path, cache_dir: Path):
    """Create a diagnostic pair using a previously built authenticated BOOM.

    Building BOOM is an explicit separate build_boom_session call, under its
    shared heavy lock. GPIO uses the standard generated local RTL build path.
    Call close() even if run() fails; neither process targets real hardware.
    """
    repo = repo.resolve()
    gpio = GeneratedPulpGpioSession(_gpio_artifact(repo), base_dir=repo,
                                    cache_dir=cache_dir)
    cpu = None
    try:
        cpu = GeneratedBoomCpuSession(cpu_output, repo=repo,
                                     external_range=(GPIO_BASE, GPIO_BASE + 0x1000))
        router = DataflowRouter((DeviceWindow('gpio', GPIO_BASE, 0x1000, gpio),))
        return BoomGpioDiagnostic(cpu, gpio, router, TransactionLedger())
    except BaseException:
        try:
            if cpu is not None:
                cpu.close()
        finally:
            gpio.end_case()
        raise
