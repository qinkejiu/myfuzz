"""ScenarioRunner transport adapter for the isolated coherent BOOM simulator.

RAM stays in the native coherent manager. Its observations do not create
PersistentMemory commits, ISA retirement evidence, or source authority.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
from pathlib import Path

from myfuzz.scenario.coherent_event_stream import CoherentAcceptedEventStream
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.router import DataflowRouter
from .boom_cpu_session import GeneratedBoomCpuSession


class GeneratedBoomScenarioSession:
    """Enqueue accepted uncached requests for the standard target scheduler.

    The CPU step never advances another component. The runner discovers router
    windows through its ordinary generic APIs, and drains one accepted request
    on a subsequent target step. The callback offers D without clocking BOOM.
    """
    artifact_kind = 'tilelink_coherent_cpu'
    max_local_ticks_per_step = 1
    max_transaction_events_per_step = 4
    max_mmio_target_accesses_per_step = 0
    defer_mmio = True

    def __init__(self, output: Path, *, repo: Path, router: DataflowRouter,
                 program: bytes, source_component: str = 'cpu',
                 program_address: int = 0x80000000,
                 observed_ram_addresses: tuple[int, ...] = (),
                 command_timeout_seconds: float = 10.0):
        if type(router) is not DataflowRouter or len(router.windows) != 1:
            raise ValueError('BOOM adapter requires one declared router window')
        window = router.windows[0]
        if not 0x4000 <= window.base < window.base + window.size <= 0x5000:
            raise ValueError('BOOM target window must fit pinned uncached page')
        if (type(program) is not bytes or not program or len(program) > 65536
                or type(program_address) is not int or program_address != 0x80000000
                or not 0x80000000 <= program_address <= (1 << 32) - len(program)):
            raise ValueError('BOOM static image must fit native RAM')
        if type(source_component) is not str or not source_component:
            raise ValueError('CPU source component identity required')
        if (type(observed_ram_addresses) is not tuple
                or len(observed_ram_addresses) > 16
                or len(set(observed_ram_addresses)) != len(observed_ram_addresses)
                or any(type(address) is not int or address % 8
                       or not 0 <= address <= 0xfffffff8
                       or window.base <= address < window.base + window.size
                       for address in observed_ram_addresses)):
            raise ValueError('invalid native RAM observation addresses')
        self.output, self.repo = output.resolve(), repo.resolve()
        self.router = router
        self.mmio_ledger = TransactionLedger()
        self.source_component = source_component
        self._program = program
        self._program_address = program_address
        self._ram_addresses = observed_ram_addresses
        self._timeout = command_timeout_seconds
        self._native = None
        self._case_id = None
        self._started = False
        self._active = None
        self.local_ticks = 0
        self.reset_epoch = 0
        self.last_samples = ()
        self._quiescing = False
        self._stream = CoherentAcceptedEventStream(
            component_id='boom', instance_id=source_component,
            endpoint_id='coherent', clock_domain='clock',
            address_bits=32, beat_bytes=8, max_records=200000,
            manager_order='per_source')
        self.runtime_events = self._stream.runtime_events
        self.source_events = []
        # No native process/build is started by constructing the adapter.
        self._artifact = json.loads((self.output / 'session-artifact.json').read_text())

    def identity_document(self):
        return {'schema_version': 'boom_scenario_session.v1',
                'source_component': self.source_component,
                'runtime_kind': self.artifact_kind,
                'native_artifact': deepcopy(self._artifact),
                'native_identity': None if self._native is None else self._native.identity_document(),
                'static_image': {'address': self._program_address,
                    'bytes': len(self._program),
                    'sha256': hashlib.sha256(self._program).hexdigest()},
                'native_ram_observation_addresses': self._ram_addresses,
                'ram_model': 'native_coherent_manager',
                'memory_commit_authority': False, 'isa_retirement_authority': False,
                'runtime_verified': False, 'generic_router_admitted': False,
                'defer_mmio': True}

    @property
    def process(self):
        return None if self._native is None else self._native._process

    @property
    def pending_responses(self):
        return max(int(self._active is not None),
                   0 if self._native is None else self._native.pending_responses)

    def begin_case(self, testcase_id: str):
        if self._started or self._native is not None or self._case_id is not None:
            raise RuntimeError('BOOM adapter testcase already started')
        if type(testcase_id) is not str or not testcase_id:
            raise ValueError('testcase identity required')
        self._case_id = testcase_id
        self._started = True
        window = self.router.windows[0]
        try:
            self._native = GeneratedBoomCpuSession(self.output, repo=self.repo,
                command_timeout_seconds=self._timeout,
                external_range=(window.base, window.base + window.size))
            self._native.begin_case(testcase_id)
            self.reset_epoch = self._native.reset_epoch
            self._native.load_program(self._program, address=self._program_address)
        except BaseException:
            if self._native is not None:
                self._native.close()
            self._native = None
            self._case_id = None
            raise

    def _require_running(self):
        if self._native is None or self._case_id is None or self.process is None:
            raise RuntimeError('BOOM adapter testcase is not running')

    def _event(self, kind, **payload):
        if len(self.source_events) >= 100000:
            raise RuntimeError('BOOM source event bound exceeded')
        self.source_events.append({'kind': kind, 'schema_version': 'boom_routing_observation.v1',
            'execution_id': self._native.execution_id, 'reset_epoch': self.reset_epoch,
            'local_tick': self.local_ticks, 'authority': 'observation_only',
            'source_authority': False, **payload})

    def _validate_request(self, request):
        fields = {'opcode': 3, 'param': 3, 'size': 4, 'source': 16,
                  'address': 32, 'mask': 8, 'data': 64,
                  'request_sequence': 64, 'reset_epoch': 64}
        if not isinstance(request, dict) or request.get('channel') != 'A':
            raise ValueError('accepted BOOM A request required')
        for field, width in fields.items():
            value = request.get(field)
            if type(value) is not int or not 0 <= value < 1 << width:
                raise ValueError('invalid BOOM request field: ' + field)
        address = request['address']
        # RegisterTarget accepts 32-bit words. Reject unsupported widths before
        # router enqueue, not after the target might have had a register effect.
        if (request['opcode'] not in (0, 1, 4) or request['param'] != 0
                or request['size'] != 2 or address % 4
                or request['mask'] != 15 << (address & 7)
                or request['request_sequence'] < 1
                or request['reset_epoch'] != self.reset_epoch
                or not self.router.owns(address)
                or not self.router.owns(address + 3)):
            raise ValueError('unsupported BOOM register transfer shape')

    def _enqueue(self, request):
        self._validate_request(request)
        if self._active is not None:
            if self._active['request'] != request:
                raise RuntimeError('BOOM external identity changed while pending')
            return
        key = TransactionKey(self._native.execution_id, self._case_id,
            self.source_component, self.reset_epoch, 'coherent-A-uncached',
            request['request_sequence'])
        active = {'request': deepcopy(request), 'key': key, 'status': 'target_pending'}
        self._active = active
        execution, epoch = self._native.execution_id, self.reset_epoch

        def complete(response):
            self._require_running()
            if (self._active is not active or self._native.execution_id != execution
                    or self.reset_epoch != epoch or active['status'] != 'target_pending'):
                raise RuntimeError('stale/duplicate BOOM router callback')
            if (not isinstance(response, tuple) or len(response) != 2
                    or type(response[0]) is not int or not 0 <= response[0] < 1 << 64
                    or type(response[1]) is not int or response[1] != 0):
                raise ValueError('unsupported BOOM target response')
            self._native.respond_external(source=request['source'], size=request['size'],
                request_sequence=request['request_sequence'], reset_epoch=epoch,
                data=response[0])
            active.update(status='d_offered', data=response[0])
            self._event('boom_external_d_offered', source_transaction=asdict(key),
                        response_data=response[0])

        fresh = self.router.enqueue(self.mmio_ledger, key, address=request['address'],
            write=request['opcode'] != 4, wdata=request['data'], be=request['mask'],
            beat_bytes=8, callback=complete)
        if not fresh:
            raise RuntimeError('duplicate BOOM source acceptance')
        self._event('boom_external_a_queued', source_transaction=asdict(key),
                    native_request=deepcopy(request))

    def step_local(self, inputs: Mapping[str, int]):
        self._require_running()
        if not isinstance(inputs, Mapping) or inputs:
            raise ValueError('BOOM runner adapter has no mutable CPU inputs')
        try:
            observation = self._native.step_local({})
            self.local_ticks += 1
            self.last_samples = deepcopy(self._native.last_samples)
            self._stream.consume_step(observation['accepted_events'],
                execution_id=self._native.execution_id, reset_epoch=self.reset_epoch,
                local_tick=self.local_ticks)
            report = self._stream.report()
            if report['structural_error'] or report.get('normalization_poisoned'):
                self._event('boom_coherent_protocol_violation',
                    checker_report=report, effect_may_have_occurred=True,
                    recovery='abort_and_replay_testcase')
                raise RuntimeError('BOOM coherent stream violates supported protocol subset')
            counts = {channel: 0 for channel in ('A', 'C', 'D', 'E')}
            for event in observation['accepted_events']:
                counts[event['channel']] += 1
                if event['channel'] == 'D' and event.get('external') is True:
                    active = self._active
                    if active is None or active['status'] != 'd_offered':
                        raise RuntimeError('BOOM accepted D without offered external response')
                    request = active['request']
                    if (event.get('source') != request['source']
                            or event.get('size') != request['size']
                            or event.get('opcode') != (1 if request['opcode'] == 4 else 0)
                            or event.get('data') != active['data']):
                        raise RuntimeError('BOOM accepted external D mismatch')
                    self._event('boom_external_d_accepted',
                        source_transaction=asdict(active['key']), native_response=deepcopy(event))
                    self._active = None
            if observation['external_request'] is not None:
                self._enqueue(observation['external_request'])
            outputs = {'tl_' + channel.lower() + '_accepted': counts[channel]
                       for channel in counts}
            outputs.update(reset=int(observation['reset']), drained=int(observation['drained']))
            # Read native manager bytes only; these observations do not pretend
            # to be independent Python PersistentMemory commits or CPU loads.
            outputs.update({'ram_' + format(address, 'x'): self._native.read64(address)
                            for address in self._ram_addresses})
            return outputs
        except BaseException:
            self._native.close()
            raise

    def begin_quiesce(self):
        self._require_running()
        self._native.begin_quiesce()
        self._quiescing = True

    def reset_local(self):
        self._require_running()
        cancelled = self.pending_responses
        targets = self.router.cancel_for_ledger(self.mmio_ledger)
        if self.mmio_ledger.uncertain_keys:
            raise RuntimeError('uncertain BOOM target effect requires testcase abort')
        try:
            if self._active is not None:
                self._event('boom_external_response_cancelled',
                    source_transaction=asdict(self._active['key']),
                    previous_status=self._active['status'], reason='reset')
            result = self._native.reset_local()
            self.reset_epoch = self._native.reset_epoch
            self._active = None
            self._quiescing = False
            self.last_samples = ()
            self._native.load_program(self._program, address=self._program_address)
            self._event('boom_reset_static_boot_loaded',
                cancelled_source_requests=[asdict(key) for key in targets])
            return {'cancelled_responses': cancelled,
                    'cancelled_target_requests': tuple(str(key) for key in targets),
                    'cancelled_native_requests': result['cancelled_target_requests']}
        except BaseException:
            self._native.close()
            raise

    def end_case(self):
        try:
            self.router.cancel_for_ledger(self.mmio_ledger)
            if self._active is not None and self._native is not None:
                self._event('boom_external_response_cancelled',
                    source_transaction=asdict(self._active['key']),
                    previous_status=self._active['status'], reason='end_case')
        finally:
            if self._native is not None:
                self._native.close()
            self._native = None
            self._case_id = None
            self._active = None

    close = end_case

    def coherent_report(self):
        return self._stream.report()

    def coherent_coverage(self):
        return self._stream.coverage()
