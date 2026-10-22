"""ScenarioRunner transport adapter for the isolated coherent BOOM simulator.

Cached RAM stays in the native coherent manager. An explicit opt-in service
handles only the pinned uncached data spans through actual MemoryService
receipts; native RAM observations carry no host memory or retirement authority.
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
from .boom_shared_memory import (BoomSharedMemoryService,
                                 validate_boom_external_request)


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
                 command_timeout_seconds: float = 10.0,
                 shared_memory_service: BoomSharedMemoryService | None = None):
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
        self.shared_memory_service = shared_memory_service
        self.mmio_ledger = (TransactionLedger() if shared_memory_service is None
                            else self._validate_shared_service().service.ledger)
        self._shared_binding = (None if shared_memory_service is None else
            (shared_memory_service, shared_memory_service.memory, router, window, window.target,
             window.target.memory_service))
        if shared_memory_service is not None:
            shared_memory_service.validate_fresh()
            # Existing Runner APIs drain actual service events and identify
            # memory by object. Default register-only sessions have neither.
            self.service = shared_memory_service.service
            self.memory = shared_memory_service.memory
        self._shared_source_identity = (None if shared_memory_service is None else
            shared_memory_service.contract.authenticate_source(self.repo))
        if shared_memory_service is not None and any(
                0x4000 <= address < 0x5000 for address in observed_ram_addresses):
            raise ValueError('shared external page is not native RAM observation storage')
        self.source_component = source_component
        self._program = program
        self._program_address = program_address
        self._ram_addresses = observed_ram_addresses
        self._timeout = command_timeout_seconds
        self._native = None
        self._case_id = None
        self._started = False
        self._active = None
        self._pending_terminal_updates = {}
        self._cleanup_terminal = False
        self._accepted_sequence = 0
        self.local_ticks = 0
        self.reset_epoch = 0
        self.last_samples = ()
        self._quiescing = False
        self._stream = CoherentAcceptedEventStream(
            component_id='boom', instance_id=source_component,
            endpoint_id='coherent', clock_domain='clock',
            address_bits=32, source_bits=3, sink_bits=3,
            beat_bytes=8, max_records=200000,
            manager_order='per_source')
        self.runtime_events = self._stream.runtime_events
        self.source_events = []
        # No native process/build is started by constructing the adapter.
        self._artifact = json.loads((self.output / 'session-artifact.json').read_text())

    def identity_document(self):
        document = {'schema_version': 'boom_scenario_session.v1',
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
        if self.shared_memory_service is not None:
            document.update(schema_version='boom_scenario_shared_memory_session.v1',
                shared_memory=self.shared_memory_service.identity_document(),
                shared_memory_source=deepcopy(self._shared_source_identity),
                external_range=self.shared_memory_service.contract.external_range)
        return document

    def _validate_shared_service(self):
        shared = self.shared_memory_service
        if type(shared) is not BoomSharedMemoryService:
            raise ValueError('exact BOOM shared service required')
        shared.validate_binding()
        window, = self.router.windows
        target_service = getattr(window.target, 'memory_service', None)
        from myfuzz.scenario.memory_service import MemoryService
        if (window.device_id != 'dma' or (window.base, window.base + window.size)
                != shared.contract.control_range
                or type(target_service) is not MemoryService
                or target_service.memory is not shared.memory
                or getattr(window.target, 'routed_register_access_enabled', False) is not True
                or getattr(window.target, 'master_targets', None) != ()):
            raise ValueError('BOOM DMA router requires exact control span and same RAM object')
        pinned = getattr(self, '_shared_binding', None)
        if pinned is not None and any(actual is not expected for actual, expected in zip(
                (shared, shared.memory, self.router, window, window.target, target_service), pinned)):
            raise ValueError('BOOM shared/router memory binding changed')
        if getattr(self, 'mmio_ledger', shared.service.ledger) is not shared.service.ledger:
            raise ValueError('BOOM CPU memory/control ledger binding changed')
        if (getattr(self, 'service', shared.service) is not shared.service
                or getattr(self, 'memory', shared.memory) is not shared.memory):
            raise ValueError('BOOM Runner shared memory/service binding changed')
        return shared

    @property
    def process(self):
        return None if self._native is None else self._native._process

    @property
    def pending_responses(self):
        shared = self.shared_memory_service
        unfinished = (0 if shared is None else sum(
            record['status'] == 'service_complete_d_pending' for record in shared.records))
        return max(int(self._active is not None),
                   unfinished, len(self._pending_terminal_updates),
                   int(bool(self.mmio_ledger.unresolved_keys)),
                   int(any(item[0] is self.mmio_ledger for item in self.router._queued)),
                   0 if self._native is None else self._native.pending_responses)

    @property
    def pending_terminal_updates(self):
        """Detached diagnostics for revoked work whose terminal update failed."""
        return tuple(dict(source_transaction=asdict(key),
            native_request=deepcopy(item['active']['request']),
            previous_status=item['previous_status'], reason=item['reason'],
            last_error=item.get('last_error'), effect_may_have_occurred=True)
            for key, item in self._pending_terminal_updates.items())

    def begin_case(self, testcase_id: str):
        if self._cleanup_terminal or self._started or self._native is not None or self._case_id is not None:
            raise RuntimeError('BOOM adapter testcase already started')
        if type(testcase_id) is not str or not testcase_id:
            raise ValueError('testcase identity required')
        self._case_id = testcase_id
        self._started = True
        window = self.router.windows[0]
        try:
            external_range = (window.base, window.base + window.size)
            if self.shared_memory_service is not None:
                shared = self._validate_shared_service()
                shared.validate_fresh()
                self._shared_source_identity = shared.contract.authenticate_source(self.repo)
                external_range = shared.contract.external_range
            self._native = GeneratedBoomCpuSession(self.output, repo=self.repo,
                command_timeout_seconds=self._timeout,
                external_range=external_range)
            self._native.begin_case(testcase_id)
            self.reset_epoch = self._native.reset_epoch
            if self.shared_memory_service is not None:
                self.shared_memory_service.bind(execution_id=self._native.execution_id,
                    testcase_id=testcase_id, source_component=self.source_component,
                    reset_epoch=self.reset_epoch)
            self._native.load_program(self._program, address=self._program_address)
        except BaseException as primary:
            try:
                self._abort_pending('startup_failure')
            except BaseException as cleanup:
                raise primary from cleanup
            finally:
                self._case_id = None
            raise

    def _require_running(self):
        if self._cleanup_terminal or self._native is None or self._case_id is None or self.process is None:
            raise RuntimeError('BOOM adapter testcase is not running')

    def _event(self, kind, **payload):
        if len(self.source_events) >= 100000:
            raise RuntimeError('BOOM source event bound exceeded')
        self.source_events.append({'kind': kind, 'schema_version': 'boom_routing_observation.v1',
            'execution_id': self._native.execution_id, 'reset_epoch': self.reset_epoch,
            'local_tick': self.local_ticks, 'authority': 'observation_only',
            'source_authority': False, **payload})

    def _validate_request(self, request):
        validate_boom_external_request(request, reset_epoch=self.reset_epoch)
        address = request['address']
        if self.shared_memory_service is not None:
            shared = self._validate_shared_service()
            if shared.contract.contains_data(address):
                return 'memory'
        if not self.router.owns(address) or not self.router.owns(address + 3):
            raise ValueError('unsupported BOOM register transfer shape')
        return 'control'

    def _enqueue(self, request):
        if self._cleanup_terminal:
            raise RuntimeError('BOOM external cleanup is terminal; fresh sessions required')
        try:
            route = self._validate_request(request)
        except (ValueError, RuntimeError):
            self._event('boom_external_request_refused',
                native_request=deepcopy(request), effect_may_have_occurred=False,
                recovery='abort_and_replay_testcase')
            raise
        if self._active is not None:
            if self._active['request'] != request:
                raise RuntimeError('BOOM external identity changed while pending')
            return
        if request['request_sequence'] != self._accepted_sequence + 1:
            raise ValueError('BOOM external native acceptance sequence is not consecutive')
        key = TransactionKey(self._native.execution_id, self._case_id,
            self.source_component, self.reset_epoch, 'coherent-A-uncached',
            request['request_sequence'])
        active = {'request': deepcopy(request), 'key': key, 'status': 'target_pending',
                  'route': route}
        self._active = active
        self._accepted_sequence = request['request_sequence']
        request = active['request']
        execution, epoch = self._native.execution_id, self.reset_epoch

        def complete(response):
            if (self._active is not active or self._native.execution_id != execution
                    or self.reset_epoch != epoch or active['status'] != 'target_pending'):
                raise RuntimeError('stale/duplicate BOOM router callback')
            self._require_running()
            if self.shared_memory_service is not None:
                self._validate_shared_service()
            if (not isinstance(response, tuple) or len(response) != 2
                    or type(response[0]) is not int or not 0 <= response[0] < 1 << 64
                    or type(response[1]) is not int or response[1] != 0):
                raise ValueError('unsupported BOOM target response')
            active['status'] = 'd_submitting'
            self._native.respond_external(source=request['source'], size=request['size'],
                request_sequence=request['request_sequence'], reset_epoch=epoch,
                data=response[0])
            active.update(status='d_offered', data=response[0])
            self._event('boom_external_d_offered', source_transaction=asdict(key),
                        response_data=response[0])

        if route == 'memory':
            self._event('boom_external_a_memory_accepted', source_transaction=asdict(key),
                        native_request=deepcopy(request))
            response = self.shared_memory_service.execute(key, request)
            self._event('boom_external_memory_service_complete',
                source_transaction=asdict(key),
                service_record=deepcopy(self.shared_memory_service.records[-1]))
            complete((response, 0))
            return
        active.update(control_window=self.router.windows[0], control_ledger=self.mmio_ledger,
            control_payload=dict(device_id=self.router.windows[0].device_id,
                address=request['address'], write=request['opcode'] != 4,
                wdata=request['data'], be=request['mask'], beat_bytes=8))
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
                    if active['route'] == 'memory':
                        self.shared_memory_service.finish(active['key'], status='d_accepted')
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
        except BaseException as primary:
            try:
                self._abort_pending('step_failure')
            except BaseException as cleanup:
                raise primary from cleanup
            raise

    def _abort_pending(self, reason):
        """Revoke first, then attempt every cleanup without losing failures."""
        self._cleanup_terminal = True
        active, self._active = self._active, None
        previous = None if active is None else active['status']
        if active is not None:
            active['status'] = 'cancelled'
        errors = []
        try:
            self.router.cancel_for_ledger(self.mmio_ledger)
        except BaseException as error:
            errors.append(error)
            if active is not None and active['route'] == 'control':
                # Router only replaces its queue after all ledger cancellations
                # succeed. A retained queue must become undrainable before a
                # future target step, rather than relying on the late callback.
                try:
                    ledger, key = active['control_ledger'], active['key']
                    entry = ledger._entries.get(key)
                    if entry is None or entry.status not in ('cancelled', 'complete'):
                        ledger.cancel_accepted(key, active['control_payload'])
                    if ledger.target_ready(key):
                        raise RuntimeError('BOOM control cancellation left target ready')
                except BaseException as fallback:
                    errors.append(fallback)
                    try:
                        active['control_window'].target.close()
                    except BaseException as target_close:
                        errors.append(target_close)
        if (active is not None and active['route'] == 'memory'
                and active['key'] in self.shared_memory_service.receipts):
            self._pending_terminal_updates.setdefault(active['key'], dict(
                active=active, previous_status=previous, reason=reason))
        for key, item in tuple(self._pending_terminal_updates.items()):
            try:
                records = [record for record in self.shared_memory_service.records
                           if record['source_transaction'] == asdict(key)]
                if len(records) != 1:
                    raise RuntimeError('BOOM pending terminal update lost its service record')
                if records[0]['status'] == 'service_complete_d_pending':
                    self.shared_memory_service.finish(key, status='cancelled')
                if records[0]['status'] not in ('cancelled', 'd_accepted'):
                    raise RuntimeError('BOOM terminal update did not resolve its service record')
                del self._pending_terminal_updates[key]
            except BaseException as error:
                item['last_error'] = repr(error)
                errors.append(error)
        if active is not None and self._native is not None:
            try:
                self._event('boom_external_response_cancelled',
                    source_transaction=asdict(active['key']),
                    previous_status=previous, reason=reason,
                    effect_may_have_occurred=(previous != 'target_pending'
                        or active['key'] in self.mmio_ledger.uncertain_keys
                        or (active['key'] in self.mmio_ledger._entries
                            and self.mmio_ledger._entries[active['key']].status == 'complete')
                        or active['key'] in getattr(self.shared_memory_service, 'receipts', {})))
            except BaseException as error:
                errors.append(error)
        native = self._native
        if native is not None:
            try:
                native.close()
            except BaseException as error:
                # Keep the handle reachable so end_case can retry cleanup.
                errors.append(error)
            else:
                self._native = None
        if len(errors) == 1:
            raise errors[0]
        if errors:
            raise BaseExceptionGroup('BOOM external cleanup failures', errors)

    def begin_quiesce(self):
        self._require_running()
        self._native.begin_quiesce()
        self._quiescing = True

    def reset_local(self):
        self._require_running()
        if self.shared_memory_service is not None:
            primary = RuntimeError('BOOM shared reset requires fresh sessions and fresh memory')
            try:
                self._abort_pending('fresh_shared_memory_reset_required')
            except BaseException as cleanup:
                raise primary from cleanup
            raise primary
        cancelled = self.pending_responses
        try:
            targets = self.router.cancel_for_ledger(self.mmio_ledger)
            if self.mmio_ledger.uncertain_keys:
                raise RuntimeError('uncertain BOOM target effect requires testcase abort')
            if self._active is not None:
                self._event('boom_external_response_cancelled',
                    source_transaction=asdict(self._active['key']),
                    previous_status=self._active['status'], reason='reset')
            result = self._native.reset_local()
            self.reset_epoch = self._native.reset_epoch
            self._stream.acknowledge_reset(result,
                execution_id=self._native.execution_id,
                reset_epoch=self.reset_epoch, local_tick=self.local_ticks)
            self._active = None
            self._accepted_sequence = 0
            self._quiescing = False
            self.last_samples = ()
            self._native.load_program(self._program, address=self._program_address)
            self._event('boom_reset_static_boot_loaded',
                cancelled_source_requests=[asdict(key) for key in targets])
            return {'cancelled_responses': cancelled,
                    'cancelled_target_requests': tuple(str(key) for key in targets),
                    'cancelled_native_requests': result['cancelled_target_requests']}
        except BaseException as primary:
            try:
                self._abort_pending('reset_failure')
            except BaseException as cleanup:
                raise primary from cleanup
            raise

    def end_case(self):
        try:
            self._abort_pending('end_case')
        finally:
            self._case_id = None

    close = end_case

    def coherent_report(self):
        return self._stream.report()

    def coherent_coverage(self):
        return self._stream.coverage()
