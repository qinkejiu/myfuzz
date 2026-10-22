"""Measured dual-role wbdmac edges with one outstanding master response.

Register accesses advance the same real DMA process. RAM and declared UART
target effects use only accepted RTL master payloads.
"""
from dataclasses import asdict, dataclass
from copy import deepcopy
import json

from .session import GeneratedLocalSession
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory_service import MemoryService


def _accepted_word_range_bounds(values):
    """Return accepted range endpoints without iterating the range."""
    if not isinstance(values, range) or not values:
        return None
    if values.step > 0:
        last = values.start + ((values.stop - 1 - values.start) // values.step) * values.step
    else:
        step = -values.step
        last = values.start - ((values.start - 1 - values.stop) // step) * step
    return values.start, last


def _valid_accepted_write_values(values):
    if isinstance(values, tuple):
        return all(type(value) is int and 0 <= value <= 0xffffffff
                   for value in values)
    if isinstance(values, range):
        bounds = _accepted_word_range_bounds(values)
        return (bounds is None or
                (0 <= min(bounds) and max(bounds) <= 0xffffffff))
    return False


def dma_route_endpoint_identity_document(endpoint):
    """Return stable route identity without asking a build/cache scanner."""
    def pin_provider(document):
        provider_identity = getattr(endpoint,
            'dma_master_target_provider_identity_document', None)
        if callable(provider_identity):
            document['dma_master_target_provider'] = deepcopy(provider_identity())
        return document

    method = getattr(endpoint, 'dma_route_endpoint_identity_document', None)
    if callable(method):
        return pin_provider(deepcopy(method()))
    artifact_document = getattr(endpoint, '_artifact_document', None)
    if type(artifact_document) is dict:
        artifact = getattr(endpoint, 'artifact', None)
        current = getattr(artifact, 'runtime_document', artifact_document)
        if current != artifact_document:
            raise ValueError('route endpoint artifact changed after session creation')
        return pin_provider(dict(schema_version='generated_local_route_endpoint.v1',
            runtime_artifact=deepcopy(artifact_document)))
    identity = getattr(endpoint, 'identity_document', None)
    if not callable(identity):
        raise ValueError('route endpoint has no stable identity document')
    return pin_provider(deepcopy(identity()))


def _canonical_dma_route_admission_identity(admission):
    """Serialize a detached admission identity for the session's pin."""
    identity = getattr(admission, 'identity_document', None)
    if not callable(identity):
        raise ValueError('DMA route admission must expose identity_document')
    document = identity()
    if type(document) is not dict or type(document.get('schema_version')) is not str:
        raise ValueError('DMA route admission identity document is invalid')
    try:
        return json.dumps(document, sort_keys=True, separators=(',', ':'),
            ensure_ascii=False, allow_nan=False).encode('utf-8')
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ValueError('DMA route admission identity document is not canonical JSON') from error


@dataclass(frozen=True)
class MasterTargetWindow:
    """One explicit 32-bit DMA master destination backed by real target RTL."""

    component: str
    base: int
    size: int
    endpoint: object
    writable_offsets: tuple[int, ...]
    accepted_write_values: tuple[int, ...] | range
    byte_enable: int = 15
    readable_offsets: tuple[int, ...] = ()

    def __post_init__(self):
        if (type(self.component) is not str or not self.component
                or type(self.base) is not int or self.base < 0
                or self.base % 0x1000 or type(self.size) is not int
                or self.size < 4 or self.size % 4
                or self.base + self.size > 1 << 64
                or type(self.writable_offsets) is not tuple
                or any(type(offset) is not int or offset < 0
                       or offset % 4 or offset + 4 > self.size
                       for offset in self.writable_offsets)
                or len(set(self.writable_offsets)) != len(self.writable_offsets)
                or type(self.readable_offsets) is not tuple
                or any(type(offset) is not int or offset < 0
                       or offset % 4 or offset + 4 > self.size
                       for offset in self.readable_offsets)
                or len(set(self.readable_offsets)) != len(self.readable_offsets)
                or not (self.writable_offsets or self.readable_offsets)
                or (self.readable_offsets and
                    (self.component != 'uart' or self.readable_offsets != (0x18,)
                     or not callable(getattr(self.endpoint,
                         'read_register', None))))
                or not isinstance(self.accepted_write_values, (tuple, range))
                or bool(self.accepted_write_values) != bool(self.writable_offsets)
                or not _valid_accepted_write_values(self.accepted_write_values)
                or type(self.byte_enable) is not int or self.byte_enable != 15
                or not callable(getattr(self.endpoint, 'write_register', None))):
            raise ValueError('invalid DMA master target window')

    def contains(self, address):
        return self.base <= address and address + 4 <= self.base + self.size

    def accepts(self, address, write, value, byte_enable):
        return (self.contains(address) and byte_enable == self.byte_enable and
                ((write and address - self.base in self.writable_offsets and
                  value in self.accepted_write_values) or
                 (not write and address - self.base in self.readable_offsets)))

    def identity_document(self):
        values = self.accepted_write_values
        return dict(component=self.component, base=self.base, size=self.size,
            writable_offsets=list(self.writable_offsets),
            accepted_write_values=([values.start, values.stop - 1]
                if isinstance(values, range) and values else list(values)),
            readable_offsets=list(self.readable_offsets),
            byte_enable=self.byte_enable,
            endpoint_identity=self.endpoint.identity_document())

    def route_identity_document(self):
        """Injective v2 identity, kept separate from the historical v1 form."""
        values = self.accepted_write_values
        accepted = ({'kind': 'range', 'start': values.start,
                     'stop': values.stop, 'step': values.step}
                    if isinstance(values, range) else
                    {'kind': 'tuple', 'values': list(values)})
        return dict(schema_version='dma_master_target_window.v2',
            component=self.component, base=self.base, size=self.size,
            writable_offsets=list(self.writable_offsets),
            accepted_write_values=accepted,
            readable_offsets=list(self.readable_offsets),
            byte_enable=self.byte_enable,
            endpoint_identity=dma_route_endpoint_identity_document(self.endpoint))


class GeneratedWishboneDmaSession(GeneratedLocalSession):
    def __init__(self, artifact, *, memory=None, memory_service=None,
                 source_component='dma', max_control_edges=32, max_events=10000,
                 master_targets=(),
                 **kwargs):
        super().__init__(artifact, **kwargs)
        if artifact.runtime_document['kind'] != 'wishbone_dma':
            raise ValueError('wishbone_dma artifact required')
        if (memory is None) == (memory_service is None):
            raise ValueError('provide exactly one memory or memory_service')
        if not source_component or type(max_control_edges) is not int or max_control_edges < 4:
            raise ValueError('invalid DMA session bounds')
        if type(max_events) is not int or max_events < 1:
            raise ValueError('invalid DMA event bound')
        if (type(master_targets) is not tuple or
                any(type(window) is not MasterTargetWindow for window in master_targets)):
            raise ValueError('invalid DMA master targets')
        for index, window in enumerate(master_targets):
            if any(window.base < old.base + old.size and
                   old.base < window.base + window.size
                   for old in master_targets[:index]):
                raise ValueError('overlapping DMA master targets')
        self.memory_service = (memory_service if memory_service is not None else
                               MemoryService(memory, TransactionLedger()))
        for window in master_targets:
            if any(window.base < region_base + region_size and
                   region_base < window.base + window.size
                   for region in self.memory_service.memory.identity_document()['regions']
                   for region_base, region_size in
                   ((region['base'], region['size']),
                    *((alias, region['size']) for alias in region['aliases']))):
                raise ValueError('DMA master target overlaps memory')
        self.master_targets = master_targets
        self.source_component = source_component
        self.max_control_edges = max_control_edges
        self.max_events = max_events
        self.events = []
        self._pending = None
        self._source_sequence = 0
        self._quiescing = False
        self._dma_route_validator = None
        self._dma_route_admission = None
        self._dma_route_admission_identity = None

    def configure_dma_route_validator(self, callback):
        """Pin the compiled topology validator before this session starts."""
        if not callable(callback):
            raise ValueError('DMA route validator must be callable')
        if self._dma_route_validator is not None:
            raise ValueError('DMA route validator is already configured')
        if (self._execution or self._process is not None or self._case_id is not None
                or self.local_ticks != 0 or self.events):
            raise ValueError('DMA route validator must be configured before startup')
        self._dma_route_validator = callback

    def configure_dma_route_admission(self, admission):
        """Install a typed route-beat policy before the DMA process starts."""
        if (not callable(getattr(admission, 'accepted', None))
                or not callable(getattr(admission, 'completed', None))):
            raise ValueError('DMA route admission must implement accepted/completed')
        if self._dma_route_admission is not None:
            raise ValueError('DMA route admission is already configured')
        if (self._execution or self._process is not None or self._case_id is not None
                or self.local_ticks != 0 or self.events):
            raise ValueError('DMA route admission must be configured before startup')
        identity_snapshot = _canonical_dma_route_admission_identity(admission)
        self._dma_route_admission = admission
        self._dma_route_admission_identity = identity_snapshot
        topology_validator = self._dma_route_validator

        def validate_pinned_route_admission():
            if self._dma_route_admission is not admission:
                raise ValueError('compiled DMA route admission changed')
            if (_canonical_dma_route_admission_identity(admission)
                    != self._dma_route_admission_identity):
                raise ValueError('compiled DMA route admission identity changed')
            if topology_validator is not None:
                topology_validator()

        self._dma_route_validator = validate_pinned_route_admission

    def dma_route_endpoint_identity_document(self):
        """Stable DMA master profile identity without build/cache inspection."""
        self._check_artifact_stable()
        return dict(schema_version='wishbone_dma_route_endpoint.v1',
            runtime_artifact=deepcopy(self._artifact_document),
            command_timeout_seconds=self.command_timeout_seconds,
            source_component=self.source_component,
            max_control_edges=self.max_control_edges,
            max_events=self.max_events, address_shift=2,
            byte_enable=15, max_outstanding=1)

    def _validate_dma_route_topology(self):
        if self._dma_route_validator is not None:
            self._dma_route_validator()

    @property
    def pending_responses(self):
        return int(self._pending is not None)

    def begin_case(self, testcase_id):
        self._validate_dma_route_topology()
        super().begin_case(testcase_id)
        self._pending = None
        self._source_sequence = 0
        self._quiescing = False
        self.events = []
        if self._dma_route_admission is not None:
            begin_case = getattr(self._dma_route_admission, 'begin_case', None)
            if callable(begin_case):
                begin_case(self._execution, self._case_id)

    def begin_quiesce(self):
        self._quiescing = True

    def _deliver_target(self, key, target, address, write, value):
        before_tick = target.endpoint.local_ticks
        before_events = GeneratedWishboneDmaSession._target_event_count(target.endpoint)
        rdata = 0
        observation = None
        route_mode = None
        provider_receipt = None
        if write:
            provider = getattr(target.endpoint, 'dma_master_target_access', None)
            if callable(provider):
                delivery_context = dict(source_transaction=asdict(key),
                    device_id=target.component, address=address,
                    offset=address-target.base, write=True, value=value, be=15,
                    window_base=target.base, window_size=target.size)
                provider_receipt = provider(key, address=address,
                    offset=address-target.base, write=True, value=value,
                    byte_enable=15, delivery_context=deepcopy(delivery_context))
                self._validate_dma_master_target_provider_receipt(key,
                    provider_receipt, address=address,
                    offset=address-target.base, write=True, value=value,
                    byte_enable=15)
                rdata = provider_receipt['response']['rdata']
                observation = provider_receipt['target_access']
                route_mode = 'dma_master_target_access.v1'
            else:
                target.endpoint.write_register(address-target.base, value, be=15)
        else:
            master_access = (getattr(target.endpoint, 'master_target_access', None)
                if getattr(target.endpoint, 'source_provenance_enabled', False)
                else None)
            if callable(master_access):
                # S4: the DMA master read carries its own transaction identity,
                # so the UART pop can be authenticated instead of being an
                # unattributed ``read_register``.  The endpoint returns the very
                # same measured ``uart_rdata_access`` record.
                delivery_context = dict(source_transaction=asdict(key),
                    device_id=target.component, address=address,
                    offset=address-target.base, write=False, value=0, be=15,
                    window_base=target.base, window_size=target.size)
                reply = master_access(key, address=address,
                    offset=address-target.base, write=False, value=0, be=15,
                    delivery_context=delivery_context)
                rdata = reply['rdata']
                observation = reply.get('target_uart_access')
                route_mode = 'dma_master'
                if (not isinstance(observation, dict)
                        or observation.get('status') != 'observed'
                        or observation.get('read_value') != rdata):
                    raise RuntimeError(
                        'DMA UART RDATA read lacks real FIFO pop proof')
            else:
                rdata = target.endpoint.read_register(address-target.base)
                new_reads = [row for row in target.endpoint.uart_events[before_events:]
                    if row.get('kind') == 'uart_rdata_access']
                observation = new_reads[0] if len(new_reads) == 1 else None
                if (type(rdata) is not int or not 0 <= rdata <= 255
                        or type(observation) is not dict
                        or observation.get('status') != 'observed'
                        or observation.get('read_value') != rdata
                        or type(observation.get('access_id')) is not str
                        or not observation['access_id']
                        or observation.get('read_capture', {}).get('pre', {}).get(
                            'probe_uart_fifo_rvalid') != 1
                        or observation.get('read_capture', {}).get('pre', {}).get(
                            'probe_uart_fifo_rdata_re') != 1
                        or observation.get('read_capture', {}).get('pre', {}).get(
                            'probe_uart_fifo_under_rst') != 0):
                    raise RuntimeError('DMA UART RDATA read lacks real FIFO pop proof')
        target_receipt = dict(source_transaction=asdict(key),
            target_component=target.component, address=address,
            offset=address-target.base, write=write,
            value=value if write else rdata, byte_enable=15,
            target_tick_before=before_tick,
            target_tick_after=target.endpoint.local_ticks,
            target_event_range=[before_events,
                GeneratedWishboneDmaSession._target_event_count(target.endpoint)])
        if provider_receipt is not None:
            target_receipt.update(target_access_id=provider_receipt['target_access_id'],
                target_provider_receipt=deepcopy(provider_receipt),
                target_route_context_mode=route_mode)
        elif not write:
            target_receipt['target_access_id'] = observation['access_id']
            target_receipt['target_uart_access'] = observation
            target_receipt['target_route_context_mode'] = route_mode
        return rdata, target_receipt

    @staticmethod
    def _target_event_count(endpoint):
        for name in ('uart_events', 'gpio_events'):
            events = getattr(endpoint, name, None)
            if isinstance(events, (tuple, list)):
                return len(events)
        return 0

    @staticmethod
    def _validate_dma_master_target_provider_receipt(key, receipt, *,
            address, offset, write, value, byte_enable):
        required = {'schema_version', 'status', 'source_transaction',
            'request', 'response', 'target_access_id', 'target_access',
            'target_request', 'target_response', 'target_effect'}
        if (type(receipt) is not dict or set(receipt) != required
                or receipt.get('schema_version') != 'dma_master_target_access.v1'
                or receipt.get('status') != 'observed'):
            raise RuntimeError('DMA target provider receipt schema/status mismatch')
        key_document = asdict(key)

        def exact_identity(left, right):
            return (type(left) is dict and set(left) == set(right)
                and all(type(left[name]) is type(expected)
                        and left[name] == expected
                        for name, expected in right.items()))

        if not exact_identity(receipt.get('source_transaction'), key_document):
            raise RuntimeError('DMA target provider transaction key mismatch')
        expected_request = dict(address=address, offset=offset, write=write,
            value=value if write else 0, byte_enable=byte_enable)
        if not exact_identity(receipt.get('request'), expected_request):
            raise RuntimeError('DMA target provider request mismatch')
        response = receipt.get('response')
        if (type(response) is not dict or set(response) != {'rdata', 'error'}
                or type(response.get('rdata')) is not int
                or not 0 <= response['rdata'] <= 0xffffffff
                or type(response.get('error')) is not int
                or response['error'] != 0):
            raise RuntimeError('DMA target provider target response is invalid')
        access_id = receipt.get('target_access_id')
        if type(access_id) is not str or not access_id:
            raise RuntimeError('DMA target provider target evidence lacks access identity')
        for name in ('target_access', 'target_request', 'target_response'):
            witness = receipt.get(name)
            if (type(witness) is not dict or witness.get('status') != 'observed'
                    or not exact_identity(witness.get('source_transaction'), key_document)):
                raise RuntimeError('DMA target provider target evidence is incomplete')
            if (type(witness.get('access_id')) is not str
                    or witness['access_id'] != access_id):
                raise RuntimeError(
                    'DMA target provider target evidence access identity mismatch')
        if receipt['target_access'].get('access_id') != access_id:
            raise RuntimeError('DMA target provider target evidence access identity mismatch')
        effect = receipt.get('target_effect')
        if (type(effect) is not dict or effect.get('status') != 'observed'
                or not exact_identity(effect.get('source_transaction'), key_document)
                or not exact_identity(effect.get('request'), expected_request)):
            raise RuntimeError('DMA target provider target effect is incomplete')
        if (type(effect.get('access_id')) is not str
                or effect['access_id'] != access_id):
            raise RuntimeError(
                'DMA target provider target evidence access identity mismatch')

    def step_local(self, *, cyc=0, stb=0, we=0, adr=0, data=0):
        self._validate_dma_route_topology()
        if len(self.events) >= self.max_events:
            raise RuntimeError('DMA edge event capacity exhausted')
        pending = self._pending
        stall = int(pending is not None or self._quiescing)
        deliver = pending is not None and pending['delay'] == 0
        ack = int(deliver and not pending['error'])
        err = int(deliver and pending['error'])
        receipt = self.command('STEP_WB_DMA', (cyc,stb,we,adr,data,stall,ack,
                            pending['rdata'] if pending else 0,err))
        if receipt.status != 'result' or receipt.new_ticks != 1:
            raise RuntimeError('DMA edge did not complete')
        payload = receipt.payload
        pre = payload['pre_backend']
        event = dict(kind='dma_edge', tick=receipt.tick_after, payload=payload)
        if pending is not None and not deliver:
            pending['delay'] -= 1
        if deliver:
            event['response'] = dict(pending)
            self._pending = None
        if pre['mwb_cyc'] and pre['mwb_stb'] and not stall:
            self._source_sequence += 1
            key = TransactionKey(self._execution, self._case_id,
                self.source_component, self.reset_epoch, 'dma-memory', self._source_sequence)
            address = pre['mwb_adr'] << 2
            accepted = dict(transaction=asdict(key), address=address,
                word_address=pre['mwb_adr'], write=bool(pre['mwb_we']),
                value=pre['mwb_dat_w'], byte_enable=15)
            # Reject invalid resources before any service callback. Other failures
            # propagate; they must never be disguised as a peripheral bus error.
            target = next((window for window in self.master_targets
                           if window.contains(address)), None)
            admission = self._dma_route_admission
            if admission is not None:
                admission.accepted(key, address=address,
                    write=bool(pre['mwb_we']), value=pre['mwb_dat_w'],
                    byte_enable=15, target=target)
            invalid = False
            if target is None:
                try:
                    if pre['mwb_we']:
                        self.memory_service.memory.validate_write(
                            address,pre['mwb_dat_w'],width_bytes=4,byte_enable=15)
                    else:
                        self.memory_service.memory.validate_read(address,4)
                except ValueError as error:
                    if str(error) not in ('unmapped address; MMIO requires real IP response',
                                          'access crosses memory window',
                                          'read-only memory', 'write-only memory'):
                        raise
                    invalid = True
            else:
                invalid = not target.accepts(address, bool(pre['mwb_we']),
                                             pre['mwb_dat_w'], 15)
                if invalid:
                    accepted['target_rejection'] = 'declared_master_target_access'
            rdata = 0
            if invalid:
                # ERR completes a real accepted master request even though no
                # target is touched. Enroll it in the same channel as successful
                # operations so later requests retain contiguous source order.
                rejected_payload = dict(op='master_environment_error',
                    address=address, write=bool(pre['mwb_we']),
                    value=pre['mwb_dat_w'], byte_enable=15,
                    reason=accepted.get('target_rejection', 'memory_access_rejected'))
                event['environment_error_receipt'] = self.memory_service.ledger.execute_once(
                    key, rejected_payload, lambda: dict(source_transaction=asdict(key),
                        error=1, target_effect=False, **rejected_payload))
            else:
                # Revalidate immediately before the configured target/service
                # can observe this accepted native DMA request.
                self._validate_dma_route_topology()
                if target is not None:
                    write = bool(pre['mwb_we'])
                    target_payload = dict(op='master_target_write' if write
                        else 'master_target_read', address=address,
                        value=pre['mwb_dat_w'] if write else 0,
                        byte_enable=15, target_component=target.component,
                        target_offset=address-target.base)
                    rdata, target_receipt = self.memory_service.ledger.execute_once(
                        key, target_payload, lambda: self._deliver_target(
                            key, target, address, write, pre['mwb_dat_w']))
                    accepted['target_delivery'] = target_receipt
                    event['target_delivery'] = target_receipt
                elif pre['mwb_we']:
                    self.memory_service.write(key,address,pre['mwb_dat_w'],width_bytes=4,byte_enable=15)
                else:
                    rdata = self.memory_service.read(key,address,width_bytes=4).value
                if admission is not None:
                    admission.completed(key, rdata=rdata, error=0)
            # This pinned RTL registers its last-write ACK predictor. Give the
            # observed end of a write burst one extra settling edge. Uniform
            # latency environments are not verified by this session contract.
            self._pending = dict(transaction=asdict(key), rdata=rdata,error=int(invalid),delay=int(bool(pre['mwb_we'] and not
                payload['observations']['backend']['mwb_stb'])))
            event['accepted'] = accepted
        self.events.append(event)
        self.memory_service.memory.advance_step()
        return receipt

    def _access_register(self, offset, value, write, byte_enable):
        if type(offset) is not int or offset not in (0,4,8,12) or byte_enable != 15:
            raise ValueError('DMA control requires aligned full-word offset 0/4/8/12')
        if type(value) is not int or not 0 <= value <= 0xffffffff:
            raise ValueError('DMA register value exceeds 32 bits')
        # Source has registered slave inputs, no STALL. Admit exactly one STB.
        self.step_local(cyc=1,stb=1,we=int(write),adr=offset//4,data=value)
        for _ in range(self.max_control_edges-2):
            receipt = self.step_local(cyc=1,we=int(write),adr=offset//4,data=value)
            if receipt.payload['pre_backend']['swb_ack']:
                result = receipt.payload['pre_backend']['swb_dat_r']
                self.step_local()
                return result
        raise TimeoutError('DMA control ACK edge bound exceeded')

    routed_register_access_enabled = True

    def routed_register_access(self, key, *, address, offset, write, value, be,
                               delivery_context):
        """Translate one router-admitted CPU beat into measured real control edges.

        This is transaction-level routing between independent processes, not a
        claim of a synthesizable OBI/Wishbone bridge or shared hardware clock.
        """
        if not isinstance(key, TransactionKey) or type(write) is not bool:
            raise ValueError('DMA routed access requires a source transaction')
        start = len(self.events)
        rdata = self._access_register(offset,value,write,be)
        receipt = dict(source_transaction=asdict(key), address=address,
            offset=offset, write=write, value=value, byte_enable=be,
            delivery_context=deepcopy(delivery_context),
            edge_ticks=[event['tick'] for event in self.events[start:]])
        return dict(rdata=rdata, dma_control_receipt=receipt)

    def write_register(self, offset, value, *, byte_enable=15):
        return self._access_register(offset,value,True,byte_enable)

    def read_register(self, offset):
        return self._access_register(offset,0,False,15)

    def reset_local(self):
        cancelled = self.pending_responses
        super().reset_local()
        return dict(cancelled_responses=cancelled)

    def close(self):
        self.end_case()

    def identity_document(self):
        document = super().identity_document()
        document['dma_environment'] = dict(max_outstanding=1,
            response_delay_edges=1,
            write_burst_tail_extra_delay_edges=1, control_edge_bound=self.max_control_edges,
            max_events=self.max_events, address_shift=2,byte_enable=15,
            source_component=self.source_component)
        if self.master_targets:
            document['dma_environment']['master_targets'] = [
                window.identity_document() for window in self.master_targets]
        return document
