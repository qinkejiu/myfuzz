"""Measured dual-role wbdmac edges with one outstanding master response.

Register accesses advance the same real DMA process. RAM and declared UART
target effects use only accepted RTL master payloads.
"""
from dataclasses import asdict, dataclass
from copy import deepcopy

from .session import GeneratedLocalSession
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory_service import MemoryService


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
                or any(type(value) is not int or not 0 <= value <= 0xffffffff
                       for value in self.accepted_write_values)
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

    @property
    def pending_responses(self):
        return int(self._pending is not None)

    def begin_case(self, testcase_id):
        super().begin_case(testcase_id)
        self._pending = None
        self._source_sequence = 0
        self._quiescing = False
        self.events = []

    def begin_quiesce(self):
        self._quiescing = True

    def _deliver_target(self, key, target, address, write, value):
        before_tick = target.endpoint.local_ticks
        before_events = len(target.endpoint.uart_events)
        rdata = 0
        if write:
            target.endpoint.write_register(address-target.base, value, be=15)
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
                len(target.endpoint.uart_events)])
        if not write:
            target_receipt['target_access_id'] = observation['access_id']
            target_receipt['target_uart_access'] = observation
        return rdata, target_receipt

    def step_local(self, *, cyc=0, stb=0, we=0, adr=0, data=0):
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
            if not invalid:
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
