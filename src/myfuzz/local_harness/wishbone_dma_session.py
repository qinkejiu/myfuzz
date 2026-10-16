"""Measured dual-role wbdmac edges with a one-outstanding RAM environment.

Register accesses advance the same real DMA process. RAM writes use only the
accepted RTL master payload; this helper does not implement a copy operation.
"""
from dataclasses import asdict

from .session import GeneratedLocalSession
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory_service import MemoryService


class GeneratedWishboneDmaSession(GeneratedLocalSession):
    def __init__(self, artifact, *, memory=None, memory_service=None,
                 source_component='dma', max_control_edges=32, max_events=10000,
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
        self.memory_service = (memory_service if memory_service is not None else
                               MemoryService(memory, TransactionLedger()))
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
            invalid = False
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
            rdata = 0
            if not invalid:
                if pre['mwb_we']:
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
        return document
