"""Generic single-outstanding completion memory service over generated RTL."""
from __future__ import annotations
import copy
from collections.abc import Mapping
from .session import GeneratedLocalSession
from myfuzz.scenario.contracts import ProtocolEnvironmentError
from myfuzz.scenario.ledger import TransactionKey,TransactionLedger
from myfuzz.scenario.memory import PersistentMemory
from myfuzz.scenario.memory_service import MemoryService


class GeneratedNativeMemorySession(GeneratedLocalSession):
    """RAM/ROM service only; native errors terminate without fake completion.

    No IRQ or instruction decoding is synthesized by the environment. An
    optional typed physical instruction marker remains an RTL observation.
    """
    artifact_kind = 'native_memory_cpu'
    max_driver_samples_per_operation=1
    max_memory_materialized_bytes_per_operation=4
    max_pending_responses=1
    max_local_ticks_per_step=1
    max_transaction_events_per_step=1
    max_mmio_target_accesses_per_step=0
    runtime_kind='native_memory_cpu'
    service_schema='generated_native_memory_service.v1'
    read_request_be=15

    def __init__(self,artifact,*,base_dir,cache_dir,memory,**kwargs):
        if artifact.runtime_document.get('kind')!=self.runtime_kind or not isinstance(memory,PersistentMemory):
            raise ValueError('native completion CPU requires authenticated artifact and persistent memory')
        super().__init__(artifact,base_dir=base_dir,cache_dir=cache_dir,**kwargs)
        self.memory=memory
        self.service=MemoryService(memory,TransactionLedger())
        self._pending=None
        self._sequence_memory=0
        self._quiescing=False
        self.memory_write_count=0
        self.native_instruction_fetch_count=0
        self.accepted_addresses=[]
        self.last_samples=()

    def identity_document(self):
        return {**super().identity_document(),
                'native_service_schema_version':self.service_schema,
                'source_component':self.artifact.plan.request.instance_id,
                'memory_policy':'ram-rom-only'}

    @property
    def pending_responses(self):
        return int(self._pending is not None)

    def begin_case(self,testcase_id):
        super().begin_case(testcase_id)
        self._pending=None;self._sequence_memory=0;self._quiescing=False;self.last_samples=()

    def begin_quiesce(self):
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError('native process is not running')
        self._quiescing=True

    def reset_local(self):
        cancelled=self.pending_responses
        self._pending=None
        super().reset_local()
        return {'cancelled_responses':cancelled}

    def step_local(self,inputs:Mapping[str,int]):
        if not isinstance(inputs,Mapping) or inputs:
            raise ValueError('native memory CPU has no declared external inputs')
        pending=self._pending
        controls=(int(pending is None and not self._quiescing),int(pending is not None),pending[0] if pending else 0,0)
        receipt=self.command('STEP_MEMORY',controls)
        if receipt.status!='result' or receipt.new_ticks!=1:
            self._abort()
            raise ProtocolEnvironmentError('native completion fault: '+str(receipt.error_detail))
        payload=receipt.payload
        pre=payload['pre_backend']
        names=('m_req_ready','m_rsp_valid','m_rsp_rdata','m_rsp_error')
        if (any(pre[name]!=value for name,value in zip(names,controls))
            or payload['samples'][0]['pre']['backend']!=pre):
            raise ProtocolEnvironmentError('native command handshake observation mismatch')
        self.last_samples=tuple(copy.deepcopy(payload['samples']))
        accepted=int(bool(pre['m_req_valid'] and pre['m_req_ready']))
        consumed=int(bool(pre['m_rsp_valid'] and pre['m_rsp_ready']))
        if consumed:
            if pending is None:raise ProtocolEnvironmentError('native response without request')
            self._pending=None
        if accepted:
            if pending is not None:raise ProtocolEnvironmentError('native concurrent request')
            address=pre['m_req_addr'];write=pre['m_req_write'];be=pre['m_req_be'];value=pre['m_req_wdata']
            if address%4 or (not write and be!=self.read_request_be):
                self._abort();raise ProtocolEnvironmentError('native unaligned or incomplete read')
            self._sequence_memory+=1
            key=TransactionKey('local-execution',self._case_id,self.artifact.plan.request.instance_id,
                self.reset_epoch,'memory',self._sequence_memory)
            try:
                if write:
                    self.service.write(key,address,value,width_bytes=4,byte_enable=be)
                    self.memory_write_count+=1;response=0
                else:response=self.service.read(key,address,width_bytes=4).value
            except (ValueError,RuntimeError) as error:
                self._abort();raise ProtocolEnvironmentError('native backend error without completion') from error
            self._pending=(response,self._sequence_memory)
            self.accepted_addresses.append(address)
            marker=self._artifact_document.get('instruction_identity_observation')
            if marker and payload['samples'][0]['pre']['physical'][marker]:
                if write:self._abort();raise ProtocolEnvironmentError('instruction marker accompanied a write')
                self.native_instruction_fetch_count+=1
        self.memory.advance_step()
        physical=payload['observations']['physical']
        outputs={}
        for row in self._artifact_document['physical_exports']:
            if row['direction']=='output':
                raw=physical[row['runtime_name']]
                value=int(raw,16) if row['width']>64 else raw
                if type(value) is not int or not 0<=value<1<<row['width']:
                    raise ProtocolEnvironmentError('native physical output width mismatch')
                name=row['physical_port'];outputs[name]=outputs.get(name,0)|(value<<row['bit_lo'])
        return {**outputs,'data_req_valid':pre['m_req_valid'],'data_req_accepted':accepted,
            'data_write':pre['m_req_write'],'data_addr':pre['m_req_addr'],
            'data_wdata':pre['m_req_wdata'],'data_be':pre['m_req_be'],
            'data_rsp_consumed':consumed,'data_rsp_rdata':pending[0] if consumed else 0,
            'data_rsp_source_epoch':self.reset_epoch if consumed else 0,
            'data_rsp_source_sequence':pending[1] if consumed else 0,
            'driver_samples':copy.deepcopy(self.last_samples),
            'physical_observations':copy.deepcopy(physical)}
