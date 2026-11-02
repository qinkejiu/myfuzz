"""Closed four-read/four-write RAM policy behind live route admission.

Policy records are comparison data. Only the native/service bridge issues read
authority; accepting a source-version document never grants that authority.
"""
from copy import deepcopy
from dataclasses import asdict
import json

from .ledger import TransactionKey
from .f6_execution_contract import CONTRACT_KEYS, EXPECTATION_IDS, SCHEMA_VERSION


def _key(key):
    if (type(key) is not TransactionKey
            or any(type(getattr(key,n)) is not str or not getattr(key,n)
                   for n in ('execution_id','testcase_id','source_component','channel_id'))
            or any(type(getattr(key,n)) is not int or not 0 <= getattr(key,n) < 2**64
                   for n in ('source_epoch','source_sequence'))):
        raise ValueError('F6 policy requires a complete typed key')
    return key


def _json(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)


class F6RamDmaPolicy:
    def __init__(self, contract):
        from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
        if (type(contract) is not dict or set(contract) != CONTRACT_KEYS
                or contract['schema_version'] != SCHEMA_VERSION
                or contract['expectation_ids'] != list(EXPECTATION_IDS)):
            raise ValueError('F6 policy requires the complete closed contract')
        build_f6_firmware(contract)
        self._contract = _json(contract)
        self._state = 'idle'
        self._scope = None
        self._pending = None
        self._case = None
        self._sources = None
        self._fault = None
        self._read = self._write = 0
        self._epoch = None
        self._keys = set()
        self._last_sequence = 0
        self._records = []

    @property
    def state(self):
        return self._state

    @property
    def records(self):
        return deepcopy(self._records)

    def identity_document(self):
        return dict(schema_version='f6_ram_dma_policy.v1', contract=json.loads(self._contract),
                    read_words=4,write_words=4,order='four_reads_then_four_writes',byte_enable=15)

    def begin_case(self, execution_id, testcase_id):
        # A native restart can replace a ready scope that never armed a transfer.
        # Pending, active and faulted transfers still require explicit cancellation.
        untouched_ready = (self._state == 'ready' and self._scope is not None
            and execution_id != self._scope[0] and self._pending is None
            and self._case is None and self._sources is None and self._fault is None
            and self._read == self._write == 0 and self._epoch is None
            and not self._keys and not self._records and self._last_sequence == 0)
        if (any(type(v) is not str or not v for v in (execution_id,testcase_id))
                or self._pending is not None
                or (self._state not in ('idle','complete') and not untouched_ready)):
            raise ValueError('F6 policy case cannot begin with an active or faulted transfer')
        self._scope = execution_id,testcase_id
        self._state = 'ready'
        self._case = None
        self._keys.clear();self._records.clear()
        self._last_sequence=0;self._epoch=None

    def begin_transfer(self, *, case_id, source_versions, fault=None):
        from myfuzz.local_harness.f6_dma_response_fault import F6ResponseFaultDeclaration
        if (self._scope is None or self._state not in ('ready','complete')
                or type(case_id) is not str or not case_id or case_id == self._case
                or type(source_versions) not in (list,tuple) or len(source_versions) != 4
                or fault is not None and type(fault) is not F6ResponseFaultDeclaration):
            raise ValueError('F6 transfer requires a new case and four source versions')
        contract=json.loads(self._contract);p=contract['program_contract']
        copied=[]
        for i,row in enumerate(source_versions):
            if (type(row) is not dict or set(row) != {'address','value','memory_id','generation',
                    'byte_offset','versions','writer_event_ids','writer_kinds'}
                    or type(row['address']) is not int or row['address'] != p['source_address']+4*i
                    or type(row['value']) is not int or not 0 <= row['value'] <= 2047
                    or type(row['memory_id']) is not str or not row['memory_id']
                    or any(type(row[n]) is not int or not 0 <= row[n] < 2**64 for n in ('generation','byte_offset'))
                    or type(row['versions']) is not list or len(row['versions']) != 4
                    or any(type(v) is not list or len(v) != 2
                           or any(type(n) is not int or not 0 <= n < 2**64 for n in v)
                           or v[0] != row['generation'] or v[1] == 0 for v in row['versions'])
                    or type(row['writer_event_ids']) is not list or len(row['writer_event_ids']) != 4
                    or any(type(v) is not str or not v for v in row['writer_event_ids'])
                    or row['writer_kinds'] != ['STORE']*4):
                raise ValueError('F6 source byte versions are incomplete or contradictory')
            copied.append(deepcopy(row))
        if len({s['value'] for s in copied}) != 4:
            raise ValueError('F6 source words must be distinct')
        self._case=case_id;self._sources=copied;self._fault=fault
        self._read=self._write=0;self._pending=None;self._records=[];self._state='transferring'

    def accepted(self,key,*,address,write,value,byte_enable,target):
        _key(key)
        contract=json.loads(self._contract);p=contract['program_contract']
        count=self._write if write is True else self._read
        if (self._state != 'transferring' or self._pending is not None
                or (key.execution_id,key.testcase_id) != self._scope
                or key.source_component != contract['dma']['instance_id'] or key.channel_id != 'dma-memory'
                or self._epoch is not None and key.source_epoch != self._epoch
                or key in self._keys or key.source_sequence <= self._last_sequence
                or type(write) is not bool or type(address) is not int or type(value) is not int
                or not 0 <= value < 2**32 or type(byte_enable) is not int or byte_enable != 15
                or target is not None or count >= 4
                or write and self._read != 4 or not write and self._write != 0
                or address != p['destination_address' if write else 'source_address']+4*count
                or write and value != self._sources[count]['value']):
            raise ValueError('F6 beat violates scope, four-word order, address, value or BE')
        self._epoch=key.source_epoch;self._keys.add(key);self._last_sequence=key.source_sequence
        self._pending=(key,write,count,value)
        self._records.append(dict(transaction=asdict(key),address=address,write=write,
                                  value=value,byte_enable=byte_enable,word_index=count))

    def completed(self,key,*,rdata,error):
        _key(key)
        if (self._pending is None or self._pending[0] is not key
                or type(error) is not int or error not in (0,1)
                or type(rdata) is not int or not 0 <= rdata < 2**32):
            raise ValueError('F6 completion requires the exact pending typed key')
        _,write,index,_=self._pending
        if error:
            if self._fault is None or (self._fault.operation,self._fault.word_index) != ('write' if write else 'read',index):
                raise ValueError('unexpected F6 native response error')
            self._records[-1].update(rdata=rdata,error=error)
            self._pending=None;self._state='expected_response_fault_pending'
            return
        if not write and rdata != self._sources[index]['value']:
            raise ValueError('F6 read response differs from source word')
        self._records[-1].update(rdata=rdata,error=error);self._pending=None
        if write:self._write+=1
        else:self._read+=1
        if self._write==4:self._state='complete'
