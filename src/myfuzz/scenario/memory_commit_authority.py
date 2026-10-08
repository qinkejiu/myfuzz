"""Live installed callback authority for modeled host RAM commits.

Content hashes and journal accepted labels are not authority. The installed
service's pending callback issuance must authenticate the exact receipt before
ack. Detached historical certificates do not grant UART or RTL RAM origin.
"""
from collections.abc import Mapping
from copy import deepcopy
import hashlib
import json
from .ledger import TransactionKey,TransactionLedger
from .memory import PersistentMemory
from .memory_service import MemoryService,WriteReceipt


def _wire(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def _uint(value):return type(value) is int and 0<=value<1<<64


class MemoryCommitAuthority:
    def __init__(self, *, services, max_services=16,max_pending=256,max_regions=256):
        for n in (max_services,max_pending,max_regions):
            if type(n) is not int or n<1:raise ValueError('invalid memory commit authority capacity')
        if not isinstance(services,Mapping) or not services or len(services)>max_services:
            raise ValueError('bounded installed services required')
        self.max_pending=max_pending;self._installed={};self._pending={};self._next_token=1
        self._floors={};self._bad=False;objects=set();regions=0
        for component,service in services.items():
            if (type(component) is not str or not component.strip() or type(service) is not MemoryService
                    or type(service.ledger) is not TransactionLedger or type(service.memory) is not PersistentMemory
                    or id(service) in objects):raise ValueError('actual distinct installed memory service required')
            objects.add(id(service));ids=tuple(service.memory.memory_ids);regions+=len(ids)
            self._installed[component]=(service,service.ledger,service.memory,ids)
        if regions>max_regions:raise ValueError('memory region capacity exceeded')

    @property
    def pending_count(self):return len(self._pending)

    @property
    def degraded(self):return self._bad

    def stage(self,component,service,ledger,key,receipt):
        """Pin one actual issued commit before producer ack; returns local token.

        Drain records must be converted to the actual receipt by the installed
        service's trusted lookup. Caller-provided documents cannot enter here.
        Rejection has no target effect and never manufactures a certificate.
        """
        if self._bad or type(component) is not str:return None
        installed=self._installed.get(component)
        if installed is None:return None
        actual,actual_ledger,memory,ids=installed
        if (service is not actual or ledger is not actual_ledger or service.ledger is not ledger
                or service.memory is not memory or type(key) is not TransactionKey
                or type(receipt) is not WriteReceipt):return None
        if (any(type(getattr(key,n)) is not str or not getattr(key,n).strip()
                for n in ('execution_id','testcase_id','source_component','channel_id'))
                or not _uint(key.source_epoch) or not _uint(key.source_sequence)
                or key.source_sequence==0 or key.source_component!=component or key.channel_id!='data'
                or receipt.transaction_id!=key):return None
        # Membership comes from successful MemoryService.write callback only.
        # A complete arbitrary external execute_once result is not issuance.
        lookup=getattr(service,'lookup_issued_write_commit',None)
        if not callable(lookup):return None
        try:
            issued=lookup(receipt)
            if type(issued) is not dict:return None
            issued=json.loads(_wire(issued));document=receipt.commit_document()
            if type(document) is not dict or _wire(document)!=_wire(issued.get('commit_document')):return None
            from dataclasses import asdict
            if (_wire(issued.get('transaction'))!=_wire(asdict(key))
                    or _wire(document.get('fullkey'))!=_wire(asdict(key))
                    or issued.get('schema_version')!='memory_write_commit.v1'
                    or not _uint(issued.get('service_commit_sequence'))
                    or issued['service_commit_sequence']==0):return None
            entry=ledger._entries.get(key)
            if entry is None or entry.status!='complete' or entry.receipt is not receipt:return None
            version=document.get('version');cells=document.get('enabled_byte_cells')
            if (document.get('schema_version')!='memory_write_commit_receipt.v1'
                    or document.get('memory_kind')!='modeled_host_persistent_memory'
                    or document.get('commit_status')!='complete' or document.get('performed_effect') is not True
                    or document.get('memory_id') not in ids or not _uint(document.get('generation'))
                    or type(version) is not list or len(version)!=2 or not all(_uint(n) for n in version)
                    or version[0]!=document['generation'] or version[1]==0
                    or type(cells) is not list or not cells
                    or document.get('payload_sha256')!=entry.payload_digest):return None
            core={k:v for k,v in document.items() if k!='commit_id'}
            digest=hashlib.sha256(_wire(core)).hexdigest()
            if document.get('commit_id')!=digest or issued.get('commit_id')!=digest:return None
            # Service-wide issuance order supplies one bounded stale-ref floor,
            # independent of testcase keys or duplicate equal memory values.
            floor=self._floors.get(component,0);sequence=issued['service_commit_sequence']
            if sequence<=floor:return None
            if len(self._pending)>=self.max_pending:
                self._bad=True;return None
            token=self._next_token;self._next_token+=1
            certificate=dict(kind='memory_commit_authority',schema_version='memory_commit_authority.v1',
                status='accepted',proof_scope='installed_host_memory_commit',component=component,
                memory_kind='modeled_host_persistent_memory',source_origin='unknown',
                commit_id=digest,service_commit_sequence=sequence,fullkey=asdict(key),
                commit_document=deepcopy(document))
            self._pending[token]=certificate;self._floors[component]=sequence
            return token
        except RuntimeError:
            # Actual issued callback evidence was corrupted or uncertain.
            self._bad=True;return None
        except (TypeError,ValueError,AttributeError,KeyError,RecursionError):return None

    def resolve(self,token):
        """Return a detached pinned certificate once; no late journal mutation."""
        if self._bad or type(token) is not int or token<1:return None
        certificate=self._pending.pop(token,None)
        return deepcopy(certificate) if certificate is not None else None
