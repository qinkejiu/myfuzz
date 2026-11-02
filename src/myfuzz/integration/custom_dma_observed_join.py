"""Correlate actual per-case DMA/RAM event facts without issuing authority."""
import json
from copy import deepcopy


def _key(value):
    if type(value) is not dict:
        return None
    required=('execution_id','testcase_id','source_component','source_epoch','channel_id','source_sequence')
    if not all(name in value for name in required):
        return None
    return json.dumps(value,sort_keys=True,separators=(',',':'))


class CustomDmaObservedJoin:
    """Collect one receipt's events once; detached equality is not a live certificate."""
    def __init__(self, *, cpu_id, dma_id, contract, words):
        self.cpu_id=cpu_id; self.dma_id=dma_id
        self.program=contract['program_contract'];self.resource=contract['memory']['resource']
        self.words=tuple(words)
        self.source={};self.read={};self.write={};self.response={};self.snapshot={};self.commit={}
        self._overflow=False

    def _add(self,table,key,event):
        if key is not None:
            if key not in table and len(table)>=64:
                self._overflow=True
                return
            rows=table.setdefault(key,[])
            if len(rows)<2:
                rows.append(event)

    def observe(self,event):
        if type(event) is not dict:return
        kind=event.get('kind');component=event.get('component')
        if kind=='memory_write_commit' and component in (self.cpu_id,self.dma_id):
            doc=event.get('commit_document')
            if type(doc) is not dict:return
            if component==self.cpu_id:
                self._add(self.source,(doc.get('memory_id'),doc.get('byte_offset')),event)
            else:
                self._add(self.commit,_key(event.get('transaction')),event)
        elif component==self.dma_id and kind=='memory_read':
            self._add(self.snapshot,_key(event.get('transaction')),event)
        elif component==self.dma_id and kind=='dma_edge':
            accepted=event.get('accepted')
            if type(accepted) is dict and type(accepted.get('write')) is bool:
                self._add(self.write if accepted['write'] else self.read,accepted.get('address'),event)
            response=event.get('response')
            if type(response) is dict:
                self._add(self.response,_key(response.get('transaction')),event)

    def finish(self):
        memory=self.resource['resource_id']; base=self.resource['base'];p=self.program
        result=[]
        if self._overflow:
            return dict(schema_version='custom_dma_observed_word_join.v1',words=[],status='unknown',
                reason='event_index_capacity_exceeded',verification_scope='detached_same_case_event_consistency_only',
                live_issuance='not_verified',retirement='unknown',irq_causality='unknown',
                transfer_certificate='not_granted',reward_eligible=False)
        for index,word in enumerate(self.words):
            source_address=p['source_address']+4*index; dest_address=p['destination_address']+4*index
            sources=self.source.get((memory,source_address-base),[])
            reads=self.read.get(source_address,[]); writes=self.write.get(dest_address,[])
            if len(sources)!=1 or len(reads)!=1 or len(writes)!=1:
                result.append(dict(word_index=index,status='unknown',reason='missing_or_ambiguous_source_read_or_write'))
                continue
            source,read,write=sources[0],reads[0],writes[0]
            read_key=_key(read['accepted'].get('transaction'));write_key=_key(write['accepted'].get('transaction'))
            snapshots=self.snapshot.get(read_key,[]); commits=self.commit.get(write_key,[])
            read_replies=self.response.get(read_key,[]);write_replies=self.response.get(write_key,[])
            if (read_key is None or write_key is None or
                    any(len(rows)!=1 for rows in (snapshots,commits,read_replies,write_replies))):
                result.append(dict(word_index=index,status='unknown',reason='missing_or_ambiguous_transaction_evidence'))
                continue
            snap=snapshots[0]; dest=commits[0]; rr=read_replies[0];wr=write_replies[0]
            source_doc=source['commit_document']; dest_doc=dest['commit_document']
            source_cells=source_doc.get('enabled_byte_cells');dest_cells=dest_doc.get('enabled_byte_cells')
            expected_bytes=list(word.to_bytes(4,'little'))
            def cells_match(cells,offset,version):
                return (type(cells) is list and len(cells)==4 and
                    all(type(cell) is dict and cell.get('byte_offset')==offset+i
                        and cell.get('value')==expected_bytes[i] and cell.get('version')==version
                        for i,cell in enumerate(cells)))
            source_version=source_doc.get('version');dest_version=dest_doc.get('version')
            versions=snap.get('versions');writers=snap.get('writer_event_ids')
            normalized=lambda rows:[list(v) if isinstance(v,(tuple,list)) else v for v in rows] if isinstance(rows,(tuple,list)) else None
            valid_version=lambda v: type(v) is list and len(v)==2 and all(type(x) is int and x>=0 for x in v) and v[1]>0
            consistent=(valid_version(source_version) and valid_version(dest_version)
                and _key(source_doc.get('fullkey'))==_key(source.get('transaction')) is not None
                and source.get('transaction',{}).get('source_component')==self.cpu_id
                and source.get('transaction',{}).get('channel_id')=='data'
                and read['accepted']['transaction'].get('source_component')==self.dma_id
                and read['accepted']['transaction'].get('channel_id')=='dma-memory'
                and write['accepted']['transaction'].get('source_component')==self.dma_id
                and write['accepted']['transaction'].get('channel_id')=='dma-memory'
                and _key(dest_doc.get('fullkey'))==write_key
                and source_doc.get('commit_status')=='complete' and source_doc.get('performed_effect') is True
                and source_doc.get('byte_enable')==15 and source_doc.get('width_bytes')==4
                and cells_match(source_cells,source_address-base,source_version)
                and snap.get('memory_id')==memory and snap.get('address')==source_address
                and snap.get('width_bytes')==4 and snap.get('generation')==source_doc.get('generation')
                and snap.get('value')==word and snap.get('data_hex')==word.to_bytes(4,'little').hex()
                and normalized(versions)==[source_version]*4
                and isinstance(writers,(tuple,list)) and list(writers)==[c.get('writer_event_id') for c in source_cells]
                and read['accepted'].get('byte_enable')==15 and rr['response'].get('error')==0
                and rr['response'].get('rdata')==word and write['accepted'].get('byte_enable')==15
                and write['accepted'].get('value')==word and wr['response'].get('error')==0
                and dest_doc.get('memory_id')==memory and dest_doc.get('byte_offset')==dest_address-base
                and dest_doc.get('generation')==source_doc.get('generation')
                and dest_doc.get('commit_status')=='complete' and dest_doc.get('performed_effect') is True
                and dest_doc.get('width_bytes')==4 and dest_doc.get('byte_enable')==15
                and cells_match(dest_cells,dest_address-base,dest_version))
            refs=dict(source_commit=source.get('event_id'),dma_read_request=read.get('event_id'),
                memory_read=snap.get('event_id'),dma_read_response=rr.get('event_id'),
                dma_write_request=write.get('event_id'),destination_commit=dest.get('event_id'),
                dma_write_response=wr.get('event_id'))
            facts=dict(source_commit=deepcopy(source_doc),dma_read_request=deepcopy(read['accepted']),
                memory_read={key:deepcopy(snap.get(key)) for key in ('transaction','address','width_bytes',
                    'memory_id','generation','byte_offset','value','data_hex','versions','writer_event_ids','writer_kinds')},
                dma_read_response=deepcopy(rr['response']),dma_write_request=deepcopy(write['accepted']),
                destination_commit=deepcopy(dest_doc),dma_write_response=deepcopy(wr['response']))
            result.append(dict(word_index=index,status='observed_consistent' if consistent else 'inconsistent',
                source_address=source_address,destination_address=dest_address,value=word,
                source_version=source_version,destination_version=dest_version,event_refs=refs,observed_facts=facts))
        return dict(schema_version='custom_dma_observed_word_join.v1',words=result,
            status='observed_consistent' if len(result)==4 and all(r['status']=='observed_consistent' for r in result) else 'unknown',
            verification_scope='detached_same_case_event_consistency_only',
            live_issuance='not_verified',retirement='unknown',irq_causality='unknown',
            transfer_certificate='not_granted',reward_eligible=False)
