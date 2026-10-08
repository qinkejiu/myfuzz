"""Bounded controlled bootstrap entry witnesses from exact measured receipts.

Registry construction is a trusted Root installation hook, never an event parser.
Accepted native-taken certificates are supplied by the authenticated native join.
"""
from collections import OrderedDict
from copy import deepcopy
import hashlib
import json
from functools import lru_cache

from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_receipt_contract
from myfuzz.local_harness.uart_controlled_irq_contract import uart_controlled_irq_contract
from .cpu_retirement import _valid_transaction, _valid_frozen_instruction, _address_triplet


def _wire(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def _same(a,b): return _wire(a)==_wire(b)
def _uint(v,bits=64): return type(v) is int and 0<=v<1<<bits
def _id(v): return _uint(v) or type(v) is str and bool(v.strip())
def _digest(v): return hashlib.sha256(_wire(v)).hexdigest()


@lru_cache(maxsize=16)
def _expected_artifact(component):
    from .ibex_pulp_dual_source import _artifact, RVFI_CPU_PROFILE
    return _artifact(RVFI_CPU_PROFILE,component).runtime_document


def controlled_uart_bootstrap_configuration(bootstrap, *, component, runtime_artifact, observation_contract):
    from pathlib import Path
    from .ibex_uart_online import IbexUartOnlineBootstrap, make_ibex_uart_online_bootstrap
    if not isinstance(bootstrap,IbexUartOnlineBootstrap) or type(component) is not str or not component:
        raise ValueError('controlled bootstrap requires actual builder identity')
    expected=tuple(make_ibex_uart_online_bootstrap(
        instruction_start=bootstrap.instruction_start,
        instruction_end=bootstrap.instruction_end, memory_readback=mode)
        for mode in (False, True))
    source_hashes={**ibex_irq_receipt_contract()['source']['sha256'],
        **uart_controlled_irq_contract()['source']['sha256']}
    source_root=Path(__file__).resolve().parents[3]/'third_party/rfuzz/upstream/ibex'
    for relative,digest in source_hashes.items():
        path=source_root/relative
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            raise ValueError('controlled bootstrap pinned RTL differs')
    if bootstrap not in expected or not _same(runtime_artifact,_expected_artifact(component)):
        raise ValueError('controlled bootstrap or authenticated artifact differs')
    if not _same(observation_contract,ibex_irq_receipt_contract()):
        raise ValueError('controlled bootstrap observation contract differs')
    images=[dict(image_id=i.image_id,component=i.component,address=i.address,data_hex=i.data_hex,
        sha256=hashlib.sha256(bytes.fromhex(i.data_hex)).hexdigest())
        for i in bootstrap.template.initial_images if i.image_id in ('cpu.main','cpu.isr')]
    if any(i['component']!=component for i in images):raise ValueError('controlled image component differs')
    rows={r['port']:r for r in runtime_artifact['plan']['ports']}
    inactive={'irq_fast_i':(15,0),'irq_nm_i':(1,0),'irq_software_i':(1,0),
        'irq_timer_i':(1,0),'debug_req_i':(1,0),'cheriot_enable_i':(4,10)}
    for name,(width,value) in inactive.items():
        r=rows.get(name,{})
        if r.get('disposition')!='constant' or not _same(r.get('value'),value) or r.get('port_width')!=width:
            raise ValueError('controlled bootstrap competing/configuration inputs differ')
    return dict(schema_version='controlled_uart_bootstrap_configuration.v1',component=component,
        instruction_start=bootstrap.instruction_start,instruction_end=bootstrap.instruction_end,
        artifact_digest=runtime_artifact['artifact_digest'], observation_contract=deepcopy(observation_contract),
        contract=uart_controlled_irq_contract(), images=images,
        boot_base=runtime_artifact['boot_contract']['configured_boot_base'],
        reset_policy=deepcopy(runtime_artifact['driver_reset']),entry_pc=0x1012c,
        rvfi_widths={r['physical_port']:r['width'] for r in runtime_artifact['physical_exports']
            if r['physical_port'].startswith('rvfi_')},
        state_load_pc=0x1022c,rdata_load_pc=0x10230,mret_pc=0x10240)


class ControlledUartBootstrapRegistry:
    def __init__(self): self._certificates={}

    @classmethod
    def from_bootstrap(cls,bootstrap,*,component,memory_metadata,runtime_artifact,observation_contract):
        configuration=controlled_uart_bootstrap_configuration(bootstrap,component=component,
            runtime_artifact=runtime_artifact,observation_contract=observation_contract)
        if type(memory_metadata) is not dict or set(memory_metadata)!={'images'}:
            raise ValueError('controlled image installation metadata missing')
        rows=memory_metadata['images']
        if type(rows) is not list or len(rows)!=2: raise ValueError('controlled images missing')
        fields={'image_id','event_id','component','address','data_hex','memory_id','generation','byte_offset'}
        actual={}
        for row in rows:
            if (type(row) is not dict or set(row)!=fields or not _id(row['event_id'])
                    or not all(_uint(row[k]) for k in ('address','generation','byte_offset'))
                    or any(type(row.get(k)) is not str or not row[k] for k in ('image_id','component','data_hex','memory_id'))
                    or row['image_id'] in actual): raise ValueError('invalid controlled image metadata')
            actual[row['image_id']]=deepcopy(row)
        for image in configuration['images']:
            row=actual.get(image['image_id'])
            if row is None or any(not _same(row[k],image[k]) for k in ('image_id','component','address','data_hex')):
                raise ValueError('controlled image differs from installed bootstrap')
        if actual['cpu.main']['event_id']==actual['cpu.isr']['event_id']:
            raise ValueError('controlled installation event identities collide')
        if (actual['cpu.main']['memory_id']!=actual['cpu.isr']['memory_id']
                or actual['cpu.main']['generation']!=actual['cpu.isr']['generation']
                or actual['cpu.main']['address']-actual['cpu.main']['byte_offset']
                   !=actual['cpu.isr']['address']-actual['cpu.isr']['byte_offset']):
            raise ValueError('controlled installation memory spans disagree')
        certificate=dict(schema_version='controlled_uart_bootstrap_certificate.v1',
            configuration=configuration,installations=actual)
        certificate['certificate_id']=_digest(certificate)
        registry=cls();registry._certificates[component]=certificate
        return registry

    def get(self,component): return deepcopy(self._certificates.get(component))
    def document(self): return dict(schema_version='controlled_uart_bootstrap_registry.v1',
        certificates=[deepcopy(self._certificates[k]) for k in sorted(self._certificates)])


class UartControlledIrqEntryJoin:
    def __init__(self,*,bootstrap_registry=None,max_components=16,max_instruction_refs=256):
        if bootstrap_registry is not None and not isinstance(bootstrap_registry,ControlledUartBootstrapRegistry):
            raise ValueError('untrusted controlled bootstrap registry')
        if any(type(x) is not int or x<1 for x in (max_components,max_instruction_refs)):
            raise ValueError('invalid controlled entry capacity')
        self.registry=bootstrap_registry;self.max_components=max_components;self.max_refs=max_instruction_refs
        self._states={};self._fetches=OrderedDict();self._seen=OrderedDict();self._global_bad=False
        self._bad_epochs={};self._global_pending=set()

    def _report(self,event,*,status='incomplete',reason=None,**fields):
        return deepcopy(dict(kind='uart_consumption_match',schema_version='uart_consumption_match.v1',
            component=event.get('component',event.get('cpu_component')),reset_epoch=event.get('reset_epoch',event.get('cpu_epoch')),
            local_tick=event.get('local_tick'),observation_event_id=event.get('event_id'),status=status,
            reason=reason,proof_scope='controlled_uart_external_irq_entry',generic_isr_origin='unknown',
            operand_origin='unknown',**fields))

    def _fail(self,event,reason):
        component=event.get('component',event.get('cpu_component'))
        state=self._states.get(component) if type(component) is str else None
        if state is not None:state['bad']=True
        elif type(component) is str and self.registry is not None and self.registry.get(component) is not None:
            epoch=event.get('reset_epoch',event.get('cpu_epoch'))
            self._bad_epochs[component]=max(epoch if _uint(epoch) else 0,self._bad_epochs.get(component,0))
        else:
            self._global_bad=True
            self._global_pending={c['configuration']['component'] for c in self.registry.document()['certificates']} if self.registry else set()
            for component in self._global_pending:self._bad_epochs[component]=max(self._states.get(component,{}).get('epoch',0),self._bad_epochs.get(component,0))
        return (self._report(event,reason=reason),)

    def _receipt(self,event):
        scope=event.get('command_scope');receipt=event.get('receipt_id');ticks=event.get('receipt_ticks')
        return (type(event.get('component')) is str and _uint(event.get('reset_epoch')) and _uint(event.get('local_tick'))
            and _same(event.get('source_component'),event['component'])
            and _same(event.get('source_epoch'),event['reset_epoch'])
            and type(scope) is dict and set(scope)=={'component','reset_epoch','command_sequence'}
            and _same(scope['component'],event['component']) and _same(scope['reset_epoch'],event['reset_epoch'])
            and _uint(scope['command_sequence']) and type(receipt) is dict and set(receipt)=={'execution','sequence'}
            and type(receipt['execution']) is str and bool(receipt['execution'])
            and _same(receipt['sequence'],scope['command_sequence'])
            and _same(event.get('observation_contract'),ibex_irq_receipt_contract())
            and type(ticks) is dict and set(ticks)=={'tick_before','tick_after','new_ticks','local_tick_base'}
            and all(_uint(v) for v in ticks.values()) and ticks['new_ticks']==1
            and ticks['tick_after']==ticks['tick_before']+1
            and ticks['local_tick_base']+ticks['tick_after']==event['local_tick'])

    def consume(self,event):
        if type(event) is not dict:return self._fail({},'malformed_controlled_entry_event')
        kinds={'cpu_native_startup','cpu_reset','cpu_external_irq_sample','cpu_external_irq_taken',
            'cpu_irq_notification','cpu_retire','instr_response','uart_consumption_match'}
        if event.get('kind') is None:return ()
        if type(event.get('kind')) is not str:return self._fail(event,'malformed_controlled_entry_kind')
        if event['kind'] not in kinds:return ()
        if event.get('kind')=='uart_consumption_match' and event.get('proof_scope')!='cpu_external_irq_taken':return ()
        try:event=json.loads(_wire(event))
        except (TypeError,ValueError,RecursionError):return self._fail({},'malformed_controlled_entry_event')
        if not _id(event.get('event_id')):return self._fail(event,'missing_controlled_entry_event_id')
        eid=event['event_id'];signature=_wire(event)
        if eid in self._seen:
            return () if self._seen[eid]==signature else self._fail(event,'conflicting_controlled_entry_event')
        self._seen[eid]=signature
        if len(self._seen)>self.max_refs*2:self._seen.popitem(last=False)
        kind=event['kind'];component=event.get('cpu_component') if kind=='uart_consumption_match' else event.get('component')
        cert=self.registry.get(component) if self.registry is not None and type(component) is str else None
        if cert is None:
            return (self._report(event,reason='untrusted_controlled_bootstrap'),) if kind in ('cpu_retire','uart_consumption_match') else ()
        if kind in ('cpu_native_startup','cpu_reset'):return self._start(event,cert)
        state=self._states.get(component)
        if state is None:return self._fail(event,'missing_actual_controlled_startup')
        if state['bad'] or self._global_bad:
            return ()
        if kind=='instr_response':return self._response(event,state)
        if kind=='uart_consumption_match':return self._proof(event,state)
        if (not self._receipt(event) or event['reset_epoch']!=state['epoch']
                or event['receipt_id']['execution']!=state['process'] or event.get('execution_id')!=state['execution_id']):
            return self._fail(event,'controlled_cpu_receipt_mismatch')
        if kind=='cpu_external_irq_sample':return self._sample(event,state)
        if (state['sample'] is None or not all(_same(event.get(k),state['sample'].get(k))
                for k in ('command_scope','receipt_id','receipt_ticks','local_tick'))):
            return self._fail(event,'missing_exact_controlled_cpu_sample')
        if kind=='cpu_external_irq_taken':return self._take(event,state)
        if kind=='cpu_irq_notification':
            if any(event.get(k,0) for k in ('rvfi_ext_nmi','rvfi_ext_nmi_int','rvfi_ext_debug_req','rvfi_ext_debug_mode')):
                return self._fail(event,'competing_controlled_entry_notification')
            return ()
        return self._retire(event,state)

    def _start(self,event,cert):
        component=event['component'];config=cert['configuration'];scope=event.get('command_scope');receipt=event.get('receipt_id')
        expected=dict(schema_version='native_cpu_reset_outcome.v1',assert_ticks=config['reset_policy']['reset_assert_ticks'],
            release_ticks=config['reset_policy']['reset_release_ticks'],artifact_digest=config['artifact_digest'],
            boot_base=config['boot_base'],source='startup_ready')
        prior=self._states.get(component)
        if (event.get('physical_reset') is not True or not _uint(event.get('reset_epoch')) or not _uint(event.get('local_tick'))
                or event['kind']=='cpu_native_startup' and event.get('schema_version')!='cpu_native_startup.v1'
                or type(event.get('execution_id')) is not str or not event['execution_id']
                or not _same(event.get('source_component'),component) or not _same(event.get('source_epoch'),event.get('reset_epoch'))
                or event.get('phase')!='startup_ready' or not _same(event.get('reset_outcome'),expected)
                or not _same(event.get('observation_contract'),config['observation_contract'])
                or not _same(event.get('artifact_digest'),config['artifact_digest']) or not _same(event.get('boot_base'),config['boot_base'])
                or not _same(scope,dict(component=component,reset_epoch=event['reset_epoch'],command_sequence=0))
                or type(receipt) is not dict or set(receipt)!={'execution','sequence'}
                or type(receipt['execution']) is not str or not receipt['execution'] or not _same(receipt['sequence'],0)
                or prior is not None and event['reset_epoch']<=prior['epoch']
                or event['reset_epoch']<=self._bad_epochs.get(component,-1)
                or prior is None and len(self._states)>=self.max_components):
            return self._fail(event,'unproven_controlled_startup_reset')
        self._states[component]=dict(epoch=event['reset_epoch'],process=receipt['execution'],tick=event['local_tick'],
            execution_id=event['execution_id'],
            sequence=0,sample=None,order=0,bad=False,cert=cert,startup_event=event['event_id'],
            mtvec=(config['boot_base']&~255)|1,mie=0,mstatus=0,setup={},main_next=0x10080,
            active=None,candidates=OrderedDict(),proofs={},episode=None,take_sequence=0,entry_sequence=0)
        self._states[component]['instr_sequence']=0
        self._bad_epochs.pop(component,None);self._global_pending.discard(component)
        for key in list(self._fetches):
            if key[0]==component:del self._fetches[key]
        if not self._global_pending:self._global_bad=False
        return ()

    def _response(self,event,state):
        from .ledger import TransactionKey
        if (not _valid_transaction(event,'instr') or not _valid_frozen_instruction(event)
                or not _address_triplet(event) or event['transaction']['source_epoch']!=state['epoch']
                or event.get('component')!=event['transaction']['source_component'] or event.get('error')!=0
                or event['transaction']['execution_id']!=state['execution_id']
                or event.get('execution_id')!=state['execution_id']
                or not _same(event.get('source_epoch'),state['epoch'])
                or not _same(event.get('reset_epoch'),state['epoch'])
                or event['transaction']['source_sequence']!=state['instr_sequence']+1
                or not _uint(event.get('acceptance_tick')) or not _uint(event.get('response_tick'))
                or event['response_tick']<event['acceptance_tick']
                or not _same(event['snapshot'].get('transaction_id'),str(TransactionKey(**event['transaction'])))):
            return self._fail(event,'invalid_controlled_instruction_response')
        state['instr_sequence']=event['transaction']['source_sequence']
        if not any(i['address']<=event['address']<i['address']+len(bytes.fromhex(i['data_hex']))
                   for i in state['cert']['installations'].values()):return ()
        key=(event['component'],event['transaction']['source_epoch'],event['address'],event['rdata'])
        if sum(len(values) for values in self._fetches.values())>=self.max_refs:
            return self._fail(event,'controlled_live_instruction_capacity')
        bucket=self._fetches.setdefault(key,[])
        if len(bucket)>=2:return self._fail(event,'ambiguous_controlled_instruction_source')
        bucket.append(event)
        return ()

    def _frozen(self,event,state):
        pc,insn=event['pc_rdata'],event['insn'];matches=[]
        for response in self._fetches.get((event['component'],state['epoch'],pc,insn),[]):
            if response['response_tick']>event['local_tick']:return None
            snapshot=response['snapshot']
            for image in state['cert']['installations'].values():
                offset=pc-image['address'];data=bytes.fromhex(image['data_hex'])
                if (0<=offset<=len(data)-4 and int.from_bytes(data[offset:offset+4],'little')==insn
                        and snapshot.get('memory_id')==image['memory_id']
                        and _same(snapshot.get('generation'),image['generation'])
                        and _same(snapshot.get('byte_offset'),image['byte_offset']+offset)
                        and _same(snapshot.get('writer_kinds'),['INITIAL_IMAGE']*4)
                        and _same(snapshot.get('writer_event_ids'),['initial-image']*4)
                        and _same(snapshot.get('versions'),[[image['generation'],0]]*4)):
                    matches.append(response)
        bucket=self._fetches.get((event['component'],state['epoch'],pc,insn),[])
        return matches[0] if len(matches)==1 and len(bucket)==1 else None

    def _sample(self,event,state):
        if (event.get('schema_version')!='cpu_external_irq_sample.v1'
                or event['local_tick']!=state['tick']+1 or event['receipt_id']['sequence']<=state['sequence']
                or any(not _uint(event.get(k),1) for k in ('expected_input','actual_pre_input','actual_post_input',
                    'irq_taken_pre','irq_masked_pre'))
                or not _same(event['expected_input'],event['actual_pre_input'])
                or not _same(event['expected_input'],event['actual_post_input'])):
            return self._fail(event,'controlled_sample_receipt_gap')
        widths=ibex_irq_receipt_contract()['notification_widths']
        if any(type(event.get(phase)) is not dict or any(not _uint(event[phase].get(k),w) for k,w in widths.items())
               for phase in ('notification_pre','notification_post')):
            return self._fail(event,'missing_controlled_notification_snapshot')
        if any(event[phase][k] for phase in ('notification_pre','notification_post')
               for k in ('rvfi_ext_nmi','rvfi_ext_nmi_int','rvfi_ext_debug_req','rvfi_ext_debug_mode')):
            return self._fail(event,'competing_controlled_entry_notification')
        state.update(sample=event,tick=event['local_tick'],sequence=event['receipt_id']['sequence'])
        return ()

    def _take(self,event,state):
        sample=state['sample'];key=event.get('take_key')
        if (event.get('schema_version')!='cpu_external_irq_taken.v1' or not _same(event.get('sample_event_id'),sample['event_id'])
                or not _same(event.get('sample_ref'),dict(command_scope=sample['command_scope'],local_tick=sample['local_tick']))
                or type(key) is not list or len(key)!=3 or not _same(key[:2],[event['component'],state['epoch']])
                or not _uint(key[2]) or key[2]<=state['take_sequence'] or sample.get('irq_taken_pre')!=1
                or any(not _same(event.get(k),sample.get(k)) for k in
                    ('expected_input','actual_pre_input','actual_post_input','irq_taken_pre','irq_masked_pre',
                     'notification_pre','notification_post','input_context','binding_delivery_event_id','source_output_key'))
                or any(not _same(sample.get(k),v) for k,v in
                    (('actual_pre_input',1),('actual_post_input',1),('irq_masked_pre',0)))
                or state['active'] is not None or state['episode'] is not None):
            return self._fail(event,'ambiguous_or_unwitnessed_controlled_take')
        if len(state['setup'])!=3 or not state['mie']&0x800 or not state['mstatus']&8:
            return self._fail(event,'missing_controlled_csr_setup')
        state['take_sequence']=key[2]
        state['active']=dict(take=event,sample=sample,mtvec=state['mtvec'],setup=deepcopy(state['setup']))
        state['mstatus']=(state['mstatus']&~8)|0x80
        return ()

    def _proof(self,event,state):
        if event.get('status')!='accepted':return ()
        take_id=event.get('cpu_take_event_id');pending=state['active']
        candidate=state['candidates'].get(take_id) if _id(take_id) else None
        take=candidate['take'] if candidate else pending['take'] if pending else None
        sampled=candidate['sample'] if candidate else pending['sample'] if pending else None
        expected_context=(dict(schema_version='native_irq_input_context.v1',
            binding_delivery_event_id=event.get('binding_delivery_event_id'),expected_input=1,
            source_output_key=event.get('source_output_key'),target_component=event.get('cpu_component'),
            target_epoch=event.get('cpu_epoch')))
        if (take is None or not _same(take_id,take['event_id']) or not _same(event.get('cpu_epoch'),state['epoch'])
                or not _same(event.get('cpu_sample_event_id'),sampled['event_id'])
                or not _same(sampled.get('input_context'),expected_context)
                or not _same(event.get('source_output_key'),sampled.get('source_output_key'))
                or not _same(event.get('binding_delivery_event_id'),sampled.get('binding_delivery_event_id'))):
            return self._fail({**event,'component':event.get('cpu_component')},'unproven_controlled_native_take_certificate')
        state['proofs'][take_id]=event
        return self._promote(state,event)

    def _retire(self,event,state):
        widths={'valid':1,'order':64,'pc_rdata':32,'pc_wdata':32,'insn':32,'trap':1,'intr':1,'mode':2,
            'rs1_addr':5,'rs1_rdata':32,'rd_addr':5,'rd_wdata':32}
        observation=event.get('observation')
        physical=observation.get('physical',{}) if type(observation) is dict else {}
        if (event.get('schema_version')!='cpu_retire.v2' or event.get('phase')!='post'
                or type(observation) is not dict or observation.get('sampling_edge')!='post_rising'
                or not _same(event.get('actual_post_ref'),dict(command_scope=event['command_scope'],local_tick=event['local_tick'],phase='post'))
                or type(physical) is not dict or set(physical)!=set(state['cert']['configuration']['rvfi_widths'])
                or any(not _uint(physical.get(k),w) or not _same(event.get(k.removeprefix('rvfi_')),physical[k])
                    for k,w in state['cert']['configuration']['rvfi_widths'].items())
                or any(not _same(state['sample']['notification_post'].get(k),physical.get(k))
                    for k in ibex_irq_receipt_contract()['notification_widths'])
                or any(not _uint(event.get(k),w) for k,w in widths.items())
                or event['valid']!=1 or event['order']!=state['order']+1 or event['trap'] or event['mode']!=3
                or any(event.get(k,0) for k in ('ext_nmi','ext_nmi_int','ext_debug_req','ext_debug_mode'))):
            return self._fail(event,'invalid_controlled_retirement_receipt')
        state['order']=event['order'];pc=event['pc_rdata'];insn=event['insn'];opcode=insn&127
        if state['main_next'] is not None:
            source=self._frozen(event,state)
            if pc!=state['main_next'] or source is None or event['intr']:
                return self._fail(event,'missing_controlled_bootstrap_execution_source')
            state['main_next']+=4
            if state['main_next']==0x100bc:state['main_next']=None
        if opcode==0x73:
            csr=(insn>>20)&0xfff
            if csr in (0x305,0x304,0x300):
                expected={0x305:(0x100a0,0x3053a073,0x1012c),0x304:(0x100ac,0x3043a073,0x800),0x300:(0x100b4,0x3003a073,8)}[csr]
                source=self._frozen(event,state)
                if (csr in state['setup'] or source is None or not _same((pc,insn,event['rs1_rdata']),expected)
                        or event['rs1_addr']!=7 or event['rd_addr']!=0 or event['trap']):
                    return self._fail(event,'controlled_csr_override_or_wrong_setup')
                if csr==0x305:state['mtvec']=((state['mtvec']|event['rs1_rdata'])&~255)|1
                elif csr==0x304:state['mie']|=event['rs1_rdata']
                else:state['mstatus']|=event['rs1_rdata']
                state['setup'][csr]=dict(retirement_event_id=event['event_id'],instruction_response_event_id=source['event_id'])
            elif insn==0x30200073:
                if state['episode'] is None or pc!=state['cert']['configuration']['mret_pc'] or self._frozen(event,state) is None:
                    return self._fail(event,'unproven_controlled_mret')
                state['episode']=None;state['mstatus']|=8
            else:return self._fail(event,'unsupported_controlled_system_effect')
        if event['intr']:
            pending=state['active'];source=self._frozen(event,state)
            if pending is None or source is None or state['episode'] is not None:
                return self._fail(event,'unproven_or_competing_controlled_entry')
            derived=(pending['mtvec']&~255)|(11<<2)
            if pc!=derived or pc!=state['cert']['configuration']['entry_pc'] or insn!=19:
                return self._fail(event,'wrong_controlled_first_handler_source')
            if len(state['candidates'])>=self.max_refs:
                return self._fail(event,'controlled_entry_pending_capacity')
            state['entry_sequence']+=1
            candidate={**pending,'entry_key':[event['component'],state['epoch'],state['entry_sequence']],
                'retirement':event,'source':source,'entry_pc':derived}
            state['candidates'][pending['take']['event_id']]=candidate
            state['active']=None;state['episode']=candidate['entry_key']
            self._fetches.pop((event['component'],state['epoch'],pc,insn),None)
            return self._promote(state,event)
        if state['active'] is not None:return self._fail(event,'intervening_retirement_before_controlled_entry')
        self._fetches.pop((event['component'],state['epoch'],pc,insn),None)
        return ()

    def _promote(self,state,event):
        if state['bad'] or self._global_bad:return ()
        reports=[]
        for take_id,c in list(state['candidates'].items()):
            proof=state['proofs'].get(take_id)
            if proof is None:continue
            reports.append(self._report(c['retirement'],status='accepted',reason='matched_controlled_external_entry',
                entry_key=c['entry_key'],cpu_take_event_id=take_id,cpu_sample_event_id=c['sample']['event_id'],
                binding_delivery_event_id=proof['binding_delivery_event_id'],source_output_key=proof['source_output_key'],
                source_entry_ids=proof.get('source_entry_ids',[]),source_admissions=proof.get('source_admissions',[]),
                native_take_proof_event_id=proof['event_id'],bootstrap_certificate_id=state['cert']['certificate_id'],
                startup_event_id=state['startup_event'],setup_witnesses=list(c['setup'].values()),
                first_retirement_event_id=c['retirement']['event_id'],retirement_receipt_event_id=c['retirement']['event_id'],
                instruction_response_event_id=c['source']['event_id'],instruction_transaction=c['source']['transaction'],
                instruction_snapshot_versions=c['source']['snapshot']['versions'],entry_pc=c['entry_pc'],
                image_installation_event_ids=[i['event_id'] for i in state['cert']['installations'].values()],
                csr_setup_scope='restricted_pinned_reset_and_complete_retirement',
                entry_order=c['retirement']['order'],derived_mtvec=c['mtvec'],
                entry_scope='controlled_bootstrap_external_irq',graph_path_certified=proof.get('graph_path_certified',False),
                path_id=proof.get('path_id')))
            del state['candidates'][take_id];del state['proofs'][take_id]
        return tuple(reports)
