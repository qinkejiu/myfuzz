"""Saved raw semantics, never substitute saved dicts for live commit authority."""
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import unittest

from tests.integration import test_uart_native_irq_taken_real as native_fixture
from tests.integration import test_uart_operand_use_real as use_fixture

_KEY=('execution_id','testcase_id','source_component','source_epoch','channel_id','source_sequence')


def _uint(value,width=64):
    return type(value) is int and 0<=value<1<<width


def _validate_commit_document(document,key,payload):
    """Content consistency only; this function never issues live authority."""
    from myfuzz.scenario.ledger import TransactionKey,TransactionLedger
    if (type(key) is not dict or set(key)!=set(_KEY)
            or any(type(key[n]) is not str or not key[n] for n in _KEY[:3]+('channel_id',))
            or not _uint(key['source_epoch']) or not _uint(key['source_sequence'])
            or key['source_sequence']==0):raise ValueError('typed fullkey required')
    if (type(document) is not dict or document.get('schema_version')!='memory_write_commit_receipt.v1'
            or document.get('memory_kind')!='modeled_host_persistent_memory'
            or document.get('commit_status')!='complete' or document.get('performed_effect') is not True
            or native_fixture._wire_bytes(document.get('fullkey'))!=native_fixture._wire_bytes(key)
            or type(document.get('memory_id')) is not str or not document['memory_id']
            or not _uint(document.get('generation')) or not _uint(document.get('byte_offset'))
            or type(document.get('width_bytes')) is not int or document['width_bytes']!=4
            or type(document.get('byte_enable')) is not int or document['byte_enable']!=15
            or document.get('payload_sha256')!=TransactionLedger._digest(payload)
            or document.get('commit_id')!=_commit_digest(document)):
        raise ValueError('commit content mismatch')
    version=document.get('version');cells=document.get('enabled_byte_cells')
    if (type(version) is not list or len(version)!=2 or not all(_uint(n) for n in version)
            or version[0]!=document['generation'] or version[1]==0
            or type(cells) is not list or len(cells)!=4):raise ValueError('typed byte versions required')
    for lane,cell in enumerate(cells):
        if (type(cell) is not dict or not _uint(cell.get('byte_offset'))
                or cell['byte_offset']!=document['byte_offset']+lane
                or not _uint(cell.get('value'),8) or cell['value']!=(payload['value']>>(lane*8))&255
                or native_fixture._wire_bytes(cell.get('version'))!=native_fixture._wire_bytes(version)
                or cell.get('writer_kind')!='STORE' or cell.get('writer_event_id')!=str(TransactionKey(**key))):
            raise ValueError('enabled byte cell mismatch')


def _raw_store_matches(events):
    from myfuzz.scenario.cpu_retirement import CpuRetirementMatcher
    matcher=CpuRetirementMatcher(max_pending=2048);matches={}
    for original in events:
        if original.get('kind') not in ('instr_response','data_accept','data_response','cpu_retire','cpu_reset','cpu_flush'):continue
        event=deepcopy(original);event.pop('provenance',None)
        for report in matcher.consume(event):
            if report.get('status') in ('incomplete','ambiguous'):raise ValueError('raw CPU certainty barrier')
            if (event['kind']=='cpu_retire' and report.get('status')=='accepted'
                    and report.get('reason')=='matched_ordered_retired_transaction'):
                matches[event['event_id']]=report
    return matches


def _saved_semantic_store_chains(manifest,events,uses):
    """Audit saved evidence; a saved certificate cannot mint callback authority."""
    by_id={e['event_id']:e for e in events};matches=_raw_store_matches(events);rows=[]
    proofs=[e for e in events if e.get('proof_scope')=='uart_operand_store_host_memory_byte'
        and e.get('status')=='accepted']
    for proof in proofs:
        rid=proof.get('store_retirement_event_id');raw=by_id.get(rid);match=matches.get(rid)
        use=next((u for u in uses if u.get('status')=='accepted' and u.get('operand_retirement_event_id')==rid),None)
        if raw is None or match is None or use is None:raise ValueError('missing independent SW/use witness')
        keys=match.get('transaction_keys');beats=match.get('data_beats')
        if type(keys) is not list or len(keys)!=1 or type(beats) is not list or len(beats)!=1:
            raise ValueError('single raw store beat required')
        key=keys[0];beat=beats[0];response=beat.get('response');commit=by_id.get(proof.get('commit_event_id'))
        if (type(commit) is not dict or commit.get('kind')!='memory_write_commit'
                or native_fixture._wire_bytes(commit.get('transaction'))!=native_fixture._wire_bytes(key)
                or native_fixture._wire_bytes(proof.get('store_fullkey'))!=native_fixture._wire_bytes(key)
                or type(response) is not dict or type(response.get('error')) is not int or response['error']!=0
                or proof.get('request_event_id')!=beat.get('event_id')
                or proof.get('response_event_id')!=response.get('event_id')):
            raise ValueError('raw fullkey/commit bridge mismatch')
        address=use['measured_mem_addr'];value=use['operand_value']
        if (beat.get('write')!=1 or beat.get('be')!=15 or beat.get('wdata')!=value
                or beat.get('raw_address')!=address or beat.get('aligned_address')!=address
                or raw.get('insn')!=use['decoded_insn'] or raw.get('order')!=use['operand_order']):
            raise ValueError('raw SW operand mismatch')
        document=commit.get('commit_document');payload=dict(op='write',address=address,value=value,width_bytes=4,byte_enable=15)
        _validate_commit_document(document,key,payload)
        if (commit.get('schema_version')!='memory_write_commit.v1'
                or commit.get('commit_id')!=document['commit_id']
                or not _uint(commit.get('service_commit_sequence')) or commit['service_commit_sequence']==0):
            raise ValueError('commit stream identity mismatch')
        writes=[e for e in events if e.get('kind')=='memory_write'
            and native_fixture._wire_bytes(e.get('transaction'))==native_fixture._wire_bytes(key)]
        if len(writes)!=1:raise ValueError('missing or duplicate actual memory write')
        write=writes[0]
        for name in ('memory_id','generation','byte_offset','version','width_bytes','byte_enable'):
            if native_fixture._wire_bytes(write.get(name))!=native_fixture._wire_bytes(document.get(name)):
                raise ValueError('memory write snapshot mismatch')
        if write.get('address')!=address or write.get('value')!=value:raise ValueError('memory write payload mismatch')
        regions=manifest['runner']['memories'][key['source_component']]['regions']
        if not any(region['memory_id']==document['memory_id'] and region['writable'] is True
                and any(base<=address and address+4<=base+region['size']
                    and address-base==document['byte_offset'] for base in [region['base']]+region['aliases'])
                for region in regions):raise ValueError('installed host region mismatch')
        expected=dict(store_order=raw['order'],source_register_version_key=use['source_register_version_key'],
            source_seed_certificate_ref=use['source_seed_certificate_ref'],
            source_load_fullkey=use['source_load_fullkey'],source_entry_id=use['source_entry_id'],
            source_admission=use['source_admission'],memory_id=document['memory_id'],generation=document['generation'],
            byte_offset=document['byte_offset'],byte_value=document['enabled_byte_cells'][0]['value'],
            byte_version=document['version'],commit_id=document['commit_id'],unknown_written_lanes=[1,2,3],
            writer_event_id=document['enabled_byte_cells'][0]['writer_event_id'],
            service_commit_sequence=commit['service_commit_sequence'],
            source_path_id=use['path_id'],source_path_certified=use['graph_path_certified'],
            store_memory_path_certified=False,influenced_bits=[0,8])
        for name,value in expected.items():
            if native_fixture._wire_bytes(proof.get(name))!=native_fixture._wire_bytes(value):raise ValueError(name+' mismatch')
        for name in ('rtl_ram_origin','later_ram_read_origin','whole_word_store_origin','generic_isr_origin'):
            if proof.get(name)!='unknown':raise ValueError('unsupported source claim')
        rows.append(dict(event_id=proof['event_id'],fullkey=key,version=document['version'],
            role=use['source_admission']['role']))
    return rows


@unittest.skipUnless(os.environ.get('MYFUZZ_UART_STORE_MEMORY_REAL')=='1',
    'requires new authenticated memory-commit online run; no saved-dict authority')
class UartStoreMemoryRealTests(unittest.TestCase):
    reconstruct=use_fixture.UartOperandUseRealTests.reconstruct

    @classmethod
    def setUpClass(cls):
        from myfuzz.integration.ibex_uart_online import _read_uart_online_trace,_saved_memory_commit_mode
        from myfuzz.integration.scenario_rfuzz_live import _verify_online_run_identity
        output=os.environ.get('MYFUZZ_UART_STORE_MEMORY_RUN_DIR')
        if not output:raise ValueError('MYFUZZ_UART_STORE_MEMORY_RUN_DIR required')
        cls.output=Path(output).resolve();cls.plan_path=cls.output/'online_plan.json';cls.trace_path=cls.output/'online_final_trace.json'
        cls.trace=_read_uart_online_trace(cls.trace_path)
        envelope=_verify_online_run_identity(cls.output,plan_path=cls.plan_path,trace_path=cls.trace_path,trace=cls.trace)
        if not _saved_memory_commit_mode(cls.output,envelope):raise ValueError('old prefix lacks commit-stream identity')
        cls.plan=json.loads(cls.plan_path.read_bytes());cls.manifest=json.loads((cls.output/'online_session_manifest.json').read_bytes())
        cls.events=list(cls.trace.events);cls.index=native_fixture._verified_saved_native_index(cls.plan,cls.manifest)

    def test_four_exact_saved_raw_semantic_chains(self):
        reports=self.reconstruct();self.assertFalse([r for r in reports if r.get('status')=='incomplete'])
        self.assertFalse([e for e in self.events if e.get('status')=='incomplete'])
        rows=_saved_semantic_store_chains(self.manifest,self.events,reports)
        self.assertEqual(len(rows),4);self.assertEqual([r['role'] for r in rows],['bootstrap']+['fuzz_source']*3)
        print(json.dumps(dict(store_memory_raw_semantics=True,chains=4,
            verification_scope='saved_raw_semantics_only',live_authority_claim=False),sort_keys=True),flush=True)

    def test_deleted_raw_stages_cannot_satisfy_saved_semantics(self):
        for kind in ('memory_write_commit','memory_write','uart_rdata_access','cpu_retire',
                     'instr_response','data_accept','data_response','cpu_retirement_match'):
            with self.subTest(kind=kind):
                events=[e for e in self.events if e.get('kind')!=kind]
                reports=self.reconstruct(lambda e:None if e.get('kind')==kind else e)
                try:rows=_saved_semantic_store_chains(self.manifest,events,reports)
                except ValueError:continue
                self.assertFalse(rows,kind)

    def test_fresh_complete_wire_prefix_equal(self):
        from myfuzz.integration.ibex_uart_online import replay_ibex_uart_online_files
        cache=os.environ.get('MYFUZZ_UART_STORE_MEMORY_CACHE_DIR')
        if not cache:raise ValueError('MYFUZZ_UART_STORE_MEMORY_CACHE_DIR required')
        result=replay_ibex_uart_online_files(cache_dir=Path(cache),plan_path=self.plan_path,trace_path=self.trace_path)
        self.assertTrue(result.matches,result.difference_context);self.assertIsNone(result.first_difference)
        native_fixture._assert_full_wire_prefix(self,result.actual_trace.events,self.events)
        self.assertEqual(native_fixture._wire_bytes(result.actual_trace.local_ticks),native_fixture._wire_bytes(self.trace.local_ticks))
        print(json.dumps(dict(store_memory_fresh_matches=True,events=len(self.events),
            first_difference=None,verification_scope='full_wire_prefix'),sort_keys=True),flush=True)


def _commit_digest(document):
    core={k:v for k,v in document.items() if k!='commit_id'}
    return hashlib.sha256(json.dumps(core,sort_keys=True,separators=(',',':'),
        allow_nan=False).encode()).hexdigest()


class StoreCommitSemanticHelpers(unittest.TestCase):
    def test_typed_cells_reject_rehashed_numeric_substitutions(self):
        from tests.scenario.test_uart_store_commit_contract import fixture,key,write
        _,_,service=fixture();document=write(service).commit_document()
        payload=dict(op='write',address=0x20000,value=90,width_bytes=4,byte_enable=15)
        payload['value']=0x5a
        _validate_commit_document(document,asdict(key()),payload)
        for version in ([False,1],[0,True],[0.0,1],[0,1.0]):
            altered=deepcopy(document);altered['version']=version
            altered['commit_id']=_commit_digest(altered)
            with self.subTest(version=version),self.assertRaises(ValueError):
                _validate_commit_document(altered,asdict(key()),payload)

    def test_valid_saved_hash_cannot_authorize_live_join(self):
        from tests.scenario.test_uart_store_commit_contract import fixture,write
        from myfuzz.scenario.uart_store_memory import UartStoreMemoryJoin
        _,_,service=fixture();document=write(service).commit_document()
        event=dict(kind='memory_write_commit',schema_version='memory_write_commit.v1',
            event_id=1,component='cpu',service_commit_sequence=1,
            transaction=document['fullkey'],commit_id=document['commit_id'],
            commit_document=document,commit_token=1)
        reports=UartStoreMemoryJoin().consume(event)
        self.assertFalse(any(r.get('status')=='accepted' for r in reports))
        self.assertEqual(reports[0]['reason'],'unregistered_host_memory_commit')
