"""Bounded CPU→IP protocol associations, separate from semantic authority."""
from collections.abc import Mapping
from copy import deepcopy
import hashlib
import json


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)


def archive_join_gap_report(journal, *, source_component, target_components, origin_ref, max_records=256):
    """Inventory one archive only; historical JSON is never a live handoff seal."""
    if type(max_records) is not int or not 1<=max_records<=256:
        raise ValueError('cpu-ip-join-bound-invalid')
    source_raw=[r for r in journal if r.get('kind')=='local_tick_sample' and r.get('component')==source_component]
    target_raw=[r for r in journal if r.get('kind')=='local_tick_sample' and r.get('component') in target_components]
    taps=any(isinstance(r.get('outputs',{}).get('protocol_taps'),Mapping) for r in source_raw)
    acceptances=[r for r in journal if r.get('kind')=='mmio_acceptance' and r.get('component')==source_component]
    deliveries=[r for r in journal if r.get('kind')=='mmio_delivery' and r.get('component')==source_component]
    pairs=[];gaps=['missing_live_handoff_authority']
    if not taps:gaps.append('missing_cpu_raw_obi_taps')
    if not source_raw:gaps.append('missing_cpu_adapter_raw_samples')
    if not any(any(name.startswith('trace_') for name in r.get('outputs',{}).get('backend',{})) for r in target_raw):
        gaps.append('missing_target_raw_protocol_taps')
    for acceptance in acceptances[:max_records]:
        matches=[r for r in deliveries if r.get('source_transaction')==acceptance.get('source_transaction')]
        status='matching_declared_host_key_only' if len(matches)==1 else 'gap'
        if len(matches)!=1 and 'router_key_not_unique_or_missing' not in gaps:gaps.append('router_key_not_unique_or_missing')
        pairs.append(dict(source_transaction=deepcopy(acceptance.get('source_transaction')),
            acceptance_event_ref=acceptance.get('event_id'),delivery_event_refs=[r.get('event_id') for r in matches],status=status))
    return dict(schema_version='cpu_ip_protocol_join_gap.v1',origin_ref=origin_ref,status='gap',
        missing_links=gaps,router_pair_candidates=pairs,grants_verified=False,
        grants_storage=False,grants_version_dependency=False,grants_prerequisites=False,grants_functional=False)


def runner_cpu_ip_protocol_joins(runner, *, max_records=256):
    """Use current live ordinary-APB seals; never accept restored JSON seals."""
    from .runner import ScenarioRunner
    from .ordinary_apb_access_evidence import OrdinaryApbAccessEvidence
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    if type(runner) is not ScenarioRunner or type(max_records) is not int or not 1<=max_records<=256:
        raise ValueError('cpu-ip-join-live-runner-and-bound-required')
    observer=runner._ordinary_apb_access_evidence
    result=dict(schema_version='cpu_ip_protocol_join_report.v1',
        proof_scope='actual_cpu_obi_adapter_router_apb_transaction_association_only',
        records=[],gaps=[],grants_verified=False,grants_storage=False,grants_version_dependency=False,grants_prerequisites=False,grants_functional=False)
    if type(observer) is not OrdinaryApbAccessEvidence or 'completed_accesses' in vars(observer):
        result['gaps'].append(dict(reason='missing_live_handoff_authority'));return result
    try:seals=observer.completed_accesses()
    except ValueError as error:
        result['gaps'].append(dict(reason='live_handoff_authority_invalid',detail=str(error)));return result
    reports={}
    rows=list(runner.events)
    if len(rows)>100000:
        result['gaps'].append(dict(reason='journal_limit'));return result
    journal={r['event_id']:r for r in rows}
    if len(journal)!=len(rows):
        result['gaps'].append(dict(reason='duplicate_event_identity'));return result
    from collections import Counter
    key_counts=Counter(_canonical(s['association']['source_transaction']) for s in seals)
    access_counts=Counter((s['association']['target_instance'],s['receipt']['access_id']) for s in seals)
    for seal in seals[:max_records]:
        key=seal['association']['source_transaction'];source=key['source_component']
        identity=dict(source_transaction=deepcopy(key),target_access_id=seal['receipt']['access_id'])
        try:
            token=_canonical(key)
            access=(seal['association']['target_instance'],identity['target_access_id'])
            if key_counts[token]!=1 or access_counts[access]!=1:
                raise ValueError('handoff_identity_not_unique')
            cpu=runner.sessions[source]
            if type(cpu) is not GeneratedCve2Session or any(n in vars(cpu) for n in ('step_local','_serve','_validate_pre','command')):
                raise ValueError('cpu_receipt_producer_not_actual')
            request=seal['request_evidence'];tick=request['acceptance_tick']
            if request['transaction']!=key:raise ValueError('source_key_mismatch')
            candidates=[r for r in journal.values() if r.get('kind')=='local_tick_sample'
                and r.get('component')==source and r.get('phase')=='pre' and r.get('local_tick')==tick
                and r.get('reset_epoch')==key['source_epoch']]
            if len(candidates)!=1:raise ValueError('cpu_raw_acceptance_tick_not_unique')
            raw=candidates[0];document=cpu.artifact.runtime_document
            traces=[t for t in document['base_protocol_traces']['traces']
                    if {'we','wdata','be'}<=set(t['signals'])]
            if len(traces)!=1:raise ValueError('data_endpoint_not_unique')
            trace=traces[0];tap=raw['outputs']['protocol_taps'];roles={r:tap[n] for r,n in trace['signals'].items()}
            if roles['req']!=1 or roles['gnt']!=1:raise ValueError('host_tick_is_not_cpu_obi_grant')
            if (roles['addr'],roles['we'],roles['be'])!=(request['raw_address'],request['write'],request['be']):
                raise ValueError('cpu_raw_request_mismatch')
            if request['write'] and roles['wdata']!=request['wdata']:raise ValueError('cpu_raw_write_value_mismatch')
            # post(t-1) is a level observation after the preceding edge;
            # pre(t) is the certified sampling edge. They are not two grants.
            previous=[r for r in rows if r.get('kind')=='local_tick_sample'
                and r.get('component')==source and r.get('phase')=='post'
                and r.get('local_tick')==tick-1 and r.get('reset_epoch')==key['source_epoch']]
            if len(previous)!=1:raise ValueError('cpu_previous_post_not_unique')
            previous_taps=previous[0]['outputs']['protocol_taps']
            if any(previous_taps[n]!=tap[n] for role,n in trace['signals'].items()
                   if role in ('req','gnt','addr','we','be','wdata')):
                raise ValueError('cpu_grant_to_host_edge_not_contiguous')
            backend=raw['outputs']['backend']
            channel={p['role']:p['name'] for p in document['backend_ports'] if p['channel']=='d'}
            if backend[channel['req_valid']]!=1 or backend[channel['req_ready']]!=1:
                raise ValueError('adapter_beat_not_accepted_same_measured_edge')
            expected={'req_addr':request['raw_address'],'req_write':request['write'],
                      'req_wdata':request['wdata'],'req_be':request['be']}
            if any(backend[channel[r]]!=v for r,v in expected.items()):raise ValueError('adapter_beat_payload_mismatch')
            if source not in reports:
                from .protocol_trace_sets import ProtocolTraceSetObserver
                reports[source]=ProtocolTraceSetObserver(source,cpu.artifact).report(runner._events)
            proof=reports[source]['endpoints'][trace['endpoint_id']]['evidence']
            certificates=[c for c in proof['certificates'] if c['accept_raw_event_id']==raw['event_id']]
            if len(certificates)!=1:raise ValueError('cpu_obi_acceptance_not_certified')
            association=seal['association']
            for kind in ('mmio_acceptance','mmio_delivery'):
                if sum(r.get('kind')==kind and r.get('source_transaction')==key for r in rows)!=1:
                    raise ValueError('router_key_not_unique')
            acceptance=journal[association['acceptance_event_id']]
            delivery=journal[association['delivery_event_id']]
            for actual,expected_row in ((acceptance,seal['acceptance']),(delivery,seal['delivery'])):
                if {k:v for k,v in actual.items() if k not in ('event_id','producer_event_id','component','kind','provenance')}!=expected_row:
                    raise ValueError('sealed_router_journal_mismatch')
                if actual['source_transaction']!=key:raise ValueError('router_source_key_mismatch')
            if association['status']!='cpu_delivery_confirmed':raise ValueError('target_handoff_not_confirmed')
            if (acceptance['address']!=request['aligned_address'] or acceptance['write']!=bool(request['write'])
                    or acceptance['byte_enable']!=request['be']
                    or request['write'] and acceptance['write_value']!=request['wdata']):
                raise ValueError('source_to_router_payload_mismatch')
            certificate=certificates[0]
            response_raw=journal[certificate['response_raw_event_id']]
            if (response_raw.get('component')!=source or response_raw.get('phase')!='pre'
                    or response_raw.get('reset_epoch')!=key['source_epoch']
                    or response_raw.get('local_tick',-1)<tick):
                raise ValueError('cpu_response_identity_mismatch')
            response_taps=response_raw['outputs']['protocol_taps']
            receipt=seal['receipt']
            if (response_taps[trace['signals']['rvalid']]!=1
                    or response_taps[trace['signals']['error']]!=receipt['error']):
                raise ValueError('cpu_response_status_mismatch')
            # The CPU service returns the complete aligned beat. Byte lane
            # extraction belongs to the CPU RTL, not this protocol join.
            if not request['write'] and (response_taps[trace['signals']['rdata']]!=receipt['rdata']
                    or delivery['read_value']!=receipt['rdata']):
                raise ValueError('cpu_response_read_data_mismatch')
            response=journal[certificate['response_event_id']]
            if (response['raw_event_refs']!=[response_raw['event_id']]
                    or response['payload']['rdata']!=response_taps[trace['signals']['rdata']]
                    or response['payload']['error']!=bool(receipt['error'])):
                raise ValueError('cpu_response_projection_mismatch')
            target_refs=association['raw_event_refs']
            if len(set(target_refs))!=len(target_refs):raise ValueError('target_raw_span_not_unique')
            if not target_refs or any(journal[r].get('component')!=association['target_instance'] for r in target_refs):
                raise ValueError('target_raw_span_mismatch')
            from myfuzz.local_harness.ordinary_apb_access_receipts import _json
            from .ip_protocol_events import IpProtocolEventNormalizer
            from .ip_protocol_checker import IpProtocolChecker
            target,helper,_,_=observer._targets[association['target_instance']]
            if observer._helper_methods[0](helper,seal['receipt']['access_id'])!=seal['receipt']:
                raise ValueError('target_seal_registry_mismatch')
            cfg=dict(component_id=target.artifact.plan.profile.component_id,
                instance_id=target.artifact.plan.request.instance_id,
                protocol_trace=target.artifact.runtime_document['base_protocol_trace'])
            normalizer=IpProtocolEventNormalizer(**cfg);checker=IpProtocolChecker(**cfg);expected_base=[]
            for ref in target_refs:
                target_raw=journal[ref]
                digest=hashlib.sha256(_json(target_raw['outputs']).encode()).hexdigest()
                if digest!=observer._helper_methods[1](helper,seal['receipt']['access_id'],
                        target_raw['local_tick'],target_raw['phase']):
                    raise ValueError('target_raw_content_mismatch')
                if checker.consume_local_tick(target_raw,reset_epoch=association['target_reset_epoch']):
                    raise ValueError('target_protocol_violation')
                expected_base.extend(r for r in normalizer.consume_local_tick(target_raw,
                    reset_epoch=association['target_reset_epoch'])
                    if r['event_type'] in ('transaction_request','transaction_accept','transaction_response'))
            actual_base=[{k:v for k,v in journal[r].items()
                if k not in ('event_id','producer_event_id','component','kind','provenance')}
                for r in association['base_event_refs']]
            if expected_base!=actual_base:raise ValueError('target_protocol_projection_mismatch')
            record=dict(**identity,status='actual_protocol_handoff_associated',
                cpu_endpoint_id=trace['endpoint_id'],cpu_local_tick=tick,
                cpu_obi_raw_event_ref=raw['event_id'],adapter_raw_event_ref=raw['event_id'],
                cpu_obi_previous_post_event_ref=previous[0]['event_id'],
                grant_host_sampling_relation='previous_post_level_contiguous_with_certified_pre_edge',
                host_acceptance_tick=tick,cpu_obi_grant_sample_tick=tick,
                cpu_obi_accept_event_ref=certificates[0]['accept_event_id'],
                cpu_obi_response_event_ref=certificates[0]['response_event_id'],
                cpu_obi_response_raw_event_ref=response_raw['event_id'],
                router_acceptance_event_ref=association['acceptance_event_id'],
                router_delivery_event_ref=association['delivery_event_id'],
                target_receipt_event_ref=association['target_receipt_event_id'],
                target_raw_event_refs=target_refs,target_protocol_event_refs=association['base_event_refs'],
                grants_verified=False,grants_storage=False,grants_version_dependency=False,grants_prerequisites=False,grants_functional=False)
            record['association_id']=hashlib.sha256(_canonical(record).encode()).hexdigest()
            result['records'].append(record)
        except (KeyError,ValueError,TypeError) as error:
            result['gaps'].append(dict(**identity,reason=str(error)))
    if len(seals)>max_records:result['gaps'].append(dict(reason='record_limit'))
    return result
