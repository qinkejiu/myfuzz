#!/usr/bin/env python3
"""Audit saved F2 RFuzz bytes against an independent supervisor ledger; no RTL."""
import argparse
from copy import deepcopy
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path,PurePosixPath
import re
import sys
import tarfile

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT/'src') not in sys.path:sys.path.insert(0,str(ROOT/'src'))


def require(condition,code):
    if not condition:raise ValueError('compiled-F2-saved-audit-'+code)


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',', ':'),allow_nan=False).encode()
def equal(left,right,code):require(canonical(left)==canonical(right),code)
def file_hash(path):return sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())


def safe_name(name):
    require(type(name) is str and bool(name) and '\\' not in name,'unsafe-name')
    parsed=PurePosixPath(name)
    require(not parsed.is_absolute() and '..' not in parsed.parts and str(parsed)==name,'unsafe-name')
    return parsed


def safe_file(base,name):
    parsed=safe_name(name);path=Path(base)
    for part in parsed.parts:
        path=path/part;require(not path.is_symlink(),'symlink')
    require(path.is_file() and path.resolve().is_relative_to(Path(base).resolve()),'missing-or-outside-file:'+name)
    return path


def _map(value):
    require(type(value) is dict and bool(value),'empty-byte-map')
    for name,digest in value.items():
        safe_name(name);require(type(digest) is str and re.fullmatch('[0-9a-f]{64}',digest) is not None,'byte-map-digest')
    return value


def verify_origin_records(invocation, sources, terminal):
    """Unavailable aliases are provenance records, never archived input bytes."""
    origins = read(safe_file(invocation,'source-origins-before.json'))
    equal(origins,read(safe_file(invocation,'source-origins-after.json')),'source-origin-drift')
    require(type(origins) is dict and set(origins) == set(sources), 'source-origin-bijection')
    require(terminal.get('source_origins_unchanged') is True, 'source-origin-supervisor-state')
    for name, record in origins.items():
        require(type(record) is dict and type(record.get('is_symlink')) is bool
            and type(record.get('resolved_path')) is str and Path(record['resolved_path']).is_absolute()
            and record.get('content_sha256') == sources[name], 'source-origin-record')
        require(type(record.get('link_target')) is str and bool(record['link_target'])
            if record['is_symlink'] else record.get('link_target') is None, 'source-origin-link')
    unavailable = read(safe_file(invocation,'unavailable-symlinks-before.json'))
    equal(unavailable,read(safe_file(invocation,'unavailable-symlinks-after.json')),'unavailable-link-drift')
    require(type(unavailable) is dict and not set(unavailable) & set(sources), 'unavailable-link-bijection')
    require(terminal.get('unavailable_symlinks_unchanged') is True, 'unavailable-link-supervisor-state')
    for name, record in unavailable.items():
        safe_name(name)
        require(type(record) is dict and record.get('is_symlink') is True
            and type(record.get('link_target')) is str and bool(record['link_target'])
            and type(record.get('resolved_path')) is str and Path(record['resolved_path']).is_absolute()
            and record.get('content_sha256', 'missing') is None
            and record.get('unavailable_reason') == 'target_missing'
            and record.get('declared_source_file') is False, 'unavailable-link-record')


def verify_external(output,invocation, *, expected_exit=0):
    require(not output.is_symlink() and not invocation.is_symlink(),'symlink-root')
    ledger=invocation.parent
    require(output.resolve().is_relative_to(ledger.resolve()) and output!=invocation,'output-outside-ledger')
    require((output/'.incomplete').is_file() if expected_exit else not (output/'.incomplete').exists(),'incomplete-marker')
    terminal=read(safe_file(invocation,'terminal.json'));process=read(safe_file(invocation,'process.json'))
    require(type(terminal.get('exit_code')) is int and terminal['exit_code']==expected_exit
        and type(terminal.get('expected_exit_code')) is int and terminal['expected_exit_code']==expected_exit
        and terminal.get('exit_matches_expectation') is True and terminal.get('reaped') is True
        and terminal.get('timed_out') is False and terminal.get('inputs_unchanged') is True
        and terminal.get('outputs_unchanged') is True and terminal.get('supervisor_error') is None,'supervisor-not-successful')
    require(type(terminal.get('pid')) is int and terminal['pid']>0 and process.get('pid')==terminal['pid'] and process.get('pgid')==terminal['pid'],'supervisor-process')
    before=_map(read(safe_file(invocation,'source-before.json')))
    equal(before,read(safe_file(invocation,'source-after.json')),'source-drift')
    verify_origin_records(invocation, before, terminal)
    archive=safe_file(invocation,'executed-inputs.tar.gz')
    require(file_hash(archive)==terminal.get('archive_sha256'),'archive-hash')
    archived={}
    try:
        with tarfile.open(archive,'r:gz') as stream:
            for member in stream:
                safe_name(member.name)
                require(member.isfile() and member.name not in archived,'archive-member')
                source=stream.extractfile(member);require(source is not None,'archive-member')
                archived[member.name]=sha256(source.read()).hexdigest()
    except (tarfile.TarError,EOFError,OSError) as error:raise ValueError('compiled-F2-saved-audit-archive-invalid') from error
    equal(archived,before,'archive-source-map')
    pins=_map(read(safe_file(invocation,'output-initial.json')))
    equal(pins,read(safe_file(invocation,'output-final.json')),'output-drift')
    actual={}
    for path in ledger.rglob('*'):
        if path.is_relative_to(invocation):continue
        require(not path.is_symlink(),'symlink')
        if path.is_file():actual[str(path.relative_to(ledger))]=file_hash(path)
    equal(actual,pins,'external-output-bytes')
    command=read(safe_file(invocation,'command.json'));argv=command.get('argv',[])
    require(type(argv) is list and argv.count('--executor')==1 and argv[argv.index('--executor')+1]=='compiled-f2-rfuzz','explicit-F2-command')
    require(type(command.get('expected_exit_code')) is int and command['expected_exit_code']==expected_exit,'command-expected-exit')
    return before,pins,ledger,terminal


def verify_current_sources(sources, base):
    """Attribute this parser and its project imports to the executed snapshot."""
    require(base.resolve() == ROOT.resolve(), 'auditor-source-root')
    paths = [Path(__file__).resolve(), *sorted((ROOT/'src/myfuzz').rglob('*.py'))]
    for path in paths:
        name = str(path.relative_to(ROOT))
        require(name in sources and file_hash(path) == sources[name], 'auditor-source-attribution:'+name)


def verify_client_pin(command, identity):
    pin = command.get('executables', {}).get('rfuzz_client')
    require(type(pin) is dict and type(pin.get('path')) is str and bool(pin['path'])
        and type(pin.get('sha256')) is str and re.fullmatch('[0-9a-f]{64}', pin['sha256']) is not None,
        'client-executable-pin-required')
    require(identity['toolchain']['client'].get('binary_sha256') == pin['sha256'], 'client-executable-association')


def verify_case_observations(certificate, candidate, declared):
    """Check saved per-case predicates; this issues no live observation tokens."""
    assertions = {row['expectation_id']:row for row in certificate['assertions']}
    protocol = assertions['protocol_checker.receipt_violations']['evidence']
    proof = assertions['cross_component.declared_edge_hops']['evidence']
    require(protocol.get('violations') == [], 'feedback-protocol')
    exact = certificate['exact_hops']; edges = exact['edges']
    require(len(edges) == len(declared) == 3, 'feedback-edges')
    for edge, expected in zip(edges, declared):
        equal({k:v for k,v in edge.items() if k not in ('status','hops')}, expected, 'feedback-edge-identity')
        require(edge.get('status') == 'certified' and bool(edge.get('hops')), 'feedback-edge-observation')
    require(bool(exact['instruction_hops']) and edges[0]['hops'] == exact['instruction_hops']
        and len(exact['data_hops']) == 1, 'feedback-functional-hops')
    hop = exact['data_hops'][0]
    equal(proof['edge_ids'], [[e['rule_index'],e['prerequisite_index']] for e in edges], 'feedback-edge-ids')
    equal(proof['roles'], [e['role'] for e in edges], 'feedback-edge-roles')
    equal(proof['endpoints'], [[e['source_component'],e['target_component']] for e in edges], 'feedback-endpoints')
    equal(proof['transaction'], hop['source_transaction'], 'feedback-transaction')
    require(proof['instruction_source_id'] == certificate['instruction_source_id']
        and proof['native_read_APB_event'] == hop['native_APB_event']
        and proof['native_read_OBI_events'] == [hop['native_acceptance_event'],hop['native_response_event']],
        'feedback-read-events')
    equal(edges[1]['hops'], [dict(hop,role='read_request',consumer_event=hop['native_APB_event'])], 'feedback-request')
    equal(edges[2]['hops'], [dict(hop,role='read_return',producer_event=hop['native_APB_event'],consumer_event=hop['native_response_event'])], 'feedback-return')
    ram = exact['ram_write_hop']; value = hop['native_obi']['rdata']
    require(type(value) is int and 0 <= value <= 0xffffffff
        and ram['memory_write_event'] == proof['dependent_RAM_write_event']
        and ram['address'] == candidate.declaration['result_address']
        and ram['value'] == value ^ candidate.declaration['xor_constant']
        and ram['width_bytes'] == 4 and ram['byte_enable'] == 15
        and len(ram['version']) == 2 and bool(ram['transaction'])
        and ram['producer_event_id'] == ram['native_acceptance_event']
        and hop['native_response_event'] < ram['native_acceptance_event'] < ram['memory_write_event'] < ram['native_response_event'],
        'feedback-dependent-store')


def _request_inputs(document,base,output,sources,pins,ledger):
    references=[]
    for row in [document['cpu'],*document['devices']]:
        references.append(row['profile'])
        if row.get('test_capability') is not None:references.append(row['test_capability'])
    references.append(document['wiring']['source'])
    for name in references:
        require(type(name) is str,'request-reference')
        source=Path(name);source=source if source.is_absolute() else base/source
        require(not source.is_symlink() and source.is_file(),'request-reference-file')
        if source.resolve().is_relative_to(output.resolve()):
            key=str(source.relative_to(ledger));require(key in pins and file_hash(source)==pins[key],'request-output-pin')
        else:
            require(source.resolve().is_relative_to(base.resolve()),'request-reference-outside-root')
            key=str(source.relative_to(base));safe_file(base,key)
            require(key in sources and file_hash(source)==sources[key],'request-source-pin')


def _normalize(prefix):
    value=deepcopy(prefix)
    for row in value['records']:
        for name in ('prerequisite','postcondition'):
            if name in row['certificate']:row['certificate'][name].pop('process_scope',None)
    return value


def _join_records(output,request,compiled,prefix,fresh,evidence,typed,manifest,online,decoder_document):
    from myfuzz.scenario.compiled_f2_decoder import CompiledF2Decoder,CompiledF2CandidateRefused
    from myfuzz.scenario.compiled_paths import compiled_document_sha256
    from myfuzz.scenario.compiled_assertion_results import validate_assertion_results
    from myfuzz.integration.compiled_f2_online_material import verify_f2_instruction_image_material
    binding=prefix['execution_binding'];selected=binding['runtime_path_admission']['selected_path']
    digest=compiled_document_sha256(compiled)
    require(prefix['compiled_sha256']==digest and binding['compiled_document_sha256']==digest,'compiled-identity')
    require(prefix['execution_binding_sha256']==binding['binding_sha256'],'binding-identity')
    equal(evidence['execution_binding'],binding,'evidence-binding')
    require(evidence['run_id']==prefix['run_id'] and evidence['path_id']==selected['path_id'],'evidence-identity')
    validate_assertion_results(typed,compiled_document_sha256=digest,binding_sha256=binding['binding_sha256'],path=selected,run_id=prefix['run_id'],cases=evidence['cases'])
    equal(prefix['assertions'],typed,'prefix-assertions');equal(fresh['assertions'],typed,'fresh-assertions')
    verify_f2_instruction_image_material(decoder_document,manifest,online)
    equal(prefix['online_plan'],online,'original-online-plan')
    decoder=CompiledF2Decoder.from_request(request=request,compiled=compiled,run_id=prefix['run_id'],schedule=tuple(manifest['runner']['sessions']),rounds=prefix['rounds_per_case'],result_address=decoder_document['result_address'])
    equal(decoder.document(),decoder_document,'independent-decoder-document')
    from myfuzz.integration.compiled_f2_feedback import f2_observation_targets
    from myfuzz.integration.compiled_f2 import _f2_edges
    targets = [asdict(target) for target in f2_observation_targets(selected)]
    equal(read(safe_file(output,'session/targets.json')), targets, 'feedback-targets')
    image = next(row for row in selected['sources'] if row['kind']=='instruction_image')
    stream = next(row for row in selected['sources'] if row['kind']=='cpu_load_stream')
    declared = _f2_edges(compiled, image, stream['register_access'])
    wire=decoder.contract['address'].to_bytes(4,'little')+bytes(4)
    require(safe_file(output,'session/seed.bin').read_bytes()==wire,'seed')
    raw=safe_file(output,'session/receipts.jsonl').read_bytes()
    rows=[json.loads(line) for line in raw.splitlines() if line.strip()]
    records=prefix['records'];require(bool(records),'no-certified-record')
    require(type(prefix.get('max_cases')) is int and 1<=prefix['max_cases']<=65536,'case-budget')
    cursor=records[0]['certificate']['instruction_address'];index=0;seen=set();mapping=[];raw_count=0;refused=0
    for row in rows:
        key=(row['run_id'],row['buffer_id'],row['slot']);require(key not in seen,'duplicate-receipt');seen.add(key)
        require(row['run_id']==prefix['run_id'] and row['flow_id']=='F2'
            and row['path_id']==decoder.path_id and row['source_id']==decoder.source_id,'receipt-identity')
        wires=tuple(bytes.fromhex(value) for value in row['online_raw_records_hex']);raw_count+=len(wires)
        require(1<=len(wires)<=200 and all(len(value)==8 for value in wires),'wire-records')
        require(sha256(b''.join(wires)).hexdigest()==row['raw_sha256'],'raw8-digest')
        try:
            if not 1<=len(wires)<=8:raise CompiledF2CandidateRefused('sequence-count','/wire/records',{'observed':len(wires)})
            if index+len(wires)>prefix['max_cases']:raise CompiledF2CandidateRefused('case-budget-exhausted','/cases',{'admitted':index,'requested':len(wires),'max_cases':prefix['max_cases']})
            candidates=decoder.decode_sequence(wires,cursor=cursor,case_index=index)
        except CompiledF2CandidateRefused as error:
            require(row.get('coverage_hex') == bytes(6).hex(), 'coverage-refusal-must-be-zero')
            require(row['status']=='input_invalid' and not row['online_source']['candidates'],'preflight-refusal')
            equal(row['rejection'],dict(code=error.code,pointer=error.pointer,detail=error.detail),'preflight-reason');refused+=1;continue
        require(row['status']=='certified','incomplete-receipt')
        require(row.get('coverage_hex') == bytes([1]*6).hex(), 'coverage-certified-observations')
        equal(row['online_source']['candidates'],[c.document() for c in candidates],'independent-wire-projection')
        require(sha256(b''.join(c.candidate_bytes for c in candidates)).hexdigest()==row['genome_sha256'],'projected4-digest')
        for candidate in candidates:
            require(index<len(records),'missing-record');record=records[index];certificate=record['certificate']
            require(record['raw']==candidate.candidate_bytes.hex(),'prefix-projection')
            expected=dict(schema_version='compiled_F2_chain.v1',status='certified',runtime_admitted=True,case_id=candidate.case.case_id,path_id=candidate.path_id,source_id=candidate.source_id,instruction_address=candidate.case.source.address,instruction_source_id=decoder.image['source_id'],instruction_sha256=sha256(candidate.case.source.data).hexdigest(),execution_binding_sha256=binding['binding_sha256'],runtime_path_id=candidate.case.path_id,runtime_path_admission_sha256=decoder.runtime_path_admission.digest)
            require(all(certificate.get(k)==v for k,v in expected.items()),'certificate-identity')
            case=online['cases'][index];source=asdict(candidate.case.source);source['kind']='bound_instruction'
            equal(case['source'],source,'case-instruction');require(case['case_id']==candidate.case.case_id,'case-order')
            require(evidence['cases'][index]['case_id']==candidate.case.case_id,'typed-case-order')
            assertions=certificate['assertions'];expected_ids=[a['expectation_id'] for a in selected['assertions']]
            equal([a['expectation_id'] for a in assertions],expected_ids,'certificate-assertions')
            for assertion in assertions:
                require(assertion['status']=='passed','certificate-failed')
                ref=candidate.case.case_id+':'+assertion['expectation_id']
                equal(evidence['cases'][index]['evidence_inventory'][ref]['details'],assertion['evidence'],'certificate-evidence')
            verify_case_observations(certificate, candidate, declared)
            mapping.append(dict(case_id=candidate.case.case_id,source_id=candidate.source_id,instruction_source_id=candidate.case.source.source_id,runtime_path_id=candidate.case.path_id,raw8_sha256=sha256(candidate.raw).hexdigest(),projected4_sha256=sha256(candidate.candidate_bytes).hexdigest()))
            index+=1;cursor+=len(candidate.case.source.data)
    require(index==len(records)==len(online['cases'])==len(evidence['cases']),'case-bijection')
    join=read(safe_file(output,'compiled_f2_receipt_join.v1.json'))
    require(join.get('schema_version')=='compiled_F2_receipt_join.v1' and join.get('status')=='ok','receipt-join-schema')
    expected=dict(run_id=prefix['run_id'],path_id=decoder.path_id,source_id=decoder.source_id,compiled_sha256=digest,execution_binding_sha256=binding['binding_sha256'],receipts_sha256=sha256(raw).hexdigest(),rows=len(rows),case_count=index,raw_record_count=raw_count,candidate_bytes=4,wire_record_bytes=8,rejected_tests=refused,cases=mapping)
    require(all(canonical(join.get(k))==canonical(v) for k,v in expected.items()),'receipt-join')
    return index,len(rows)


def verify_process_receipts(binding,replay):
    from myfuzz.integration.compiled_build_join import built_receipt_sha256
    receipts=binding['built_executable_receipts'];cpu=binding['cpu']['instance_id']
    for name in ('original_execution_audit','execution_audit'):
        audit=replay[name]
        require(audit.get('closed') is True and set(audit['identities'])==set(audit['exits'])==set(receipts),'process-components')
        for component,receipt in receipts.items():
            identity=audit['identities'][component];exit_row=audit['exits'][component]
            expected=dict(component=component,role='cpu' if component==cpu else 'bound_target',
                artifact_digest=receipt['artifact_digest'],build_digest=receipt['build_digest'],
                binary_sha256=receipt['binary_sha256'],observed_executable_sha256=receipt['binary_sha256'],
                built_receipt_sha256=built_receipt_sha256(receipt),ready_artifact_digest=receipt['artifact_digest'])
            require(all(identity.get(k)==v for k,v in expected.items()),'process-built-receipt-binary-association')
            require(type(exit_row.get('returncode')) is int and exit_row['returncode']==0
                and exit_row.get('reaped') is True,'process-exit')


def resolve_audit_paths(output, invocation, base_dir):
    """Normalize relative arguments before lexical ownership checks."""
    output = Path(output)
    invocation = Path(invocation) if invocation is not None else output.parent/'invocation'
    require(not output.is_symlink() and not invocation.is_symlink(), 'symlink-root')
    return output.resolve(strict=True), invocation.resolve(strict=True), Path(base_dir).resolve(strict=True)


def verify_saved_f2_run(output, *, invocation=None, base_dir=ROOT):
    try:
        output, invocation, base = resolve_audit_paths(output, invocation, base_dir)
        sources,pins,ledger,terminal=verify_external(output,invocation)
        verify_current_sources(sources,base)
        summary=read(safe_file(output,'run-summary.json'))
        require(type(summary.get('exit_code')) is int and summary['exit_code']==0 and not summary.get('refusals')
            and summary.get('executor',{}).get('name')=='compiled-f2-rfuzz','driver-not-completed')
        request_document=read(safe_file(output,'path_compile_request.json'))
        _request_inputs(request_document,base,output,sources,pins,ledger)
        from myfuzz.scenario.compiled_paths import load_path_compile_request,compile_paths
        request=load_path_compile_request(request_document,base_dir=base)
        saved_compiled=read(safe_file(output,'compiled_paths.v1.json'))
        compiled=compile_paths(request);equal(compiled,saved_compiled,'source-compiled-paths')
        prefix=read(safe_file(output,'compiled_f2_prefix.json'));fresh=read(safe_file(output,'compiled_f2_fresh_prefix.json'))
        equal(_normalize(prefix),_normalize(fresh),'full-prefix')
        replay=read(safe_file(output,'compiled_f2_replay.json'));verification=read(safe_file(output,'compiled_f2_fresh_verification.json'))
        for document in (replay,verification):
            require(document.get('matches') is True and document.get('first_difference','missing') is None and document.get('verification_scope')=='full','full-fresh')
        audit=read(safe_file(output,'compiled_f2_fresh_execution_audit.json'));equal(audit,replay['execution_audit'],'fresh-audit')
        from myfuzz.integration.compiled_f4 import _check_fresh_identities,normalized_semantic_sha256
        _check_fresh_identities([replay['original_execution_audit']['identities']],audit['identities'])
        verify_process_receipts(prefix['execution_binding'],replay)
        events=read(safe_file(output,'compiled_f2_fresh_events.json'))
        from myfuzz.integration.scenario_rfuzz_replay import _candidate_reference
        from myfuzz.integration.scenario_rfuzz_live import _verify_online_run_identity
        session=output/'session';trace_path,trace=_candidate_reference(session)
        require(_verify_online_run_identity(session,plan_path=session/'online_plan.json',trace_path=trace_path,trace=trace) is not None,'online-identity')
        verify_client_pin(read(safe_file(invocation,'command.json')),
            read(safe_file(output,'session/online_run_identity.json'))['identity'])
        for observed in (trace.events,events):
            require(normalized_semantic_sha256(trace.status,observed,trace.local_ticks)==prefix['semantic_hash'],'event-semantic-hash')
        for document in (replay,verification):
            require(document.get('expected_semantic_hash')==prefix['semantic_hash']
                and document.get('actual_semantic_hash')==prefix['semantic_hash'],'fresh-semantic-hash')
        manifest=read(safe_file(output,'session/online_session_manifest.json'));online=read(safe_file(output,'session/online_plan.json'))
        count,rows=_join_records(output,request,compiled,prefix,fresh,read(safe_file(output,'compiled_assertion_evidence.v1.json')),read(safe_file(output,'compiled_assertion_results.v1.json')),manifest,online,read(safe_file(output,'session/decoder_manifest.json')))
        report=read(safe_file(output,'session/report.json'));require(type(report.get('client_returncode')) is int and report['client_returncode']==0 and report.get('tests')==rows,'client-result')
        from myfuzz.integration.compiled_f2_build_join import verify_compiled_f2_build_material
        verify_compiled_f2_build_material(read(safe_file(output,'compiled_f2_build_join.v1.json')),harness_set=read(safe_file(output,'generated/harness_set.json')),manifest=manifest,prefix=prefix,replay=replay)
        return dict(schema_version='compiled_F2_saved_audit.v1',status='ok',case_count=count,receipt_count=rows,
            pinned_output_count=len(pins),source_file_count=len(sources),supervisor_pid=terminal['pid'],
            native_authority_issued=False,scope='saved byte and identity consistency under the supplied external supervisor ledger')
    except (KeyError,TypeError,IndexError,OSError) as error:raise ValueError('compiled-F2-saved-audit-material-shape-or-missing') from error


DECLARATIONS = '.superpowers/sdd/compiled-f2-rfuzz-entry-20261023/gates/inputs/negative-control-declarations.json'


def verify_refusal_material(output, *, control, sources, base_dir=ROOT):
    """Join a refused CLI result with its frozen guarded preconstruction proof."""
    base = Path(base_dir); output = Path(output)
    require(control in ('wrong-registration','incompatible-shape'), 'unknown-refusal-control')
    def frozen(name, expected_hash=None):
        path = safe_file(base, name)
        actual = file_hash(path)
        require(name in sources and actual == sources[name]
            and (expected_hash is None or actual == expected_hash), 'refusal-source-pin:'+name)
        return path
    declaration = read(frozen(DECLARATIONS))['expected_refusals'][control]
    require(type(declaration.get('exit_code')) is int and declaration['exit_code'] == 1, 'refusal-exit-declaration')
    proof = declaration['preconstruction_proof']
    receipt = read(frozen(proof['receipt'], proof['receipt_sha256']))
    before = read(frozen(proof['source_before'], proof['source_before_sha256']))
    after = read(frozen(proof['source_after'], proof['source_after_sha256']))
    equal(before,after,'refusal-guard-source-drift')
    for name, digest in _map(before).items():
        require(sources.get(name) == digest, 'refusal-guard-source-changed:'+name)
    require(receipt.get('control') == control and receipt.get('constructor_called') is False
        and receipt.get('inputs_unchanged') is True and receipt.get('cli_exit_code') == 1
        and receipt.get('status') == 'refused' and receipt.get('incomplete_marker') is True,
        'refusal-preconstruction-proof')
    summary = read(safe_file(output,'run-summary.json'))
    require(type(summary.get('exit_code')) is int and summary['exit_code'] == 1
        and (output/'.incomplete').is_file(), 'refusal-driver-state')
    rows = summary.get('refusals'); require(type(rows) is list and len(rows) == 1, 'refusal-count')
    for key in ('stage','code','pointer'):
        require(rows[0].get(key) == declaration[key], 'refusal-exact-'+key)
        require(receipt['actual_refusals'][0].get(key) == declaration[key], 'refusal-guard-'+key)
    if declaration.get('detail_error') is not None:
        require(rows[0].get('detail',{}).get('error') == declaration['detail_error'], 'refusal-detail')
    require(not (output/'session').exists(), 'refusal-native-session-present')
    for name in ('compiled_f2_prefix.json','compiled_f2_build_join.v1.json',
                 'compiled_assertion_results.v1.json','compiled_assertion_evidence.v1.json'):
        require(not (output/name).exists(), 'refusal-execution-material-present')
    return dict(control=control,code=declaration['code'],stage=declaration['stage'],
        constructor_called=False,proof_scope='same-source guarded preparation joined to unpatched frozen CLI refusal')


def verify_saved_f2_refusal(output, *, control, invocation=None, base_dir=ROOT):
    try:
        output, invocation, base = resolve_audit_paths(output, invocation, base_dir)
        sources,pins,ledger,terminal = verify_external(output,invocation,expected_exit=1)
        verify_current_sources(sources,base)
        declaration = read(safe_file(base, DECLARATIONS))['expected_refusals'][control]
        command = read(safe_file(invocation,'command.json'))
        argv = command['argv']
        for option,name in (('--compose',declaration['fixture']),('--ip',declaration['profile'])):
            require(argv.count(option) == 1, 'refusal-command-'+option)
            value = Path(argv[argv.index(option)+1]); value = value if value.is_absolute() else base/value
            require(value.resolve() == (base/name).resolve(), 'refusal-fixture-command')
        material = verify_refusal_material(output,control=control,sources=sources,base_dir=base)
        return dict(schema_version='compiled_F2_refusal_saved_audit.v1',status='ok',
            refusal=material,pinned_output_count=len(pins),supervisor_pid=terminal['pid'],
            native_authority_issued=False,scope='expected refusal and preconstruction evidence consistency')
    except (KeyError,TypeError,IndexError,OSError) as error:
        raise ValueError('compiled-F2-saved-audit-refusal-material-shape-or-missing') from error


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--invocation',type=Path);parser.add_argument('--base-dir',type=Path,default=ROOT)
    parser.add_argument('--refusal-control', choices=('wrong-registration','incompatible-shape'))
    args=parser.parse_args()
    try:
        if args.refusal_control:
            result=verify_saved_f2_refusal(args.output,control=args.refusal_control,invocation=args.invocation,base_dir=args.base_dir)
        else:
            result=verify_saved_f2_run(args.output,invocation=args.invocation,base_dir=args.base_dir)
    except ValueError as error:print(json.dumps({'status':'refused','error':str(error),'native_authority_issued':False}));return 2
    print(json.dumps(result,sort_keys=True));return 0


if __name__=='__main__':raise SystemExit(main())
