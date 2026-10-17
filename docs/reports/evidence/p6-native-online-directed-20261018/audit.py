"""Read saved JSON/tar only; no project imports, tools or model execution."""
import gzip
import hashlib
import json
from pathlib import Path
import tarfile

BASE = Path(__file__).resolve().parent

def require(value, name):
    if not value:
        raise ValueError(name)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode()

with tarfile.open(BASE / 'remote-records.tar.gz') as tar:
    raw = {}
    for member in tar.getmembers():
        if member.isfile():
            require(member.name not in raw, 'duplicate archive file')
            raw[member.name] = tar.extractfile(member).read()

def document(name):
    data = raw[name]
    return json.loads(gzip.decompress(data) if name.endswith('.gz') else data)

manifest = json.loads((BASE / 'remote-members.json').read_text())
require(set(raw) == {row['path'] for row in manifest}, 'archive membership')
require(all(len(raw[row['path']]) == row['bytes'] and sha(raw[row['path']]) == row['sha256']
            for row in manifest), 'archive member pin')
terminal_rows = []
for name in raw:
    if name.endswith('.terminal.json'):
        row = document(name)
        stem = name[:-len('.terminal.json')]
        require(row['returncode'] == 0 and row['pid'] > 0, name + ': child terminal')
        for channel in ('stdout', 'stderr'):
            require(sha(raw[stem + '.' + channel]) == row[channel + '_sha256'], name + ': stdio SHA')
        terminal_rows.append(dict(path=name, pid=row['pid'], returncode=row['returncode']))
require(len(terminal_rows) == 7, 'exact metadata/layout/gate terminal count')
control = 'gate-attempt3-control/'
operation = document(control + 'native-operation-result.json')
require(operation['status'] == 'collected_pending_independent_audit'
        and operation['gate_returncode'] == operation['layout_returncode'] == 0
        and operation['error'] is None and operation['formal_p6_complete'] is False,
        'operation outcome')
require(len(operation['git_metadata']) == 4 and all(row['returncode'] == 0
        for row in operation['git_metadata']), 'Git metadata outcome')
require(document(control+'before-tools.json') == document(control+'after-tools.json'), 'tool receipts differ')
layout_before = document(control+'layout-before-native.stdout')
layout_after = document(control+'layout-after-native.stdout')
for key in ('files', 'directories', 'freeze_sha256', 'directory_manifest_sha256'):
    require(layout_before[key] == layout_after[key], 'layout identity ' + key)
require(layout_before['files'] == 8887 and layout_before['directories'] == 600, 'layout counts')
require(layout_before['freeze_sha256'] == '50145c2408804a76c6ff651cefbb143aae17cd1be18559f79ea6386b510e2cc4', 'file freeze')
require(layout_before['directory_manifest_sha256'] == '7cf80b4ce94a31703f41df19307efe7227090ba330130acbe1d1a4a8bf5417ad', 'directory freeze')

runs = {}
all_processes = []
for name, expected_sources in [('positive', ['cpu.instructions','gpio0.pin_byte','cpu.instructions']),
                               ('controlled-response', ['cpu.instructions'])]:
    prefix = 'run-attempt3/' + name + '/'
    result = document(prefix+'result.json.gz')
    first = document(prefix+'first.json.gz')
    fresh = document(prefix+'fresh-comparison.json.gz')
    require(result['status'] == 'bounded_directed_gate_passed' and not result['capture_errors'], name+': status')
    require(result['source_selection'] == expected_sources, name+': selected sources')
    require(fresh['matches'] is True and fresh['verification_scope'] == 'full'
            and fresh['first_difference'] is None and fresh['difference_context'] is None,
            name+': comparison scope')
    require(first == fresh['actual_trace'], name+': entire first/fresh document equality')
    require(first['status'] == 'complete', name+': trace complete')
    require(sha(raw[prefix+'plan.json']) == first['genome_sha256'], name+': full plan digest')
    semantic = sha(canonical(dict(status=first['status'], events=first['events'], local_ticks=first['local_ticks'])))
    require(semantic == first['semantic_sha256'], name+': independently recomputed semantic digest')
    for field in ('first_bundle', 'fresh_bundle'):
        bundle = result[field]
        packed = raw[prefix+bundle['path']]
        require(sha(packed) == bundle['gzip_sha256'] and sha(gzip.decompress(packed)) == bundle['json_sha256'], name+': saved bundle pin')
    processes = result['processes']
    require(len(processes) == 4 and all(row['terminal_returncode'] == 0
            and row['reset_epoch'] == 0 for row in processes), name+': actual terminal handles')
    for component in ('cpu','gpio0'):
        pair = [row for row in processes if row['component'] == component]
        require(len(pair) == 2 and {row['runner_namespace'] for row in pair} == {'runner-0','runner-1'}, name+': fresh namespaces')
        require(pair[0]['pid'] != pair[1]['pid'] and pair[0]['execution_nonce'] != pair[1]['execution_nonce']
                and pair[0]['artifact_digest'] == pair[1]['artifact_digest'], name+': actual fresh identity')
    require(len(result['cases']) == len(expected_sources), name+': case count')
    for index, case in enumerate(result['cases'], 1):
        require(case['process_identities'] == result['initial_process_identities'], name+': continuous process identities')
        require(case['actual_next_slot'] == 0x200 + 32 * index, name+': actual next slot')
        receipt = case['receipt']
        require(receipt['events'] == first['events'][receipt['event_start']:receipt['event_end']], name+': full case slice')
        require(document(prefix+f'case-{index}.json.gz') == case, name+': standalone case pin')
        for component, identity in case['process_identities'].items():
            actual = next(row for row in processes if row['component']==component and row['runner_namespace']=='runner-0')
            require(identity == {key:value for key,value in actual.items() if key not in ('terminal_returncode','component')}, name+': original identity join')
    faults = result['controlled_response_records']
    if name == 'positive':
        require(not faults, 'positive must have no perturbation')
    else:
        require(len(faults) == 2 and faults[0] == faults[1], 'one same-policy first/fresh fault')
        fault = faults[0]
        require(fault['address'] == 0x4000000c and fault['actual_target_response'][1] == fault['delivered_response'][1] == 0
                and fault['actual_target_response'][0] ^ fault['delivered_response'][0] == 1, 'actual target-to-delivery XOR1')
        deliveries = [row for row in first['events'] if row.get('kind')=='mmio_delivery'
                      and row.get('source_transaction')==fault['transaction']]
        require(len(deliveries)==1 and deliveries[0]['read_value']==fault['actual_target_response'][0], 'raw original target retained')
        responses = [row for row in first['events'] if row.get('component')=='cpu'
            and row.get('outputs',{}).get('data_rsp_consumed')==1
            and row['outputs'].get('data_rsp_source_sequence')==fault['transaction']['source_sequence']
            and row['outputs'].get('data_rsp_source_epoch')==fault['transaction']['source_epoch']]
        require(len(responses)==1 and responses[0]['outputs']['data_rsp_rdata']==fault['delivered_response'][0], 'actual altered CPU response consumed')
    all_processes.extend(processes)
    runs[name] = dict(events=len(first['events']), cases=len(result['cases']), local_ticks=first['local_ticks'],
        entire_first_fresh_document_equal=True, semantic_sha256=semantic, processes=processes,
        controlled_response_records=faults)
require(len({row['pid'] for row in all_processes}) == 8 and len({row['execution_nonce'] for row in all_processes}) == 8, 'eight distinct actual model identities')
for component in ('cpu','gpio0'):
    require(len({row['artifact_digest'] for row in all_processes if row['component']==component}) == 1, 'positive controlled artifact identity')
summary = dict(status='independent_saved_evidence_audit_passed', archive_files=len(raw),
    gate_pid=document(control+'native-directed-gate.terminal.json')['pid'], gate_returncode=0,
    terminal_receipts=terminal_rows, layout=layout_before, tools_before_after_equal=True,
    runs=runs, all_eight_model_receipts_terminal0=True, formal_p6_complete=False,
    no_new_models_tests_or_project_imports=True)
(BASE/'independent-summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
print(json.dumps(dict(status=summary['status'], gate_pid=summary['gate_pid'],
    positive_events=runs['positive']['events'],controlled_events=runs['controlled-response']['events'])))
