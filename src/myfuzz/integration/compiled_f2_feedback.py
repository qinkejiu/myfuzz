"""Pure F2 observation projection. Serialized facts grant no native authority."""
from copy import deepcopy
from hashlib import sha256

from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.compiled_assertion_results import validate_assertion_results

_NAMES = ('protocol_receipt', 'declared_edges', 'instruction_fetches',
          'mmio_read_request', 'mmio_read_return', 'dependent_ram_store')
_PROTOCOL = 'protocol_checker.receipt_violations'
_EDGES = 'cross_component.declared_edge_hops'


def f2_observation_targets(path):
    if path.get('flow_id') != 'F2' or path.get('status') != 'executable':
        raise ValueError('compiled-F2-feedback-path-required')
    component = path['execution_contract']['source_component']
    return tuple(CoverageTarget(f'compiled_f2.{path["path_id"]}.{name}',
        component, 'compiled_F2_case_facts', 1 << bit, 1 << bit)
        for bit, name in enumerate(_NAMES))


def _require(condition, detail):
    if not condition:
        raise ValueError('compiled-F2-feedback-' + detail)


def _unique(rows, key):
    result = {}
    for row in rows:
        identity = key(row)
        _require(identity not in result, 'duplicate-case')
        result[identity] = row
    return result


def f2_observation_hits(*, runtime, candidates, certificates):
    """Join typed results, independent live inventory and same-call certificates.

    An incomplete submitted test returns no hits, retaining detached diagnostics.
    The caller authenticates the runtime; this function issues no live tokens.
    """
    targets = f2_observation_targets(runtime.path)
    cases = deepcopy(runtime.assertion_case_evidence())
    document = deepcopy(runtime.assertion_results())
    binding = runtime.execution_binding.document()
    path = binding['runtime_path_admission']['selected_path']
    validate_assertion_results(document,
        compiled_document_sha256=runtime.compiled_digest,
        binding_sha256=runtime.execution_binding.digest, path=path,
        run_id=runtime.run_id, cases=cases)
    inventory = _unique(cases, lambda c:c['case_id'])
    submitted = _unique(candidates, lambda c:c.case.case_id)
    supplied = _unique(certificates, lambda c:c.get('case_id'))
    _require(set(supplied).issubset(submitted), 'unsubmitted-certificate')
    _require(set(submitted).issubset(inventory), 'missing-case')
    diagnostics = dict(cases=deepcopy([inventory[cid] for cid in submitted]),
        submitted_case_ids=list(submitted), complete=False)
    if not submitted or set(supplied) != set(submitted):
        return frozenset(), diagnostics
    records = _unique(runtime.records, lambda r:r['certificate']['case_id'])
    attempts = _unique(runtime.attempts, lambda a:a['case_id'])
    hits = set()
    for cid, candidate in submitted.items():
        case = inventory[cid]; certificate = supplied[cid]
        _require(cid in records and certificate == records[cid]['certificate'], 'certificate-not-observed')
        _require(certificate.get('schema_version') == 'compiled_F2_chain.v1'
            and certificate.get('status') == 'certified'
            and certificate.get('path_id') == runtime.path['path_id']
            and certificate.get('source_id') == runtime.path['execution_contract']['load_source_id']
            and certificate.get('execution_binding_sha256') == runtime.execution_binding.digest,
            'certificate-identity')
        _require(records[cid]['raw'] == candidate.candidate_bytes.hex(), 'candidate-identity')
        _require(certificate.get('instruction_sha256') == sha256(bytes.fromhex(candidate.declaration['code_hex'])).hexdigest(), 'instruction-code')
        observations = case['observations']
        if any(observations.get(eid, {}).get('status') != 'passed' for eid in (_PROTOCOL, _EDGES)):
            return frozenset(), diagnostics
        actual = {eid:[case['evidence_inventory'][ref]['details']
            for ref in observations[eid]['evidence_refs']] for eid in (_PROTOCOL, _EDGES)}
        assertions = _unique(certificate.get('assertions', []), lambda a:a['expectation_id'])
        _require(set(assertions) == {_PROTOCOL, _EDGES}, 'certificate-assertions')
        for eid in (_PROTOCOL, _EDGES):
            _require(assertions[eid].get('status') == 'passed'
                and assertions[eid]['evidence'] in actual[eid], 'assertion-observation')
        receipt = attempts.get(cid, {}).get('receipt')
        if receipt != dict(status='running', violations=[]):
            return frozenset(), diagnostics
        _require(all(details.get('violations') == [] for details in actual[_PROTOCOL]), 'receipt-violations')
        exact = certificate.get('exact_hops', {})
        _require(all(key in exact for key in ('edges','instruction_hops','data_hops','ram_write_hop')), 'exact-hops-missing')
        edges = exact['edges']
        _require(len(edges) == len(runtime.declared_edges) == 3, 'edge-count')
        for edge, declared in zip(edges, runtime.declared_edges):
            _require({k:v for k,v in edge.items() if k not in ('status','hops')} == declared
                and edge.get('status') == 'certified' and bool(edge.get('hops')), 'edge-identity')
        _require([e['relation'] for e in edges] == ['persistent_state','mmio_route','mmio_route']
            and [e['role'] for e in edges] == ['read_request','read_request','read_return'], 'edge-order')
        functional = exact['instruction_hops']; data = exact['data_hops']
        _require(bool(functional) and edges[0]['hops'] == functional and len(data) == 1, 'functional-hops')
        hop = data[0]; proof = assertions[_EDGES]['evidence']
        _require(proof['edge_ids'] == [[e['rule_index'],e['prerequisite_index']] for e in edges]
            and proof['roles'] == [e['role'] for e in edges]
            and proof['endpoints'] == [[e['source_component'],e['target_component']] for e in edges]
            and proof['transaction'] == hop['source_transaction']
            and proof['instruction_source_id'] == certificate['instruction_source_id']
            and proof['native_read_APB_event'] == hop['native_APB_event']
            and proof['native_read_OBI_events'] == [hop['native_acceptance_event'],hop['native_response_event']], 'transaction-join')
        _require(edges[1]['hops'] == [dict(hop, role='read_request',consumer_event=hop['native_APB_event'])]
            and edges[2]['hops'] == [dict(hop,role='read_return',producer_event=hop['native_APB_event'],consumer_event=hop['native_response_event'])], 'edge-hops')
        ram = exact['ram_write_hop']
        _require(ram['memory_write_event'] == proof['dependent_RAM_write_event']
            and ram['address'] == candidate.declaration['result_address']
            and ram['value'] == (hop['native_obi']['rdata'] ^ candidate.declaration['xor_constant'])
            and ram['width_bytes'] == 4 and ram['byte_enable'] == 15
            and len(ram['version']) == 2 and bool(ram['transaction'])
            and ram['producer_event_id'] == ram['native_acceptance_event']
            and hop['native_response_event'] < ram['native_acceptance_event'] < ram['memory_write_event'] < ram['native_response_event'], 'dependent-store')
        hits.update(t.target_id for t in targets)
    diagnostics['complete'] = True
    return frozenset(hits), diagnostics
