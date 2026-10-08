"""Online decisions bind an executable path before selecting its source."""

import hashlib
import json

from myfuzz.scenario.dependency import DependencyRule
from myfuzz.scenario.online_case_decoder import (
    OnlineCaseDecoder, OnlineDependencyGraph, OnlineDependencySource, OnlineSource,
)
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runtime_path_contract import RuntimePathContract


def decoder(*, shared=False):
    targets = ('shared.target', 'shared.target') if shared else ('left.target', 'right.target')
    graph = OnlineDependencyGraph(
        sources=(
            OnlineDependencySource('left', 'source', 'ip', ('IP_TO_CPU',), 'left'),
            OnlineDependencySource('right', 'source', 'ip', ('IP_TO_CPU',), 'right'),
        ),
        rules=((DependencyRule('shared.target', ('left', 'right'), 'DATA_BINDING'),)
               if shared else
               (DependencyRule('left.target', ('left',), 'DATA_BINDING'),
                DependencyRule('right.target', ('right',), 'DATA_BINDING'))),
    )
    ownership = compile_ownership(
        (InputField('ip', 'left', 1), InputField('ip', 'right', 1)),
        (InputOwner('ip', 'left', 0, 1, 'source', 'external'),
         InputOwner('ip', 'right', 0, 1, 'source', 'external')),
    )
    return OnlineCaseDecoder(
        sources=(
            OnlineSource('left', 'source', 'ip', 'IP_TO_CPU', targets[0], port='left'),
            OnlineSource('right', 'source', 'ip', 'IP_TO_CPU', targets[1], port='right'),
        ),
        ownership=ownership, graph=graph, schedule=('ip',),
        instruction_start=0, instruction_end=4,
    )


def test_selected_path_excludes_direct_byte_source_on_other_path():
    subject = decoder()
    case = subject.decode(bytes((0, 0, 1, 7, 0, 0, 0, 0)))
    assert case.path_id == 'left.target'
    assert case.source.port == 'left'


def test_feedback_changes_selected_path_before_source():
    subject = decoder()
    # This raw maps to selector 1 for equal weights and for left=3/right=1.
    raw = bytes((0, 1, 1, 1, 0, 0, 0, 0))
    first = subject.decode(raw)
    next_case = subject.decode(raw, coverage_hints={'left': 3})
    assert first.path_id == 'right.target'
    assert first.source.port == 'right'
    assert next_case.path_id == 'left.target'
    assert next_case.source.port == 'left'


def test_path_selection_uses_payload_when_transport_path_byte_is_fixed():
    subject = decoder()
    selected = {subject.decode(bytes((0, 1, 99, value, 3, 5, 7, 11))).path_id
                for value in range(32)}
    assert selected == {'left.target', 'right.target'}


def test_path_selection_uses_entropy_beyond_one_byte_for_large_weights():
    subject = decoder()
    # The rotated selector is 65536; 65536 % 400 = 336, selecting right.
    case = subject.decode(bytes((0, 0, 0, 1, 0, 0, 0, 0)),
                          coverage_hints={'left': 200, 'right': 200})
    assert case.path_id == 'right.target'
    assert case.source.port == 'right'


def test_single_path_still_honors_direct_source_byte():
    subject = decoder(shared=True)
    case = subject.decode(bytes((0, 0, 1, 7, 0, 0, 0, 0)))
    assert case.path_id == 'shared.target'
    assert case.source.port == 'right'


def runtime_decoder(*, flow_by_target=None):
    subject = decoder(shared=True)
    graph = OnlineDependencyGraph(
        sources=tuple(subject.graph.sources.values()),
        rules=(DependencyRule('shared.target', ('left',), 'DATA_BINDING'),
               DependencyRule('shared.target', ('right',), 'DATA_BINDING')),
    )
    digest = hashlib.sha256(json.dumps(graph.edge_document(), sort_keys=True,
        separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
    return OnlineCaseDecoder(
        sources=subject.sources, ownership=subject.ownership, graph=graph,
        schedule=('ip',), instruction_start=0, instruction_end=4,
        runtime_contract=RuntimePathContract(digest, (), ()),
        flow_by_target=flow_by_target,
    )


def test_runtime_or_path_restricts_source_before_direct_byte_selection():
    subject = runtime_decoder()
    first = subject.decode(bytes((0, 0, 1, 7, 0, 0, 0, 0)))
    second = subject.decode(bytes((0, 1, 0, 7, 0, 0, 0, 0)))
    assert first.path_id != second.path_id
    assert first.source.port == 'left'
    assert second.source.port == 'right'


def test_declared_flow_metadata_roundtrips_with_stable_runtime_path_identity():
    subject = runtime_decoder(flow_by_target={'shared.target': 'F5'})
    case = subject.decode(bytes((0, 1, 0, 7, 0, 0, 0, 0)))
    metadata = subject.decision_metadata(case)
    assert subject.document()['schema_version'] == 'online_case_decoder.v3'
    assert {key: metadata[key] for key in (
        'case_id', 'direction', 'flow_id', 'path_id', 'target_id', 'source_id')
    } == {
        'case_id': case.case_id, 'direction': 'IP_TO_CPU',
        'flow_id': 'F5', 'path_id': case.path_id,
        'target_id': 'shared.target', 'source_id': 'right',
    }
    assert metadata['operator_id'] == 'external_event'
    assert metadata['candidate_id'].startswith('online-candidate.v1:')
    restored = OnlineCaseDecoder.from_document(subject.document())
    replayed = restored.decode(bytes((0, 1, 0, 7, 0, 0, 0, 0)))
    assert restored.decision_metadata(replayed) == metadata


def test_flow_declaration_rejects_missing_or_unsupported_category():
    for declaration in ({}, {'shared.target': 'F7'}):
        try:
            runtime_decoder(flow_by_target=declaration)
        except ValueError:
            pass
        else:
            raise AssertionError('invalid flow declaration accepted')


def test_flow_declaration_requires_runtime_edge_identity():
    subject = decoder(shared=True)
    try:
        OnlineCaseDecoder(
            sources=subject.sources, ownership=subject.ownership,
            graph=subject.graph, schedule=('ip',),
            instruction_start=0, instruction_end=4,
            flow_by_target={'shared.target': 'F5'},
        )
    except ValueError:
        pass
    else:
        raise AssertionError('flow declaration accepted without stable runtime path')


def test_old_manifest_has_no_inferred_flow_category():
    subject = runtime_decoder()
    case = subject.decode(bytes((0, 0, 0, 7, 0, 0, 0, 0)))
    assert subject.document()['schema_version'] == 'online_case_decoder.v2'
    assert subject.decision_metadata(case)['flow_id'] is None
    assert OnlineCaseDecoder.from_document(subject.document()).document() == subject.document()
