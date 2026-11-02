"""Detached software declaration checks; no Runner or native operations."""
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
from unittest.mock import patch

import pytest

from myfuzz.scenario.compiled_paths import load_path_wiring
from myfuzz.scenario.dependency import DependencyGraph, DependencyRule
from myfuzz.scenario.dma_route_intent import DmaMasterRouteIntent, dma_master_route_intents_document
from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract, RuntimePathContract, RuntimeNode
from tests.scenario import test_runtime_path_contract as existing_routes
from myfuzz.scenario.dma_intent_topology_binding import (
    DmaIntentBindingError, PreparedDmaIntentBinding, prepare_dma_intent_binding,
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


BINDING = dict(profile_endpoint_sha256='1' * 64, template_id='master.wishbone-pipelined',
               template_version='1', variant_id='dma-full-word-no-select',
               contract_sha256='2' * 64, selection_sha256='3' * 64)


def fixture(*, identical=False, values=(2,)):
    graph, _, contract, path, _, _ = existing_routes.DmaMasterRouteContractTests().fixture()
    routes = list(contract.dma_master_routes)
    routes[0] = replace(routes[0], accepted_write_values=values)
    if identical:
        # Two reads with identical policy remain distinct graph edges.
        graph = DependencyGraph(sources=tuple(graph.sources.values()), rules=(
            DependencyRule('uart.read_result', ('uart.payload',), 'EVENT_ORDER'),
            DependencyRule('dma.receive', ('uart.read_result',), 'DMA_MASTER_TRANSFER'),
            DependencyRule('uart.second', ('dma.receive',), 'EVENT_ORDER'),
            DependencyRule('dma.second', ('uart.second',), 'DMA_MASTER_TRANSFER')))
        nodes = tuple(node for node in contract.nodes if node.node_id not in
                      ('dma.write_payload', 'ram.target_effect')) + (
            RuntimeNode('uart.second', 'uart', 'logical'),
            RuntimeNode('dma.second', 'dma', 'logical'))
        routes[1] = replace(routes[0], rule_index=3, source_node_id='uart.second', target_node_id='dma.second')
        contract = RuntimePathContract(digest(graph.edge_document()), nodes, contract.edges, tuple(routes))
        path = graph.edge_paths_to('dma.second', direction='CPU_TO_IP')[0]
    else:
        contract = replace(contract, dma_master_routes=tuple(routes))
    prepared = PreparedRuntimePathContract(graph, contract, (('CPU_TO_IP', path),))
    intents, bindings, links = [], [], []
    for index, route in enumerate(routes):
        target = dict(kind=route.target_kind, component_instance=route.target_component)
        target.update(dict(device_id=route.target_id, endpoint_id='target.bus') if
                      route.target_kind == 'peripheral' else dict(resource_id=route.target_id))
        intent = DmaMasterRouteIntent(route_id=f'route.{index}', initiator_instance='dma',
            initiator_endpoint_id='dma.master', target=target, base=route.base, size=route.size,
            operation=route.operation, permissions=route.permissions, byte_enable=15,
            readable_offsets=route.readable_offsets, writable_offsets=route.writable_offsets,
            accepted_write_values=route.accepted_write_values)
        intents.append(intent)
        bindings.append(dict(route_id=intent.route_id, initiator=dict(BINDING), target=(
            dict(BINDING) if route.target_kind == 'peripheral' else dict(kind='persistent_memory',
                owner_profile_fingerprint='sha256:' + '4' * 64, resource_sha256='5' * 64))))
        links.append(dict(route_id=intent.route_id, rule_index=route.rule_index,
            prerequisite_index=0, runtime_route_sha256=route.identity_sha256,
            endpoint_link=dict(mode='exact_id', static_endpoint_id='dma.master',
                runtime_endpoint_id='dma.master', artifact_endpoint_id='dma.master',
                artifact_link_id='physical-master', artifact_link_provider_id='wishbone-dma-single-master.v1',
                operation=route.operation, template_binding=dict(BINDING))))
    wrapped = dma_master_route_intents_document(intents)
    document = dict(schema_version='path_wiring.v2', cpu=dict(instance_id='cpu'),
        windows=[dict(device_id='uart', target_instance='uart', endpoint_id='target.bus', base=0x50000000, size=0x1000)],
        resources=[dict(resource_id='ram', component_instance='cpu', base=0x1000, size=0x1000, read=True, write=True)],
        dma_master_routes=wrapped, dma_master_routes_sha256=digest(wrapped), dma_master_route_bindings=bindings)
    return load_path_wiring(document), prepared, links


def rebuild(wiring, change):
    document = deepcopy(wiring.document)
    change(document)
    document['dma_master_routes_sha256'] = digest(document['dma_master_routes'])
    return load_path_wiring(document)


def refuse(wiring, prepared, links, code, pointer=None):
    with pytest.raises(DmaIntentBindingError) as caught:
        prepare_dma_intent_binding(wiring, prepared, route_links=links)
    assert caught.value.code == code
    assert caught.value.pointer.startswith('/')
    if pointer is not None:
        assert caught.value.pointer == pointer


def test_exact_id_route_links_preserve_existing_prepared_bytes():
    wiring, prepared, links = fixture()
    before = canonical(prepared.document()), canonical(prepared.contract.document()), canonical(wiring.document)
    with patch.object(PreparedRuntimePathContract, 'bind', side_effect=AssertionError('bind called')), patch.object(
            PreparedRuntimePathContract, 'from_document', side_effect=AssertionError('graph restored')):
        declaration = prepare_dma_intent_binding(wiring, prepared, route_links=list(reversed(links)))
    doc = declaration.document()
    assert doc['schema_version'] == 'dma_intent_binding_declaration.v1'
    assert canonical(doc['prepared_runtime_paths']) == before[0]
    assert canonical(doc['wiring']) == before[2]
    assert canonical(prepared.document()) == before[0]
    assert canonical(prepared.contract.document()) == before[1]
    assert canonical(wiring.document) == before[2]
    assert doc['route_links'] == links
    assert declaration.identity_sha256 == digest({k: v for k, v in doc.items() if k != 'identity_sha256'})
    assert PreparedDmaIntentBinding.from_document(doc).document() == doc
    links[0]['endpoint_link']['template_binding']['template_id'] = 'mutated'
    doc['route_links'].clear()
    assert len(declaration.document()['route_links']) == 2
    with pytest.raises(FrozenInstanceError):
        declaration.identity_sha256 = '0' * 64


def test_identical_policies_require_explicit_edge_keys():
    wiring, prepared, links = fixture(identical=True)
    assert prepare_dma_intent_binding(wiring, prepared, route_links=links)
    links[1]['rule_index'] = links[0]['rule_index']
    refuse(wiring, prepared, links, 'dma-binding-route-set-mismatch')


@pytest.mark.parametrize('variant', ['duplicate', 'missing', 'extra'],
                         ids=['schema-duplicate', 'schema-missing', 'schema-extra'])
def test_duplicate_missing_or_extra_routes_refuse(variant):
    wiring, prepared, links = fixture()
    if variant == 'duplicate':
        links[1] = deepcopy(links[0])
    elif variant == 'missing':
        links.pop()
    else:
        links.append({**links[0], 'route_id': 'extra'})
    refuse(wiring, prepared, links, 'dma-binding-route-set-mismatch')


@pytest.mark.parametrize('values,other', [((2, 1, 2), (2, 2, 1)), ((0, 2, 4), range(0, 5, 2)),
    (range(0, 5, 2), range(0, 6, 2)), (range(2, 3, 1), range(2, 3, 2))])
def test_policy_exact_tuple_and_range_identity(values, other):
    wiring, prepared, links = fixture(values=values)
    assert prepare_dma_intent_binding(wiring, prepared, route_links=links)
    policy = (dict(kind='range', start=other.start, stop=other.stop, step=other.step)
              if isinstance(other, range) else dict(kind='values', values=list(other)))
    wiring = rebuild(wiring, lambda d: d['dma_master_routes']['routes'][0].update(accepted_write_values=policy))
    refuse(wiring, prepared, links, 'dma-binding-policy-mismatch', '/wiring/dma_master_routes/routes/0/accepted_write_values')


@pytest.mark.parametrize('field,value', [('base', 0x50001000), ('size', 0x800),
    ('readable_offsets', [0x10]), ('writable_offsets', [0x14])])
def test_policy_fields_require_exact_values(field, value):
    wiring, prepared, links = fixture()
    wiring = rebuild(wiring, lambda d: d['dma_master_routes']['routes'][0].update({field: value}))
    refuse(wiring, prepared, links, 'dma-binding-policy-mismatch', f'/wiring/dma_master_routes/routes/0/{field}')


@pytest.mark.parametrize('location', ['row', 'endpoint', 'template'])
def test_schema_closed_route_and_endpoint_fields(location):
    wiring, prepared, links = fixture()
    row = links[0]
    if location != 'row':
        row = row['endpoint_link']
    if location == 'template':
        row = row['template_binding']
    row['unknown'] = True
    refuse(wiring, prepared, links, 'dma-binding-endpoint-link-mismatch')


@pytest.mark.parametrize('field,value,code', [('rule_index', True, 'dma-binding-edge-mismatch'),
    ('rule_index', 0, 'dma-binding-edge-mismatch'),
    ('runtime_route_sha256', '0' * 64, 'dma-binding-edge-mismatch')])
def test_edge_schema_and_digest_reject(field, value, code):
    wiring, prepared, links = fixture()
    links[0][field] = value
    refuse(wiring, prepared, links, code)


def test_declaration_schema_digest_and_embedded_readers():
    wiring, prepared, links = fixture()
    doc = prepare_dma_intent_binding(wiring, prepared, route_links=links).document()
    for change in (lambda d: d.update(unknown=1), lambda d: d.update(identity_sha256='0' * 64),
                   lambda d: d['wiring'].update(unknown=1),
                   lambda d: d['prepared_runtime_paths']['contract'].update(unknown=1),
                   lambda d: d['route_links'].reverse()):
        broken = deepcopy(doc)
        change(broken)
        with pytest.raises(DmaIntentBindingError):
            PreparedDmaIntentBinding.from_document(broken)


def test_exact_id_and_explicit_alias_schema():
    wiring, prepared, links = fixture()
    links[0]['endpoint_link']['artifact_endpoint_id'] = 'another'
    refuse(wiring, prepared, links, 'dma-binding-endpoint-link-mismatch')
    links[0]['endpoint_link'].update(mode='explicit_alias', static_endpoint_id='physical', artifact_endpoint_id='physical')
    wiring = rebuild(wiring, lambda d: d['dma_master_routes']['routes'][0].update(initiator_endpoint_id='physical'))
    assert prepare_dma_intent_binding(wiring, prepared, route_links=links)
    links[0]['endpoint_link']['operation'] = 'write'
    refuse(wiring, prepared, links, 'dma-binding-endpoint-link-mismatch')


def test_policy_target_owner_resource_and_device_restrictions():
    wiring, prepared, links = fixture()
    for index, change in [(0, dict(device_id='independent')), (1, dict(component_instance='other')),
                          (1, dict(resource_id='other'))]:
        changed = rebuild(wiring, lambda d: d['dma_master_routes']['routes'][index]['target'].update(change))
        refuse(changed, prepared, links, 'dma-binding-target-unsupported')


def test_schema_template_and_provider_checks():
    wiring, prepared, links = fixture()
    links[0]['endpoint_link']['template_binding']['selection_sha256'] = '6' * 64
    refuse(wiring, prepared, links, 'dma-binding-template-mismatch')
    links[0]['endpoint_link']['template_binding'] = dict(BINDING)
    links[0]['endpoint_link']['artifact_link_provider_id'] = 'unknown'
    refuse(wiring, prepared, links, 'dma-binding-provider-unsupported')


@pytest.mark.parametrize('field', sorted(['route_id', 'rule_index', 'prerequisite_index',
    'runtime_route_sha256', 'endpoint_link']))
def test_schema_requires_every_link_field(field):
    wiring, prepared, links = fixture()
    del links[0][field]
    refuse(wiring, prepared, links, 'dma-binding-endpoint-link-mismatch')


@pytest.mark.parametrize('field', sorted(['mode', 'static_endpoint_id', 'runtime_endpoint_id',
    'artifact_endpoint_id', 'artifact_link_id', 'artifact_link_provider_id', 'operation', 'template_binding']))
def test_schema_requires_every_endpoint_field(field):
    wiring, prepared, links = fixture()
    del links[0]['endpoint_link'][field]
    refuse(wiring, prepared, links, 'dma-binding-endpoint-link-mismatch')


def test_policy_requires_full_exact_memory_resource_and_window():
    wiring, prepared, links = fixture()
    for section, changes in [('resources', {'size': 0x2000}),
                             ('resources', {'write': False}),
                             ('resources', {'component_instance': 'another'}),
                             ('windows', {'size': 0x2000}),
                             ('windows', {'endpoint_id': 'another'})]:
        changed = rebuild(wiring, lambda d: d[section][0].update(changes))
        refuse(changed, prepared, links, 'dma-binding-target-unsupported')


def f6_write_only_ram_route_fixture():
    """Represent F6's write-only route over its shared read/write RAM."""
    wiring, prepared, links = fixture()
    routes = list(prepared.contract.dma_master_routes)
    index = next(i for i, route in enumerate(routes)
                 if route.target_kind == 'persistent_memory')
    routes[index] = replace(routes[index], permissions=('write',))
    contract = replace(prepared.contract, dma_master_routes=tuple(routes))
    prepared = PreparedRuntimePathContract(prepared.graph, contract,
        prepared.runtime_paths)
    document = deepcopy(wiring.document)
    document['dma_master_routes']['routes'][index]['permissions'] = ['write']
    document['dma_master_routes_sha256'] = digest(document['dma_master_routes'])
    wiring = load_path_wiring(document)
    route_key = routes[index].key
    link = next(row for row in links
                if (row['rule_index'], row['prerequisite_index']) == route_key)
    link['runtime_route_sha256'] = routes[index].identity_sha256
    return wiring, prepared, links


def test_operation_scoped_ram_write_route_is_subset_of_shared_rw_resource():
    wiring, prepared, links = f6_write_only_ram_route_fixture()
    declaration = prepare_dma_intent_binding(wiring, prepared, route_links=links)
    assert declaration.document()['wiring']['resources'][0]['read'] is True
    assert declaration.document()['wiring']['resources'][0]['write'] is True
    assert next(route for route in prepared.contract.dma_master_routes
        if route.target_kind == 'persistent_memory').permissions == ('write',)


@pytest.mark.parametrize('change', ['remove_write', 'extra_read_permission', 'unknown_read_permission'])
def test_operation_scoped_ram_write_route_refuses_disabled_or_unselected_permission(change):
    wiring, prepared, links = f6_write_only_ram_route_fixture()
    if change == 'remove_write':
        wiring = rebuild(wiring, lambda d: d['resources'][0].update(write=False))
    elif change == 'unknown_read_permission':
        wiring = rebuild(wiring, lambda d: d['resources'][0].update(read=None))
    else:
        routes = list(prepared.contract.dma_master_routes)
        index = next(i for i, route in enumerate(routes)
                     if route.target_kind == 'persistent_memory')
        routes[index] = replace(routes[index], permissions=('read', 'write'))
        prepared = PreparedRuntimePathContract(prepared.graph,
            replace(prepared.contract, dma_master_routes=tuple(routes)),
            prepared.runtime_paths)
        document = deepcopy(wiring.document)
        document['dma_master_routes']['routes'][index]['permissions'] = ['read', 'write']
        document['dma_master_routes_sha256'] = digest(document['dma_master_routes'])
        document['resources'][0]['read'] = False
        wiring = load_path_wiring(document)
        route_key = routes[index].key
        link = next(row for row in links if
            (row['rule_index'], row['prerequisite_index']) == route_key)
        link['runtime_route_sha256'] = routes[index].identity_sha256
    refuse(wiring, prepared, links, 'dma-binding-target-unsupported')


def test_route_contract_rejects_operation_missing_from_its_permission_tuple():
    wiring, prepared, links = f6_write_only_ram_route_fixture()
    route = next(route for route in prepared.contract.dma_master_routes
                 if route.target_kind == 'persistent_memory')
    with pytest.raises(ValueError):
        replace(route, permissions=('read',))


def test_operation_scoped_ram_route_still_requires_exact_static_live_permission_tuple():
    wiring, prepared, links = f6_write_only_ram_route_fixture()
    routes = list(prepared.contract.dma_master_routes)
    index = next(i for i, route in enumerate(routes)
                 if route.target_kind == 'persistent_memory')
    routes[index] = replace(routes[index], permissions=('read', 'write'))
    changed = PreparedRuntimePathContract(prepared.graph,
        replace(prepared.contract, dma_master_routes=tuple(routes)),
        prepared.runtime_paths)
    link = next(row for row in links if row['rule_index'] == routes[index].rule_index)
    link['runtime_route_sha256'] = routes[index].identity_sha256
    refuse(wiring, changed, links, 'dma-binding-policy-mismatch',
        '/wiring/dma_master_routes/routes/1/permissions')


def test_declaration_rejects_changed_retained_wiring_and_constructor_bytes():
    wiring, prepared, links = fixture()
    declaration = prepare_dma_intent_binding(wiring, prepared, route_links=links)
    assert PreparedDmaIntentBinding(canonical(declaration.document())).document() == declaration.document()
    with pytest.raises(DmaIntentBindingError):
        PreparedDmaIntentBinding(canonical(declaration.document()) + b'\n')
    wiring.document['dma_master_routes']['routes'][0]['base'] += 4096
    refuse(wiring, prepared, links, 'dma-binding-replay-material-invalid')


def test_schema_missing_endpoint_link_has_named_refusal():
    wiring, prepared, links = fixture()
    links[0]['endpoint_link'] = None
    refuse(wiring, prepared, links, 'dma-binding-endpoint-link-required', '/route_links/0/endpoint_link')


@pytest.mark.parametrize('location', ['route_links', 'row', 'endpoint_link', 'template_binding'])
def test_declaration_schema_rejects_non_json_container_types(location):
    from types import MappingProxyType

    wiring, prepared, links = fixture()
    document = prepare_dma_intent_binding(wiring, prepared, route_links=links).document()
    if location == 'route_links':
        document['route_links'] = tuple(document['route_links'])
    elif location == 'row':
        document['route_links'][0] = MappingProxyType(document['route_links'][0])
    elif location == 'endpoint_link':
        row = document['route_links'][0]
        row['endpoint_link'] = MappingProxyType(row['endpoint_link'])
    else:
        endpoint = document['route_links'][0]['endpoint_link']
        endpoint['template_binding'] = MappingProxyType(endpoint['template_binding'])
    # Canonical normalization produces the original bytes and digest for each
    # malformed container. The reader must inspect the original input types.
    with pytest.raises(DmaIntentBindingError):
        PreparedDmaIntentBinding.from_document(document)


def test_declaration_direct_prepare_retains_tuple_route_links_convenience():
    wiring, prepared, links = fixture()
    declaration = prepare_dma_intent_binding(wiring, prepared, route_links=tuple(links))
    assert type(declaration.document()['route_links']) is list
    assert PreparedDmaIntentBinding.from_document(declaration.document()).document() == declaration.document()


def test_in_memory_prepared_object_must_match_embedded_authenticated_document():
    wiring, prepared, links = fixture()
    declaration = prepare_dma_intent_binding(wiring, prepared, route_links=links)
    retained = PreparedDmaIntentBinding.from_document(
        declaration.document(), prepared_runtime_paths=prepared)
    assert retained._prepared_runtime_paths is prepared

    _, different_prepared, _ = fixture(values=(3,))
    with pytest.raises(DmaIntentBindingError) as caught:
        PreparedDmaIntentBinding.from_document(
            declaration.document(), prepared_runtime_paths=different_prepared)
    assert caught.value.code == 'dma-binding-replay-material-invalid'
    assert caught.value.pointer == '/prepared_runtime_paths'


def test_schema_endpoint_refusal_pointer_uses_fixed_field_order():
    wiring, prepared, links = fixture()
    endpoint = links[0]['endpoint_link']
    fields = ('mode', 'static_endpoint_id', 'runtime_endpoint_id',
              'artifact_endpoint_id', 'artifact_link_id', 'artifact_link_provider_id', 'operation')
    original = dict(endpoint)
    for offset, field in enumerate(fields):
        endpoint.update(original)
        endpoint.update({name: '' for name in fields[offset:]})
        refuse(wiring, prepared, links, 'dma-binding-endpoint-link-mismatch',
               f'/route_links/0/endpoint_link/{field}')

# Live fixtures render source text only. Any transport access is a test failure.
from functools import lru_cache


@lru_cache(maxsize=None)
def generated_instance(instance_id):
    from pathlib import Path
    from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
        render_local_harness, verify_local_source_lock)
    from myfuzz.local_harness.dma_artifact_endpoint_links import render_dma_linked_runtime, PROVIDER_ID
    root = Path(__file__).resolve().parents[2]
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path='configs/peripherals/zipcpu_wbdmac/component_profile.json', instance_id=instance_id,
        reset_assert_ticks=8, reset_release_ticks=8, max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=root)
    return render_dma_linked_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=root), base_dir=root, provider_id=PROVIDER_ID)


@pytest.fixture(scope='module')
def issued_artifact():
    return generated_instance('dma')


def live_fixture(issued, tmp_path, *, aliases=False):
    from types import SimpleNamespace
    from myfuzz.local_harness.wishbone_dma_session import (GeneratedWishboneDmaSession,
        dma_route_endpoint_identity_document)
    from myfuzz.local_harness.session import GeneratedLocalSession
    from myfuzz.scenario.runtime_path_contract import persistent_memory_route_identity_document
    from myfuzz.scenario.compiled_paths import _wiring_resource_document
    wiring, prepared, links = fixture()
    graph, runner, old, path, _, memory = existing_routes.DmaMasterRouteContractTests().fixture()
    dma = GeneratedWishboneDmaSession(issued.artifact, memory=memory,
        base_dir=tmp_path, cache_dir=tmp_path)
    owner = GeneratedLocalSession(generated_instance('cpu').artifact, base_dir=tmp_path, cache_dir=tmp_path)
    uart_owner = GeneratedLocalSession(generated_instance('uart').artifact, base_dir=tmp_path, cache_dir=tmp_path)
    owner.memory = uart_owner.memory = memory
    def refuse_transport(*args, **kwargs):
        raise AssertionError('transport command reached')
    dma.command = owner.command = uart_owner.command = refuse_transport
    runner.sessions.update(dma=dma, cpu=owner, uart=uart_owner)
    document = deepcopy(wiring.document)
    document['windows'] = []
    document['resources'].append(dict(resource_id='ram', component_instance='uart',
        base=0x1000, size=0x1000, read=True, write=True))
    binding = issued.endpoint_links_document()['links'][0]['template_binding']
    routes = []
    for index, route in enumerate(old.dma_master_routes):
        endpoint = ('opaque-input-17' if index == 0 else 'opaque-output-29') if aliases else 'dma.memory'
        if aliases == 'conventional':
            endpoint = 'read_master' if index == 0 else 'write_master'
        route = replace(route, endpoint_id=endpoint,
            endpoint_identity_sha256=digest(dma_route_endpoint_identity_document(dma)),
            target_kind='persistent_memory', target_id='ram', base=0x1000, size=0x1000,
            readable_offsets=(), writable_offsets=(), accepted_write_values=(),
            target_identity_sha256=digest(persistent_memory_route_identity_document(memory,
                memory_id='ram', base=0x1000, size=0x1000)))
        routes.append(route)
        intent = document['dma_master_routes']['routes'][index]
        intent.update(initiator_endpoint_id='dma.memory', target=dict(kind='persistent_memory',
            component_instance=route.target_component, resource_id='ram'), base=route.base, size=route.size,
            readable_offsets=[], writable_offsets=[], accepted_write_values=dict(kind='values', values=[]))
        links[index].update(runtime_route_sha256=route.identity_sha256)
        links[index]['endpoint_link'].update(mode='explicit_alias' if aliases else 'exact_id',
            static_endpoint_id='dma.memory', runtime_endpoint_id=endpoint, artifact_endpoint_id='dma.memory',
            artifact_link_id='mwb', template_binding=binding)
        document['dma_master_route_bindings'][index].update(initiator=binding,
            target=dict(kind='persistent_memory', owner_profile_fingerprint=runner.sessions[route.target_component].artifact.plan.profile.profile_fingerprint,
                resource_sha256='0' * 64))
    document['dma_master_routes_sha256'] = digest(document['dma_master_routes'])
    wiring = load_path_wiring(document)
    for index, route in enumerate(routes):
        resource, = [r for r in wiring.resources if r.component_instance == route.target_component]
        document['dma_master_route_bindings'][index]['target']['resource_sha256'] = digest(_wiring_resource_document(resource))
    wiring = load_path_wiring(document)
    prepared = PreparedRuntimePathContract(graph, replace(old, dma_master_routes=tuple(routes)), (('CPU_TO_IP', path),))
    declaration = prepare_dma_intent_binding(wiring, prepared, route_links=links)
    return declaration, runner, {'dma': issued.endpoint_links_document()}, prepared


def live_bind(*args, **kwargs):
    from myfuzz.scenario.dma_intent_topology_binding import bind_dma_intent_topology
    return bind_dma_intent_topology(*args, **kwargs)


def test_exact_id_live_binding_uses_actual_artifact(issued_artifact, tmp_path):
    declaration, runner, evidence, prepared = live_fixture(issued_artifact, tmp_path)
    real_bind = PreparedRuntimePathContract.bind
    expected = prepared.bind(deepcopy(runner)).document()
    with patch.object(PreparedRuntimePathContract, 'bind', autospec=True, wraps=PreparedRuntimePathContract.bind) as spy:
        # autospec wraps does not delegate bound methods, so explicitly retain
        # the real implementation while counting exactly one bind.
        spy.side_effect = lambda self, *a, **k: real_bind(self, *a, **k)
        bound = live_bind(declaration, runner, artifact_links=evidence)
        bound.validate_topology()
        assert spy.call_count == 1
    assert bound.runtime_compilation.document() == expected
    assert bound.document()['tier'] == 'topology_bound'
    assert bound.document()['declaration_sha256'] == declaration.identity_sha256
    assert bound.runtime_compilation.document()['contract_sha256'] == prepared.contract.identity_sha256
    assert bound.identity_sha256 == digest({k:v for k,v in bound.document().items() if k != 'identity_sha256'})


def test_explicit_alias_link_has_no_name_inference(issued_artifact, tmp_path):
    declaration, runner, evidence, _ = live_fixture(issued_artifact, tmp_path, aliases=True)
    bound = live_bind(declaration, runner, artifact_links=evidence)
    assert {r.endpoint_id for r in bound.runtime_compilation.dma_master_routes} == {'opaque-input-17', 'opaque-output-29'}
    bound.validate_topology()


@pytest.mark.parametrize('mutation', ['missing', 'provider', 'fake_session', 'read_master_without_link'])
def test_missing_artifact_link_or_provider_refuses(issued_artifact, tmp_path, mutation):
    declaration, runner, evidence, _ = live_fixture(issued_artifact, tmp_path,
        aliases='conventional' if mutation == 'read_master_without_link' else False)
    if mutation in ('missing', 'read_master_without_link'): evidence.clear()
    elif mutation == 'provider': evidence['dma']['provider_id'] = 'unknown'
    else:
        from types import SimpleNamespace
        runner.sessions['dma'] = SimpleNamespace(**runner.sessions['dma'].__dict__)
    with pytest.raises(DmaIntentBindingError):
        live_bind(declaration, runner, artifact_links=evidence)


@pytest.mark.parametrize('mutation', ['template', 'profile', 'selection', 'master', 'role', 'backend'])
def test_live_artifact_mismatch_refuses(issued_artifact, tmp_path, mutation):
    declaration, runner, evidence, _ = live_fixture(issued_artifact, tmp_path)
    link = evidence['dma']['links'][0]
    if mutation in ('template', 'profile', 'selection'):
        key = {'template':'contract_sha256', 'profile':'profile_endpoint_sha256', 'selection':'selection_sha256'}[mutation]
        link['template_binding'][key] = '0' * 64
    elif mutation == 'master': link['endpoint_id'] = 'another.master'
    elif mutation == 'role': link['roles'].pop()
    else: link['backend_channel'] = 'other'
    evidence['dma']['identity_sha256'] = digest({k:v for k,v in evidence['dma'].items() if k != 'identity_sha256'})
    with pytest.raises(DmaIntentBindingError):
        live_bind(declaration, runner, artifact_links=evidence)


@pytest.mark.parametrize('mutation', ['artifact', 'plan', 'session', 'service', 'ledger', 'memory_index', 'evidence', 'artifact_metadata'])
def test_bound_live_mutations_refuse(issued_artifact, tmp_path, mutation):
    from copy import copy
    declaration, runner, evidence, _ = live_fixture(issued_artifact, tmp_path)
    bound = live_bind(declaration, runner, artifact_links=evidence)
    dma = runner.sessions['dma']
    if mutation == 'artifact': dma.artifact = replace(dma.artifact)
    elif mutation == 'plan': dma.artifact = replace(dma.artifact, plan=replace(dma.artifact.plan))
    elif mutation == 'session': runner.sessions['dma'] = copy(dma)
    elif mutation == 'service': dma.memory_service = copy(dma.memory_service)
    elif mutation == 'ledger': dma.memory_service.ledger = copy(dma.memory_service.ledger)
    elif mutation == 'memory_index': dma.memory_service.memory._windows = list(dma.memory_service.memory._windows)
    elif mutation == 'evidence': evidence['dma'] = deepcopy(evidence['dma'])
    else:
        dma.artifact = deepcopy(dma.artifact)
        dma.artifact.runtime_document['kind'] = 'wrong'
    with pytest.raises((DmaIntentBindingError, ValueError)):
        bound.validate_topology()


@pytest.fixture(scope='module')
def uart_artifact():
    from pathlib import Path
    from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
        render_local_harness, render_local_runtime, render_local_driver, verify_local_source_lock)
    root = Path(__file__).resolve().parents[2]
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path='configs/peripherals/opentitan_uart_local/component_profile.json', instance_id='uart',
        reset_assert_ticks=8, reset_release_ticks=8, max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=root)
    return render_local_driver(render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=root), base_dir=root), base_dir=root)


def peripheral_fixture(issued, uart_artifact, tmp_path):
    from myfuzz.local_harness.opentitan_uart_session import GeneratedOpentitanUartSession
    from myfuzz.local_harness.wishbone_dma_session import MasterTargetWindow, dma_route_endpoint_identity_document
    from myfuzz.local_harness.template_contracts import select_template_contract
    declaration, runner, evidence, prepared = live_fixture(issued, tmp_path)
    uart = GeneratedOpentitanUartSession(uart_artifact, base_dir=tmp_path, cache_dir=tmp_path)
    runner.sessions['uart'] = uart
    size = uart_artifact.plan.profile.address.window_size
    window = MasterTargetWindow('uart', 0x50000000, size, uart, (0x1c,), (2,), readable_offsets=(0x18,))
    runner.sessions['dma'].master_targets = (window,)
    route = replace(prepared.contract.dma_master_routes[0], target_kind='peripheral', target_id='uart',
        base=window.base, size=size, readable_offsets=(0x18,), writable_offsets=(0x1c,),
        accepted_write_values=(2,), target_identity_sha256=digest(window.route_identity_document()))
    prepared = PreparedRuntimePathContract(prepared.graph, replace(prepared.contract,
        dma_master_routes=(route, prepared.contract.dma_master_routes[1])), prepared.runtime_paths)
    document = declaration.document()['wiring']
    document['resources'] = [r for r in document['resources'] if r['component_instance'] != 'uart']
    endpoint, = [e for e in uart_artifact.plan.binding.endpoints if e.function == 'mmio_slave']
    document['windows'] = [dict(device_id='uart', target_instance='uart', endpoint_id=endpoint.endpoint_id,
        base=window.base, size=size)]
    document['dma_master_routes']['routes'][0].update(target=dict(kind='peripheral', component_instance='uart',
        device_id='uart', endpoint_id=endpoint.endpoint_id), base=window.base, size=size,
        readable_offsets=[0x18], writable_offsets=[0x1c], accepted_write_values=dict(kind='values', values=[2]))
    selection = select_template_contract(
        endpoint, uart_artifact.plan.profile.capabilities,
        template_id='target.tl-ul', template_version='1',
        variant_id='user-integrity')
    document['dma_master_route_bindings'][0]['target'] = dict(
        profile_endpoint_sha256=digest(dict(profile_fingerprint=uart_artifact.plan.profile.profile_fingerprint,
            endpoint_id=endpoint.endpoint_id)), template_id=selection.contract.template_id,
        template_version=selection.contract.template_version, variant_id=selection.contract.variant_id,
        contract_sha256=selection.contract.identity_sha256, selection_sha256=selection.identity_sha256)
    document['dma_master_routes_sha256'] = digest(document['dma_master_routes'])
    links = declaration.document()['route_links']
    links[0]['runtime_route_sha256'] = route.identity_sha256
    return prepare_dma_intent_binding(load_path_wiring(document), prepared, route_links=links), runner, evidence


@pytest.mark.parametrize('mutation', ['none', 'window_copy', 'unsupported_target', 'subwindow'])
def test_live_peripheral_target_and_window_identity(issued_artifact, uart_artifact, tmp_path, mutation):
    from copy import copy
    declaration, runner, evidence = peripheral_fixture(issued_artifact, uart_artifact, tmp_path)
    if mutation == 'unsupported_target':
        from myfuzz.local_harness.session import GeneratedLocalSession
        runner.sessions['uart'] = GeneratedLocalSession(uart_artifact, base_dir=tmp_path, cache_dir=tmp_path)
        with pytest.raises(DmaIntentBindingError) as error:
            live_bind(declaration, runner, artifact_links=evidence)
        assert error.value.code == 'dma-binding-target-unsupported'
    elif mutation == 'subwindow':
        # Coherent static/runtime/window subranges remain unsupported against
        # the actual artifact's larger declared aperture.
        doc = declaration.document()
        doc['wiring']['dma_master_routes']['routes'][0]['size'] -= 4
        doc['wiring']['windows'][0]['size'] -= 4
        doc['wiring']['dma_master_routes_sha256'] = digest(doc['wiring']['dma_master_routes'])
        prepared = PreparedRuntimePathContract.from_document(doc['prepared_runtime_paths'])
        routes = list(prepared.contract.dma_master_routes)
        window = replace(runner.sessions['dma'].master_targets[0], size=routes[0].size - 4)
        runner.sessions['dma'].master_targets = (window,)
        routes[0] = replace(routes[0], size=window.size, target_identity_sha256=digest(window.route_identity_document()))
        prepared = PreparedRuntimePathContract(prepared.graph, replace(prepared.contract, dma_master_routes=tuple(routes)), prepared.runtime_paths)
        doc['route_links'][0]['runtime_route_sha256'] = routes[0].identity_sha256
        declaration = prepare_dma_intent_binding(load_path_wiring(doc['wiring']), prepared, route_links=doc['route_links'])
        with pytest.raises(DmaIntentBindingError) as error:
            live_bind(declaration, runner, artifact_links=evidence)
        assert error.value.code == 'dma-binding-target-unsupported'
    else:
        bound = live_bind(declaration, runner, artifact_links=evidence)
        if mutation == 'window_copy':
            runner.sessions['dma'].master_targets = tuple(copy(w) for w in runner.sessions['dma'].master_targets)
            with pytest.raises(DmaIntentBindingError): bound.validate_topology()
        else: bound.validate_topology()


@pytest.mark.parametrize('mutation', ['master', 'role', 'backend'])
def test_wrong_actual_master_roles_or_backend_refuse(issued_artifact, tmp_path, mutation):
    declaration, runner, evidence, _ = live_fixture(issued_artifact, tmp_path)
    artifact = deepcopy(runner.sessions['dma'].artifact)
    if mutation == 'backend':
        artifact.runtime_document['backend_ports'][0]['name'] = 'wrong_backend'
    else:
        master, = [e for e in artifact.plan.binding.endpoints if e.function == 'memory_master']
        wrong = replace(master, endpoint_id='wrong.master') if mutation == 'master' else replace(master, fields=master.fields[:-1])
        plan = replace(artifact.plan, binding=replace(artifact.plan.binding,
            endpoints=tuple(wrong if e is master else e for e in artifact.plan.binding.endpoints)))
        artifact = replace(artifact, plan=plan)
        artifact.runtime_document['plan'] = plan.document()
    artifact.runtime_document['artifact_digest'] = digest({k:v for k,v in artifact.runtime_document.items() if k != 'artifact_digest'})
    runner.sessions['dma'].artifact = artifact
    runner.sessions['dma']._artifact_document = deepcopy(artifact.runtime_document)
    with pytest.raises(DmaIntentBindingError):
        live_bind(declaration, runner, artifact_links=evidence)


@pytest.mark.parametrize('field', ['profile_endpoint_sha256', 'selection_sha256', 'contract_sha256'])
def test_actual_target_template_binding_mismatch_refuses(issued_artifact, uart_artifact, tmp_path, field):
    declaration, runner, evidence = peripheral_fixture(issued_artifact, uart_artifact, tmp_path)
    document = declaration.document()
    document['wiring']['dma_master_route_bindings'][0]['target'][field] = '0' * 64
    prepared = PreparedRuntimePathContract.from_document(document['prepared_runtime_paths'])
    changed = prepare_dma_intent_binding(load_path_wiring(document['wiring']), prepared,
        route_links=document['route_links'])
    with pytest.raises(DmaIntentBindingError) as error:
        live_bind(changed, runner, artifact_links=evidence)
    assert error.value.code == 'dma-binding-template-mismatch'


@pytest.mark.parametrize('session_key,wrong_instance', [('dma', 'cpu'), ('cpu', 'dma'), ('uart', 'dma')])
def test_live_session_key_must_match_actual_artifact_instance(issued_artifact, tmp_path, session_key, wrong_instance):
    declaration, runner, evidence, _ = live_fixture(issued_artifact, tmp_path)
    session = runner.sessions[session_key]
    session.artifact = generated_instance(wrong_instance).artifact
    session._artifact_document = deepcopy(session.artifact.runtime_document)
    if session_key == 'dma':
        evidence['dma'] = generated_instance(wrong_instance).endpoint_links_document()
    with pytest.raises(DmaIntentBindingError) as error:
        live_bind(declaration, runner, artifact_links=evidence)
    assert error.value.code == 'dma-binding-artifact-mismatch'
    assert error.value.pointer == '/sessions/' + session_key + '/artifact/plan/request/instance_id'


def test_explicit_boundary_validation_defers_static_drift_but_keeps_full_gate(issued_artifact,tmp_path):
    declaration,runner,evidence,_=live_fixture(issued_artifact,tmp_path)
    from myfuzz.scenario.dma_intent_topology_binding import bind_dma_intent_topology
    bound=bind_dma_intent_topology(declaration,runner,artifact_links=evidence,
        boundary_static_validation=True)
    bound.runtime_compilation.validate_dynamic_topology()
    runner.sessions['dma'].artifact.runtime_document['boundary_test_drift']=True
    try:
        bound.runtime_compilation.validate_dynamic_topology()
        with pytest.raises(ValueError):bound.validate_topology()
    finally:
        runner.sessions['dma'].artifact.runtime_document.pop('boundary_test_drift')


def test_dynamic_topology_still_rejects_replaced_session(issued_artifact,tmp_path):
    declaration,runner,evidence,_=live_fixture(issued_artifact,tmp_path)
    from myfuzz.scenario.dma_intent_topology_binding import bind_dma_intent_topology
    bound=bind_dma_intent_topology(declaration,runner,artifact_links=evidence,
        boundary_static_validation=True)
    runner.sessions['dma']=deepcopy(runner.sessions['dma'])
    with pytest.raises(ValueError):bound.runtime_compilation.validate_dynamic_topology()


@pytest.mark.parametrize('mutation',['artifact','session','service','ledger','memory_index','config'])
def test_boundary_mode_keeps_dynamic_owners_and_config(issued_artifact,tmp_path,mutation):
    from copy import copy
    declaration,runner,evidence,_=live_fixture(issued_artifact,tmp_path)
    from myfuzz.scenario.dma_intent_topology_binding import bind_dma_intent_topology
    bound=bind_dma_intent_topology(declaration,runner,artifact_links=evidence,
        boundary_static_validation=True)
    dma=runner.sessions['dma']
    if mutation=='artifact':dma.artifact=replace(dma.artifact)
    elif mutation=='session':runner.sessions['dma']=copy(dma)
    elif mutation=='service':dma.memory_service=copy(dma.memory_service)
    elif mutation=='ledger':dma.memory_service.ledger=copy(dma.memory_service.ledger)
    elif mutation=='memory_index':dma.memory_service.memory._windows=list(dma.memory_service.memory._windows)
    else:dma.max_events+=1
    with pytest.raises(ValueError):bound.runtime_compilation.validate_dynamic_topology()


def test_boundary_dynamic_does_not_recreate_static_endpoint_document(issued_artifact,tmp_path,monkeypatch):
    declaration,runner,evidence,_=live_fixture(issued_artifact,tmp_path)
    from myfuzz.scenario.dma_intent_topology_binding import bind_dma_intent_topology
    bound=bind_dma_intent_topology(declaration,runner,artifact_links=evidence,
        boundary_static_validation=True)
    import myfuzz.local_harness.wishbone_dma_session as module
    def expensive(_):raise AssertionError('static endpoint reconstruction')
    monkeypatch.setattr(module,'dma_route_endpoint_identity_document',expensive)
    bound.runtime_compilation.validate_dynamic_topology()
    with pytest.raises(AssertionError,match='static endpoint'):bound.validate_topology()
