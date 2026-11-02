"""Detached DMA intent declarations for an explicitly selected typed topology.

Detached declarations and opt-in live bindings preserve existing runtime bytes.
A topology credential grants no new execution or replay authority.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, fields
import hashlib
import json
from types import CodeType

from myfuzz.local_harness.dma_artifact_endpoint_links import PROVIDER_ID
from .compiled_paths import PathWiring, load_path_wiring, _dma_template_binding
from .runtime_path_contract import PreparedRuntimePathContract, RuntimePathContract

SCHEMA = 'dma_intent_binding_declaration.v1'
_DOCUMENT_KEYS = {'schema_version', 'wiring', 'prepared_runtime_paths', 'route_links', 'identity_sha256'}
_ROW_KEYS = {'route_id', 'rule_index', 'prerequisite_index', 'runtime_route_sha256', 'endpoint_link'}
_ENDPOINT_TEXT_FIELDS = ('mode', 'static_endpoint_id', 'runtime_endpoint_id',
                         'artifact_endpoint_id', 'artifact_link_id',
                         'artifact_link_provider_id', 'operation')
_ENDPOINT_KEYS = {*_ENDPOINT_TEXT_FIELDS, 'template_binding'}
_ZIPCPU_UART_PROVIDER_METHODS = (
    '_dma_exact_document',
    '_dma_target_identity_components',
    'dma_master_target_provider_identity_document',
    '_dma_target_require_ready',
    '_dma_target_backend_values',
    '_dma_target_check_uart_pin',
    'dma_master_target_access',
)
_CALIPTRA_AHB_PROVIDER_METHODS = (
    'dma_master_target_provider_identity_document',
    'dma_master_target_access',
    '_check_artifact_stable',
    'command',
    '_command_impl',
    '_expected_ready',
    '_take',
    '_take_impl',
)
_CALIPTRA_AHB_TRACE_WIDTHS = {
    'haddr': 32, 'hwdata': 32, 'hsel': 1, 'hwrite': 1,
    'hreadyin': 1, 'htrans': 2, 'hsize': 3, 'hresp': 1,
    'hreadyout': 1, 'hrdata': 32,
}


class DmaIntentBindingError(ValueError):
    """Stable refusal code and JSON pointer for a contradictory declaration."""

    def __init__(self, code: str, pointer: str):
        self.code = code
        self.pointer = pointer
        super().__init__(f'{code} at {pointer}')


def _fail(code, pointer):
    raise DmaIntentBindingError('dma-binding-' + code, pointer)


def _plain(value):
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    return value


def _canonical(value):
    try:
        return json.dumps(_plain(value), sort_keys=True, separators=(',', ':'),
                          ensure_ascii=False, allow_nan=False).encode('utf-8')
    except (ValueError, TypeError, UnicodeError) as error:
        raise DmaIntentBindingError('dma-binding-replay-material-invalid', '/') from error


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _zipcpu_uart_provider_method_implementations(session):
    """Return the exact provider methods after rejecting instance shadows."""
    from myfuzz.local_harness.wishbone_uart_session import GeneratedWishboneUartSession
    if type(session) is not GeneratedWishboneUartSession:
        raise ValueError('ZipCPU UART DMA provider session type changed')
    instance_state = getattr(session, '__dict__', None)
    class_methods = vars(type(session))
    if (type(instance_state) is not dict
            or any(name in instance_state for name in _ZIPCPU_UART_PROVIDER_METHODS)
            or any(name not in class_methods for name in _ZIPCPU_UART_PROVIDER_METHODS)):
        raise ValueError('ZipCPU UART provider methods are shadowed or missing')
    return tuple(class_methods[name] for name in _ZIPCPU_UART_PROVIDER_METHODS)


def _caliptra_ahb_provider_method_implementations(session):
    """Resolve the exact AHB provider call path through the class MRO."""
    from myfuzz.local_harness.ahb_lite_register_session import (
        GeneratedAhbLiteRegisterSession)

    if type(session) is not GeneratedAhbLiteRegisterSession:
        raise ValueError('Caliptra AHB DMA provider session type changed')
    instance_state = getattr(session, '__dict__', None)
    if (type(instance_state) is not dict
            or any(name in instance_state for name in _CALIPTRA_AHB_PROVIDER_METHODS)):
        raise ValueError('Caliptra AHB provider method is shadowed')
    resolved = []
    for name in _CALIPTRA_AHB_PROVIDER_METHODS:
        implementation = next(((owner, vars(owner)[name])
            for owner in type(session).__mro__ if name in vars(owner)), None)
        if (implementation is None or not callable(implementation[1])
                or type(getattr(implementation[1], '__code__', None)) is not CodeType):
            raise ValueError('Caliptra AHB provider method is missing')
        resolved.append((*implementation, implementation[1].__code__))
    return tuple(resolved)


def _caliptra_ahb_provider_configuration(session):
    """Stable provider inputs omitted from the returned provider identity."""
    return (
        getattr(session, 'artifact_kind', None),
        getattr(session, 'access_operation', None),
        getattr(session, '_window', None),
        getattr(session, 'DMA_CTRL_OFFSET', None),
        getattr(session, 'DMA_CTRL_START_VALUE', None),
    )


def _caliptra_ahb_provider_identity(session, artifact):
    expected = {
        'schema_version': 'caliptra_sha256_dma_target_provider.v1',
        'api_schema_version': 'dma_master_target_access.v1',
        'implementation_profile': 'caliptra_sha256_ctrl_ahb_write_completion.v1',
        'artifact_digest': artifact.runtime_document.get('artifact_digest'),
        'endpoint_id': 'sha256.bus',
        'operation': 'write', 'register': 'CTRL', 'offset': 16,
        'value': 5, 'byte_enable': 15,
        'observation_contract_schema_version': 'ip_protocol_trace.v1',
    }
    supplied = session.dma_master_target_provider_identity_document()
    if type(supplied) is not dict or _canonical(supplied) != _canonical(expected):
        raise ValueError('Caliptra AHB DMA provider identity changed')
    return supplied


def _closed(value, keys, pointer):
    if type(value) is not dict or set(value) != keys:
        _fail('endpoint-link-mismatch', pointer)


def _text(value, pointer):
    if type(value) is not str or not value or value.strip() != value:
        _fail('endpoint-link-mismatch', pointer)



def _require_json_containers(value, pointer='/'):
    """Inspect original serialized input before canonical convenience coercion."""
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                _fail('replay-material-invalid', pointer)
            token = key.replace('~', '~0').replace('/', '~1')
            _require_json_containers(item, pointer.rstrip('/') + '/' + token)
    elif type(value) is list:
        for index, item in enumerate(value):
            _require_json_containers(item, pointer.rstrip('/') + '/' + str(index))
    elif type(value) not in (str, int, float, bool, type(None)):
        _fail('replay-material-invalid', pointer)


def _read_wiring(document):
    if type(document) is not dict or document.get('schema_version') not in (
            'path_wiring.v2', 'wiring_contract.v2'):
        _fail('replay-material-invalid', '/wiring/schema_version')
    try:
        return load_path_wiring(document)
    except ValueError as error:
        raise DmaIntentBindingError('dma-binding-replay-material-invalid', '/wiring') from error


@dataclass(frozen=True)
class PreparedDmaIntentBinding:
    """Immutable canonical declaration bytes; every document is a fresh copy."""

    _document_bytes: bytes
    # Retain the already validated typed graph for in-memory Task 2/3 handoff.
    # This is intentionally omitted from the serialized declaration; replay
    # readers still restore and validate the graph from authenticated bytes.
    _prepared_runtime_paths: PreparedRuntimePathContract | None = field(
        default=None, repr=False, compare=False)

    def __post_init__(self):
        # Keep direct construction subject to the same closed parser as replay.
        if type(self._document_bytes) is not bytes:
            _fail('replay-material-invalid', '/')
        try:
            document = json.loads(self._document_bytes)
        except (ValueError, UnicodeError) as error:
            raise DmaIntentBindingError('dma-binding-replay-material-invalid', '/') from error
        parsed = self.from_document(document)
        if parsed._document_bytes != self._document_bytes:
            _fail('replay-material-invalid', '/')

    @classmethod
    def _validated(cls, document, *, prepared_runtime_paths=None):
        result = object.__new__(cls)
        object.__setattr__(result, '_document_bytes', _canonical(document))
        object.__setattr__(result, '_prepared_runtime_paths', prepared_runtime_paths)
        return result

    def document(self) -> dict:
        return json.loads(self._document_bytes)

    @property
    def identity_sha256(self) -> str:
        return self.document()['identity_sha256']

    @classmethod
    def from_document(cls, document, *, prepared_runtime_paths=None):
        if type(document) is not dict or set(document) != _DOCUMENT_KEYS:
            _fail('replay-material-invalid', '/')
        _require_json_containers(document)
        if document['schema_version'] != SCHEMA:
            _fail('replay-material-invalid', '/schema_version')
        wiring = _read_wiring(document['wiring'])
        if prepared_runtime_paths is None:
            try:
                prepared = PreparedRuntimePathContract.from_document(document['prepared_runtime_paths'])
            except (ValueError, TypeError, AttributeError) as error:
                raise DmaIntentBindingError('dma-binding-replay-material-invalid', '/prepared_runtime_paths') from error
        else:
            if not isinstance(prepared_runtime_paths, PreparedRuntimePathContract):
                _fail('replay-material-invalid', '/prepared_runtime_paths')
            try:
                supplied_document = prepared_runtime_paths.document()
            except (ValueError, TypeError, AttributeError) as error:
                raise DmaIntentBindingError('dma-binding-replay-material-invalid', '/prepared_runtime_paths') from error
            if _canonical(supplied_document) != _canonical(document['prepared_runtime_paths']):
                _fail('replay-material-invalid', '/prepared_runtime_paths')
            prepared = prepared_runtime_paths
        rebuilt = prepare_dma_intent_binding(wiring, prepared, route_links=document['route_links'])
        if document['identity_sha256'] != rebuilt.identity_sha256:
            _fail('replay-material-invalid', '/identity_sha256')
        if _canonical(document) != rebuilt._document_bytes:
            _fail('replay-material-invalid', '/route_links')
        return rebuilt


def _target_policy(wiring, intent, route, pointer):
    target = intent.target
    if (target['kind'] != route.target_kind
            or target['component_instance'] != route.target_component):
        _fail('target-unsupported', pointer + '/target')
    if target['kind'] == 'peripheral':
        if not (target['device_id'] == target['component_instance'] == route.target_id):
            _fail('target-unsupported', pointer + '/target/device_id')
        windows = [window for window in wiring.windows if window.device_id == target['device_id']]
        if len(windows) != 1:
            _fail('target-unsupported', pointer + '/target')
        window = windows[0]
        if (window.target_instance != target['component_instance']
                or window.endpoint_id != target['endpoint_id']
                or (window.base, window.size) != (route.base, route.size)):
            _fail('target-unsupported', pointer + '/target')
    else:
        if target['resource_id'] != route.target_id:
            _fail('target-unsupported', pointer + '/target/resource_id')
        resources = [resource for resource in wiring.resources
                     if resource.resource_id == target['resource_id']
                     and resource.component_instance == target['component_instance']]
        if len(resources) != 1:
            _fail('target-unsupported', pointer + '/target')
        resource = resources[0]
        permissions = tuple(name for name in ('read', 'write') if getattr(resource, name) is True)
        if ((resource.base, resource.size) != (route.base, route.size)
                or resource.read is None or resource.write is None
                or not set(route.permissions).issubset(permissions)
                or route.operation not in permissions):
            _fail('target-unsupported', pointer + '/target')


def prepare_dma_intent_binding(wiring, prepared, *, route_links) -> PreparedDmaIntentBinding:
    """Validate a complete explicit static-route to typed-edge bijection.

    No graph is generated or restored here; the supplied prepared object's
    existing canonical graph and selected edges are used literally.
    """
    if not isinstance(wiring, PathWiring):
        _fail('replay-material-invalid', '/wiring')
    parsed_wiring = _read_wiring(_plain(wiring.document))
    # PathWiring has a mutable retained document. Refuse contradictions between
    # that document and its parsed fields, including range representation.
    for item in fields(PathWiring):
        name = item.name
        if name in ('document', 'dma_master_routes'):
            continue
        if getattr(wiring, name) != getattr(parsed_wiring, name):
            _fail('replay-material-invalid', '/wiring/' + name)
    if _canonical([route.document() for route in wiring.dma_master_routes]) != _canonical(
            [route.document() for route in parsed_wiring.dma_master_routes]):
        _fail('replay-material-invalid', '/wiring/dma_master_routes')
    wiring = parsed_wiring
    if not isinstance(prepared, PreparedRuntimePathContract):
        _fail('replay-material-invalid', '/prepared_runtime_paths')
    prepared_doc = prepared.document()
    try:
        contract = RuntimePathContract.from_document(prepared_doc['contract'])
    except ValueError as error:
        raise DmaIntentBindingError('dma-binding-replay-material-invalid', '/prepared_runtime_paths/contract') from error
    if _canonical(contract.document()) != _canonical(prepared.contract.document()):
        _fail('replay-material-invalid', '/prepared_runtime_paths/contract')
    routes = {route.key: route for route in contract.dma_master_routes}
    intents = {intent.route_id: intent for intent in wiring.dma_master_routes}
    bindings = {row['route_id']: row for row in wiring.dma_master_route_bindings}
    if not routes or not intents or type(route_links) not in (list, tuple):
        _fail('route-set-mismatch', '/route_links')
    graph_edges = {(edge['rule_index'], edge['prerequisite_index']): edge
                   for edge in prepared_doc['graph']['edges']}
    selected = {(edge['rule_index'], edge['prerequisite_index'])
                for selection in prepared_doc['selections'] for edge in selection['edges']}
    edge_contracts = {edge.key: edge for edge in contract.edges}
    nodes = {node.node_id: node for node in contract.nodes}
    seen_ids, seen_keys, rows = set(), set(), []
    for index, raw in enumerate(route_links):
        pointer = f'/route_links/{index}'
        _closed(raw, _ROW_KEYS, pointer)
        row = json.loads(_canonical(raw))
        route_id = row['route_id']
        _text(route_id, pointer + '/route_id')
        if route_id not in intents or route_id in seen_ids:
            _fail('route-set-mismatch', pointer + '/route_id')
        seen_ids.add(route_id)
        for name in ('rule_index', 'prerequisite_index'):
            if type(row[name]) is not int or row[name] < 0:
                _fail('edge-mismatch', pointer + '/' + name)
        key = row['rule_index'], row['prerequisite_index']
        if key in seen_keys:
            _fail('route-set-mismatch', pointer)
        seen_keys.add(key)
        route, edge, relation = routes.get(key), graph_edges.get(key), edge_contracts.get(key)
        if (route is None or edge is None or relation is None or key not in selected
                or edge['kind'] != 'DMA_MASTER_TRANSFER' or relation.relation != 'dma_master_route'):
            _fail('edge-mismatch', pointer)
        if (route.source_node_id != edge['prerequisite'] or route.target_node_id != edge['target']
                or row['runtime_route_sha256'] != route.identity_sha256):
            _fail('edge-mismatch', pointer + '/runtime_route_sha256')
        source, target = nodes[route.source_node_id], nodes[route.target_node_id]
        orientation = ((target.component, source.component) if route.operation == 'read'
                       else (source.component, target.component))
        if orientation != (route.initiator_component, route.target_component):
            _fail('edge-mismatch', pointer)
        intent = intents[route_id]
        static_pointer = '/wiring/dma_master_routes/routes/' + str(
            tuple(intents).index(route_id))
        static, live = intent.document(), route.document()
        if intent.initiator_instance != route.initiator_component:
            _fail('policy-mismatch', static_pointer + '/initiator_instance')
        for name in ('base', 'size', 'operation', 'permissions', 'byte_enable',
                     'readable_offsets', 'writable_offsets', 'accepted_write_values'):
            expected = static[name]
            if name == 'accepted_write_values' and expected['kind'] == 'values':
                expected = {**expected, 'kind': 'tuple'}
            if _canonical(expected) != _canonical(live[name]):
                _fail('policy-mismatch', static_pointer + '/' + name)
        _target_policy(wiring, intent, route, static_pointer)
        endpoint = row['endpoint_link']
        endpoint_pointer = pointer + '/endpoint_link'
        if endpoint is None:
            _fail('endpoint-link-required', endpoint_pointer)
        _closed(endpoint, _ENDPOINT_KEYS, endpoint_pointer)
        for name in _ENDPOINT_TEXT_FIELDS:
            _text(endpoint[name], endpoint_pointer + '/' + name)
        if (endpoint['mode'] not in ('exact_id', 'explicit_alias')
                or endpoint['static_endpoint_id'] != intent.initiator_endpoint_id
                or endpoint['runtime_endpoint_id'] != route.endpoint_id
                or endpoint['operation'] != route.operation
                or endpoint['static_endpoint_id'] != endpoint['artifact_endpoint_id']
                or (endpoint['mode'] == 'exact_id' and endpoint['runtime_endpoint_id'] != endpoint['static_endpoint_id'])):
            _fail('endpoint-link-mismatch', endpoint_pointer)
        if endpoint['artifact_link_provider_id'] != PROVIDER_ID:
            _fail('provider-unsupported', endpoint_pointer + '/artifact_link_provider_id')
        try:
            template = _dma_template_binding(endpoint['template_binding'], endpoint_pointer + '/template_binding')
        except ValueError as error:
            raise DmaIntentBindingError('dma-binding-endpoint-link-mismatch', endpoint_pointer + '/template_binding') from error
        if _canonical(template) != _canonical(bindings[route_id]['initiator']):
            _fail('template-mismatch', endpoint_pointer + '/template_binding')
        rows.append(row)
    if seen_ids != set(intents) or seen_keys != set(routes):
        _fail('route-set-mismatch', '/route_links')
    document = dict(schema_version=SCHEMA, wiring=_plain(wiring.document),
                    prepared_runtime_paths=prepared_doc,
                    route_links=sorted(rows, key=lambda row: row['route_id']))
    document['identity_sha256'] = _digest(document)
    return PreparedDmaIntentBinding._validated(document, prepared_runtime_paths=prepared)


@dataclass(frozen=True)
class BoundDmaIntentTopology:
    """Credential for an existing, guarded topology; no execution authority."""

    runtime_compilation: object
    _runtime_edge_index: object = field(repr=False, compare=False)
    _document_bytes: bytes

    def document(self):
        return json.loads(self._document_bytes)

    @property
    def identity_sha256(self):
        return self.document()['identity_sha256']

    def validate_topology(self):
        try:
            self.runtime_compilation.validate_topology()
        except DmaIntentBindingError:
            raise
        except ValueError as error:
            raise DmaIntentBindingError('dma-binding-topology-changed', '/') from error

    def match_dma_master_route(self, path_id, *, initiator_component,
            endpoint_id, target_kind, target_component, target_id, base, size,
            operation, address, byte_enable, transaction_key, value=None):
        """Match one observed beat against this binding's selected DMA route.

        The topology guard is rechecked before every lookup. A returned match
        only identifies a declared route; callers still join the accepted
        request, target effect, and native response under the transaction key.
        """
        self.runtime_compilation.validate_dynamic_topology()
        return self._runtime_edge_index.match_dma_master_route(path_id,
            initiator_component=initiator_component, endpoint_id=endpoint_id,
            target_kind=target_kind, target_component=target_component,
            target_id=target_id, base=base, size=size, operation=operation,
            address=address, byte_enable=byte_enable,
            transaction_key=transaction_key, value=value)


def _actual_artifact(session, pointer, *, instance_id):
    from myfuzz.local_harness.session import GeneratedLocalSession
    from myfuzz.local_harness.runtime_artifact import LocalRuntimeArtifact
    if not isinstance(session, GeneratedLocalSession):
        _fail('target-unsupported', pointer)
    artifact = getattr(session, 'artifact', None)
    if not isinstance(artifact, LocalRuntimeArtifact):
        _fail('artifact-mismatch', pointer)
    if artifact.plan.request.instance_id != instance_id:
        _fail('artifact-mismatch', '/sessions/' + instance_id + '/artifact/plan/request/instance_id')
    document = artifact.runtime_document
    if (document != session._artifact_document
            or document.get('plan') != artifact.plan.document()
            or document.get('structural_abi') != artifact.structural.abi_document
            or document.get('structural_build') != artifact.structural.build_document
            or document.get('source_verification') != artifact.source_verification
            or document.get('artifact_digest') != _digest({k:v for k,v in document.items() if k != 'artifact_digest'})
            or document.get('runtime_sv_sha256') != hashlib.sha256(artifact.runtime_sv.encode()).hexdigest()
            or document.get('cpp_sha256') != hashlib.sha256(artifact.cpp_text.encode()).hexdigest()):
        _fail('artifact-mismatch', pointer)
    return artifact


def _target_binding(wiring, intent, session, pointer, *, provider_snapshots=None,
                   pulp_provider_snapshots=None, ahb_provider_snapshots=None):
    from .compiled_paths import _wiring_resource_document
    artifact = _actual_artifact(session, pointer, instance_id=intent.target['component_instance'])
    if intent.target['kind'] == 'persistent_memory':
        resource, = [r for r in wiring.resources if r.component_instance == intent.target['component_instance']
                       and r.resource_id == intent.target['resource_id']]
        return dict(kind='persistent_memory', owner_profile_fingerprint=artifact.plan.profile.profile_fingerprint,
                    resource_sha256=_digest(_wiring_resource_document(resource)))
    # Target transports remain a closed generated-session set; a new provider
    # cannot be admitted merely through duck typing.
    from myfuzz.local_harness.opentitan_uart_session import GeneratedOpentitanUartSession
    from myfuzz.local_harness.wishbone_uart_session import GeneratedWishboneUartSession
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    from myfuzz.local_harness.ahb_lite_register_session import GeneratedAhbLiteRegisterSession
    from myfuzz.local_harness.template_contracts import select_template_contract
    if type(session) not in (GeneratedOpentitanUartSession,
                              GeneratedWishboneUartSession,
                              GeneratedPulpGpioSession,
                              GeneratedAhbLiteRegisterSession):
        _fail('target-unsupported', pointer)
    is_pulp_gpio = type(session) is GeneratedPulpGpioSession
    is_zipcpu_uart = type(session) is GeneratedWishboneUartSession
    is_caliptra_ahb = type(session) is GeneratedAhbLiteRegisterSession
    if is_zipcpu_uart:
        from myfuzz.scenario.zipcpu_uart_dma_paths import _validate_provider_identity
        try:
            provider_methods = _zipcpu_uart_provider_method_implementations(session)
        except (TypeError, ValueError, AttributeError):
            _fail('provider-unsupported', pointer)
        if (artifact.plan.profile.component_id != 'zipcpu_uart'
                or artifact.runtime_document.get('kind') != 'wishbone_uart'
                or artifact.plan.profile.address is None
                or artifact.plan.profile.address.window_size != 16):
            _fail('provider-unsupported', pointer)
        try:
            provider_identity = _validate_provider_identity(session)
            if (_zipcpu_uart_provider_method_implementations(session)
                    != provider_methods):
                raise ValueError('ZipCPU UART provider methods changed during identity check')
        except (TypeError, ValueError, AttributeError):
            _fail('provider-unsupported', pointer)
        if provider_snapshots is not None:
            provider_snapshots.append((session, _canonical(provider_identity),
                                      provider_methods))
    if is_pulp_gpio:
        from myfuzz.local_harness.native_reset_producer_contract import check_producer
        from myfuzz.local_harness.pulp_gpio_probe_contract import pulp_gpio_observation_contract
        try:
            producer_kind = check_producer(session)
        except (TypeError, ValueError, AttributeError):
            producer_kind = None
        if producer_kind != 'gpio':
            _fail('provider-unsupported', pointer)
        provider_identity = getattr(session,
            'dma_master_target_provider_identity_document', None)
        expected_provider = {
            'schema_version': 'pulp_gpio_dma_target_provider.v1',
            'api_schema_version': 'dma_master_target_access.v1',
            'implementation_profile': 'pulp_gpio_padout_apb3.v1',
            'observation_contract': pulp_gpio_observation_contract(),
            'operations': [{'operation': 'write', 'register': 'PADOUT',
                'offset': 12, 'byte_enable': 15}],
        }
        try:
            supplied_provider = provider_identity() if callable(provider_identity) else None
            provider_matches = (_canonical(supplied_provider)
                                == _canonical(expected_provider))
        except (TypeError, ValueError, AttributeError):
            provider_matches = False
        if (not provider_matches
                or artifact.plan.profile.component_id != 'pulp_gpio_causal_local'
                or artifact.runtime_document.get('kind') != 'apb_gpio'
                or artifact.runtime_document.get('gpio_observation_contract')
                    != pulp_gpio_observation_contract()):
            _fail('provider-unsupported', pointer)
        if pulp_provider_snapshots is not None:
            pulp_provider_snapshots.append((session,
                _canonical(supplied_provider)))
    if is_caliptra_ahb:
        try:
            provider_methods = _caliptra_ahb_provider_method_implementations(session)
            configuration = _caliptra_ahb_provider_configuration(session)
        except (TypeError, ValueError, AttributeError):
            _fail('provider-unsupported', pointer)
        if (artifact.plan.profile.component_id != 'caliptra_sha256'
                or artifact.runtime_document.get('kind') != 'ahb_lite_register_observe'
                or artifact.plan.request.instance_id != 'sha'
                or configuration != ('ahb_lite_register_observe',
                    'ACCESS_AHB_REG', 4096, 16, 5)
                or artifact.plan.profile.address is None
                or artifact.plan.profile.address.window_size != 4096):
            _fail('provider-unsupported', pointer)
        trace = artifact.runtime_document.get('base_protocol_trace')
        if (type(trace) is not dict
                or trace.get('schema_version') != 'ip_protocol_trace.v1'
                or trace.get('protocol') != 'ahb-lite'
                or trace.get('endpoint_id') != 'sha256.bus'
                or type(trace.get('signals')) is not dict
                or set(trace['signals']) != set(_CALIPTRA_AHB_TRACE_WIDTHS)
                or any(type(signal) is not str or not signal
                       for signal in trace['signals'].values())
                or trace['signals'] != {
                    role: 'trace_' + role for role in _CALIPTRA_AHB_TRACE_WIDTHS}
                or type(trace.get('signal_widths')) is not dict
                or set(trace['signal_widths']) != set(_CALIPTRA_AHB_TRACE_WIDTHS)
                or any(type(width) is not int
                       for width in trace['signal_widths'].values())
                or trace['signal_widths'] != _CALIPTRA_AHB_TRACE_WIDTHS):
            _fail('provider-unsupported', pointer)
        try:
            provider_identity = _caliptra_ahb_provider_identity(session, artifact)
            if (_caliptra_ahb_provider_method_implementations(session)
                    != provider_methods
                    or _caliptra_ahb_provider_configuration(session)
                    != configuration):
                raise ValueError('Caliptra AHB provider changed during identity check')
        except (TypeError, ValueError, AttributeError):
            _fail('provider-unsupported', pointer)
        if ahb_provider_snapshots is not None:
            ahb_provider_snapshots.append((session,
                _canonical(provider_identity), provider_methods, configuration))
    endpoint_id = intent.target['endpoint_id']
    endpoints = [e for e in artifact.plan.binding.endpoints if e.endpoint_id == endpoint_id
                 and e.function == 'mmio_slave']
    if len(endpoints) != 1 or endpoint_id not in artifact.runtime_document.get('adapted_endpoint_ids', []):
        _fail('target-unsupported', pointer)
    if is_zipcpu_uart:
        try:
            protocol = tuple(endpoints[0].protocol)
        except (AttributeError, TypeError):
            protocol = ()
        if endpoint_id != 'uart.bus' or protocol != ('wishbone', 'classic'):
            _fail('target-unsupported', pointer)
        registers = [register for register in artifact.plan.profile.address.registers
                     if register.name == 'TXREG' and register.offset == 12]
        if (len(registers) != 1
                or (registers[0].width, registers[0].access) != (32, 'rw')
                or intent.operation != 'write'
                or intent.permissions != ('write',)
                or intent.byte_enable != 15
                or intent.readable_offsets
                or intent.writable_offsets != (12,)
                or intent.accepted_write_values != range(0, 256)):
            _fail('target-unsupported', pointer)
    if is_pulp_gpio:
        try:
            protocol = tuple(endpoints[0].protocol)
        except (AttributeError, TypeError):
            protocol = ()
        if endpoint_id != 'gpio.bus' or protocol != ('apb', '3'):
            _fail('target-unsupported', pointer)
    if is_caliptra_ahb:
        try:
            protocol = tuple(endpoints[0].protocol)
        except (AttributeError, TypeError):
            protocol = ()
        if endpoint_id != 'sha256.bus' or protocol != ('ahb-lite', '1'):
            _fail('target-unsupported', pointer)
        registers = [register for register in artifact.plan.profile.address.registers
                     if register.name == 'CTRL' and register.offset == 16]
        if (len(registers) != 1
                or (registers[0].width, registers[0].access) != (32, 'wo')
                or intent.operation != 'write'
                or intent.permissions != ('write',)
                or intent.byte_enable != 15
                or intent.readable_offsets
                or intent.writable_offsets != (16,)
                or intent.accepted_write_values != (5,)):
            _fail('target-unsupported', pointer)
    address = artifact.plan.profile.address
    if address is None or address.window_size != intent.size:
        _fail('target-unsupported', pointer)
    for permission in intent.permissions:
        if artifact.plan.profile.capabilities.get(permission) is not True:
            _fail('target-unsupported', pointer)
        offsets = intent.readable_offsets if permission == 'read' else intent.writable_offsets
        for offset in offsets:
            registers = [r for r in address.registers if r.offset == offset]
            if (len(registers) != 1 or (permission == 'read' and registers[0].access == 'wo')
                    or (permission == 'write' and registers[0].access == 'ro')):
                _fail('target-unsupported', pointer)
    if is_pulp_gpio:
        padouts = [register for register in address.registers
                   if register.offset == 12]
        if len(padouts) != 1:
            _fail('target-unsupported', pointer)
        padout = padouts[0]
        if (intent.operation != 'write' or intent.permissions != ('write',)
                or intent.byte_enable != 15 or intent.readable_offsets
                or intent.writable_offsets != (12,)
                or (padout.name, padout.width, padout.access) != ('PADOUT', 32, 'rw')):
            _fail('target-unsupported', pointer)
    declared_bindings = {row['route_id']: row
                         for row in wiring.dma_master_route_bindings}
    declared_binding = declared_bindings.get(intent.route_id)
    if not isinstance(declared_binding, Mapping) or not isinstance(
            declared_binding.get('target'), Mapping):
        _fail('template-mismatch', pointer)
    declared_template = declared_binding['target']
    if is_pulp_gpio and (declared_template.get('template_id') != 'target.apb3'
            or declared_template.get('template_version') != '1'
            or declared_template.get('variant_id') != 'full-word'):
        _fail('template-mismatch', pointer)
    if is_zipcpu_uart and (declared_template.get('template_id') != 'target.wishbone'
            or declared_template.get('template_version') != '1'
            or declared_template.get('variant_id') != 'word-addressed-registered-ack'):
        _fail('template-mismatch', pointer)
    if is_caliptra_ahb and (declared_template.get('template_id') != 'target.ahb-lite'
            or declared_template.get('template_version') != '1'
            or declared_template.get('variant_id') != 'full-word-single'):
        _fail('template-mismatch', pointer)
    try:
        # D2 records the selection made from its explicit template declaration.
        # Recompute that exact selection identity from the actual target endpoint;
        # using the default selector here produces a different selection digest
        # even when it resolves to the same registered template contract.
        selection = select_template_contract(
            endpoints[0], artifact.plan.profile.capabilities,
            template_id=declared_template['template_id'],
            template_version=declared_template['template_version'],
            variant_id=declared_template['variant_id'])
    except ValueError as error:
        raise DmaIntentBindingError('dma-binding-target-unsupported', pointer) from error
    selected = selection.document()
    declared_binding = selected.get('binding')
    if is_caliptra_ahb:
        request = artifact.plan.request
        tuning = getattr(request, 'tuning', None)
        records = getattr(tuning, 'records', None)
        endpoint_policies = ([record.document() for record in records]
                             if type(records) is tuple else None)
        expected_policy = [{
            'endpoint_id': 'sha256.bus', 'template_id': 'target.ahb-lite',
            'template_version': '1', 'variant_id': 'full-word-single',
            'max_outstanding': 1,
        }]
        if endpoint_policies != expected_policy:
            _fail('template-mismatch', pointer)
        # The generated AHB executor stores this request policy in the pinned
        # plan but currently omits a duplicate protocol_templates row. The
        # selection above is therefore recomputed from that exact plan request,
        # endpoint and profile, then compared against D2's selected identity.
        artifact_binding = declared_binding
    else:
        artifact_selections = artifact.runtime_document['selected_template']['executor'].get(
            'protocol_templates', ())
        matches = [row for row in artifact_selections
                   if isinstance(row, Mapping)
                   and row.get('contract_sha256') == selection.contract.identity_sha256
                   and row.get('contract') == selection.contract.document()]
        if len(matches) != 1:
            _fail('template-mismatch', pointer)
        # The artifact records its automatic default selection while D2 binds
        # the explicitly declared contract. Both selections must describe the
        # same physical endpoint/profile facts; only selection mode may differ.
        artifact_binding = matches[0].get('binding')
    if not isinstance(artifact_binding, Mapping) or not isinstance(declared_binding, Mapping):
        _fail('template-mismatch', pointer)
    artifact_binding = dict(artifact_binding)
    declared_binding = dict(declared_binding)
    artifact_binding.pop('selection_mode', None)
    declared_binding.pop('selection_mode', None)
    if artifact_binding != declared_binding:
        _fail('template-mismatch', pointer)
    return dict(profile_endpoint_sha256=_digest(dict(profile_fingerprint=artifact.plan.profile.profile_fingerprint,
        endpoint_id=endpoint_id)), template_id=selection.contract.template_id,
        template_version=selection.contract.template_version, variant_id=selection.contract.variant_id,
        contract_sha256=selection.contract.identity_sha256, selection_sha256=selection.identity_sha256)


def bind_dma_intent_topology(declaration, runner, *, artifact_links,
                             path_ids: tuple[str, ...] | None = None,
                             boundary_static_validation=False) -> BoundDmaIntentTopology:
    """Validate actual generated artifacts, then bind the supplied route set once."""
    from myfuzz.local_harness.dma_artifact_endpoint_links import validate_dma_artifact_endpoint_links
    from myfuzz.local_harness.wishbone_dma_session import GeneratedWishboneDmaSession
    from myfuzz.local_harness.wishbone_dma_scenario_session import GeneratedWishboneDmaScenarioSession
    if not isinstance(declaration, PreparedDmaIntentBinding):
        _fail('replay-material-invalid', '/')
    if type(boundary_static_validation) is not bool:
        raise ValueError("boundary_static_validation must be boolean")
    supplied_prepared = declaration._prepared_runtime_paths
    verified = PreparedDmaIntentBinding.from_document(
        declaration.document(), prepared_runtime_paths=supplied_prepared)
    document = verified.document()
    wiring = _read_wiring(document['wiring'])
    prepared = verified._prepared_runtime_paths
    if not isinstance(prepared, PreparedRuntimePathContract):
        _fail('replay-material-invalid', '/prepared_runtime_paths')
    intents = {r.route_id:r for r in wiring.dma_master_routes}
    bindings = {r['route_id']:r for r in wiring.dma_master_route_bindings}
    routes = {r.key:r for r in prepared.contract.dma_master_routes}
    initiators = {r.initiator_component for r in routes.values()}
    if not isinstance(artifact_links, Mapping) or not initiators <= set(artifact_links):
        _fail('endpoint-link-required', '/artifact_links')
    if set(artifact_links) != initiators:
        _fail('endpoint-link-mismatch', '/artifact_links')
    snapshots, evidence = [], []
    provider_snapshots, pulp_provider_snapshots = [], []
    ahb_provider_snapshots = []
    components = initiators | {r.target_component for r in routes.values()}
    for name in sorted(components):
        session = runner.sessions.get(name)
        if name in initiators and type(session) not in (GeneratedWishboneDmaSession, GeneratedWishboneDmaScenarioSession):
            _fail('provider-unsupported', '/artifact_links/' + name)
        artifact = _actual_artifact(session, '/artifact_links/' + name, instance_id=name)
        snapshots.append((name, session, artifact, artifact.plan, artifact.structural,
                          _canonical(artifact.runtime_document), _canonical(artifact.plan.document())))
    for name in sorted(initiators):
        try:
            parsed = validate_dma_artifact_endpoint_links(artifact_links[name], runner.sessions[name].artifact,
                pointer='/artifact_links/' + name)
        except ValueError as error:
            raise DmaIntentBindingError(getattr(error, 'code', 'dma-binding-artifact-mismatch'),
                getattr(error, 'pointer', '/artifact_links/' + name)) from error
        evidence.append(dict(instance_id=name, endpoint_links=parsed.document()))
    evidence_by_name = {r['instance_id']:r['endpoint_links'] for r in evidence}
    credential_routes = []
    for index, row in enumerate(document['route_links']):
        route = routes[row['rule_index'], row['prerequisite_index']]
        endpoint = row['endpoint_link']
        link_document = evidence_by_name[route.initiator_component]
        physical, = link_document['links']
        pointer = '/route_links/' + str(index) + '/endpoint_link'
        if (endpoint['artifact_link_provider_id'] != link_document['provider_id']
                or endpoint['artifact_link_id'] != physical['link_id']
                or endpoint['artifact_endpoint_id'] != physical['endpoint_id']):
            _fail('endpoint-link-mismatch', pointer)
        if endpoint['template_binding'] != physical['template_binding']:
            _fail('template-mismatch', pointer + '/template_binding')
        intent = intents[row['route_id']]
        target = _target_binding(wiring, intent,
            runner.sessions[route.target_component], pointer + '/target',
            provider_snapshots=provider_snapshots,
            pulp_provider_snapshots=pulp_provider_snapshots,
            ahb_provider_snapshots=ahb_provider_snapshots)
        if target != _plain(bindings[row['route_id']]['target']):
            _fail('template-mismatch', pointer + '/target')
        credential_routes.append(dict(route_id=row['route_id'], intent_sha256=intent.identity_sha256,
            rule_index=row['rule_index'], prerequisite_index=row['prerequisite_index'],
            runtime_route_sha256=route.identity_sha256, endpoint_link_sha256=_digest(endpoint)))
    link_objects = tuple((name, artifact_links[name], _canonical(artifact_links[name])) for name in sorted(initiators))

    def guard(*, dynamic=False):
        try:
            if set(artifact_links) != initiators:
                _fail('topology-changed', '/artifact_links')
            for name, original, saved in link_objects:
                if artifact_links[name] is not original or (not dynamic and _canonical(original) != saved):
                    _fail('topology-changed', '/artifact_links/' + name)
            for name, session, artifact, plan, structural, saved, saved_plan in snapshots:
                if (runner.sessions.get(name) is not session or session.artifact is not artifact
                        or artifact.plan is not plan or artifact.structural is not structural
                        or (not dynamic and (_canonical(artifact.runtime_document) != saved
                        or _canonical(plan.document()) != saved_plan))):
                    _fail('topology-changed', '/sessions/' + name)
                if not dynamic:
                    _actual_artifact(session, '/sessions/' + name, instance_id=name)
            for session, provider_identity_json, provider_methods in provider_snapshots:
                provider_pointer = '/sessions/' + session.artifact.plan.request.instance_id + '/provider'
                if (runner.sessions.get(session.artifact.plan.request.instance_id) is not session):
                    _fail('topology-changed', provider_pointer)
                try:
                    current_methods = _zipcpu_uart_provider_method_implementations(session)
                    from myfuzz.scenario.zipcpu_uart_dma_paths import _validate_provider_identity
                    current_identity = _validate_provider_identity(session)
                except (TypeError, ValueError, AttributeError):
                    _fail('topology-changed', provider_pointer)
                if (current_methods != provider_methods
                        or _canonical(current_identity) != provider_identity_json):
                    _fail('topology-changed', provider_pointer)
            for session, provider_identity_json in pulp_provider_snapshots:
                instance_id = session.artifact.plan.request.instance_id
                provider_pointer = '/sessions/' + instance_id + '/provider'
                if runner.sessions.get(instance_id) is not session:
                    _fail('topology-changed', provider_pointer)
                try:
                    from myfuzz.local_harness.native_reset_producer_contract import (
                        check_producer)
                    if (check_producer(session) != 'gpio'
                            or _canonical(session.dma_master_target_provider_identity_document())
                                != provider_identity_json):
                        _fail('topology-changed', provider_pointer)
                except DmaIntentBindingError:
                    raise
                except (TypeError, ValueError, AttributeError):
                    _fail('topology-changed', provider_pointer)
            for session, provider_identity_json, provider_methods, configuration in ahb_provider_snapshots:
                provider_pointer = '/sessions/sha/provider'
                if runner.sessions.get('sha') is not session:
                    _fail('topology-changed', provider_pointer)
                try:
                    current_methods = _caliptra_ahb_provider_method_implementations(session)
                    current_configuration = _caliptra_ahb_provider_configuration(session)
                    current_identity = _caliptra_ahb_provider_identity(
                        session, session.artifact)
                except (TypeError, ValueError, AttributeError):
                    _fail('topology-changed', provider_pointer)
                if (current_methods != provider_methods
                        or current_configuration != configuration
                        or _canonical(current_identity) != provider_identity_json):
                    _fail('topology-changed', provider_pointer)
            for name in sorted(initiators) if not dynamic else ():
                validate_dma_artifact_endpoint_links(artifact_links[name], runner.sessions[name].artifact)
        except DmaIntentBindingError:
            raise
        except (ValueError, TypeError, KeyError, AttributeError) as error:
            raise DmaIntentBindingError('dma-binding-topology-changed', '/') from error

    from functools import partial
    try:
        # Fresh RFuzz selection replay may bind one already-prepared selection
        # at a time. The route/link declaration above remains complete; the
        # existing compiler still requires every DMA route to be covered by
        # the selected path set.
        compilation = prepared.bind(runner, path_ids=path_ids,
                                    topology_guard=guard, dynamic_topology_guard=partial(guard, dynamic=True),
                                    boundary_static_validation=boundary_static_validation)
    except DmaIntentBindingError:
        raise
    except ValueError as error:
        raise DmaIntentBindingError('dma-binding-target-unsupported', '/topology') from error
    credential = dict(schema_version='dma_intent_topology_binding.v1',
        declaration_sha256=declaration.identity_sha256, prepared_sha256=_digest(prepared.document()),
        runtime_contract_sha256=prepared.contract.identity_sha256,
        runtime_compilation_sha256=compilation.identity_sha256, topology_sha256=compilation.topology_sha256,
        artifact_links=evidence, routes=credential_routes, tier='topology_bound')
    credential['identity_sha256'] = _digest(credential)
    from .runtime_edge_index import RuntimeEdgeIndex
    index_document = compilation.document()
    index_document['declaration'] = prepared.document()
    try:
        route_index = RuntimeEdgeIndex(index_document,
            prepared.contract.document(), prepared=prepared)
    except ValueError as error:
        raise DmaIntentBindingError(
            'dma-binding-target-unsupported', '/topology/runtime_edge_index') from error
    return BoundDmaIntentTopology(compilation, route_index,
                                  _canonical(credential))
