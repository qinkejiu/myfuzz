"""Per-case UART FIFO source authority joined to the real pop/read rows (S4).

The tracker emits ``uart_consumption_match`` rows from real journal evidence.
This module *joins* those rows to the case's own certified FIFO entries and
pops.  A case may only claim ``accepted_uart_fifo_entry`` when, for every
admitted serial byte, exactly one accepted retention proof carries the declared
admission and entry, and every real pop has exactly one accepted read proof
with the same entry identity, value, access id and route mode.

A missing proof keeps the case ``unknown`` with the missing element named.  A
*contradictory* proof (foreign entry/frame, wrong admission, wrong route) is a
hard error: it can never be downgraded to unknown, because a tampered accepted
row must fail the gate instead of silently disappearing.
"""
from __future__ import annotations

from collections.abc import Mapping
import json

SCHEMA = 'uart_fifo_source_authority.v1'
SCHEMA_V2 = 'uart_fifo_source_authority.v2'
ACCEPTED = 'accepted_uart_fifo_entry'
UNKNOWN = 'unknown'
INCOMPLETE = 'incomplete'
BOUNDED_CHAIN = 'bounded_historical_chain'
ACCEPTED_CHAIN = 'accepted_uart_fifo_chain'
RETENTION_SCOPE = 'uart_fifo_retention'
READ_SCOPE = 'uart_fifo_read_consumption'
MATCH_KIND = 'uart_consumption_match'
_ROUTE_MODES = ('router', 'dma_master')
_REQUIRED_AUTHORITY = ('installed', 'path_id', 'source_id', 'producer_ref',
    'source_component', 'graph_sha256', 'contract_sha256', 'edge_index_sha256',
    'admissions')


def _same(left, right):
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(
        right, sort_keys=True, allow_nan=False)


def _is_int(value):
    return type(value) is int


def _entry_id(value):
    return (isinstance(value, list) and len(value) == 4
        and isinstance(value[0], str) and value[0]
        and _is_int(value[1]) and _is_int(value[2]) and _is_int(value[3]))


def _sorted_ids(values):
    return sorted({json.dumps(value, sort_keys=True) for value in values})


def _summary(authority):
    """Stable identity of the installed authority (no host or process UUIDs)."""
    summary = dict(installed=True, source_id=authority['source_id'],
        source_component=authority['source_component'],
        producer_ref=authority['producer_ref'], path_id=authority['path_id'],
        graph_sha256=authority['graph_sha256'],
        contract_sha256=authority['contract_sha256'],
        topology_sha256=authority.get('topology_sha256'),
        edge_index_sha256=authority['edge_index_sha256'],
        master_route=authority.get('master_route'))
    if 'dma_master_routes' in authority:
        summary['dma_master_routes'] = authority['dma_master_routes']
    return summary


def _validate_dma_master_route_match(row, *, read, authority):
    """Check the accepted UART proof names its exact selected typed route."""
    match = row.get('dma_master_route_match')
    routes = authority.get('dma_master_routes')
    if not isinstance(match, dict) or not isinstance(routes, (list, tuple)):
        raise RuntimeError('accepted DMA UART read lacks its compiled route match')
    matches = [route for route in routes
        if isinstance(route, dict)
        and route.get('route_sha256') == match.get('route_sha256')]
    if len(matches) != 1:
        raise RuntimeError('accepted DMA UART read names an unknown or duplicate route')
    route = matches[0]
    if (route.get('identity_sha256') != route.get('route_sha256')
            or authority.get('path_id') not in route.get('path_ids', ())):
        raise RuntimeError('compiled DMA route index identity or selected path is invalid')
    # RuntimeEdgeIndex rows carry the route declaration fields at the top
    # level.  The nested ``route`` form belongs to the compilation topology;
    # source authority consumes the detached index document instead.
    declaration = route
    expected = dict(edge_key=route.get('edge_key'),
        source_node_id=declaration.get('source_node_id'),
        target_node_id=declaration.get('target_node_id'),
        path_id=authority.get('path_id'),
        initiator_component=declaration.get('initiator_component'),
        endpoint_id=declaration.get('endpoint_id'),
        target_kind=declaration.get('target_kind'),
        target_component=declaration.get('target_component'),
        target_id=declaration.get('target_id'), base=declaration.get('base'),
        size=declaration.get('size'), operation=declaration.get('operation'),
        byte_enable=declaration.get('byte_enable'),
        target_identity_sha256=declaration.get('target_identity_sha256'))
    if any(not _same(match.get(name), value)
           for name, value in expected.items()):
        raise RuntimeError('accepted DMA UART read route identity differs from its declaration')
    transaction = row.get('source_transaction')
    address = match.get('address')
    route_base = declaration.get('base')
    route_size = declaration.get('size')
    if (type(address) is not int or type(route_base) is not int
            or type(route_size) is not int
            or not isinstance(transaction, dict)
            or not _same(match.get('transaction_key'), transaction)
            or match.get('operation') != 'read'
            or match.get('target_kind') != 'peripheral'
            or match.get('target_component') != 'uart'
            or match.get('target_id') != 'uart'
            or transaction.get('channel_id') != 'dma-memory'
            or transaction.get('source_component') != 'dma'
            or match.get('address') != row.get('address')
            or match.get('byte_enable') != 15):
        raise RuntimeError('accepted DMA UART read route lacks its exact transaction/access')
    if (address < route_base or address + 4 > route_base + route_size
            or address - route_base
                not in declaration.get('readable_offsets', ())):
        raise RuntimeError('accepted DMA UART read lies outside its declared RDATA route')
    if read.get('route') != 'dma_master':
        raise RuntimeError('DMA route match was attached to a non-master FIFO read')


def _admissions(authority):
    rows = authority.get('admissions')
    if not isinstance(rows, (list, tuple)):
        raise ValueError('installed source authority requires admission documents')
    by_action = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('source admission documents must be objects')
        action = row.get('action_id')
        if not isinstance(action, str) or not action or action in by_action:
            raise ValueError('source admission action identities are invalid')
        by_action[action] = row
    return by_action


def _check_common(row, *, admission, authority, entry_id):
    source = row.get('source_admission')
    if not isinstance(source, dict):
        raise RuntimeError('accepted UART FIFO proof lacks its source admission')
    if source.get('admission_id') != admission.get('admission_id'):
        raise RuntimeError('accepted UART FIFO proof carries a different admission')
    if source.get('path_id') != authority['path_id']:
        raise RuntimeError('accepted UART FIFO proof carries a different graph path')
    if source.get('source_id') != authority['source_id']:
        raise RuntimeError('accepted UART FIFO proof carries a different graph source')
    if source.get('component') != authority['source_component']:
        raise RuntimeError('accepted UART FIFO proof carries a different source component')
    if row.get('path_id') != authority['path_id']:
        raise RuntimeError('accepted UART FIFO proof graph path differs from the declaration')
    if row.get('graph_path_certified') is not True:
        raise RuntimeError('accepted UART FIFO proof is not graph-path certified')
    if not _entry_id(row.get('entry_id')):
        raise RuntimeError('accepted UART FIFO proof lacks a real FIFO entry identity')
    if not _same(row['entry_id'], entry_id):
        raise RuntimeError('accepted UART FIFO proof names a different FIFO entry')


def _retention_document(row):
    return dict(entry_id=list(row['entry_id']),
        receiver_id=row.get('receiver_id'), frame_id=row.get('frame_id'),
        push_event=row.get('push_event'),
        validation_event=row.get('validation_event'),
        observation_event_id=row.get('observation_event_id'),
        local_tick=row.get('local_tick'),
        retained_at_push=row.get('retained_at_push'),
        disposition=row.get('disposition'),
        path_id=row.get('path_id'),
        graph_path_certified=row.get('graph_path_certified'))


def _read_document(row):
    transaction = row.get('source_transaction')
    document = dict(access_id=row.get('access_id'), entry_id=list(row['entry_id']),
        frame_id=row.get('frame_id'), read_value=row.get('read_value'),
        route_context_mode=row.get('route_context_mode'),
        address=row.get('address'), window_base=row.get('window_base'),
        window_size=row.get('window_size'),
        channel_id=(transaction.get('channel_id')
                    if isinstance(transaction, dict) else None),
        source_sequence=(transaction.get('source_sequence')
                         if isinstance(transaction, dict) else None),
        request_event=row.get('request_event'),
        response_event=row.get('response_event'),
        request_tick=row.get('request_tick'),
        response_tick=row.get('response_tick'),
        pop_event=row.get('pop_event'), access_event=row.get('access_event'),
        path_id=row.get('path_id'),
        graph_path_certified=row.get('graph_path_certified'))
    if 'dma_master_route_match' in row:
        document['dma_master_route_match'] = row['dma_master_route_match']
    return document


def _incomplete_reasons(rows):
    """Tracker refusal reasons inside this case slice (never synthesized)."""
    reasons = []
    for row in rows:
        if row.get('kind') != MATCH_KIND or row.get('status') != 'incomplete':
            continue
        if row.get('proof_scope') not in (RETENTION_SCOPE, READ_SCOPE):
            continue
        reason = row.get('reason')
        if isinstance(reason, str) and reason and reason not in reasons:
            reasons.append(reason)
    return reasons


def source_authority_evidence(rows, *, entries, admissions, reads, authority):
    """Join accepted tracker proofs to this case's certified FIFO rows.

    ``entries`` is the FIFO order of admitted serial bytes (one record per
    byte), ``reads`` the certified real pops in the same FIFO order with their
    access ids and expected route mode, and ``authority`` the installed
    provenance document plus the admission documents of this case.
    """
    if not isinstance(authority, Mapping):
        raise ValueError('source authority document is required')
    if not isinstance(authority, dict):
        authority = dict(authority)
    if authority.get('installed') is not True:
        return dict(schema_version=SCHEMA, fifo_origin=UNKNOWN,
            source_authority=INCOMPLETE, proof_grade=BOUNDED_CHAIN,
            reason='source_provenance_not_installed', missing=['installed'],
            authority=dict(installed=False), retention=[], reads=[],
            incomplete_reasons=[])
    missing = [name for name in _REQUIRED_AUTHORITY
               if name not in authority and name != 'installed']
    if missing:
        raise ValueError('installed source authority lacks '
                         + ', '.join(sorted(missing)))
    admission_map = _admissions(authority)
    entries = tuple(entries)
    reads = tuple(reads)
    if not entries:
        raise ValueError('a case authority needs at least one admitted entry')
    for index, entry in enumerate(entries):
        if entry.get('index') != index:
            raise ValueError('FIFO entries must be declared in serial order')
        action = entry.get('action_id')
        if action not in admission_map:
            raise RuntimeError('a certified frame has no registered source admission')
        if admission_map[action].get('admission_id') != entry.get('admission_id'):
            raise RuntimeError('certified frame admission differs from the declared action')

    retention = [row for row in rows
                 if row.get('kind') == MATCH_KIND
                 and row.get('status') == 'accepted'
                 and row.get('proof_scope') == RETENTION_SCOPE]
    accepted_reads = [row for row in rows
                      if row.get('kind') == MATCH_KIND
                      and row.get('status') == 'accepted'
                      and row.get('proof_scope') == READ_SCOPE]
    frame_ids = {entry['frame_id'] for entry in entries}
    expected_access = {read['access_id'] for read in reads}
    foreign_retention = [row for row in retention
                         if row.get('frame_id') not in frame_ids]
    if foreign_retention:
        raise RuntimeError(
            'accepted UART FIFO retention proof names a foreign frame')
    foreign_reads = [row for row in accepted_reads
                     if row.get('access_id') not in expected_access]
    if foreign_reads:
        raise RuntimeError(
            'accepted UART FIFO read proof names a foreign access')

    entry_ids = {}
    retention_documents = []
    for entry in entries:
        matches = [row for row in retention
                   if row.get('frame_id') == entry['frame_id']]
        if not matches:
            missing.append('uart_fifo_retention:' + entry['action_id'])
            continue
        if len(matches) > 1:
            raise RuntimeError('duplicate accepted UART FIFO retention proof')
        row = matches[0]
        admission = admission_map[entry['action_id']]
        _check_common(row, admission=admission, authority=authority,
                      entry_id=row.get('entry_id'))
        if row.get('retained_at_push') is not True:
            raise RuntimeError('accepted UART FIFO retention proof does not retain at push')
        if row.get('disposition') not in ('retained', 'popped', 'cleared'):
            raise RuntimeError('accepted UART FIFO retention proof has an unknown disposition')
        if not _is_int(row.get('observation_event_id')) or not _is_int(
                row.get('push_event')):
            raise RuntimeError('accepted UART FIFO retention proof lacks real events')
        entry_ids[entry['index']] = list(row['entry_id'])
        retention_documents.append(_retention_document(row))

    read_documents = []
    route_bearing = (authority.get('schema_version') == 'dma_source_provenance.v2')
    for read in reads:
        entry_index = read['entry_index']
        if entry_index not in entry_ids:
            missing.append('uart_fifo_read_consumption:' + read['access_id'])
            continue
        matches = [row for row in accepted_reads
                   if row.get('access_id') == read['access_id']]
        if not matches:
            missing.append('uart_fifo_read_consumption:' + read['access_id'])
            continue
        if len(matches) > 1:
            raise RuntimeError('duplicate accepted UART FIFO read proof')
        row = matches[0]
        entry = entries[entry_index]
        admission = admission_map[entry['action_id']]
        _check_common(row, admission=admission, authority=authority,
                      entry_id=entry_ids[entry_index])
        if row.get('read_value') != entry['value']:
            raise RuntimeError('accepted UART FIFO read value differs from the entry')
        if row.get('route_context_mode') != read['route']:
            raise RuntimeError('accepted UART FIFO read route mode differs from the pop')
        if read['route'] not in _ROUTE_MODES:
            raise ValueError('unknown UART FIFO pop route mode')
        transaction = row.get('source_transaction')
        expected_channel = 'dma-memory' if read['route'] == 'dma_master' else 'data'
        if not isinstance(transaction, dict) or transaction.get('channel_id') != expected_channel:
            raise RuntimeError('accepted UART FIFO read carries the wrong channel')
        if route_bearing and read['route'] == 'dma_master':
            _validate_dma_master_route_match(row, read=read, authority=authority)
        for name in ('request_tick', 'response_tick', 'request_event',
                     'response_event', 'pop_event', 'access_event'):
            if not _is_int(row.get(name)):
                raise RuntimeError(
                    'accepted UART FIFO read proof lacks real ' + name)
        if row['request_tick'] > row['response_tick']:
            raise RuntimeError('accepted UART FIFO read response precedes its request')
        read_documents.append(_read_document(row))

    if len({read['access_id'] for read in reads}) != len(reads):
        raise ValueError('real FIFO pops must have unique access identities')
    if len({entry['frame_id'] for entry in entries}) != len(entries):
        raise ValueError('admitted FIFO entries must have unique frame identities')

    reasons = _incomplete_reasons(rows)
    schema = SCHEMA_V2 if route_bearing else SCHEMA
    if missing:
        return dict(schema_version=schema, fifo_origin=UNKNOWN,
            source_authority=INCOMPLETE, proof_grade=BOUNDED_CHAIN,
            reason=missing[0], missing=sorted(set(missing)),
            authority=_summary(authority),
            retention=retention_documents, reads=read_documents,
            incomplete_reasons=reasons)
    return dict(schema_version=schema, fifo_origin=ACCEPTED,
        source_authority=ACCEPTED, proof_grade=ACCEPTED_CHAIN, reason=None,
        missing=[], authority=_summary(authority),
        retention=retention_documents, reads=read_documents,
        incomplete_reasons=reasons)


__all__ = ['SCHEMA', 'ACCEPTED', 'UNKNOWN', 'INCOMPLETE', 'BOUNDED_CHAIN',
           'ACCEPTED_CHAIN', 'RETENTION_SCOPE', 'READ_SCOPE', 'MATCH_KIND',
           'source_authority_evidence']
