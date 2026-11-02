"""Native MMIO hop consumption for a row whose fetch identity is declared.

:func:`myfuzz.integration.native_mmio_hops.check_native_mmio_hops` consumes two
independent kinds of evidence: the *data* chain (an accepted native CPU beat ->
routed MMIO delivery -> native completion -> the later dependent RAM store) and
the *instruction* chain (one 4-byte ``memory_read`` per functional instruction
word, each joined to an accepted native fetch beat).

Two kinds of real CPU cannot be read that way, and this module covers both
without ever relaxing a check:

*no declared fetch identity*
    The packed single-port CVA6 used to be read like this: one packed AXI4
    master, ``ar.user``/``ar.prot`` tied to zero (see
    :mod:`myfuzz.integration.cva6_axi_mmio`), and fetch beats 8 bytes wide, so
    a beat could not be told apart as a fetch and could not be reported as the
    4-byte word read the instruction-hop contract expects.  Such a row gets the
    *data* chain only: same event journal, same transaction keys, same lane and
    strobe rules, same dependent XOR store and installed RAM snapshot, plus the
    refusal as a named, quoted reason.  This path is unchanged and is still the
    default for every row that carries no declaration.

*declared address-ID fetch identity*
    When the adapter's traces carry ``instruction_id_map`` (``{'arid': 0,
    'rid': 0, 'granule_bytes': 8, 'rsize': 3}`` for the pinned CVA6 WT
    configuration), a fetch is the accepted read whose **ARID** the map names
    and its response is the completing beat whose **RID** the map names.  Every
    granule of the materialized fragment then has to be observed on the bus, its
    real 8 bytes have to equal the case's own instruction-source bytes
    byte for byte, and each of the two 32-bit words it covers is reported with
    its own byte comparison.  The hop is refused when the map is absent: nothing
    here opens a hop by guessing, and no width is ever restated (the beat is
    reported as the 8-byte transfer it was).

Nothing in the data chain is weaker than the full row's check.  What is missing
on a data-only row is missing because the pins do not carry it, not because the
check was relaxed, and the certificate says which of the two scopes it is.
"""
from __future__ import annotations

from copy import deepcopy

from .native_obi_hops import F2ObservationMissing

#: One channel; the unified model numbers fetches and data beats together.
DATA_CHANNEL = 'memory'

#: ``arsize`` -> the byte width of that beat.  The pinned CVA6 I-cache issues
#: one non-cacheable beat per fetched granule at ``arsize = clog2(64/8) = 3``
#: (``core/cache_subsystem/cva6_icache_axi_wrapper.sv:87``), so the only
#: declared fetch width this reader accepts is the 8-byte one.
ID_GRANULE_WIDTHS = {3: 8}

#: Bytes per 32-bit instruction word, the unit the hop reports.
WORD_BYTES = 4


def _require_instruction_source(*, events, cpu, access, address, code,
                                source_event_id, error_prefix):
    """Authenticate that the declared fragment was installed at this address.

    This is the host-side half of the instruction story and it is real: the
    online-slot materialization journal event names the very bytes and the very
    source.  It says nothing about what the core fetched afterwards.
    """
    sources = [e for e in events if e.get('kind') == 'instruction_source'
               and e.get('component') == cpu
               and e.get('source_event_id') == source_event_id
               and e.get('address') == address
               and e.get('data_hex') == code.hex()]
    if len(sources) != 1:
        error = (ValueError if any(e.get('kind') == 'instruction_source'
                                   and e.get('component') == cpu
                                   and e.get('address') == address for e in events)
                 else F2ObservationMissing)
        raise error(error_prefix + '-instruction-source-missing')
    return sources[0]


def _verify_dependent_ram_store(*, declaration, data_hops, image, by_id,
                                ram_event_id, cpu, completed, result_snapshot,
                                native_field, xor_constant):
    """The full row's dependent-store check minus its instruction ordering.

    Every identity, version, byte-enable and snapshot rule is the shared one.
    The two orderings that remain provable are kept: the MMIO access completed
    before the store was accepted, and the store's own journal entry lies
    strictly between its acceptance and its completion.
    """
    from myfuzz.scenario.edge_provenance import _transaction_key
    result_address = declaration.get('result_address')
    value = data_hops[0]['value'] ^ xor_constant
    if declaration.get('xor_constant', 0) != xor_constant:
        raise ValueError('compiled-F2-dependent-XOR-mismatch')
    memory_range = image.get('range')
    if (not isinstance(memory_range, (list, tuple)) or len(memory_range) != 2
            or any(type(bound) is not int for bound in memory_range)
            or not 0 <= memory_range[0] <= memory_range[1] < 1 << 32
            or type(result_address) is not int or result_address < memory_range[0]
            or result_address + 3 > memory_range[1] or result_address % 4
            or type(value) is not int or not 0 <= value <= 0xffffffff
            or type(ram_event_id) is not int):
        raise ValueError('compiled-F2-result-RAM-hop-missing')
    ram_event = by_id.get(ram_event_id)
    if ram_event is None:
        raise F2ObservationMissing('compiled-F2-result-RAM-hop-missing')
    if (not isinstance(ram_event, dict) or ram_event.get('kind') != 'memory_write'
            or ram_event.get('component') != cpu
            or ram_event.get('memory_id') != image.get('port')
            or ram_event.get('address') != result_address
            or ram_event.get('value') != value
            or ram_event.get('byte_enable') != 15
            or ram_event.get('width_bytes') != 4
            or type(ram_event.get('generation')) is not int
            or ram_event['generation'] < 0
            or type(ram_event.get('byte_offset')) is not int
            or ram_event['byte_offset'] != result_address - memory_range[0]):
        raise ValueError('compiled-F2-result-RAM-hop-missing')
    version = ram_event.get('version')
    if (not isinstance(version, (list, tuple)) or len(version) != 2
            or any(type(item) is not int or item < 0 for item in version)
            or version[0] != ram_event['generation'] or version[1] < 1):
        raise ValueError('compiled-F2-result-RAM-version-mismatch')
    transaction = ram_event.get('transaction')
    if _transaction_key(transaction) is None:
        raise ValueError('compiled-F2-result-RAM-transaction-mismatch')
    read_transaction = data_hops[0]['source_transaction']
    if (transaction.get('channel_id') != DATA_CHANNEL
            or transaction.get('source_component') != cpu
            or transaction.get('source_epoch') != 0
            or any(transaction.get(key) != read_transaction.get(key)
                   for key in ('execution_id', 'testcase_id', 'source_component',
                               'source_epoch'))
            or transaction.get('source_sequence', -1)
            <= read_transaction.get('source_sequence', -1)):
        raise ValueError('compiled-F2-result-RAM-transaction-mismatch')
    ram_beat = completed.get(('data', transaction['source_sequence']))
    read_beat = data_hops[0][native_field]
    if ram_beat is None:
        raise F2ObservationMissing('compiled-F2-result-RAM-native-hop-missing')
    if (ram_beat['write'] != 1
            or ram_beat['address'] != result_address or ram_beat['value'] != value
            or ram_beat['byte_enable'] != 15
            or ram_event.get('producer_event_id') != ram_beat['acceptance_event']
            or ram_beat['acceptance_event'] <= read_beat['response_event']
            or not ram_beat['acceptance_event'] < ram_event_id < ram_beat['response_event']):
        raise ValueError('compiled-F2-result-RAM-native-hop-missing')
    if result_snapshot is None:
        raise F2ObservationMissing('compiled-F2-result-RAM-authoritative-snapshot-mismatch')
    from myfuzz.scenario.ledger import TransactionKey
    if (result_snapshot.data != value.to_bytes(4, 'little')
            or tuple(result_snapshot.versions) != (tuple(version),) * 4
            or result_snapshot.writer_event_ids != (str(TransactionKey(**transaction)),) * 4
            or result_snapshot.writer_kinds != ('STORE',) * 4):
        raise ValueError('compiled-F2-result-RAM-authoritative-snapshot-mismatch')
    return dict(memory_write_event=ram_event_id,
                producer_event_id=ram_event['producer_event_id'],
                memory_id=ram_event['memory_id'], generation=ram_event['generation'],
                byte_offset=ram_event['byte_offset'],
                width_bytes=ram_event['width_bytes'],
                address=ram_event['address'], value=ram_event['value'],
                byte_enable=ram_event['byte_enable'], version=list(version),
                transaction=deepcopy(transaction),
                native_acceptance_event=ram_beat['acceptance_event'],
                native_response_event=ram_beat['response_event'],
                **{native_field: dict(ram_beat)})


def _instruction_id_fields(instruction_id_map):
    """Validate one declared ``instruction_id_map``; never a default.

    The map is the *declaration*: ``arid``/``rid`` name the IDs the adapter
    proved from its own RTL, and ``granule_bytes``/``rsize`` name the single
    fetch width it proved the core issues.  A map that names anything else, or
    a width the pinned core cannot produce, is refused instead of coerced.
    """
    if not isinstance(instruction_id_map, dict):
        raise ValueError('MMIO-native-instruction-id-map')
    extra = set(instruction_id_map) - {'arid', 'rid', 'granule_bytes', 'rsize'}
    if extra:
        raise ValueError('MMIO-native-instruction-id-map')
    fields = {}
    for name in ('arid', 'rid', 'granule_bytes', 'rsize'):
        value = instruction_id_map.get(name)
        if type(value) is not int or value < 0:
            raise ValueError('MMIO-native-instruction-id-map')
        fields[name] = value
    if fields['arid'] > 0xf or fields['rid'] > 0xf:
        raise ValueError('MMIO-native-instruction-id-map')
    if ID_GRANULE_WIDTHS.get(fields['rsize']) != fields['granule_bytes']:
        raise ValueError('MMIO-native-instruction-id-granule')
    if fields['granule_bytes'] % WORD_BYTES:
        raise ValueError('MMIO-native-instruction-id-granule')
    return fields


def _id_instruction_hops(*, events, cpu, address, code, source, source_event_id,
                         completed, fields, image, instruction_snapshots,
                         error_prefix='MMIO-native'):
    """One hop per fetched granule, joined by the declared address IDs.

    Each hop reports the accepted ``AR`` event, the completing ``R`` event, the
    addressed granule, the 8 bytes that really came back, the two 32-bit words
    those bytes cover with a byte-for-byte comparison against the case's own
    materialized instruction source, and the ``memory_read`` journal entry that
    the host RAM service issued strictly between that acceptance and response.

    A granule is only accepted when every one of those facts holds.  The core
    may issue the same granule twice (the pinned adapter re-requests after a
    parked answer); both beats are reported rather than one being dropped, and
    the ``materialized_before_acceptance`` flag says whether the case's own
    instruction source already existed when the AR was accepted.
    """
    from myfuzz.scenario.edge_provenance import _transaction_key
    if not isinstance(code, bytes) or not code:
        raise ValueError(error_prefix + '-instruction-source-empty')
    granule = fields['granule_bytes']
    rsize = fields['rsize']
    arid, rid = fields['arid'], fields['rid']
    if len(code) % granule or address % granule:
        raise ValueError(error_prefix + '-instruction-id-granule')
    port = image.get('port')
    base = image['range'][0]
    generation = source.get('generation')
    # Only reads the declared identity names: an accepted AR with the declared
    # ID and the declared single-beat width.  A data beat cannot enter here,
    # which is exactly what the ID declaration buys.
    beats = [(key, beat) for key, beat in completed.items()
             if beat.get('write') == 0 and beat.get('id') == arid
             and beat.get('size') == rsize]
    hops = []
    for offset in range(0, len(code), granule):
        granule_address = address + offset
        want = code[offset:offset + granule]
        matched, superseded = [], []
        for key, beat in beats:
            if beat.get('address') != granule_address:
                continue
            if beat.get('rid') is not None and beat['rid'] != rid:
                raise ValueError(error_prefix + '-instruction-id-response')
            if beat.get('rdata') != int.from_bytes(want, 'little'):
                # The same address really was read with other bytes: keep the
                # observation, but it is not this case's fetch.
                superseded.append({'acceptance_event': beat['acceptance_event'],
                                   'response_event': beat['response_event'],
                                   'read_hex': int(beat['rdata']).to_bytes(
                                       granule, 'little').hex()})
                continue
            matched.append((key, beat))
        if not matched:
            contradictory = any(e.get('kind') == 'memory_read'
                                and e.get('component') == cpu
                                and e.get('address') == granule_address
                                for e in events)
            raise (ValueError if contradictory else F2ObservationMissing)(
                error_prefix + '-instruction-id-hop-missing')
        reads = [e for e in events if e.get('kind') == 'memory_read'
                 and e.get('component') == cpu
                 and e.get('address') == granule_address]
        own = [e for e in reads if e.get('data_hex') == want.hex()]
        if not own:
            raise F2ObservationMissing(
                error_prefix + '-instruction-id-read-missing')
        observed = []
        for key, beat in matched:
            inside = [e for e in own
                      if beat['acceptance_event'] <= e.get('producer_event_id', -1)
                      < beat['response_event']]
            if len(inside) != 1:
                raise ValueError(error_prefix + '-instruction-id-read-join')
            read = inside[0]
            transaction = read.get('transaction') or {}
            versions = read.get('versions')
            if (_transaction_key(transaction) is None
                    or transaction.get('channel_id') != DATA_CHANNEL
                    or transaction.get('source_component') != cpu
                    or key != ('data', transaction.get('source_sequence'))
                    or read.get('memory_id') != port
                    or read.get('generation') != generation
                    or read.get('byte_offset') != granule_address - base
                    or read.get('width_bytes') != granule
                    or read.get('value') != int.from_bytes(want, 'little')
                    or not (beat['acceptance_event']
                            <= read.get('producer_event_id', -1)
                            < beat['response_event'])
                    or not isinstance(versions, (list, tuple))
                    or len(versions) != granule
                    or any(type(v) not in (list, tuple) or len(v) != 2
                           or any(type(n) is not int or n < 0 for n in v)
                           or v[0] != generation or v[1] < 1 for v in versions)
                    or any(list(v) != list(versions[0]) for v in versions)
                    or tuple(read.get('writer_event_ids') or ())
                    != (source_event_id,) * granule
                    or tuple(read.get('writer_kinds') or ())
                    != ('INSTRUCTION_SOURCE',) * granule):
                raise ValueError(error_prefix + '-instruction-id-read-identity')
            observed.append({
                'acceptance_event': beat['acceptance_event'],
                'response_event': beat['response_event'],
                'memory_read_event': read['event_id'],
                'memory_read_transaction': deepcopy(transaction),
                'materialized_before_acceptance':
                    beat['acceptance_event'] > source['event_id'],
                'read_hex': want.hex(),
                'versions': [list(v) for v in versions],
            })
        # The 8 bytes that really came back, and the two 32-bit words they
        # cover, each compared byte for byte with this case's source word.
        fetched = int(matched[0][1]['rdata']).to_bytes(granule, 'little')
        first = observed[0]
        words = []
        for index in range(granule // WORD_BYTES):
            low = index * WORD_BYTES
            word_address = granule_address + low
            source_word = want[low:low + WORD_BYTES]
            fetched_word = fetched[low:low + WORD_BYTES]
            match = [fetched_word[i] == source_word[i]
                     for i in range(WORD_BYTES)]
            word = {'index': index, 'address': word_address,
                    'byte_offset': offset + low,
                    'source_word_hex': source_word.hex(),
                    'fetched_word_hex': fetched_word.hex(),
                    'bytes_match': match}
            snapshot = None
            if instruction_snapshots is not None:
                index_into = (offset + low) // WORD_BYTES
                snapshots = tuple(instruction_snapshots)
                if index_into < len(snapshots):
                    snapshot = snapshots[index_into]
            if snapshot is not None:
                word_versions = first['versions'][low:low + WORD_BYTES]
                if (snapshot.data != source_word
                        or snapshot.byte_offset != word_address - base
                        or tuple(snapshot.writer_event_ids)
                        != (source_event_id,) * WORD_BYTES
                        or snapshot.writer_kinds != ('INSTRUCTION_SOURCE',) * WORD_BYTES
                        or [list(v) for v in snapshot.versions] != word_versions):
                    raise ValueError(
                        error_prefix + '-instruction-authoritative-version')
                word['authoritative_snapshot'] = 'checked'
                word['versions'] = word_versions
            else:
                word['authoritative_snapshot'] = 'not-in-declared-window'
            words.append(word)
        if not all(all(word['bytes_match']) for word in words):
            raise ValueError(error_prefix + '-instruction-id-granule-bytes')
        hops.append({
            'kind': 'address_id_granule',
            'granule_index': offset // granule,
            'granule_address': granule_address,
            'granule_bytes': granule,
            'granule_hex': want.hex(),
            'fetched_hex': fetched.hex(),
            'arsize': rsize, 'arlen': 0, 'arid': arid, 'rid': rid,
            'instruction_source_event': source['event_id'],
            'instruction_source_id': source_event_id,
            'instruction_source_byte_offset': offset,
            'acceptance_event': first['acceptance_event'],
            'response_event': first['response_event'],
            'memory_read_event': first['memory_read_event'],
            'native_beats': observed,
            'superseded_same_address_beats': superseded,
            'instruction_words': words,
            'bytes_match': True,
        })
    return hops


def check_native_mmio_data_hops(*, events, declaration, image, stream, address,
                                source_event_id, joins, instruction_snapshots,
                                ram_event_id, result_snapshot, cpu_adapter, flow,
                                refusal=None, instruction_id_map=None):
    """Consume the real native data chain plus the declared instruction scope.

    Exactly one scope is passed and it is never chosen here:

    * ``refusal`` (a quoted reason, RTL locations included) means the row has no
      fetch identity: ``instruction_hops`` stays empty and the refusal is copied
      into the returned document and into the certificate;
    * ``instruction_id_map`` means the adapter *declared* the address IDs that
      mark a fetch: the hops are built from those beats only, and the map itself
      is echoed so a reader can check the IDs against the adapter's evidence.

    Passing both (or neither) is a contradiction and is refused.
    """
    from myfuzz.scenario.edge_provenance import _transaction_key
    traces = getattr(cpu_adapter, 'traces', None)
    if not isinstance(traces, dict):
        raise ValueError('MMIO-native-trace-required')
    if refusal is not None and type(refusal) is not str:
        raise ValueError('MMIO-native-instruction-hop-refusal-required')
    if refusal is None and instruction_id_map is None:
        raise ValueError('MMIO-native-instruction-scope-required')
    if refusal is not None and instruction_id_map is not None:
        raise ValueError('MMIO-native-instruction-scope-conflict')
    fields = (None if instruction_id_map is None
              else _instruction_id_fields(instruction_id_map))
    cpu = image['component']
    access = stream['register_access']
    by_id = {e['event_id']: e for e in events}
    if len(by_id) != len(events):
        raise ValueError('MMIO-duplicate-native-event')
    source = _require_instruction_source(events=events, cpu=cpu, access=access,
        address=address, code=bytes.fromhex(declaration['code_hex']),
        source_event_id=source_event_id, error_prefix='MMIO-native')
    if len(joins) != (2 if flow == 'F4' else 1):
        raise ValueError('MMIO-route-joins')
    completed = cpu_adapter.completed_beats(events, cpu)
    transaction = by_id[joins[0]['delivery_event']]['source_transaction']
    data = []
    for join in joins:
        delivery = by_id[join['delivery_event']]
        accepted = by_id[join['acceptance_event']]
        key = delivery['source_transaction']
        beat = completed.get(('data', key['source_sequence']))
        if (_transaction_key(key) is None
                or any(key[k] != transaction[k] for k in
                       ('execution_id', 'testcase_id', 'source_component', 'source_epoch'))
                or key['source_component'] != cpu or key['source_epoch'] != 0
                or key['channel_id'] != DATA_CHANNEL
                or accepted.get('source_transaction') != key
                or accepted.get('component') != cpu
                or accepted.get('device_id') != access['device_id']
                or delivery.get('device_id') != access['device_id']
                or delivery.get('offset') != access['register_offset']
                or beat is None
                or beat['acceptance_event'] != accepted['producer_event_id']
                or beat['address'] != access['address']
                or beat['write'] != int(delivery['write'])
                or delivery.get('byte_enable') != 15
                or (delivery['write'] and (beat['value'] != join['value']
                                          or beat['byte_enable'] != 15))
                or (not delivery['write'] and beat['rdata'] != join['value'])
                or not accepted['event_id'] < delivery['event_id'] < beat['response_event']):
            raise ValueError('MMIO-native-CPU-data-route')
        data.append(dict(join, native_acceptance_event=beat['acceptance_event'],
                         native_response_event=beat['response_event'],
                         native_cpu=deepcopy(beat)))
    ram = _verify_dependent_ram_store(declaration=declaration, data_hops=[data[-1]],
        image=image, by_id=by_id, ram_event_id=ram_event_id, cpu=cpu,
        completed=completed, result_snapshot=result_snapshot,
        native_field='native_cpu', xor_constant=0 if flow == 'F4' else 0x5a5)
    if fields is None:
        hops, scope, document = [], (
            'actual_CPU_native_MMIO_data_route_native_target_and_return_'
            'dependent_RAM_no_internal_version_no_instruction_hop'), {}
    else:
        hops = _id_instruction_hops(events=events, cpu=cpu, address=address,
            code=bytes.fromhex(declaration['code_hex']), source=source,
            source_event_id=source_event_id, completed=completed, fields=fields,
            image=image, instruction_snapshots=instruction_snapshots)
        scope = ('actual_CPU_native_MMIO_data_route_native_target_and_return_'
                 'dependent_RAM_declared_address_id_fetch_hop_no_internal_version')
        beats = [beat for hop in hops for beat in hop['native_beats']]
        words = [word for hop in hops for word in hop['instruction_words']]
        document = {
            'instruction_id_map': dict(fields),
            # Every claim below is a count of what the beats themselves showed.
            'instruction_coverage': {
                'granules': len(hops),
                'granule_bytes': fields['granule_bytes'],
                'bytes': len(hops) * fields['granule_bytes'],
                'words': len(words),
                'words_with_authoritative_snapshot': len(
                    [word for word in words
                     if word['authoritative_snapshot'] == 'checked']),
                'native_beats': len(beats),
                'materialized_before_acceptance': len(
                    [beat for beat in beats if beat['materialized_before_acceptance']]),
                'superseded_same_address_beats': len(
                    [row for hop in hops for row in hop['superseded_same_address_beats']]),
            },
            'instruction_hop_scope': {
                'identity': 'declared ARID/RID map of this adapter, echoed above',
                'width': 'the beat is reported as the '
                         + str(fields['granule_bytes'])
                         + '-byte transfer it was, never restated as a 4-byte word',
                'ordering': 'each memory_read lies strictly between its own '
                            'accepted AR and its R response; no order between a '
                            'word fetch and the MMIO access is claimed, because '
                            'the core prefetches ahead',
                'not_claimed': 'instruction retirement and DUT-internal storage '
                               'version stay unknown',
            },
        }
    return dict(schema_version='native_CPU_MMIO_data_hops.v1',
        native_protocol=cpu_adapter.protocol,
        proof_scope=scope,
        instruction_hops=hops,
        **({'instruction_hop_refusal': refusal} if refusal is not None else {}),
        **document,
        instruction_source_event=source['event_id'],
        instruction_snapshots=len(tuple(instruction_snapshots or ())),
        data_hops=data, ram_write_hop=ram,
        instruction_retirement='unknown',
        internal_storage_version='unknown',
        cross_case_origin='unknown')
