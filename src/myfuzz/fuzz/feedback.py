"""Feature feedback for the closed-loop in-process fuzzer.

The unified in-process executor prints one ``case`` line per flow.  A line is a
flat set of key/value observations; :func:`parse_case_line` turns it into a
dictionary whose values are ints (hex or decimal) or strings.  This module maps
that dictionary onto a small, hashable, *bounded* feature vocabulary so a
fuzzer can compare two runs, and remembers which features have already been
seen.

Two rules shape every extraction:

* **Absence is unknown, not zero.**  A key the case line does not carry yields
  no feature; a string such as ``unknown`` never becomes a number.
* **Values are normalised.**  Raw counters are bucketed and raw words are
  classified, so a feature identifies a kind of observation instead of one
  arbitrary counter value.  The few exact values kept (the register write mask,
  the changed-data hash, the DMA destination hash, ...) are the ones whose
  identity is the discovery.

The module is pure: no file I/O, no clock, no randomness.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ['COUNTER_KEYS', 'FLOWS', 'FEATURE_SCHEMA', 'CaseFeedback',
           'FeedbackState', 'bucket', 'value_class']

#: Version tag of the :meth:`FeedbackState.document` payload.
FEATURE_SCHEMA = 'inprocess_fuzz_features.v1'
#: A hard vocabulary bound: a feature whose value is effectively unique per case
#: (for example an exact destination hash) must not grow the set without limit.
DEFAULT_MAX_FEATURES = 8192
#: How many features are embedded in the JSON document; the rest stay counted.
FEATURE_SAMPLE_LIMIT = 2048

#: The flows the unified executor runs, in order.
FLOWS = ('F1', 'F2', 'F3', 'F4', 'F5', 'F6')

#: The bounded bus/CPU counters a case line may carry (the executor's
#: ``CASE_COUNTER_KEYS``).  An absent counter is unknown, never zero.
COUNTER_KEYS = ('i_fetches', 'd_reads', 'd_writes', 'apb_reads', 'apb_writes',
                'retires', 'rvfi_writebacks', 'rvfi_order_monotonic', 'traps',
                'bus_errors')

#: Counter buckets, in ascending order of the counts they describe.
_COUNTER_BUCKETS = (('0', 0), ('1', 1), ('2-4', 4), ('5-8', 8), ('9-16', 16))

#: FNV-1a constants for the destination-block hash.
_FNV_OFFSET_BASIS = 0x811C9DC5
_FNV_PRIME = 0x01000193

_ALL_ONES = 0xFFFFFFFF
_HIGH_BIT = 0x80000000


def bucket(count) -> str:
    """The bounded bucket of one observed counter; non-ints are ``unknown``."""
    if type(count) is not int:
        return 'unknown'
    if count <= 0:
        return '0'
    for name, limit in _COUNTER_BUCKETS:
        if count <= limit:
            return name
    return '17+'


def value_class(value) -> str:
    """The class of one observed word; non-ints are ``unknown``.

    ``all-ones`` wins over ``high`` because ``0xffffffff`` satisfies both, and
    ``zero``/``one`` win over ``small`` for the same reason.
    """
    if type(value) is not int:
        return 'unknown'
    if value == _ALL_ONES:
        return 'all-ones'
    if value == 0:
        return 'zero'
    if value == 1:
        return 'one'
    if 0 <= value < 256:
        return 'small'
    if value >= _HIGH_BIT:
        return 'high'
    return 'other'


def _as_int(value):
    """The value when the parsed case line really carried an integer.

    Numeric strings are not reparsed: :func:`parse_case_line` already did that,
    and a token it left as a string (``unknown``) is not a number.
    """
    return value if type(value) is int else None


def _first_int(case, *keys):
    """The first key present as an integer, or ``None``.

    The executor prints one target counter under the protocol's own word, so
    the neutral name and the APB3 spelling are both accepted.
    """
    for key in keys:
        number = _as_int(case.get(key))
        if number is not None:
            return number
    return None


def _capped(number, limit):
    return max(0, min(limit, number))


def _fnv1a32(words):
    """A stable 32-bit FNV-1a digest over 32-bit words (little-endian bytes)."""
    digest = _FNV_OFFSET_BASIS
    for word in words:
        word &= _ALL_ONES
        for shift in (0, 8, 16, 24):
            digest ^= (word >> shift) & 0xFF
            digest = (digest * _FNV_PRIME) & _ALL_ONES
    return digest


def _feature_order(feature):
    """A total order over feature tuples whose members may mix ints and strs."""
    return tuple((0, part) if type(part) is int else (1, str(part))
                 for part in feature)


# ---------------------------------------------------------------------------
# Per-flow extraction
# ---------------------------------------------------------------------------
def _f1_features(case):
    features = []
    for key, name in (('prog_words', 'words'),
                      ('prog_retires', 'retires'),
                      ('prog_pc_ordered', 'pc_ordered'),
                      ('prog_insns_match', 'insns_match'),
                      ('prog_rd_mask', 'rd_mask'),
                      ('prog_last_rd', 'last_rd'),
                      ('prog_traps', 'traps'),
                      ('data_changed', 'data_changed')):
        value = _as_int(case.get(key))
        if value is not None:
            features.append(('F1', name, value))
    last_wdata = _as_int(case.get('prog_last_wdata'))
    if last_wdata is not None:
        features.append(('F1', 'last_wdata_class', value_class(last_wdata)))
    changed = _as_int(case.get('data_changed'))
    if changed is not None and changed != 0:
        # Only the post-case hash says what appeared; with an unchanged window
        # the before/after hashes are the same value and discover nothing new.
        data_hash = _as_int(case.get('data_hash_after'))
        if data_hash is not None:
            features.append(('F1', 'data_hash', data_hash))
    return features


def _f2_features(case):
    features = []
    read_from = case.get('read_from')
    if type(read_from) is str and read_from and read_from != 'unknown':
        features.append(('F2', 'read_from', read_from))
    read_addr = _as_int(case.get('read_addr'))
    if read_addr is not None:
        features.append(('F2', 'read_addr', read_addr))
    target_reads = _first_int(case, 'target_reads', 'apb_reads')
    if target_reads is not None:
        features.append(('F2', 'target_reads', bucket(target_reads)))
    read_value = _as_int(case.get('read_value'))
    if read_value is not None:
        features.append(('F2', 'value_class', value_class(read_value)))
    echo_value = _as_int(case.get('echo_value'))
    if read_value is not None and echo_value is not None:
        # A committed echo is the stored word read back; anything else lost it.
        echo = 'committed' if echo_value == read_value else 'lost'
        features.append(('F2', 'echo', echo))
    stimulus = case.get('pin_stimulus')
    if stimulus in ('applied', 'declared_default'):
        features.append(('F2', 'pin_stimulus', stimulus))
    return features


def _f3_features(case):
    features = []
    write_addr = _as_int(case.get('write_addr'))
    if write_addr is not None:
        features.append(('F3', 'write_addr', write_addr))
    write_value = _as_int(case.get('write_value'))
    if write_value is not None:
        features.append(('F3', 'value_class', value_class(write_value)))
    ram_after = _as_int(case.get('ram_after'))
    if write_value is not None and ram_after is not None:
        committed = 'yes' if ram_after == write_value else 'no'
        features.append(('F3', 'ram_committed', committed))
    # The executor spells the byte-enable field ``write_be``.
    write_be = _as_int(case.get('write_be'))
    if write_be is not None:
        features.append(('F3', 'be', write_be))
    return features


def _f4_features(case):
    features = []
    target_offset = _first_int(case, 'target_offset', 'apb_offset')
    if target_offset is not None:
        features.append(('F4', 'target_offset', target_offset))
    mmio_value = _as_int(case.get('mmio_value'))
    if mmio_value is not None:
        features.append(('F4', 'value_class', value_class(mmio_value)))
    target_writes = _first_int(case, 'target_writes', 'apb_writes')
    if target_writes is not None:
        features.append(('F4', 'target_writes', bucket(target_writes)))
    # An AXI4-Lite build prints the response code only for a completed channel.
    target_resp = _as_int(case.get('target_resp'))
    if target_resp is not None:
        features.append(('F4', 'target_resp', target_resp))
    # Pin-only facts: a target without the pin endpoint prints neither.
    for key in ('out_after', 'dir_after'):
        value = _as_int(case.get(key))
        if value is not None:
            features.append(('F4', key, value))
    return features


def _f5_features(case):
    features = []
    irq_edges = _as_int(case.get('irq_edges'))
    if irq_edges is not None:
        features.append(('F5', 'irq_edges', _capped(irq_edges, 3)))
    irq_takes = _as_int(case.get('irq_takes'))
    if irq_takes is not None:
        features.append(('F5', 'irq_takes', _capped(irq_takes, 2)))
    status = _first_int(case, 'apb_read_data', 'target_read_data')
    if status is not None:
        features.append(('F5', 'status_class', value_class(status)))
    kind = case.get('isr_read_register_kind')
    if type(kind) is str and kind and kind != 'unknown':
        features.append(('F5', 'isr_kind', kind))
    # Pin-only facts: the cause bit and the enable mask are sampled together.
    cause_pins = _as_int(case.get('irq_cause_pins'))
    inten = _as_int(case.get('inten_at_irq'))
    if cause_pins is not None and inten is not None:
        enabled = 'yes' if cause_pins & inten else 'no'
        features.append(('F5', 'cause_enabled', enabled))
    return features


def _f6_features(case):
    features = []
    dma_reads = _as_int(case.get('dma_reads'))
    if dma_reads is not None:
        features.append(('F6', 'dma_reads', bucket(dma_reads)))
    dma_writes = _as_int(case.get('dma_writes'))
    if dma_writes is not None:
        features.append(('F6', 'dma_writes', bucket(dma_writes)))
    ctl_status = _as_int(case.get('ctl_status'))
    if ctl_status is not None:
        features.append(('F6', 'status_class', value_class(ctl_status)))
    busy_after = _as_int(case.get('busy_after'))
    if busy_after is not None:
        features.append(('F6', 'busy_after', busy_after))
    err_after = _as_int(case.get('err_after'))
    if err_after is not None:
        features.append(('F6', 'err_after', err_after))
    irq_takes = _as_int(case.get('irq_takes'))
    if irq_takes is not None:
        features.append(('F6', 'irq_takes', _capped(irq_takes, 2)))
    destinations = [_as_int(case.get(f'dst{index}')) for index in range(4)]
    if all(value is not None for value in destinations):
        features.append(('F6', 'dst_hash', _fnv1a32(destinations)))
    return features


_FLOW_FEATURES = {'F1': _f1_features, 'F2': _f2_features, 'F3': _f3_features,
                  'F4': _f4_features, 'F5': _f5_features, 'F6': _f6_features}


def _extract(case, flow, failed):
    """Every feature the case line supports, deduplicated and ordered."""
    features = []
    if failed:
        # A passing case contributes no status feature at all.
        features.append(('status', flow, 'failed'))
    for key in COUNTER_KEYS:
        count = _as_int(case.get(key))
        if count is not None:
            features.append(('count', key, bucket(count)))
    features.extend(_FLOW_FEATURES[flow](case))
    return tuple(sorted(dict.fromkeys(features), key=_feature_order))


# ---------------------------------------------------------------------------
# Human summaries
# ---------------------------------------------------------------------------
def _f1_summary(case):
    words = _as_int(case.get('prog_words'))
    retires = _as_int(case.get('prog_retires'))
    parts = []
    if words is not None:
        head = f'program {words} words'
        if retires is not None:
            head += f' retired {retires}'
        parts.append(head)
    elif retires is not None:
        parts.append(f'retired {retires}')
    rd_mask = _as_int(case.get('prog_rd_mask'))
    if rd_mask is not None:
        parts.append(f'rd_mask 0x{rd_mask & _ALL_ONES:08x}')
    data_changed = _as_int(case.get('data_changed'))
    if data_changed is not None:
        parts.append(f'data_changed {data_changed}')
    traps = _as_int(case.get('prog_traps'))
    if traps is not None:
        parts.append(f'traps {traps}')
    return 'F1 ' + ', '.join(parts) if parts else None


def _f2_summary(case):
    read_from = case.get('read_from')
    source = read_from if type(read_from) is str and read_from != 'unknown' else None
    read_addr = _as_int(case.get('read_addr'))
    parts = []
    if read_addr is not None:
        prefix = source + ' ' if source else ''
        parts.append(f'{prefix}read offset 0x{read_addr:x}')
    elif source:
        parts.append(f'{source} read')
    read_value = _as_int(case.get('read_value'))
    if read_value is not None:
        parts.append(f'value class {value_class(read_value)}')
    echo_value = _as_int(case.get('echo_value'))
    if read_value is not None and echo_value is not None:
        parts.append('echo committed' if echo_value == read_value else 'echo lost')
    stimulus = case.get('pin_stimulus')
    if stimulus in ('applied', 'declared_default'):
        parts.append(f'pin_stimulus {stimulus}')
    return 'F2 ' + ' '.join(parts) if parts else None


def _f3_summary(case):
    parts = []
    write_addr = _as_int(case.get('write_addr'))
    if write_addr is not None:
        parts.append(f'write offset 0x{write_addr:x}')
    write_value = _as_int(case.get('write_value'))
    if write_value is not None:
        parts.append(f'value class {value_class(write_value)}')
    write_be = _as_int(case.get('write_be'))
    if write_be is not None:
        parts.append(f'be {write_be}')
    ram_after = _as_int(case.get('ram_after'))
    if write_value is not None and ram_after is not None:
        committed = 'yes' if ram_after == write_value else 'no'
        parts.append(f'ram committed {committed}')
    return 'F3 ' + ' '.join(parts) if parts else None


def _f4_summary(case):
    parts = []
    target_offset = _first_int(case, 'target_offset', 'apb_offset')
    if target_offset is not None:
        parts.append(f'target write offset 0x{target_offset:x}')
    mmio_value = _as_int(case.get('mmio_value'))
    if mmio_value is not None:
        parts.append(f'value class {value_class(mmio_value)}')
    target_writes = _first_int(case, 'target_writes', 'apb_writes')
    if target_writes is not None:
        parts.append(f'target writes {target_writes}')
    target_resp = _as_int(case.get('target_resp'))
    if target_resp is not None:
        parts.append(f'target_resp {target_resp}')
    for key in ('out_after', 'dir_after'):
        value = _as_int(case.get(key))
        if value is not None:
            parts.append(f'{key} 0x{value:x}')
    return 'F4 ' + ' '.join(parts) if parts else None


def _f5_summary(case):
    parts = []
    irq_edges = _as_int(case.get('irq_edges'))
    if irq_edges is not None:
        parts.append(f'irq edges {_capped(irq_edges, 3)}')
    irq_takes = _as_int(case.get('irq_takes'))
    if irq_takes is not None:
        parts.append(f'takes {_capped(irq_takes, 2)}')
    status = _first_int(case, 'apb_read_data', 'target_read_data')
    if status is not None:
        parts.append(f'status 0x{status:x}')
    kind = case.get('isr_read_register_kind')
    if type(kind) is str and kind and kind != 'unknown':
        parts.append(f'isr kind {kind}')
    cause_pins = _as_int(case.get('irq_cause_pins'))
    inten = _as_int(case.get('inten_at_irq'))
    if cause_pins is not None and inten is not None:
        parts.append(f'cause enabled {"yes" if cause_pins & inten else "no"}')
    return 'F5 ' + ' '.join(parts) if parts else None


def _f6_summary(case):
    parts = []
    for key in ('dma_reads', 'dma_writes'):
        value = _as_int(case.get(key))
        if value is not None:
            parts.append(f'{key} {value}')
    ctl_status = _as_int(case.get('ctl_status'))
    if ctl_status is not None:
        parts.append(f'status 0x{ctl_status:x}')
    for key in ('busy_after', 'err_after', 'irq_takes'):
        value = _as_int(case.get(key))
        if value is not None:
            parts.append(f'{key} {value}')
    destinations = [_as_int(case.get(f'dst{index}')) for index in range(4)]
    if all(value is not None for value in destinations):
        parts.append(f'dst_hash 0x{_fnv1a32(destinations):08x}')
    return 'F6 ' + ' '.join(parts) if parts else None


_FLOW_SUMMARIES = {'F1': _f1_summary, 'F2': _f2_summary, 'F3': _f3_summary,
                   'F4': _f4_summary, 'F5': _f5_summary, 'F6': _f6_summary}


def _summarise(flow, status, case):
    text = _FLOW_SUMMARIES[flow](case)
    if text is not None:
        return text
    # No flow-specific fact: name the bounded counters still observed, so the
    # line is not silently empty when the target printed only bus traffic.
    counters = []
    for key in COUNTER_KEYS:
        count = _as_int(case.get(key))
        if count is not None:
            counters.append(f'{key} {count}')
        if len(counters) == 4:
            break
    if counters:
        return flow + ' ' + ' '.join(counters)
    return f'{flow} {status} with no recognised observation'


# ---------------------------------------------------------------------------
# Feedback records and state
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class CaseFeedback:
    """The feedback of one observed case line."""

    index: int
    flow: str
    status: str
    #: Every feature this case provides, deduplicated and stably ordered.
    features: tuple[tuple, ...]
    #: The subset of ``features`` that no earlier case had provided.
    new: tuple[tuple, ...]
    #: One compact, deterministic sentence of the observed facts.
    summary: str
    #: ``True`` only when the case line said ``failed``.
    failed: bool


class FeedbackState:
    """The bounded set of features discovered by one fuzzing session.

    ``max_features`` caps the vocabulary: once it is full, newly seen features
    are counted as observed but not retained, so a long batch cannot grow the
    set (and therefore the process RSS) linearly.  The document keeps an exact
    ``distinct``/``by_family`` summary and only a bounded feature sample.
    """

    __slots__ = ('_discovered', '_max_features', '_observed', '_truncated')

    def __init__(self, max_features: int = DEFAULT_MAX_FEATURES) -> None:
        if type(max_features) is not int or max_features < 1:
            raise ValueError('max_features must be a positive integer')
        self._discovered: set[tuple] = set()
        self._max_features = max_features
        self._observed = 0
        self._truncated = False

    def observe(self, case: dict) -> CaseFeedback:
        """Record one parsed case line and report its new features.

        The input dictionary is read, never mutated.  A non-dict, a missing
        ``flow`` or a flow outside ``F1..F6`` is refused by name.
        """
        if not isinstance(case, dict):
            raise ValueError('feedback observation must be a dict')
        flow = case.get('flow')
        if flow is None:
            raise ValueError('feedback observation lacks a flow tag')
        if flow not in FLOWS:
            raise ValueError('unsupported feedback flow: ' + str(flow))
        status = case.get('status')
        if type(status) is not str:
            status = 'unknown'
        failed = status == 'failed'
        index = _as_int(case.get('index'))
        if index is None:
            index = -1
        features = _extract(case, flow, failed)
        self._observed += len(features)
        candidates = tuple(feature for feature in features
                           if feature not in self._discovered)
        room = self._max_features - len(self._discovered)
        if room <= 0:
            self._truncated = True
            new = ()
        else:
            new = candidates[:room]
            self._discovered.update(new)
            if len(candidates) > room:
                self._truncated = True
        return CaseFeedback(index=index, flow=flow, status=status,
                            features=features, new=new,
                            summary=_summarise(flow, status, case),
                            failed=failed)

    @property
    def discovered(self) -> frozenset[tuple]:
        """Every feature observed so far."""
        return frozenset(self._discovered)

    def document(self) -> dict:
        """The discovered features as a stable, JSON-serialisable document."""
        ordered = sorted(self._discovered, key=_feature_order)
        by_family: dict[str, int] = {}
        for feature in ordered:
            family = feature[0]
            by_family[family] = by_family.get(family, 0) + 1
        sample = ordered[:FEATURE_SAMPLE_LIMIT]
        return {
            'schema_version': FEATURE_SCHEMA,
            'distinct': len(ordered),
            'features_observed': self._observed,
            'features_retained': len(ordered),
            'features_truncated': self._truncated,
            'features_sampled': len(sample),
            'features': [{'feature': list(feature)} for feature in sample],
            'by_family': by_family,
        }
