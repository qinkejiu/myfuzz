"""Typed fresh-replay normalizer: declared rules, never whole-document rewriting.

A fresh replay runs the same recorded command prefix on brand new native
processes, so only the *execution identities* legitimately differ.  This module
declares, per field and per event type, exactly which strings may be rewritten
and which fields must survive unchanged.  Anything not named in
:data:`NORMALIZER_RULES` is retained byte for byte.

A whole-JSON ``str.replace`` of the old execution UUID is expressly not a
rewrite rule: it silently alters payload bytes, addresses, ticks and frame
identities that happen to contain the same substring, so a replay can be made
to "match" by erasing real differences.  :func:`normalize_execution_identities`
never does that, and :func:`first_difference` reports the first real difference
with its path instead of collapsing the comparison to one boolean.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re
from types import MappingProxyType

NORMALIZER_SCHEMA = 'typed_replay_normalizer.v1'
EXECUTION_ROLES = ('cpu', 'dma', 'uart', 'runner')
EXECUTION_TOKEN_PREFIX = 'execution:'
_UUID = re.compile(r'[0-9a-f]{32}\Z')
_TRANSACTION_KEY = re.compile(
    r"TransactionKey\(execution_id='([0-9a-f]{32})', (.*)\)")
_STATE_EDGE_KIND = 'state_dependency'
_STATE_EDGE_FIELDS = ('source', 'target')
_STATE_EDGE_REQUIRED = frozenset(('event_id', 'producer_event_id', 'edge_kind',
    'memory_id', 'generation', 'byte_offset', 'version', 'source', 'target'))


@dataclass(frozen=True)
class NormalizerRule:
    """One declared rewrite rule of the typed normalizer.

    ``scope`` is one of ``field`` (a value whose dict key is ``field``),
    ``state_edge_endpoint`` (the ``source``/``target`` of a canonical
    ``state_dependency`` journal root record) or ``ledger_reference`` (a value
    stored by the transaction ledger, where only a leading
    ``TransactionKey(execution_id=...)`` token is rewritten).
    """

    name: str
    scope: str
    fields: tuple[str, ...]
    action: str
    retained: bool = False

    def __post_init__(self):
        if self.scope not in ('field', 'state_edge_endpoint', 'ledger_reference'):
            raise ValueError('unknown normalizer rule scope')
        if self.action not in ('execution_identity', 'transaction_execution_prefix',
                               'state_dependency_endpoint'):
            raise ValueError('unknown normalizer rule action')
        if (not isinstance(self.fields, tuple) or not self.fields
                or not all(isinstance(field, str) and field for field in self.fields)):
            raise ValueError('normalizer rule needs declared fields')
        if self.retained:
            raise ValueError('a rewrite rule cannot also be a retained field')


#: The complete declared rewrite table.  Every normalizable field appears here;
#: there is no catch-all rule and no regular expression applied to whole
#: documents.
NORMALIZER_RULES = (
    NormalizerRule('execution_value', 'field', ('execution',),
                   'execution_identity'),
    NormalizerRule('execution_id_value', 'field', ('execution_id',),
                   'execution_identity'),
    NormalizerRule('state_edge_endpoint', 'state_edge_endpoint',
                   _STATE_EDGE_FIELDS, 'state_dependency_endpoint'),
    NormalizerRule('ledger_writer', 'field', ('writer_event_id',),
                   'transaction_execution_prefix'),
    NormalizerRule('ledger_writers', 'field', ('writer_event_ids',),
                   'transaction_execution_prefix'),
    NormalizerRule('ledger_pending_before', 'field',
                   ('pending_before_finalize',),
                   'transaction_execution_prefix'),
    NormalizerRule('ledger_pending_after', 'field',
                   ('pending_after_finalize',),
                   'transaction_execution_prefix'),
    NormalizerRule('ledger_uncertain', 'field', ('uncertain_transactions',),
                   'transaction_execution_prefix'),
    # Source-provenance diagnostics carry the same ledger transaction key in a
    # list of unresolved writer references; only its leading execution token is
    # process-local and may be rewritten.
    NormalizerRule('provenance_unknown_writers', 'field',
                   ('unknown_writer_ids',),
                   'transaction_execution_prefix'),
)
RULES_BY_NAME = MappingProxyType({rule.name: rule for rule in NORMALIZER_RULES})
#: One value-level rule lookup used by the walker: ``field -> rule``.
FIELD_RULES = MappingProxyType({
    field: rule for rule in NORMALIZER_RULES if rule.scope == 'field'
    for field in rule.fields})
STATE_EDGE_RULE = RULES_BY_NAME['state_edge_endpoint']

#: Fields that must survive a fresh comparison unchanged.  This positive list
#: is the audit counterpart of ``NORMALIZER_RULES``: the two are disjoint, and
#: a replay that hides any of these is not a replay of the same evidence.
RETAINED_FIELDS = (
    'value', 'write_value', 'read_value', 'rdata',
    'address', 'offset', 'window_base', 'window_size', 'byte_enable',
    'transaction', 'testcase_id', 'source_component', 'source_epoch',
    'channel_id', 'source_sequence', 'version', 'versions', 'generation',
    'byte_offset', 'writer_event_id', 'writer_event_ids', 'writer_kinds',
    'local_tick', 'tick', 'native_local_tick', 'scheduled_local_tick',
    'request_tick', 'response_tick', 'drive_tick',
    'frame_id', 'action_id', 'admission_id', 'access_id', 'entry_id',
    'receiver_id', 'input_sha256', 'source_id', 'path_id',
    'waveform_matched', 'sample_count', 'mismatch_count', 'bit_witness',
    'bit_index', 'bit_value', 'source_drive_refs',
    'probe_uart_fifo_wvalid', 'probe_uart_fifo_wready',
    'probe_uart_fifo_rvalid', 'probe_uart_fifo_rdata_re',
    'probe_uart_fifo_depth', 'probe_uart_fifo_head', 'probe_uart_fifo_data',
    'mcause', 'pc_rdata', 'mem_addr', 'mem_rmask', 'mem_wmask', 'mem_rdata',
    'mem_wdata', 'rd_addr', 'rd_wdata', 'rs1_addr', 'rs2_addr', 'rs2_rdata',
    'status', 'error', 'error_code', 'reason', 'fifo_origin',
    'source_authority', 'proof_grade', 'proof_scope', 'outcome', 'sealed',
)
#: Rule namespaces reserved for whole-document rewriting.  They exist only so a
#: test can prove they are *not* part of the declared table.
FORBIDDEN_REWRITE_SCOPES = ('whole_json', 'whole_document', 'string_replace')


def _validate_ids(execution_ids):
    if not isinstance(execution_ids, Mapping):
        raise ValueError('execution IDs must be a mapping of role to UUID')
    if set(execution_ids) != set(EXECUTION_ROLES):
        raise ValueError('execution IDs must identify CPU, DMA, UART and Runner')
    issued = {name: value for name, value in execution_ids.items()
              if value is not None}
    if (len(set(issued.values())) != len(issued)
            or any(type(value) is not str or _UUID.fullmatch(value) is None
                   for value in issued.values())):
        raise ValueError('execution IDs must be distinct native UUID hex strings')
    return {value: EXECUTION_TOKEN_PREFIX + name for name, value in issued.items()}


def normalize_execution_identities(value, execution_ids):
    """Return ``value`` with only declared execution identities rewritten.

    ``execution_ids`` maps the four issued roles to their native UUIDs (or
    ``None`` when a role has not started).  Unknown strings, unknown UUIDs and
    every retained field are left exactly as measured.
    """
    mapping = _validate_ids(execution_ids)

    def visit(item, field=None, *, event_record=False, ledger_reference=False):
        if isinstance(item, dict):
            state_edge = (event_record
                and item.get('kind') == _STATE_EDGE_KIND
                and _STATE_EDGE_REQUIRED <= item.keys())
            return {key: visit(child, key,
                ledger_reference=state_edge and key in _STATE_EDGE_FIELDS)
                for key, child in item.items()}
        if isinstance(item, (tuple, list)):
            return [visit(child, field) for child in item]
        if type(item) is str:
            rule = FIELD_RULES.get(field)
            if rule is not None and rule.action == 'execution_identity':
                return mapping.get(item, item)
            if rule is not None or ledger_reference:
                match = _TRANSACTION_KEY.fullmatch(item)
                if match is not None and match.group(1) in mapping:
                    return ("TransactionKey(execution_id='"
                            + mapping[match.group(1)] + "', " + match.group(2) + ')')
        return item

    if isinstance(value, (tuple, list)):
        return [visit(event, event_record=True) for event in value]
    return visit(value)


def _normalized(value, execution_ids):
    return normalize_execution_identities(value, execution_ids)


def _type_name(value):
    return type(value).__name__


def _diff(left, right, path):
    if type(left) is not type(right):
        return dict(path=list(path), reason='type', reference_type=_type_name(left),
                    actual_type=_type_name(right), reference=left, actual=right)
    if isinstance(left, dict):
        missing = sorted(set(left) - set(right))
        extra = sorted(set(right) - set(left))
        if missing:
            return dict(path=list(path) + [missing[0]], reason='missing_key',
                        reference=left[missing[0]], actual=None)
        if extra:
            return dict(path=list(path) + [extra[0]], reason='extra_key',
                        reference=None, actual=right[extra[0]])
        for key in sorted(left):
            found = _diff(left[key], right[key], (*path, key))
            if found is not None:
                return found
        return None
    if isinstance(left, (list, tuple)):
        if len(left) != len(right):
            index = min(len(left), len(right))
            return dict(path=list(path) + [index], reason='length',
                        reference_length=len(left), actual_length=len(right),
                        reference=left[index] if index < len(left) else None,
                        actual=right[index] if index < len(right) else None)
        for index, (first, second) in enumerate(zip(left, right)):
            found = _diff(first, second, (*path, index))
            if found is not None:
                return found
        return None
    if left != right:
        return dict(path=list(path), reason='value', reference=left, actual=right)
    return None


def first_difference(reference, actual, execution_ids):
    """First real difference between two value trees after typed normalization.

    Returns ``None`` when the typed-normalized trees are equal, otherwise a
    stable record ``{path, reason, reference, actual, ...}``.  Whole-JSON
    replacement is never applied here, so a payload string that embeds an old
    execution UUID still compares unequal.
    """
    left = _normalized(reference, execution_ids)
    right = _normalized(actual, execution_ids)
    return _diff(left, right, ())


def first_replay_difference(reference, actual, *, reference_execution_ids,
                            actual_execution_ids):
    """First real difference between two *different* fresh executions.

    Each side is normalized with its own issued UUIDs, then compared.  This is
    the only correct way to compare a reference run with a fresh replay: one
    shared mapping cannot rewrite both sides and would report a false difference
    (or, with a whole-JSON replacement, hide a real one).
    """
    left = _normalized(reference, reference_execution_ids)
    right = _normalized(actual, actual_execution_ids)
    return _diff(left, right, ())


def first_difference_normalized(left, right):
    """First difference between two already typed-normalized value trees."""
    return _diff(left, right, ())


def normalized_digest(value, execution_ids):
    """SHA-256 of canonical typed-normalized JSON (diagnostics only)."""
    import hashlib
    import json
    normalized = _normalized(value, execution_ids)
    return hashlib.sha256(json.dumps(normalized, sort_keys=True,
        separators=(',', ':'), ensure_ascii=False, allow_nan=False)
        .encode('utf-8')).hexdigest()


class PrefixDivergence(RuntimeError):
    """A fresh prefix replay diverged; carries the first difference record."""

    def __init__(self, scope, difference):
        self.scope = scope
        self.difference = difference
        super().__init__(f'{scope} prefix differs at {difference.get("path")}: '
                         f'{difference.get("reason")}')


@dataclass(frozen=True)
class PrefixComparison:
    """Result of comparing one normalized fresh prefix."""

    events_compared: int
    ticks_equal: bool
    cases_compared: int
    difference: dict | None

    @property
    def equal(self) -> bool:
        return self.difference is None

    def raise_for_difference(self):
        if self.difference is not None:
            raise PrefixDivergence('replay', self.difference)


def compare_prefix_events(reference_events, actual_events, execution_ids, *,
        limit=None, scope='event'):
    """Compare raw event lists up to ``limit`` with the typed normalizer."""
    reference = list(reference_events)
    actual = list(actual_events)
    if limit is not None:
        reference = reference[:limit]
        actual = actual[:limit]
    if len(reference) != len(actual):
        difference = dict(path=[], reason='length',
            reference_length=len(reference), actual_length=len(actual),
            reference=None, actual=None)
        raise PrefixDivergence(scope, difference)
    difference = first_difference(reference, actual, execution_ids)
    if difference is not None:
        raise PrefixDivergence(scope, difference)
    return len(reference)


def assert_prefix_equal(reference, actual, execution_ids, *, scope='replay'):
    """Raise :class:`PrefixDivergence` at the first real difference."""
    difference = first_difference(reference, actual, execution_ids)
    if difference is not None:
        raise PrefixDivergence(scope, difference)
    return True


__all__ = ['NORMALIZER_SCHEMA', 'EXECUTION_ROLES', 'NormalizerRule',
           'NORMALIZER_RULES', 'RULES_BY_NAME', 'FIELD_RULES',
           'STATE_EDGE_RULE', 'RETAINED_FIELDS', 'FORBIDDEN_REWRITE_SCOPES',
           'normalize_execution_identities', 'first_difference',
           'first_replay_difference', 'first_difference_normalized',
           'normalized_digest', 'PrefixDivergence', 'PrefixComparison',
           'compare_prefix_events', 'assert_prefix_equal']
