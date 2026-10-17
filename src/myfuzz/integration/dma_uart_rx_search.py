"""Single-boot continuous DMA RX search skeleton (S1b).

One boot, serial 8-bit source bytes only. The DMA configuration, the CPU program
and the firmware are never mutated, and no firmware expectation is read back:
the admitted serial byte is the only search input. Guided and uniform arms share
one decision planner, so every saved decision can be recomputed offline from the
saved per-case feedback.

This module makes no source-authority claim. ``fifo_origin`` stays ``unknown``;
``_case_evidence`` remains the only completed-chain certificate.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import random
import time
from typing import Callable, Mapping, Sequence

from myfuzz.local_harness.build import host_source_discovery_scope
from myfuzz.scenario.batch import BatchSourceEvent, ScenarioBatchPlan
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.dma_chain_feedback import dma_chain_features, new_features
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.ibex_dma_example import DESTINATION
from myfuzz.scenario.ibex_dma_uart_example import UART_BASE
from myfuzz.scenario.ibex_dma_uart_rx_continuous import continuous_uart_rx_images

from .dma_uart_rx_runtime import (
    ContinuousRxFailure, ContinuousRxResult, _ContinuousRxBoot,
    _replay_continuous_uart_rx, _source_pins, make_continuous_uart_rx_runner)


SEARCH_SCHEMA = 'continuous_dma_rx_search.v1'
DECISION_SCHEMA = 'continuous_dma_decision.v1'
STRATEGIES = ('guided', 'uniform')
# S1 mutates exactly one serial byte into the pinned continuous firmware.
DIRECTIONS = ('RX_TO_RAM',)
OUTCOMES = ('complete',)
STATUSES = ('complete', 'rejected_prertl', 'case_failed', 'session_failed')
SEARCH_WINDOWS = {'uart_rx_byte': (0, 255)}
SOURCE_PORT = 'uart_rx_byte'
SOURCE_COMPONENT = 'uart'
ACTION_PREFIX = 'dma-search'
DEFAULT_SEED = bytes.fromhex('5a17c0de0badf00d0e0d010203040506')
# The tested data-path addresses a host write must never touch.
GUARDED_ADDRESSES = (DESTINATION, DESTINATION + 0x1000, DESTINATION + 0x100c)
HARD_FINDINGS = ('plan_decision_mismatch', 'host_wrote_data', 'expected_from_host')


class DmaSearchError(RuntimeError):
    """Base class for search-level refusals; the saved prefix stays readable."""


class DmaSearchRejected(DmaSearchError):
    """A structural integrity violation; never downgraded to a finding."""

    def __init__(self, message, *, result=None):
        self.result = result
        self.findings = tuple(part for part in message.split(', ') if part)
        super().__init__(message)


class DmaSearchFailed(DmaSearchError):
    """A post-RTL session failure was saved and fresh-replayed; no search claim."""

    def __init__(self, result):
        self.result = result
        super().__init__('continuous DMA search failed: ' + str(result.failure))


class DmaSearchNotARealSearch(DmaSearchError):
    """The run did not satisfy the anti-fake-search structural criteria."""

    def __init__(self, result, findings):
        self.result = result
        self.findings = tuple(findings)
        super().__init__('not_a_search: ' + ', '.join(self.findings))


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode('utf-8')


def _sha256_hex(document) -> str:
    return hashlib.sha256(_canonical(document)).hexdigest()


def _positive_int(value, name, *, minimum=1):
    if type(value) is not int or value < minimum:
        raise ValueError(f'{name} must be an integer >= {minimum}')
    return value


def _hex_digest(value, name):
    if (not isinstance(value, str) or len(value) != 64
            or any(character not in '0123456789abcdef' for character in value)):
        raise ValueError(f'{name} must be a lowercase sha256 hex digest')
    return value


@dataclass(frozen=True)
class DmaCaseSpec:
    """One declared search input. The spec is the only case input source."""

    direction: str
    source_bytes: tuple[int, ...]
    descriptor: dict
    expect: str

    def __post_init__(self):
        if self.direction not in DIRECTIONS:
            raise ValueError('S1 search direction must be RX_TO_RAM')
        if not isinstance(self.source_bytes, tuple) or len(self.source_bytes) != 1:
            raise ValueError('S1 RX_TO_RAM executes exactly one serial byte')
        if type(self.source_bytes[0]) is not int:
            raise ValueError('serial bytes must be integers in 0..255')
        if (not isinstance(self.descriptor, dict)
                or set(self.descriptor) != {'byte'}
                or self.descriptor['byte'] != self.source_bytes[0]):
            raise ValueError('S1 descriptor must be exactly the admitted byte field')
        if self.expect not in OUTCOMES:
            raise ValueError('S1 has no declared non-complete outcome')

    def validate(self, windows: Mapping[str, tuple[int, int]]) -> None:
        """Pure pre-RTL window check; executing it never touches RTL."""
        if not isinstance(windows, Mapping) or SOURCE_PORT not in windows:
            raise ValueError('a declared window for uart_rx_byte is required')
        low, high = windows[SOURCE_PORT]
        if type(low) is not int or type(high) is not int or not 0 <= low <= high <= 255:
            raise ValueError('declared uart_rx_byte window is invalid')
        value = self.source_bytes[0]
        if not low <= value <= high:
            raise ValueError(f'serial byte {value} is outside the declared window')
        if self.descriptor != {'byte': value}:
            raise ValueError('descriptor must equal the admitted serial byte')

    def identity(self, firmware_sha256: str) -> str:
        """Stable case identity bound to the firmware build, not to a run."""
        _hex_digest(firmware_sha256, 'firmware_sha256')
        return _sha256_hex(dict(direction=self.direction,
            source_bytes=list(self.source_bytes), descriptor=self.descriptor,
            expect=self.expect, firmware_sha256=firmware_sha256))

    def to_document(self) -> dict:
        return dict(direction=self.direction, source_bytes=list(self.source_bytes),
            descriptor=dict(self.descriptor), expect=self.expect)

    @classmethod
    def from_document(cls, document) -> DmaCaseSpec:
        if not isinstance(document, dict) or set(document) != {
                'direction', 'source_bytes', 'descriptor', 'expect'}:
            raise ValueError('saved case spec fields are invalid')
        return cls(document['direction'], tuple(document['source_bytes']),
            dict(document['descriptor']), document['expect'])


@dataclass(frozen=True)
class DmaCaseFeedback:
    """Per-case search feedback derived from one recorded journal slice."""

    case_index: int
    spec_id: str
    status: str
    features: dict
    new_features: tuple[str, ...]
    completed_chain: bool
    target_error: bool
    ticks_before: dict
    ticks_after: dict
    command_start: int
    command_end: int
    event_start: int
    event_end: int
    prefix_sha256: str | None
    evidence: dict | None
    error: dict | None
    spec: DmaCaseSpec

    def __post_init__(self):
        _positive_int(self.case_index, 'case_index')
        _hex_digest(self.spec_id, 'spec_id')
        if self.status not in STATUSES:
            raise ValueError('unknown case feedback status')
        if not isinstance(self.spec, DmaCaseSpec):
            raise ValueError('DmaCaseSpec is required')
        if self.prefix_sha256 is not None:
            _hex_digest(self.prefix_sha256, 'prefix_sha256')
        for name, value in (('features', self.features), ('ticks_before', self.ticks_before),
                ('ticks_after', self.ticks_after)):
            if not isinstance(value, dict):
                raise ValueError(f'{name} must be an object')
        for name, value in (('command_start', self.command_start),
                ('command_end', self.command_end), ('event_start', self.event_start),
                ('event_end', self.event_end)):
            if type(value) is not int or value < 0:
                raise ValueError(f'{name} must be a nonnegative integer')
        if any(type(value) is not int or value < 0
               for value in (*self.ticks_before.values(), *self.ticks_after.values())):
            raise ValueError('tick boundaries must be nonnegative integers')

    @property
    def source_byte(self) -> int:
        return self.spec.source_bytes[0]

    def to_document(self) -> dict:
        return dict(case_index=self.case_index, spec_id=self.spec_id,
            status=self.status, features=dict(sorted(self.features.items())),
            new_features=list(self.new_features),
            completed_chain=self.completed_chain, target_error=self.target_error,
            ticks_before=dict(self.ticks_before), ticks_after=dict(self.ticks_after),
            command_start=self.command_start, command_end=self.command_end,
            event_start=self.event_start, event_end=self.event_end,
            prefix_sha256=self.prefix_sha256, evidence=self.evidence,
            error=self.error, spec=self.spec.to_document())

    @classmethod
    def from_document(cls, document) -> DmaCaseFeedback:
        if not isinstance(document, dict):
            raise ValueError('saved case feedback must be an object')
        fields = dict(document)
        fields['new_features'] = tuple(fields['new_features'])
        fields['spec'] = DmaCaseSpec.from_document(fields['spec'])
        return cls(**fields)


class DmaCorpus:
    """Bounded corpus of cases that produced new features or a full chain."""

    def __init__(self, *, max_entries: int = 256, max_bytes: int = 1 << 20):
        self.max_entries = _positive_int(max_entries, 'max_entries')
        self.max_bytes = _positive_int(max_bytes, 'max_bytes')
        self._entries: list[dict] = []
        self._evictions: list[dict] = []
        self._operator_yield: dict[str, int] = {}
        self._next_id = 1
        self._bytes = 0

    def __len__(self):
        return len(self._entries)

    @property
    def entries(self) -> tuple[dict, ...]:
        return tuple(self._entries)

    def add(self, spec: DmaCaseSpec, feedback: DmaCaseFeedback) -> str:
        if not isinstance(spec, DmaCaseSpec) or not isinstance(feedback, DmaCaseFeedback):
            raise ValueError('DmaCaseSpec and DmaCaseFeedback are required')
        if feedback.status != 'complete':
            raise ValueError('only executed cases enter the corpus')
        size = len(spec.source_bytes) + len(_canonical(feedback.to_document()))
        entry = dict(id=f'corpus-{self._next_id}', case_index=feedback.case_index,
            spec_id=feedback.spec_id, spec=spec,
            source_bytes=list(spec.source_bytes),
            new_features=list(feedback.new_features),
            completed_chain=bool(feedback.completed_chain),
            target_error=bool(feedback.target_error),
            prefix_sha256=feedback.prefix_sha256,
            energy=1 + len(feedback.new_features) + (2 if feedback.completed_chain else 0),
            bytes=size)
        self._next_id += 1
        self._entries.append(entry)
        self._bytes += size
        while (len(self._entries) > self.max_entries
               or (self._bytes > self.max_bytes and len(self._entries) > 1)):
            evicted = self._entries.pop(0)
            self._bytes -= evicted['bytes']
            self._evictions.append(dict(id=evicted['id'], reason='fifo',
                case_index=evicted['case_index']))
        return entry['id']

    def energy(self, entry_id: str) -> int:
        for entry in self._entries:
            if entry['id'] == entry_id:
                return entry['energy']
        raise ValueError('unknown corpus entry')

    def record_operator_yield(self, operator: str, count: int) -> None:
        if not isinstance(operator, str):
            raise ValueError('operator name is required')
        if type(count) is not int or count < 0:
            raise ValueError('operator yield must be a nonnegative integer')
        self._operator_yield[operator] = self._operator_yield.get(operator, 0) + count

    def operator_yields(self) -> dict[str, int]:
        return dict(self._operator_yield)

    def select(self, rng) -> tuple[DmaCaseSpec, str]:
        """Energy-weighted parent selection using exactly one recorded draw."""
        if not self._entries:
            raise ValueError('cannot select from an empty corpus')
        draw = rng.random()
        if type(draw) not in (int, float) or isinstance(draw, bool) or not 0 <= draw < 1:
            raise ValueError('rng draw must be in [0, 1)')
        total = sum(entry['energy'] for entry in self._entries)
        target = draw * total
        cumulative = 0
        for entry in self._entries:
            cumulative += entry['energy']
            if target < cumulative:
                return entry['spec'], entry['id']
        return self._entries[-1]['spec'], self._entries[-1]['id']

    def document(self) -> dict:
        return dict(max_entries=self.max_entries, max_bytes=self.max_bytes,
            bytes=self._bytes,
            entries=[{key: value for key, value in entry.items() if key != 'spec'}
                     | {'spec': entry['spec'].to_document()}
                     for entry in self._entries],
            evictions=list(self._evictions),
            operator_yields=dict(sorted(self._operator_yield.items())))


class DmaMutator:
    """Serial 8-bit byte mutator; every operator stays inside a declared window."""

    OPERATORS = ('byte_bitflip', 'byte_interesting', 'byte_addsub', 'byte_splice',
                 'descriptor_field', 'length', 'direction', 'payload')
    SERIAL_BYTE_OPERATORS = ('byte_bitflip', 'byte_interesting', 'byte_addsub',
                             'byte_splice', 'descriptor_field')
    LATER_OPERATORS = ('length', 'direction', 'payload')
    INTERESTING = (0x00, 0x01, 0x02, 0x03, 0x04, 0x07, 0x08, 0x0f, 0x10, 0x1f,
                   0x20, 0x3f, 0x40, 0x41, 0x55, 0x7e, 0x7f, 0x80, 0xaa, 0xfe, 0xff)

    def __init__(self, *, windows: Mapping[str, tuple[int, int]],
                 firmware_sha256: str,
                 operators: tuple[str, ...] = SERIAL_BYTE_OPERATORS,
                 interesting: Sequence[int] = INTERESTING):
        if not isinstance(windows, Mapping) or SOURCE_PORT not in windows:
            raise ValueError('a declared window for uart_rx_byte is required')
        low, high = windows[SOURCE_PORT]
        if type(low) is not int or type(high) is not int or not 0 <= low <= high <= 255:
            raise ValueError('declared uart_rx_byte window is invalid')
        self.windows = {SOURCE_PORT: (low, high)}
        self.firmware_sha256 = _hex_digest(firmware_sha256, 'firmware_sha256')
        if (not isinstance(operators, tuple) or not operators
                or any(operator not in self.OPERATORS for operator in operators)):
            raise ValueError('unknown mutation operator')
        self.operators = tuple(operators)
        self.interesting = tuple(interesting)
        if (not self.interesting
                or any(type(value) is not int or not 0 <= value <= 255
                       for value in self.interesting)):
            raise ValueError('interesting bytes must be integers in 0..255')

    def choose_operator(self, rng, corpus: DmaCorpus | None) -> tuple[str, float]:
        draw = rng.random()
        if corpus is None:
            index = min(int(draw * len(self.operators)), len(self.operators) - 1)
            return self.operators[index], draw
        yields = corpus.operator_yields()
        weights = [max(yields.get(operator, 0), 0) for operator in self.operators]
        if not any(weights):
            weights = [1] * len(self.operators)
        total = sum(weights)
        target = draw * total
        cumulative = 0
        for operator, weight in zip(self.operators, weights):
            cumulative += weight
            if target < cumulative:
                return operator, draw
        return self.operators[-1], draw

    def mutate(self, parent: DmaCaseSpec, *, rng,
               corpus: DmaCorpus | None = None) -> tuple[DmaCaseSpec, dict]:
        """Return (spec, mutation decision). Never emits an out-of-window byte."""
        if not isinstance(parent, DmaCaseSpec):
            raise ValueError('parent DmaCaseSpec is required')
        operator, operator_draw = self.choose_operator(rng, corpus)
        if operator in self.LATER_OPERATORS:
            raise ValueError(f'operator {operator} requires the S2 descriptor '
                             'firmware (not the S1 serial byte)')
        draws = [operator_draw]
        current = parent.source_bytes[0]
        low, high = self.windows[SOURCE_PORT]
        if operator == 'byte_bitflip':
            value = current ^ (1 << _index(rng, draws, 8))
        elif operator == 'byte_interesting':
            value = self.interesting[_index(rng, draws, len(self.interesting))]
        elif operator == 'byte_addsub':
            delta = _index(rng, draws, 33) - 16
            value = current + (delta if delta else 1)
        elif operator == 'byte_splice':
            donor = current if corpus is None or not len(corpus) else (
                corpus.entries[_index(rng, draws, len(corpus))]['source_bytes'][0])
            if corpus is not None:
                donor = corpus.entries[_index(rng, draws, len(corpus))]['source_bytes'][0]
            value = ((current & 0xf0) | (donor & 0x0f) if _index(rng, draws, 2) == 0
                     else (current & 0x0f) | (donor & 0xf0))
        else:  # descriptor_field
            value = current + (_index(rng, draws, 9) - 4)
            if not low <= value <= high:
                raise ValueError('descriptor field outside the declared window')
        if not 0 <= value <= 255:
            raise ValueError('mutated byte outside the declared 8-bit window')
        if not low <= value <= high:
            raise ValueError('mutated byte outside the declared window')
        spec = DmaCaseSpec('RX_TO_RAM', (value,), {'byte': value}, 'complete')
        return spec, dict(operator=operator, operator_draw=operator_draw,
            draws=draws, value=value, parent=parent.to_document())


def _index(rng, draws: list, size: int) -> int:
    """One bounded integer draw, recorded for offline recomputation."""
    draw = rng.random()
    draws.append(draw)
    return min(int(draw * size), size - 1)


class _SearchRng:
    """Deterministic draw stream that records every value it consumed."""

    def __init__(self, seed: bytes):
        self._rng = random.Random(hashlib.sha256(seed).digest())
        self.draws: list[float] = []

    def random(self) -> float:
        value = self._rng.random()
        self.draws.append(value)
        return value


def seed_spec(seed: bytes) -> DmaCaseSpec:
    if not isinstance(seed, (bytes, bytearray)) or not seed:
        raise ValueError('search seed must be nonempty bytes')
    value = bytes(seed)[0]
    return DmaCaseSpec('RX_TO_RAM', (value,), {'byte': value}, 'complete')


class _DecisionPlanner:
    """Deterministic parent/operator/spec selection shared by search and audit."""

    def __init__(self, *, seed: bytes, strategy: str, windows: Mapping[str, tuple[int, int]],
                 firmware_sha256: str, mutator: DmaMutator):
        if strategy not in STRATEGIES:
            raise ValueError('unknown search strategy')
        if not isinstance(mutator, DmaMutator):
            raise ValueError('DmaMutator is required')
        self.seed = bytes(seed)
        self.strategy = strategy
        self.windows = dict(windows)
        self.firmware_sha256 = _hex_digest(firmware_sha256, 'firmware_sha256')
        self.mutator = mutator
        self.rng = _SearchRng(self.seed)
        self.corpus = DmaCorpus()
        self.seen: frozenset[str] = frozenset()
        self.executed: list[tuple[DmaCaseSpec, str]] = []
        self.attempted_ids: set[str] = set()
        self._seed_spec = seed_spec(self.seed)

    def _spec_id(self, spec: DmaCaseSpec) -> str:
        return spec.identity(self.firmware_sha256)

    def _spec_ref(self, spec: DmaCaseSpec) -> str:
        return 'spec-' + self._spec_id(spec)[:16]

    def _choose_parent(self) -> tuple[DmaCaseSpec, str, str, int]:
        corpus_entries = self.corpus.entries
        if self.strategy == 'guided' and corpus_entries:
            spec, entry_id = self.corpus.select(self.rng)
            return spec, entry_id, 'corpus', self.corpus.energy(entry_id)
        pool = self.executed or [(self._seed_spec, self._spec_ref(self._seed_spec))]
        index = _index(self.rng, [], len(pool))
        spec, reference = pool[index]
        return spec, reference, 'spec', 0

    def next_case(self, case_index: int) -> tuple[DmaCaseSpec, dict]:
        """Plan one case; consumes recorded rng draws only, never RTL."""
        _positive_int(case_index, 'case_index')
        if case_index == 1:
            spec = self._seed_spec
            decision = dict(schema_version=DECISION_SCHEMA, case_index=case_index,
                strategy=self.strategy, parent_id=None, parent_kind='seed',
                energy=0, operator='seed', mutation=None,
                spec=spec.to_document(), spec_id=self._spec_id(spec),
                duplicate_attempts=0, draws=[], draw_offset=0)
            self.attempted_ids.add(decision['spec_id'])
            return spec, decision
        offset = len(self.rng.draws)
        duplicates = 0
        for _ in range(64):
            parent, parent_id, parent_kind, energy = self._choose_parent()
            corpus = self.corpus if self.strategy == 'guided' else None
            spec, mutation = self.mutator.mutate(parent, rng=self.rng, corpus=corpus)
            spec_id = self._spec_id(spec)
            if spec_id in self.attempted_ids:
                duplicates += 1
                continue
            self.attempted_ids.add(spec_id)
            decision = dict(schema_version=DECISION_SCHEMA, case_index=case_index,
                strategy=self.strategy, parent_id=parent_id,
                parent_kind=parent_kind, energy=energy,
                operator=mutation['operator'], mutation=mutation,
                spec=spec.to_document(), spec_id=spec_id,
                duplicate_attempts=duplicates,
                draws=list(self.rng.draws[offset:]), draw_offset=offset)
            return spec, decision
        raise DmaSearchRejected('mutation_cannot_escape_executed_specs')

    def record(self, decision: dict, case: dict) -> dict:
        """Merge one recorded case and update corpus/feature state."""
        merged = {**decision, 'status': case['status'],
            'observed_features': sorted(case['features']),
            'new_features': list(case['new_features']),
            'completed_chain': bool(case['completed_chain']),
            'target_error': bool(case['target_error'])}
        if case['status'] == 'rejected_prertl':
            merged['rejected'] = (case.get('error') or {}).get('message')
        self.seen = self.seen | frozenset(case['features'])
        if decision.get('operator') and decision['operator'] != 'seed':
            self.corpus.record_operator_yield(decision['operator'],
                len(case['new_features']))
        if case['status'] == 'complete':
            spec = DmaCaseSpec.from_document(case['spec'])
            self.executed.append((spec, self._spec_ref(spec)))
            if case['new_features'] or case['completed_chain']:
                self.corpus.add(spec, DmaCaseFeedback.from_document(case))
        return merged


def recompute_decisions(*, seed: bytes, strategy: str, cases: Sequence[dict],
        windows: Mapping[str, tuple[int, int]] | None = None,
        firmware_sha256: str | None = None,
        mutator: DmaMutator | None = None) -> tuple[dict, ...]:
    """Replay the decision stream from saved feedback only (no RTL, no corpus)."""
    selected_windows = dict(windows or SEARCH_WINDOWS)
    digest = firmware_sha256 or _firmware_sha256()
    selected_mutator = mutator or DmaMutator(windows=selected_windows,
        firmware_sha256=digest)
    planner = _DecisionPlanner(seed=seed, strategy=strategy,
        windows=selected_windows, firmware_sha256=digest, mutator=selected_mutator)
    decisions = []
    for position, case in enumerate(cases, 1):
        document = dict(case)
        if document['case_index'] != position:
            raise DmaSearchRejected('recomputed case order differs from the saved run')
        spec, decision = planner.next_case(position)
        if spec.to_document() != document['spec']:
            raise DmaSearchRejected('recomputed spec differs from the saved case')
        decisions.append(planner.record(decision, document))
    return tuple(decisions)


@dataclass(frozen=True)
class DmaSearchResult:
    schema_version: str
    strategy: str
    seed_hex: str
    decisions: tuple[dict, ...]
    cases: tuple[DmaCaseFeedback, ...]
    corpus: dict
    stats: dict
    result: ContinuousRxResult
    failure: dict | None

    def to_document(self) -> dict:
        return dict(schema_version=self.schema_version, strategy=self.strategy,
            seed_hex=self.seed_hex,
            decisions=[dict(decision) for decision in self.decisions],
            cases=[case.to_document() for case in self.cases],
            corpus=self.corpus, stats=self.stats,
            result=self.result.to_document(), failure=self.failure)

    @classmethod
    def from_document(cls, document) -> DmaSearchResult:
        if (not isinstance(document, dict)
                or document.get('schema_version') != SEARCH_SCHEMA):
            raise ValueError('unsupported continuous DMA search bundle')
        return cls(document['schema_version'], document['strategy'],
            document['seed_hex'], tuple(document['decisions']),
            tuple(DmaCaseFeedback.from_document(case) for case in document['cases']),
            document['corpus'], document['stats'],
            ContinuousRxResult.from_document(document['result']),
            document['failure'])

    def save_bundle(self, path) -> None:
        from pathlib import Path
        Path(path).write_text(json.dumps(self.to_document(), sort_keys=True,
            allow_nan=False), encoding='utf-8')


def _firmware_sha256() -> str:
    """Firmware identity from the pinned image bytes; never a case input."""
    images = continuous_uart_rx_images()
    document = {f'{address:08x}': data.hex() for address, data in sorted(images.items())}
    return _sha256_hex(document)


def _case_feedback(*, firmware_sha256, spec: DmaCaseSpec, case_index: int,
                   status: str, features=None, new_features=(),
                   completed_chain=False, target_error=False, evidence=None,
                   error=None) -> DmaCaseFeedback:
    evidence = dict(evidence or {})
    return DmaCaseFeedback(case_index=case_index,
        spec_id=spec.identity(firmware_sha256), status=status,
        features=dict(features or {}), new_features=tuple(new_features),
        completed_chain=bool(completed_chain), target_error=bool(target_error),
        ticks_before=dict(evidence.get('ticks_before') or {}),
        ticks_after=dict(evidence.get('ticks_after') or {}),
        command_start=int(evidence.get('command_start') or 0),
        command_end=int(evidence.get('command_end') or 0),
        event_start=int(evidence.get('event_start') or 0),
        event_end=int(evidence.get('event_end') or 0),
        prefix_sha256=evidence.get('prefix_sha256'),
        evidence=evidence or None, error=error, spec=spec)


def _boot_command_count(boot) -> int:
    return len(getattr(getattr(boot, 'recorder', None), 'commands', ()))


def _search_template(budget: ResourceBudget) -> ScenarioGenome:
    return ScenarioGenome('continuous-dma-rx-search', 'IP_TO_CPU',
        'uart-fifo-dma-ram-cpu-isr', ('dma', 'cpu', 'uart'),
        budget.max_scheduler_steps, ())


def _evaluate_search(result: DmaSearchResult) -> tuple[list[str], dict]:
    """Recompute every structural criterion from recorded case feedback."""
    if not isinstance(result, DmaSearchResult):
        raise ValueError('DmaSearchResult is required')
    cases = result.cases
    executed = [case for case in cases if case.status == 'complete']
    seed = seed_spec(bytes.fromhex(result.seed_hex))
    post_seed = [case for case in executed
                 if case.case_index > 1
                 and case.ticks_after != case.ticks_before]
    distinct = {case.spec.source_bytes for case in post_seed
                if case.spec.source_bytes != seed.source_bytes}
    influenced = any(case_index > 1 for case_index in ())
    influenced = any(decision.get('parent_kind') == 'corpus'
                     and decision.get('energy', 0) > 1
                     and decision.get('new_features')
                     for decision in result.decisions if decision['case_index'] > 1)
    completed = [case for case in post_seed if case.completed_chain]
    findings: list[str] = []
    executed_all = [case for case in cases
                    if case.status in ('complete', 'session_failed', 'case_failed')]
    plan_values = [command.value for command in result.result.plan.commands
                   if isinstance(command, BatchSourceEvent)]
    plan_ids = [command.action_id for command in result.result.plan.commands
                if isinstance(command, BatchSourceEvent)]
    if plan_values != [case.spec.source_bytes[0] for case in executed_all]:
        findings.append('plan_decision_mismatch')
    if plan_ids != [f'{ACTION_PREFIX}-{case.case_index}' for case in executed_all]:
        findings.append('plan_decision_mismatch')
    for event in result.result.events:
        if (isinstance(event, dict) and event.get('kind') == 'memory_write'
                and event.get('component') not in ('cpu', 'dma')
                and event.get('address') in GUARDED_ADDRESSES):
            findings.append('host_wrote_data')
            break
    for case in executed:
        evidence = case.evidence or {}
        if (evidence.get('source_byte') != case.spec.source_bytes[0]
                or evidence.get('action_id') != f'{ACTION_PREFIX}-{case.case_index}'):
            findings.append('expected_from_host')
            break
    if result.stats.get('spec_independent_runner') is not True:
        findings.append('expected_from_host')
    if not executed:
        findings.append('no_executed_cases')
    if len(post_seed) < 2:
        findings.append('insufficient_mutation_batches')
    if len(distinct) < 2:
        findings.append('insufficient_effective_specimen_diversity')
    if result.strategy == 'guided' and not influenced:
        findings.append('feedback_not_influential')
    if not completed:
        findings.append('no_post_seed_completed_chain')
    if any(entry.get('prefix_sha256') is None
           for entry in result.corpus.get('entries', ())):
        findings.append('corpus_not_replayable')
    effective = result.stats.get('effective_search_seconds')
    wall = result.stats.get('search_wall_seconds')
    if (not isinstance(effective, (int, float)) or isinstance(effective, bool)
            or not isinstance(wall, (int, float)) or isinstance(wall, bool)
            or effective < 0 or effective > wall + 0.05):
        findings.append('search_time_unsubstantiated')
    hard = [finding for finding in findings if finding in HARD_FINDINGS]
    soft = [finding for finding in findings if finding not in HARD_FINDINGS]
    if result.failure is not None:
        status = 'failed'
    elif findings:
        status = 'not_a_search'
    else:
        status = 'ok'
    stats = dict(result.stats)
    stats.update(strategy=result.strategy, post_seed_cases=len(post_seed),
        distinct_effective_specs=len(distinct), feedback_influenced=bool(influenced),
        post_seed_completed_chains=len(completed),
        completed_chains=sum(1 for case in executed if case.completed_chain),
        executed_cases=len(executed), case_count=len(cases),
        rejected_prertl=sum(1 for case in cases if case.status == 'rejected_prertl'),
        session_failed=sum(1 for case in cases if case.status == 'session_failed'),
        new_features_total=sum(len(case.new_features) for case in cases),
        corpus_entries=len(result.corpus.get('entries', ())),
        findings=findings, hard_findings=hard, search_status=status)
    return findings, stats


def _assert_real_search(result: DmaSearchResult) -> dict:
    """Raise unless the run structurally is a real guided (or control) search."""
    findings, stats = _evaluate_search(result)
    hard = [finding for finding in findings if finding in HARD_FINDINGS]
    if hard:
        raise DmaSearchRejected(', '.join(hard), result=result)
    if result.failure is not None:
        raise DmaSearchFailed(result)
    if findings:
        raise DmaSearchNotARealSearch(result, findings)
    return stats


def _replay_failure(result: ContinuousRxResult, *, cache_dir, budget,
                    factory) -> ContinuousRxResult:
    """Fresh replay of a failed prefix; tests may substitute a fake."""
    return _replay_continuous_uart_rx(result, cache_dir=cache_dir, budget=budget,
        factory=factory)


@host_source_discovery_scope()
def search_continuous_dma(*, cache_dir, seconds: float, seed: bytes,
        strategy: str = 'guided', budget: ResourceBudget | None = None,
        max_cases: int = 4096, min_cases: int = 3,
        factory: Callable[[], object] | None = None,
        mutator: DmaMutator | None = None,
        windows: Mapping[str, tuple[int, int]] | None = None,
        firmware_sha256: str | None = None) -> DmaSearchResult:
    """Run one boot, mutate only the serial byte, and certify a real search.

    ``seconds`` bounds the case loop only; build, boot and replay are excluded
    from ``effective_search_seconds``. ``min_cases`` keeps enough post-seed cases
    to evaluate the structural criteria honestly when the case cost is high.
    """
    if not isinstance(seed, (bytes, bytearray)) or not seed:
        raise ValueError('search seed must be nonempty bytes')
    if (not isinstance(seconds, (int, float)) or isinstance(seconds, bool)
            or not 0 <= seconds <= 3600):
        raise ValueError('search seconds must be in 0..3600')
    if strategy not in STRATEGIES:
        raise ValueError('unknown search strategy')
    _positive_int(min_cases, 'min_cases', minimum=2)
    _positive_int(max_cases, 'max_cases', minimum=min_cases)
    if factory is None and cache_dir is None:
        raise ValueError('either cache_dir or a runner factory is required')
    selected_budget = budget or ResourceBudget(max_wall_time_ms=300000)
    if not isinstance(selected_budget, ResourceBudget):
        raise ValueError('ResourceBudget is required')
    selected_windows = dict(windows or SEARCH_WINDOWS)
    digest = firmware_sha256 or _firmware_sha256()
    selected_mutator = mutator or DmaMutator(windows=selected_windows,
        firmware_sha256=digest)
    template = _search_template(selected_budget)
    step_bound = 3 * 512
    per_case = 2048 + 3 * 4096
    case_limit = min(max_cases, max(0, (selected_budget.max_scheduler_steps
        - step_bound) // per_case))
    if case_limit < min_cases:
        raise ValueError('search budget cannot hold the minimum case count')
    source_pins = _source_pins()
    runner = factory() if factory is not None else make_continuous_uart_rx_runner(
        cache_dir=cache_dir)
    runner.set_resource_budget(selected_budget)
    boot = _ContinuousRxBoot(runner, budget=selected_budget, template=template,
        source_pins=source_pins)
    planner = _DecisionPlanner(seed=bytes(seed), strategy=strategy,
        windows=selected_windows, firmware_sha256=digest, mutator=selected_mutator)
    cases: list[DmaCaseFeedback] = []
    decisions: list[dict] = []
    failure = None
    replay_state = None
    phase, case_index = 'boot', 0
    wall_start = time.monotonic()
    loop_seconds = 0.0
    loop_start = None
    try:
        boot.boot()
        loop_start = time.monotonic()
        for case_index in range(1, case_limit + 1):
            if case_index > min_cases and time.monotonic() - loop_start >= seconds:
                case_index -= 1
                break
            spec, decision = planner.next_case(case_index)
            try:
                spec.validate(selected_windows)
            except ValueError as exc:
                case = _case_feedback(firmware_sha256=digest, spec=spec,
                    case_index=case_index, status='rejected_prertl',
                    error=dict(type=type(exc).__name__, message=str(exc)))
                decisions.append(planner.record(decision, case.to_document()))
                cases.append(case)
                continue
            try:
                evidence = boot.run_case(spec.source_bytes, case_index=case_index,
                    action_prefix=ACTION_PREFIX,
                    expected={'outcome': spec.expect})
            except Exception as exc:
                diagnostic = dict(type=type(exc).__name__, message=str(exc),
                    command_count=_boot_command_count(boot),
                    case_start=boot.case_start,
                    requested_source_bytes=list(spec.source_bytes))
                failed = boot.finish(phase=boot.phase, case_index=boot.case_index,
                    error=diagnostic)
                case = _case_feedback(firmware_sha256=digest, spec=spec,
                    case_index=case_index, status='session_failed',
                    error=diagnostic, evidence=dict(boot.case_failure or {}))
                decisions.append(planner.record(decision, case.to_document()))
                cases.append(case)
                fresh = _replay_failure(failed, cache_dir=cache_dir,
                    budget=selected_budget, factory=factory)
                if fresh.error != failed.error:
                    raise DmaSearchRejected('failure_replay_mismatch') from exc
                replay_state = 'reproduced'
                failure = dict(error=dict(failed.error or {}),
                    phase=failed.phase, case_index=failed.case_index,
                    command_count=len(failed.plan.commands),
                    fresh_replay=replay_state)
                result = failed
                break
            boot.cases.append(evidence)
            features = dma_chain_features(runner.events,
                start=evidence['event_start'], end=evidence['event_end'],
                destination=DESTINATION, uart_base=UART_BASE)
            novel = new_features(planner.seen, features)
            case = _case_feedback(firmware_sha256=digest, spec=spec,
                case_index=case_index, status='complete',
                features=features.features, new_features=novel,
                completed_chain=features.completed_chain,
                target_error=features.target_error, evidence=evidence)
            decisions.append(planner.record(decision, case.to_document()))
            cases.append(case)
        else:
            case_index = case_limit
        loop_seconds = time.monotonic() - loop_start
        if failure is None:
            result = boot.finish()
    except DmaSearchRejected:
        raise
    except Exception as exc:
        diagnostic = dict(type=type(exc).__name__, message=str(exc),
            command_count=_boot_command_count(boot),
            case_start=boot.case_start)
        try:
            result = boot.finish(phase=boot.phase, case_index=boot.case_index,
                error=diagnostic)
        except Exception:
            raise exc
        failure = dict(error=diagnostic, phase=boot.phase,
            case_index=boot.case_index,
            command_count=_boot_command_count(boot), fresh_replay=None)
        raise exc
    finally:
        boot.close()
    wall_seconds = time.monotonic() - wall_start
    stats = dict(seed_hex=bytes(seed).hex(), strategy=strategy, seed_byte=seed_spec(seed).source_bytes[0],
        firmware_sha256=digest, windows={key: list(value) for key, value in
            selected_windows.items()},
        min_cases=min_cases, max_cases=max_cases, case_limit=case_limit,
        seconds=float(seconds), effective_search_seconds=float(loop_seconds),
        search_wall_seconds=float(wall_seconds),
        failure_replay=replay_state, spec_independent_runner=True,
        operators=list(selected_mutator.operators))
    built = DmaSearchResult(SEARCH_SCHEMA, strategy, bytes(seed).hex(),
        tuple(decisions), tuple(cases), planner.corpus.document(), stats,
        result, failure)
    built.stats.update(_evaluate_search(built)[1])
    _assert_real_search(built)
    return built
