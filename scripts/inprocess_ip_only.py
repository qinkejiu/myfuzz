"""One in-process IP-only run: a single target IP model, no CPU and no DMA.

This module is the IP-only mode of the unified in-process entry
(``scripts/run_inprocess_f1f6.py --mode ip-only``) and it is also importable as
``run_ip_only(config_path, cache, output, ...)``.  It builds exactly one
generated target model from the scenario's declared profile, renders the same
``myfuzz_ip::IpTarget<0>`` port traits the combined host uses, links
``scripts/inprocess_ip_only_host.cpp`` beside that model only, and drives the
declared protocol transactions directly from the host.

What it proves and what it does not:

* the build's archive list contains one archive, the target's, and the link
  command names no CPU model (``cpu_archive_present`` is read from the link log,
  not asserted);
* each transaction's evidence is the device's own response (rdata/error) plus
  the passive protocol trace of that protocol, sampled from the target's own
  generated traits: ``psel``/``penable``/``pready`` (APB3), ``cyc``/``ack``
  (Wishbone), the A-channel then D-channel handshake (TL-UL), and the B/R
  response after its request channels (AXI4-Lite).  The address a case checks is
  the one the target's address port carried, not the request the host drove;
* the target's interrupt output, when the artifact exposes one, is sampled every
  tick and its edges/high ticks are reported, but nothing consumes the interrupt;
* a transaction whose request is never accepted or whose response never arrives
  inside the case budget is a bus timeout reported as an environment issue, kept
  apart from a device assertion;
* no RTL coverage, no certificate and no replay is claimed.

Transaction session shapes.  ``transactions`` in the scenario is the fixed
declared sequence; the ``records`` argument of :func:`run_ip_only` overrides it
with the same canonical record text the host echoes
(``R:<offset>``, ``W:<offset>:<value>``, ``WAIT:<ticks>``, optionally as the
``CASE R ...`` message the online hand-over writes).  ``online=True`` hands one
record over per ``NEED_RECORD`` exactly like the combined entry.  ``sequence``
repeats the list a declared number of times (a light loop); the host prints one
case per executed transaction and states the loop index.

``fuzz=<mapping>`` replaces the fixed list with a closed loop: the host asks for
one record per ``NEED_RECORD``, the parent answers from
:class:`IpFuzzPolicy`, and the policy folds the device's own answer back into its
state before it decides the next input.  Every write is followed by a readback of
the same offset, and the readback word (not the word written) seeds later
mutation.  Each case's record, mutation strategy and basis, observation, result
and readback comparison are written to ``fuzz.json``.

Process shape.  ``case_isolation`` is ``long-running`` by default: one process
initializes the model once and advances it through the whole session, so no
transaction is ever re-run and the run's cost is the DUT's own advance plus one
process's fixed cost.  ``prefix-replay`` is the historical capture, kept as an
explicit choice: one child per case, each running the first k+1 transactions.
The summary's ``advance`` section reports, for both shapes, the ticks and the
seconds spent inside the model's evaluation (measured by the host, not
estimated), the child-process count, the transaction runs and the replayed ones.

Assertion capture.  Verilator 5.x executes ``assert`` statements by default, so
a DUT assertion does not return through this process: it prints
``%Error: <file>:<line>: Assertion failed in <scope>: <text>`` followed by
``%Error: ... Verilog $stop`` and aborts with a non-zero exit code.  In the
long-running shape that abort ends the session at the transaction that raised it:
the event keeps the source file, line, scope and text Verilator printed plus the
last ``case_begin``/``tick`` line the host flushed, and every later case is
reported as not run (``cases_not_run``).  In prefix replay the abort is attributed
to the one new transaction because the previous prefix ended cleanly.  The
assertion helper agent C is adding is a drop-in replacement for
:func:`classify_child_process` / :func:`scan_assertion_lines`; the integration
point is stated in the module notes and in the report.  A bus timeout is never
classified as an assertion.
"""
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT))

SCHEMA_VERSION = 'inprocess_ip_only.v1'
HOST_SOURCE = ROOT / 'scripts/inprocess_ip_only_host.cpp'
#: The target protocols this host really drives and samples.  Each one's passive
#: trace roles and completion criterion are the ones the combined host already
#: runs for that protocol (``PROTOCOL_TRACE_ROLES``); the host selects one from
#: the target's own generated traits, so this is a protocol fact and never a
#: component-name branch.  A protocol outside this tuple keeps a named refusal.
SUPPORTED_PROTOCOLS = ('apb3', 'axi4-lite', 'wishbone', 'tl-ul')
RECORD_TAGS = ('R', 'W', 'WAIT')
#: The session shapes this runner offers.  ``long-running`` initializes the model
#: once and advances it through the whole list; ``prefix-replay`` is the
#: historical capture that re-runs the first k+1 transactions in a fresh child
#: per case.
CASE_ISOLATION_MODES = ('long-running', 'prefix-replay')
CASE_ISOLATION_DEFAULT = 'long-running'

#: The exact Verilator assertion line, e.g.
#: ``[0] %Error: t.sv:3: Assertion failed in TOP.t: ip assertion fired``.
ASSERTION_RE = re.compile(
    r'%Error:\s*(?P<source>[^:\s]+):(?P<line>\d+):\s*Assertion failed in\s*'
    r'(?P<scope>[^:]+):\s*(?P<text>.*)$', re.MULTILINE)
VERILATOR_ERROR_RE = re.compile(r'%Error:\s*(?P<text>.*)$')

#: The transaction keys a scenario may declare, and the subset each operation
#: admits.  An undeclared key is refused by name rather than ignored.
TRANSACTION_KEYS = {'op', 'offset', 'value', 'ticks', 'expect_rdata',
                    'expect_error', 'expect_irq_edges_min', 'note'}


# ---------------------------------------------------------------------------
# Scenario and record parsing
# ---------------------------------------------------------------------------
def _hex_value(value, what):
    """One declared word, from a hex string or a JSON integer.

    A string follows the repository's record convention: bare digits are hex, so
    the canonical record text (``R 00000004``) round-trips through this parser.
    A JSON integer is taken as written, so a scenario can state decimal.
    """
    if type(value) is int:
        number = value
    elif type(value) is str and value:
        text = value[2:] if value.lower().startswith('0x') else value
        try:
            number = int(text, 16)
        except ValueError:
            raise ValueError('invalid-' + what + ':' + value)
    else:
        raise ValueError('invalid-' + what + ':' + repr(value))
    if not 0 <= number <= 0xFFFFFFFF:
        raise ValueError('invalid-' + what + ':out-of-32-bit-range')
    return number


def canonical_record(text):
    return 'CASE ' + text


def parse_transaction(text, *, window):
    """One canonical transaction text, validated against the declared window.

    ``R:<offset>``, ``W:<offset>:<value>`` and ``WAIT:<ticks>`` are the input
    spellings.  An offset inside the declared window is accepted as an offset;
    a word inside ``[base, base+size)`` is accepted as that absolute address and
    the declared base is subtracted.  Anything else is refused by name.
    """
    if not isinstance(text, str) or not text.strip():
        raise ValueError('invalid-transaction:empty')
    # Both spellings are accepted: the record file's ``R:<offset>`` and the
    # canonical message the online hand-over writes (``CASE R <offset>``).
    normalized = text.strip()
    if ':' in normalized and ' ' not in normalized:
        normalized = normalized.replace(':', ' ')
    tokens = normalized.split()
    if tokens and tokens[0] == 'CASE':
        tokens = tokens[1:]
    if not tokens:
        raise ValueError('invalid-transaction:empty')
    tag = tokens[0].upper()
    if tag not in RECORD_TAGS:
        raise ValueError('unsupported-transaction-tag:' + tokens[0])
    if tag == 'WAIT':
        if len(tokens) != 2:
            raise ValueError('invalid-transaction:wait-takes-one-tick-count')
        ticks = _hex_value(tokens[1], 'wait-ticks')
        if not 1 <= ticks <= 65535:
            raise ValueError('invalid-wait-ticks:' + tokens[1])
        message = canonical_record('WAIT %08x' % ticks)
        return dict(op='wait', ticks=ticks, offset=None, value=None,
                    text=message, message=message)
    if tag == 'R':
        if len(tokens) != 2:
            raise ValueError('invalid-transaction:read-takes-one-offset')
        value = None
    else:
        if len(tokens) != 3:
            raise ValueError('invalid-transaction:write-takes-an-offset-and-a-value')
        value = _hex_value(tokens[2], 'value')
    offset = _resolve_offset(_hex_value(tokens[1], 'offset'), window)
    message = (canonical_record('R %08x' % offset) if tag == 'R' else
               canonical_record('W %08x %08x' % (offset, value)))
    return dict(op=('read' if tag == 'R' else 'write'), offset=offset, value=value,
                ticks=None, text=message, message=message)


def _resolve_offset(value, window):
    """Resolve a declared offset/absolute word against the target window."""
    base, size = window['base'], window['size']
    if base <= value < base + size:
        offset = value - base
    elif value < size:
        offset = value
    else:
        raise ValueError('unsupported-ip-only:offset-outside-window:0x%08x' % value)
    if offset % 4:
        raise ValueError('unsupported-ip-only:offset-not-word-aligned:0x%08x' % offset)
    if offset > size - 4:
        raise ValueError('unsupported-ip-only:offset-outside-window:0x%08x' % offset)
    return offset


def declared_transactions(config, window):
    """The scenario's own fixed transaction list, in declaration order."""
    rows = config.get('transactions')
    if not isinstance(rows, list) or not rows:
        raise ValueError('unsupported-ip-only:no-declared-transactions')
    specs = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('unsupported-ip-only:transaction-not-an-object')
        unknown = sorted(set(row) - TRANSACTION_KEYS)
        if unknown:
            raise ValueError('unsupported-ip-only:transaction-key:' + unknown[0])
        operation = row.get('op')
        if operation not in ('read', 'write', 'wait'):
            raise ValueError('unsupported-ip-only:transaction-op:' + str(operation))
        if operation == 'wait':
            if 'offset' in row or 'value' in row:
                raise ValueError('unsupported-ip-only:wait-takes-no-address-or-value')
            ticks = row.get('ticks')
            if type(ticks) is not int or not 1 <= ticks <= 65535:
                raise ValueError('unsupported-ip-only:wait-ticks')
            message = canonical_record('WAIT %08x' % ticks)
            spec = dict(op='wait', ticks=ticks, offset=None, value=None,
                        text=message, message=message)
        else:
            if 'ticks' in row:
                raise ValueError('unsupported-ip-only:bus-transaction-takes-no-ticks')
            if 'offset' not in row:
                raise ValueError('unsupported-ip-only:transaction-needs-an-offset')
            offset = _resolve_offset(_hex_value(row['offset'], 'offset'), window)
            if operation == 'write':
                if 'value' not in row:
                    raise ValueError('unsupported-ip-only:write-needs-a-value')
                value = _hex_value(row['value'], 'value')
                message = canonical_record('W %08x %08x' % (offset, value))
                spec = dict(op='write', offset=offset, value=value, ticks=None,
                            text=message, message=message)
            else:
                if 'value' in row:
                    raise ValueError('unsupported-ip-only:read-takes-no-value')
                message = canonical_record('R %08x' % offset)
                spec = dict(op='read', offset=offset, value=None, ticks=None,
                            text=message, message=message)
        if 'expect_rdata' in row:
            if operation != 'read':
                raise ValueError('unsupported-ip-only:expect-rdata-is-a-read-check')
            spec['expect_rdata'] = _hex_value(row['expect_rdata'], 'expect-rdata')
        if 'expect_error' in row:
            if operation == 'wait':
                raise ValueError('unsupported-ip-only:expect-error-is-a-bus-check')
            expected = _hex_value(row['expect_error'], 'expect-error')
            if expected not in (0, 1):
                raise ValueError('unsupported-ip-only:expect-error-is-0-or-1')
            spec['expect_error'] = expected
        if 'expect_irq_edges_min' in row:
            minimum = _hex_value(row['expect_irq_edges_min'], 'expect-irq-edges-min')
            if not 0 <= minimum <= 65535:
                raise ValueError('unsupported-ip-only:expect-irq-edges-min')
            spec['expect_irq_edges_min'] = minimum
        if 'note' in row:
            if not isinstance(row['note'], str) or not row['note']:
                raise ValueError('unsupported-ip-only:transaction-note')
            spec['note'] = row['note']
        specs.append(spec)
    return specs


def transaction_specs(config, window, records):
    """The transaction list this run executes: handed-over records win.

    The scenario's expectations are matched by position only when the handed-over
    record count equals the declared one; otherwise the run still checks the real
    responses the device returns but states that no declared expectation applied.
    """
    declared = declared_transactions(config, window)
    if records is None:
        return declared, 'scenario'
    if isinstance(records, str):
        texts = [item for item in records.split(',') if item.strip()]
    elif isinstance(records, (list, tuple)):
        texts = [str(item) for item in records if str(item).strip()]
    else:
        raise ValueError('unsupported-ip-only:records-must-be-text-or-a-list')
    if not texts:
        raise ValueError('unsupported-ip-only:empty-record-list')
    executed = [parse_transaction(text, window=window) for text in texts]
    if len(executed) == len(declared):
        for spec, row in zip(executed, declared):
            for key in ('expect_rdata', 'expect_error', 'expect_irq_edges_min', 'note'):
                if key in row:
                    spec[key] = row[key]
    return executed, 'records'


def sequence_loops(config):
    sequence = config.get('sequence') or {}
    if not isinstance(sequence, dict):
        raise ValueError('unsupported-ip-only:sequence-not-an-object')
    unknown = sorted(set(sequence) - {'loops'})
    if unknown:
        raise ValueError('unsupported-ip-only:sequence-key:' + unknown[0])
    loops = sequence.get('loops', 1)
    if type(loops) is not int or not 1 <= loops <= 16:
        raise ValueError('unsupported-ip-only:sequence-loops')
    return loops


def case_isolation_mode(config, override=None, *, online=False, fuzz=False):
    """The session shape for this run: one long-lived process, or one child a case.

    ``long-running`` is the default: the model is built, reset and initialized
    once, then advanced through the whole transaction list in that one process.
    That is where the run's time goes - into the DUT - and there is no re-run of
    an earlier transaction.  An assertion that aborts the process therefore ends
    the list at that transaction and every later case is reported as not run.

    ``prefix-replay`` is the historical capture, kept as an explicit choice: case
    k runs in a fresh child that executes the first k+1 transactions, so an abort
    is attributable to the one new transaction at the cost of re-executing every
    earlier one (``n(n+1)/2`` transactions for n cases, n process starts).

    The declaration spellings ``true``/``false`` are the P0 ones: ``true`` is the
    historical spelling of prefix replay and keeps that meaning, ``false`` means
    one process.  An online hand-over cannot be replayed from a prefix of
    itself, so it always runs as one process; a *declared* prefix replay is
    reported as not applicable instead of silently changing the run.
    """
    declared = override if override is not None else config.get('case_isolation')
    note = None
    if declared is None:
        mode = CASE_ISOLATION_DEFAULT
    elif declared is True:
        mode = 'prefix-replay'
    elif declared is False:
        mode = 'long-running'
    elif isinstance(declared, str) and declared in CASE_ISOLATION_MODES:
        mode = declared
    else:
        raise ValueError('unsupported-ip-only:case-isolation:' + repr(declared))
    if online and mode == 'prefix-replay':
        if override is not None:
            raise ValueError('unsupported-ip-only:case-isolation:prefix-replay-with-'
                             'online-handover')
        mode = 'long-running'
        note = ('the declaration asked for prefix replay, but an online hand-over is '
                'one process by construction: this run is long-running')
    if fuzz and mode == 'prefix-replay':
        note = ('prefix replay of a closed-loop fuzz session re-runs the policy from '
                'the same seed in every child; the prefix is only reproducible '
                'because the policy is a function of the observed device answers')
    return mode, note


# ---------------------------------------------------------------------------
# Closed-loop mutation policy
# ---------------------------------------------------------------------------
#: The mutation strategies one fuzz case is drawn from.  Every one of them states
#: the word it mutated and where that word came from, so a case's `basis` is a
#: fact about this session rather than a label.
FUZZ_WRITE_STRATEGIES = ('write-seed', 'write-readback-mutated', 'write-corpus-mutated',
                         'write-increment', 'write-bitflip', 'write-ones',
                         'write-zeros', 'write-random')
FUZZ_DEFAULT_CASES = 32
FUZZ_DEFAULT_SEED = 0
FUZZ_MAX_CASES = 4096
#: How many idle ticks a generated WAIT drives (the mutation loop needs a
#: no-request case so a device that only reacts to time is also exercised).
FUZZ_WAIT_TICKS = (1, 2, 4, 8, 12, 16)


def fuzz_specification(fuzz, config):
    """The declared fuzz budget and seed, from the CLI mapping or the scenario.

    The scenario may declare the policy shape (``wait_every``); the budget and the
    seed are the campaign's, so the caller's mapping wins for them.
    """
    if not fuzz:
        return None
    declared = dict(config.get('fuzz') or {})
    if fuzz is True:
        pass
    elif isinstance(fuzz, dict):
        declared.update(fuzz)
    else:
        raise ValueError('unsupported-ip-only:fuzz-budget')
    unknown = sorted(set(declared) - {'cases', 'seed', 'wait_every'})
    if unknown:
        raise ValueError('unsupported-ip-only:fuzz-key:' + unknown[0])
    cases = declared.get('cases', FUZZ_DEFAULT_CASES)
    seed = declared.get('seed', FUZZ_DEFAULT_SEED)
    wait_every = declared.get('wait_every', 9)
    if type(cases) is not int or not 1 <= cases <= FUZZ_MAX_CASES:
        raise ValueError('unsupported-ip-only:fuzz-cases')
    if type(seed) is not int or seed < 0:
        raise ValueError('unsupported-ip-only:fuzz-seed')
    if type(wait_every) is not int or not 1 <= wait_every <= 1000:
        raise ValueError('unsupported-ip-only:fuzz-wait-every')
    return dict(cases=cases, seed=seed, wait_every=wait_every)


def fuzz_offsets(config, window, profile):
    """The word offsets the mutation loop may pick, from the declaration itself.

    The declared transactions' offsets and the profile's own register map come
    first (a device that already decoded them), then every other word-aligned
    offset in the declared window.  The first group's length is returned with the
    list so the policy can bias towards registers the device really implements
    without ever leaving the declared window.  Nothing here is invented by the
    harness: both sources are the declaration's own words.
    """
    ordered = []

    def add(offset):
        if (isinstance(offset, int) and 0 <= offset <= window['size'] - 4
                and offset % 4 == 0 and offset not in ordered):
            ordered.append(offset)

    for row in config.get('transactions') or []:
        if isinstance(row, dict) and row.get('op') in ('read', 'write'):
            try:
                add(_resolve_offset(_hex_value(row.get('offset'), 'offset'), window))
            except ValueError:
                pass
    address = profile.get('address') or {}
    for row in address.get('registers') or []:
        offset = row.get('offset')
        if isinstance(offset, int):
            add(offset)
    registers = len(ordered)
    for offset in range(0, window['size'], 4):
        add(offset)
        if len(ordered) >= 64:
            break
    if not ordered:
        raise ValueError('unsupported-ip-only:fuzz-no-offsets')
    return ordered, registers


class IpFuzzPolicy:
    """The closed-loop mutation policy one IP-only fuzz session runs.

    Every decision is a function of the PRNG state, of the declaration, and of
    the *real* device answers this session has already observed:

    * a write is followed by a readback read of the same offset, so the word the
      device really stored is observed and not assumed;
    * the next value written to an offset is mutated from the device's readback
      when one exists (basis ``device readback``), from the last write when none
      does (basis ``last write``), or from the declared seed word;
    * an offset whose readback differs from the word written is remembered as
      device derived, and later mutations of it are seeded from the device's own
      word - which is the feedback this loop closes on;
    * the readback itself is reported as ``equal``/``differs``, a real
      observation, never as a pass or a failure of the device (a counter or a
      FIFO status legitimately differs from what was written).

    The policy is deterministic for one seed and one observed sequence, which is
    what makes a prefix-replay child reproduce the same decisions.
    """
    def __init__(self, *, seed, offsets, registers, cases, wait_every, window):
        import random
        self.rng = random.Random(seed)
        self.seed = seed
        self.offsets = list(offsets)
        # How many of those offsets are the device's own declared registers.  The
        # mutation loop picks from that group most of the time and from the whole
        # window the rest of it.
        self.registers = max(1, min(int(registers), len(self.offsets)))
        self.cases = cases
        self.wait_every = wait_every
        self.window = dict(window)
        self.records = []
        self.rows = []
        self.written = {}
        self.read = {}
        self.derived = set()
        self.pending = []
        self.current_offset = None

    # -- decisions ---------------------------------------------------
    def next_record(self):
        """The next canonical record text, or ``None`` when the budget is spent."""
        if len(self.records) >= self.cases:
            return None
        index = len(self.records)
        self.rows.append(None)
        if self.pending and (index == 0 or self.rng.random() < 0.85):
            readback = self.pending.pop(0)
            return self._emit(index, dict(
                op='read', offset=readback['offset'], value=None, ticks=None,
                strategy='readback',
                readback_of=dict(index=readback['write_index'],
                                 written=readback['value']),
                basis=('the device answer to the write at case %d (written word '
                       '0x%08x)' % (readback['write_index'], readback['value']))))
        if index > 0 and index % self.wait_every == 0:
            ticks = self.rng.choice(FUZZ_WAIT_TICKS)
            return self._emit(index, dict(
                op='wait', offset=None, value=None, ticks=ticks, strategy='wait',
                basis=('a no-request interval of %d ticks: the device is advanced '
                       'without a bus transaction' % ticks)))
        offset = self._pick_offset()
        if self.rng.random() < 0.45:
            return self._emit(index, dict(
                op='read', offset=offset, value=None, ticks=None, strategy='read',
                basis=('a declared/profile/window offset the device decodes; the read '
                       'is checked against its own response and trace completion')))
        strategy, value, basis = self._pick_value(offset)
        self.written[offset] = dict(value=value, index=index)
        self.pending.append(dict(offset=offset, value=value, write_index=index))
        return self._emit(index, dict(
            op='write', offset=offset, value=value, ticks=None, strategy=strategy,
            basis=basis))

    def _pick_offset(self):
        # A device-derived offset is picked again with a real bias: that is where
        # the readback disagreed, so that is where the loop has something to
        # learn.  Otherwise the device's own declared registers are preferred over
        # the rest of the window, and the offset just used is kept some of the
        # time so a write/readback pair stays comparable.
        rng = self.rng
        if self.derived and rng.random() < 0.35:
            offset = rng.choice(sorted(self.derived))
        elif self.current_offset is not None and rng.random() < 0.35:
            offset = self.current_offset
        elif rng.random() < 0.75:
            offset = rng.choice(self.offsets[:self.registers])
        else:
            offset = rng.choice(self.offsets)
        self.current_offset = offset
        return offset

    def _pick_value(self, offset):
        rng = self.rng
        read = self.read.get(offset)
        written = self.written.get(offset)
        if read is not None:
            base, base_basis = read['value'], 'a device readback at case %d' % read['index']
        elif written is not None:
            base, base_basis = written['value'], 'the last write at case %d' % written['index']
        else:
            base, base_basis = 0, 'the declared seed word'
        strategies = list(FUZZ_WRITE_STRATEGIES)
        if read is None:
            strategies = [row for row in strategies if row != 'write-readback-mutated']
        strategy = rng.choice(strategies)
        if strategy == 'write-increment':
            value = (base + rng.choice((1, 2, 4, -1, -4))) & 0xFFFFFFFF
            basis = 'incremented from ' + base_basis + ' (0x%08x)' % base
        elif strategy == 'write-bitflip':
            value = base ^ (1 << rng.randrange(32))
            basis = 'one bit flipped in ' + base_basis + ' (0x%08x)' % base
        elif strategy == 'write-ones':
            value = 0xFFFFFFFF
            basis = 'the all-ones word, independent of the device answer'
        elif strategy == 'write-zeros':
            value = 0
            basis = 'the zero word, independent of the device answer'
        elif strategy == 'write-random':
            value = rng.getrandbits(32)
            basis = 'a fresh 32-bit word from the PRNG (no device answer used)'
        elif strategy == 'write-corpus-mutated':
            other = rng.choice(self.offsets)
            source = self.read.get(other) or self.written.get(other)
            value = (source['value'] if source else 0) ^ (1 << rng.randrange(32))
            basis = ('one bit flipped in the observed word 0x%08x of offset 0x%08x'
                     % (source['value'], other) if source is not None else
                     'one bit flipped in the declared seed word')
        elif strategy == 'write-readback-mutated':
            value = (base ^ (1 << rng.randrange(32))) & 0xFFFFFFFF
            if value == base:
                value = (base + 1) & 0xFFFFFFFF
            basis = 'mutated from ' + base_basis + ' (0x%08x)' % base
        else:  # write-seed
            value = 0
            basis = 'the declared seed word 0x00000000'
        return strategy, value, basis

    def _emit(self, index, decision):
        if decision['op'] == 'wait':
            text = 'CASE WAIT %08x' % decision['ticks']
        elif decision['op'] == 'read':
            text = 'CASE R %08x' % decision['offset']
        else:
            text = 'CASE W %08x %08x' % (decision['offset'], decision['value'])
        row = dict(index=index, record=text, **decision)
        self.records.append(text)
        self.rows[index] = row
        return text

    # -- feedback ----------------------------------------------------
    def observe(self, index, case):
        """Fold one real case answer into the policy state."""
        if not isinstance(index, int) or not 0 <= index < len(self.rows):
            return None
        row = self.rows[index]
        if row is None:
            return None
        fields = case.get('fields') or {}
        observation = dict(
            status=case.get('status'),
            rdata=fields.get('rdata'),
            response_error=fields.get('response_error'),
            response_seen=fields.get('response_seen'),
            target_transfers=fields.get('target_transfers'),
            target_ready=fields.get('target_ready'),
            # The sampled address on the completed transfer: the neutral word for
            # the protocols that print it, the APB3 trace's own paddr otherwise.
            target_offset=fields.get('target_offset', fields.get('apb_paddr')),
            ticks=fields.get('ticks'),
            total_tick=fields.get('total_tick'))
        row['observed'] = observation
        if row['op'] == 'read' and case.get('status') == 'observations_passed' \
                and isinstance(fields.get('rdata'), int):
            self.read[row['offset']] = dict(value=fields['rdata'], index=index)
            if 'readback_of' in row:
                written = row['readback_of']['written']
                write_row = self.rows[row['readback_of']['index']] or {}
                write_error = ((write_row.get('observed') or {})
                               .get('response_error'))
                read_error = fields.get('response_error')
                equal = fields['rdata'] == written
                # A pair whose accesses the device answered with an error response
                # is not a comparable retention observation: the word returned is
                # the error response's, not a stored one.
                comparable = not read_error and not write_error
                row['readback'] = dict(
                    written=written, observed=fields['rdata'], equal=equal,
                    comparable=bool(comparable),
                    write_case=row['readback_of']['index'],
                    write_error=write_error, read_error=read_error)
                if comparable and not equal:
                    self.derived.add(row['offset'])
        elif row['op'] == 'write' and 'readback_of' not in row:
            pass
        return observation


# ---------------------------------------------------------------------------
# Model request, window and generated header
# ---------------------------------------------------------------------------
def _profile_window(config, profile):
    window = config.get('target_window')
    if not isinstance(window, dict) or set(window) != {'base', 'size'}:
        raise ValueError('unsupported-ip-only:target-window')
    base, size = window.get('base'), window.get('size')
    declared = (profile.get('address') or {}).get('window_size')
    if type(base) is not int or type(size) is not int or size <= 0:
        raise ValueError('unsupported-ip-only:target-window')
    if type(declared) is not int or declared != size:
        raise ValueError('unsupported-ip-only:window-size-differs-from-profile')
    if base % size:
        raise ValueError('unsupported-ip-only:window-base-not-aligned')
    address_width = (profile.get('capabilities') or {}).get('address_width')
    if type(address_width) is int:
        # The profile's address width is in its own address units: a
        # word-addressed target (the classic Wishbone register kernel) presents a
        # word address on its port, so its declared window in bytes is four times
        # the address space.  A byte-addressed target is one for one.
        units = (profile.get('capabilities') or {}).get('address_units')
        width_bytes = (1 << address_width) * (4 if units == 'word' else 1)
        if size > width_bytes:
            raise ValueError('unsupported-ip-only:window-wider-than-address-bus')
    return dict(base=base, size=size)


def build_request(config, protocol, profile):
    """The declared v2 request for this target, built by the existing builders.

    Each protocol has exactly one builder that already knows its template and
    variant, and each derives that from the profile's own MMIO slave endpoint
    (never from a component name): the historical APB3 request, the entry's
    generic Wishbone/TL-UL register-target request, and the AXI4-Lite entry's
    request.  A profile this protocol cannot build is refused by name with the
    original builder's own reason kept in the message.
    """
    try:
        if protocol == 'apb3':
            from scripts.run_inprocess_f1f4 import source_request_from_profile
            return source_request_from_profile(config)
        if protocol == 'axi4-lite':
            from scripts.run_inprocess_axi4lite import (
                source_request_from_profile as axil_request)
            return axil_request(config, profile)
        if protocol in ('wishbone', 'tl-ul'):
            from scripts.run_inprocess_f1f6 import generic_target_request_from_profile
            return generic_target_request_from_profile(config, profile, protocol)
    except ValueError as error:
        text = str(error)
        if text.startswith('unsupported-ip-only:'):
            raise
        raise ValueError('unsupported-ip-only:target-request:%s:%s' % (protocol, text))
    raise ValueError('unsupported-ip-only:protocol:' + str(protocol))


def ip_port_fields(document, protocol):
    """The host-visible port names of one target artifact, from its own runtime.

    This is the one-target form of the field derivation the combined header
    performs inline (``render_bindings``): the beat channels and the passive
    protocol trace come from the artifact's declared runtime rows, so the host
    has no device-name branch.  The four protocols share one beat face and differ
    only in the trace roles and completion criterion the host samples from the
    generated traits.
    """
    from scripts.run_inprocess_f1f6 import PROTOCOL_TRACE_ROLES, WB_OPTIONAL_TRACE_ROLES
    if protocol not in SUPPORTED_PROTOCOLS:
        raise ValueError('unsupported-ip-only:protocol:' + protocol)
    roles = ('req_valid', 'req_ready', 'req_write', 'req_addr', 'req_wdata', 'req_be',
             'rsp_valid', 'rsp_ready', 'rsp_rdata', 'rsp_error')
    fields = {}
    for role in roles:
        rows = [row for row in document['backend_ports']
                if row.get('role') == role and row.get('channel') != 'ip_protocol_trace']
        if len(rows) != 1:
            raise ValueError('unsupported-ip-only:beat-role:' + role)
        fields['IP_' + role.upper()] = rows[0]['name']
    signals = (document.get('base_protocol_trace') or {}).get('signals') or {}
    if protocol not in PROTOCOL_TRACE_ROLES:
        raise ValueError('unsupported-ip-only:protocol:' + protocol)
    missing = [role for role in PROTOCOL_TRACE_ROLES[protocol] if role not in signals]
    if missing:
        raise ValueError('unsupported-ip-only:trace-lacks:' + ','.join(missing))
    for role in PROTOCOL_TRACE_ROLES[protocol]:
        fields['IP_TRACE_' + role.upper()] = signals[role]
    for role in WB_OPTIONAL_TRACE_ROLES:
        if role in signals:
            fields['IP_TRACE_' + role.upper()] = signals[role]
    if 'pslverr' in signals:
        fields['IP_TRACE_PSLVERR'] = signals['pslverr']
    return fields


def ip_fixed_rows(document, declared_inputs):
    """The declared pin constants as (identifier, value) rows, or a refusal."""
    from scripts.prepare_inprocess_irq_bindings import identifier
    declared = {(row.get('endpoint_id'), row.get('role')): row.get('value')
                for row in (declared_inputs or [])}
    exposed = {(row.get('endpoint_id'), row.get('role')): row
               for row in (document.get('fixed_physical_inputs') or [])}
    if set(exposed) != set(declared):
        raise ValueError('unsupported-ip-only:generated-target-pins-differ')
    rows = []
    for key, value in sorted(declared.items()):
        row = exposed[key]
        width = row.get('width')
        if (not isinstance(row.get('runtime_name'), str)
                or row.get('value') != value
                or type(width) is not int or not 1 <= width <= 64
                or value >= 1 << width):
            raise ValueError('unsupported-ip-only:generated-target-pin-constant')
        rows.append((identifier(row['runtime_name']), value))
    return rows


def render_header(*, document, protocol, window, fields, fixed_rows,
                  observed_irq, config):
    """The generated header: one model, its ports, and the shared target trait."""
    from scripts.prepare_inprocess_irq_bindings import identifier
    from scripts.run_inprocess_f1f6 import (TARGET_BRIDGES, TARGET_LABELS,
                                            _generated_target_traits)
    model = 'V' + identifier(document['module_name'])
    timing = (document.get('plan') or {}).get('timing') or {}
    reset_assert = int(timing.get('reset_assert_ticks', 2))
    reset_release = int(timing.get('reset_release_ticks', 3))
    case_tick_budget = config.get('case_tick_budget', 256)
    loops = sequence_loops(config)
    lines = [
        '#pragma once',
        '#include "%s.h"' % model,
        '#define IP_ONLY_MODEL %s' % model,
        '#define IP_ONLY_MODEL_NAME "%s"' % document['module_name'],
        '#define IP_ONLY_PROTOCOL "%s"' % protocol,
        '#define IP_ONLY_BASE 0x%xu' % window['base'],
        '#define IP_ONLY_SIZE %du' % window['size'],
        '#define IP_ONLY_RESET_ASSERT %du' % reset_assert,
        '#define IP_ONLY_RESET_RELEASE %du' % reset_release,
        '#define IP_ONLY_CASE_TICK_BUDGET %du' % case_tick_budget,
        '#define IP_ONLY_LOOP_COUNT %du' % loops,
        '#define IP_ONLY_TRACE_TICKS 0',
        '#define IP_ONLY_HAS_IRQ %d' % int(observed_irq is not None),
        # One build-wide protocol selector, exactly like the combined header's
        # TARGET_PROTOCOL_* macros: this host links one target, so the per-protocol
        # trace sample and case-line spelling are a compile-time choice.  The pin
        # names and accessors themselves still come from the target's own trait
        # (myfuzz_ip::IpTarget<0>), not from these macros.
        '#define IP_ONLY_PROTOCOL_APB3 %d' % int(protocol == 'apb3'),
        '#define IP_ONLY_PROTOCOL_AXI4LITE %d' % int(protocol == 'axi4-lite'),
        '#define IP_ONLY_PROTOCOL_WISHBONE %d' % int(protocol == 'wishbone'),
        '#define IP_ONLY_PROTOCOL_TLUL %d' % int(protocol == 'tl-ul'),
        # The optional Wishbone stall pin: sampled only when this target's own
        # trace carries it.  A preprocessor guard, not if constexpr, because the
        # guareded accessor only exists in that case.
        '#define IP_ONLY_WB_STALL_SAMPLED %d' % int('IP_TRACE_STALL' in fields),
        '#define IP_ONLY_APB_ERROR_SAMPLED %d' % int('IP_TRACE_PSLVERR' in fields),
        '#define IP_MODEL_0 %s' % model,
        '#define TARGET_NAME_0 "%s"' % TARGET_LABELS[protocol],
        '#define TARGET_BRIDGE_0 "%s"' % TARGET_BRIDGES[protocol],
        '#define TARGET_BUS_CHANNEL_0 "%s"' % {'axi4-lite': 'axi', 'wishbone': 'wb',
                                              'tl-ul': 'tlul'}.get(protocol, 'apb'),
        '#define IP_FIXED_INPUT_COUNT_0 %d' % len(fixed_rows),
        '#define IP_FIXED_INPUTS_0(X)' + ''.join(' \\\n  X(%s, %su)' % row
                                                for row in fixed_rows),
    ]
    for key, value in fields.items():
        lines.append('#define %s %s' % (key, identifier(value)))
    target = dict(index=0, name=document.get('instance_id', 'target'),
                  protocol=protocol, window=window, irq=None,
                  reset_assert=reset_assert, reset_release=reset_release)
    lines += _generated_target_traits([target], [fields], [fixed_rows],
                                      {0: observed_irq}, protocol, identifier)
    facts = dict(model=model, reset_assert=reset_assert,
                 reset_release=reset_release, case_tick_budget=case_tick_budget,
                 loops=loops, trait_interface='myfuzz_ip::IpTarget<0>',
                 bridge=TARGET_BRIDGES[protocol], label=TARGET_LABELS[protocol],
                 profile_fields=list(fields))
    return '\n'.join(lines) + '\n', facts


# ---------------------------------------------------------------------------
# Child-process capture (assertions, aborts) and the run log
# ---------------------------------------------------------------------------
def classify_child_process(stdout, stderr, returncode):
    """Classify one host process end.

    Returns ``None`` for a clean exit, or a row that keeps a DUT assertion, a
    Verilator error without an assertion, and an unexplained abort apart.  The
    assertion row carries the source file, source line, scope and text Verilator
    printed; nothing is invented when the line is absent.
    """
    text = (stderr or '') + (('\n' + stdout) if stdout else '')
    match = ASSERTION_RE.search(text)
    if match is not None:
        return dict(kind='dut_assertion',
                    source=match.group('source'),
                    line=int(match.group('line')),
                    scope=match.group('scope').strip(),
                    text=match.group('text').strip(),
                    returncode=returncode)
    if '%Error:' in text:
        error = VERILATOR_ERROR_RE.search(text)
        return dict(kind='verilator_error',
                    text=(error.group('text').strip() if error else ''),
                    returncode=returncode)
    if returncode != 0:
        return dict(kind='host_abort', text='', returncode=returncode)
    return None


def scan_assertion_lines(log_text, *, model):
    """Every assertion event in one host log, with its tick and transaction.

    Verilator prints the assertion *instead of* returning through the host, so
    the event is attributed to the last ``case_begin``/``tick`` line this host
    flushed before the abort.  An assertion that fires outside any transaction is
    still attributed to the model with ``transaction=None``.
    """
    events = []
    last_begin = None
    last_tick = None
    for line in log_text.splitlines():
        stripped = line.strip()
        if stripped.startswith('case_begin '):
            tokens = stripped.split()
            fields = {}
            position = 2
            while position + 1 < len(tokens):
                fields[tokens[position]] = tokens[position + 1]
                position += 2
            last_begin = dict(index=_int_or_none(tokens[1]),
                              op=fields.get('op'),
                              offset=fields.get('offset'),
                              value=fields.get('value'),
                              ticks=_int_or_none(fields.get('ticks')),
                              loop=_int_or_none(fields.get('loop')),
                              record=(stripped.split(' record ', 1)[1]
                                      if ' record ' in stripped else None))
            continue
        if stripped.startswith('tick '):
            tokens = stripped.split()
            if len(tokens) >= 2:
                last_tick = _int_or_none(tokens[1])
            continue
        match = ASSERTION_RE.search(stripped)
        if match is None:
            continue
        events.append(dict(
            kind='assertion', classification='dut_assertion', model=model,
            source=match.group('source'), line=int(match.group('line')),
            scope=match.group('scope').strip(),
            text=match.group('text').strip(),
            tick=last_tick,
            transaction=None if last_begin is None else dict(last_begin),
            tick_attribution=('the last case_begin/tick line the host flushed before '
                              'the abort' if last_tick is not None else
                              'unavailable: no tick line was printed for this case'),
            message='%s:%d %s' % (match.group('source'), int(match.group('line')),
                                  match.group('text').strip())))
    return events


def _int_or_none(text):
    if text is None:
        return None
    try:
        return int(text, 0)
    except (TypeError, ValueError):
        return None


def parse_ip_run_log(text):
    """Parse the IP-only host log into header/summary/cases/begin/timing rows."""
    parsed = dict(header=None, summary=None, cases=[], begins=[], ticks=[],
                  timing=None)
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        tokens = stripped.split()
        head = tokens[0]
        if head == 'ip_only' and parsed['header'] is None:
            parsed['header'] = _pairs(tokens[1:])
        elif head == 'summary':
            parsed['summary'] = _pairs(tokens[1:])
        elif head == 'timing' and parsed['timing'] is None:
            parsed['timing'] = _timing_row(tokens[1:])
        elif head == 'case' and len(tokens) >= 3:
            parsed['cases'].append(dict(index=_int_or_none(tokens[1]),
                                        status=tokens[2],
                                        fields=_pairs(tokens[3:])))
        elif head == 'case_begin':
            parsed['begins'].append(_pairs(tokens[1:]))
        elif head == 'tick' and len(tokens) >= 2:
            parsed['ticks'].append(_int_or_none(tokens[1]))
    return parsed


def _timing_row(tokens):
    """The host's own measured advance: wall, DUT and the tick count it bought."""
    fields = _pairs(tokens)
    for key in ('wall_seconds', 'dut_seconds', 'dut_fraction'):
        raw = fields.get(key)
        if isinstance(raw, str):
            try:
                fields[key] = float(raw)
            except ValueError:
                fields[key] = None
    return fields


def _pairs(tokens):
    fields = {}
    position = 0
    while position + 1 < len(tokens):
        key, raw = tokens[position], tokens[position + 1]
        position += 2
        if raw.startswith('0x') or raw.startswith('0X'):
            try:
                fields[key] = int(raw, 16)
            except ValueError:
                fields[key] = raw
        elif re.fullmatch(r'-?\d+', raw) and not key.endswith('reason'):
            fields[key] = int(raw)
        else:
            fields[key] = raw
    return fields


# ---------------------------------------------------------------------------
# Component inventory
# ---------------------------------------------------------------------------
def component_inventory(archive_paths):
    """The component set of an IP-only link, stated from its own archives.

    One archive is the target's; the CPU and DMA counters are zero because the
    link never receives those artifacts.  This is the shape the summary prints,
    and it is also what the no-CPU tests check.
    """
    paths = list(archive_paths)
    return dict(cpu=0, targets=len(paths), dma=0, ram=0,
                model_archives=len(paths))


def model_archive_inventory(archive_rows):
    """The per-component archive lists of one IP-only link."""
    rows = list(archive_rows)
    return dict(cpu=[], targets=[row['path'] for row in rows], dma=[],
                all=[row['path'] for row in rows],
                sha256=[row.get('sha256') for row in rows],
                source='the link command and its archive list, read from link.log '
                       'and the build result')


#: The assertion string Verilator emits into a compiled model, with the source
#: file and line it came from.  Scanning the linked archive is how an IP-only run
#: states whether the model it built actually carries assertion code, instead of
#: assuming it either way.
MODEL_ASSERTION_RE = re.compile(
    rb'%Error: ([A-Za-z0-9_./+-]+):(\d+): Assertion failed in ')


def model_assertion_sites(archive_path):
    """The compiled assertion sites inside one model archive, deduplicated.

    An empty list is a real fact: the model's build contains no assertion code
    (the PULP timer, the zipCPU UARTs and the OpenTitan IP built through
    ``prim_assert`` under Verilator all fall here).  A non-empty list names the
    RTL files and lines the model can abort at.
    """
    try:
        data = Path(archive_path).read_bytes()
    except OSError:
        return []
    sites = {(match.group(1).decode('utf-8', 'replace'), int(match.group(2)))
             for match in MODEL_ASSERTION_RE.finditer(data)}
    return [dict(source=source, line=line) for source, line in sorted(sites)]


# ---------------------------------------------------------------------------
# Case checks
# ---------------------------------------------------------------------------
def check_case(spec, case):
    """One transaction's correspondence: the device's real answer vs the file.

    ``None`` means matched.  A bus timeout is not a mismatch here: it is an
    environment issue reported by :func:`case_issue`.  The response and the
    protocol trace must both be present, because a trace with no beat response
    (or the reverse) states no completed device answer.
    """
    if case['status'] == 'environment_timeout':
        return None
    fields = case['fields']
    if case['status'] == 'failed':
        return 'host reported a failed transaction'
    if spec['op'] == 'wait':
        minimum = spec.get('expect_irq_edges_min')
        if minimum is not None and fields.get('irq_edges', 0) < minimum:
            return ('irq edges: expected at least %d, observed %s'
                    % (minimum, fields.get('irq_edges')))
        return None
    if fields.get('response_seen') != 1:
        return 'the beat response was not observed'
    if fields.get('target_transfers') != 1:
        return ('target transfers: expected exactly 1, observed %s'
                % fields.get('target_transfers'))
    if fields.get('target_ready') != 1:
        return 'the protocol trace did not show a completed transfer'
    if fields.get('offset') != spec['offset']:
        return ('offset: expected 0x%08x, observed %s'
                % (spec['offset'], fields.get('offset')))
    # The address the target's own address port carried on the completed
    # transfer.  It is the sampled fact, printed for the protocols whose trace
    # carries the address in the completion it samples; the APB3 line keeps its
    # historical spelling (apb_paddr) and an older line without either field is
    # checked on the requested offset only.
    sampled = fields.get('target_offset', fields.get('apb_paddr'))
    if sampled is not None and sampled != spec['offset']:
        return ('target_offset: expected 0x%08x, the trace sampled 0x%08x'
                % (spec['offset'], sampled))
    if spec.get('expect_error') is not None \
            and fields.get('response_error') != spec['expect_error']:
        return ('response_error: expected %d, observed %s'
                % (spec['expect_error'], fields.get('response_error')))
    if spec['op'] == 'read' and spec.get('expect_rdata') is not None:
        if fields.get('rdata') != spec['expect_rdata']:
            return ('rdata: expected 0x%08x, observed %s'
                    % (spec['expect_rdata'], fields.get('rdata')))
    if (spec['op'] == 'write' and not spec.get('fuzz')
            and fields.get('response_error') not in (0, None)):
        # A generated fuzz transaction states no expectation: a device that
        # answers a write with an error response is a real observation, reported
        # in the case line, not a failed mutation.  A declared transaction keeps
        # the rule (and may state expect_error instead).
        return ('write answered with response_error %s' % fields.get('response_error'))
    return None


def case_issue(case, spec):
    """The environment row for a bus timeout, or ``None`` for a real answer."""
    if case['status'] != 'environment_timeout':
        return None
    reason = case['fields'].get('reason', 'unknown')
    return dict(
        kind='bus_timeout', transaction_index=case['index'],
        reason=reason,
        operation=(None if spec is None else spec['op']),
        offset=(None if spec is None else spec['offset']),
        waited=case['fields'].get('waited'),
        classification='environment',
        statement=('the target did not answer inside the declared case budget; this '
                   'is an environment fact (bus timeout), not a device assertion and '
                   'not a passed observation'))


# ---------------------------------------------------------------------------
# Session drivers
# ---------------------------------------------------------------------------
def online_session(command, log_path, policy, *, stop_after=None):
    """Drive one host process that asks for one record per ``NEED_RECORD``.

    The parent answers each request from ``policy`` and folds the host's own
    ``case`` line straight back into it, so the next decision is taken from the
    device answer this very process produced.  That is the closed loop: no record
    is ever generated from a model of the device.

    ``stop_after`` ends the hand-over once that many cases have been asked for (a
    prefix-replay child); the host then finalizes and exits on its own.  The
    child's stderr is kept beside its log as ``<log>.stderr`` so a Verilator
    assertion is available to the classifier even though stdout is a pipe.

    Returns the lines the child printed, its end code and the parsed case rows it
    produced (the same rows the parent's policy state was folded from).
    """
    lines = []
    observed = []
    stderr_path = Path(str(log_path) + '.stderr')
    with stderr_path.open('w') as stderr:
        process = subprocess.Popen(list(command), stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=stderr,
                                   text=True, bufsize=1)
        try:
            for line in process.stdout:
                stripped = line.rstrip('\n')
                lines.append(stripped)
                tokens = stripped.split()
                if not tokens:
                    continue
                if tokens[0] == 'NEED_RECORD':
                    index = _int_or_none(tokens[1]) if len(tokens) > 1 else None
                    record = None
                    if index is not None and (stop_after is None or index < stop_after):
                        record = policy.next_record()
                    if record is None:
                        process.stdin.write('END\n')
                    else:
                        process.stdin.write(record + '\n')
                    process.stdin.flush()
                    continue
                if tokens[0] == 'case' and len(tokens) >= 3:
                    parsed = dict(index=_int_or_none(tokens[1]), status=tokens[2],
                                  fields=_pairs(tokens[3:]))
                    policy.observe(parsed['index'], parsed)
                    observed.append(parsed)
            returncode = process.wait()
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait()
    if stderr_path.is_file():
        for row in stderr_path.read_text().rstrip().splitlines():
            lines.append('# stderr ' + row)
    log_path.write_text('\n'.join(lines) + ('\n' if lines else ''))
    return dict(lines=lines, returncode=returncode, cases=observed,
                stderr=str(stderr_path))


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def run_ip_only(config_path, cache, output, *, records=None, fuzz=None,
                max_ticks=None, online=False, quiet=False,
                case_isolation=None):
    """Build one target model and run the declared transaction session.

    Returns the summary document that is also written to ``summary.json``.  No
    CPU model, no DMA model and no RAM image is built or linked.

    Two independent session choices are made here:

    * the transaction source: the scenario's fixed list, a handed-over record
      list, an online hand-over, or (``fuzz``) a closed-loop mutation policy that
      picks every next input from the device answers already observed;
    * the process shape (``case_isolation``): ``long-running`` (the default)
      builds, resets and initializes the model once and advances it through the
      whole session, so the run's time is spent in the DUT; ``prefix-replay``
      keeps the historical one-child-per-case capture.

    An event that ends the process (a DUT assertion, or any other abort) is
    reported with the transaction that was running: file, line, scope and text
    from Verilator's own message, the tick stream's last case, and every case
    after it as not run.  A bus timeout is an environment issue and is never
    reported as an assertion.
    """
    started = time.monotonic()
    config_path, cache, output = Path(config_path), Path(cache), Path(output)
    try:
        config = json.loads(config_path.read_text())
    except (OSError, ValueError) as error:
        raise ValueError('cannot read the IP-only declaration: ' + str(error))
    if not isinstance(config, dict):
        raise ValueError('unsupported-ip-only:declaration-not-an-object')
    if config.get('schema_version') != SCHEMA_VERSION:
        raise ValueError('unsupported-ip-only:schema:'
                         + str(config.get('schema_version')))
    if output.exists():
        raise ValueError('output directory already exists')
    for key in ('source_profile', 'active_id'):
        if not isinstance(config.get(key), str) or not config[key]:
            raise ValueError('unsupported-ip-only:' + key)
    if config.get('cpu_profile') is not None or config.get('dma_profile') is not None:
        raise ValueError('unsupported-ip-only:the-declaration-names-a-cpu-or-dma')
    case_tick_budget = config.get('case_tick_budget', 256)
    if type(case_tick_budget) is not int or not 4 <= case_tick_budget <= 1000000:
        raise ValueError('unsupported-ip-only:case-tick-budget')
    fuzz_spec = fuzz_specification(fuzz, config)
    if fuzz_spec is not None and records:
        raise ValueError('unsupported-ip-only:fuzz-with-handover-records')
    isolation_mode, isolation_note = case_isolation_mode(
        config, case_isolation, online=online, fuzz=fuzz_spec is not None)
    isolation = isolation_mode == 'prefix-replay'

    from myfuzz.composition.component_profile import elaboration_mode_scope
    from myfuzz.local_harness.build import (host_source_discovery_scope,
                                            harness_validation_scope)
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from scripts.run_timer_irq_smoke import timer_artifact
    from scripts.run_inprocess_f1f6 import (observed_irq_output, profile_protocol,
                                            target_protocol)
    from scripts.inprocess_build import build_link_run

    profile_document = json.loads((ROOT / config['source_profile']).read_text())
    protocol = profile_protocol(profile_document)
    if protocol not in SUPPORTED_PROTOCOLS:
        raise ValueError('unsupported-ip-only:protocol:' + protocol)
    window = _profile_window(config, profile_document)
    loops = sequence_loops(config)
    if records is None and fuzz_spec is not None and not config.get('transactions'):
        # A fuzz-only declaration needs no fixed list: its seed corpus is the
        # declared transaction list when there is one and the profile's register
        # map otherwise.
        specs, source = [], 'fuzz-policy'
    else:
        specs, source = transaction_specs(config, window, records)
    if fuzz_spec is not None:
        planned_cases = fuzz_spec['cases']
    else:
        planned_cases = len(specs) * (1 if online else loops)
    if planned_cases < 1:
        raise ValueError('unsupported-ip-only:no-cases')
    if max_ticks is None:
        max_ticks = max(20000, planned_cases * case_tick_budget)
    if type(max_ticks) is not int or max_ticks < 1:
        raise ValueError('--max-ticks must be positive')
    # The request is computed before anything is created: a declaration this
    # protocol cannot build is refused by name without leaving an empty output
    # directory behind (which would then make a corrected rerun collide).
    request = build_request(config, protocol, profile_document)
    output.mkdir(parents=True)
    request_path = (output / 'source_request.json').resolve()
    request_path.write_text(json.dumps(request, indent=2) + '\n')

    isolation_state = dict(
        mode=isolation_mode, note=isolation_note, aborted_at=None, consistent=True,
        prefix_runs=[], case_lines={})
    trace_ticks = not quiet
    fuzz_state = dict(policy=None, child_runs=0)
    fuzz_offset_list, fuzz_register_count = (
        fuzz_offsets(config, window, profile_document)
        if fuzz_spec is not None else ([], 0))

    with elaboration_mode_scope('direct'), \
            host_source_discovery_scope(reuse_nested=True), \
            harness_validation_scope(), execution_validation_scope():
        artifact = timer_artifact(ROOT, str(request_path), config['active_id'])
        document = artifact.runtime_document
        artifact_protocol = target_protocol(document)
        if artifact_protocol != protocol:
            raise ValueError('unsupported-ip-only:profile-and-artifact-protocol-differ:'
                             + protocol + ':' + artifact_protocol)
        fields = ip_port_fields(document, protocol)
        fixed_rows = ip_fixed_rows(document, config.get('source_fixed_inputs') or [])
        observed_irq = observed_irq_output(document)
        header, header_facts = render_header(
            document=document, protocol=protocol, window=window, fields=fields,
            fixed_rows=fixed_rows, observed_irq=observed_irq, config=config)
        (output / 'ip_only_config.h').write_text(header)
        model_name = document['module_name']
        if fuzz_spec is not None:
            ordered = []
            total_cases = fuzz_spec['cases']
        else:
            ordered = ([spec for _loop in range(loops) for spec in specs]
                       if not online else list(specs))
            total_cases = len(ordered)
        prefix_dir = (output / 'prefix-runs' if isolation else None)

        def make_policy():
            return IpFuzzPolicy(seed=fuzz_spec['seed'], offsets=fuzz_offset_list,
                                registers=fuzz_register_count,
                                cases=fuzz_spec['cases'],
                                wait_every=fuzz_spec['wait_every'], window=window)

        def fuzz_session(command, stop_after, log_path):
            """One closed-loop child: ask, answer, observe, decide again."""
            policy = make_policy()
            case_started = time.monotonic()
            session = online_session(command, log_path, policy,
                                     stop_after=stop_after)
            elapsed = time.monotonic() - case_started
            parsed_child = parse_ip_run_log(Path(log_path).read_text())
            return dict(policy=policy, session=session, elapsed=elapsed,
                        timing=parsed_child['timing'],
                        summary=parsed_child['summary'])

        def isolated_runner(command, log_path):
            """Prefix replay: case k runs the first k+1 transactions.

            Sequence semantics (a write before a later read) are preserved, and an
            assertion abort stays attributable: the previous prefix ended cleanly,
            so the abort happened inside the one new transaction.  A clean prefix
            also reproduces every earlier case line, which is checked here and
            stated in the summary.  One child process per case is what makes a
            Verilator $stop (which kills the process) survive as data.
            """
            executable = command[0]
            lines = []
            header_seen = False
            seen = {}
            previous_seconds = 0.0
            for index in range(total_cases):
                prefix = [spec['message'] for spec in ordered[:index + 1]]
                child_argv = [executable, ','.join(prefix), str(max_ticks),
                              '--loops', '1']
                if trace_ticks:
                    child_argv.append('--trace-ticks')
                case_started = time.monotonic()
                completed = subprocess.run(child_argv, capture_output=True,
                                           text=True)
                elapsed = time.monotonic() - case_started
                child = parse_ip_run_log(completed.stdout)
                child_log = prefix_dir / ('case-%03d.log' % index)
                child_log.parent.mkdir(exist_ok=True)
                child_log.write_text(completed.stdout + completed.stderr)
                isolation_state['prefix_runs'].append(dict(
                    index=index, returncode=completed.returncode,
                    prefix_transactions=len(prefix), seconds=elapsed,
                    derived_case_seconds=max(0.0, elapsed - previous_seconds),
                    timing=child['timing'],
                    ticks=(child['timing'] or {}).get('ticks'),
                    dut_seconds=(child['timing'] or {}).get('dut_seconds')))
                previous_seconds = elapsed
                child_cases = {case['index']: case for case in child['cases']}
                for prior_index, prior_case in child_cases.items():
                    if prior_index == index:
                        continue
                    if prior_index in seen and seen[prior_index] != prior_case:
                        isolation_state['consistent'] = False
                    seen.setdefault(prior_index, prior_case)
                raw_lines = completed.stdout.splitlines()
                if not header_seen:
                    for row in raw_lines:
                        if row.startswith('ip_only '):
                            lines.append(row)
                            header_seen = True
                            break
                if index in child_cases:
                    seen.setdefault(index, child_cases[index])
                    for row in raw_lines:
                        tokens = row.split()
                        if tokens[:1] == ['case'] and tokens[1:2] == [str(index)]:
                            isolation_state['case_lines'].setdefault(index, row)
                            break
                    continue
                # The new transaction never produced a case line: the child ended
                # inside it.  Keep that transaction's own lines (case_begin, the
                # tick stream and stderr), which is what the assertion scan reads.
                isolation_state['aborted_at'] = index
                capture = False
                for row in raw_lines:
                    if row.startswith('case_begin ' + str(index) + ' '):
                        capture = True
                    if capture:
                        lines.append(row)
                if completed.stderr.strip():
                    for row in completed.stderr.rstrip().splitlines():
                        lines.append('# stderr ' + row)
                break
            for index in sorted(isolation_state['case_lines']):
                lines.append(isolation_state['case_lines'][index])
            cases = [line for line in lines if line.startswith('case ')]
            passed = sum(1 for line in cases if ' observations_passed ' in line + ' ')
            failed = sum(1 for line in cases if ' failed ' in line + ' ')
            timeouts = sum(1 for line in cases if ' environment_timeout ' in line + ' ')
            last_tick = 0
            for line in cases:
                try:
                    last_tick = max(last_tick, int(
                        line.split(' total_tick ')[1].split()[0]))
                except (IndexError, ValueError):
                    pass
            lines.append('summary mode ip-only aggregate 1 model ' + model_name +
                         ' protocol ' + protocol + ' transactions ' +
                         str(len(cases)) + ' cases ' + str(len(cases)) +
                         ' passed ' + str(passed) + ' failed ' + str(failed) +
                         ' timeouts ' + str(timeouts) + ' ticks ' + str(last_tick))
            log_path.write_text('\n'.join(lines) + ('\n' if lines else ''))
            return 0 if isolation_state['aborted_at'] is None else 1

        def fuzz_prefix_runner(command, log_path):
            """The closed-loop policy under the one-child-per-case capture.

            Each child starts the policy from the same seed and re-runs it for the
            first k+1 cases; the decisions are reproducible only because they are
            a function of the observed device answers, which the check below
            verifies line by line.  This is the shape the cost comparison uses.
            """
            lines = ['# prefix replay of the closed-loop fuzz policy: one child per case',
                     '# every child re-runs the same seed and answers its prefix']
            header_seen = False
            seen = {}
            previous_seconds = 0.0
            aborted_at = None
            for index in range(total_cases):
                child_log = prefix_dir / ('case-%03d.log' % index)
                child_log.parent.mkdir(exist_ok=True)
                child = fuzz_session(command, index + 1, child_log)
                isolation_state['prefix_runs'].append(dict(
                    index=index, returncode=child['session']['returncode'],
                    prefix_transactions=index + 1, seconds=child['elapsed'],
                    derived_case_seconds=max(0.0, child['elapsed'] - previous_seconds),
                    timing=child['timing'],
                    ticks=(child['timing'] or {}).get('ticks'),
                    dut_seconds=(child['timing'] or {}).get('dut_seconds')))
                previous_seconds = child['elapsed']
                fuzz_state['policy'] = child['policy']
                fuzz_state['child_runs'] += 1
                child_cases = {case['index']: case
                               for case in child['session']['cases']}
                for prior_index, prior_case in child_cases.items():
                    if prior_index == index:
                        continue
                    if prior_index in seen and seen[prior_index] != prior_case:
                        isolation_state['consistent'] = False
                    seen.setdefault(prior_index, prior_case)
                raw_lines = child['session']['lines']
                if not header_seen:
                    for row in raw_lines:
                        if row.startswith('ip_only '):
                            lines.append(row)
                            header_seen = True
                            break
                if index in child_cases:
                    seen.setdefault(index, child_cases[index])
                    for row in raw_lines:
                        tokens = row.split()
                        if tokens[:1] == ['case'] and tokens[1:2] == [str(index)]:
                            isolation_state['case_lines'].setdefault(index, row)
                            break
                    continue
                aborted_at = index
                capture = False
                for row in raw_lines:
                    if row.startswith('case_begin ' + str(index) + ' '):
                        capture = True
                    if capture:
                        lines.append(row)
                break
            isolation_state['aborted_at'] = aborted_at
            for index in sorted(isolation_state['case_lines']):
                lines.append(isolation_state['case_lines'][index])
            cases = [line for line in lines if line.startswith('case ')]
            passed = sum(1 for line in cases if ' observations_passed ' in line + ' ')
            failed = sum(1 for line in cases if ' failed ' in line + ' ')
            timeouts = sum(1 for line in cases if ' environment_timeout ' in line + ' ')
            lines.append('summary mode ip-only aggregate 1 model ' + model_name +
                         ' protocol ' + protocol + ' transactions ' +
                         str(len(cases)) + ' cases ' + str(len(cases)) +
                         ' passed ' + str(passed) + ' failed ' + str(failed) +
                         ' timeouts ' + str(timeouts))
            log_path.write_text('\n'.join(lines) + ('\n' if lines else ''))
            return 0 if aborted_at is None else 1

        def fuzz_long_runner(command, log_path):
            """One process for the whole mutation session: the long-running shape."""
            child = fuzz_session(command, None, log_path)
            fuzz_state['policy'] = child['policy']
            fuzz_state['child_runs'] = 1
            executed = len(child['session']['cases'])
            if executed < total_cases:
                isolation_state['aborted_at'] = executed
            return child['session']['returncode']

        def batch_runner(command, log_path):
            """One process for the whole list (online hand-over or declared)."""
            if online:
                from scripts.run_inprocess_f1f4 import incremental_runner
                messages = [spec['message'] for spec in specs]
                submitted = []
                return incremental_runner(messages, submitted)(command, log_path)
            completed = subprocess.run(command, capture_output=True, text=True)
            log_path.write_text(completed.stdout + completed.stderr)
            return completed.returncode

        encoded = ('--online' if (online or fuzz_spec is not None) else
                   ','.join(spec['message'] for spec in specs))
        argv = [encoded, str(max_ticks)]
        if trace_ticks:
            argv.append('--trace-ticks')
        if fuzz_spec is not None:
            runner = fuzz_prefix_runner if isolation else fuzz_long_runner
        elif isolation:
            runner = isolated_runner
        else:
            runner = batch_runner
        build = build_link_run(
            (artifact,), HOST_SOURCE, output, cache, argv, root=ROOT,
            runner=runner)

    log_text = ((output / 'run.log').read_text()
                if (output / 'run.log').is_file() else '')
    parsed = parse_ip_run_log(log_text)
    assertions = scan_assertion_lines(log_text, model=model_name)
    policy = fuzz_state['policy']
    fuzz_rows = {} if policy is None else {
        row['index']: row for row in policy.rows if row is not None}
    cases = []
    environment = []
    mismatches = []
    for case in parsed['cases']:
        if fuzz_spec is not None:
            fuzz_row = fuzz_rows.get(case['index'])
            spec = None if fuzz_row is None else dict(
                op=fuzz_row['op'], offset=fuzz_row['offset'],
                value=fuzz_row['value'], ticks=fuzz_row['ticks'],
                text=fuzz_row['record'], fuzz=True,
                expect_rdata=None, expect_error=None, expect_irq_edges_min=None)
            loop = None
        else:
            spec = specs[case['index'] % len(specs)] if specs else None
            loop = (None if online else
                    0 if case['index'] is None else case['index'] // len(specs))
        document_row = dict(case)
        document_row['transaction'] = None if spec is None else dict(
            op=spec['op'], offset=spec['offset'], value=spec['value'],
            ticks=spec['ticks'], text=spec['text'],
            expect_rdata=spec.get('expect_rdata'),
            expect_error=spec.get('expect_error'),
            expect_irq_edges_min=spec.get('expect_irq_edges_min'))
        if loop is not None:
            document_row['loop'] = loop
        if spec is not None:
            mismatch = check_case(spec, case)
            document_row['correspondence'] = ('matched' if mismatch is None
                                              else 'mismatched')
            if mismatch is not None:
                document_row['correspondence_reason'] = mismatch
                mismatches.append(dict(index=case['index'], reason=mismatch))
        else:
            document_row['correspondence'] = 'not_checked'
        if fuzz_spec is not None and case['index'] in fuzz_rows:
            fuzz_row = fuzz_rows[case['index']]
            document_row['fuzz'] = dict(
                strategy=fuzz_row['strategy'], basis=fuzz_row['basis'],
                record=fuzz_row['record'],
                readback=fuzz_row.get('readback'))
        issue = case_issue(case, spec)
        if issue is not None:
            environment.append(issue)
        cases.append(document_row)

    expected_cases = total_cases
    executed = len(cases)
    aborted_at = isolation_state['aborted_at']
    cases_not_run = 0 if aborted_at is None else max(0, expected_cases - executed)
    passed = sum(1 for case in cases
                 if case['status'] == 'observations_passed'
                 and case.get('correspondence') == 'matched')
    failed = sum(1 for case in cases if case['status'] == 'failed')
    timeouts = sum(1 for case in cases if case['status'] == 'environment_timeout')
    archives = build['archives']
    if len(archives) != 1:
        raise RuntimeError('the IP-only link states %d model archives, not one'
                           % len(archives))
    link_log = ((output / 'link.log').read_text()
                if (output / 'link.log').is_file() else '')
    cpu_archive_absent = 'local_runtime_cpu' not in link_log
    components = component_inventory([row['path'] for row in archives])
    model_archives = model_archive_inventory(archives)
    status = ('dut_assertion' if assertions else
              'environment_issue' if environment else
              'failed' if (mismatches or failed or timeouts
                           or executed != expected_cases) else
              'fuzz_completed' if fuzz_spec is not None else
              'observations_passed')
    total_seconds = time.monotonic() - started
    assertion_sites = model_assertion_sites(archives[0]['path'])
    advance = session_advance_measurement(
        isolation=isolation, timing=parsed['timing'],
        prefix_runs=isolation_state['prefix_runs'],
        run_seconds=build.get('run_seconds'), planned_cases=expected_cases)
    fuzz_document = None
    if fuzz_spec is not None and policy is not None:
        rows = []
        for row in policy.rows:
            if row is None:
                continue
            case_row = next((case for case in cases
                             if case['index'] == row['index']), None)
            rows.append(dict(
                index=row['index'], input=row['record'], op=row['op'],
                offset=row['offset'], value=row['value'], ticks=row['ticks'],
                mutation=dict(strategy=row['strategy'], basis=row['basis']),
                readback=row.get('readback'),
                observation=row.get('observed'),
                result=(None if case_row is None else case_row['status']),
                correspondence=(None if case_row is None
                                else case_row.get('correspondence'))))
        strategies = {}
        for row in rows:
            name = row['mutation']['strategy']
            strategies[name] = strategies.get(name, 0) + 1
        readbacks = [row['readback'] for row in rows if row.get('readback')]
        fuzz_document = dict(
            schema_version='inprocess_ip_only_fuzz.v1',
            cases=fuzz_spec['cases'], seed=fuzz_spec['seed'],
            wait_every=fuzz_spec['wait_every'],
            closed_loop=('the next record is chosen from the device answers already '
                         'observed: every write is followed by a readback of the same '
                         'offset and the readback word seeds later mutation'),
            offsets=dict(values=['0x%08x' % offset for offset in fuzz_offset_list],
                         register_count=fuzz_register_count,
                         source='the declared transactions and the profile register map '
                                'first (the device\'s own declared words), then every '
                                'other word-aligned offset of the declared window'),
            strategies=sorted(FUZZ_WRITE_STRATEGIES) + ['read', 'readback', 'wait'],
            strategy_counts=strategies,
            readbacks=dict(
                comparable=sum(1 for row in readbacks if row.get('comparable')),
                equal=sum(1 for row in readbacks
                          if row.get('comparable') and row['equal']),
                differs=sum(1 for row in readbacks
                            if row.get('comparable') and not row['equal']),
                errored=sum(1 for row in readbacks if not row.get('comparable')),
                interpretation=('a comparable pair is one the device answered without '
                                'an error response on either access; equal means the '
                                'word read back is the word written, differs means the '
                                'device stored something else - a real observation, '
                                'never a pass or a fail of the device'),
                rows=readbacks),
            records=[row['input'] for row in rows], rows=rows)
    result = dict(
        schema_version='inprocess_ip_only_summary.v1',
        status=status,
        mode='ip-only',
        components_loaded=components,
        model_archives=model_archives,
        cpu_archive_present=not cpu_archive_absent,
        cpu_model=None,
        scope='one ' + protocol.upper() + ' register target model, no CPU, no DMA, no '
              'RAM: the host drives the declared transactions through the device\'s '
              'own request/response beat port and reads its real responses and '
              'passive protocol trace',
        target=dict(
            profile=config['source_profile'], instance_id=config['active_id'],
            module=model_name, protocol=protocol, bridge=header_facts['bridge'],
            window=dict(window),
            artifact=dict(runtime_sha256=document.get('runtime_sv_sha256'),
                          cpp_sha256=document.get('cpp_sha256'),
                          artifact_digest=document.get('artifact_digest')),
            irq=(None if observed_irq is None else dict(
                runtime_name=observed_irq.get('runtime_name'),
                endpoint_id=observed_irq.get('endpoint_id'),
                width=observed_irq.get('width'),
                bit_lo=observed_irq.get('bit_lo'))),
            fixed_inputs=list(fixed_rows),
            reset_assert=header_facts['reset_assert'],
            reset_release=header_facts['reset_release'],
            trait_interface=header_facts['trait_interface']),
        session=dict(
            source=('closed-loop fuzz policy over the ' + source + ' corpus'
                    if fuzz_spec is not None else
                    'online hand-over of the ' + source + ' list'
                    if online else source),
            fuzz=(None if fuzz_spec is None else
                  dict(cases=fuzz_spec['cases'], seed=fuzz_spec['seed'])),
            isolation_mode=isolation_mode,
            isolation=('prefix replay: one child process per case, each running the '
                       'first k+1 transactions' if isolation else
                       'long running: one process initializes the model once and '
                       'advances it through the whole session'),
            isolation_note=isolation_note,
            child_runs=(len(isolation_state['prefix_runs']) if isolation
                        else fuzz_state['child_runs'] or 1),
            sequence_loops=(1 if (online or fuzz_spec is not None) else loops),
            transactions=len(specs),
            case_tick_budget=case_tick_budget,
            max_ticks=max_ticks,
            tick_stream=('recorded' if trace_ticks else 'suppressed'),
            cases_expected=expected_cases,
            cases_executed=executed,
            cases_not_run=cases_not_run,
            aborted_at=aborted_at),
        transactions=[dict(op=spec['op'], offset=spec['offset'], value=spec['value'],
                           ticks=spec['ticks'], text=spec['text'],
                           message=spec['message'],
                           expect_rdata=spec.get('expect_rdata'),
                           expect_error=spec.get('expect_error'),
                           expect_irq_edges_min=spec.get('expect_irq_edges_min'),
                           note=spec.get('note'))
                      for spec in specs],
        cases=cases,
        cases_total=executed,
        cases_passed=passed,
        cases_failed=failed,
        cases_timeout=timeouts,
        fuzz=fuzz_document,
        correspondence=dict(
            checked=sum(1 for case in cases
                        if case.get('correspondence') in ('matched', 'mismatched')),
            matched=sum(1 for case in cases if case.get('correspondence') == 'matched'),
            mismatched=mismatches),
        assertions=dict(
            enabled=True,
            enablement='verilator-default: the 5.x frontend executes assert statements '
                       'without --assert; verified with a standalone probe model',
            capture=('prefix replay: one child process per case, each running the '
                     'first k+1 transactions, so the state sequence is preserved and '
                     'the abort is attributable to the one new transaction'
                     if isolation else
                     'long running: the whole session is one process, so an abort ends '
                     'it at the transaction that raised it; the event keeps the file, '
                     'line, scope and text Verilator printed plus that transaction, and '
                     'no earlier transaction is re-run to find it'),
            tick_attribution=('recorded from the host tick stream'
                              if trace_ticks else
                              'unavailable: the tick stream was suppressed'),
            model_assertion_code_present=bool(assertion_sites),
            model_assertion_sites=assertion_sites,
            events=assertions,
            triggers=(('observed: the model aborted at the site above'
                       if len(assertions) else
                       'none fired: the linked model carries compiled assertion code '
                       'at the listed sites, but no declared or declared-fault '
                       'transaction reached one in this batch') if assertion_sites else
                      'none available: the linked model archive contains no compiled '
                      'assertion code, so this build cannot raise a DUT assertion'),
            helper='agent C\'s shared assertion helper is not present yet; '
                   'classify_child_process/scan_assertion_lines in this module are '
                   'the integration point that helper replaces'),
        environment_issues=environment,
        host_log=dict(path=str(output / 'run.log'),
                      summary=parsed['summary'], header=parsed['header'],
                      timing=parsed['timing'],
                      last_case_tick=(parsed['ticks'][-1] if parsed['ticks'] else None),
                      child_runs=(len(isolation_state['prefix_runs']) if isolation
                                  else 1)),
        build=dict(link_seconds=build.get('link_seconds'),
                   link_cache_hit=build.get('link_cache_hit'),
                   link_cache_key=build.get('link_cache_key'),
                   returncode=build.get('returncode'),
                   archive_count=len(archives),
                   link_log=str(output / 'link.log')),
        advance=advance,
        prefix_replay=(dict(
            consistent=isolation_state['consistent'],
            runs=isolation_state['prefix_runs'],
            case_wall_seconds=[row['derived_case_seconds']
                               for row in isolation_state['prefix_runs']],
            prefix_wall_seconds=[row['seconds']
                                 for row in isolation_state['prefix_runs']])
            if isolation else None),
        per_case_wall_seconds=(
            [row['derived_case_seconds'] for row in isolation_state['prefix_runs']]
            if isolation else None),
        wall_seconds=dict(total=total_seconds, run=build.get('run_seconds'),
                          link=build.get('link_seconds')),
        total_seconds=total_seconds,
        toolchain=_toolchain_row(),
        certificate='none', replay='not_performed', coverage='not_measured',
        notes=[
            'the model archive list is the link\'s own: it contains the target '
            'archive and no CPU or DMA archive',
            'a device response is the beat response (rdata/error) plus the protocol '
            'trace completion; either one alone is not a passed read or write',
            'the protocol trace sample, the completion criterion and the case-line '
            'words come from the target\'s own generated traits, per protocol: '
            'psel+penable+pready (APB3), cyc+ack (Wishbone), the A then D handshake '
            '(TL-UL), and the B/R response after its request channels (AXI4-Lite)',
            'a bus timeout is reported under environment_issues and is never counted '
            'as a device assertion',
            'the interrupt output is sampled and its edges reported; nothing consumes '
            'it in an IP-only run',
            'decimal resistors: advance.dut_share_of_run is measured inside the model, '
            'not estimated from wall time',
            'no RTL coverage, certificate or replay is claimed'])
    if assertions:
        (output / 'assertions.jsonl').write_text(
            ''.join(json.dumps(event, sort_keys=True) + '\n' for event in assertions))
    (output / 'transactions.json').write_text(json.dumps(
        dict(schema_version='inprocess_ip_only_transactions.v1',
             source=('closed-loop fuzz policy over the ' + source + ' corpus'
                     if fuzz_spec is not None else
                     'online hand-over of the ' + source + ' list'
                     if online else source),
             sequence_loops=(1 if (online or fuzz_spec is not None) else loops),
             transactions=result['transactions'],
             fuzz_records=(None if fuzz_document is None else fuzz_document['records'])),
        indent=2) + '\n')
    if fuzz_document is not None:
        (output / 'fuzz.json').write_text(json.dumps(fuzz_document, indent=2) + '\n')
    (output / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def session_advance_measurement(*, isolation, timing, prefix_runs, run_seconds,
                                planned_cases):
    """How much of this run was the DUT being advanced, measured not estimated.

    The host measures the seconds it spent inside the model's own evaluation and
    the ticks that bought.  In long-running mode there is one child, so that pair
    is the whole session.  In prefix replay there is one child per case, the last
    of which executes the complete list: its pair is the single pass, and the sum
    over all children is the work actually executed, which is larger than one
    pass by exactly the replayed prefixes.  ``run_seconds`` is the parent's wall
    around every child, so ``overhead = run_seconds - dut_seconds`` is the time
    that went into process starts, I/O and printing rather than the DUT.
    """
    rows = [row for row in (prefix_runs or []) if row.get('timing')]
    if isolation:
        single = rows[-1]['timing'] if rows else {}
        total_dut = sum((row['timing'] or {}).get('dut_seconds') or 0.0 for row in rows)
        total_wall = sum((row['timing'] or {}).get('wall_seconds') or 0.0 for row in rows)
        total_ticks = sum((row['timing'] or {}).get('ticks') or 0 for row in rows)
        transaction_runs = sum(row.get('prefix_transactions') or 0 for row in rows)
        child_runs = len(rows)
    else:
        single = timing or {}
        total_dut = single.get('dut_seconds') or 0.0
        total_wall = single.get('wall_seconds') or 0.0
        total_ticks = single.get('ticks') or 0
        transaction_runs = planned_cases
        child_runs = 1
    run = run_seconds if isinstance(run_seconds, (int, float)) else None
    overhead = None if run is None else max(0.0, run - total_dut)
    return dict(
        source='the host\'s own timing line: wall seconds inside one process, the '
               'seconds spent inside the model\'s evaluation, and the ticks that '
               'advanced it',
        child_runs=child_runs,
        planned_cases=planned_cases,
        single_pass=dict(ticks=single.get('ticks'),
                         dut_seconds=single.get('dut_seconds'),
                         wall_seconds=single.get('wall_seconds')),
        total=dict(ticks=total_ticks, dut_seconds=total_dut,
                   wall_seconds=total_wall),
        run_seconds=run,
        restart_overhead_seconds=overhead,
        dut_share_of_run=(None if not run else
                          (single.get('dut_seconds') or 0.0) / run),
        transaction_runs=transaction_runs,
        replayed_transactions=max(0, transaction_runs - planned_cases))


def _toolchain_row():
    try:
        from myfuzz.local_harness.build import _toolchain
        tools = _toolchain()
        verilator = tools.get('verilator', {}).get('path')
        version = None
        if verilator:
            try:
                completed = subprocess.run([verilator, '--version'],
                                           capture_output=True, text=True)
                version = (completed.stdout or completed.stderr).strip()
            except OSError:
                version = None
        return dict(verilator=verilator, version=version,
                    cxx=tools.get('cxx', {}).get('path'))
    except Exception as error:  # pragma: no cover - toolchain discovery is external
        return dict(error=str(error))


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--records', default=None)
    parser.add_argument('--online', action='store_true')
    parser.add_argument('--fuzz', action='store_true',
                        help='closed loop: mutate the next transaction from the device '
                             'answers already observed in this session')
    parser.add_argument('--cases', type=int, default=FUZZ_DEFAULT_CASES,
                        help='fuzz case budget (default %d)' % FUZZ_DEFAULT_CASES)
    parser.add_argument('--seed', type=int, default=FUZZ_DEFAULT_SEED,
                        help='fuzz PRNG seed (deterministic for the same tree)')
    parser.add_argument('--case-isolation', choices=CASE_ISOLATION_MODES,
                        default=None,
                        help='session shape: one long-running process per session '
                             '(default) or the historical one-child-per-case prefix '
                             'replay')
    parser.add_argument('--max-ticks', type=int, default=None)
    parser.add_argument('--quiet', action='store_true')
    args = parser.parse_args(argv)
    result = run_ip_only(
        args.config, args.cache, args.output, records=args.records,
        online=args.online, max_ticks=args.max_ticks, quiet=args.quiet,
        case_isolation=args.case_isolation,
        fuzz=(dict(cases=args.cases, seed=args.seed) if args.fuzz else None))
    print(json.dumps(dict(status=result['status'], output=str(args.output),
                          cases=result['cases_executed'],
                          passed=result['cases_passed'],
                          isolation=result['session']['isolation_mode'],
                          model_archives=result['model_archives']['all'],
                          total_seconds=result['total_seconds'])))
    return 0 if result['status'] in ('observations_passed', 'fuzz_completed') else 1


if __name__ == '__main__':
    raise SystemExit(main())
