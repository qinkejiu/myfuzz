"""Declarative device-behavior facts for the unified in-process F1-F6 entry.

The executor is deliberately split in two layers.  The *protocol connection* -
an APB3, AXI4-Lite or Wishbone adapter plus the host's RAM and bus routing - is
written once per protocol and is not described here.  The *device behavior* is
per component: how an interrupt is produced and cleared, which register is the
status word an ISR reads, which registers trigger it, how a pin pad is resolved,
and where a DMA's control-status bits live.  This module reads that second layer.

One behavior document (``configs/behaviors/*.json``) holds one device's facts.
A scenario points at it with a relative path (``source_behavior`` for an F5
source, ``dma_behavior`` for an F6 DMA), so several scenarios can share the same
file and a new device can be described without editing the executor.  The inline
scenario keys the executor already consumes keep working, but when a file and an
inline value disagree the disagreement is refused by name instead of one of them
being silently ignored.

The split is intentionally narrow and honest about what it owns:

* owned here - the shape and ranges of every fact, file-over-inline precedence,
  conflict refusal, and provenance (``declared_by`` / ``declaration_path``);
* not owned here - whether the facts agree with the device's own register map
  and interrupt declaration.  The executor keeps doing that cross-check
  (``irq_declaration`` / ``pin_declaration`` / ``dma_declaration``), and no
  behavior file proves that the device actually behaves as declared.

The ZipDMA control-status bits are the honest incremental case: they were the
anonymous executor constants ``DMA_BUSY_BIT`` / ``DMA_ERR_BIT``.  They are now a
reported built-in default (``builtin_zipdma_rtl_default``) until a DMA behavior
file states them, and ``configs/behaviors/zipdma_f6.json`` is that declaration.

Two expressive extensions live here, and both keep the same split:

* **ordered clear sequences** (``clear_sequence``) - a link may state its clear as
  a write/read/write sequence or as a list of clear writes instead of the single
  ``clear_writes`` row.  The sequence is normalized and validated here; a
  one-write sequence *is* the executor's single clear write and is derived into
  ``clear_writes``, while any longer sequence or a clear-by-read is refused by
  name (``unsupported-behavior-execution:...``) because this host performs one
  clear write.  The declaration is never narrowed silently.
* **named pad groups / a serial peer** (``pin_groups``) - one or more pad
  groups, each either the dir-resolved pad word this host resolves (with its
  direction and hold timing) or a serial peer that states the two pad roles and
  the bit timing a host serial driver would need.  Every group kind is executable
  now: the host drives up to ``MAX_PIN_GROUPS`` dir-resolved groups in declaration
  order, each for its own declared window, and one framed serial peer per target
  (it drives ``rx_role`` and samples ``tx_role`` at ``bit_ticks`` per bit in the
  declared 8n1/8e1/8o1 frame).  A group the host cannot execute is refused by
  name by the same ``execution_refusals`` list.

And one declarable DMA capability set (``capabilities``: channels, beat size,
outstanding count, beats per burst).  It is shape-checked here and *reported*;
the planner cross-checks it against the selected device's pinned facts and
refuses an overstated declaration by name.  No number declared here is narrowed
to the four-word single-channel transfer the current host runs.
"""

from __future__ import annotations

import json
from pathlib import Path

SOURCE_BEHAVIOR_SCHEMA = 'inprocess_source_behavior.v1'
#: A v2 source file states its F5 links as a list instead of one flat fact set.
#: One link is the v1 shape; N links let one target declare several real IRQ
#: outputs, each with its own status word, cause bits, clear write and trigger
#: sequence.  The executor selects one link per F5 case instead of OR-ing two
#: sources into one handler read.
SOURCE_BEHAVIOR_SCHEMA_V2 = 'inprocess_source_behavior.v2'
DMA_BEHAVIOR_SCHEMA = 'inprocess_dma_behavior.v1'
BEHAVIOR_DOCUMENT_SCHEMA = 'inprocess_behavior.v1'

#: F5 keys the executor already consumes.  A file may state them; the inline
#: scenario keys stay supported for existing configurations.
SOURCE_BEHAVIOR_KEYS = ('source_port', 'source_bit_offset', 'pulse_width_ticks',
                        'trigger_writes', 'status_offsets', 'status_cause_bits',
                        'clear_writes')
#: The per-link keys beyond the executor's flat set: the report-only name and the
#: ordered clear sequence.  A clear belongs to one IRQ link (each link has its own
#: status word and acknowledge), so the sequence is a link fact, not a device one.
SOURCE_LINK_KEYS = SOURCE_BEHAVIOR_KEYS + ('name', 'clear_sequence')
#: The document-level keys a v1 file may additionally state: the pad model and its
#: group spelling, and the clear sequence for the single flat link.
SOURCE_DOCUMENT_EXTRA_KEYS = ('pins', 'pin_groups', 'clear_sequence')
#: One target may declare up to this many IRQ links.  The host's dispatch table
#: and the per-case link selector are sized from this bound.
MAX_SOURCE_LINKS = 8
DMA_BEHAVIOR_KEYS = ('block_words', 'irq_pulse_ticks', 'busy_bit', 'err_bit',
                     'status_kind', 'capabilities')

#: The one pad model this host implements: a pin is driven by the device's own
#: output while its dir bit is high, and by the declared external value otherwise.
PAD_RESOLUTION = 'device_drives_when_dir_bit_high_else_host'
PIN_KEYS = ('padin_offset', 'external_value', 'pad_resolution')

#: One behavior document may declare its pads as a list of named groups instead
#: of the single ``pins`` block.  A group is either the dir-resolved pad word this
#: host already resolves (plus the direction/timing the group states) or a serial
#: peer: the two pad roles a framed serial line occupies and the bit timing the
#: peer drives.  Both kinds are executable by the current host (see
#: ``HOST_SOURCE_EXECUTION``); a group it cannot execute is refused by name
#: instead of being dropped.
PIN_GROUP_KINDS = ('dir_resolved_pad_word', 'serial_peer')
PIN_GROUP_DIRECTIONS = ('in', 'out', 'inout')
PIN_GROUP_DIR_KEYS = ('name', 'kind', 'direction', 'hold_ticks',
                      'padin_offset', 'external_value', 'pad_resolution')
PIN_GROUP_SERIAL_KEYS = ('name', 'kind', 'rx_role', 'tx_role', 'tx_en_role',
                         'idle_level', 'bit_ticks', 'frame')
#: The frame shapes the host's serial driver encodes and decodes: eight data
#: bits, no parity or even/odd parity, one stop bit.  A shape outside this tuple
#: (more stop bits, fewer data bits, two stop bits) is a declaration-value
#: refusal, not a narrowed frame.
SERIAL_FRAMES = ('8n1', '8e1', '8o1')
MAX_PIN_GROUPS = 4
MAX_PIN_HOLD_TICKS = 65535
MAX_SERIAL_BIT_TICKS = 1 << 20

#: One behavior link may declare its clear as an ordered sequence of register
#: steps instead of the single ``clear_writes`` row: a write step, a read step,
#: or the ``[offset, value]`` pair shorthand for a write.  The order is the order
#: the handler performs it, so a write/read/write sequence is not the same
#: declaration as three independent clears.
CLEAR_STEP_KINDS = ('write', 'read')
CLEAR_STEP_KEYS = {'write': ('kind', 'offset', 'value'), 'read': ('kind', 'offset')}
MAX_CLEAR_STEPS = 8

#: What the current in-process F5 host executes, stated as a fact so the
#: declaration layer can name what it refuses.  ``clear_steps`` is the number of
#: clear steps the handler performs; ``pin_groups`` the number of pad groups the
#: host drives, in declaration order, each for its own declared window;
#: ``pin_group_kinds`` the group kinds it has a model for; ``serial_peer`` whether
#: it has a framed serial driver at all and ``serial_peers`` how many peers it
#: drives on one target.  Raising or lowering a number here is how a host admits
#: more or less without this parser changing.
#:
#: The pad-word and serial-peer execution landed together, so both group kinds are
#: executable now: up to ``MAX_PIN_GROUPS`` dir-resolved pad groups (each with its
#: own direction witness and hold window) and one serial peer per target (a
#: framed driver on ``rx_role`` and a sampler on ``tx_role``, with ``tx_en_role``
#: asserted while a frame the host drives is on the wire).  What still has no
#: model is named by ``execution_refusals``: a group kind outside this tuple, a
#: pad word the bound endpoint does not expose (the entry names that one), a
#: half-duplex peer whose rx and tx roles are the same pad, a role set that puts
#: tx_en on a data role, and more than one peer per target.
HOST_SOURCE_EXECUTION = {
    'clear_steps': 1,
    'pin_groups': MAX_PIN_GROUPS,
    'pin_group_kinds': ('dir_resolved_pad_word', 'serial_peer'),
    'serial_peer': True,
    'serial_peers': 1,
}

#: What the current in-process F6 host executes of a DMA's declared capabilities:
#: one channel, one 32-bit beat per master request, and one outstanding request.
#: A behavior file or profile that declares more is refused by name by the
#: planner (``dma_transfer``); nothing here silently narrows a declaration.
HOST_DMA_CAPABILITY = {'channels': 1, 'beat_bytes': 4, 'max_outstanding': 1,
                       'burst_beats': 1}
#: The declarable DMA capability names and the range a declaration may state.
#: These are shape bounds, not device limits: the device bound is cross-checked
#: by the planner against its pinned facts.
DMA_CAPABILITY_KEYS = ('channels', 'beat_bytes', 'max_outstanding', 'burst_beats')
DMA_CAPABILITY_BOUNDS = {'channels': (1, 64), 'beat_bytes': (1, 128),
                         'max_outstanding': (1, 16), 'burst_beats': (1, 256)}

#: What a DMA control-status register is, as the declaration states it.  A name
#: without a recognisable word stays ``undeclared`` rather than being guessed.
DMA_STATUS_KINDS = ('status', 'count', 'compare', 'control', 'data', 'undeclared')

#: The declared-by-nobody default for the DMA control-status bits.  These are the
#: ZipDMA control bits (``third_party/soc-zipcpu/rtl/zipdma/zipdma_ctrl.v:116-117``);
#: a device that wants other positions declares them in its own behavior file.
BUILTIN_STATUS_SOURCE = 'builtin_zipdma_rtl_default'
ZIPDMA_BUSY_BIT = 31
ZIPDMA_ERR_BIT = 30
BUILTIN_DMA_STATUS_KIND = 'status'

MAX_WORD = (1 << 32) - 1
MAX_SOURCE_BIT = 63
MAX_PULSE_TICKS = 4096

#: Metadata a behavior file may carry.  It is accepted and never leaks into the
#: returned fact dict.
METADATA_KEYS = ('schema_version', 'description', 'notes')

#: Inline scenario spellings of the declarable DMA facts.  ``busy_bit``,
#: ``err_bit`` and ``status_kind`` have no inline form: the scenario vocabulary
#: never carried them, so a device states them in its file or reports the default.
DMA_INLINE_KEYS = {'block_words': 'dma_block_words',
                   'irq_pulse_ticks': 'dma_irq_pulse_ticks'}


class BehaviorError(ValueError):
    """A behavior declaration is absent, malformed, conflicting or unsafe."""


def _fail(reason: str) -> None:
    raise BehaviorError(reason)


def _is_int(value: object) -> bool:
    """A JSON integer, not a bool and not a float."""
    return type(value) is int


def _is_word(value: object) -> bool:
    return _is_int(value) and 0 <= value <= MAX_WORD


def _copy(value: object) -> object:
    """A JSON-shaped deep copy, so callers never share a fact dict's lists."""
    if isinstance(value, dict):
        return {key: _copy(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_copy(item) for item in value]
    return value


def _relative_path(path: object) -> str:
    """The declared path as a normalized relative POSIX path, or a refusal."""
    if not isinstance(path, str) or not path or '\x00' in path or '\\' in path:
        _fail('unsupported-behavior-path')
    candidate = Path(path)
    if candidate.is_absolute() or not candidate.parts or '..' in candidate.parts:
        _fail('unsupported-behavior-path')
    return candidate.as_posix()


def _check_document(document: dict, *, schema: str, allowed: tuple[str, ...]) -> None:
    """The file's own version, field set and metadata types."""
    observed = document.get('schema_version')
    if observed != schema:
        if 'schema_version' not in document:
            label = 'missing'
        else:
            label = observed if isinstance(observed, str) and observed else 'invalid'
        _fail('unsupported-behavior-schema:' + label)
    for key in document:
        if key in METADATA_KEYS or key in allowed:
            continue
        _fail('unsupported-behavior-field:' + key)
    description = document.get('description')
    if description is not None and not isinstance(description, str):
        _fail('unsupported-behavior-value:description')
    notes = document.get('notes')
    if notes is not None and (not isinstance(notes, list)
                              or any(not isinstance(note, str) for note in notes)):
        _fail('unsupported-behavior-value:notes')


def read_behavior_file(path: object, *, base_dir: object) -> dict:
    """Read one declared behavior document, resolved inside ``base_dir``.

    A behavior file is a repo-relative path: absolute paths and paths escaping
    ``base_dir`` are unsafe declarations, not alternative spellings.  The raw
    document is returned; the callers own the schema and fact checks.
    """
    relative = _relative_path(path)
    base = Path(base_dir).resolve()
    candidate = (base / relative).resolve()
    try:
        candidate.relative_to(base)
    except ValueError:
        _fail('unsupported-behavior-path')
    if not candidate.is_file():
        _fail('unsupported-behavior-file:' + relative)
    try:
        text = candidate.read_text(encoding='utf-8')
    except OSError:
        _fail('unsupported-behavior-file:' + relative)
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError):
        _fail('unsupported-behavior-json:' + relative)
    if not isinstance(document, dict):
        _fail('unsupported-behavior-document:' + relative)
    return document


def _writes(value: object, key: str, *, least: int, most: int | None) -> list[list[int]]:
    """A list of ``[offset, value]`` register writes, bounded in length."""
    if not isinstance(value, list):
        _fail('unsupported-behavior-value:' + key)
    if len(value) < least or (most is not None and len(value) > most):
        _fail('unsupported-behavior-value:' + key)
    rows = []
    for row in value:
        if not isinstance(row, list) or len(row) != 2:
            _fail('unsupported-behavior-value:' + key)
        offset, data = row
        if not _is_word(offset) or not _is_word(data):
            _fail('unsupported-behavior-value:' + key)
        rows.append([offset, data])
    return rows


def _pad_word(value: object, where: str) -> dict:
    """The dir-resolved pad facts, validated from one object.

    ``where`` is the field path the refusal names, so the same pad word is
    refused as ``pins.padin_offset`` in the v1 block and as
    ``pin_groups.padin_offset`` in a group.
    """
    if not isinstance(value, dict):
        _fail('unsupported-behavior-value:' + where)
    if value.get('pad_resolution') != PAD_RESOLUTION:
        _fail('unsupported-behavior-value:' + where + '.pad_resolution')
    offset = value.get('padin_offset')
    if not _is_int(offset) or offset < 0:
        _fail('unsupported-behavior-value:' + where + '.padin_offset')
    external = value.get('external_value')
    if not _is_word(external):
        _fail('unsupported-behavior-value:' + where + '.external_value')
    return {'padin_offset': offset, 'external_value': external,
            'pad_resolution': PAD_RESOLUTION}


def _pins(value: object) -> dict:
    """The declared dir-resolved pad model, normalized to its three facts."""
    if not isinstance(value, dict):
        _fail('unsupported-behavior-value:pins')
    for key in value:
        if key not in PIN_KEYS:
            _fail('unsupported-behavior-field:pins.' + key)
    return _pad_word(value, 'pins')


def _clear_sequence(value: object) -> list[dict]:
    """The ordered clear steps of one link, normalized to write/read objects.

    Two spellings are accepted and normalized to the same steps: a list of step
    objects (``{"kind": "write"|"read", "offset": n, "value": v}``) and the
    ``[offset, value]`` pair shorthand for a list of clear writes.  One list may
    not mix the two spellings - that is the ambiguous form - and a read step
    carries no value.
    """
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_CLEAR_STEPS:
        _fail('unsupported-behavior-value:clear_sequence')
    shapes = {isinstance(row, list) for row in value}
    if len(shapes) != 1:
        _fail('unsupported-behavior-value:clear_sequence.mixed')
    steps = []
    for row in value:
        if isinstance(row, list):
            if len(row) != 2:
                _fail('unsupported-behavior-value:clear_sequence')
            offset, data = row
            if not _is_word(offset) or not _is_word(data):
                _fail('unsupported-behavior-value:clear_sequence')
            steps.append({'kind': 'write', 'offset': offset, 'value': data})
            continue
        if not isinstance(row, dict):
            _fail('unsupported-behavior-value:clear_sequence')
        kind = row.get('kind')
        if kind not in CLEAR_STEP_KINDS:
            _fail('unsupported-behavior-value:clear_sequence.kind')
        for key in row:
            if key not in CLEAR_STEP_KEYS[kind]:
                _fail('unsupported-behavior-field:clear_sequence.' + key)
        offset = row.get('offset')
        if not _is_word(offset):
            _fail('unsupported-behavior-value:clear_sequence.offset')
        if kind == 'read':
            if 'value' in row:
                _fail('unsupported-behavior-field:clear_sequence.value')
            steps.append({'kind': 'read', 'offset': offset})
            continue
        data = row.get('value')
        if not _is_word(data):
            _fail('unsupported-behavior-value:clear_sequence.value')
        steps.append({'kind': 'write', 'offset': offset, 'value': data})
    return steps


def _pin_group(row: object, index: int) -> dict:
    """One named pad group, validated and normalized by its declared kind."""
    if not isinstance(row, dict):
        _fail('unsupported-behavior-value:pin_groups')
    kind = row.get('kind')
    if kind not in PIN_GROUP_KINDS:
        _fail('unsupported-behavior-value:pin_groups.kind')
    allowed = (PIN_GROUP_DIR_KEYS if kind == 'dir_resolved_pad_word'
               else PIN_GROUP_SERIAL_KEYS)
    for key in row:
        if key not in allowed:
            _fail('unsupported-behavior-field:pin_groups.' + key)
    name = row.get('name')
    if name is not None and (not isinstance(name, str) or not name):
        _fail('unsupported-behavior-value:pin_groups.name')
    name = 'group%d' % index if name is None else name
    if kind == 'dir_resolved_pad_word':
        pad = _pad_word(row, 'pin_groups')
        direction = row.get('direction', 'inout')
        if direction not in PIN_GROUP_DIRECTIONS:
            _fail('unsupported-behavior-value:pin_groups.direction')
        hold = row.get('hold_ticks', 0)
        if not _is_int(hold) or not 0 <= hold <= MAX_PIN_HOLD_TICKS:
            _fail('unsupported-behavior-value:pin_groups.hold_ticks')
        return dict(name=name, kind=kind, direction=direction, hold_ticks=hold,
                    **pad)
    for key in ('rx_role', 'tx_role'):
        role = row.get(key)
        if not isinstance(role, str) or not role:
            _fail('unsupported-behavior-value:pin_groups.' + key)
    tx_en = row.get('tx_en_role')
    if tx_en is not None and (not isinstance(tx_en, str) or not tx_en):
        _fail('unsupported-behavior-value:pin_groups.tx_en_role')
    idle = row.get('idle_level', 1)
    if not _is_int(idle) or idle not in (0, 1):
        _fail('unsupported-behavior-value:pin_groups.idle_level')
    bit_ticks = row.get('bit_ticks')
    if not _is_int(bit_ticks) or not 1 <= bit_ticks <= MAX_SERIAL_BIT_TICKS:
        _fail('unsupported-behavior-value:pin_groups.bit_ticks')
    frame = row.get('frame', '8n1')
    if frame not in SERIAL_FRAMES:
        _fail('unsupported-behavior-value:pin_groups.frame')
    return dict(name=name, kind=kind, rx_role=row['rx_role'],
                tx_role=row['tx_role'], tx_en_role=tx_en, idle_level=idle,
                bit_ticks=bit_ticks, frame=frame)


def _pin_groups(value: object) -> list[dict]:
    """One or more named pad groups, each validated under its own kind."""
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_PIN_GROUPS:
        _fail('unsupported-behavior-value:pin_groups')
    groups = [_pin_group(row, index) for index, row in enumerate(value)]
    names = [group['name'] for group in groups]
    if len(set(names)) != len(names):
        _fail('unsupported-behavior-value:pin_groups.name')
    return groups


def execution_refusals(facts: dict, *, limits: dict | None = None) -> list[str]:
    """Every declared fact this host has no execution model for, by name.

    The declaration is not narrowed: the returned names say exactly which
    declared clear steps, pad groups or serial peers the current in-process host
    cannot perform, so a caller refuses the declaration instead of running the
    part it happens to understand.  ``limits`` defaults to
    ``HOST_SOURCE_EXECUTION``.

    A pad group is refusable for three independent reasons, and each is named:
    its *kind* has no host model (``...:<kind>``), there are more groups than the
    host drives (``...:pin_groups:<n>``), or a serial peer states a role set the
    framed driver cannot own (``...:serial_peer:half_duplex`` when rx and tx are
    the same pad, ``...:serial_peer:role_conflict`` when tx_en doubles as a data
    role, ``...:serial_peer:count:<n>`` for more peers than the host drives).
    """
    limit = dict(HOST_SOURCE_EXECUTION if limits is None else limits)
    refusals = []
    steps = facts.get('clear_sequence')
    if steps is not None:
        if len(steps) > limit['clear_steps']:
            refusals.append('unsupported-behavior-execution:multi_step_clear:%d'
                            % len(steps))
        elif any(step['kind'] not in ('write',) for step in steps):
            refusals.append('unsupported-behavior-execution:clear_read_step')
    groups = facts.get('pin_groups')
    if groups is not None:
        unsupported = [group for group in groups
                       if group['kind'] not in limit['pin_group_kinds']]
        if unsupported:
            refusals.append('unsupported-behavior-execution:'
                            + unsupported[0]['kind'])
        if len(groups) > limit['pin_groups']:
            refusals.append('unsupported-behavior-execution:pin_groups:%d'
                            % len(groups))
        peers = [group for group in groups if group['kind'] == 'serial_peer']
        allowed = int(limit.get('serial_peers', 0)) if limit.get('serial_peer') else 0
        if len(peers) > allowed:
            refusals.append('unsupported-behavior-execution:serial_peer:count:%d'
                            % len(peers))
        for peer in peers:
            if peer['rx_role'] == peer['tx_role']:
                refusals.append('unsupported-behavior-execution:serial_peer:'
                                'half_duplex')
            if peer['tx_en_role'] is not None \
                    and peer['tx_en_role'] in (peer['rx_role'], peer['tx_role']):
                refusals.append('unsupported-behavior-execution:serial_peer:'
                                'role_conflict')
    return refusals


def dma_capabilities(value: object) -> dict | None:
    """The declared multi-channel / wider-beat / outstanding capabilities.

    This is a declaration layer: the numbers are shape-checked against
    ``DMA_CAPABILITY_BOUNDS`` and returned as stated.  Whether a selected device
    or the current F6 host can honour them is the planner's cross-check, not
    this function's, so a value inside the shape bound is normalized here and
    refused there by name.
    """
    if value is None:
        return None
    if not isinstance(value, dict):
        _fail('unsupported-behavior-value:capabilities')
    capabilities = {}
    for key, item in value.items():
        if key not in DMA_CAPABILITY_KEYS:
            _fail('unsupported-behavior-field:capabilities.' + key)
        low, high = DMA_CAPABILITY_BOUNDS[key]
        if not _is_int(item) or not low <= item <= high:
            _fail('unsupported-behavior-value:capabilities.' + key)
        # A beat is a whole number of byte lanes: a width that is not a power of
        # two is not a beat size any bus encodes, so it is a shape error here
        # rather than a device-bound question later.
        if key == 'beat_bytes' and item & (item - 1):
            _fail('unsupported-behavior-value:capabilities.' + key)
        capabilities[key] = item
    return capabilities


def dma_capability_refusals(capabilities: object, *, limit: dict | None = None) -> list[str]:
    """Declared capabilities that exceed ``limit``, as ``key:declared>limit``.

    The names are the body of a named refusal, not a rewrite: a caller that finds
    any name must refuse the declaration, never lower the declared number.
    """
    bound = HOST_DMA_CAPABILITY if limit is None else limit
    if not capabilities:
        return []
    names = []
    for key in DMA_CAPABILITY_KEYS:
        declared = capabilities.get(key)
        allowed = bound.get(key)
        if declared is None or allowed is None:
            continue
        if declared > allowed:
            names.append('%s:%d>%d' % (key, declared, allowed))
    return names


def _source_facts(facts: dict) -> dict:
    """The merged F5 facts, validated and normalized in declaration order."""
    checked: dict = {}
    if 'source_port' in facts:
        port = facts['source_port']
        if not isinstance(port, str) or not port:
            _fail('unsupported-behavior-value:source_port')
        checked['source_port'] = port
    if 'source_bit_offset' in facts:
        bit = facts['source_bit_offset']
        if not _is_int(bit) or not 0 <= bit <= MAX_SOURCE_BIT:
            _fail('unsupported-behavior-value:source_bit_offset')
        checked['source_bit_offset'] = bit
    if 'pulse_width_ticks' in facts:
        width = facts['pulse_width_ticks']
        if not _is_int(width) or not 1 <= width <= MAX_PULSE_TICKS:
            _fail('unsupported-behavior-value:pulse_width_ticks')
        checked['pulse_width_ticks'] = width
    if 'trigger_writes' in facts:
        checked['trigger_writes'] = _writes(facts['trigger_writes'],
                                           'trigger_writes', least=1, most=None)
    if 'status_offsets' in facts:
        offsets = facts['status_offsets']
        if not isinstance(offsets, list) or len(offsets) != 1 or not _is_word(offsets[0]):
            _fail('unsupported-behavior-value:status_offsets')
        checked['status_offsets'] = [offsets[0]]
    if 'status_cause_bits' in facts:
        bits = facts['status_cause_bits']
        if bits is not None:
            if (not isinstance(bits, list)
                    or any(not _is_int(bit) or not 0 <= bit <= 31 for bit in bits)):
                _fail('unsupported-behavior-value:status_cause_bits')
            bits = list(bits)
        checked['status_cause_bits'] = bits
    if 'clear_writes' in facts:
        checked['clear_writes'] = _writes(facts['clear_writes'],
                                         'clear_writes', least=0, most=1)
    if 'clear_sequence' in facts:
        # One link states its clear one way.  The two spellings are not merged:
        # a declaration that states both is the ambiguous form, and the ordered
        # sequence wins over nothing because nothing else is read.
        if 'clear_writes' in facts:
            _fail('behavior-source-conflict:clear_writes')
        steps = _clear_sequence(facts['clear_sequence'])
        checked['clear_sequence'] = steps
        # A single write step *is* the executor's one clear write, so the flat
        # fact the host consumes is derived here instead of the declaration
        # having to repeat itself in the old spelling.  Any other sequence is
        # left un-derived and refused by ``execution_refusals`` - never dropped.
        if len(steps) == 1 and steps[0]['kind'] == 'write':
            checked['clear_writes'] = [[steps[0]['offset'], steps[0]['value']]]
        else:
            checked['clear_writes'] = []
    return checked


def _source_link(row: object, index: int, *, complete: bool) -> dict:
    """One F5 link, validated as a complete v2 row or a partial v1 fact set.

    A v2 ``irq_sources`` row must state the four facts F5 consumes (port, bit,
    trigger writes and one status word); the v1 flat shape keeps its historical
    partial-fact tolerance because the executor is the layer that checks whether
    all four are present.  The name is report metadata only.
    """
    if not isinstance(row, dict):
        _fail('unsupported-behavior-value:irq_sources')
    for key in row:
        if key not in SOURCE_LINK_KEYS:
            _fail(('unsupported-behavior-field:irq_sources.' if complete
                   else 'unsupported-behavior-field:') + key)
    name = row.get('name')
    if name is not None and (not isinstance(name, str) or not name):
        _fail('unsupported-behavior-value:irq_sources.name')
    facts = _source_facts(row)
    if complete:
        for key in ('source_port', 'source_bit_offset', 'trigger_writes', 'status_offsets'):
            if key not in facts:
                _fail('unsupported-behavior-value:irq_sources.' + key)
    link = dict(facts, index=index, name=name if name is not None else 'source%d' % index)
    return link


def _sources_facts(value: object) -> list[dict]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_SOURCE_LINKS:
        _fail('unsupported-behavior-value:irq_sources')
    links = [_source_link(row, index, complete=True) for index, row in enumerate(value)]
    names = [link['name'] for link in links]
    if len(set(names)) != len(names):
        _fail('unsupported-behavior-value:irq_sources.name')
    return links


def source_behavior(config: dict, *, base_dir: object,
                    limits: dict | None = None) -> dict | None:
    """The declared F5 source behavior, or ``None`` when nothing is declared.

    ``config['source_behavior']`` names a behavior file relative to ``base_dir``.
    Without a file the inline keys keep their old meaning.  With a file the file
    wins per fact, but an inline value that disagrees is refused as
    ``behavior-source-conflict:<key>`` rather than silently dropped.

    ``limits`` is the execution capability the caller wants judged against and
    defaults to ``HOST_SOURCE_EXECUTION``.  Nothing else about the declaration
    changes: the same document normalizes identically for every host, and only
    the set of named execution refusals depends on the limit.

    A v2 file replaces the flat fact set with an ordered ``irq_sources`` list.
    The returned dict always carries ``sources`` (length 1 for the v1/inline
    shape); the first link's facts are also flattened so every existing caller
    keeps its exact field names.

    Returning ``None`` is what keeps the executor's existing F5 refusal path
    intact: a target that declares none of these facts is refused by name there,
    not given a default IRQ here.
    """
    declared = config.get('source_behavior')
    document = None
    if declared is not None:
        document = read_behavior_file(declared, base_dir=base_dir)
        version = document.get('schema_version')
        if version == SOURCE_BEHAVIOR_SCHEMA_V2:
            _check_document(document, schema=SOURCE_BEHAVIOR_SCHEMA_V2,
                            allowed=('irq_sources', 'pins', 'pin_groups'))
        else:
            _check_document(document, schema=SOURCE_BEHAVIOR_SCHEMA,
                            allowed=SOURCE_BEHAVIOR_KEYS + SOURCE_DOCUMENT_EXTRA_KEYS)
    # The pads are device facts, so a v2 file states them once beside its links.
    # They are parsed before the "is this an F5 declaration at all" question: a
    # pad declaration the host cannot resolve must be refused even when the
    # scenario declares no IRQ fact.  The two spellings - the v1 pad word and the
    # named group list - are not merged: a declaration that states both is the
    # ambiguous form.
    file_groups = document.get('pin_groups') if document is not None else None
    if file_groups is not None and 'pin_groups' in config \
            and config['pin_groups'] != file_groups:
        _fail('behavior-source-conflict:pin_groups')
    declared_groups = file_groups if file_groups is not None else config.get('pin_groups')
    file_pins = document.get('pins') if document is not None else None
    if file_pins is not None and 'pins' in config and config['pins'] != file_pins:
        _fail('behavior-source-conflict:pins')
    declared_pins = file_pins if file_pins is not None else config.get('pins')
    if declared_pins is not None and declared_groups is not None:
        _fail('behavior-source-conflict:pins')
    pins = None
    groups = None
    if declared_groups is not None:
        groups = _pin_groups(declared_groups)
        # The bound pad endpoint of the selected device owns one pad word, so the
        # first dir-resolved group is the one whose pad word the ``pins`` fact
        # states; the declaration keeps every group, and the entry is the layer
        # that refuses a group addressing a pad word the endpoint does not expose
        # (``unsupported-pins:pin_groups:second-pad-word``) instead of dropping
        # it.  Groups of different pad words are not merged into one word here.
        pad_groups = [group for group in groups
                      if group['kind'] == 'dir_resolved_pad_word']
        if pad_groups:
            pins = {key: pad_groups[0][key] for key in PIN_KEYS}
    elif declared_pins is not None:
        pins = _pins(declared_pins)
    # A declaration that states no F5 fact and no group list is not an F5
    # declaration: the executor's own refusal path stays the authority there.
    # A group list *is* a declaration this layer consumes, so it is not dropped.
    if document is None and groups is None \
            and not any(key in config
                        for key in SOURCE_BEHAVIOR_KEYS + ('clear_sequence',)):
        return None
    if document is not None and 'irq_sources' in document:
        if any(key in document for key in SOURCE_BEHAVIOR_KEYS):
            _fail('unsupported-behavior-field:irq_sources')
        if any(key in config for key in SOURCE_BEHAVIOR_KEYS):
            _fail('behavior-source-conflict:irq_sources')
        links = _sources_facts(document['irq_sources'])
        facts: dict = {}
    else:
        facts = {}
        for key in SOURCE_BEHAVIOR_KEYS + ('clear_sequence',):
            if document is not None and key in document:
                if key in config and config[key] != document[key]:
                    _fail('behavior-source-conflict:' + key)
                facts[key] = document[key]
            elif key in config:
                facts[key] = config[key]
        links = [_source_link(facts, 0, complete=False)] if facts else []
    merged = dict(links[0]) if links else {}
    merged.pop('index', None)
    merged.pop('name', None)
    # The flat v1 shape stays byte-identical: ``sources``/``source_count`` are
    # added only when the declaration actually states more than one link (or a v2
    # file was read), so every existing caller keeps its exact fact dict.
    if len(links) > 1 or (document is not None
                          and document.get('schema_version') == SOURCE_BEHAVIOR_SCHEMA_V2):
        merged['sources'] = links
        merged['source_count'] = len(links)
    if groups is not None:
        merged['pin_groups'] = groups
        merged['pin_group_count'] = len(groups)
    merged['pins'] = pins
    # A declared form this host has no execution model for is refused by name
    # here, before any caller can run the part it happens to understand.  The
    # declaration itself is not rewritten: the named refusal is the answer.
    refusals: list[str] = []
    for link in links:
        refusals.extend(execution_refusals(link, limits=limits))
    if groups is not None:
        refusals.extend(execution_refusals({'pin_groups': groups}, limits=limits))
    if refusals:
        _fail(refusals[0])
    merged['declared_by'] = 'file' if document is not None else 'inline'
    merged['declaration_path'] = None if declared is None else _relative_path(declared)
    return merged


def dma_behavior(config: dict, *, base_dir: object) -> dict:
    """The declared F6 DMA behavior with the reported built-in status default.

    ``config['dma_behavior']`` names a file; ``dma_block_words`` and
    ``dma_irq_pulse_ticks`` stay supported inline.  ``block_words`` and
    ``irq_pulse_ticks`` are ``None`` when nobody declared them: this module does
    not invent a block length or a pulse width.

    The control-status bits are the reported default until a device states its
    own.  ``status_bits_declared`` / ``status_bits_source`` say which case holds,
    so a run summary can no longer present the ZipDMA RTL constants as if the
    selected device had declared them.
    """
    declared = config.get('dma_behavior')
    document = None
    if declared is not None:
        document = read_behavior_file(declared, base_dir=base_dir)
        _check_document(document, schema=DMA_BEHAVIOR_SCHEMA,
                        allowed=DMA_BEHAVIOR_KEYS)
    facts: dict = {}
    for key, inline in DMA_INLINE_KEYS.items():
        if document is not None and key in document:
            if inline in config and config[inline] != document[key]:
                _fail('behavior-source-conflict:' + key)
            facts[key] = document[key]
        elif inline in config:
            facts[key] = config[inline]
    if document is not None:
        for key in ('busy_bit', 'err_bit', 'status_kind'):
            if key in document:
                facts[key] = document[key]
    # A declared multi-channel / wider-beat / outstanding count is normalized as
    # the declaration states it and reported with the named refusals this host's
    # F6 executor would owe it.  It is never narrowed to what runs: the planner
    # (`myfuzz.composition.dma_transfer`) is the authority that refuses a plan
    # whose declaration exceeds the selected device, and it names the same facts.
    capabilities = dma_capabilities(document.get('capabilities')
                                    if document is not None else None)
    capability_refusals = ['unsupported-dma-capability:' + name
                           for name in dma_capability_refusals(capabilities)]
    block_words = None
    if 'block_words' in facts:
        block_words = facts['block_words']
        if not _is_int(block_words) or not 1 <= block_words <= 4:
            _fail('unsupported-behavior-value:block_words')
    irq_pulse_ticks = None
    if 'irq_pulse_ticks' in facts:
        irq_pulse_ticks = facts['irq_pulse_ticks']
        if not _is_int(irq_pulse_ticks) or not 1 <= irq_pulse_ticks <= MAX_PULSE_TICKS:
            _fail('unsupported-behavior-value:irq_pulse_ticks')
    # A device states both control-status bits or neither: pairing a declared bit
    # with a built-in one would report one number from two different sources.
    if ('busy_bit' in facts) != ('err_bit' in facts):
        _fail('unsupported-behavior-value:status_bits')
    status_bits_declared = 'busy_bit' in facts
    if status_bits_declared:
        busy_bit = facts['busy_bit']
        err_bit = facts['err_bit']
        if not _is_int(busy_bit) or not 0 <= busy_bit <= 31:
            _fail('unsupported-behavior-value:busy_bit')
        if not _is_int(err_bit) or not 0 <= err_bit <= 31:
            _fail('unsupported-behavior-value:err_bit')
        if busy_bit == err_bit:
            _fail('unsupported-behavior-value:err_bit')
        status_bits_source = _relative_path(declared)
    else:
        busy_bit, err_bit = ZIPDMA_BUSY_BIT, ZIPDMA_ERR_BIT
        status_bits_source = BUILTIN_STATUS_SOURCE
    status_kind = BUILTIN_DMA_STATUS_KIND
    if 'status_kind' in facts:
        status_kind = facts['status_kind']
    if status_kind not in DMA_STATUS_KINDS:
        _fail('unsupported-behavior-value:status_kind')
    result = dict(block_words=block_words, irq_pulse_ticks=irq_pulse_ticks,
                  busy_bit=busy_bit, err_bit=err_bit, status_kind=status_kind,
                  status_bits_declared=status_bits_declared,
                  status_bits_source=status_bits_source,
                  declared_by='file' if document is not None else 'inline',
                  declaration_path=None if declared is None else _relative_path(declared))
    # The historical fact set stays byte-identical for a file that declares no
    # capability: a minimal declaration normalizes to exactly what it always did.
    if capabilities is not None:
        result['capabilities'] = capabilities
        result['capability_refusals'] = capability_refusals
        result['capabilities_executable'] = not capability_refusals
    return result


def behavior_document(source: dict | None, dma: dict | None) -> dict:
    """A JSON-ready summary of what was declared and from where, for a run log.

    The fact dicts are copied, so a summary keeps the declaration it reports even
    if the caller later reuses or mutates its own dicts.
    """
    return {'schema_version': BEHAVIOR_DOCUMENT_SCHEMA,
            'source': None if source is None else _copy(source),
            'dma': None if dma is None else _copy(dma)}


__all__ = [
    'BEHAVIOR_DOCUMENT_SCHEMA',
    'BUILTIN_DMA_STATUS_KIND',
    'BUILTIN_STATUS_SOURCE',
    'BehaviorError',
    'CLEAR_STEP_KEYS',
    'CLEAR_STEP_KINDS',
    'DMA_BEHAVIOR_KEYS',
    'DMA_BEHAVIOR_SCHEMA',
    'DMA_CAPABILITY_BOUNDS',
    'DMA_CAPABILITY_KEYS',
    'DMA_INLINE_KEYS',
    'DMA_STATUS_KINDS',
    'HOST_DMA_CAPABILITY',
    'HOST_SOURCE_EXECUTION',
    'MAX_CLEAR_STEPS',
    'MAX_PIN_GROUPS',
    'METADATA_KEYS',
    'PAD_RESOLUTION',
    'PIN_GROUP_DIRECTIONS',
    'PIN_GROUP_KINDS',
    'PIN_KEYS',
    'MAX_SERIAL_BIT_TICKS',
    'MAX_SOURCE_LINKS',
    'SERIAL_FRAMES',
    'SOURCE_BEHAVIOR_KEYS',
    'SOURCE_BEHAVIOR_SCHEMA',
    'SOURCE_BEHAVIOR_SCHEMA_V2',
    'SOURCE_DOCUMENT_EXTRA_KEYS',
    'SOURCE_LINK_KEYS',
    'ZIPDMA_BUSY_BIT',
    'ZIPDMA_ERR_BIT',
    'behavior_document',
    'dma_behavior',
    'dma_capabilities',
    'dma_capability_refusals',
    'execution_refusals',
    'read_behavior_file',
    'source_behavior',
]
