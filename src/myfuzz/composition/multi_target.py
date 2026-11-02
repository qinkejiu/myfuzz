"""Address-routed declarations for one CPU with several independent MMIO IPs.

The unified in-process F1-F6 entry was written around one CPU, one register
target and one optional DMA: ``source_profile``/``active_id``/``target_window``
described the one target, and every helper in that entry (the window builder,
the record parser, the F5 program generator and the report) reads those three
keys directly.  Reaching a second IP that way would mean copying the CPU wiring
per target.  This module is the pure-Python half of the alternative: one CPU,
one RAM image, one DMA window, and an ordered ``targets`` declaration whose
windows are routed by address.  The C++ host and the entry still have to be
taught to build one model per target; nothing here claims they already do.

What is declared
----------------

A scenario declares ``targets`` as a list of 1..8 rows::

    "targets": [
      {"name": "timer",
       "profile": "configs/peripherals/pulp_timer_irq/component_profile.json",
       "active_id": "pulp_timer_active",
       "window": {"base": 1073745920, "size": 4096},
       "timing": {"reset_assert_ticks": 2, "reset_release_ticks": 3,
                  "max_wait_cycles": 16},
       "behavior": "configs/behaviors/pulp_timer_f5.json",
       "pins": null,
       "fixed_inputs": [],
       "tuning": {}},
      ...
    ]

The legacy single-target keys (``source_profile``, ``active_id``,
``target_window``, ``source_timing``, ``source_behavior``, ``pins``,
``source_fixed_inputs``, ``source_tuning``) are normalized to the same list of
one target, so the integration can keep reading a legacy scenario.  Declaring
``targets`` and any legacy target key together is refused rather than resolved
in favour of one shape.  Inline F5 facts at the top level (``source_port`` and
friends) are legacy single-target declarations too and are refused alongside
``targets`` for the same reason.

Routing
-------

:func:`target_windows` normalizes the declarations and returns the host's
address view: the RAM image, the ordered target windows, the optional DMA
control window, and the first target's window under the historical
``ip_base``/``ip_size`` names.  Windows are half-open and checked for every
pairwise overlap, including RAM and DMA.  :func:`route_address` maps one
address to ``(target_index, offset)``; an address in RAM, in the DMA window or
outside every declared window returns ``None``, and a non-word address that
does fall inside a target window is refused by name.

The one IRQ line
----------------

The CPU has one external interrupt input, and the host delivers the OR of every
declared F5 link's real device output to it.  A target's IRQ output may exist and
be observable without being wired, but a declaring target is wired.  Two
selection helpers exist because two builds do: :func:`target_for_f5` keeps the
historical single-owner rule and refuses two declaring targets with
``unsupported-f5:multiple-target-irq-sources``; :func:`targets_for_f5` returns
every declaring target in declaration order, which is what the multi-target entry
uses to build one global link table.  One F5 case still selects one link (and
therefore one target), so an assertion attributed to a target is the one the ISR
really read, never an inference from the shared line.

What this module does not do
----------------------------

It does not read or elaborate RTL, does not prove a profile's register map,
does not know whether a behavior file agrees with the device, and does not
build or run a model.  The profile/behavior cross-checks the entry already
performs stay the entry's job; this module only decides which declared target
owns which address and which one may carry F5.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path

#: One CPU reaches at most eight independently addressed MMIO targets.  The
#: bound is a declaration limit, not a bus limit: the host's routing table and
#: report are sized from it.
MAX_TARGETS = 8

MAX_WORD = (1 << 32) - 1
MAX_ADDRESS = 1 << 32

#: Fixed offsets of the one RAM image the unified entry builds.  They are copied
#: from the entry rather than imported from it so this module stays a pure
#: declaration/routing layer and can be tested without the entry's RTL imports.
DATA_OFFSET = 0x4000
DMA_DESTINATION_OFFSET = 0x7000
DMA_BLOCK_BYTES = 4 * 4
#: The RAM has to hold the fixed image through the DMA destination block.  The
#: current entry refuses a smaller image before it routes anything; the check is
#: repeated here so a target declaration cannot be separated from a usable RAM.
MINIMUM_RAM_SIZE = DMA_DESTINATION_OFFSET + DMA_BLOCK_BYTES

#: The four facts F5 needs from a target: the IRQ output and bit, the writable
#: trigger sequence, and the one readable status word.  The entry's ``F5_KEYS``
#: has the same values; they are repeated here because importing the entry would
#: pull in its build/RTL layer for a pure-Python check.
F5_FACT_KEYS = ('source_port', 'source_bit_offset', 'trigger_writes', 'status_offsets')

#: The single-target keys the entry already knows.  A scenario that declares
#: ``targets`` may not also carry them: there would be two spellings of target 0
#: and no honest way to choose between them.
LEGACY_TARGET_KEYS = (
    'source_profile', 'active_id', 'target_window', 'source_timing',
    'source_behavior', 'pins', 'source_fixed_inputs', 'source_tuning',
)
#: Inline F5 facts are the other legacy single-target declaration.  They live at
#: the top level in old scenarios, so a multi-target scenario that also carries
#: them is ambiguous even though it states no ``source_behavior`` file.
LEGACY_INLINE_BEHAVIOR_KEYS = (
    'source_port', 'source_bit_offset', 'pulse_width_ticks', 'trigger_writes',
    'status_offsets', 'status_cause_bits', 'clear_writes', 'irq_sources',
)

#: One new ``targets`` row, in normalized order.  The metadata keys are accepted
#: and ignored; they never leak into the normalized target.
TARGET_KEYS = ('profile', 'active_id', 'window', 'timing', 'behavior', 'pins',
               'fixed_inputs', 'tuning', 'name')
TARGET_METADATA_KEYS = ('description', 'notes')
TIMING_KEYS = ('reset_assert_ticks', 'reset_release_ticks', 'max_wait_cycles')
FIXED_INPUT_KEYS = ('endpoint_id', 'role', 'value')

#: The checked-in two-IP scenario this module was verified against.  The helper
#: below loads it by this exact relative path.
TWO_IP_SCENARIO_PATH = 'configs/scenarios/inprocess-obi-apb-two-ip-timer-i2c-f1f6.json'


class MultiTargetError(ValueError):
    """A target declaration, window set, route or F5 selection is refused."""


def _fail(reason: str) -> None:
    raise MultiTargetError(reason)


def _is_int(value: object) -> bool:
    """A JSON integer, not a bool and not a float."""
    return type(value) is int


def _copy(value: object) -> object:
    """A JSON-shaped deep copy, so callers never share a declaration's lists."""
    if isinstance(value, Mapping):
        return {key: _copy(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_copy(item) for item in value]
    return value


def _relative_path(value: object, reason: str) -> str:
    """The declared path as a normalized relative POSIX path, or a refusal."""
    if not isinstance(value, str) or not value or '\x00' in value or '\\' in value:
        _fail(reason)
    candidate = Path(value)
    if candidate.is_absolute() or not candidate.parts or '..' in candidate.parts:
        _fail(reason)
    return candidate.as_posix()


def _window(value: object, reason: str) -> dict:
    """``{base, size}`` from a declaration, with both fields required ints."""
    if not isinstance(value, Mapping):
        _fail(reason)
    base, size = value.get('base'), value.get('size')
    if not _is_int(base) or not _is_int(size):
        _fail(reason)
    return {'base': base, 'size': size}


def _check_target_window(window: dict, index: int) -> None:
    """A target window has to hold at least one word inside the address space."""
    base, size = window['base'], window['size']
    if base < 0 or size < 4 or base + size > MAX_ADDRESS:
        _fail('unsupported-target-window-range:%d' % index)
    if base % 4:
        _fail('unsupported-target-window-alignment:%d' % index)


def _timing(value: object, reason: str) -> dict | None:
    """The three explicit timing facts the entry's request builder requires."""
    if value is None:
        return None
    if not isinstance(value, Mapping):
        _fail(reason)
    checked = {}
    for key in value:
        if key not in TIMING_KEYS:
            _fail(reason)
    for key in TIMING_KEYS:
        item = value.get(key)
        if not _is_int(item) or item < 0:
            _fail(reason)
        checked[key] = item
    return checked


def _pins(value: object, reason: str) -> dict | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        _fail(reason)
    return _copy(value)  # type: ignore[return-value]


def _fixed_inputs(value: object, reason: str) -> list[dict]:
    """The declared constant pad inputs, normalized to ``{endpoint_id, role, value}``."""
    if value is None:
        return []
    if not isinstance(value, list):
        _fail(reason)
    rows: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for row in value:
        if not isinstance(row, Mapping):
            _fail(reason)
        for key in row:
            if key not in FIXED_INPUT_KEYS:
                _fail(reason)
        endpoint_id, role, constant = (row.get('endpoint_id'), row.get('role'),
                                       row.get('value'))
        if (not isinstance(endpoint_id, str) or not endpoint_id
                or not isinstance(role, str) or not role
                or not _is_int(constant) or not 0 <= constant <= MAX_WORD):
            _fail(reason)
        key = (endpoint_id, role)
        if key in seen:
            _fail(reason)
        seen.add(key)
        rows.append({'endpoint_id': endpoint_id, 'role': role, 'value': constant})
    return rows


def _tuning(value: object, reason: str) -> dict:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        _fail(reason)
    return _copy(value)  # type: ignore[return-value]


def _active_id(value: object, index: int) -> str:
    if not isinstance(value, str) or not value or '\x00' in value \
            or any(character.isspace() for character in value) \
            or any(character in '/\\:' for character in value):
        _fail('unsupported-target-active-id:%d' % index)
    return value


def _behavior_path(value: object, index: int) -> str | None:
    if value is None:
        return None
    return _relative_path(value, 'unsupported-target-behavior:%d' % index)


def _target_row(row: object, index: int) -> dict:
    """Validate and normalize one new ``targets`` row."""
    if not isinstance(row, Mapping):
        _fail('unsupported-target:%d' % index)
    for key in row:
        if key not in TARGET_KEYS and key not in TARGET_METADATA_KEYS:
            _fail('unsupported-target-field:' + str(key))
    description = row.get('description')
    if description is not None and not isinstance(description, str):
        _fail('unsupported-target-metadata:%d' % index)
    notes = row.get('notes')
    if notes is not None and (not isinstance(notes, list)
                              or any(not isinstance(note, str) for note in notes)):
        _fail('unsupported-target-metadata:%d' % index)
    name = row['name'] if 'name' in row else 'target%d' % index
    if not isinstance(name, str) or not name or '\x00' in name:
        _fail('unsupported-target-name:%d' % index)
    window = _window(row.get('window'), 'unsupported-target-window:%d' % index)
    _check_target_window(window, index)
    return {
        'profile': _relative_path(row.get('profile'),
                                  'unsupported-target-profile:%d' % index),
        'active_id': _active_id(row.get('active_id'), index),
        'window': window,
        'timing': _timing(row.get('timing'), 'unsupported-target-timing:%d' % index),
        'behavior': _behavior_path(row.get('behavior'), index),
        'pins': _pins(row.get('pins'), 'unsupported-target-pins:%d' % index),
        'fixed_inputs': _fixed_inputs(row.get('fixed_inputs'),
                                      'unsupported-target-fixed-inputs:%d' % index),
        'tuning': _tuning(row.get('tuning'), 'unsupported-target-tuning:%d' % index),
        'index': index,
        'name': name,
    }


def _legacy_target(config: Mapping) -> dict:
    """The one target a legacy single-target scenario already declares."""
    window = _window(config.get('target_window'), 'unsupported-target-window:0')
    _check_target_window(window, 0)
    return {
        'profile': _relative_path(config.get('source_profile'),
                                  'unsupported-target-profile:0'),
        'active_id': _active_id(config.get('active_id'), 0),
        'window': window,
        'timing': _timing(config.get('source_timing'),
                          'unsupported-target-timing:0'),
        'behavior': _behavior_path(config.get('source_behavior'), 0),
        'pins': _pins(config.get('pins'), 'unsupported-target-pins:0'),
        'fixed_inputs': _fixed_inputs(config.get('source_fixed_inputs'),
                                      'unsupported-target-fixed-inputs:0'),
        'tuning': _tuning(config.get('source_tuning'), 'unsupported-target-tuning:0'),
        'index': 0,
        'name': 'source',
    }


def _overlaps(left: Mapping, right: Mapping) -> bool:
    """Half-open windows overlap; touching endpoints do not."""
    return max(left['base'], right['base']) < min(left['base'] + left['size'],
                                                 right['base'] + right['size'])


def _check_unique(targets: Sequence[Mapping]) -> None:
    active_ids: set[str] = set()
    names: set[str] = set()
    for target in targets:
        active_id, name = target['active_id'], target['name']
        if active_id in active_ids:
            _fail('unsupported-target-active-id-duplicate:' + active_id)
        active_ids.add(active_id)
        if name in names:
            _fail('unsupported-target-name-duplicate:' + name)
        names.add(name)


def _check_target_pair_overlaps(targets: Sequence[Mapping]) -> None:
    for left in range(len(targets)):
        for right in range(left + 1, len(targets)):
            if _overlaps(targets[left]['window'], targets[right]['window']):
                _fail('unsupported-window-overlap:target[%d]-target[%d]'
                      % (left, right))


def _normalize_targets(config: Mapping) -> list[dict]:
    """The declared target list, before RAM/DMA windows are attached."""
    if 'targets' in config:
        legacy = [key for key in LEGACY_TARGET_KEYS + LEGACY_INLINE_BEHAVIOR_KEYS
                  if key in config]
        if legacy:
            _fail('unsupported-targets-ambiguous:' + legacy[0])
        rows = config['targets']
        if not isinstance(rows, list):
            _fail('unsupported-targets-shape')
        if not 1 <= len(rows) <= MAX_TARGETS:
            _fail('unsupported-targets-count')
        targets = [_target_row(row, index) for index, row in enumerate(rows)]
    else:
        targets = [_legacy_target(config)]
    _check_unique(targets)
    _check_target_pair_overlaps(targets)
    return targets


def _ram_window(start: int, end: int) -> dict:
    """The RAM image as a half-open window, from its declared start and end."""
    if start < 0 or end <= start or end > MAX_ADDRESS:
        _fail('unsupported-ram:range')
    if start % 4:
        _fail('unsupported-ram:alignment')
    return {'base': start, 'size': end - start}


def _ram_from_config(config: Mapping, *, required: bool) -> dict | None:
    if 'image_start' not in config and 'image_end' not in config:
        if required:
            _fail('unsupported-ram:missing')
        return None
    start, end = config.get('image_start'), config.get('image_end')
    if not _is_int(start) or not _is_int(end):
        _fail('unsupported-ram:type')
    return _ram_window(start, end)


def _ram_override(value: object) -> dict:
    """``ram=`` is either ``{base, size}`` or a ``(base, size)`` pair."""
    if isinstance(value, Mapping):
        base, size = value.get('base'), value.get('size')
    elif isinstance(value, (list, tuple)) and len(value) == 2:
        base, size = value
    else:
        _fail('unsupported-ram:type')
    if not _is_int(base) or not _is_int(size):
        _fail('unsupported-ram:type')
    if base < 0 or size < 4 or base + size > MAX_ADDRESS:
        _fail('unsupported-ram:range')
    if base % 4:
        _fail('unsupported-ram:alignment')
    return {'base': base, 'size': size}


def _dma_window_value(value: object) -> dict:
    """A DMA control window: aligned to its own size and to a 32-bit word."""
    if isinstance(value, Mapping):
        base, size = value.get('base'), value.get('size')
    elif isinstance(value, (list, tuple)) and len(value) == 2:
        base, size = value
    else:
        _fail('unsupported-dma-window:type')
    if not _is_int(base) or not _is_int(size):
        _fail('unsupported-dma-window:type')
    if base < 0 or size < 4 or size % 4 or base + size > MAX_ADDRESS:
        _fail('unsupported-dma-window:range')
    if base % size:
        _fail('unsupported-dma-window:alignment')
    return {'base': base, 'size': size}


def _dma_from_config(config: Mapping) -> dict | None:
    raw = config.get('dma_window')
    if raw is None:
        return None
    return _dma_window_value(raw)


def _dma_declared_size(config: Mapping, declared_size: int) -> dict:
    """The current entry's ``dma_window_size`` check, kept for compatibility.

    ``target_windows(config, dma_window=dma_profile.address.window_size)`` is
    the direct replacement for ``declared_windows(config, dma_window_size)``:
    the config still states the window, and the profile's declared size must
    agree with it exactly.
    """
    if not _is_int(declared_size) or declared_size < 4 or declared_size % 4:
        _fail('unsupported-dma-window:size')
    raw = config.get('dma_window')
    if raw is None:
        _fail('unsupported-dma-window:missing')
    window = _dma_window_value(raw)
    if window['size'] != declared_size:
        _fail('unsupported-dma-window:size')
    return window


def _check_routing(targets: Sequence[Mapping], ram: Mapping | None,
                   dma: Mapping | None) -> None:
    """No target window may overlap RAM or the DMA control window."""
    if ram is not None:
        for index, target in enumerate(targets):
            if _overlaps(target['window'], ram):
                _fail('unsupported-window-overlap:target[%d]-ram' % index)
    if dma is not None:
        for index, target in enumerate(targets):
            if _overlaps(target['window'], dma):
                _fail('unsupported-window-overlap:target[%d]-dma' % index)
        if ram is not None and _overlaps(ram, dma):
            _fail('unsupported-window-overlap:ram-dma')


def target_as_legacy_config(target: Mapping) -> dict:
    """One normalized target as the legacy single-target config the entry reads.

    The current entry's per-target helpers (``profile_protocol``,
    ``source_request_from_profile``, ``source_behavior``, ``pin_declaration``,
    ``irq_declaration`` and ``declared_windows``) all take the legacy keys.
    This adapter lets the integration call them once per target without
    copying the CPU wiring or teaching those helpers about ``targets``.

    Optional ``source_behavior``/``pins``/``source_timing`` keys are present
    only when the target states them: an explicit ``pins: null`` would be read
    by the behavior layer as an attempted pad declaration, not as absence.
    ``source_fixed_inputs`` and ``source_tuning`` are always present because
    their empty values are meaningful to the request builder.
    """
    if not isinstance(target, Mapping):
        _fail('unsupported-target:legacy-config')
    for key in ('profile', 'active_id', 'window'):
        if key not in target:
            _fail('unsupported-target:legacy-config')
    legacy = {
        'source_profile': target['profile'],
        'active_id': target['active_id'],
        'target_window': _copy(target['window']),
        'source_fixed_inputs': _copy(target.get('fixed_inputs') or []),
        'source_tuning': _copy(target.get('tuning') or {}),
    }
    if target.get('timing') is not None:
        legacy['source_timing'] = _copy(target['timing'])
    if target.get('behavior') is not None:
        legacy['source_behavior'] = target['behavior']
    if target.get('pins') is not None:
        legacy['pins'] = _copy(target['pins'])
    return legacy


def declared_targets(config: dict) -> list[dict]:
    """Normalize the declared targets to an ordered list of 1..8 target dicts.

    New declarations use ``targets``; the historical single-target keys are
    normalized to one target named ``"source"``.  Each returned target has the
    exact keys ``profile``, ``active_id``, ``window``, ``timing``, ``behavior``,
    ``pins``, ``fixed_inputs``, ``tuning``, ``index`` and ``name``.  Optional
    facts are ``None`` for ``timing``/``behavior``/``pins``, ``[]`` for
    ``fixed_inputs`` and ``{}`` for ``tuning``.

    The declaration is refused by name for a bad count or shape, a duplicate
    ``active_id`` or name, an unsafe profile/behavior path, a malformed or
    unusable window, an overlapping target pair, and a target window overlapping
    the RAM image or DMA window when the config states them.
    """
    if not isinstance(config, Mapping):
        _fail('unsupported-targets-shape')
    targets = _normalize_targets(config)
    ram = _ram_from_config(config, required=False)
    dma = _dma_from_config(config)
    _check_routing(targets, ram, dma)
    return targets


def target_windows(config: dict, *, ram: dict | tuple | list | None = None,
                   dma_window: dict | tuple | list | int | None = None) -> dict:
    """The host's address view for the declared targets.

    Returns ``ram_base``/``ram_size``, the ordered ``ip_targets`` list of
    ``{base, size}``, the first target's window under the historical
    ``ip_base``/``ip_size`` names, the optional ``dma_base``/``dma_size``,
    ``data_base`` (the fixed program-data window inside RAM) and
    ``target_count``.

    ``ram`` overrides the config's ``image_start``/``image_end`` and is either
    ``{base, size}`` or ``(base, size)``.  ``dma_window`` overrides the
    config's ``dma_window`` in the same shape; passing an integer instead keeps
    the config's window and requires its size to equal that declared DMA
    window size, which is how the current entry's ``declared_windows(config,
    dma_window_size)`` call is replaced.

    The checks the current entry performs are repeated here (RAM word alignment
    and fixed-image minimum, target word alignment and range, DMA control-window
    size/alignment, and the RAM/DMA/target overlaps), plus every target-target
    pair.  All windows are half-open.
    """
    if not isinstance(config, Mapping):
        _fail('unsupported-targets-shape')
    targets = _normalize_targets(config)
    ram_window = (_ram_override(ram) if ram is not None
                  else _ram_from_config(config, required=True))
    if dma_window is None:
        dma = _dma_from_config(config)
    elif _is_int(dma_window):
        dma = _dma_declared_size(config, dma_window)
    else:
        dma = _dma_window_value(dma_window)
    if ram_window['size'] < MINIMUM_RAM_SIZE:
        _fail('unsupported-ram:too-small')
    _check_routing(targets, ram_window, dma)
    first = targets[0]['window']
    return {
        'ram_base': ram_window['base'],
        'ram_size': ram_window['size'],
        'ip_targets': [{'base': target['window']['base'],
                        'size': target['window']['size']}
                       for target in targets],
        'ip_base': first['base'],
        'ip_size': first['size'],
        'dma_base': None if dma is None else dma['base'],
        'dma_size': None if dma is None else dma['size'],
        'data_base': ram_window['base'] + DATA_OFFSET,
        'target_count': len(targets),
    }


def route_address(windows: dict, address: int) -> tuple[int, int] | None:
    """Route one CPU address to ``(target_index, offset)`` or ``None``.

    ``None`` is the honest answer for RAM, for the DMA control window and for
    any address outside every declared target window; those are not target
    words and the caller has its own handling for them.  An address that *is*
    inside a target window but is not 4-byte aligned is refused by name, because
    a target word is the unit the host routes.  Overlapping target windows are
    refused rather than resolved to the first match.
    """
    if not isinstance(windows, Mapping):
        _fail('unsupported-route-windows')
    ip_targets = windows.get('ip_targets')
    if not isinstance(ip_targets, list) or not ip_targets:
        _fail('unsupported-route-windows')
    for row in ip_targets:
        if (not isinstance(row, Mapping) or not _is_int(row.get('base'))
                or not _is_int(row.get('size')) or row['base'] < 0
                or row['size'] < 4 or row['base'] + row['size'] > MAX_ADDRESS):
            _fail('unsupported-route-windows')
    if not _is_int(address):
        _fail('unsupported-address:type')
    if address < 0 or address > MAX_WORD:
        _fail('unsupported-address:range')
    matches = [(index, address - row['base'])
               for index, row in enumerate(ip_targets)
               if row['base'] <= address < row['base'] + row['size']]
    if not matches:
        return None
    if len(matches) > 1:
        _fail('unsupported-route-windows:overlap')
    index, offset = matches[0]
    if address % 4:
        _fail('unsupported-address:unaligned')
    return index, offset


def _f5_facts(behavior: object) -> Mapping | None:
    """The F5 facts a behavior declaration carries, or ``None``.

    A flat v1 fact set counts when all four F5 facts are present.  A v2
    declaration carries its links in ``sources``; one complete link is enough
    for the target to be the one IRQ target, because the entry selects one link
    per F5 case.  Presence is the selection criterion; the entry still validates
    the values and the profile cross-check.
    """
    if behavior is None:
        return None
    if not isinstance(behavior, Mapping):
        _fail('unsupported-f5:behavior-shape')
    if all(key in behavior for key in F5_FACT_KEYS):
        return behavior
    sources = behavior.get('sources')
    if isinstance(sources, list):
        for source in sources:
            if isinstance(source, Mapping) and all(key in source for key in F5_FACT_KEYS):
                return source
    return None


def _behavior_rows(targets: Sequence[Mapping], behaviors: object) -> list[object]:
    """One behavior entry per target, from a parallel sequence or a mapping.

    A mapping may be keyed by target index, name or ``active_id``; a key that
    names no target is refused instead of being ignored.  A single raw behavior
    dict is accepted only for a one-target declaration, where it is unambiguous.
    """
    count = len(targets)
    if behaviors is None:
        return [None] * count
    if isinstance(behaviors, Mapping):
        if any(key in behaviors for key in F5_FACT_KEYS) or 'sources' in behaviors:
            if count != 1:
                _fail('unsupported-f5:behaviors-shape')
            return [behaviors]
        known = set()
        for target in targets:
            known.update((target['index'], target['name'], target['active_id']))
        if set(behaviors) - known:
            _fail('unsupported-f5:behaviors-shape')
        rows = []
        for target in targets:
            values = [behaviors[key] for key in
                      (target['index'], target['name'], target['active_id'])
                      if key in behaviors]
            if len(values) > 1 and any(value != values[0] for value in values[1:]):
                _fail('unsupported-f5:behaviors-shape')
            rows.append(values[0] if values else None)
        return rows
    if isinstance(behaviors, Sequence) and not isinstance(behaviors, (str, bytes, bytearray)):
        if len(behaviors) != count:
            _fail('unsupported-f5:behaviors-shape')
        return list(behaviors)
    _fail('unsupported-f5:behaviors-shape')


def _target_rows(targets: object) -> list[dict]:
    """The index/name/active_id rows :func:`_behavior_rows` is keyed by."""
    if not isinstance(targets, Sequence) or isinstance(targets, (str, bytes, bytearray)):
        _fail('unsupported-f5:targets-shape')
    rows = []
    for index, target in enumerate(targets):
        if not isinstance(target, Mapping):
            _fail('unsupported-f5:targets-shape')
        target_index = target.get('index', index)
        target_name = target.get('name', 'target%d' % index)
        active_id = target.get('active_id')
        if not _is_int(target_index) or not isinstance(target_name, str) \
                or (active_id is not None and not isinstance(active_id, str)):
            _fail('unsupported-f5:targets-shape')
        rows.append({'index': target_index, 'name': target_name,
                     'active_id': active_id})
    return rows


def targets_for_f5(targets: list[dict], behaviors: object) -> list[dict]:
    """Every target whose behavior states all four F5 facts, in declaration order.

    This is the multi-target selection: each returned target may own one or
    more declared IRQ links, and the entry numbers all of their links in one
    global table.  ``behaviors`` is either one entry per target (parallel to
    ``targets``) or a mapping keyed by target index, name or ``active_id``.  A
    target counts only when its entry states all four F5 facts (directly or in a
    v2 ``sources`` link).  An empty list means no target declares F5 facts.

    The returned rows are the caller's own target mappings, so a caller reads
    the target's index and window exactly as it declared them.
    """
    rows = _target_rows(targets)
    behavior_rows = _behavior_rows(rows, behaviors)
    return [target for target, behavior in zip(targets, behavior_rows)
            if _f5_facts(behavior) is not None]


def target_for_f5(targets: list[dict], behaviors: object) -> dict | None:
    """The one target that may carry F5, ``None``, or the multiple-source refusal.

    ``behaviors`` is either one entry per target (parallel to ``targets``) or a
    mapping keyed by target index, name or ``active_id``.  Each entry is the
    behavior facts the entry's ``source_behavior`` layer returns for that
    target, or ``None``.  A target counts only when its entry states all four
    F5 facts (directly or in a v2 ``sources`` link).

    This helper keeps the historical single-owner rule: the CPU has one IRQ line
    and a legacy build has one ISR status/result/clear cell set, so two declaring
    targets are refused here with
    ``unsupported-f5:multiple-target-irq-sources``.  The multi-target entry calls
    :func:`targets_for_f5` instead: there every declaring target's real IRQ
    output feeds the one CPU input through the host's OR, and one F5 case selects
    one global link.  Observing a second target's IRQ output without delivering
    it would still not be delivery, and neither function claims that.
    """
    declaring = targets_for_f5(targets, behaviors)
    if len(declaring) > 1:
        _fail('unsupported-f5:multiple-target-irq-sources')
    return declaring[0] if declaring else None


def single_irq_target(targets: list[dict], behaviors: object) -> dict | None:
    """Alias for :func:`target_for_f5`: the one target allowed to own the IRQ line."""
    return target_for_f5(targets, behaviors)


def two_ip_scenario(*, base_dir: object | None = None) -> dict:
    """Load the checked-in two-IP scenario (timer + I2C) as a fresh document.

    The default base directory is the repository root this source file lives
    under.  The document is returned as JSON, not validated: pass it to
    :func:`declared_targets` and :func:`target_windows` for that.
    """
    root = Path(base_dir).resolve() if base_dir is not None else Path(__file__).resolve().parents[3]
    path = root / TWO_IP_SCENARIO_PATH
    try:
        text = path.read_text(encoding='utf-8')
    except OSError:
        _fail('unsupported-two-ip-scenario:missing')
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError):
        _fail('unsupported-two-ip-scenario:json')
    if not isinstance(document, dict):
        _fail('unsupported-two-ip-scenario:document')
    return document


__all__ = [
    'F5_FACT_KEYS',
    'MAX_TARGETS',
    'MultiTargetError',
    'TWO_IP_SCENARIO_PATH',
    'declared_targets',
    'route_address',
    'single_irq_target',
    'target_as_legacy_config',
    'target_for_f5',
    'target_windows',
    'targets_for_f5',
    'two_ip_scenario',
]
