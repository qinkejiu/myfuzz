"""The declared word-level input space of the F2..F6 flows.

A closed-loop fuzzer draws a fresh record per case and then mutates it, but the
single-process host only accepts records that the scenario and target profiles
declare.  This module is that declaration projected into words: the RAM data
window, the readable and writable target registers, the optional external pin
word, the declared F5 trigger-write values and the declared DMA block length.

The record shapes are the host's own:

* ``F2:<address>`` reads one RAM data word or one readable target register.  On
  a pin target the PADIN address may carry a second word with the external pin
  stimulus, and no other address may.
* ``F3:<address>:<value>`` stores one word in the RAM data window.
* ``F4:<address>:<value>`` stores one word in a writable target register.
* ``F5:<w0>:...:<wN>`` carries one value per declared trigger write.
* ``F6:<w0>:...:<wN>`` carries one value per declared DMA block word.

The module is pure: stdlib only, no file I/O, no clock, and the caller's
``random.Random`` is the only source of choice.  The caller builds
:class:`DeclaredSpace` from its own scenario and profiles; this module never
reads a JSON file and never imports the host script.

Rules
-----
1. Only 4-byte aligned words inside the declared windows are candidates.
   Readable target words are 32-bit registers with ``ro`` or ``rw`` access and
   writable target words are 32-bit registers with ``wo`` or ``rw`` access.  A
   write to a read-only register is not in the space even when the bus accepts
   it.  The RAM space is ``data_base + 4*k`` for the declared program data
   words, clipped to the declared RAM image.
2. A fresh value is a random 32-bit word, with a small interesting pool drawn
   about two times in five.  Pin registers (PADOUT, PADOUTSET, PADOUTCLR and
   PADIN) are masked to the declared pin width.
3. ``mutate`` applies one to three word-level changes that are legal by
   construction and never changes the record length of F3..F6.  A two-word F2
   exists only at PADIN.
4. ``valid`` is the same declaration check the host applies to an operator
   record, minus the host's firmware side effects: flow, length, word range,
   alignment, window membership and the pin width.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

_MASK32 = 0xFFFFFFFF
_INTERESTING = (0, 1, 0xFFFFFFFF, 0x80000000)
_DELTAS = (1, 2, 4, 8, 16, 0x100, 0x1000, 0x10000)
_F6_EXAMPLE = (0xDEADBEEF, 0x11111111, 0x22222222, 0x33333333)
_PIN_VALUE_NAMES = ('PADOUT', 'PADOUTSET', 'PADOUTCLR')
_READABLE_ACCESS = ('ro', 'rw')
_WRITABLE_ACCESS = ('wo', 'rw')
_KNOWN_FLOWS = ('F2', 'F3', 'F4', 'F5', 'F6')
_FIXED_ARITY = {'F3': 2, 'F4': 2}


@dataclass(frozen=True, slots=True)
class DeclaredSpace:
    """The scenario facts the word space is derived from.

    The caller fills this from the scenario declaration and the target profile:
    ``ram_base``/``ram_size`` are the host's RAM image, ``data_base`` is the
    program data window the firmware exposes to F2 reads and F3 stores,
    ``target_base``/``target_size`` are the first register target window, and
    ``registers`` is the profile's ``address.registers`` rows.  ``targets``
    optionally states the whole address-routed target list; each row carries its
    own window and register map, which is how one CPU with several independent
    MMIO IPs reaches every one of them.  ``arity`` is
    the serving components' word count per flow (the host's ``flow_arity``
    plus F2), ``pins`` is ``{'padin_offset': int, 'width': int}`` on a pin
    target and ``None`` otherwise.  ``trigger_values`` holds the declared F5
    example rows and ``block_words`` the declared DMA block length.
    """

    ram_base: int
    ram_size: int
    data_base: int
    target_base: int
    target_size: int
    arity: dict[str, int]
    registers: tuple[dict, ...]
    pins: dict | None
    trigger_values: tuple[tuple[int, ...], ...] = ()
    block_words: int = 0
    program_data_words: int = 16
    #: Optional address-routed target list, one row per declared IP:
    #: ``{'index': int, 'base': int, 'size': int, 'registers': tuple}``.
    #: When it is empty the legacy single ``target_base``/``target_size``/
    #: ``registers`` projection is used, so every existing caller keeps the
    #: exact address space it had.
    targets: tuple[dict, ...] = ()


class WordSpace:
    """The address sets, values and mutators declared by one scenario."""

    def __init__(self, declaration: DeclaredSpace) -> None:
        self.declaration = declaration
        self._ram_base = _int_field(declaration.ram_base)
        self._ram_size = _int_field(declaration.ram_size)
        self._data_base = _int_field(declaration.data_base)
        self._target_base = _int_field(declaration.target_base)
        self._target_size = _int_field(declaration.target_size)
        self._target_rows = self._declared_target_rows()
        self._multiple_targets = bool(declaration.targets)
        arity = declaration.arity if isinstance(declaration.arity, dict) else {}
        self._arity = {key: value for key, value in arity.items()
                       if key in _KNOWN_FLOWS}
        block = _int_field(declaration.block_words)
        self._block_words = block if block > 0 else 0
        words = _int_field(declaration.program_data_words)
        self._program_data_words = words if words > 0 else 0
        self._register_rows = self._read_register_rows()
        self._readable_rows = self._rows_for_access(_READABLE_ACCESS)
        self._writable_rows = self._rows_for_access(_WRITABLE_ACCESS)
        self._readable_addresses = tuple(row['address'] for row in self._readable_rows)
        self._writable_addresses = tuple(row['address'] for row in self._writable_rows)
        self._ram_addresses = self._data_window_addresses()
        (self._padin_offset, self._padin_address,
         self._pin_width) = self._pin_declaration()
        self._pin_mask = ((1 << self._pin_width) - 1
                          if self._pin_width < 32 else _MASK32)
        self._pin_mask_addresses = self._pin_masked_addresses()
        self._f2_addresses = self._f2_address_list()
        self._trigger_rows = self._declared_trigger_rows()
        self._f6_example_used = False

    # -- declaration projection -------------------------------------------
    def _declared_target_rows(self) -> tuple[dict, ...]:
        """The address-routed target list, or the one legacy target row."""
        declared = self.declaration.targets
        rows = []
        if declared:
            for index, item in enumerate(declared):
                if not isinstance(item, dict):
                    continue
                base = _int_field(item.get('base'))
                size = _int_field(item.get('size'))
                registers = item.get('registers')
                rows.append({'index': index, 'base': base, 'size': size,
                             'registers': tuple(registers or ())})
        if not rows:
            rows.append({'index': 0, 'base': self._target_base,
                         'size': self._target_size,
                         'registers': tuple(self.declaration.registers or ())})
        return tuple(rows)

    def _read_register_rows(self) -> tuple[dict, ...]:
        rows = []
        for target in self._target_rows:
            base, size = target['base'], target['size']
            for item in target['registers']:
                if not isinstance(item, dict):
                    continue
                offset = item.get('offset')
                width = item.get('width')
                access = item.get('access')
                if type(offset) is not int or type(width) is not int:
                    continue
                if not isinstance(access, str):
                    continue
                if not self._inside_target(offset, base, size):
                    continue
                name = item.get('name')
                row = {'offset': offset,
                       'address': base + offset,
                       'name': name if isinstance(name, str) else '',
                       'width': width,
                       'access': access.lower()}
                if self._multiple_targets:
                    row['target'] = target['index']
                rows.append(row)
        return tuple(rows)

    def _rows_for_access(self, access: tuple[str, ...]) -> tuple[dict, ...]:
        rows = []
        seen = set()
        for row in self._register_rows:
            if row['width'] != 32 or row['access'] not in access:
                continue
            if row['address'] in seen:
                continue
            seen.add(row['address'])
            rows.append(row)
        return tuple(rows)

    @staticmethod
    def _inside_target(offset: int, base: int, size: int) -> bool:
        if size < 4 or base % 4:
            return False
        if offset < 0 or offset % 4 or offset + 4 > size:
            return False
        address = base + offset
        return 0 <= address <= _MASK32

    def _data_window_addresses(self) -> tuple[int, ...]:
        end = self._ram_base + self._ram_size
        base = self._data_base
        if self._ram_size < 4 or base < self._ram_base or base % 4:
            return ()
        if base + 4 > end:
            return ()
        available = (end - base) // 4
        count = min(self._program_data_words, available)
        return tuple(base + 4 * index for index in range(count)
                     if base + 4 * index <= _MASK32)

    def _pin_declaration(self) -> tuple[int | None, int | None, int]:
        pins = self.declaration.pins
        if not isinstance(pins, dict):
            return None, None, 0
        offset = pins.get('padin_offset')
        width = pins.get('width', 32)
        if (type(offset) is not int
                or not self._inside_target(offset, self._target_base, self._target_size)):
            return None, None, 0
        if type(width) is not int or width < 0:
            width = 32
        return offset, self._target_base + offset, min(width, 32)

    def _pin_masked_addresses(self) -> frozenset[int]:
        if self._padin_address is None:
            return frozenset()
        addresses = {row['address'] for row in self._register_rows
                     if row['name'].upper() in _PIN_VALUE_NAMES}
        addresses.add(self._padin_address)
        return frozenset(addresses)

    def _f2_address_list(self) -> tuple[int, ...]:
        addresses = list(self._readable_addresses)
        if (self._padin_address is not None
                and self._padin_address not in addresses):
            addresses.append(self._padin_address)
        for address in self._ram_addresses:
            if address not in addresses:
                addresses.append(address)
        return tuple(addresses)

    def _declared_trigger_rows(self) -> tuple[tuple[int, ...], ...]:
        rows = []
        for row in self.declaration.trigger_values or ():
            if not isinstance(row, (tuple, list)):
                continue
            values = tuple(row)
            if not values or any(type(value) is not int for value in values):
                continue
            rows.append(values)
        return tuple(rows)

    def _mask_for(self, address: int) -> int:
        if self._padin_address is None:
            return _MASK32
        return self._pin_mask if address in self._pin_mask_addresses else _MASK32

    # -- declaration checks ------------------------------------------------
    def flows(self) -> tuple[str, ...]:
        """The flows this declaration can serve, in record order."""
        names = ['F2', 'F3', 'F4']
        if 'F5' in self._arity:
            names.append('F5')
        if 'F6' in self._arity or self._block_words > 0:
            names.append('F6')
        return tuple(names)

    def _require_flow(self, flow: str) -> str:
        if not isinstance(flow, str) or flow not in _KNOWN_FLOWS:
            raise ValueError('unsupported input flow: ' + str(flow))
        if flow not in self.flows():
            raise ValueError('unsupported input flow: ' + flow)
        return flow

    def _flow_arity(self, flow: str) -> int | None:
        """Check one flow's declared arity, returning its fixed word count."""
        if flow == 'F2':
            declared = self._arity.get('F2', 1)
            if type(declared) is not int or declared not in (1, 2):
                raise ValueError('F2 arity must be 1 or 2, declared '
                                 + _shown(declared))
            if declared == 2 and self._padin_address is None:
                raise ValueError('F2 arity 2 requires a declared PADIN register')
            return None
        if flow in _FIXED_ARITY:
            declared = self._arity.get(flow, _FIXED_ARITY[flow])
            if type(declared) is not int or declared != _FIXED_ARITY[flow]:
                raise ValueError(flow + ' arity must be '
                                 + str(_FIXED_ARITY[flow]) + ', declared '
                                 + _shown(declared))
            return _FIXED_ARITY[flow]
        if flow == 'F5':
            declared = self._arity.get('F5')
            if type(declared) is not int or declared < 1:
                raise ValueError('F5 arity must be at least 1, declared '
                                 + _shown(declared))
            return declared
        if flow == 'F6':
            declared = self._arity.get('F6')
            if self._block_words < 1:
                raise ValueError('F6 arity is declared with no DMA block words')
            if type(declared) is not int or declared != self._block_words:
                raise ValueError('F6 arity must be ' + str(self._block_words)
                                 + ', declared ' + _shown(declared))
            return self._block_words
        raise ValueError('unsupported input flow: ' + str(flow))

    # -- candidate sets ----------------------------------------------------
    def _f2_candidates(self) -> tuple[int, ...]:
        if not self._f2_addresses:
            raise ValueError('no readable target address or RAM data-window '
                             'address for F2')
        return self._f2_addresses

    def _f3_candidates(self) -> tuple[int, ...]:
        if not self._ram_addresses:
            raise ValueError('no RAM data-window address for F3')
        return self._ram_addresses

    def _f4_candidates(self) -> tuple[int, ...]:
        if not self._writable_addresses:
            raise ValueError('no writable target register for F4')
        return self._writable_addresses

    # -- generation --------------------------------------------------------
    def fresh(self, flow: str, rng: random.Random) -> tuple[int, ...]:
        """One fresh record drawn uniformly from the declared flow space."""
        flow = self._require_flow(flow)
        self._flow_arity(flow)
        if flow == 'F2':
            address = rng.choice(self._f2_candidates())
            if (address == self._padin_address
                    and rng.random() < 0.5):
                return (address, _random_word(rng, self._pin_mask))
            return (address,)
        if flow == 'F3':
            address = rng.choice(self._f3_candidates())
            return (address, _random_word(rng))
        if flow == 'F4':
            address = rng.choice(self._f4_candidates())
            return (address, _random_word(rng, self._mask_for(address)))
        if flow == 'F5':
            return self._fresh_f5(rng)
        return self._fresh_f6(rng)

    def _fresh_f5(self, rng: random.Random) -> tuple[int, ...]:
        words = self._flow_arity('F5')
        rows = [row for row in self._trigger_rows if len(row) == words]
        if rows and rng.random() < 0.5:
            row = rng.choice(rows)
            values = [value & _MASK32 for value in row]
            for position in range(words):
                if rng.random() < 0.5:
                    values[position] = _random_word(rng)
            return tuple(values)
        return tuple(_random_word(rng) for _ in range(words))

    def _fresh_f6(self, rng: random.Random) -> tuple[int, ...]:
        words = self._flow_arity('F6')
        if not self._f6_example_used:
            self._f6_example_used = True
            values = []
            for position in range(words):
                if position < len(_F6_EXAMPLE):
                    values.append(_F6_EXAMPLE[position])
                else:
                    values.append(_random_word(rng))
            return tuple(values)
        return tuple(_random_word(rng) for _ in range(words))

    # -- mutation ----------------------------------------------------------
    def mutate(self, flow: str, fields: tuple[int, ...],
               rng: random.Random) -> tuple[int, ...]:
        """One to three legal word-level changes to an existing record."""
        flow = self._require_flow(flow)
        self._flow_arity(flow)
        if flow == 'F2':
            addresses = self._f2_candidates()
        elif flow == 'F3':
            addresses = self._f3_candidates()
        elif flow == 'F4':
            addresses = self._f4_candidates()
        else:
            addresses = ()
        if not self.valid(flow, fields):
            raise ValueError('invalid ' + flow + ' input fields')
        values = tuple(fields)
        if flow == 'F2':
            return self._mutate_f2(values, addresses, rng)
        if flow == 'F3':
            return self._mutate_f3(values, addresses, rng)
        if flow == 'F4':
            return self._mutate_f4(values, addresses, rng)
        if flow == 'F5':
            return self._mutate_values(values, self._flow_arity('F5'), rng)
        return self._mutate_values(values, self._flow_arity('F6'), rng)

    def _mutate_f2(self, fields: tuple[int, ...], addresses: tuple[int, ...],
                   rng: random.Random) -> tuple[int, ...]:
        current = list(fields)
        for _ in range(rng.randint(1, 3)):
            kinds = []
            if len(addresses) > 1:
                kinds.append('address')
            if (self._padin_address is not None
                    and current[0] == self._padin_address):
                kinds.append('form')
                if len(current) == 2:
                    kinds.append('stimulus')
            if not kinds:
                break
            kind = rng.choice(kinds)
            if kind == 'address':
                other = _other_address(addresses, current[0], rng)
                if other is None:
                    continue
                if (other == self._padin_address
                        and rng.random() < 0.5):
                    current = [other, _random_word(rng, self._pin_mask)]
                else:
                    current = [other]
            elif kind == 'form':
                if len(current) == 2:
                    current = [current[0]]
                else:
                    current = [current[0], _random_word(rng, self._pin_mask)]
            else:
                current[1] = _different_word(rng, current[1], self._pin_mask)
        if tuple(current) == fields:
            current = list(self._forced_f2(fields, addresses, rng))
        return tuple(current)

    def _forced_f2(self, fields: tuple[int, ...], addresses: tuple[int, ...],
                   rng: random.Random) -> tuple[int, ...]:
        if len(fields) == 2:
            return (fields[0],)
        if (self._padin_address is not None
                and fields[0] == self._padin_address):
            return (fields[0], _random_word(rng, self._pin_mask))
        other = _other_address(addresses, fields[0], rng)
        if other is None:
            return tuple(fields)
        if other == self._padin_address and rng.random() < 0.5:
            return (other, _random_word(rng, self._pin_mask))
        return (other,)

    def _mutate_f3(self, fields: tuple[int, ...], addresses: tuple[int, ...],
                   rng: random.Random) -> tuple[int, ...]:
        current = list(fields)
        for _ in range(rng.randint(1, 3)):
            if len(addresses) > 1 and rng.random() < 0.5:
                other = _other_address(addresses, current[0], rng)
                if other is not None:
                    current[0] = other
                    continue
            current[1] = _different_word(rng, current[1])
        if tuple(current) == fields:
            current[1] = _different_word(rng, current[1])
        return tuple(current)

    def _mutate_f4(self, fields: tuple[int, ...], addresses: tuple[int, ...],
                   rng: random.Random) -> tuple[int, ...]:
        current = list(fields)
        for _ in range(rng.randint(1, 3)):
            if len(addresses) > 1 and rng.random() < 0.5:
                other = _other_address(addresses, current[0], rng)
                if other is not None:
                    current[0] = other
                    current[1] &= self._mask_for(other)
                    continue
            changed = _different_word(rng, current[1],
                                      self._mask_for(current[0]))
            if changed != current[1]:
                current[1] = changed
            elif len(addresses) > 1:
                other = _other_address(addresses, current[0], rng)
                if other is not None:
                    current[0] = other
                    current[1] &= self._mask_for(other)
        if tuple(current) == fields:
            changed = _different_word(rng, current[1],
                                      self._mask_for(current[0]))
            if changed != current[1]:
                current[1] = changed
            else:
                other = _other_address(addresses, current[0], rng)
                if other is not None:
                    current[0] = other
                    current[1] &= self._mask_for(other)
        return tuple(current)

    def _mutate_values(self, fields: tuple[int, ...], words: int,
                       rng: random.Random) -> tuple[int, ...]:
        current = list(fields)
        for _ in range(rng.randint(1, 3)):
            position = rng.randrange(words)
            current[position] = _different_word(rng, current[position])
        if tuple(current) == fields:
            position = rng.randrange(words)
            current[position] = _different_word(rng, current[position])
        return tuple(current)

    # -- validation --------------------------------------------------------
    def valid(self, flow: str, fields: tuple[int, ...]) -> bool:
        """Whether one record is in the declared space."""
        if not isinstance(flow, str) or flow not in _KNOWN_FLOWS:
            return False
        if flow not in self.flows():
            return False
        try:
            self._flow_arity(flow)
        except ValueError:
            return False
        if not isinstance(fields, (tuple, list)):
            return False
        values = tuple(fields)
        if not all(type(value) is int and 0 <= value <= _MASK32
                   for value in values):
            return False
        if flow == 'F2':
            return self._valid_f2(values)
        if flow == 'F3':
            return len(values) == 2 and values[0] in self._ram_addresses
        if flow == 'F4':
            return len(values) == 2 and values[0] in self._writable_addresses
        if flow == 'F5':
            return len(values) == self._flow_arity('F5')
        return len(values) == self._block_words

    def _valid_f2(self, values: tuple[int, ...]) -> bool:
        if len(values) == 1:
            return values[0] in self._f2_addresses
        if len(values) == 2:
            return (self._padin_address is not None
                    and values[0] == self._padin_address
                    and values[1] <= self._pin_mask)
        return False

    # -- description -------------------------------------------------------
    def candidates(self, flow: str) -> dict:
        """Counts of the words one flow can draw, for the saved document."""
        flow = self._require_flow(flow)
        self._flow_arity(flow)
        if flow == 'F2':
            return {'target_read': len(self._readable_addresses),
                    'pin_word': 1 if self._padin_address is not None else 0,
                    'ram_read': len(self._ram_addresses),
                    'two_word': 1 if self._padin_address is not None else 0,
                    'total': len(self._f2_addresses)}
        if flow == 'F3':
            return {'ram_write': len(self._ram_addresses),
                    'total': len(self._ram_addresses)}
        if flow == 'F4':
            return {'target_write': len(self._writable_addresses),
                    'total': len(self._writable_addresses)}
        if flow == 'F5':
            words = self._flow_arity('F5')
            matching = sum(1 for row in self._trigger_rows if len(row) == words)
            return {'words': words,
                    'declared_rows': len(self._trigger_rows),
                    'matching_rows': matching,
                    'total': words}
        words = self._flow_arity('F6')
        return {'words': words,
                'block_words': self._block_words,
                'example_words': min(words, len(_F6_EXAMPLE)),
                'total': words}

    def document(self) -> dict:
        """The declared input space as one JSON-ready object."""
        flows = self.flows()
        arity = {}
        for flow in flows:
            if flow == 'F2':
                declared = self._arity.get('F2', 1)
                arity[flow] = declared if type(declared) is int else 1
            else:
                arity[flow] = self._flow_arity(flow)
        pins = None
        if self._padin_address is not None:
            pins = {'padin_offset': self._padin_offset,
                    'padin_address': self._padin_address,
                    'width': self._pin_width,
                    'stimulus_mask': self._pin_mask,
                    'f2_words': [1, 2]}
        document = {
            'windows': {
                'ram': {'base': self._ram_base, 'size': self._ram_size,
                        'end': self._ram_base + self._ram_size},
                'data': {'base': self._data_base,
                         'words': len(self._ram_addresses),
                         'end': self._data_base + 4 * len(self._ram_addresses)},
                'target': {'base': self._target_base,
                           'size': self._target_size,
                           'end': self._target_base + self._target_size},
            },
            'flows': list(flows),
            'arity': arity,
            'registers': [dict(row) for row in self._register_rows],
            'readable_registers': [dict(row) for row in self._readable_rows],
            'writable_registers': [dict(row) for row in self._writable_rows],
            'ram_addresses': list(self._ram_addresses),
            'trigger_values': [list(row) for row in self._trigger_rows],
            'block_words': self._block_words,
            'pins': pins,
            'candidates': {flow: self.candidates(flow) for flow in flows},
            'limits': _limits(pins is not None),
        }
        if self._multiple_targets:
            document['windows']['targets'] = [
                {'index': target['index'], 'base': target['base'],
                 'size': target['size'],
                 'end': target['base'] + target['size']}
                for target in self._target_rows]
        return document


def _limits(pins: bool) -> list[str]:
    limits = [
        'F2 addresses are the declared readable 32-bit registers and the RAM '
        'data window',
        'F2 may carry an external pin word only at PADIN',
        'F3 addresses are the declared program data window only',
        'F4 addresses are the declared writable 32-bit registers only',
        'F5 records carry one word per declared trigger write',
        'F6 records carry exactly the declared DMA block length',
        'only 32-bit declared registers enter the target address sets',
    ]
    if pins:
        limits.append('PADIN and the PADOUT family are masked to the declared '
                      'pin width')
    return limits


def _int_field(value: object) -> int:
    return value if type(value) is int else 0


def _shown(value: object) -> str:
    return 'absent' if value is None else str(value)


def _pool_word(rng: random.Random) -> int:
    pick = rng.randrange(5)
    if pick < len(_INTERESTING):
        return _INTERESTING[pick]
    return rng.getrandbits(32)


def _random_word(rng: random.Random, mask: int = _MASK32) -> int:
    if mask == 0:
        return 0
    if rng.random() < 0.4:
        value = _pool_word(rng)
    else:
        value = rng.getrandbits(32)
    return value & mask


def _different_word(rng: random.Random, old: int, mask: int = _MASK32) -> int:
    old &= mask
    if mask == 0:
        return 0
    bits = mask.bit_length()
    for _ in range(8):
        strategy = rng.randrange(3)
        if strategy == 0:
            candidate = old ^ (1 << rng.randrange(bits))
        elif strategy == 1:
            delta = rng.choice(_DELTAS) * rng.choice((-1, 1))
            candidate = old + delta
        else:
            candidate = _pool_word(rng)
        candidate &= mask
        if candidate != old:
            return candidate
    return (old + 1) & mask


def _other_address(addresses: tuple[int, ...], current: int,
                   rng: random.Random) -> int | None:
    choices = tuple(address for address in addresses if address != current)
    if not choices:
        return None
    return rng.choice(choices)
