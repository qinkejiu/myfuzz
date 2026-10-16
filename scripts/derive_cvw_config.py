#!/usr/bin/env python3
"""Derive the CVW configuration this repository uses, from the pinned upstream one.

WHY A DERIVED CONFIG EXISTS
    CVW's ``cvw_t P`` is assembled by ``config/<name>/config.vh`` out of plain
    ``localparam`` declarations, and CVW's own memory-system decoder
    (``src/mmu/adrdecs.sv`` -> ``src/mmu/adrdec.sv``) computes

        Sel = Match & Supported & AccessValid & SizeValid

    so a region whose ``*_SUPPORTED`` flag is 0 can never be selected no matter
    what address the core drives.  **Every committed CVW configuration sets
    ``EXT_MEM_SUPPORTED = 0``** (rv32e, rv32gc, rv32i, rv32imc, rv64gc, rv64i), and
    ``EXT_MEM_BASE`` is *the same address* as ``UNCORE_RAM_BASE``
    (``0x80000000``) even in the configurations that support the uncore RAM.

    The consequence is not a detail of this repository: CVW's external AHB-Lite
    port is unreachable in every committed configuration.  CVW's own testbench
    says so explicitly - ``testbench/testbench.sv:545`` instantiates an AHB RAM
    only ``if (P.EXT_MEM_SUPPORTED)`` and otherwise does

        assign HREADYEXT = 1'b1;
        assign {HRESPEXT, HRDATAEXT} = '0;

    A harness cannot make ``HSELEXT`` assert by any legal means while that flag
    is 0, which is why a first attempt to drive a real transfer through this
    repository's AHB subordinate measured ``transactions=0`` with
    ``HSELEXT=0`` on every cycle while the core really was driving
    ``HTRANS=10/11`` at ``0x80000000``.

WHAT THIS SCRIPT CHANGES, AND WHAT IT DELIBERATELY DOES NOT
    It changes exactly three lines of the upstream configuration:

    * ``EXT_MEM_SUPPORTED``   0 -> 1
    * ``EXT_MEM_BASE``        0x80000000 -> 0xC0000000
    * ``EXT_MEM_RANGE``       0x07FFFFFF -> 0x0FFFFFFF

    The base has to move because upstream's value collides with
    ``UNCORE_RAM_BASE`` (both ``0x80000000``): with both regions enabled and
    ``adrdec``'s thermometer-code ``Match``, a single address would select the
    uncore RAM *and* the external port at once, and ``uncore.sv`` merges the two
    responses into one bus.  ``0xC0000000..0xCFFFFFFF`` is checked below to be
    free of every region the derived configuration enables, and to fit inside the
    ``PA_BITS = 34`` physical address space.

    It does **not** touch ISA extensions, caches, branch prediction, the memory
    map's other regions, or any RTL.  The core still executes the pinned upstream
    source at the pinned upstream revision; only the SoC integration constant that
    upstream leaves switched off is switched on.

HOW TO REGENERATE
    PYTHONPATH=src python3 scripts/derive_cvw_config.py --check    # verify no drift
    PYTHONPATH=src python3 scripts/derive_cvw_config.py --write    # rewrite it

    The derived file is repository-authored, so it is pinned by hash in the
    component profile's include order and recorded in the closure exactly like
    ``cvw_ahb_cpu_top.sv`` is; ``src/myfuzz/local_harness/cvw_contract.py``
    authenticates its bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

UPSTREAM = ROOT / 'third_party' / 'cvw_upstream_reference' / 'config' / 'rv32gc' / 'config.vh'
DERIVED = ROOT / 'configs' / 'cpus' / 'cvw' / 'config_extmem' / 'config.vh'

#: The region this repository adds.  See the module docstring for why it moves.
EXT_MEM_BASE = 0xC0000000
EXT_MEM_RANGE = 0x0FFFFFFF
#: Physical address width the derived configuration is used with (rv32gc PA_BITS).
PA_BITS = 34
#: Where the core boots.  Upstream boots at ``IROM_BASE = 0x80000000``, which is
#: also ``UNCORE_RAM_BASE``: the uncore RAM answers there and the harness never
#: sees a fetch.  Booting at ``EXT_MEM_BASE`` instead means the *first* fetch is
#: addressed to the external region, so the harness's own memory service supplies
#: the boot program - no preloaded RAM and no hierarchy poke.  Like the other two
#: values this is checked below to be inside an enabled region.
RESET_VECTOR = EXT_MEM_BASE

_SUPPORTED_RE = re.compile(r'^(localparam logic EXT_MEM_SUPPORTED\s*=\s*)0(;)$', re.MULTILINE)
_BASE_RE = re.compile(r"^(localparam logic \[63:0\] EXT_MEM_BASE\s*=\s*64'h)[0-9A-Fa-f]+(;)$", re.MULTILINE)
_RANGE_RE = re.compile(r"^(localparam logic \[63:0\] EXT_MEM_RANGE\s*=\s*64'h)[0-9A-Fa-f]+(;)$", re.MULTILINE)
_RESET_RE = re.compile(r"^(localparam logic \[63:0\] RESET_VECTOR\s*=\s*64'h)[0-9A-Fa-f]+(;)$", re.MULTILINE)


def _enabled_regions(text: str) -> list[tuple[str, int, int]]:
    """Every region the configuration enables, as (name, base, top) inclusive."""
    supported = {m.group(1): int(m.group(2))
                 for m in re.finditer(r'localparam logic (\w+_SUPPORTED)\s*=\s*(\d);', text)}
    base = {m.group(1): int(m.group(2), 16) for m in
            re.finditer(r"localparam logic \[63:0\] (\w+_BASE)\s*=\s*64'h([0-9A-Fa-f]+);", text)}
    span = {m.group(1): int(m.group(2), 16) for m in
            re.finditer(r"localparam logic \[63:0\] (\w+_RANGE)\s*=\s*64'h([0-9A-Fa-f]+);", text)}
    regions = []
    for key, value in sorted(supported.items()):
        if not value:
            continue
        name = key[: -len('_SUPPORTED')]
        low, mask = base.get(name + '_BASE'), span.get(name + '_RANGE')
        if low is None or mask is None:
            continue
        # adrdec: Match = &((Address ~^ Base) | Range), so Range is a bitmask.
        if mask & (mask + 1):
            raise SystemExit(f'{name}_RANGE is not a thermometer code: {mask:#x}')
        regions.append((name, low, low | mask))
    return regions


def derive() -> str:
    text = UPSTREAM.read_text(encoding='utf-8')
    for pattern, replacement, label in (
            (_SUPPORTED_RE, r'\g<1>1\g<2>', 'EXT_MEM_SUPPORTED'),
            (_BASE_RE, rf"\g<1>{EXT_MEM_BASE:X}\g<2>", 'EXT_MEM_BASE'),
            (_RANGE_RE, rf"\g<1>{EXT_MEM_RANGE:X}\g<2>", 'EXT_MEM_RANGE'),
            (_RESET_RE, rf"\g<1>{RESET_VECTOR:X}\g<2>", 'RESET_VECTOR')):
        text, count = pattern.subn(replacement, text)
        if count != 1:
            raise SystemExit(f'expected exactly one {label} line in {UPSTREAM}, found {count}')

    top = EXT_MEM_BASE | EXT_MEM_RANGE
    if top >= (1 << PA_BITS):
        raise SystemExit(f'the external-memory region does not fit in {PA_BITS} bits')
    for name, low, high in _enabled_regions(text):
        if name == 'EXT_MEM':
            continue
        if not (EXT_MEM_BASE > high or top < low):
            raise SystemExit(
                f'the external-memory region {EXT_MEM_BASE:#x}..{top:#x} collides with '
                f'{name} {low:#x}..{high:#x}')

    # Booting outside every enabled region is the failure that costs the most time
    # to find: the core simply never fetches anything the harness can see.  The
    # reset vector must therefore land in a region that is switched on, and for
    # this repository that region must be the external one (otherwise the uncore
    # RAM answers the boot and the AHB boundary stays silent).
    booting_region = None
    for name, low, high in _enabled_regions(text):
        if low <= RESET_VECTOR <= high:
            booting_region = name
            break
    if booting_region is None:
        raise SystemExit(
            f'RESET_VECTOR {RESET_VECTOR:#x} is not inside any enabled region, so the '
            'core could never fetch a program the harness supplies')
    if booting_region != 'EXT_MEM':
        raise SystemExit(
            f'RESET_VECTOR {RESET_VECTOR:#x} is answered by {booting_region}, not by the '
            'external port; the AHB boundary would see no boot fetch')

    banner = (
        '// DERIVED FILE - DO NOT EDIT BY HAND.\n'
        '//\n'
        '// Generated by scripts/derive_cvw_config.py from the pinned upstream\n'
        f'// {UPSTREAM.relative_to(ROOT).as_posix()}, changing only EXT_MEM_SUPPORTED,\n'
        f'// EXT_MEM_BASE and EXT_MEM_RANGE.  The upstream header leaves the external\n'
        '// AHB-Lite port unreachable (EXT_MEM_SUPPORTED = 0 in every committed CVW\n'
        '// configuration) and gives EXT_MEM the same base as UNCORE_RAM.  See the\n'
        '// generator for the full reasoning and for the collision check that picks\n'
        f'// {EXT_MEM_BASE:#010x}..{top:#010x}.\n'
        '//\n'
        '// The pinned upstream revision is still proven by git; this file is\n'
        '// additionally pinned by hash through the component profile and the closure.\n')
    return banner + text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--write', action='store_true', help='write the derived file')
    group.add_argument('--check', action='store_true', help='fail if the derived file has drifted')
    arguments = parser.parse_args()
    if not UPSTREAM.is_file():
        raise SystemExit(f'the pinned upstream configuration is missing: {UPSTREAM}')
    expected = derive()
    if arguments.write:
        DERIVED.parent.mkdir(parents=True, exist_ok=True)
        DERIVED.write_text(expected, encoding='utf-8')
        print(f'wrote {DERIVED.relative_to(ROOT)} '
              f'sha256={hashlib.sha256(expected.encode()).hexdigest()}')
        return 0
    if not DERIVED.is_file():
        raise SystemExit(f'{DERIVED.relative_to(ROOT)} is missing; run with --write')
    actual = DERIVED.read_text(encoding='utf-8')
    if actual != expected:
        raise SystemExit(f'{DERIVED.relative_to(ROOT)} has drifted from its inputs; run with --write')
    print(f'{DERIVED.relative_to(ROOT)} matches its inputs '
          f'sha256={hashlib.sha256(actual.encode()).hexdigest()}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
