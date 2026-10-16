"""The derived CVW configuration: why it exists, and the guards that keep it honest.

CVW's memory-system decoder is ``src/mmu/adrdec.sv``::

    Sel = Match & Supported & AccessValid & SizeValid

A region whose ``*_SUPPORTED`` flag is 0 can therefore never be selected, no
matter what address the core drives.  Every committed CVW configuration
(rv32e/rv32gc/rv32i/rv32imc/rv64gc/rv64i) sets ``EXT_MEM_SUPPORTED = 0``, which
makes the whole external AHB-Lite port unreachable - CVW's own testbench says so
at ``testbench/testbench.sv:545``, where an AHB RAM is instantiated only
``if (P.EXT_MEM_SUPPORTED)`` and otherwise ``HREADYEXT`` is tied to 1.

These tests cover the three things that can silently rot:

* the derivation still reproduces byte-for-byte from its pinned upstream input;
* the region it picks is still free of every region the configuration enables;
* the contract still refuses a configuration that switched the feature back off,
  even when the hash constant has been "helpfully" updated to match.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts' / 'derive_cvw_config.py'
DERIVED = ROOT / 'configs' / 'cpus' / 'cvw' / 'config_extmem' / 'config.vh'
PROFILE = ROOT / 'configs' / 'cpus' / 'cvw' / 'component_profile.json'
UPSTREAM = (ROOT / 'third_party' / 'cvw_upstream_reference' / 'config' / 'rv32gc'
            / 'config.vh')

pytestmark = pytest.mark.skipif(
    not UPSTREAM.is_file(), reason='the pinned upstream CVW checkout is not present')


def test_the_derived_config_reproduces_from_its_pinned_input():
    """Byte-for-byte, so the pinned hash and the derivation cannot disagree."""
    result = subprocess.run([sys.executable, str(SCRIPT), '--check'],
                            cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'matches its inputs' in result.stdout


#: Exactly which parameters the derivation is allowed to touch.  Kept as an
#: explicit set rather than a count so that adding one is a deliberate edit here.
DERIVED_PARAMETERS = {'EXT_MEM_SUPPORTED', 'EXT_MEM_BASE', 'EXT_MEM_RANGE', 'RESET_VECTOR'}


def test_the_derivation_changes_only_the_named_parameters():
    """A derived file that "also" changed something else would be unreviewable."""
    banner_end = 0
    derived_lines = DERIVED.read_text(encoding='utf-8').splitlines()
    for index, line in enumerate(derived_lines):
        if line.startswith('///'):
            banner_end = index + 1
    # Everything after the banner must equal upstream except the named parameters.
    derived_body = [line for line in derived_lines[banner_end:]
                    if not line.startswith('//')]
    upstream_body = [line for line in UPSTREAM.read_text(encoding='utf-8').splitlines()
                     if not line.startswith('//')]
    differing = [(a, b) for a, b in zip(derived_body, upstream_body) if a != b]
    assert len(derived_body) == len(upstream_body), 'the derivation changed the line count'
    changed = set()
    for derived_line, upstream_line in differing:
        named = [name for name in DERIVED_PARAMETERS if name in derived_line]
        assert named, f'the derivation changed an unnamed line: {derived_line}'
        changed.update(named)
    assert changed == DERIVED_PARAMETERS, (changed, DERIVED_PARAMETERS)


def test_the_derived_config_enables_external_memory_at_a_free_range():
    derived = DERIVED.read_text(encoding='utf-8')
    assert 'localparam logic EXT_MEM_SUPPORTED = 1;' in derived
    # The base has to move: upstream gives EXT_MEM and UNCORE_RAM the same base,
    # so enabling EXT_MEM as-is would select two regions for one address.
    assert "localparam logic [63:0] EXT_MEM_BASE     = 64'hC0000000;" in derived
    upstream = UPSTREAM.read_text(encoding='utf-8')
    assert (f"localparam logic [63:0] EXT_MEM_BASE     = 64'h80000000;" in upstream
            and f"localparam logic [63:0] UNCORE_RAM_BASE  = 64'h80000000;" in upstream)
    assert 'DERIVED FILE - DO NOT EDIT BY HAND' in derived

    # Re-derive the collision check independently of the generator's own code path.
    def regions(text: str) -> list[tuple[str, int, int]]:
        import re as _re

        supported = {m.group(1): int(m.group(2)) for m in _re.finditer(
            r'localparam logic (\w+_SUPPORTED)\s*=\s*(\d);', text)}
        base = {m.group(1): int(m.group(2), 16) for m in _re.finditer(
            r"localparam logic \[63:0\] (\w+_BASE)\s*=\s*64'h([0-9A-Fa-f]+);", text)}
        span = {m.group(1): int(m.group(2), 16) for m in _re.finditer(
            r"localparam logic \[63:0\] (\w+_RANGE)\s*=\s*64'h([0-9A-Fa-f]+);", text)}
        out = []
        for key, value in supported.items():
            if not value:
                continue
            name = key[: -len('_SUPPORTED')]
            low, mask = base.get(name + '_BASE'), span.get(name + '_RANGE')
            if low is not None and mask is not None:
                out.append((name, low, low | mask))
        return out

    external = [item for item in regions(derived) if item[0] == 'EXT_MEM']
    assert len(external) == 1
    _, low, high = external[0]
    for name, other_low, other_high in regions(derived):
        if name == 'EXT_MEM':
            continue
        assert low > other_high or high < other_low, (name, hex(low), hex(high))
    assert high < (1 << 34), 'PA_BITS is 34 for the configuration this is used with'

    # The reset vector must be inside that region, or the core boots from memory it
    # owns and no fetch ever reaches the AHB port.
    reset = re.search(r"localparam logic \[63:0\] RESET_VECTOR\s*=\s*64'h([0-9A-Fa-f]+);",
                      derived)
    assert reset is not None, 'the derived config declares no RESET_VECTOR'
    reset_vector = int(reset.group(1), 16)
    assert low <= reset_vector <= high, (hex(reset_vector), hex(low), hex(high))
    upstream_reset = re.search(
        r"localparam logic \[63:0\] RESET_VECTOR\s*=\s*64'h([0-9A-Fa-f]+);", upstream)
    assert int(upstream_reset.group(1), 16) == 0x80000000, 'upstream reset vector moved'


def test_the_contract_refuses_a_re_disabled_config_even_with_a_matching_hash(monkeypatch):
    """The hash alone is not the guard: pinning a bad body must still be refused.

    This is the failure mode a hash pin invites - "the config changed, so update
    the constant" - and it is exactly how the external-memory port would go back
    to being dead code without anyone noticing.
    """
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.local_harness import cvw_contract

    good = DERIVED.read_text(encoding='utf-8')
    bad = good.replace('localparam logic EXT_MEM_SUPPORTED = 1;',
                       'localparam logic EXT_MEM_SUPPORTED = 0;')
    assert bad != good
    monkeypatch.setattr(cvw_contract, '_CONFIG_SHA256',
                        hashlib.sha256(bad.encode()).hexdigest())
    DERIVED.write_text(bad, encoding='utf-8')
    try:
        profile = load_component_profile(json.loads(PROFILE.read_text(encoding='utf-8')))
        with pytest.raises(ValueError, match='cvw-config-external-memory-disabled'):
            cvw_contract.verify_cvw_source_contract(profile, base_dir=ROOT)
    finally:
        DERIVED.write_text(good, encoding='utf-8')
    assert DERIVED.read_text(encoding='utf-8') == good
