"""The AHB-Lite CPU-side contract, derived from CORE-V Wally's real boundary.

Before this contract existed the repository recorded "no AHB-Lite CPU-side
contract, because there is no real AHB-Lite declaration to align with".  That
changed when CVW's SystemVerilog source was obtained: its top-level
``wallypipelinedsoc`` module declares the complete external bus, and
``src/ebu/ebu.sv`` plus ``src/uncore/uncore.sv`` give the verbatim port names and
directions.

The contract is only worth having if it matches that declaration rather than a
textbook idea of AHB-Lite, so these tests drive the real selector
(``select_template_contract``) over the real declaration and pin the two places
where a guessed contract would be wrong:

* read data arrives at the CPU boundary as ``HRDATAEXT``, not ``HRDATA`` (the
  EBU deliberately has no HRDATA port - its comment reads "HRDATA is sent to all
  controllers at the core level");
* ``HSELEXT`` is a CVW chip-select extension, not an AHB-Lite signal.

Nothing here claims the boundary has been elaborated or run: the contract
carries ``elaboration_status='not-elaborated'`` and these tests assert that,
so a later reader cannot mistake a shape match for a working harness.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
DECLARATION = ROOT / 'configs' / 'cpus' / 'cvw' / 'interface_description.json'
CVW_TOP = ROOT / 'third_party' / 'cvw_upstream_reference' / 'src' / 'wally' / 'wallypipelinedsoc.sv'
CVW_EBU = ROOT / 'third_party' / 'cvw_upstream_reference' / 'src' / 'ebu' / 'ebu.sv'

sys.path.insert(0, str(ROOT / 'src'))

from myfuzz.composition.component_profile import ResolvedEndpoint, ResolvedField  # noqa: E402
from myfuzz.local_harness.template_contracts import (  # noqa: E402
    list_template_contracts, select_template_contract)

# The CVW boundary is parameterised (cvw_t fields AHBW/PA_BITS/XLEN) and this
# repository has no CVW profile carrying concrete widths, so the test reads them
# from CVW's own configuration instead of assuming them.  That matters: an
# earlier version of this test assumed a 32-bit address and so never exercised
# the contract's parameterised range, while the real rv32imc value is 34
# (config/shared/config-shared.vh: PA_BITS = XLEN==32 ? 34 : 56).
CVW_CONFIG = ('third_party', 'cvw_upstream_reference', 'config')


def _localparams(relative: str) -> dict[str, str]:
    """Read ``localparam NAME = EXPR;`` from a CVW configuration header."""
    text = (ROOT.joinpath(*CVW_CONFIG) / relative).read_text(encoding='utf-8')
    found = {}
    for line in text.splitlines():
        line = line.split('//', 1)[0].strip()
        if not line.startswith('localparam '):
            continue
        body = line[len('localparam '):].rstrip(';')
        for part in body.split(','):
            if '=' not in part:
                continue
            name, _, expression = part.partition('=')
            name = name.strip().split()[-1]
            expression = re.sub(r"32'd", '', expression.strip())
            found[name] = expression
    return found


def cvw_widths(config: str = 'rv32imc') -> dict[str, int]:
    """Resolve XLEN/AHBW/PA_BITS the way CVW's own headers do."""
    local = _localparams(f'{config}/config.vh')
    shared = _localparams('shared/config-shared.vh')
    xlen = int(local['XLEN'])
    ahbw = int(local['AHBW'].strip('()')) if local['AHBW'].strip('()').isdigit() else xlen
    pa_bits = int(shared['PA_BITS'].split('?')[1].split(':')[0].strip()) \
        if '?' in shared['PA_BITS'] and f'XLEN=={xlen}' in shared['PA_BITS'] \
        else int(shared['PA_BITS'].strip('()'))
    return {'XLEN': xlen, 'AHBW': ahbw, 'PA_BITS': pa_bits}


_WIDTHS_CACHE: dict[str, int] = {}


def widths() -> dict[str, int]:
    if not _WIDTHS_CACHE:
        real = cvw_widths()
        _WIDTHS_CACHE.update({
            'htrans': 2, 'haddr': real['PA_BITS'], 'hwrite': 1,
            'hwdata': real['AHBW'], 'hwstrb': real['AHBW'] // 8,
            'hsize': 3, 'hburst': 3, 'hprot': 4, 'hmastlock': 1, 'hsel': 1,
            'hrdata': real['AHBW'], 'hresp': 1, 'hready': 1,
        })
    return _WIDTHS_CACHE


_HOST_ROLES = frozenset({'htrans', 'haddr', 'hwrite', 'hwdata', 'hwstrb',
                         'hsize', 'hburst', 'hprot', 'hmastlock', 'hsel'})


def declaration() -> dict:
    return json.loads(DECLARATION.read_text(encoding='utf-8'))


def endpoint_document() -> dict:
    endpoints = declaration()['endpoints']
    assert len(endpoints) == 1, 'CVW declares exactly one external bus endpoint'
    return endpoints[0]


def resolved_endpoint() -> ResolvedEndpoint:
    source = endpoint_document()
    fields = []
    for field in source['fields']:
        role = field['role']
        width = widths()[role]
        fields.append(ResolvedField(
            source['endpoint_id'], role, field['aliases'][0], (),
            'output' if role in _HOST_ROLES else 'input',
            width, 0, width - 1, False, 'wallypipelinedsoc.sv', 1, width))
    return ResolvedEndpoint(source['endpoint_id'], source['function'],
                            tuple(source['protocol']), tuple(fields))


def contract():
    return next(row for row in list_template_contracts()
                if row.template_id == 'cpu.ahb-lite')


def _match_for_test(endpoint):
    """Run the inner matcher so the concrete refusal reason is pinned too."""
    from myfuzz.local_harness.template_contracts import _match
    return _match(contract(), endpoint, {}, False)


def test_the_widths_come_from_cvw_config_and_haddr_is_34_bits():
    """The widths are read, not assumed - and the real address is 34 bits.

    This is the check that would have caught the earlier assumption: AHBW equals
    XLEN (32) but PA_BITS is 34 for a 32-bit CVW configuration, so the address
    port is wider than the data port and a contract that pinned the address to
    the data width would reject the real boundary.
    """
    if not ROOT.joinpath(*CVW_CONFIG, 'rv32imc', 'config.vh').is_file():
        pytest.skip('the CVW reference source is not present in this checkout')
    real = cvw_widths('rv32imc')
    assert real == {'XLEN': 32, 'AHBW': 32, 'PA_BITS': 34}
    assert widths()['haddr'] == 34
    assert widths()['hwdata'] == 32
    # The contract must accept that asymmetry.
    limits = dict(contract().limits)
    assert limits['address_width_min'] <= 34 <= limits['address_width_max']
    assert 32 in limits['supported_data_widths']


def _lint_cvw(root, verilator, mdir, *, drop=None, extra_command=()):
    """Run CVW's own lint invocation; ``drop`` removes one source file."""
    sources = sorted(str(path) for path in (root / 'src').rglob('*.sv')
                     if path.name != drop)
    return subprocess.run(
        [verilator, '--lint-only', '--quiet', '--top-module', 'wallywrapper',
         '--Mdir', mdir,
         f'-I{root / "config" / "shared"}',
         f'-I{root / "config" / "rv32imc"}',
         f'-I{root / "config" / "deriv" / "rv32imc"}',
         f'-I{root / "src"}',
         *extra_command,
         str(root / 'src' / 'cvw.sv'), *sources,
         str(root / 'testbench' / 'wallywrapper.sv')],
        cwd=root, capture_output=True, text=True, timeout=1800)


def test_the_cvw_boundary_really_elaborates():
    """Elaborate CVW's own lint wrapper - the entry the repository ships.

    CVW is SystemVerilog and needs no JVM, so unlike BOOM this is directly
    checkable here.  The command mirrors `bin/lint-wally` (``src/cvw.sv`` first,
    then the wrapper); ``-Isrc``, the full source list and ``--Mdir`` are needed
    because the wrapper's dependencies live in subdirectories and the check must
    not depend on a previous run's cache.

    A passing exit code alone is weak - an invocation that elaborated nothing
    would also pass - so the sibling test below removes one source file and
    requires the same invocation to fail.  Together they show the check really
    elaborates the boundary the contract was derived from.
    """
    verilator = shutil.which('verilator')
    if verilator is None:
        pytest.skip('verilator is not installed')
    root = ROOT.joinpath(*CVW_CONFIG).parents[0]
    if not (root / 'src' / 'cvw.sv').is_file():
        pytest.skip('the CVW reference source is not present in this checkout')
    with tempfile.TemporaryDirectory(prefix='cvw-lint-') as mdir:
        result = _lint_cvw(root, verilator, mdir)
    assert result.returncode == 0, (result.stdout + result.stderr)[-3000:]


def test_the_elaboration_check_would_notice_a_missing_source():
    """The guard for the test above: drop a needed module and it must fail."""
    verilator = shutil.which('verilator')
    if verilator is None:
        pytest.skip('verilator is not installed')
    root = ROOT.joinpath(*CVW_CONFIG).parents[0]
    if not (root / 'src' / 'ebu' / 'ebu.sv').is_file():
        pytest.skip('the CVW reference source is not present in this checkout')
    with tempfile.TemporaryDirectory(prefix='cvw-lint-') as mdir:
        result = _lint_cvw(root, verilator, mdir, drop='ebu.sv')
    assert result.returncode != 0
    assert 'ebu' in (result.stdout + result.stderr)


def test_the_declaration_names_the_real_cvw_ports_verbatim():
    """Every declared alias must occur in the real CVW source, none invented."""
    if not CVW_TOP.is_file():
        pytest.skip('the CVW reference source is not present in this checkout')
    top = CVW_TOP.read_text(encoding='utf-8')
    for field in endpoint_document()['fields']:
        alias = field['aliases'][0]
        assert alias in top, f'{alias} is not a CVW top-level port name'


def test_read_data_is_hrdataext_and_ebu_has_no_hrdata():
    """The two facts a textbook AHB-Lite contract would get wrong."""
    if not (CVW_TOP.is_file() and CVW_EBU.is_file()):
        pytest.skip('the CVW reference source is not present in this checkout')
    aliases = {field['role']: field['aliases'][0]
               for field in endpoint_document()['fields']}
    assert aliases['hrdata'] == 'HRDATAEXT'
    ebu = CVW_EBU.read_text(encoding='utf-8')
    # The EBU's port list deliberately omits HRDATA: it is routed at core level.
    assert 'HRDATA is sent to all controllers at the core level' in ebu
    port_list = ebu.split(');', 1)[0]
    assert 'HRDATA,' not in port_list and 'HRDATA ' not in port_list


def test_the_cvw_endpoint_selects_the_ahb_lite_contract():
    """The real selector, over the real declared role vocabulary."""
    selected = select_template_contract(resolved_endpoint(), {})
    assert selected.contract.template_id == 'cpu.ahb-lite'
    assert selected.contract.variant_id == 'cvw-external-bus'
    assert selected.contract.protocol == ('ahb-lite', '1')


def test_the_contract_claims_a_parameterised_boundary_and_no_elaboration():
    """The limits must say what is not claimed, including that it was not built."""
    limits = dict(contract().limits)
    assert limits['elaboration_status'] == 'not-elaborated'
    assert limits['width_parameterisation'] == 'cvw_t_fields_ahbw_pa_bits_xlen'
    assert limits['read_data_name_policy'] == 'cpu_boundary_signal_is_hrdataext'
    assert limits['select_policy'] == 'hselext_is_a_cvw_extension_not_ahb_lite'
    # Byte enables are real pins (HWSTRB), so these are shape facts, not wishes.
    assert limits['write'] is True and limits['byte_enable'] is True


def test_the_contract_is_not_the_tilelink_or_tl_ul_entry():
    """Three different entries must not be confused for one another."""
    rows = list_template_contracts()
    ahb = [row for row in rows if row.template_id == 'cpu.ahb-lite']
    tl_cpu = [row for row in rows if row.protocol == ('tilelink', '1')]
    tl_ul = [row for row in rows if row.template_id == 'target.tl-ul']
    assert len(ahb) == 1 and len(tl_cpu) == 2 and len(tl_ul) == 1
    assert ahb[0].side == 'cpu' and tl_ul[0].side == 'target'
    assert ahb[0].protocol != tl_cpu[0].protocol


def test_a_dropped_role_is_refused_rather_than_silently_tolerated():
    """A contract that does not cover the declaration must not match it.

    This is the guard that makes the positive test meaningful: if the selector
    accepted a subset, the CVW endpoint would match a contract that does not
    actually describe it.
    """
    source = endpoint_document()
    fields = [field for field in resolved_endpoint().fields if field.role != 'hready']
    assert len(fields) == len(source['fields']) - 1
    incomplete = ResolvedEndpoint(source['endpoint_id'], source['function'],
                                  tuple(source['protocol']), tuple(fields))
    with pytest.raises(ValueError) as raised:
        select_template_contract(incomplete, {})
    # The public selector reports the refusal, and the inner reason names the roles.
    assert 'template-selection-refused' in str(raised.value)
    with pytest.raises(ValueError) as inner:
        _match_for_test(incomplete)
    assert 'template-missing-or-unknown-roles' in str(inner.value)


def test_a_textbook_hrdata_role_does_not_match():
    """Renaming HRDATAEXT to the textbook HRDATA must break the match."""
    source = endpoint_document()
    fields = []
    for field in resolved_endpoint().fields:
        if field.role == 'hrdata':
            # Renaming the *role* is what a textbook contract would do; renaming
            # only the physical port is harmless because role names are matched,
            # not port names.
            width = widths()['hrdata']
            fields.append(ResolvedField(
                source['endpoint_id'], 'rdata', 'HRDATA', (),
                'input', width, 0, width - 1, False, 'textbook.sv', 1, width))
        else:
            fields.append(field)
    textbook = ResolvedEndpoint(source['endpoint_id'], source['function'],
                                tuple(source['protocol']), tuple(fields))
    with pytest.raises(ValueError) as raised:
        select_template_contract(textbook, {})
    assert 'template-selection-refused' in str(raised.value)
    with pytest.raises(ValueError) as inner:
        _match_for_test(textbook)
    assert 'template-missing-or-unknown-roles' in str(inner.value)
