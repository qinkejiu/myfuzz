"""Task 6b: the closed minimal-bootstrap selector in the frozen integration layer.

The audit (``runs/stage2-e2-native-reset-task6-bootstrap-audit-20261012/
bootstrap-audit.md`` section 5.2) requires ``_verify_bootstrap_plan`` to branch on
``MINIMAL_BOOTSTRAP_SELECTOR`` and rebuild/compare the minimal declaration, and
``make_ibex_pulp_online_runtime`` to stop hard-coding the shipped bootstrap
(``ibex_pulp_online.py:674``).  This module is that channel's closed software TDD.

Scope: software only.  No RTL, no Verilator, no native build, no native
execution, no ``runs/`` script.  Every value below is recomputed from code or
from the produced fixture bytes; a saved document is only ever *compared*.

Chosen home: this is a new file rather than an addition to
``tests/integration/test_register_reset_default_replay.py``.  That module is the
Task-5 reset-default *session channel* witness (its fixtures install the Task1/2/3
producers into a real session); the bootstrap selector is a different closed
channel -- assembly field, source closure and plan comparison -- whose whole
point is that it is verifiable without any session at all.  Keeping them apart
keeps each file's docstring scope true.
"""
from copy import deepcopy
import hashlib
import json

import pytest

from myfuzz.integration import ibex_pulp_online as online
from myfuzz.integration import ibex_pulp_register_replay as api
from myfuzz.scenario import ibex_pulp_dual_source as fixture
from myfuzz.scenario.genome import GenomeCodec
from tests.integration.test_register_reset_default_replay import (
    BASE_CLOSURE, DEFAULT_KEYS)

MINIMAL = fixture.MINIMAL_BOOTSTRAP_SELECTOR
RTL_SOURCE = 'third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv'

#: Pre-Task-6 witness of the shipped bytes (``test_cv32e40p_pulp_online_factory.py:28-36``).
SHIPPED_BOOT_IMAGE_SHA256 = '51e344aca5262f86996969b317b31373232521311fb9eb3e8ff5844d31b23b2c'
#: The declared minimal fixture of Task 6 (unchanged by this task).
MINIMAL_BOOT_IMAGE_SHA256 = 'bc5f9b5234b864b4bd914bb183fb3e6eb4ec7b8c1c07aabfdd39194697a62ac1'
REMOVED_ADDRESSES = (0x40000004, 0x40000018, 0x40001000, 0x4000100C)
RETAINED_ADDRESSES = (0x4000001C, 0x40001004)


def plan_for(bootstrap):
    """The two saved plan fields ``_verify_bootstrap_plan`` compares."""
    return dict(template=json.loads(GenomeCodec.encode(bootstrap.template)),
                instruction_slots=[['cpu', bootstrap.instruction_start,
                                    bootstrap.instruction_count]])


def shipped_plan():
    return plan_for(fixture.make_ibex_pulp_dual_source_stream_bootstrap())


def minimal_plan():
    return plan_for(fixture.make_ibex_pulp_dual_source_minimal_bootstrap())


def boot_image_sha256(bootstrap):
    image = next(image for image in bootstrap.template.initial_images
                 if image.image_id == fixture.STREAM_BOOTSTRAP_IMAGE_ID)
    return hashlib.sha256(image.data).hexdigest()


def closure_paths(assembly):
    return [row['path'] for row in api._sources(assembly)]


# ---------------------------------------------------------------------------
# Default off: the shipped path keeps its frozen shape, closure and comparison
# ---------------------------------------------------------------------------

def test_default_off_assembly_closure_and_shipped_comparison_are_unchanged():
    """Control: passes before any selector branch exists, by design."""
    default = api.make_register_assembly()
    assert sorted(default) == sorted(DEFAULT_KEYS)
    assert 'bootstrap_selector' not in default
    assert 'bootstrap_declaration' not in default
    assert closure_paths(default) == list(BASE_CLOSURE)
    assert len(closure_paths(default)) == len(BASE_CLOSURE)
    assert RTL_SOURCE not in closure_paths(default)
    plan = shipped_plan()
    api._verify_bootstrap_plan(plan)
    assert boot_image_sha256(fixture.make_ibex_pulp_dual_source_stream_bootstrap()) \
        == SHIPPED_BOOT_IMAGE_SHA256
    for key, value in (('instruction_slots', [['cpu', 0x11000, 1]]), ('template', {})):
        with pytest.raises(ValueError):
            api._verify_bootstrap_plan(dict(plan, **{key: value}))


# ---------------------------------------------------------------------------
# The one closed selector, its code-recomputed declaration and its closure
# ---------------------------------------------------------------------------

def test_minimal_selector_declares_the_closed_fixture_and_its_closure():
    assembly = api.make_register_assembly(bootstrap_selector=MINIMAL)
    assert api._json(api.make_register_assembly(bootstrap_selector=None)) \
        == api._json(api.make_register_assembly())
    assert assembly['bootstrap_selector'] == MINIMAL
    declaration = assembly['bootstrap_declaration']
    assert declaration == fixture.minimal_bootstrap_declaration()
    assert fixture.validate_minimal_bootstrap_declaration(declaration) == declaration
    assert declaration['selector'] == MINIMAL
    assert declaration['instruction_slots'] == [['cpu', 0x11000, 31616]]
    assert [row['address'] for row in declaration['removed_gpio_writes']] \
        == list(REMOVED_ADDRESSES)
    assert sorted(row['address'] for row in declaration['gpio_writes']) \
        == list(RETAINED_ADDRESSES)
    body = next(row for row in declaration['images']
                if row['image_id'] == fixture.STREAM_BOOTSTRAP_IMAGE_ID)
    assert body['sha256'] == MINIMAL_BOOT_IMAGE_SHA256
    assert body['sha256'] != SHIPPED_BOOT_IMAGE_SHA256
    assert closure_paths(assembly) == sorted(
        set(BASE_CLOSURE) | {row['path'] for row in declaration['source_files']})
    assert RTL_SOURCE in closure_paths(assembly)
    for row in api._sources(assembly):
        assert row['sha256'] == hashlib.sha256((api._ROOT / row['path']).read_bytes()).hexdigest()
    # Requesting the selector moved nothing for a caller that did not ask.
    assert closure_paths(api.make_register_assembly()) == list(BASE_CLOSURE)


def test_minimal_selector_rebuilds_and_compares_the_saved_plan():
    assembly = api.make_register_assembly(bootstrap_selector=MINIMAL)
    plan = minimal_plan()
    api._verify_bootstrap_plan(plan, assembly)
    assert api._json(plan['template']) != api._json(shipped_plan()['template'])
    assert api._json(assembly['bootstrap_declaration']) == api._json(
        fixture.minimal_bootstrap_declaration(
            fixture.make_ibex_pulp_dual_source_minimal_bootstrap()))
    # The plan comparison alone is not enough: a minimal plan and the shipped
    # assembly are an inconsistent pair.
    with pytest.raises(ValueError):
        api._verify_bootstrap_plan(plan, api.make_register_assembly())


def test_saved_plan_whose_selector_does_not_match_the_rebuild_is_refused():
    minimal_assembly = api.make_register_assembly(bootstrap_selector=MINIMAL)
    shipped_assembly = api.make_register_assembly()
    with pytest.raises(ValueError):
        api._verify_bootstrap_plan(shipped_plan(), minimal_assembly)
    with pytest.raises(ValueError):
        api._verify_bootstrap_plan(minimal_plan(), shipped_assembly)
    # No assembly at all is the shipped selection, so a minimal saved plan is
    # refused by the pre-existing call shape too.
    with pytest.raises(ValueError):
        api._verify_bootstrap_plan(minimal_plan())
    # The honest pairs still pass.
    api._verify_bootstrap_plan(shipped_plan(), shipped_assembly)
    api._verify_bootstrap_plan(minimal_plan(), minimal_assembly)


# ---------------------------------------------------------------------------
# Boundary negatives: unknown selector, tampered declaration, reintroduced write
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('value', [
    'ibex_pulp_dual_source.minimal_bootstrap',      # no version
    'ibex_pulp_dual_source.minimal_bootstrap.v0',   # wrong version
    'IBEX_PULP_DUAL_SOURCE.MINIMAL_BOOTSTRAP.V1',   # wrong case
    '', 'shipped', True, 1, {}, ['ibex_pulp_dual_source.minimal_bootstrap.v1'],
])
def test_unknown_selector_value_is_refused_by_both_entry_points(value):
    with pytest.raises(ValueError):
        api.make_register_assembly(bootstrap_selector=value)
    forged = dict(api.make_register_assembly(),
                  bootstrap_selector=value,
                  bootstrap_declaration=fixture.minimal_bootstrap_declaration())
    with pytest.raises(ValueError, match='unsupported bootstrap_selector'):
        api.validate_register_assembly(forged)


@pytest.mark.parametrize('mutation', [
    'image_sha256', 'removed_gpio_writes', 'selector', 'instruction_slots',
    'template_sha256', 'source_files', 'extra_key',
])
def test_tampered_minimal_declaration_is_refused(mutation):
    assembly = api.make_register_assembly(bootstrap_selector=MINIMAL)
    tampered = deepcopy(assembly)
    declaration = tampered['bootstrap_declaration']
    if mutation == 'image_sha256':
        declaration['images'][0]['sha256'] = '0' * 64
    elif mutation == 'removed_gpio_writes':
        declaration['removed_gpio_writes'] = []
    elif mutation == 'selector':
        declaration['selector'] = 'ibex_pulp_dual_source.minimal_bootstrap'
    elif mutation == 'instruction_slots':
        declaration['instruction_slots'] = [['cpu', 0x11000, 1]]
    elif mutation == 'template_sha256':
        declaration['template_sha256'] = '0' * 64
    elif mutation == 'source_files':
        declaration['source_files'] = declaration['source_files'][:1]
    else:
        declaration['nonce'] = '0' * 32
    with pytest.raises(ValueError):
        api.validate_register_assembly(tampered)
    with pytest.raises(ValueError):
        api._verify_bootstrap_plan(minimal_plan(), tampered)


def test_selector_and_declaration_presence_are_coupled():
    assembly = api.make_register_assembly(bootstrap_selector=MINIMAL)
    without_declaration = {name: value for name, value in assembly.items()
                           if name != 'bootstrap_declaration'}
    with pytest.raises(ValueError, match='requires its declaration'):
        api.validate_register_assembly(without_declaration)
    without_selector = {name: value for name, value in assembly.items()
                        if name != 'bootstrap_selector'}
    with pytest.raises(ValueError, match='requires its selector'):
        api.validate_register_assembly(without_selector)
    # A shipped-derived declaration cannot claim the minimal identity, and the
    # integration path is anchored on that same refusal.
    with pytest.raises(ValueError,
                       match='minimal bootstrap still writes a removed GPIO word'):
        fixture.minimal_bootstrap_declaration(
            fixture.make_ibex_pulp_dual_source_stream_bootstrap())


def test_reintroduced_removed_write_is_refused_through_every_selector_path(monkeypatch):
    """A selector that cannot deliver the declared bytes must never be accepted."""
    assembly = api.make_register_assembly(bootstrap_selector=MINIMAL)
    monkeypatch.setattr(fixture, 'make_ibex_pulp_dual_source_minimal_bootstrap',
                        fixture.make_ibex_pulp_dual_source_stream_bootstrap)
    with pytest.raises(ValueError,
                       match='minimal bootstrap still writes a removed GPIO word'):
        api.validate_register_assembly(assembly)
    with pytest.raises(ValueError,
                       match='minimal bootstrap still writes a removed GPIO word'):
        api._verify_bootstrap_plan(minimal_plan(), assembly)
    with pytest.raises(ValueError,
                       match='minimal bootstrap still writes a removed GPIO word'):
        online.select_ibex_pulp_dual_source_bootstrap(MINIMAL)
    monkeypatch.undo()
    api.validate_register_assembly(assembly)
    online.select_ibex_pulp_dual_source_bootstrap(MINIMAL)


# ---------------------------------------------------------------------------
# The public online entry point no longer hard-codes the shipped bootstrap
# ---------------------------------------------------------------------------

def test_online_entry_point_selects_only_the_closed_bootstrap(tmp_path, monkeypatch):
    captured = {}

    def assemble(**kwargs):
        captured.clear()
        captured.update(kwargs)
        return 'runtime'

    monkeypatch.setattr(online, 'make_pulp_dual_source_online_runtime', assemble)
    runtime = online.make_ibex_pulp_online_runtime(cache_dir=tmp_path / 'a', run_id='r')
    assert runtime == 'runtime'
    assert boot_image_sha256(captured['bootstrap']) == SHIPPED_BOOT_IMAGE_SHA256
    runtime = online.make_ibex_pulp_online_runtime(
        cache_dir=tmp_path / 'b', run_id='r', bootstrap_selector=MINIMAL)
    assert runtime == 'runtime'
    # The selector is resolved before the shared, CPU-agnostic assembly: that
    # builder's contract and every other caller of it stay unchanged.
    assert 'bootstrap_selector' not in captured
    assert boot_image_sha256(captured['bootstrap']) == MINIMAL_BOOT_IMAGE_SHA256
    assert captured['bootstrap'].instruction_start == 0x11000
    assert captured['bootstrap'].instruction_count == 31616
    runtime = online.make_ibex_pulp_online_runtime(
        cache_dir=tmp_path / 'c', run_id='r', bootstrap_selector=None)
    assert runtime == 'runtime'
    assert boot_image_sha256(captured['bootstrap']) == SHIPPED_BOOT_IMAGE_SHA256
    with pytest.raises(ValueError):
        online.make_ibex_pulp_online_runtime(
            cache_dir=tmp_path / 'd', run_id='r', bootstrap_selector='minimal')
    assert boot_image_sha256(online.select_ibex_pulp_dual_source_bootstrap()) \
        == SHIPPED_BOOT_IMAGE_SHA256
    with pytest.raises(ValueError):
        online.select_ibex_pulp_dual_source_bootstrap('minimal')
