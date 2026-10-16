"""PADIN/INTSTATUS stay refused: this file pins the current refusal, adds no rule.

Task 6's third bullet keeps both registers out of ordinary reset-default scope
until a separate reviewed source audit exists.  Nothing here widens
``_READ_EFFECTS``/``_WRITE_EFFECTS``/``CLEARING_SIDE_EFFECTS`` and nothing here
invents a PADIN/INTSTATUS rule.  Every assertion either recomputes a current
refusal from the pinned profile/sidecar/RTL bytes or records the exact current
behaviour that forces the refusal to stay; the obligations come from
``runs/stage2-e2-native-reset-task6-padin-intstatus-audit-20261012/``.

Real facts used below (measured against the pinned files, not restated blindly):
PADIN decodes at offset 8 / decode word 2, INTSTATUS at offset 36 / decode word
9, both alias every 128 bytes (mask 124, 32 alias blocks), neither profile entry
declares a ``reset_value`` while both sidecar entries declare 0.
"""
import json

import pytest

from myfuzz.scenario.memory import MemoryRegion
from tests.composition.test_pulp_gpio_test_capability import ROOT, loaded
from tests.local_harness.test_ordinary_apb_access_receipts import native_factory
from tests.scenario.test_native_reset_evidence import configured_runner
from tests.scenario.test_register_program_verification import arguments
from tests.scenario.test_register_program_replay import adapter


def installed(native_factory, tmp_path):
    """The Task-3 idiom: real target observers, Task2 evidence, real adapter."""
    from myfuzz.scenario.genome import ScenarioGenome
    from myfuzz.scenario.session_runtime import ScenarioSession
    runner = configured_runner(native_factory, tmp_path)
    session = ScenarioSession(ScenarioGenome('directed', 'CPU_TO_IP', 'register_program',
                                             ('cpu', 'gpio_a', 'gpio_b'), 144, ()), runner)
    session.declare_instruction_slots('cpu', 0x11000, 32)
    runner.install_native_reset_evidence(max_commands=32)
    return adapter(session)


def test_padin_default_read_has_no_rule_and_its_sidecar_zero_is_not_provenance():
    """Profile absence and sidecar/RTL zero are different facts, and neither is a rule."""
    from myfuzz.scenario.register_reset_default_verifier import (
        _validate_inten_rule, derive_inten_reset_rule)
    profile, capability = loaded()
    rule = derive_inten_reset_rule(profile, capability, base_dir=ROOT, target_instance='gpio_a')
    assert (rule['register'], rule['offset']) == ('INTEN', 24)
    # A PADIN-shaped rule is refused even when every other byte is the reviewed rule.
    # It would fail if the validator ever accepted a rule whose register/offset the
    # source audit does not cover (the mismatch is the whole comparison, not a name test).
    with pytest.raises(ValueError, match='reset-rule-current-target-comparison-mismatch'):
        _validate_inten_rule({**rule, 'register': 'PADIN', 'offset': 8})
    register = next(row for row in profile.address.registers if row.name == 'PADIN')
    field = next(row for row in capability.register_semantics
                 if (row.register, row.field) == ('PADIN', 'value'))
    # The profile declares no reset value at all ...
    assert (register.offset, register.width, register.access, register.side_effect,
            register.reset_value) == (8, 32, 'ro', 'none', None)
    # ... while the sidecar declares 0: exactly the "reset_value alone" input the plan
    # forbids as a PADIN expectation.  Pinning both halves proves the temptation exists
    # and that no rule consumes it.
    assert (field.lsb, field.width, field.access, field.read_mask, field.write_mask,
            field.reset_value, field.side_effect) == (0, 32, 'ro', 0xffffffff, 0, 0, 'none')
    assert 8 in rule['known_unrelated_offsets'] and rule['offset'] == 24


def test_intstatus_repeated_zero_read_is_not_accepted_as_a_default_proof():
    """The read clears state, so a second zero is strictly less informative than the first."""
    from myfuzz.local_harness.pulp_gpio_probe_contract import decoded_gpio_word
    from myfuzz.scenario.register_reset_default_verifier import (
        _validate_inten_rule, classify_inten_command, derive_inten_reset_rule)
    profile, capability = loaded()
    rule = derive_inten_reset_rule(profile, capability, base_dir=ROOT, target_instance='gpio_a')
    with pytest.raises(ValueError, match='reset-rule-current-target-comparison-mismatch'):
        _validate_inten_rule({**rule, 'register': 'INTSTATUS', 'offset': 36})
    # RTL decode identity: raw 36 and every 36 + 128k alias are the same decoded word 9
    # (REG_INTSTATUS_00_31).  A rule that looked at raw offsets only would miss 31 aliases.
    assert [decoded_gpio_word(raw) for raw in (36, 164, 292, 4004)] == [9, 9, 9, 9]
    assert all(raw & rule['address_decode_mask'] == 36 for raw in (36, 164, 292, 4004))
    # The current total-effect classifier calls any read harmless and lists 36 as an
    # unrelated word.  This is precisely why a "read it twice, both zero" story must not
    # be assembled from the ledger: the classifier cannot express the clear at all.
    # A future INTSTATUS rule has to change this classification, and this assertion is
    # the guard that it cannot inherit the blind spot silently.
    assert [classify_inten_command(
        dict(status='parsed_complete', operation='ACCESS_GPIO',
             fields=[0, 0, raw, 0, 15]), rule=rule) for raw in (36, 164, 4004)] == \
        ['read', 'read', 'read']
    assert 36 in rule['known_unrelated_offsets']
    register = next(row for row in profile.address.registers if row.name == 'INTSTATUS')
    field = next(row for row in capability.register_semantics
                 if (row.register, row.field) == ('INTSTATUS', 'value'))
    assert (register.offset, register.access, register.side_effect,
            register.reset_value) == (36, 'ro', 'read_clears', None)
    assert (field.width, field.access, field.read_mask, field.write_mask,
            field.reset_value, field.side_effect) == (32, 'ro', 0xffffffff, 0, 0, 'read_clears')


def test_two_zero_intstatus_reads_through_the_actual_ledger_are_not_a_certificate(
        native_factory, tmp_path):
    """Real wire reads at 36 and its alias 164 leave the live verifier with no proof."""
    from myfuzz.scenario.register_reset_default_verifier import (
        RegisterResetDefaultVerifier, validate_register_reset_default_session_document)
    runtime = installed(native_factory, tmp_path)
    verifier = RegisterResetDefaultVerifier(runtime, max_records=4)
    target = runtime.runner.sessions['gpio_a']
    target.begin_case('intstatus-zero-reads')
    try:
        target.command('ACCESS_GPIO', (0, 0, 36, 0, 15))
        target.command('ACCESS_GPIO', (0, 0, 164, 0, 15))
        rows = target.native_reset_observation_commands()
        # The two reads really were issued, parsed and sealed by the actual observer.
        assert [(row['operation'], row['fields'], row['status']) for row in rows] == [
            ('ACCESS_GPIO', [0, 0, 36, 0, 15], 'parsed_complete'),
            ('ACCESS_GPIO', [0, 0, 164, 0, 15], 'parsed_complete')]
        assert [row['parsed_receipt_projection']['payload']['rdata'] for row in rows] == [0, 0]
        state = verifier.report()
        # No certificate of any kind, current or historical: two zero INTSTATUS reads
        # are not a reset default.  It would fail if a rule ever promoted this pair.
        assert state['current_certificates'] == [] and state['historical_certificates'] == []
        assert state['gaps'] == [dict(target_instance='gpio_a',
                                      reason='missing_native_reset_default_readback')]
        validate_register_reset_default_session_document(
            verifier.session_document(), configuration=runtime.configuration())
    finally:
        target.end_case()


def test_compiler_consent_does_not_widen_the_read_clear_whitelist():
    """``allow_side_effect=True`` is caller consent, not a reviewed effect allowance."""
    from myfuzz.composition.component_profile import CLEARING_SIDE_EFFECTS
    from myfuzz.composition.test_capability import IPTestCapabilityError
    from myfuzz.scenario.register_program import (
        _READ_EFFECTS, _WRITE_EFFECTS, compile_register_program)
    assert 'read_clears' in CLEARING_SIDE_EFFECTS and 'read_clears' not in _READ_EFFECTS
    assert 'write_1_to_clear' in CLEARING_SIDE_EFFECTS and 'write_1_to_clear' not in _WRITE_EFFECTS
    profile, capability, args = arguments(
        register='INTSTATUS', field='value', operation='register_read', value=None,
        result_address=0x21000, result_regions=(MemoryRegion('result', 0x21000, 64),))
    # Gate one: without consent the typed capability refuses the declared effect.
    with pytest.raises(IPTestCapabilityError,
                       match='register-side-effect-requires-explicit-authorization:read_clears'):
        compile_register_program(profile, capability, allow_side_effect=False, **args)
    # Gate two: consent alone does not widen the compiler whitelist.  A future change
    # that "just passes allow_side_effect=True" fails closed here.
    with pytest.raises(ValueError, match='register-program-unsupported-side-effect'):
        compile_register_program(profile, capability, allow_side_effect=True, **args)


def test_padin_read_compiles_but_grants_no_reset_default():
    """Compiler acceptance means "admissible access", never "reset default value"."""
    from myfuzz.scenario.register_program import compile_register_program
    profile, capability, args = arguments(
        register='PADIN', field='value', operation='register_read', value=None,
        result_address=0x21000, result_regions=(MemoryRegion('result', 0x21000, 64),))
    document = compile_register_program(profile, capability, allow_side_effect=False, **args).document()
    assert document['operation_plan']['offset'] == 8
    assert document['operation_plan']['side_effect'] == 'none'
    assert document['scope'] == 'declarative_cpu_register_program_only'
    assert document['grants_prerequisites'] is False
    assert document['result_storage']['evidence_scope'] == 'requires_actual_cpu_store_and_read_snapshot'
    # The program claims nothing about a reset default, in any field, under any casing.
    # This is the readable form of "admitted access != default value": a future PADIN
    # rule that cites compiler acceptance as evidence fails this line.
    assert 'reset' not in json.dumps(document, sort_keys=True).lower()


def test_write_to_padin_is_refused_by_the_typed_capability():
    """PADIN is read-only in the pinned profile; no write path may be implied."""
    from myfuzz.composition.test_capability import IPTestCapabilityError
    from myfuzz.scenario.register_program import compile_register_program
    profile, capability, args = arguments(
        register='PADIN', field='value', operation='register_write', value=0,
        result_address=None, result_regions=())
    with pytest.raises(IPTestCapabilityError, match='register-field-not-writable:PADIN.value'):
        compile_register_program(profile, capability, allow_side_effect=False, **args)
