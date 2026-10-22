"""P6 row-5 (PicoRV32 native ready/valid memory x PULP APB3 GPIO) campaign.

``docs/superpowers/plans/2026-10-13-p6-per-protocol-row-checklist.md`` row 5
recorded the native CPU's local RAM/ROM acceptance and a directed CPU<->GPIO
chain, and listed the remaining gaps as the multi-case persistent session with
both sides' sources, the four feedback families and the queued ``defer_mmio``
form.  This file pins the pieces that make the campaign evidence honest, at
three levels.

**The program and its sources.**  The image the fuzzer mutates is assembled by
an explicit RV32I encoder in the fixture, and the mutable bit range is asserted
to be exactly the low byte of one ``addi`` immediate, so a mutation can change
the byte the CPU drives to PADOUT and nothing else.  Both declared sources --
the CPU program immediate and the external GPIO pin byte -- are checked to be
real owners of disjoint inputs.

**The checker.**  ``assess_native_gpio_closed_chain`` is exercised against a
canonical synthetic two-round stream per direction and one tampered copy per
required stage.  A checker that cannot fail is not a checker, so every tamper
asserts the *specific* finding it must produce -- including the queued-MMIO
evidence: a delivery whose producer is a CPU step instead of a device step must
be refused.

**The campaign.**  A saved 18-cell campaign is audited from its own bytes by
``test_picorv32_native_campaign_saved_run_audit.py``; this file audits the
provider guards that make substitution impossible (an Ibex/CVA6 seed fed to
this provider is refused) and the row's own directed real-RTL chain, which is
gated behind ``MYFUZZ_SCENARIO_REAL=1`` like the other pinned-RTL gates.
"""
from __future__ import annotations

import json
import os
from dataclasses import replace
from inspect import signature
from pathlib import Path

import pytest

from myfuzz.integration.picorv32_native_scenario_campaign import (
    PicoNativeGpioBoundProvider, assess_native_gpio_closed_chain)
from myfuzz.integration.scenario_campaign import CampaignBlocked
from myfuzz.integration.picorv32_native_online import (
    PicoNativeOnlineRuntime, make_picorv32_native_online_runtime)
from myfuzz.scenario.native_packet_session import (
    native_packet_source_binding_configuration,
    native_packet_source_completion_configuration)
from myfuzz.scenario import picorv32_native_cpu_example as fixture
from myfuzz.scenario.genome import GenomeCodec

ROOT = Path(__file__).resolve().parents[2]
CONFIGS = ROOT / 'configs/scenario'
BOUND_SEED = CONFIGS / 'pico_native_gpio_campaign_seed.json'
REVERSE_SEED = CONFIGS / 'pico_native_gpio_reverse_seed.json'
BASELINE = CONFIGS / 'pico_native_gpio_campaign_baseline.json'
CVA6_SEED = CONFIGS / 'cva6_cpu_two_gpio_campaign_seed.json'
IBEX_SEED = CONFIGS / 'ibex_two_gpio_closed_two_rounds.json'

CPU = 'CPU_TO_IP_TO_CPU'
IP = 'IP_TO_CPU_TO_IP'

A = fixture.PADOUT_BYTE_SEED
B = fixture.GPIO_INPUT_SEED
C1 = fixture.joint_value(A, B)
C2 = fixture.round_two_value(A, B)


def seed(direction):
    return GenomeCodec.decode(
        (BOUND_SEED if direction == CPU else REVERSE_SEED).read_bytes())


class TestNativeSourceCompletionOptIn:
    def test_source_completion_is_a_strict_default_off_opt_in(self):
        parameter = signature(make_picorv32_native_online_runtime).parameters[
            'native_source_completion']
        assert parameter.default is False
        for invalid in (0, 1, None, 'true'):
            with pytest.raises(ValueError, match='native_source_completion must be boolean'):
                make_picorv32_native_online_runtime(
                    cache_dir=Path('/tmp/native-source-completion-test'),
                    native_source_completion=invalid)

    def test_source_completion_requires_both_existing_native_prerequisites(self):
        with pytest.raises(ValueError, match='native completion observation'):
            make_picorv32_native_online_runtime(
                cache_dir=Path('/tmp/native-source-completion-test'),
                native_source_completion=True)
        with pytest.raises(ValueError, match='native source binding'):
            make_picorv32_native_online_runtime(
                cache_dir=Path('/tmp/native-source-completion-test'),
                native_completion_observation=True,
                native_source_completion=True)
        with pytest.raises(ValueError, match='native completion observation'):
            make_picorv32_native_online_runtime(
                cache_dir=Path('/tmp/native-source-completion-test'),
                native_source_binding=True, native_source_completion=True)

    def test_raw_sample_bound_allows_28_cases_and_refuses_29_without_changing_binding(self, monkeypatch):
        completion = native_packet_source_completion_configuration(28)
        assert completion['max_native_raw_samples'] == 4096
        assert completion['max_warmup_native_samples'] + (
            completion['max_cases'] * completion['native_samples_per_case']) == 4096
        assert completion['max_completion_objects'] == 256
        with pytest.raises(ValueError, match='raw-sample bound'):
            native_packet_source_completion_configuration(29)
        assert native_packet_source_binding_configuration(96)['max_cases'] == 96

        import myfuzz.integration.picorv32_native_online as native_online
        def forbidden(*args, **kwargs):
            pytest.fail('29 case completion plan must fail before bootstrap or factory')
        monkeypatch.setattr(native_online, 'make_picorv32_native_online_bootstrap', forbidden)
        monkeypatch.setattr(native_online, 'make_picorv32_native_online_factory', forbidden)
        with pytest.raises(ValueError, match='raw-sample bound'):
            native_online.make_picorv32_native_online_runtime(
                cache_dir=Path('/tmp/native-source-completion-test'), max_cases=29,
                native_completion_observation=True, native_source_binding=True,
                native_source_completion=True)

    @pytest.mark.parametrize('failure', [False, True])
    def test_finish_revokes_completion_owner_after_success_or_failure(self, failure):
        class Session:
            def __init__(self):
                self.revocations = 0

            def finish_export(self):
                if failure:
                    raise RuntimeError('finish failed')
                return 'finished'

            def _revoke_native_source_completion(self, primary=None):
                self.revocations += 1

            def abort_packet_submission(self, primary):
                pass

        runtime = PicoNativeOnlineRuntime.__new__(PicoNativeOnlineRuntime)
        runtime.session = Session()
        runtime._begun = True
        runtime._terminal = False
        if failure:
            with pytest.raises(RuntimeError, match='finish failed'):
                runtime.finish()
        else:
            assert runtime.finish() == 'finished'
        assert runtime.session.revocations == 1


# --------------------------------------------------------------------------
# the program image and its mutation source
# --------------------------------------------------------------------------
class TestProgramImage:
    def test_the_mutable_source_is_the_padout_immediate_field(self):
        for direction in (CPU, IP):
            program = fixture.direction_program(direction)
            index = fixture.PADOUT_IMMEDIATE_INSTRUCTION
            word = int.from_bytes(program[4 * index:4 * index + 4], 'little')
            assert word & 0x7f == 0x13, 'opcode must be addi'
            assert (word >> 15) & 0x1f == 0, 'rs1 must be x0'
            assert (word >> 7) & 0x1f == 3, 'rd must be the padout register'
            assert (word >> 20) & 0xfff == fixture.PADOUT_BYTE_SEED
            assert 32 * index + 20 == fixture.PADOUT_BYTE_BIT_OFFSET
            assert fixture.SOURCE_WIDTH == 8
            assert (fixture.PADOUT_BYTE_BIT_OFFSET + fixture.SOURCE_WIDTH
                    < 32 * index + 32)

    def test_mutating_the_source_changes_only_the_transmitted_byte(self):
        for direction in (CPU, IP):
            program = bytearray(fixture.direction_program(direction))
            for bit in range(fixture.SOURCE_WIDTH):
                absolute = fixture.PADOUT_BYTE_BIT_OFFSET + bit
                mutated = bytearray(program)
                mutated[absolute // 8] ^= 1 << (absolute % 8)
                index = fixture.PADOUT_IMMEDIATE_INSTRUCTION
                word = int.from_bytes(mutated[4 * index:4 * index + 4], 'little')
                assert word & 0x7f == 0x13
                assert (word >> 7) & 0x1f == 3
                assert (word >> 20) & 0xfff == (
                    fixture.PADOUT_BYTE_SEED ^ (1 << bit))
                mask = ~(((1 << fixture.SOURCE_WIDTH) - 1) << 20) & 0xffffffff
                original = int.from_bytes(
                    program[4 * index:4 * index + 4], 'little')
                assert original & mask == word & mask

    def test_the_two_directions_run_the_same_pinned_program(self):
        assert fixture.direction_program(CPU) == fixture.direction_program(IP)
        assert fixture.program_digest(CPU) == fixture.program_digest(IP)

    def test_the_committed_values_are_joint_functions_of_both_sources(self):
        for a in (0x00, 0x5A, 0xFF):
            for b in (0x00, 0x3C, 0xFF):
                assert fixture.joint_value(a, b) == a ^ b
                assert fixture.round_two_value(a, b) == (a ^ b) + b


# --------------------------------------------------------------------------
# Genome pinning and provider guards
# --------------------------------------------------------------------------
class TestGenomePins:
    def test_both_seed_genomes_carry_both_sources(self):
        for direction in (CPU, IP):
            genome = seed(direction)
            assert genome.direction == direction
            assert genome.schedule_order == ('cpu', 'gpio0')
            assert (genome.max_steps, genome.quiesce_steps) == \
                fixture.DIRECTION_SHAPES[direction]
            assert [image.image_id for image in genome.initial_images] == \
                ['cpu.program']
            assert genome.initial_images[0].data == \
                fixture.direction_program(direction)
            assert len(genome.actions) == 1
            action = genome.actions[0]
            assert (action.component, action.port) == ('gpio0', 'gpio_in')
            assert (action.bit_offset, action.width) == (0, 8)
            assert action.value == fixture.GPIO_INPUT_SEED
            assert action.trigger.kind == (
                'AFTER_OUTPUT' if direction == CPU else 'START')

    def test_the_pinned_seed_checker_accepts_the_seeds(self):
        for direction, path in ((CPU, BOUND_SEED), (IP, REVERSE_SEED)):
            image = PicoNativeGpioBoundProvider._require_pinned_seed(
                seed(direction), direction, path)
            assert image.image_id == 'cpu.program'

    def test_the_pinned_seed_checker_refuses_a_direction_swap(self):
        with pytest.raises(CampaignBlocked):
            PicoNativeGpioBoundProvider._require_pinned_seed(
                seed(CPU), IP, BOUND_SEED)

    def test_the_pinned_seed_checker_refuses_a_changed_pin_value(self):
        genome = seed(CPU)
        altered = replace(genome, actions=(replace(
            genome.actions[0], value=fixture.GPIO_INPUT_SEED ^ 1),))
        with pytest.raises(CampaignBlocked):
            PicoNativeGpioBoundProvider._require_pinned_seed(
                altered, CPU, BOUND_SEED)

    def test_the_pinned_seed_checker_refuses_a_changed_program_image(self):
        genome = seed(CPU)
        image = genome.initial_images[0]
        data = bytearray(image.data)
        data[0] ^= 1
        altered = replace(genome, initial_images=(
            replace(image, data_hex=bytes(data).hex()),))
        with pytest.raises(CampaignBlocked):
            PicoNativeGpioBoundProvider._require_pinned_seed(
                altered, CPU, BOUND_SEED)

    def test_foreign_cpu_seeds_are_refused_by_the_native_provider(self):
        """An Ibex or CVA6 seed may never be relabelled as row 5 evidence."""
        from myfuzz.integration.scenario_campaign import (
            _require_pinned_bound_seed)

        for path in (CVA6_SEED, IBEX_SEED):
            with pytest.raises(CampaignBlocked):
                _require_pinned_bound_seed(
                    path, PicoNativeGpioBoundProvider.BOUND_SEED_SHAPE)
            with pytest.raises(CampaignBlocked):
                PicoNativeGpioBoundProvider()._fixture(CPU, path)

    def test_reserved_pin_bits_and_masked_spans_are_not_mutable(self):
        ownership = fixture.gpio_ownership()
        assert ownership.field_width('gpio0', 'gpio_in') == 32
        assert ownership.mutation_source(
            'gpio0', 'gpio_in', 0, 8, direction=CPU) == 'external_gpio_pins'
        # Bits 8..31 are the fixture's declared constant zero: neither a
        # reserved bit nor a span that reaches it may be selected.
        for bit_offset, width in ((8, 1), (31, 1), (0, 9), (7, 2)):
            with pytest.raises(ValueError):
                ownership.mutation_source('gpio0', 'gpio_in', bit_offset,
                                          width, direction=CPU)

    def test_the_independent_baseline_is_well_formed(self):
        document = json.loads(BASELINE.read_text(encoding='utf-8'))
        assert document['schema_version'] == 'scenario_independent_baseline.v1'
        assert document['local_response_model'] == 'persistent_shadow_registers'
        assert document['cross_component_bindings'] == []
        assert document['cpu_irq'] == 'constant_zero'
        assert document['gpio_local_window'] == {
            'base': fixture.GPIO_BASE, 'size': fixture.GPIO_WINDOW}
        for key in ('cpu_seed', 'reverse_seed'):
            assert (CONFIGS / document[key]).is_file()
        reverse = GenomeCodec.decode(
            (CONFIGS / document['reverse_seed']).read_bytes())
        assert reverse.direction == IP


# --------------------------------------------------------------------------
# the closed-chain checker: one canonical stream per direction and tampers
# --------------------------------------------------------------------------
def _transaction(sequence):
    return {'execution_id': 'exec', 'testcase_id': 'case',
            'source_component': 'cpu', 'source_epoch': 0,
            'channel_id': 'memory', 'source_sequence': sequence}


class _Stream:
    def __init__(self):
        self.events = []

    def add(self, **event):
        event['event_id'] = len(self.events) + 1
        self.events.append(event)
        return event

    def gpio_step(self, *, gpio_out=None, gpio_in_sync=None):
        outputs = {}
        if gpio_out is not None:
            outputs['gpio_out'] = gpio_out
        if gpio_in_sync is not None:
            outputs['gpio_in_sync'] = gpio_in_sync
        return self.add(component='gpio0', tick=len(self.events) + 1,
                        outputs=outputs)

    def cpu_step(self, *, consumed=None, rdata=None, epoch=0, sequence=0):
        outputs = {'data_rsp_consumed': int(bool(consumed)),
                   'data_rsp_rdata': rdata or 0,
                   'data_rsp_source_epoch': epoch,
                   'data_rsp_source_sequence': sequence}
        return self.add(component='cpu', tick=len(self.events) + 1,
                        outputs=outputs)


def _canonical_stream(direction, *, injection='normal'):
    """A synthetic two-round stream in the shape the checker consumes.

    It is not copied from a run; each event records only the fields the
    assessment reads, in the order a real deferred-MMIO round produces them.
    The real RTL tests below are what prove the shape is not invented.
    """
    stream = _Stream()
    stream.add(kind='initial_image', component='cpu', image_id='cpu.program',
               address=0, data_hex=fixture.direction_program(direction).hex())

    def inject_pin():
        return stream.add(kind='source_injection', action_id='gpio_pin_byte',
                          component='gpio0', port='gpio_in', bit_offset=0,
                          width=8, value=B, direction=direction,
                          source_ref=fixture.GPIO_SOURCE_ID)

    if direction == IP and injection == 'normal':
        inject_pin()

    def device_beat(sequence, offset, write, value):
        transaction = _transaction(sequence)
        stream.add(kind='mmio_acceptance', device_id='gpio0',
                   source_transaction=transaction, offset=offset, write=write,
                   write_value=value if write else None,
                   source_sequence=sequence)
        return transaction

    def deliver(transaction, offset, write, value, *, producer='gpio0'):
        if producer == 'gpio0':
            stream.gpio_step()
        else:
            stream.cpu_step()
        producer_id = stream.events[-1]['event_id']
        return stream.add(kind='mmio_delivery', device_id='gpio0',
                          source_transaction=transaction, offset=offset,
                          write=write,
                          write_value=value if write else None,
                          read_value=None if write else value,
                          producer_event_id=producer_id,
                          address=fixture.GPIO_BASE + offset)

    for sequence, offset in ((1, fixture.PADDIR), (2, fixture.GPIOEN)):
        transaction = device_beat(sequence, offset, True, 0xffffffff)
        deliver(transaction, offset, True, 0xffffffff)
    if injection == 'early':
        inject_pin()
    transaction = device_beat(3, fixture.PADOUT, True, A)
    if direction == CPU and injection == 'normal':
        inject_pin()
    deliver(transaction, fixture.PADOUT, True, A)
    stream.gpio_step(gpio_out=A)
    transaction = device_beat(4, fixture.PADIN, False, 0)
    deliver(transaction, fixture.PADIN, False, B)
    stream.gpio_step(gpio_in_sync=B)
    stream.cpu_step(consumed=True, rdata=B, sequence=4)
    stream.add(kind='memory_write', component='cpu',
               address=fixture.RESULT_ADDRESS, value=C1)
    transaction = device_beat(5, fixture.PADOUT, True, C1)
    if injection == 'late':
        inject_pin()
    deliver(transaction, fixture.PADOUT, True, C1)
    stream.gpio_step(gpio_out=C1)
    transaction = device_beat(6, fixture.PADIN, False, 0)
    deliver(transaction, fixture.PADIN, False, B)
    stream.cpu_step(consumed=True, rdata=B, sequence=6)
    stream.add(kind='memory_write', component='cpu',
               address=fixture.RESULT2_ADDRESS, value=C2)
    stream.add(kind='memory_write', component='cpu',
               address=fixture.MARKER_ADDRESS, value=fixture.MARKER_VALUE)
    return stream


def _final_state():
    return {'inputs': {'gpio0': {'gpio_in': B}, 'cpu': {}},
            'pending_responses': {'cpu': 0, 'gpio0': 0}}


def _assess(direction, stream, final_state=None):
    return assess_native_gpio_closed_chain(
        direction, stream.events,
        _final_state() if final_state is None else final_state)


def _delivery(stream, *, offset, write, value=None):
    return [event for event in stream.events
            if event.get('kind') == 'mmio_delivery'
            and event.get('offset') == offset
            and event.get('write') is write
            and (value is None or event.get('write_value') == value)]


class TestClosedChainChecker:
    def test_the_canonical_cpu_direction_round_completes(self):
        assessment = _assess(CPU, _canonical_stream(CPU))
        assert assessment['complete'] is True, assessment['findings']
        assert assessment['rounds'] == 2
        assert assessment['padout_byte'] == A
        assert assessment['pin_byte'] == B
        assert assessment['joint_value'] == C1
        assert assessment['second_commit'] == C2
        assert assessment['queued_device_deliveries'] == 6

    def test_the_canonical_ip_direction_round_completes(self):
        assessment = _assess(IP, _canonical_stream(IP))
        assert assessment['complete'] is True, assessment['findings']
        assert assessment['rounds'] == 2

    def test_a_delivery_that_ran_on_the_cpu_step_is_refused(self):
        """The queued form must execute on the device's own step."""
        stream = _canonical_stream(CPU)
        first_write = _delivery(stream, offset=fixture.PADOUT, write=True,
                                value=A)[0]
        cpu_step = next(event for event in stream.events
                        if event.get('component') == 'cpu'
                        and 'outputs' in event)
        first_write['producer_event_id'] = cpu_step['event_id']
        assert 'device_delivery_not_executed_on_device_step' in \
            _assess(CPU, stream)['findings']

    def test_the_cpu_direction_requires_the_cpu_to_initiate(self):
        assessment = _assess(CPU, _canonical_stream(CPU, injection='early'))
        assert 'cpu_did_not_initiate' in assessment['findings']
        assert assessment['complete'] is False

    def test_the_ip_direction_requires_the_ip_to_initiate(self):
        assessment = _assess(IP, _canonical_stream(IP, injection='late'))
        assert 'ip_did_not_initiate' in assessment['findings']

    def test_a_wrong_pin_answer_is_refused(self):
        stream = _canonical_stream(CPU)
        _delivery(stream, offset=fixture.PADIN, write=False)[0]['read_value'] = \
            B ^ 1
        assert 'round_one_padin_answer_mismatch' in _assess(CPU, stream)['findings']

    def test_a_non_joint_second_write_is_refused(self):
        stream = _canonical_stream(CPU)
        _delivery(stream, offset=fixture.PADOUT, write=True,
                  value=C1)[0]['write_value'] = C1 ^ 1
        assert 'second_padout_write_is_not_the_joint_value' in \
            _assess(CPU, stream)['findings']

    def test_a_missing_ram_commit_is_refused(self):
        stream = _canonical_stream(CPU)
        commit = next(event for event in stream.events
                      if event.get('kind') == 'memory_write'
                      and event.get('address') == fixture.RESULT_ADDRESS)
        commit['address'] = fixture.RESULT2_ADDRESS + 4
        assert 'cpu_ram_commit_round_one_missing' in \
            _assess(CPU, stream)['findings']

    def test_a_reused_transaction_identity_is_refused(self):
        stream = _canonical_stream(CPU)
        reads = _delivery(stream, offset=fixture.PADIN, write=False)
        reads[1]['source_transaction'] = dict(reads[0]['source_transaction'])
        assert 'padin_read_round_two_transaction_reused' in \
            _assess(CPU, stream)['findings']

    def test_a_reset_barrier_is_refused(self):
        stream = _canonical_stream(CPU)
        stream.add(kind='reset_barrier', component='cpu')
        assert 'unexpected_reset' in _assess(CPU, stream)['findings']

    def test_a_pending_response_at_the_end_is_refused(self):
        final = _final_state()
        final['pending_responses']['gpio0'] = 1
        assessment = _assess(CPU, _canonical_stream(CPU), final)
        assert 'pending_responses_at_end' in assessment['findings']

    def test_the_direction_must_be_declared(self):
        assert assess_native_gpio_closed_chain(
            'CPU_TO_IP', _canonical_stream(CPU).events, _final_state()) is None


# --------------------------------------------------------------------------
# directed real RTL: the same two-round chain the campaign runs
# --------------------------------------------------------------------------
REAL = pytest.mark.skipif(
    os.environ.get('MYFUZZ_SCENARIO_REAL') != '1',
    reason='set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')


@pytest.fixture(scope='module')
def pair(tmp_path_factory):
    cache = tmp_path_factory.mktemp('pico-native-gpio-cache')
    return fixture.PicoNativeGpioPair(base_dir=ROOT, cache_dir=cache)


@REAL
class TestDirectedRealRtl:
    def _run(self, pair, direction):
        from myfuzz.scenario.replay import record_scenario

        genome = seed(direction)
        held = {}

        def factory():
            runner = pair.runner()
            held['runner'] = runner
            return runner

        trace = record_scenario(genome, factory)
        assessment = assess_native_gpio_closed_chain(
            direction, trace.events, held['runner'].final_state_document())
        return genome, trace, assessment

    def test_the_cpu_direction_runs_two_real_rounds_and_replays(self, pair):
        from myfuzz.scenario.replay import replay_scenario

        genome, trace, assessment = self._run(pair, CPU)
        assert trace.status == 'complete', trace.status
        assert assessment['complete'] is True, assessment['findings']
        assert assessment['rounds'] == 2
        assert assessment['queued_device_deliveries'] >= 6
        memory = pair.cpu.memory
        assert memory.read(fixture.RESULT_ADDRESS, 4,
                           transaction_id='check1').value == C1
        assert memory.read(fixture.RESULT2_ADDRESS, 4,
                           transaction_id='check2').value == C2
        assert replay_scenario(genome, pair.runner, trace).matches

    def test_the_ip_direction_runs_two_real_rounds_and_replays(self, pair):
        from myfuzz.scenario.replay import replay_scenario

        genome, trace, assessment = self._run(pair, IP)
        assert trace.status == 'complete', trace.status
        assert assessment['complete'] is True, assessment['findings']
        assert assessment['rounds'] == 2
        assert replay_scenario(genome, pair.runner, trace).matches
