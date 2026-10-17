"""P6 row-4 (classic Wishbone) campaign fixture, checker, guards and audit.

``docs/superpowers/plans/2026-10-13-p6-per-protocol-row-checklist.md`` row 4
records three missing pieces for the PicoRV32 Wishbone + OpenTitan GPIO row: a
scenario-layer fixture, a ``CampaignProvider``, and a closed checker that keeps
the Pico custom0 IRQ ABI (``getq``/``maskirq``/``retirq``) with the bound and
independent manifests.  ``scenario/picorv32_wb_two_gpio_example`` plus
``integration/picorv32_wb_scenario_campaign`` supply them; this file pins the
parts that make the campaign honest.

Three levels are tested:

**The program.**  The mutable source is assembled here from an explicit RV32I
encoder check: it is the three-bit immediate field of one ``addi``, its two
neighbour bits (value bit 0 and bit 4) are outside the source, and every one of
the eight mutated values keeps the round-1 edge the chain needs.  The handler is
also checked to never write the registers the resumed main program depends on
(the custom0 ABI saves only q0..q3, not the general registers).

**The checker.**  ``assess_pico_wb_closed_chain`` is exercised against a
synthetic two-round stream built stage by stage, and one tampered copy per
required stage must produce that stage's own finding.

**The provider and the saved-run audit.**  Foreign seeds (Ibex/CVA6) must be
refused before any RTL is built, and ``audit_campaign_run`` must recompute every
count from receipts/chain_checks/corpus/run identity instead of trusting the
report.  The audit is exercised on a synthetic 18-cell bundle (clearly labelled:
it validates the audit logic, not a real RTL campaign) and on a real bundle when
one is present.

Real-RTL single-case tests run only with ``MYFUZZ_SCENARIO_REAL=1``; the 18-cell
campaign itself is run by the coordinating agent under the heavy lock.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from myfuzz.integration.picorv32_wb_scenario_campaign import (
    CPU, IP, PicoWbGpioBoundProvider, assess_pico_wb_closed_chain,
    audit_campaign_run, program_image_matches)
from myfuzz.integration.scenario_campaign import CampaignBlocked
from myfuzz.scenario import picorv32_wb_two_gpio_example as fixture
from myfuzz.scenario.genome import GenomeCodec, MemoryImage

ROOT = Path(__file__).resolve().parents[2]
BOUND = ROOT / 'configs/scenario/pico_wb_two_gpio_campaign_seed.json'
BASELINE = ROOT / 'configs/scenario/pico_wb_two_gpio_campaign_baseline.json'
CVA6_SEED = ROOT / 'configs/scenario/cva6_cpu_two_gpio_campaign_seed.json'
IBEX_SEED = ROOT / 'configs/scenario/ibex_two_gpio_closed_two_rounds.json'
REAL_RUN = Path(os.environ.get(
    'MYFUZZ_PICO_WB_CAMPAIGN_RUN',
    str(ROOT / 'runs/scenario/campaign-pico-wb-g4-18cell-p6-row4-20261017')))


# --------------------------------------------------------------------------
# the program image and its mutation source
# --------------------------------------------------------------------------
class ProgramAndSourceTests(unittest.TestCase):
    def test_the_mutable_source_is_the_addi_immediate_field(self):
        for direction, seed in ((CPU, fixture.CPU_ROUND1_SEED),
                                (IP, fixture.IP_CONST_SEED)):
            program = fixture.direction_program(direction)
            index = fixture.SOURCE_INSTRUCTION
            word = int.from_bytes(program[4 * index:4 * index + 4], 'little')
            self.assertEqual(0x13, word & 0x7F, 'opcode must be addi')
            self.assertEqual(9, (word >> 7) & 0x1F, 'rd must be x9')
            self.assertEqual(0, (word >> 15) & 0x1F, 'rs1 must be x0')
            self.assertEqual(seed, (word >> 20) & 0xFFF)
            self.assertEqual(32 * index + 21, fixture.SOURCE_BIT_OFFSET)
            self.assertEqual(3, fixture.SOURCE_WIDTH)
            self.assertEqual(seed, fixture.source_immediate(direction))
            # Value bit 0 (word bit 20) and value bit 4 (word bit 24) are
            # outside the declared source, so every mutation keeps them.
            if direction == CPU:
                self.assertEqual(1, seed & 1)
            else:
                self.assertEqual(0, seed & 0x11)
            self.assertLessEqual(
                fixture.SOURCE_BIT_OFFSET + fixture.SOURCE_WIDTH,
                32 * index + 24)

    def test_every_mutated_genotype_keeps_the_round_one_edge(self):
        for direction in (CPU, IP):
            program = fixture.direction_program(direction)
            for bit in range(fixture.SOURCE_WIDTH):
                mutated = bytearray(program)
                absolute = fixture.SOURCE_BIT_OFFSET + bit
                mutated[absolute // 8] ^= 1 << (absolute % 8)
                value = (int.from_bytes(
                    mutated[4 * fixture.SOURCE_INSTRUCTION:
                            4 * fixture.SOURCE_INSTRUCTION + 4], 'little')
                    >> 20) & 0xFFF
                if direction == CPU:
                    self.assertEqual(1, value & 1)
                    self.assertEqual(0, value & 0x10)
                    self.assertLess(value, 16)
                else:
                    self.assertEqual(0, value & 0x11)
                    self.assertLess(value, 16)
                self.assertTrue(program_image_matches(bytes(mutated), direction))
            # Anything else is a different program, not a mutated source.
            foreign = bytearray(program)
            foreign[4 * fixture.SOURCE_INSTRUCTION] ^= 0x01
            self.assertFalse(program_image_matches(bytes(foreign), direction))

    def test_the_handler_only_writes_the_isr_temporaries(self):
        """The custom0 ABI saves q0..q3 only; the main registers must survive."""
        for direction in (CPU, IP):
            program = fixture.direction_program(direction)
            handler = [int.from_bytes(program[offset:offset + 4], 'little')
                       for offset in range(0x10, 0x80, 4)]
            # Everything up to the first nop after the retirq belongs to the
            # handler; the reset vector's jal word is at 0.
            written = set()
            stopped = False
            for word in handler:
                opcode = word & 0x7F
                rd = (word >> 7) & 0x1F
                rs1 = (word >> 15) & 0x1F
                rs2 = (word >> 20) & 0x1F
                if opcode == 0x03:                     # loads
                    written.add(rd)
                elif opcode == 0x23:                   # stores read rs2, write RAM
                    self.assertIn(rs1, (1, 2, 8, 9))
                    self.assertIn(rs2, (0, 3, 4, 5, 6, 7, 9))
                elif opcode == 0x13:                   # addi
                    if word == 0x00000013:
                        stopped = True
                    else:
                        written.add(rd)
                elif opcode == 0x0B:                   # custom0
                    if word == fixture.RETIRQ:
                        stopped = True
                    else:
                        written.add(rd)
                else:
                    self.fail(f'unexpected handler opcode {opcode:#x}')
                if stopped:
                    break
            self.assertNotIn(1, written)
            self.assertNotIn(2, written)
            self.assertNotIn(8, written)
            self.assertNotIn(9, written)
            self.assertTrue(written.issubset({0, 3, 4, 5, 6, 7}))

    def test_the_two_rounds_use_two_real_pins_and_two_cpu_irq_bits(self):
        bindings = fixture.pico_wb_bindings()
        irq_targets = [binding.target_bit_offset for binding in bindings
                       if binding.target_port == 'irq']
        self.assertEqual(
            [fixture.CPU_IRQ_CPU_ROUND1, fixture.CPU_IRQ_CPU_ROUND2,
             fixture.CPU_IRQ_IP_ROUND1, fixture.CPU_IRQ_IP_ROUND2],
            sorted(irq_targets))
        self.assertEqual(4, len(set(irq_targets)))
        document = fixture.pico_wb_ownership().document()
        bound = {(row['bit_offset'], row['width'], row['producer_ref'])
                 for row in document['owners']
                 if row['component_id'] == 'cpu' and row['kind'] == 'bound'}
        self.assertEqual({(fixture.CPU_IRQ_CPU_ROUND1, 1, 'gpio_b.irq'),
                          (fixture.CPU_IRQ_CPU_ROUND2, 1, 'gpio_b.irq'),
                          (fixture.CPU_IRQ_IP_ROUND1, 1, 'gpio_b.irq'),
                          (fixture.CPU_IRQ_IP_ROUND2, 1, 'gpio_b.irq')}, bound)
        sources = {(row['component_id'], row['port'], row['bit_offset'],
                    row['width'], row['producer_ref'])
                   for row in document['owners'] if row['kind'] == 'source'}
        self.assertEqual({('gpio_b', 'gpio_in', 8, 24, 'external_b')}, sources)


# --------------------------------------------------------------------------
# the closed-chain checker, against a stage-by-stage synthetic stream
# --------------------------------------------------------------------------
def _identity(sequence):
    return {'execution_id': 'exec', 'testcase_id': 'case',
            'source_component': 'cpu', 'source_epoch': 0,
            'channel_id': 'data', 'source_sequence': sequence}


def _canonical_stream(direction, *, program=None, rounds=2):
    program = fixture.direction_program(direction) if program is None else program
    immediate = (int.from_bytes(
        program[4 * fixture.SOURCE_INSTRUCTION:
                4 * fixture.SOURCE_INSTRUCTION + 4], 'little') >> 20) & 0xFFF
    pin_value = 1
    events: list[dict] = []

    def add(**event):
        event['event_id'] = len(events) + 1
        events.append(event)
        return event

    add(kind='initial_image', component='cpu', image_id=fixture.PROGRAM_IMAGE,
        address=0, data_hex=program.hex())
    add(kind='source_injection', action_id='data-pin', component='gpio_b',
        port='gpio_in', bit_offset=fixture.PIN_DATA, width=1, value=pin_value)
    if direction == IP:
        add(kind='source_injection', action_id='first-rise', component='gpio_b',
            port='gpio_in', bit_offset=fixture.PIN_IP_ROUND1, width=1, value=1)
    sequence = 0
    for index in range(rounds):
        if direction == CPU:
            output = immediate if index == 0 else immediate | 0x10
            status = 1 if index == 0 else 0x11
            q1 = 8 if index == 0 else 16
            cpu_bit = fixture.CPU_IRQ_CPU_ROUND1 if index == 0 else fixture.CPU_IRQ_CPU_ROUND2
            pin = fixture.PIN_CPU_ROUND1 if index == 0 else fixture.PIN_CPU_ROUND2
            data = (output & 0xFF) | (pin_value << fixture.PIN_DATA)
        else:
            output = immediate
            pin = fixture.PIN_IP_ROUND1 if index == 0 else fixture.PIN_IP_ROUND2
            status = 1 << pin
            q1 = 32 if index == 0 else 64
            cpu_bit = fixture.CPU_IRQ_IP_ROUND1 if index == 0 else fixture.CPU_IRQ_IP_ROUND2
            data = (1 << pin) | (pin_value << fixture.PIN_DATA) | (
                0 if index == 0 else output)
            if index == 1:
                add(kind='source_injection', action_id='second-rise',
                    component='gpio_b', port='gpio_in',
                    bit_offset=fixture.PIN_IP_ROUND2, width=1, value=1)
        if direction == CPU:
            sequence += 1
            add(kind='mmio_delivery', device_id='gpio_a',
                offset=fixture.DIRECT_OUT, write=True, write_value=output,
                source_transaction=_identity(sequence))
            add(component='gpio_a', outputs={'gpio_out': output})
            add(kind='dataflow_delivery', source=('gpio_a', 'gpio_out'),
                target=('gpio_b', 'gpio_in'), value=output & 0xFF,
                source_bit_offset=0, target_bit_offset=0)
        add(component='gpio_b', inputs={'gpio_in': data},
            outputs={'irq': status})
        add(kind='dataflow_delivery', source=('gpio_b', 'irq'),
            target=('cpu', 'irq'), value=1, source_bit_offset=pin,
            target_bit_offset=cpu_bit)
        add(component='cpu', inputs={'irq': 1 << cpu_bit}, outputs={})
        add(component='cpu', outputs={'eoi': q1})
        sequence += 1
        state = add(kind='mmio_delivery', device_id='gpio_b',
                    offset=fixture.INTR_STATE, write=False, read_value=status,
                    source_transaction=_identity(sequence))
        sequence += 1
        add(kind='mmio_delivery', device_id='gpio_b', offset=fixture.DATA_IN,
            write=False, read_value=data,
            source_transaction=_identity(sequence))
        add(component='cpu', outputs={'data_rsp_consumed': 1,
                                      'data_rsp_rdata': data,
                                      'data_rsp_source_epoch': 0,
                                      'data_rsp_source_sequence': sequence})
        add(kind='memory_write', component='cpu',
            address=fixture.RESULT_STATUS, value=status)
        add(kind='memory_write', component='cpu',
            address=fixture.RESULT_DATA, value=data)
        add(kind='memory_write', component='cpu',
            address=fixture.RESULT_Q1, value=q1)
        if direction == IP:
            sequence += 1
            add(kind='mmio_delivery', device_id='gpio_a',
                offset=fixture.DIRECT_OUT, write=True, write_value=output,
                source_transaction=_identity(sequence))
            add(component='gpio_a', outputs={'gpio_out': output})
        sequence += 1
        add(kind='mmio_delivery', device_id='gpio_b',
            offset=fixture.INTR_STATE, write=True, write_value=status,
            source_transaction=_identity(sequence))
        add(component='gpio_b', inputs={}, outputs={'irq': 0})
        add(kind='memory_write', component='cpu',
            address=fixture.RESULT_STATUS_AFTER, value=0)
        add(component='cpu', inputs={'irq': 0}, outputs={})
    return events


def _state():
    return {'inputs': {'cpu': {'irq': 0},
                       'gpio_b': {'gpio_in': 1 << fixture.PIN_DATA}},
            'pending_responses': {'cpu': 0, 'gpio_a': 0, 'gpio_b': 0}}


class ClosedChainCheckerTests(unittest.TestCase):
    def test_a_complete_two_round_stream_is_credited(self):
        for direction in (CPU, IP):
            stream = _canonical_stream(direction)
            assessment = assess_pico_wb_closed_chain(direction, stream, _state())
            self.assertIsNotNone(assessment)
            self.assertEqual((), tuple(assessment['findings']), direction)
            self.assertTrue(assessment['complete'], direction)
            self.assertEqual(2, assessment['rounds'], direction)
            self.assertEqual(fixture.source_immediate(direction),
                             assessment['cpu_immediate'], direction)
            self.assertEqual(1, assessment['external_pin_value'], direction)

    def test_every_required_stage_is_individually_required(self):
        def drop(predicate):
            stream = _canonical_stream(CPU)
            for event in [event for event in stream if predicate(event)]:
                stream.remove(event)
            return stream

        tampering = {
            'cpu_store_missing': lambda event: (
                event.get('kind') == 'mmio_delivery'
                and event.get('offset') == fixture.DIRECT_OUT
                and event.get('write') is True and event.get('write_value') == 5),
            'output_to_input_route_missing': lambda event: (
                event.get('kind') == 'dataflow_delivery'
                and tuple(event.get('source', ())) == ('gpio_a', 'gpio_out')),
            'gpio_irq_rise_missing': lambda event: (
                event.get('component') == 'gpio_b'
                and event.get('outputs', {}).get('irq') == 1),
            'irq_binding_missing': lambda event: (
                event.get('kind') == 'dataflow_delivery'
                and tuple(event.get('source', ())) == ('gpio_b', 'irq')),
            'intr_state_read_missing': lambda event: (
                event.get('kind') == 'mmio_delivery'
                and event.get('offset') == fixture.INTR_STATE
                and event.get('write') is False),
            'data_in_read_missing': lambda event: (
                event.get('kind') == 'mmio_delivery'
                and event.get('offset') == fixture.DATA_IN),
            'cpu_consume_data_missing': lambda event: (
                event.get('component') == 'cpu'
                and 'data_rsp_consumed' in event.get('outputs', {})),
            'ram_q1_missing': lambda event: (
                event.get('kind') == 'memory_write'
                and event.get('address') == fixture.RESULT_Q1),
            'w1c_missing': lambda event: (
                event.get('kind') == 'mmio_delivery'
                and event.get('offset') == fixture.INTR_STATE
                and event.get('write') is True),
            'ram_status_after_missing': lambda event: (
                event.get('kind') == 'memory_write'
                and event.get('address') == fixture.RESULT_STATUS_AFTER),
            'gpio_irq_fall_missing': lambda event: (
                event.get('component') == 'gpio_b'
                and event.get('outputs', {}).get('irq') == 0),
        }
        for expected, predicate in tampering.items():
            stream = drop(predicate)
            assessment = assess_pico_wb_closed_chain(CPU, stream, _state())
            findings = assessment['findings']
            self.assertTrue(
                any(finding == expected or finding.endswith(':' + expected)
                    for finding in findings),
                (expected, findings))
            self.assertFalse(assessment['complete'], expected)

    def test_a_program_outside_the_pinned_image_is_refused(self):
        program = bytearray(fixture.direction_program(CPU))
        program[4 * fixture.SOURCE_INSTRUCTION + 2] &= ~0x10   # immediate bit 0
        stream = _canonical_stream(CPU, program=bytes(program))
        assessment = assess_pico_wb_closed_chain(CPU, stream, _state())
        self.assertIn('cpu_program_immediate_outside_source',
                      assessment['findings'])
        foreign = bytearray(fixture.direction_program(CPU))
        foreign[0] = 0x00
        stream = _canonical_stream(CPU, program=bytes(foreign))
        assessment = assess_pico_wb_closed_chain(CPU, stream, _state())
        self.assertIn('cpu_program_image_differs', assessment['findings'])

    def test_a_reset_barrier_and_pending_responses_are_refused(self):
        stream = _canonical_stream(CPU)
        stream.append({'event_id': len(stream) + 1, 'kind': 'reset_barrier'})
        assessment = assess_pico_wb_closed_chain(CPU, stream, _state())
        self.assertIn('unexpected_reset', assessment['findings'])
        stream = _canonical_stream(CPU)
        state = _state()
        state['pending_responses'] = {'cpu': 1}
        assessment = assess_pico_wb_closed_chain(CPU, stream, state)
        self.assertIn('pending_responses_at_end', assessment['findings'])

    def test_a_single_round_and_a_reused_transaction_are_refused(self):
        stream = _canonical_stream(CPU, rounds=1)
        assessment = assess_pico_wb_closed_chain(CPU, stream, _state())
        self.assertIn('too_few_closed_rounds', assessment['findings'])
        stream = _canonical_stream(CPU)
        writes = [event for event in stream
                  if event.get('kind') == 'mmio_delivery'
                  and event.get('offset') == fixture.DIRECT_OUT]
        writes[1]['source_transaction'] = dict(writes[0]['source_transaction'])
        assessment = assess_pico_wb_closed_chain(CPU, stream, _state())
        self.assertIn('round_2:transaction_reused', assessment['findings'])

    def test_an_unknown_direction_is_not_assessed(self):
        self.assertIsNone(assess_pico_wb_closed_chain('CPU_TO_IP', [], {}))


# --------------------------------------------------------------------------
# provider guards: foreign seeds and tampered manifests are refused pre-RTL
# --------------------------------------------------------------------------
class ProviderGuardTests(unittest.TestCase):
    def provider(self):
        return PicoWbGpioBoundProvider()

    def test_an_ibex_or_cva6_seed_cannot_pose_as_the_pico_bound_seed(self):
        provider = self.provider()
        for direction in (CPU, IP):
            for foreign in (IBEX_SEED, CVA6_SEED):
                with self.assertRaises(CampaignBlocked):
                    provider._fixture(direction, foreign)

    def test_a_seed_with_another_shape_is_refused(self):
        provider = self.provider()
        seed = GenomeCodec.decode(BOUND.read_bytes())
        directory = Path(tempfile.mkdtemp(prefix='myfuzz-pico-wb-guard-'))
        try:
            tampered = replace(seed, max_steps=seed.max_steps + 2)
            path = directory / BOUND.name
            path.write_bytes(GenomeCodec.encode(tampered))
            with self.assertRaises(CampaignBlocked):
                provider._fixture(CPU, path)
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    def test_a_seed_with_another_program_is_refused(self):
        provider = self.provider()
        seed = GenomeCodec.decode(BOUND.read_bytes())
        image = seed.initial_images[0]
        data = bytearray(image.data)
        data[0] ^= 0x01
        directory = Path(tempfile.mkdtemp(prefix='myfuzz-pico-wb-guard-'))
        try:
            tampered = replace(seed, initial_images=(
                MemoryImage(image.image_id, image.component, image.address,
                            bytes(data).hex()),) + seed.initial_images[1:])
            path = directory / BOUND.name
            path.write_bytes(GenomeCodec.encode(tampered))
            with self.assertRaises(CampaignBlocked):
                provider._fixture(CPU, path)
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    def test_a_seed_without_the_pinned_actions_is_refused(self):
        provider = self.provider()
        reverse = GenomeCodec.decode(
            (ROOT / 'configs/scenario/pico_wb_two_gpio_reverse_seed.json')
            .read_bytes())
        directory = Path(tempfile.mkdtemp(prefix='myfuzz-pico-wb-guard-'))
        try:
            tampered = replace(reverse, actions=reverse.actions[:2])
            path = directory / provider.BOUND_REVERSE_SEED
            path.write_bytes(GenomeCodec.encode(tampered))
            with self.assertRaises(CampaignBlocked):
                provider._fixture(IP, directory / BOUND.name)
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    def test_a_tampered_independent_baseline_is_refused(self):
        provider = self.provider()
        directory = Path(tempfile.mkdtemp(prefix='myfuzz-pico-wb-baseline-'))
        try:
            for name in ('pico_wb_two_gpio_campaign_seed.json',
                         'pico_wb_two_gpio_reverse_seed.json',
                         'pico_wb_two_gpio_independent_cpu_seed.json',
                         'pico_wb_two_gpio_independent_ip_seed.json'):
                shutil.copy(ROOT / 'configs/scenario' / name, directory / name)
            document = json.loads(BASELINE.read_text())
            document['gpio_local_windows']['gpio_a_local']['size'] *= 2
            tampered = directory / BASELINE.name
            tampered.write_text(json.dumps(document, sort_keys=True))
            with self.assertRaises(CampaignBlocked):
                provider._independent_fixture(CPU, tampered)
            document = json.loads(BASELINE.read_text())
            document['cpu_irq'] = 'bound'
            tampered.write_text(json.dumps(document, sort_keys=True))
            with self.assertRaises(CampaignBlocked):
                provider._independent_fixture(IP, tampered)
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    def test_the_bound_seed_declares_both_sides_in_both_directions(self):
        provider = self.provider()
        for direction, manifest in (
                (CPU, BOUND),
                (IP, ROOT / 'configs/scenario/pico_wb_two_gpio_reverse_seed.json')):
            seed = GenomeCodec.decode(manifest.read_bytes())
            self.assertEqual(direction, seed.direction)
            self.assertEqual(('cpu', 'gpio_a', 'gpio_b'), seed.schedule_order)
            self.assertEqual(fixture.DIRECTION_SHAPES[direction],
                             (seed.max_steps, seed.quiesce_steps))
            self.assertEqual(tuple(fixture.bound_actions(direction)),
                             tuple(seed.actions))
            sources = provider._sources(direction)
            self.assertEqual({'cpu.program', 'b.pin9'},
                             {source.source_id for source in sources})
            self.assertEqual({source.source_id for source in sources},
                             {binding.source_id
                              for binding in provider._source_bindings().entries})
            targets = provider._targets(direction)
            self.assertEqual(1 + 3, len(targets))
            self.assertEqual({'gpio_a.out_bit_1', 'gpio_a.out_bit_2',
                              'gpio_a.out_bit_3'},
                             {target.target_id for target in targets[1:]})


# --------------------------------------------------------------------------
# the independent saved-run audit
# --------------------------------------------------------------------------
def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _canonical(document):
    return json.dumps(document, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


def _write_json(path, document):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + '\n')
    return path


def _receipt(record):
    """A compact but complete-enough live receipt for the audit."""
    return {
        'run_id': record['cell_id'], 'buffer_id': record['buffer_id'],
        'slot': 0, 'raw_sha256': 'aa' * 32,
        'genome_sha256': record['genome_sha256'],
        'effective_genome_sha256': record['effective_genome_sha256'],
        'semantic_sha256': 'bb' * 32, 'status': record['status'],
        'local_ticks': {'cpu': 100, 'gpio_a': 110, 'gpio_b': 120},
        'total_local_ticks': 330,
        'manifest_sha256': 'cc' * 32,
        'applied_sources': record['applied_sources'],
        'applied_source_ids': record['applied_source_ids'],
        'violations': [], 'error': None,
    }


def _synth_cell(run, cell_id, direction, strategy, *, seed_actions,
                independent=False):
    cell = run / cell_id
    live = cell / 'live'
    seed = fixture.bound_actions(direction) if not independent else \
        fixture.independent_actions(direction)
    genome = _synth_genome(cell_id, direction, seed_actions)
    seed_hash = hashlib.sha256(GenomeCodec.encode(genome)).hexdigest()
    mutated = _synth_genome(cell_id + '-mutated', direction, seed_actions)
    mutated_hash = hashlib.sha256(GenomeCodec.encode(mutated)).hexdigest()
    effective = hashlib.sha256(b'effective-' + mutated_hash.encode()).hexdigest()
    records = [dict(cell_id=cell_id, buffer_id=0, genome_sha256=seed_hash,
                    effective_genome_sha256=seed_hash, status='complete',
                    applied_sources=[], applied_source_ids=[])]
    if not independent:
        records += [dict(cell_id=cell_id, buffer_id=1, genome_sha256=mutated_hash,
                         effective_genome_sha256=effective, status='complete',
                         applied_sources=['cpu.program'],
                         applied_source_ids=['cpu.program']),
                    dict(cell_id=cell_id, buffer_id=2, genome_sha256=mutated_hash + '1',
                         effective_genome_sha256=effective + '1', status='complete',
                         applied_sources=['b.pin9'],
                         applied_source_ids=['b.pin9'])]
    live.mkdir(parents=True)
    (live / 'receipts.jsonl').write_text(''.join(
        json.dumps(_receipt(record), sort_keys=True) + '\n'
        for record in records))
    (live / 'corpus').mkdir()
    (live / 'corpus/entry_0000.json').write_text(json.dumps(
        {'entry': {'inputs': [0, 0, 0, 0, 0, 0, 0, 0]}}, sort_keys=True) + '\n')
    (cell / 'seed_genome.json').write_bytes(GenomeCodec.encode(genome) + b'\n')
    _write_json(live / 'decoder_manifest.json', {
        'schema_version': 'scenario_rfuzz_decoder.v2',
        'templates': [{'target_id': 'anchor',
                       'genome': json.loads(GenomeCodec.encode(genome))}]})
    checks = []
    if not independent:
        checks = [{'genome_sha256': record['genome_sha256'], 'status': 'complete',
                   'assessment': {'complete': True, 'rounds': 2, 'findings': []}}
                  for record in records[1:]]
    (cell / 'chain_checks.jsonl').write_text(''.join(
        json.dumps(check, sort_keys=True) + '\n' for check in checks))
    ticks = {}
    for record in records:
        for component, value in _receipt(record)['local_ticks'].items():
            ticks[component] = ticks.get(component, 0) + value
    statuses = {}
    for record in records:
        statuses[record['status']] = statuses.get(record['status'], 0) + 1
    from myfuzz.integration.scenario_campaign import (
        _post_seed_completed_causal_chains, _post_seed_effective_genotypes,
        _post_seed_real_mutation_batches)
    import types
    rows = [types.SimpleNamespace(**_receipt(record)) for record in records]
    search = {
        'status': 'ok', 'effective_search_seconds': 61.0,
        'seed_status': 'supported', 'testcases': len(records),
        'local_cycles': ticks, 'valid_testcases': len(records),
        'completed_chains': len(checks), 'coverage_count': 1,
        'failures': statuses, 'saved_corpus_entries': 1, 'error': None,
        'client_binary_sha256': 'dd' * 32,
        'applied_source_uses': {'cpu.program': 1, 'b.pin9': 1},
        'post_seed_mutation_batches': _post_seed_real_mutation_batches(rows),
        'post_seed_effective_genotypes': len(_post_seed_effective_genotypes(rows)),
        'post_seed_completed_chains': _post_seed_completed_causal_chains(rows, checks),
    }
    replay = {'total_entries': 1, 'matched_entries': 1,
              'failure_entries': 0, 'matched_failure_entries': 0, 'error': None}
    body = {'schema_version': 'scenario_fresh_run_identity.v1',
            'run_config': {'run_id': cell_id},
            'artifacts': {'receipts.jsonl': _sha256(live / 'receipts.jsonl'),
                          'decoder_manifest.json': _sha256(
                              live / 'decoder_manifest.json')}}
    digest = hashlib.sha256(_canonical(body)).hexdigest()
    _write_json(live / 'run_identity.json', {
        'schema_version': 'scenario_fresh_run_identity_envelope.v1',
        'sha256': digest, 'identity': body})
    _write_json(live / 'report.json', {'run_identity_sha256': digest,
                                       'status': 'complete'})
    return {'cell_id': cell_id, 'strategy': strategy, 'direction': direction,
            'seed': 20260927, 'status': 'complete', 'gate_failures': [],
            'search': search, 'replay': replay,
            'cost': {'effective_search_seconds': 61.0},
            'manifest': str(BOUND), 'saved_manifest': 'inputs/bound/x.json'}


def _synth_genome(cell_id, direction, actions):
    return fixture_bound_genome(cell_id, direction, actions)


def fixture_bound_genome(cell_id, direction, actions):
    from myfuzz.scenario.genome import ScenarioGenome
    return ScenarioGenome(
        testcase_id=cell_id, direction=direction,
        path_id=f'path-{direction.lower()}',
        schedule_order=('cpu', 'gpio_a', 'gpio_b'), encoding_version=3,
        max_steps=fixture.DIRECTION_SHAPES[direction][0],
        quiesce_steps=fixture.DIRECTION_SHAPES[direction][1],
        actions=tuple(actions),
        initial_images=(
            MemoryImage('cpu.program', 'cpu', 0,
                        fixture.program_hex(direction)),
            MemoryImage('cpu.result', 'cpu', fixture.RESULT, bytes(24).hex())))


def _synth_campaign(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    cells = []
    for strategy in ('dependency_guided', 'uniform_source', 'independent_drive'):
        for direction in (CPU, IP):
            for seed in (20260927, 20260928, 20260929):
                cell_id = f'{strategy}__{direction}__seed_{seed}'
                cells.append(_synth_cell(
                    directory, cell_id, direction, strategy,
                    seed_actions=(fixture.independent_actions(direction)
                                  if strategy == 'independent_drive'
                                  else fixture.bound_actions(direction)),
                    independent=strategy == 'independent_drive'))
    coverage = {}
    for strategy in ('dependency_guided', 'uniform_source'):
        for direction in (CPU, IP):
            coverage[f'{strategy}__{direction}'] = {
                'declared': ['b.pin9', 'cpu.program'],
                'executed': ['b.pin9', 'cpu.program'], 'measured': True}
    effective = sum(cell['cost']['effective_search_seconds'] for cell in cells)
    associations = [{'cell_id': cell['cell_id'],
                     'execution_identity_status': 'available',
                     'auxiliary_artifacts': {
                         cell['cell_id'] + '/chain_checks.jsonl':
                             _sha256(directory / cell['cell_id']
                                     / 'chain_checks.jsonl')}}
                    for cell in cells]
    body = {'schema_version': 'scenario_campaign_run_identity.v1',
            'inputs': {}, 'input_stability': {}, 'campaign_sources': {},
            'configuration': {}, 'cells': associations}
    digest = hashlib.sha256(_canonical(body)).hexdigest()
    _write_json(directory / 'campaign_run_identity.json', {
        'schema_version': 'scenario_campaign_run_identity_envelope.v1',
        'sha256': digest, 'identity': body})
    report = {
        'schema_version': 'scenario_campaign.v1', 'gate': 'G4',
        'gate_status': 'complete', 'required_cells': 18,
        'required_effective_search_seconds': 1080.0,
        'effective_search_seconds': effective,
        'campaign_source_identity_stable': True,
        'campaign_input_stability': {'originals_stable': True,
                                     'snapshots_stable': True,
                                     'files': [{'relative_path': 'x'}]},
        'campaign_run_identity_sha256': digest,
        'actual_source_coverage': coverage, 'cells': cells,
    }
    _write_json(directory / 'campaign_report.json', report)
    return directory


class SavedRunAuditTests(unittest.TestCase):
    """The audit is exercised on a labelled synthetic bundle, then on real data."""

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp(prefix='myfuzz-pico-wb-audit-'))
        self.run = _synth_campaign(self.directory / 'run')

    def tearDown(self):
        shutil.rmtree(self.directory, ignore_errors=True)

    def _report(self):
        return json.loads((self.run / 'campaign_report.json').read_text())

    def _write_report(self, report):
        _write_json(self.run / 'campaign_report.json', report)

    def test_the_audit_recomputes_a_complete_bundle(self):
        facts = audit_campaign_run(self.run)
        self.assertEqual(18, facts['cell_count'])
        # 12 bound cells (three receipts -> two chain checks each) and six
        # independent cells (one receipt, no chain claim).
        self.assertEqual(12 * 3 + 6 * 1, facts['testcases'])
        self.assertEqual(12 * 2, facts['completed_chains'])
        self.assertEqual(18, facts['corpus_entries'])
        report = self._report()
        self.assertAlmostEqual(report['effective_search_seconds'],
                               facts['effective_search_seconds'])

    def test_the_audit_rejects_a_failed_gate_and_bad_coverage(self):
        report = self._report()
        report['gate_status'] = 'incomplete'
        self._write_report(report)
        with self.assertRaises(AssertionError):
            audit_campaign_run(self.run)
        report = self._report()
        report['gate_status'] = 'complete'
        report['actual_source_coverage'][
            'dependency_guided__CPU_TO_IP_TO_CPU']['executed'] = ['cpu.program']
        self._write_report(report)
        with self.assertRaises(AssertionError):
            audit_campaign_run(self.run)

    def test_the_audit_recomputes_chain_checks_corpus_and_seed(self):
        cell_id = 'dependency_guided__CPU_TO_IP_TO_CPU__seed_20260927'
        cell = self.run / cell_id
        # A chain check without two complete rounds is not evidence.
        checks = [json.loads(line) for line in
                  (cell / 'chain_checks.jsonl').read_text().splitlines()]
        checks[0]['assessment']['rounds'] = 1
        (cell / 'chain_checks.jsonl').write_text(''.join(
            json.dumps(check, sort_keys=True) + '\n' for check in checks))
        with self.assertRaises(AssertionError):
            audit_campaign_run(self.run)
        # A corpus entry the report does not account for is a mismatch.
        checks[0]['assessment']['rounds'] = 2
        (cell / 'chain_checks.jsonl').write_text(''.join(
            json.dumps(check, sort_keys=True) + '\n' for check in checks))
        audit_campaign_run(self.run)
        (cell / 'live/corpus/entry_0001.json').write_text(
            json.dumps({'entry': {'inputs': [0]}}, sort_keys=True) + '\n')
        with self.assertRaises(AssertionError):
            audit_campaign_run(self.run)
        (cell / 'live/corpus/entry_0001.json').unlink()
        # A saved seed that is not this direction's pinned action table is a
        # foreign source identity, not a valid seed.
        seed = GenomeCodec.decode((cell / 'seed_genome.json').read_bytes())
        (cell / 'seed_genome.json').write_bytes(GenomeCodec.encode(
            replace(seed, actions=fixture.bound_actions(IP))) + b'\n')
        with self.assertRaises(AssertionError):
            audit_campaign_run(self.run)

    def test_the_audit_rejects_a_tampered_identity_envelope(self):
        envelope = json.loads(
            (self.run / 'campaign_run_identity.json').read_text())
        envelope['identity']['cells'][0]['execution_identity_status'] = 'invalid'
        digest = hashlib.sha256(_canonical(envelope['identity'])).hexdigest()
        envelope['sha256'] = digest
        _write_json(self.run / 'campaign_run_identity.json', envelope)
        report = self._report()
        report['campaign_run_identity_sha256'] = digest
        self._write_report(report)
        with self.assertRaises(AssertionError):
            audit_campaign_run(self.run)

    @unittest.skipUnless(REAL_RUN.is_dir(),
                         'the real 18-cell P6 row-4 campaign bundle is not present')
    def test_the_real_campaign_bundle_recomputes(self):
        facts = audit_campaign_run(REAL_RUN)
        self.assertEqual(18, facts['cell_count'])
        self.assertGreaterEqual(facts['effective_search_seconds'], 1080.0)


# --------------------------------------------------------------------------
# one real RTL case per direction (opt-in: builds both pinned harnesses)
# --------------------------------------------------------------------------
@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned Pico and GPIO RTL')
class RealCaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = Path(tempfile.mkdtemp(prefix='myfuzz-pico-wb-real-'))
        cls.pair = fixture.PicoWbTwoGpioPair(cache_dir=cls.directory / 'cache')

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.directory, ignore_errors=True)

    def run_direction(self, direction):
        from myfuzz.local_harness.build import host_source_discovery_scope
        from myfuzz.scenario.genome import ScenarioGenome
        from myfuzz.scenario.replay import record_scenario

        seed = GenomeCodec.decode(
            (BOUND if direction == CPU else
             ROOT / 'configs/scenario/pico_wb_two_gpio_reverse_seed.json'
             ).read_bytes())
        holder = {}

        def factory():
            runner = self.pair.runner()
            holder['runner'] = runner
            return runner

        with host_source_discovery_scope():
            trace = record_scenario(seed, factory)
        assessment = assess_pico_wb_closed_chain(
            direction, trace.events, holder['runner'].final_state_document())
        self.assertEqual('complete', trace.status, trace.events[-4:])
        self.assertTrue(assessment['complete'], assessment['findings'])
        self.assertEqual(2, assessment['rounds'])
        self.assertEqual(fixture.source_immediate(direction),
                         assessment['cpu_immediate'])
        return trace, assessment

    def test_a_real_cpu_initiated_two_round_case_closes_the_chain(self):
        self.run_direction(CPU)

    def test_a_real_ip_initiated_two_round_case_closes_the_chain(self):
        # The second round needs a longer pinned budget than the CPU direction
        # (two external edges plus the handler's extra output store).
        self.run_direction(IP)


if __name__ == '__main__':
    unittest.main()
