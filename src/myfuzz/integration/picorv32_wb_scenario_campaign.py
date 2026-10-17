"""P6 row-4 (classic Wishbone) campaign: real PicoRV32 WB x two real GPIO.

``docs/superpowers/plans/2026-10-13-p6-per-protocol-row-checklist.md`` row 4
records three missing pieces for the classic-Wishbone row: a scenario-layer
fixture, a ``CampaignProvider``, and a closed checker that preserves the Pico
custom0 IRQ ABI (``getq``/``maskirq``/``retirq``, not machine-mode CSRs) together
with the two bound/independent manifests.  ``scenario/picorv32_wb_two_gpio_example``
supplies the first; this module supplies the other two.

Why this pair
-------------
The pinned CPU is ``configs/cpus/picorv32_wb_irq`` (``ENABLE_IRQ=1``) and the
pinned IP is ``configs/peripherals/opentitan_gpio_local`` twice.  The directed
acceptance test (``tests/integration/test_scenario_picorv32_wb_opentitan_gpio_irq_real.py``)
already proves the real custom0 IRQ chain for a single GPIO; this module runs
that same shape as a *two-round, two-sided, per-testcase* search over the real
RTL.  Nothing here names a component in the runner, router or mutator: the two
fuzzable sources are a memory-image bit range and a declared external pin, both
supplied through the ordinary dependency graph.

What each direction claims
--------------------------
* ``CPU_TO_IP_TO_CPU`` - the CPU initiates.  Its real MMIO store to ``gpio_a``
  DIRECT_OUT is the first observation; the store value comes from the mutable
  program immediate.  The real ``gpio_a`` output pins reach ``gpio_b``'s input
  pins through the declared binding, ``gpio_b`` raises a real interrupt, the CPU
  takes a real custom0 trap, reads ``gpio_b``'s state and ``DATA_IN`` (which also
  carries the fuzzed external pin), writes both to RAM, clears with W1C, and the
  interrupt falls.  Round 2 repeats on a second GPIO interrupt pin.
* ``IP_TO_CPU_TO_IP`` - the IP initiates.  A declared external pin source raises
  ``gpio_b``'s pin, the real interrupt reaches the CPU, the trap's handler reads
  state and ``DATA_IN``, drives ``gpio_a``'s real output pins with the CPU
  program's pinned constant (the CPU-side fuzzable source), writes both values
  to RAM and clears with W1C.  Round 2 is a second real external pin edge.

Both directions therefore fuzz a CPU program-image immediate *and* a GPIO
external-pin source, and the checker only credits a round when every stage was
observed with its own event identity, in causal order.

Honesty notes
-------------
* ``DATA_IN`` is declared by the pinned GPIO profile as a read-only register that
  exposes the sampled input pins, so the checker's expected ``DATA_IN`` is
  stated from observed CPU stores / declared source injections and the profile's
  own register semantics - never from a value the DUT was asked to produce.
* The CPU program image itself appears in the trace as the runtime's own
  ``initial_image`` event; the checker decodes the mutable immediate from that
  real event and requires the A-output store of the IP direction to equal it.
* One round per direction is one real edge.  A second edge on the *same* GPIO
  interrupt pin is not available on this pinned core (``LATCHED_IRQ`` is all
  ones and a pending bit is only cleared by the masked deassert), so the fixture
  uses a second real pin and a second CPU IRQ bit instead of pretending.
"""
from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
from typing import Mapping

from myfuzz.scenario import picorv32_wb_two_gpio_example as fixture
from myfuzz.scenario.dependency import (DependencyGraph, DependencyRule,
                                        FuzzableSource, SourceBinding,
                                        SourceBindings)
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.genome import GenomeCodec
from myfuzz.scenario.rfuzz_decoder import DecoderTemplate, GenomeRecordDecoder

from .scenario_campaign import (CampaignBlocked, IbexTwoGpioBoundProvider,
                                _require_pinned_bound_seed)

CPU = 'CPU_TO_IP_TO_CPU'
IP = 'IP_TO_CPU_TO_IP'
DIRECTIONS = (CPU, IP)

ROOT = Path(__file__).resolve().parents[3]

#: The one byte that carries the mutable three-bit immediate field.
SOURCE_BYTE = 4 * fixture.SOURCE_INSTRUCTION + 2
SOURCE_BYTE_MASK = 0xE0
#: Effective IRQ vectors each round must produce on ``gpio_b``.
CPU_ROUND_VECTORS = (1 << fixture.PIN_CPU_ROUND1, 1 << fixture.PIN_CPU_ROUND2)
IP_ROUND_VECTORS = (1 << fixture.PIN_IP_ROUND1, 1 << fixture.PIN_IP_ROUND2)
CPU_ROUND_IRQ_BITS = (1 << fixture.CPU_IRQ_CPU_ROUND1,
                      1 << fixture.CPU_IRQ_CPU_ROUND2)
IP_ROUND_IRQ_BITS = (1 << fixture.CPU_IRQ_IP_ROUND1,
                    1 << fixture.CPU_IRQ_IP_ROUND2)
#: ``DATA_IN`` makes the low byte the CPU-driven pins.  CPU direction rounds
#: write V then V | (1 << PIN_CPU_ROUND2); the IP direction's handler writes the
#: program constant and the external pins sit at PIN_DATA / PIN_IP_ROUND*.
CPU_ROUND2_OUTPUT = 1 << fixture.PIN_CPU_ROUND2



def _transaction_identity(event: Mapping) -> tuple:
    transaction = event.get('source_transaction', event.get('transaction', {}))
    if not isinstance(transaction, Mapping):
        return ()
    return tuple(transaction.get(key) for key in (
        'execution_id', 'testcase_id', 'source_component', 'source_epoch',
        'channel_id', 'source_sequence'))


def _initial_image(stream, component: str, image_id: str) -> bytes | None:
    """The genome's own initial image, as the runtime reported loading it."""
    for event in stream:
        if (event.get('kind') == 'initial_image'
                and event.get('component') == component
                and event.get('image_id') == image_id):
            data = event.get('data_hex')
            if not isinstance(data, str):
                return None
            try:
                return bytes.fromhex(data)
            except ValueError:
                return None
    return None


def _program_immediate(image: bytes) -> int | None:
    offset = 4 * fixture.SOURCE_INSTRUCTION
    if len(image) < offset + 4:
        return None
    word = int.from_bytes(image[offset:offset + 4], 'little')
    if word & 0x7F != 0x13:
        return None
    return (word >> 20) & 0xFFF


def program_image_matches(image: bytes, direction: str) -> bool:
    """The image may differ from the pinned program only in the source bits."""
    pinned = fixture.direction_program(direction)
    if len(image) != len(pinned):
        return False
    for index, (actual, expected) in enumerate(zip(image, pinned)):
        if index == SOURCE_BYTE:
            if (actual & 0x1F) != (expected & 0x1F):
                return False
        elif actual != expected:
            return False
    return True


def _expected_immediate(direction: str, immediate: int) -> bool:
    """Every mutated genotype must keep the chain's two guard bits intact."""
    if direction == CPU:
        return (immediate & 0x1 == 1) and (immediate & 0x10 == 0) and immediate < 0x100
    return (immediate & 0x11 == 0) and immediate < 0x100


def _find(stream, after: int, predicate):
    return next((event for event in stream
                 if type(event.get('event_id')) is int
                 and event['event_id'] > after and predicate(event)), None)


def _is_mmio(event, *, device: str, offset: int, write: bool) -> bool:
    return (event.get('kind') == 'mmio_delivery'
            and event.get('device_id') == device
            and event.get('offset') == offset
            and event.get('write') is write)


def _irq_steps(stream, component: str) -> tuple:
    return tuple(event for event in stream
                 if event.get('component') == component
                 and 'irq' in event.get('outputs', {})
                 and type(event.get('outputs', {}).get('irq')) is int)


def _pin_edges(steps, bit: int) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Real rising and falling edges of one interrupt pin's pending bit.

    The GPIO's interrupt vector can assert several enabled pins over more than
    one local tick (each pad goes through the IP's own input synchronizer), so a
    round's edge is the edge of *its* pin, not a whole-vector equality.
    """
    rises, falls = [], []
    previous = 0
    for event in steps:
        value = (event['outputs']['irq'] >> bit) & 1
        if value and not previous:
            rises.append(event['event_id'])
        if previous and not value:
            falls.append(event['event_id'])
        previous = value
    return tuple(rises), tuple(falls)


def _round_expectations(direction: str, immediate: int,
                        pin_value: int) -> tuple[dict, ...]:
    """Expected per-round observations, from declared sources only."""
    if direction == CPU:
        values = (immediate, immediate | CPU_ROUND2_OUTPUT)
        return tuple({
            'output': value,
            'status': (1 << fixture.PIN_CPU_ROUND1) if index == 0 else
                      ((1 << fixture.PIN_CPU_ROUND1) | (1 << fixture.PIN_CPU_ROUND2)),
            'data': (value & 0xFF) | (pin_value << fixture.PIN_DATA),
            'q1': 1 << (fixture.CPU_IRQ_CPU_ROUND1 if index == 0
                        else fixture.CPU_IRQ_CPU_ROUND2),
            'irq_bit': (1 << fixture.CPU_IRQ_CPU_ROUND1 if index == 0
                        else 1 << fixture.CPU_IRQ_CPU_ROUND2),
            'vector': CPU_ROUND_VECTORS[index],
            'pin': (fixture.PIN_CPU_ROUND1 if index == 0 else
                    fixture.PIN_CPU_ROUND2),
            'injection': None,
            'a_write': None,
        } for index, value in enumerate(values))
    first_pin = (fixture.PIN_IP_ROUND1, fixture.PIN_IP_ROUND2)
    return tuple({
        'output': immediate,
        'status': 1 << first_pin[index],
        'data': (1 << first_pin[index]) | (pin_value << fixture.PIN_DATA)
                | (0 if index == 0 else immediate),
        'q1': 1 << (fixture.CPU_IRQ_IP_ROUND1 if index == 0
                    else fixture.CPU_IRQ_IP_ROUND2),
        'irq_bit': (1 << fixture.CPU_IRQ_IP_ROUND1 if index == 0
                    else 1 << fixture.CPU_IRQ_IP_ROUND2),
        'vector': IP_ROUND_VECTORS[index],
        'pin': first_pin[index],
        'injection': 1,
        'a_write': immediate,
    } for index in range(2))


def assess_pico_wb_closed_chain(direction: str, events,
                                final_state: Mapping) -> dict | None:
    """Two ordered, real, custom0-mediated rounds over the pinned RTL.

    Every stage is an observation copied out of the runner's event stream;
    nothing is inferred from a schedule.  ``expected`` values come from observed
    CPU stores, declared source injections and the runtime's own initial-image
    event, never from a value the environment was told to return.

    The handler's real order is the order below: the two reads, the RAM stores
    of the read values and of ``q1``, (in the IP direction) the output store the
    handler drives, the W1C, the real GPIO interrupt fall, the post-clear status
    read committed to RAM, and finally the CPU's own IRQ input returning low.
    """
    if direction not in DIRECTIONS:
        return None
    stream = tuple(events)
    findings: list[str] = []
    identifiers = [event.get('event_id') for event in stream]
    if any(type(item) is not int for item in identifiers) \
            or identifiers != sorted(set(identifiers)):
        findings.append('event_ids_not_strictly_ordered')
    if any(event.get('kind') == 'reset_barrier' for event in stream):
        findings.append('unexpected_reset')
    if any(event.get('kind') in ('harness_failure', 'budget_exhausted')
           for event in stream):
        findings.append('harness_failure_present')
    image = _initial_image(stream, fixture.CPU_COMPONENT, fixture.PROGRAM_IMAGE)
    immediate = _program_immediate(image) if image is not None else None
    if immediate is None:
        findings.append('cpu_program_image_missing')
        return {'complete': False, 'rounds': 0, 'findings': findings}
    if not _expected_immediate(direction, immediate):
        findings.append('cpu_program_immediate_outside_source')
        return {'complete': False, 'rounds': 0, 'findings': findings}
    if not program_image_matches(image, direction):
        findings.append('cpu_program_image_differs')
        return {'complete': False, 'rounds': 0, 'findings': findings}

    data_injections = [event for event in stream
                       if event.get('kind') == 'source_injection'
                       and event.get('component') == fixture.GPIO_B_COMPONENT
                       and event.get('port') == 'gpio_in'
                       and event.get('action_id') == 'data-pin']
    if len(data_injections) != 1:
        findings.append('external_data_pin_injection_not_unique')
        return {'complete': False, 'rounds': 0, 'findings': findings}
    data_injection = data_injections[0]
    if (data_injection.get('bit_offset') != fixture.PIN_DATA
            or data_injection.get('width') != 1
            or type(data_injection.get('value')) is not int
            or data_injection['value'] not in (0, 1)):
        findings.append('external_data_pin_injection_invalid')
        return {'complete': False, 'rounds': 0, 'findings': findings}
    pin_value = data_injection['value']
    expected_rounds = _round_expectations(direction, immediate, pin_value)

    irq_steps = _irq_steps(stream, fixture.GPIO_B_COMPONENT)
    edges = {pin: _pin_edges(irq_steps, pin)
             for pin in (fixture.PIN_CPU_ROUND1, fixture.PIN_CPU_ROUND2,
                         fixture.PIN_IP_ROUND1, fixture.PIN_IP_ROUND2)}

    rounds = 0
    used_transactions: set[tuple] = set()
    round_beginnings: list[int] = []
    round_ends: list[int] = []
    cursor = 0
    for index, expected in enumerate(expected_rounds):
        label = f'round_{index + 1}'
        stages: list[tuple[str, Mapping]] = []

        def take(name, predicate):
            nonlocal cursor
            event = _find(stream, cursor, predicate)
            if event is None:
                findings.append(f'{label}:{name}_missing')
                return None
            cursor = event['event_id']
            stages.append((name, event))
            return event

        if direction == CPU:
            beginning = take('cpu_store', lambda event: _is_mmio(
                event, device=fixture.GPIO_A_COMPONENT,
                offset=fixture.DIRECT_OUT, write=True)
                and event.get('write_value') == expected['output'])
        else:
            beginning = take('external_pin_edge', lambda event:
                             event.get('kind') == 'source_injection'
                             and event.get('component') == fixture.GPIO_B_COMPONENT
                             and event.get('port') == 'gpio_in'
                             and event.get('bit_offset') == expected['pin']
                             and event.get('value') == expected['injection']
                             and event.get('event_id')
                             != data_injection['event_id'])
        if beginning is None:
            break
        round_beginnings.append(beginning['event_id'])

        if direction == CPU:
            # The CPU's own store is the initiating observation, so its output
            # pins are observed before the routed input.
            if take('cpu_output_store_not_observed', lambda event:
                    event.get('component') == fixture.GPIO_A_COMPONENT
                    and event.get('outputs', {}).get('gpio_out')
                    == expected['output']) is None:
                break
            # The runner routes each *sampled* output, so the delivery's
            # producer is a local tick sample rather than the summary step.
            # The delivery is pinned to this route, this value and the first
            # occurrence after the CPU's own observed output instead.
            if take('output_to_input_route', lambda event:
                    event.get('kind') == 'dataflow_delivery'
                    and tuple(event.get('source', ()))
                    == (fixture.GPIO_A_COMPONENT, 'gpio_out')
                    and tuple(event.get('target', ()))
                    == (fixture.GPIO_B_COMPONENT, 'gpio_in')
                    and event.get('source_bit_offset') == 0
                    and event.get('target_bit_offset') == 0
                    and event.get('value') == expected['output'] & 0xFF) is None:
                break

        b_rise = take('gpio_irq_rise', lambda event:
                      event.get('event_id') in edges[expected['pin']][0]
                      and event.get('inputs', {}).get('gpio_in', -1)
                      == expected['data'])
        if b_rise is None:
            break

        cpu_irq_bit = (fixture.CPU_IRQ_CPU_ROUND1 if direction == CPU and index == 0
                       else fixture.CPU_IRQ_CPU_ROUND2 if direction == CPU
                       else fixture.CPU_IRQ_IP_ROUND1 if index == 0
                       else fixture.CPU_IRQ_IP_ROUND2)
        if take('irq_binding', lambda event:
                event.get('kind') == 'dataflow_delivery'
                and tuple(event.get('source', ()))
                == (fixture.GPIO_B_COMPONENT, 'irq')
                and tuple(event.get('target', ()))
                == (fixture.CPU_COMPONENT, 'irq')
                and event.get('value') == 1
                and event.get('source_bit_offset') == expected['pin']
                and event.get('target_bit_offset') == cpu_irq_bit) is None:
            break

        if take('cpu_irq_input', lambda event:
                event.get('component') == fixture.CPU_COMPONENT
                and 'outputs' in event
                and event.get('inputs', {}).get('irq', 0)
                & expected['irq_bit']) is None:
            break

        if take('custom0_eoi', lambda event:
                event.get('component') == fixture.CPU_COMPONENT
                and event.get('outputs', {}).get('eoi') == expected['q1']) is None:
            break

        if take('intr_state_read', lambda event: _is_mmio(
                event, device=fixture.GPIO_B_COMPONENT,
                offset=fixture.INTR_STATE, write=False)
                and event.get('read_value') == expected['status']) is None:
            break

        data = take('data_in_read', lambda event: _is_mmio(
            event, device=fixture.GPIO_B_COMPONENT,
            offset=fixture.DATA_IN, write=False)
            and event.get('read_value') == expected['data'])
        if data is None:
            break

        transaction = data.get('source_transaction', {})
        if take('cpu_consume_data', lambda event:
                event.get('component') == fixture.CPU_COMPONENT
                and event.get('outputs', {}).get('data_rsp_consumed') == 1
                and event['outputs'].get('data_rsp_rdata') == expected['data']
                and event['outputs'].get('data_rsp_source_epoch')
                == transaction.get('source_epoch')
                and event['outputs'].get('data_rsp_source_sequence')
                == transaction.get('source_sequence')) is None:
            break

        for offset, name, wanted in (
                (0, 'ram_status', expected['status']),
                (4, 'ram_data', expected['data']),
                (8, 'ram_q1', expected['q1'])):
            if take(name, lambda event, offset=offset, wanted=wanted:
                    event.get('kind') == 'memory_write'
                    and event.get('component') == fixture.CPU_COMPONENT
                    and event.get('address') == fixture.RESULT + offset
                    and event.get('value') == wanted) is None:
                break
        else:
            if direction == IP:
                if take('isr_output_store', lambda event: _is_mmio(
                        event, device=fixture.GPIO_A_COMPONENT,
                        offset=fixture.DIRECT_OUT, write=True)
                        and event.get('write_value') == expected['a_write']) is None:
                    break
                if take('isr_output_not_observed', lambda event:
                        event.get('component') == fixture.GPIO_A_COMPONENT
                        and event.get('outputs', {}).get('gpio_out')
                        == expected['a_write']) is None:
                    break

            if take('w1c', lambda event: _is_mmio(
                    event, device=fixture.GPIO_B_COMPONENT,
                    offset=fixture.INTR_STATE, write=True)
                    and event.get('write_value') == expected['status']) is None:
                break

            if take('gpio_irq_fall', lambda event:
                    event.get('event_id') in edges[expected['pin']][1]) is None:
                break

            if take('ram_status_after', lambda event:
                    event.get('kind') == 'memory_write'
                    and event.get('component') == fixture.CPU_COMPONENT
                    and event.get('address') == fixture.RESULT + 12
                    and event.get('value') == 0) is None:
                break

            if take('cpu_irq_not_low', lambda event:
                    event.get('component') == fixture.CPU_COMPONENT
                    and 'outputs' in event
                    and not event.get('inputs', {}).get('irq', 0)) is None:
                break

            for name, event in stages:
                if name not in ('cpu_store', 'intr_state_read', 'data_in_read',
                                'w1c', 'isr_output_store'):
                    continue
                identity = _transaction_identity(event)
                if not identity or any(item is None for item in identity):
                    findings.append(f'{label}:transaction_identity_missing')
                elif identity in used_transactions:
                    findings.append(f'{label}:transaction_reused')
                used_transactions.add(identity)
            rounds += 1
            round_ends.append(cursor)
            continue
        break

    if rounds < 2:
        findings.append('too_few_closed_rounds')
    if len(round_beginnings) >= 2 and round_ends \
            and round_ends[0] >= round_beginnings[1]:
        findings.append('rounds_overlap')
    pending = final_state.get('pending_responses', {})
    if not isinstance(pending, Mapping) or any(value != 0
                                               for value in pending.values()):
        findings.append('pending_responses_at_end')
    inputs = final_state.get('inputs', {})
    if not isinstance(inputs, Mapping) \
            or inputs.get(fixture.CPU_COMPONENT, {}).get('irq') != 0:
        findings.append('cpu_irq_high_at_end')
    if not irq_steps or irq_steps[-1]['outputs']['irq'] != 0:
        findings.append('gpio_irq_high_at_end')
    return {'complete': not findings, 'rounds': rounds,
            'findings': findings, 'cpu_immediate': immediate,
            'external_pin_value': pin_value}


class PicoWbGpioBoundProvider(IbexTwoGpioBoundProvider):
    """Three strategies over one real Pico Wishbone CPU and two real GPIO RTLs."""

    requires_execution_identity = True

    BOUND_REVERSE_SEED = 'pico_wb_two_gpio_reverse_seed.json'

    #: Pinned shape of this provider's CPU-direction seed genome.
    BOUND_SEED_SHAPE = fixture.DIRECTION_SHAPES[CPU]

    #: Every direction pins the sha256 of the program image its seed declares.
    PROGRAM_SHA256 = {direction: fixture.program_digest(direction)
                      for direction in DIRECTIONS}

    def __init__(self, client_binary: Path | None = None) -> None:
        super().__init__(client_binary)
        #: One Verilator build cache for every cell of one campaign.
        self._build_cache = Path(tempfile.mkdtemp(prefix='myfuzz-pico-wb-campaign-'))
        self._bound_pair = None
        self._independent_pair = None

    # -- admitted pairs ----------------------------------------------------
    def _bound(self):
        if self._bound_pair is None:
            self._bound_pair = fixture.PicoWbTwoGpioPair(
                base_dir=ROOT, cache_dir=self._build_cache)
        return self._bound_pair

    def _independent(self):
        if self._independent_pair is None:
            self._independent_pair = fixture.PicoWbTwoGpioPair(
                base_dir=ROOT, cache_dir=self._build_cache,
                independent_baseline=True)
        return self._independent_pair

    def search(self, cell, output, manifest):
        """Reuse the code-owned host closure across every cell of the campaign."""
        from myfuzz.local_harness.build import host_source_discovery_scope

        with host_source_discovery_scope():
            return super().search(cell, output, manifest)

    def replay(self, cell, output, manifest):
        from myfuzz.local_harness.build import host_source_discovery_scope

        with host_source_discovery_scope():
            return super().replay(cell, output, manifest)

    @staticmethod
    def _assess_trace_chain(direction, events, final_state):
        return assess_pico_wb_closed_chain(direction, events, final_state)

    # -- declared sources and pin-level targets ----------------------------
    @staticmethod
    def _sources(direction):
        return (
            FuzzableSource(fixture.CPU_SOURCE_ID, fixture.CPU_COMPONENT,
                           fixture.PROGRAM_IMAGE, fixture.SOURCE_BIT_OFFSET,
                           fixture.SOURCE_WIDTH, (direction,), 'memory_image'),
            FuzzableSource(fixture.IP_SOURCE_ID, fixture.GPIO_B_COMPONENT,
                           'gpio_in', fixture.PIN_DATA, 1, (direction,)),
        )

    @staticmethod
    def _source_bindings():
        return SourceBindings((
            SourceBinding(fixture.CPU_SOURCE_ID, 'memory_image',
                          fixture.CPU_COMPONENT, fixture.PROGRAM_IMAGE,
                          fixture.SOURCE_BIT_OFFSET, fixture.SOURCE_WIDTH,
                          'initial_image:cpu:cpu.program', 0),
            SourceBinding(fixture.IP_SOURCE_ID, 'source',
                          fixture.GPIO_B_COMPONENT, 'gpio_in',
                          fixture.PIN_DATA, 1, 'external_b'),
        ))

    @staticmethod
    def _targets(direction):
        """One anchor plus one target per mutated immediate bit.

        The anchor is an observation the real RTL only produces after the
        direction's own causal stage.  The three bit targets sit on ``gpio_a``'s
        real output pins 1..3 (the mutated immediate bits), so a mutated genome
        newly satisfies a target the previous testcase did not and the RFuzz
        client has a reason to keep it in the corpus.
        """
        anchor = (CoverageTarget('gpio_b.irq_pin0', fixture.GPIO_B_COMPONENT,
                                 'irq', 1, 1) if direction == CPU else
                  CoverageTarget('gpio_b.irq_pin8', fixture.GPIO_B_COMPONENT,
                                 'irq', 1 << fixture.PIN_IP_ROUND1,
                                 1 << fixture.PIN_IP_ROUND1))
        return (anchor,) + tuple(
            CoverageTarget(f'gpio_a.out_bit_{bit}', fixture.GPIO_A_COMPONENT,
                           'gpio_out', 1 << bit, 1 << bit)
            for bit in (1, 2, 3))

    # -- pinned seed identity ---------------------------------------------
    @staticmethod
    def _program_image(seed, direction):
        image = next((item for item in seed.initial_images
                      if item.image_id == fixture.PROGRAM_IMAGE
                      and item.component == fixture.CPU_COMPONENT), None)
        if image is None or image.address != 0:
            raise CampaignBlocked('Pico Wishbone campaign program image differs')
        return image

    @classmethod
    def _require_pinned_image(cls, seed, direction):
        image = cls._program_image(seed, direction)
        if not program_image_matches(image.data, direction):
            raise CampaignBlocked('Pico Wishbone campaign program image differs')
        immediate = (int.from_bytes(
            image.data[4 * fixture.SOURCE_INSTRUCTION:
                       4 * fixture.SOURCE_INSTRUCTION + 4], 'little') >> 20) & 0xFFF
        if not _expected_immediate(direction, immediate):
            raise CampaignBlocked('Pico Wishbone campaign source immediate differs')
        return image

    @classmethod
    def _require_result_image(cls, seed):
        image = next((item for item in seed.initial_images
                      if item.image_id == 'cpu.result'), None)
        if (image is None or image.component != fixture.CPU_COMPONENT
                or image.address != fixture.RESULT or image.data != bytes(24)):
            raise CampaignBlocked('Pico Wishbone campaign result image differs')

    @staticmethod
    def _require_action_shape(seed, direction, *, independent=False):
        expected = (fixture.independent_actions(direction) if independent
                    else fixture.bound_actions(direction))
        if tuple(seed.actions) != tuple(expected):
            raise CampaignBlocked('Pico Wishbone campaign action shape differs')

    @classmethod
    def _require_pinned_seed(cls, seed, direction, *, independent=False):
        if seed.direction != direction:
            raise CampaignBlocked('Pico Wishbone campaign seed direction mismatch')
        shape = (fixture.INDEPENDENT_SHAPES[direction] if independent
                 else fixture.DIRECTION_SHAPES[direction])
        if (seed.max_steps, seed.quiesce_steps) != tuple(shape):
            raise CampaignBlocked('Pico Wishbone campaign needs the pinned Genome shape')
        if seed.schedule_order != (fixture.CPU_COMPONENT, fixture.GPIO_A_COMPONENT,
                                   fixture.GPIO_B_COMPONENT):
            raise CampaignBlocked('Pico Wishbone campaign schedule differs')
        image = cls._require_pinned_image(seed, direction)
        cls._require_result_image(seed)
        cls._require_action_shape(seed, direction, independent=independent)
        digest = hashlib.sha256(image.data).hexdigest()
        if independent:
            # The comparison-only arm runs the same pinned CPU program.
            if image.data != fixture.direction_program(direction):
                raise CampaignBlocked(
                    'Pico Wishbone baseline arm needs the pinned program')
        else:
            seed_immediate = fixture.source_immediate(direction)
            actual = (int.from_bytes(
                image.data[4 * fixture.SOURCE_INSTRUCTION:
                           4 * fixture.SOURCE_INSTRUCTION + 4], 'little')
                >> 20) & 0xFFF
            if (actual & ~0xE) != (seed_immediate & ~0xE):
                raise CampaignBlocked(
                    'Pico Wishbone campaign seed immediate differs')
        return seed

    # -- fixtures ----------------------------------------------------------
    def _fixture(self, direction: str, bound_manifest: Path | None = None):
        if direction not in DIRECTIONS:
            raise CampaignBlocked(f'unsupported direction: {direction}')
        if bound_manifest is None:
            bound_manifest = (ROOT / 'configs/scenario/'
                              'pico_wb_two_gpio_campaign_seed.json')
        bound_manifest = Path(bound_manifest)
        _require_pinned_bound_seed(bound_manifest, self.BOUND_SEED_SHAPE)
        genome_path = (bound_manifest if direction == CPU else
                       bound_manifest.parent / self.BOUND_REVERSE_SEED)
        if not genome_path.is_file():
            raise CampaignBlocked(f'seed genome is missing: {genome_path}')
        seed = GenomeCodec.decode(genome_path.read_bytes())
        self._require_pinned_seed(seed, direction)
        targets = self._targets(direction)
        factory = self._bound().runner
        runner = factory()
        graph = DependencyGraph(
            sources=self._sources(direction),
            rules=(DependencyRule(targets[0].target_id,
                                  (fixture.CPU_SOURCE_ID,
                                   fixture.IP_SOURCE_ID), 'DATA_BINDING'),))
        decoder = GenomeRecordDecoder(
            graph=graph, ownership=runner.ownership,
            templates=(DecoderTemplate(targets[0].target_id, seed),),
            source_bindings=self._source_bindings())
        return factory, decoder, targets, seed

    def _independent_fixture(self, direction: str, manifest: Path):
        """Two real RTL instances, no cross-component route, local CPU shadow."""
        manifest = Path(manifest)
        if not manifest.is_file():
            raise CampaignBlocked('Pico Wishbone independent baseline is missing')
        try:
            document = json.loads(manifest.read_text(encoding='utf-8'))
        except (ValueError, UnicodeError) as exc:
            raise CampaignBlocked('Pico Wishbone independent baseline is not JSON') from exc
        if (document.get('schema_version') != 'scenario_independent_baseline.v1'
                or document.get('local_response_model') != 'persistent_shadow_registers'
                or document.get('cross_component_bindings') != []
                or document.get('cpu_irq') != 'constant_zero'):
            raise CampaignBlocked('Pico Wishbone independent baseline is invalid')
        windows = document.get('gpio_local_windows', {})
        declared = {name: windows.get(name) for name in
                    (fixture.GPIO_A_COMPONENT + '_local',
                     fixture.GPIO_B_COMPONENT + '_local')}
        expected = {fixture.GPIO_A_COMPONENT + '_local': {
                        'base': fixture.GPIO_A_BASE,
                        'size': fixture.GPIO_WINDOW},
                    fixture.GPIO_B_COMPONENT + '_local': {
                        'base': fixture.GPIO_B_BASE,
                        'size': fixture.GPIO_WINDOW}}
        if declared != expected:
            raise CampaignBlocked('Pico Wishbone independent local windows differ')
        if direction == CPU:
            seed_name = document.get('cpu_seed')
            source = FuzzableSource(fixture.CPU_SOURCE_ID, fixture.CPU_COMPONENT,
                                    fixture.PROGRAM_IMAGE,
                                    fixture.SOURCE_BIT_OFFSET,
                                    fixture.SOURCE_WIDTH, (direction,),
                                    'memory_image')
            binding = SourceBinding(fixture.CPU_SOURCE_ID, 'memory_image',
                                    fixture.CPU_COMPONENT, fixture.PROGRAM_IMAGE,
                                    fixture.SOURCE_BIT_OFFSET,
                                    fixture.SOURCE_WIDTH,
                                    'initial_image:cpu:cpu.program', 0)
            targets = (CoverageTarget('cpu.local_response_consumed',
                                      fixture.CPU_COMPONENT,
                                      'data_rsp_consumed', 1, 1),) + tuple(
                CoverageTarget(f'cpu.store_byte_bit_{bit}',
                               fixture.CPU_COMPONENT, 'data_wdata',
                               1 << bit, 1 << bit)
                for bit in (1, 2, 3))
        elif direction == IP:
            seed_name = document.get('reverse_seed')
            source = FuzzableSource(fixture.IP_SOURCE_ID,
                                    fixture.GPIO_B_COMPONENT, 'gpio_in',
                                    fixture.PIN_DATA, 1, (direction,))
            binding = SourceBinding(fixture.IP_SOURCE_ID, 'source',
                                    fixture.GPIO_B_COMPONENT, 'gpio_in',
                                    fixture.PIN_DATA, 1, 'external_b')
            targets = (CoverageTarget('gpio_b.baseline_irq',
                                      fixture.GPIO_B_COMPONENT, 'irq',
                                      1 << fixture.PIN_IP_ROUND1,
                                      1 << fixture.PIN_IP_ROUND1),)
        else:
            raise CampaignBlocked(f'unsupported direction: {direction}')
        if (not isinstance(seed_name, str) or not seed_name
                or Path(seed_name).name != seed_name or seed_name in ('.', '..')):
            raise CampaignBlocked('Pico Wishbone independent seed path is invalid')
        genome_path = manifest.parent / seed_name
        if not genome_path.is_file():
            raise CampaignBlocked(f'independent seed genome is missing: {genome_path}')
        seed = GenomeCodec.decode(genome_path.read_bytes())
        self._require_pinned_seed(seed, direction, independent=True)
        factory = self._independent().runner
        runner = factory()
        graph = DependencyGraph(
            sources=(source,),
            rules=(DependencyRule(targets[0].target_id, (source.source_id,),
                                  'BASELINE_GROUPING'),))
        decoder = GenomeRecordDecoder(
            graph=graph, ownership=runner.ownership,
            templates=(DecoderTemplate(targets[0].target_id, seed),),
            source_bindings=SourceBindings((binding,)))
        return factory, decoder, targets, seed


# --------------------------------------------------------------------------
# independent saved-run audit
# --------------------------------------------------------------------------
class CampaignAuditError(AssertionError):
    """A saved campaign does not recompute to what its own report claims."""


def _canonical(document) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def audit_campaign_cell(cell_dir: Path, cell: Mapping) -> list[str]:
    """Recompute one saved cell's claims from its own receipts and artifacts."""
    import types

    from .scenario_campaign import (_post_seed_completed_causal_chains,
                                    _post_seed_effective_genotypes,
                                    _post_seed_real_mutation_batches,
                                    _search_manifest_status)
    from myfuzz.scenario.genome import GenomeCodec

    cell_dir = Path(cell_dir)
    live = cell_dir / "live"
    findings: list[str] = []
    search, replay = cell.get("search"), cell.get("replay")
    if cell.get("status") != "complete":
        findings.append("cell_status_not_complete")
    if cell.get("gate_failures"):
        findings.append("cell_gate_failures_present")
    if not isinstance(search, Mapping) or not isinstance(replay, Mapping):
        return findings + ["cell_evidence_missing"]

    checks = _jsonl(cell_dir / "chain_checks.jsonl")
    if not checks and cell.get("strategy") != "independent_drive":
        findings.append("chain_checks_empty")
    # An incomplete assessment is a legal search outcome: the campaign counts
    # only two-round complete chains as ``completed_chains``.  The audit must
    # recompute that same count, not demand that every scored genome closed.
    # Only a malformed assessment (missing/typed-wrong fields, or "complete"
    # with fewer than two rounds) is an audit failure.
    complete_checks = 0
    for check in checks:
        assessment = check.get("assessment")
        if (not isinstance(assessment, Mapping)
                or type(assessment.get("complete")) is not bool
                or type(assessment.get("rounds")) is not int
                or not 0 <= assessment.get("rounds") <= 2
                or (assessment.get("complete")
                    and assessment.get("rounds") != 2)):
            findings.append("chain_check_assessment_invalid")
            break
        if assessment.get("complete") and assessment.get("rounds") == 2:
            complete_checks += 1
    if search.get("completed_chains") != complete_checks:
        findings.append("completed_chains_mismatch")

    receipts = _jsonl(live / "receipts.jsonl")
    rows = [types.SimpleNamespace(**row) for row in receipts]
    if len(receipts) != search.get("testcases"):
        findings.append("testcase_count_mismatch")
    valid = sum(row.get("status") in ("complete", "dut_violation")
                for row in receipts)
    if valid != search.get("valid_testcases"):
        findings.append("valid_testcase_count_mismatch")
    statuses: dict[str, int] = {}
    for row in receipts:
        statuses[row["status"]] = statuses.get(row["status"], 0) + 1
    if statuses != search.get("failures"):
        findings.append("status_counts_mismatch")
    ticks: dict[str, int] = {}
    for row in receipts:
        for component, value in (row.get("local_ticks") or {}).items():
            ticks[component] = ticks.get(component, 0) + value
    if ticks != search.get("local_cycles"):
        findings.append("local_cycles_mismatch")
    if rows:
        if _search_manifest_status(rows) != "ok":
            findings.append("mixed_manifest_identity")
        if (_post_seed_real_mutation_batches(rows)
                != search.get("post_seed_mutation_batches")):
            findings.append("post_seed_mutation_batches_mismatch")
        if (len(_post_seed_effective_genotypes(rows))
                != search.get("post_seed_effective_genotypes")):
            findings.append("post_seed_effective_genotypes_mismatch")
        if (_post_seed_completed_causal_chains(rows, [
                {"genome_sha256": check.get("genome_sha256"),
                 "assessment": check.get("assessment")} for check in checks])
                != search.get("post_seed_completed_chains")):
            findings.append("post_seed_completed_chains_mismatch")
        if rows[0].run_id != cell.get("cell_id"):
            findings.append("receipt_run_id_differs")

    corpus = sorted((live / "corpus").glob("entry_*.json"))
    if len(corpus) != search.get("saved_corpus_entries"):
        findings.append("corpus_entry_count_mismatch")
    if len(corpus) != replay.get("total_entries"):
        findings.append("replay_total_entries_mismatch")
    if replay.get("matched_entries") != replay.get("total_entries"):
        findings.append("replay_entries_not_matched")
    if replay.get("matched_failure_entries") != replay.get("failure_entries"):
        findings.append("replay_failures_not_matched")
    if replay.get("error") is not None:
        findings.append("replay_error_present")
    if cell.get("strategy") != "independent_drive":
        if replay.get("failure_entries", 0) > len(corpus):
            findings.append("replay_failure_count_exceeds_corpus")
    else:
        if search.get("completed_chains") not in (0, None):
            findings.append("independent_baseline_claims_a_chain")

    seed_file = cell_dir / "seed_genome.json"
    if not seed_file.is_file():
        findings.append("seed_genome_missing")
    else:
        seed = GenomeCodec.decode(seed_file.read_bytes())
        pinned = (fixture.independent_actions(seed.direction)
                  if cell.get("strategy") == "independent_drive"
                  else fixture.bound_actions(seed.direction))
        if tuple(seed.actions) != tuple(pinned):
            findings.append("saved_seed_actions_differ")
        if seed.direction != cell.get("direction"):
            findings.append("saved_seed_direction_differs")
        decoder_path = live / "decoder_manifest.json"
        if decoder_path.is_file():
            decoder = json.loads(decoder_path.read_bytes())
            templates = decoder.get("templates") or []
            expected = json.loads(GenomeCodec.encode(seed))
            if not templates or templates[0].get("genome") != expected:
                findings.append("decoder_template_differs")

    identity_path = live / "run_identity.json"
    if not identity_path.is_file():
        findings.append("run_identity_missing")
    else:
        envelope = json.loads(identity_path.read_bytes())
        body = envelope.get("identity")
        digest = (hashlib.sha256(_canonical(body)).hexdigest()
                  if isinstance(body, Mapping) else None)
        if (envelope.get("schema_version")
                != "scenario_fresh_run_identity_envelope.v1"
                or envelope.get("sha256") != digest):
            findings.append("run_identity_envelope_invalid")
        live_report = json.loads((live / "report.json").read_bytes())
        if live_report.get("run_identity_sha256") != envelope.get("sha256"):
            findings.append("run_identity_not_referenced_by_live_report")
        artifacts = body.get("artifacts") if isinstance(body, Mapping) else None
        if not isinstance(artifacts, Mapping) or not artifacts:
            findings.append("run_identity_artifacts_missing")
        else:
            for name, expected_sha in artifacts.items():
                path = live / name
                if not path.is_file() or _file_sha256(path) != expected_sha:
                    findings.append("run_identity_artifact_changed")
                    break
    return findings


def audit_campaign_run(run_dir: Path) -> dict:
    """Recompute every saved claim; raise if the bundle does not add up.

    The audit never reads the report's summary fields as evidence: each count is
    re-derived from ``receipts.jsonl``, ``chain_checks.jsonl``, the corpus and
    the run identity envelopes, then compared with the report.
    """
    run = Path(run_dir)
    report_path = run / "campaign_report.json"
    if not report_path.is_file():
        raise CampaignAuditError(f"campaign report is missing: {report_path}")
    report = json.loads(report_path.read_bytes())
    findings: list[str] = []
    if report.get("schema_version") != "scenario_campaign.v1":
        findings.append("report_schema_differs")
    if report.get("gate") != "G4" or report.get("required_cells") != 18:
        findings.append("report_gate_differs")
    cells = report.get("cells") or []
    if len(cells) != 18:
        findings.append("cell_count_differs")
    if report.get("gate_status") != "complete":
        findings.append("gate_status_not_complete")
    if report.get("campaign_source_identity_stable") is not True:
        findings.append("campaign_source_identity_not_stable")
    stability = report.get("campaign_input_stability") or {}
    if not (stability.get("originals_stable")
            and stability.get("snapshots_stable") and stability.get("files")):
        findings.append("campaign_inputs_not_stable")
    effective = sum((cell.get("cost", {}).get("effective_search_seconds") or 0)
                    for cell in cells)
    if abs(effective - (report.get("effective_search_seconds") or 0)) > 1e-6:
        findings.append("effective_seconds_sum_differs")
    if effective < (report.get("required_effective_search_seconds") or 0):
        findings.append("effective_seconds_below_requirement")
    coverage = report.get("actual_source_coverage") or {}
    if len(coverage) != 4:
        findings.append("source_coverage_groups_missing")
    for name, group in coverage.items():
        if (group.get("measured") is not True or len(group.get("declared") or []) < 2
                or group.get("executed") != group.get("declared")):
            findings.append(f"source_coverage_not_exercised:{name}")
    cells_dir = {cell.get("cell_id"): run / str(cell.get("cell_id"))
                 for cell in cells}
    for cell_id, cell in ((cell.get("cell_id"), cell) for cell in cells):
        if not cells_dir[cell_id].is_dir():
            findings.append(f"cell_directory_missing:{cell_id}")
            continue
        for finding in audit_campaign_cell(cells_dir[cell_id], cell):
            findings.append(f"{cell_id}:{finding}")

    identity_path = run / "campaign_run_identity.json"
    if not identity_path.is_file():
        findings.append("campaign_run_identity_missing")
    else:
        envelope = json.loads(identity_path.read_bytes())
        body = envelope.get("identity")
        digest = (hashlib.sha256(_canonical(body)).hexdigest()
                  if isinstance(body, Mapping) else None)
        if (envelope.get("schema_version")
                != "scenario_campaign_run_identity_envelope.v1"
                or envelope.get("sha256") != digest
                or report.get("campaign_run_identity_sha256") != digest):
            findings.append("campaign_run_identity_invalid")
        if isinstance(body, Mapping):
            associations = {row.get("cell_id"): row
                            for row in body.get("cells") or []}
            if set(associations) != set(cells_dir):
                findings.append("campaign_run_identity_cell_set_differs")
            for cell_id, association in associations.items():
                if association.get("execution_identity_status") != "available":
                    findings.append(f"execution_identity_not_available:{cell_id}")
                auxiliary = association.get("auxiliary_artifacts") or {}
                for relative, expected_sha in auxiliary.items():
                    path = run / relative
                    if not path.is_file() or _file_sha256(path) != expected_sha:
                        findings.append(f"auxiliary_artifact_changed:{cell_id}")
                        break
    if findings:
        raise CampaignAuditError("; ".join(findings))
    return {
        "cell_count": len(cells),
        "effective_search_seconds": effective,
        "testcases": sum(cell["search"]["testcases"] for cell in cells),
        "completed_chains": sum(cell["search"]["completed_chains"] for cell in cells),
        "corpus_entries": sum(cell["replay"]["total_entries"] for cell in cells),
        "source_coverage": {name: group["executed"] for name, group in coverage.items()},
    }
