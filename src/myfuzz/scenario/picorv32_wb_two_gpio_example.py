"""Real PicoRV32 classic Wishbone plus two real OpenTitan GPIO TL-UL targets.

This is the scenario-layer fixture for the P6 row-4 (classic Wishbone) campaign.
Both sides are pinned RTL: the CPU is ``configs/cpus/picorv32_wb_irq`` driven
through its generated local harness (``GeneratedWishboneCpuSession``), and the
two IP instances are ``configs/peripherals/opentitan_gpio_local`` driven through
their generated local harnesses (``GeneratedOpentitanGpioSession``).  The fixture
is the *directed* acceptance program of
``tests/integration/test_scenario_picorv32_wb_opentitan_gpio_irq_real.py``
extended to two devices and two ordered rounds, with the same custom0 IRQ ABI
(``getq``/``maskirq``/``retirq``; there is no machine-mode CSR trap path here).

Wiring
------
* ``gpio_a`` sits at 0x4000_1000 and is the CPU's output device.
* ``gpio_b`` sits at 0x4000_0000 and is the interrupt source.  Its low eight
  input pins are *bound* to ``gpio_a``'s real output pins, so a real CPU store
  to ``gpio_a`` DIRECT_OUT only reaches ``gpio_b`` through sampled RTL output.
* Four single-bit bindings carry ``gpio_b``'s real IRQ vector into the CPU's
  32-bit custom IRQ input: vector bits 0, 4, 8 and 12 reach CPU IRQ bits 3, 4,
  5 and 6.  Distinct CPU IRQ bits matter: the pinned core's ``LATCHED_IRQ``
  parameter is all ones, so a pending bit that was masked stays latched, and
  re-unmasking it would re-enter the handler without a new physical edge.  A
  second round on the *same* bit is therefore not a second real edge; the
  fixture uses a second GPIO pin instead.
* Host-side startup writes program ``gpio_b``'s INTR_ENABLE and
  INTR_CTRL_EN_RISING for pins 0, 4, 8, 12.  These are ordinary real RTL
  register writes through ``ACCESS_TLUL_GPIO``; the IRQ itself is produced by
  the GPIO RTL from a real sampled pin, never by the scheduler.

Two ordered rounds per case
---------------------------
``CPU_TO_IP_TO_CPU`` (the CPU initiates)::

    CPU store gpio_a.DIRECT_OUT = V      (V's bit 0 set, bit 4 clear)
      -> real gpio_a output pins 0..7
      -> routed to gpio_b input pins 0..7
      -> gpio_b real rising edge on pin 0 -> gpio_b.irq bit 0
      -> CPU IRQ bit 3 -> real custom0 trap (q1 = 8)
      -> ISR reads gpio_b INTR_STATE / DATA_IN, writes both to RAM, W1C,
         stores the post-clear status, bumps the round counter, maskirq, retirq
      -> gpio_b.irq falls, CPU IRQ input falls
    round 2 repeats with gpio_a.DIRECT_OUT = V | 0x10: pin 0 rises again and
    pin 4 rises; pin 0's pending bit is masked, so the trap is the real pin-4
    edge (q1 = 16), with INTR_STATE = 0x11.

``IP_TO_CPU_TO_IP`` (the IP initiates)::

    external source raises gpio_b input pin 8 (pinned action, START)
      -> gpio_b real rising edge on pin 8 -> gpio_b.irq bit 8
      -> CPU IRQ bit 5 -> real custom0 trap (q1 = 32)
      -> ISR reads gpio_b INTR_STATE / DATA_IN, writes both to RAM, drives
         gpio_a.DIRECT_OUT = the CPU program's constant, W1C, bumps the round
         counter, maskirq, retirq
      -> gpio_b.irq falls, CPU IRQ input falls
    round 2: the source drops pin 8 and raises pin 12 (pinned actions triggered
    by the real IRQ fall), CPU IRQ bit 6 -> trap (q1 = 64), ISR repeats.

The second external pin (``gpio_in`` bit 9) is the IP-side fuzzable source in
both directions: it is a real sampled input pin whose value appears in the
``DATA_IN`` register the CPU reads, so it is a genuine joint prerequisite of an
observed effect.  The CPU-side fuzzable source is the three-bit immediate field
of the ``addi x9, x0, X`` instruction at word 37 (image bits [21, 24) of that
word): bit 0 always stays set and bit 4 always stays clear, so every mutated
genotype still produces the round-1 edge the chain needs.

Honesty notes
-------------
* ``defer_mmio`` is declared false on the CPU session, exactly like the AXI4-Lite
  row-3 fixture: a routed beat is answered inline in the step that accepted it,
  and the session itself declares the one target access that costs.
* ``DATA_IN`` is the profile's read-only raw pin register, so the fixture's
  checker may state the observation ``DATA_IN == gpio_in`` that the pinned
  profile declares; it never predicts a value the DUT did not produce.
* This module only assembles the pair.  Search, mutation, assertion and replay
  live in ``myfuzz.integration.picorv32_wb_scenario_campaign``.
"""
from __future__ import annotations

from functools import lru_cache
import hashlib
from pathlib import Path

from myfuzz.local_harness.opentitan_gpio_session import GeneratedOpentitanGpioSession
from myfuzz.local_harness.wishbone_cpu_session import GeneratedWishboneCpuSession
from .ledger import TransactionLedger
from .memory import MemoryRegion, PersistentMemory
from .memory_service import MemoryService
from .ownership import InputField, InputOwner, compile_ownership
from .router import DataflowRouter, DeviceWindow
from .runner import Binding, ScenarioRunner

ROOT = Path(__file__).resolve().parents[3]

CPU_PROFILE = 'configs/cpus/picorv32_wb_irq/component_profile.json'
GPIO_PROFILE = 'configs/peripherals/opentitan_gpio_local/component_profile.json'

CPU_COMPONENT = 'cpu'
GPIO_A_COMPONENT = 'gpio_a'
GPIO_B_COMPONENT = 'gpio_b'
GPIO_A_BASE = 0x40001000
GPIO_B_BASE = 0x40000000
GPIO_WINDOW = 0x1000

RAM_BASE = 0
RAM_SIZE = 0x8000
#: Result block the ISR and the main program commit to.
RESULT = 0x200

#: OpenTitan GPIO register offsets (``configs/peripherals/opentitan_gpio_local``
#: declares them; nothing here invents a register).
INTR_STATE = 0x00
INTR_ENABLE = 0x04
DATA_IN = 0x10
DIRECT_OUT = 0x14
DIRECT_OE = 0x20
INTR_CTRL_EN_RISING = 0x2C

PROGRAM_IMAGE = 'cpu.program'

#: Real GPIO pins used by the fixture: one interrupt pin per round and per
#: direction, plus the external data pin that every direction fuzzes.
PIN_CPU_ROUND1 = 0
PIN_CPU_ROUND2 = 4
PIN_IP_ROUND1 = 8
PIN_IP_ROUND2 = 12
PIN_DATA = 9

#: CPU custom IRQ bits the four GPIO interrupt pins are bound to.
CPU_IRQ_CPU_ROUND1 = 3
CPU_IRQ_CPU_ROUND2 = 4
CPU_IRQ_IP_ROUND1 = 5
CPU_IRQ_IP_ROUND2 = 6
#: Startup register value: INTR_ENABLE and INTR_CTRL_EN_RISING for the four
#: interrupt pins.  Written by the host through real ``ACCESS_TLUL_GPIO``.
IRQ_STARTUP_MASK = ((1 << PIN_CPU_ROUND1) | (1 << PIN_CPU_ROUND2)
                    | (1 << PIN_IP_ROUND1) | (1 << PIN_IP_ROUND2))

#: The mutable CPU program immediate lives in the ``addi x9, x0, X`` word.
SOURCE_INSTRUCTION = 37
SOURCE_BIT_OFFSET = 32 * SOURCE_INSTRUCTION + 21
SOURCE_WIDTH = 3

#: Seed values of the two CPU-side immediates.  Both are three bits wide at
#: [21, 24), so bit 0 of the loaded value stays zero and every mutation keeps
#: the registers the chain depends on.
CPU_ROUND1_SEED = 0x05
IP_CONST_SEED = 0x0A

#: Mutation unit of the IP-side external data pin source (one pin bit).
IP_DATA_SEED = 1

#: Pinned Genome step budgets: three components step per schedule position, so
#: a budget of N steps gives each harness N/3 local ticks.
DIRECTION_SHAPES = {'CPU_TO_IP_TO_CPU': (1800, 8), 'IP_TO_CPU_TO_IP': (2400, 8)}

#: Independent (comparison-only) baseline shapes.  They are short on purpose:
#: that arm must observe a real local response or a real GPIO interrupt, not
#: spend the campaign budget spinning on a handler that cannot run.
INDEPENDENT_SHAPES = {'CPU_TO_IP_TO_CPU': (900, 8), 'IP_TO_CPU_TO_IP': (600, 8)}

#: The mutable images/actions the campaign mutations target.
CPU_SOURCE_ID = 'cpu.program'
IP_SOURCE_ID = 'b.pin9'


#: Result-block offsets the program commits; the checker names these once.
RESULT_STATUS = RESULT + 0
RESULT_DATA = RESULT + 4
RESULT_Q1 = RESULT + 8
RESULT_STATUS_AFTER = RESULT + 12
RESULT_COUNTER = RESULT + 16
RESULT_MARKER = RESULT + 20


def _data_pin_action(direction: str):
    """The IP-side fuzzable source: one real external GPIO input pin."""
    from .genome import Action, Trigger

    return Action('data-pin', GPIO_B_COMPONENT, 'gpio_in', IP_DATA_SEED,
                  direction, Trigger('START'), bit_offset=PIN_DATA, width=1,
                  delay_component=GPIO_B_COMPONENT, delay_ticks=0)


def _second_edge_trigger():
    """Real CPU observation that closes round 1 of the IP-initiated direction.

    The handler stores the post-clear status to RAM; the CPU's own store
    address is an observed output, so the second external edge is admitted only
    after round 1's last committed observation.  Triggering on the *fall* of the
    GPIO interrupt would inject pin 12 while the handler is still reading the
    post-clear status, and that read would then legitimately see the next
    round's pending bit.
    """
    from .genome import Trigger

    return Trigger('AFTER_OUTPUT', CPU_COMPONENT, 'data_addr', 0xFFFFFFFF,
                   RESULT_STATUS_AFTER, 1)


def bound_actions(direction: str):
    """The exact scenario inputs of one bound-direction seed genome."""
    from .genome import Action, Trigger

    if direction not in DIRECTION_SHAPES:
        raise ValueError('unknown mutation direction')
    if direction == 'CPU_TO_IP_TO_CPU':
        return (_data_pin_action(direction),)
    trigger = _second_edge_trigger()
    return (Action('first-rise', GPIO_B_COMPONENT, 'gpio_in', 1, direction,
                   Trigger('START'), bit_offset=PIN_IP_ROUND1, width=1,
                   delay_component=GPIO_B_COMPONENT, delay_ticks=0),
            Action('first-low', GPIO_B_COMPONENT, 'gpio_in', 0, direction,
                   trigger, bit_offset=PIN_IP_ROUND1, width=1,
                   delay_component=GPIO_B_COMPONENT, delay_ticks=0),
            Action('second-rise', GPIO_B_COMPONENT, 'gpio_in', 1, direction,
                   trigger, bit_offset=PIN_IP_ROUND2, width=1,
                   delay_component=GPIO_B_COMPONENT, delay_ticks=8),
            _data_pin_action(direction))


def independent_actions(direction: str):
    """The comparison-only arm's inputs: no CPU-observed trigger at all."""
    from .genome import Action, Trigger

    if direction == 'CPU_TO_IP_TO_CPU':
        return (_data_pin_action(direction),)
    return (Action('first-rise', GPIO_B_COMPONENT, 'gpio_in', 1, direction,
                   Trigger('START'), bit_offset=PIN_IP_ROUND1, width=1,
                   delay_component=GPIO_B_COMPONENT, delay_ticks=0),
            _data_pin_action(direction))


# --------------------------------------------------------------------------
# RV32I encoding (explicit, so the mutation source is a stated instruction)
# --------------------------------------------------------------------------
def _imm(value: int) -> int:
    return value & 0xFFF


def _addi(rd: int, rs1: int, immediate: int) -> int:
    return (_imm(immediate) << 20) | (rs1 << 15) | (rd << 7) | 0x13


def _lui(rd: int, upper: int) -> int:
    return ((upper & 0xFFFFF) << 12) | (rd << 7) | 0x37


def _lw(rd: int, rs1: int, offset: int) -> int:
    return (_imm(offset) << 20) | (rs1 << 15) | (2 << 12) | (rd << 7) | 0x03


def _sw(rs2: int, rs1: int, offset: int) -> int:
    return ((((offset >> 5) & 0x7F) << 25) | (rs2 << 20) | (rs1 << 15)
            | (2 << 12) | ((offset & 0x1F) << 7) | 0x23)


def _or(rd: int, rs1: int, rs2: int) -> int:
    return (rs2 << 20) | (rs1 << 15) | (6 << 12) | (rd << 7) | 0x33


def _bne(rs1: int, rs2: int, offset: int) -> int:
    if offset % 2 or not -4096 <= offset <= 4094:
        raise ValueError('branch offset out of range')
    value = offset & 0x1FFF
    return (((value >> 12) & 1) << 31 | ((value >> 5) & 0x3F) << 25
            | (rs2 << 20) | (rs1 << 15) | (1 << 12) | ((value >> 1) & 0xF) << 8
            | ((value >> 11) & 1) << 7 | 0x63)


#: Pico custom0 encodings, copied from the pinned firmware ABI the directed
#: Wishbone acceptance already exercises: ``getq rd,q1`` (funct3=4),
#: ``maskirq x0,rs1`` (funct3=6, funct7=3) and ``retirq`` (funct7=2).
GETQ_Q1 = 0x0000C28B
RETIRQ = 0x0400000B


def _maskirq(rs1: int) -> int:
    return (3 << 25) | (rs1 << 15) | (6 << 12) | 0x0B


#: Register roles of the program.  The handler may clobber x3..x7 only; x1
#: (gpio_a base), x2 (gpio_b base), x8 (result block) and x9 (the fuzzed
#: immediate) must survive a trap because the main program continues with them.
def _wait_counter(expected: int) -> tuple[int, ...]:
    """Loop until RAM[RESULT + 16] == expected, using only x10/x11."""
    return (_lw(10, 8, 16), _addi(11, 0, expected), _bne(10, 11, -8))


def _isr_words(*, write_a_output: bool) -> tuple[int, ...]:
    words = [
        GETQ_Q1,                    # 0x10 getq x5, q1
        _lw(3, 2, INTR_STATE),      # INTR_STATE (real GPIO state)
        _lw(4, 2, DATA_IN),         # DATA_IN (real sampled pins)
        _sw(3, 8, 0),               # RAM[RESULT + 0] = status
        _sw(4, 8, 4),               # RAM[RESULT + 4] = data
        _sw(5, 8, 8),               # RAM[RESULT + 8] = q1
    ]
    if write_a_output:
        # IP_TO_CPU_TO_IP: the handler drives gpio_a's real output pins with the
        # program's pinned constant (the CPU-side fuzzable source).
        words.append(_sw(9, 1, DIRECT_OUT))
    words += [
        _sw(3, 2, INTR_STATE),      # W1C with the observed status
        _lw(7, 2, INTR_STATE),      # post-clear status
        _sw(7, 8, 12),              # RAM[RESULT + 12] = status after W1C
        _lw(7, 8, 16),              # round counter
        _addi(7, 7, 1),
        _sw(7, 8, 16),
        _addi(6, 0, -1),            # mask every custom IRQ while finishing
        _maskirq(6),
        RETIRQ,
    ]
    return tuple(words)


def _cpu_direction_program() -> tuple[int, ...]:
    words = [0x0800006F] + [0x00000013] * 3       # jal x0, 0x80
    handler = _isr_words(write_a_output=False)
    if len(handler) > 28:
        raise ValueError('CPU-direction handler does not fit below 0x80')
    words += list(handler) + [0x00000013] * (32 - len(words) - len(handler))
    main = [
        _lui(1, GPIO_A_BASE >> 12),               # x1 = gpio_a window
        _lui(2, GPIO_B_BASE >> 12),               # x2 = gpio_b window
        _addi(8, 0, RESULT),                      # x8 = result block
        _addi(3, 0, 0xFF),
        _sw(3, 1, DIRECT_OE),                     # real CPU -> IP setup write
        _addi(9, 0, CPU_ROUND1_SEED),             # <-- mutable immediate word
        _addi(7, 0, ~(1 << CPU_IRQ_CPU_ROUND1)),  # unmask the pin-0 IRQ only
        _maskirq(7),
        _sw(9, 1, DIRECT_OUT),                    # round 1: CPU initiates
        *_wait_counter(1),
        _sw(0, 1, DIRECT_OUT),                    # drop the pins again
        _addi(7, 0, ~(1 << CPU_IRQ_CPU_ROUND2)),  # round 2 is the pin-4 edge
        _maskirq(7),
        _addi(7, 0, 1 << PIN_CPU_ROUND2),
        _or(7, 9, 7),
        _sw(7, 1, DIRECT_OUT),                    # round 2: pins 0 and 4 rise
        *_wait_counter(2),
        _addi(7, 0, 0x66),
        _sw(7, 8, 20),                            # completion marker
        0x0000006F,
    ]
    words += main
    return tuple(words)


def _ip_direction_program() -> tuple[int, ...]:
    words = [0x0800006F] + [0x00000013] * 3
    handler = _isr_words(write_a_output=True)
    if len(handler) > 28:
        raise ValueError('IP-direction handler does not fit below 0x80')
    words += list(handler) + [0x00000013] * (32 - len(words) - len(handler))
    main = [
        _lui(1, GPIO_A_BASE >> 12),
        _lui(2, GPIO_B_BASE >> 12),
        _addi(8, 0, RESULT),
        _addi(3, 0, 0xFF),
        _sw(3, 1, DIRECT_OE),
        _addi(9, 0, IP_CONST_SEED),               # <-- mutable immediate word
        _addi(7, 0, ~(1 << CPU_IRQ_IP_ROUND1)),   # unmask the pin-8 IRQ only
        _maskirq(7),
        *_wait_counter(1),
        _addi(7, 0, ~(1 << CPU_IRQ_IP_ROUND2)),   # round 2 is the pin-12 edge
        _maskirq(7),
        *_wait_counter(2),
        _addi(7, 0, 0x66),
        _sw(7, 8, 20),
        0x0000006F,
    ]
    words += main
    return tuple(words)


def _image(words: tuple[int, ...]) -> bytes:
    return b''.join(word.to_bytes(4, 'little') for word in words)


def direction_program(direction: str) -> bytes:
    if direction == 'CPU_TO_IP_TO_CPU':
        return _image(_cpu_direction_program())
    if direction == 'IP_TO_CPU_TO_IP':
        return _image(_ip_direction_program())
    raise ValueError('unknown mutation direction')


def program_hex(direction: str) -> str:
    return direction_program(direction).hex()


def program_digest(direction: str) -> str:
    return hashlib.sha256(direction_program(direction)).hexdigest()


def source_immediate(direction: str) -> int:
    """The pinned three-bit immediate the CPU-side source mutates."""
    program = direction_program(direction)
    word = int.from_bytes(program[4 * SOURCE_INSTRUCTION:
                                  4 * SOURCE_INSTRUCTION + 4], 'little')
    return (word >> 20) & 0xFFF


# --------------------------------------------------------------------------
# artifacts, ownership, runner
# --------------------------------------------------------------------------
def _artifact(profile: str, instance: str, *, base_dir: Path = ROOT):
    from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
                                      render_local_harness, render_local_runtime,
                                      verify_local_source_lock)
    from myfuzz.local_harness.driver_renderer import render_local_driver

    request = load_local_harness_request(dict(
        schema_version='local_harness.v1', profile_path=profile,
        instance_id=instance, reset_assert_ticks=8, reset_release_ticks=8,
        max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=base_dir)
    runtime = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=base_dir),
        base_dir=base_dir)
    return render_local_driver(runtime, base_dir=base_dir)


@lru_cache(maxsize=4)
def pico_wb_artifacts(base_dir: Path = ROOT):
    """The three admitted artifacts; rendering is deterministic."""
    return (_artifact(CPU_PROFILE, CPU_COMPONENT, base_dir=base_dir),
            _artifact(GPIO_PROFILE, GPIO_A_COMPONENT, base_dir=base_dir),
            _artifact(GPIO_PROFILE, GPIO_B_COMPONENT, base_dir=base_dir))


def pico_wb_bindings() -> tuple[Binding, ...]:
    """The four real pin routes and the one real output-to-input route."""
    return (
        Binding(GPIO_A_COMPONENT, 'gpio_out', GPIO_B_COMPONENT, 'gpio_in', 8),
        Binding(GPIO_B_COMPONENT, 'irq', CPU_COMPONENT, 'irq', 1,
                source_bit_offset=PIN_CPU_ROUND1,
                target_bit_offset=CPU_IRQ_CPU_ROUND1),
        Binding(GPIO_B_COMPONENT, 'irq', CPU_COMPONENT, 'irq', 1,
                source_bit_offset=PIN_CPU_ROUND2,
                target_bit_offset=CPU_IRQ_CPU_ROUND2),
        Binding(GPIO_B_COMPONENT, 'irq', CPU_COMPONENT, 'irq', 1,
                source_bit_offset=PIN_IP_ROUND1,
                target_bit_offset=CPU_IRQ_IP_ROUND1),
        Binding(GPIO_B_COMPONENT, 'irq', CPU_COMPONENT, 'irq', 1,
                source_bit_offset=PIN_IP_ROUND2,
                target_bit_offset=CPU_IRQ_IP_ROUND2),
    )


def pico_wb_ownership():
    """Every declared input bit has exactly one owner.

    ``gpio_b``'s low byte is the CPU-driven output route; bits [8, 32) are the
    external pin source the campaign fuzzes; the cpu IRQ bits that are not
    bound to a real GPIO pin are constant zero.
    """
    owners = [InputOwner(CPU_COMPONENT, 'irq', 0, 3, 'fixed', 'constant_zero'),
              InputOwner(CPU_COMPONENT, 'irq', CPU_IRQ_CPU_ROUND1, 1, 'bound',
                         'gpio_b.irq'),
              InputOwner(CPU_COMPONENT, 'irq', CPU_IRQ_CPU_ROUND2, 1, 'bound',
                         'gpio_b.irq'),
              InputOwner(CPU_COMPONENT, 'irq', CPU_IRQ_IP_ROUND1, 1, 'bound',
                         'gpio_b.irq'),
              InputOwner(CPU_COMPONENT, 'irq', CPU_IRQ_IP_ROUND2, 1, 'bound',
                         'gpio_b.irq'),
              InputOwner(CPU_COMPONENT, 'irq', CPU_IRQ_IP_ROUND2 + 1, 32 -
                         (CPU_IRQ_IP_ROUND2 + 1), 'fixed', 'constant_zero'),
              InputOwner(GPIO_A_COMPONENT, 'gpio_in', 0, 32, 'fixed',
                         'constant_zero'),
              InputOwner(GPIO_B_COMPONENT, 'gpio_in', 0, 8, 'bound',
                         'gpio_a.gpio_out'),
              InputOwner(GPIO_B_COMPONENT, 'gpio_in', 8, 24, 'source',
                         'external_b'),
              InputOwner(GPIO_A_COMPONENT, 'strap_en', 0, 1, 'fixed',
                         'constant_zero'),
              InputOwner(GPIO_B_COMPONENT, 'strap_en', 0, 1, 'fixed',
                         'constant_zero')]
    return compile_ownership(
        (InputField(CPU_COMPONENT, 'irq', 32),
         InputField(GPIO_A_COMPONENT, 'gpio_in', 32),
         InputField(GPIO_B_COMPONENT, 'gpio_in', 32),
         InputField(GPIO_A_COMPONENT, 'strap_en', 1),
         InputField(GPIO_B_COMPONENT, 'strap_en', 1)),
        tuple(owners))


def pico_wb_independent_ownership():
    """The comparison-only baseline: no bound input, no cross-component route."""
    return compile_ownership(
        (InputField(CPU_COMPONENT, 'irq', 32),
         InputField(GPIO_A_COMPONENT, 'gpio_in', 32),
         InputField(GPIO_B_COMPONENT, 'gpio_in', 32),
         InputField(GPIO_A_COMPONENT, 'strap_en', 1),
         InputField(GPIO_B_COMPONENT, 'strap_en', 1)),
        (InputOwner(CPU_COMPONENT, 'irq', 0, 32, 'fixed', 'constant_zero'),
         InputOwner(GPIO_A_COMPONENT, 'gpio_in', 0, 32, 'source', 'external_a'),
         InputOwner(GPIO_B_COMPONENT, 'gpio_in', 0, 8, 'fixed',
                    'constant_zero'),
         InputOwner(GPIO_B_COMPONENT, 'gpio_in', 8, 24, 'source', 'external_b'),
         InputOwner(GPIO_A_COMPONENT, 'strap_en', 0, 1, 'fixed',
                    'constant_zero'),
         InputOwner(GPIO_B_COMPONENT, 'strap_en', 0, 1, 'fixed',
                    'constant_zero')))


class LocalRegisterModel:
    """Persistent per-testcase CPU response model, never an IP RTL view."""

    def __init__(self):
        self.words: dict[int, int] = {}

    def write_register(self, offset: int, value: int, *, be: int = 15):
        old = self.words.get(offset, 0)
        mask = sum(0xFF << (8 * byte) for byte in range(4) if be & (1 << byte))
        self.words[offset] = ((old & ~mask) | (value & mask)) & 0xFFFFFFFF

    def read_register(self, offset: int) -> int:
        return self.words.get(offset, 0)


class PicoWbTwoGpioPair:
    """One admitted Pico Wishbone CPU and two admitted GPIO RTL instances.

    The generated harness binaries are admitted once, outside every testcase
    wall clock, exactly like the AXI4-Lite row-3 fixture: ``begin_case`` starts
    a brand new RTL process for each harness and ``end_case`` reaps it, while
    the CPU's persistent memory, its router and every counter are rebuilt for
    each case.  No DUT state survives a case.
    """

    def __init__(self, *, base_dir: Path = ROOT, cache_dir: Path,
                 independent_baseline: bool = False,
                 defer_mmio: bool = False,
                 initialization_seed: int = 7,
                 command_timeout_seconds: float = 10.0):
        cpu_artifact, a_artifact, b_artifact = pico_wb_artifacts(base_dir)
        self.base_dir = Path(base_dir)
        self.cache_dir = Path(cache_dir)
        self.independent_baseline = bool(independent_baseline)
        self.defer_mmio = bool(defer_mmio)
        self.initialization_seed = initialization_seed
        self._shadow_a = LocalRegisterModel() if independent_baseline else None
        self._shadow_b = LocalRegisterModel() if independent_baseline else None
        self.gpio_a = GeneratedOpentitanGpioSession(
            a_artifact, base_dir=self.base_dir, cache_dir=self.cache_dir)
        self.gpio_b = GeneratedOpentitanGpioSession(
            b_artifact, base_dir=self.base_dir, cache_dir=self.cache_dir,
            startup_writes=((INTR_ENABLE, IRQ_STARTUP_MASK),
                            (INTR_CTRL_EN_RISING, IRQ_STARTUP_MASK)))
        self.router = self._router()
        self.cpu = GeneratedWishboneCpuSession(
            cpu_artifact, base_dir=self.base_dir, cache_dir=self.cache_dir,
            memory=self._memory(), router=self.router, defer_mmio=self.defer_mmio,
            command_timeout_seconds=command_timeout_seconds)
        for session in (self.cpu, self.gpio_a, self.gpio_b):
            session.prepare_local()
        self.runner()

    def _memory(self) -> PersistentMemory:
        return PersistentMemory(
            regions=(MemoryRegion('ram', RAM_BASE, RAM_SIZE),),
            initialization_seed=self.initialization_seed,
            max_initialized_bytes=RAM_SIZE)

    def _router(self) -> DataflowRouter:
        if self.independent_baseline:
            # Comparison-only local shadow registers: no CPU observation can
            # depend on either GPIO's RTL.
            return DataflowRouter((
                DeviceWindow(GPIO_A_COMPONENT + '_local', GPIO_A_BASE,
                             GPIO_WINDOW, self._shadow_a),
                DeviceWindow(GPIO_B_COMPONENT + '_local', GPIO_B_BASE,
                             GPIO_WINDOW, self._shadow_b)))
        return DataflowRouter((
            DeviceWindow(GPIO_A_COMPONENT, GPIO_A_BASE, GPIO_WINDOW, self.gpio_a),
            DeviceWindow(GPIO_B_COMPONENT, GPIO_B_BASE, GPIO_WINDOW,
                         self.gpio_b)))

    def runner(self) -> ScenarioRunner:
        """A fresh runner over this pair, with every per-case fact reset."""
        cpu = self.cpu
        memory = self._memory()
        cpu.memory = memory
        cpu.service = MemoryService(memory, TransactionLedger())
        self.router = self._router()
        cpu.router = self.router
        cpu.mmio_write_count = 0
        cpu.mmio_read_count = 0
        cpu.memory_write_count = 0
        cpu.last_samples = ()
        if self.independent_baseline:
            # The comparison-only response model is per testcase, exactly like
            # the AXIL4-Lite row-3 fixture's local shadow.
            self._shadow_a.words.clear()
            self._shadow_b.words.clear()
        for session in (cpu, self.gpio_a, self.gpio_b):
            session.local_ticks = 0
        # A surviving GPIO sample deque would present the previous case's ticks
        # as this case's events; the runner drains it after every step.
        self.gpio_a.drain_tick_samples()
        self.gpio_b.drain_tick_samples()
        return ScenarioRunner(
            sessions={CPU_COMPONENT: cpu, GPIO_A_COMPONENT: self.gpio_a,
                      GPIO_B_COMPONENT: self.gpio_b},
            ownership=(pico_wb_independent_ownership()
                       if self.independent_baseline else pico_wb_ownership()),
            bindings=() if self.independent_baseline else pico_wb_bindings(),
            independent_baseline=self.independent_baseline)


def make_pico_wb_two_gpio_runner(*, cache_dir: Path, base_dir: Path = ROOT,
                                 direction: str | None = None,
                                 independent_baseline: bool = False):
    """One fresh pair; ``direction`` records the fixture's planned direction."""
    if direction is not None and direction not in DIRECTION_SHAPES:
        raise ValueError('unknown mutation direction')
    pair = PicoWbTwoGpioPair(base_dir=base_dir, cache_dir=cache_dir,
                             independent_baseline=independent_baseline)
    return pair.runner()
