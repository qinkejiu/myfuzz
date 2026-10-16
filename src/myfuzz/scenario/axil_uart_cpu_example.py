"""PicoRV32 AXI4-Lite CPU and the generic ZipCPU AXI4-Lite UART in one loop.

This is the scenario-layer fixture for the P6 row-3 (AXI4-Lite) campaign.  The
CPU side is the *real* pinned ``picorv32_axi`` RTL driven through
``GeneratedAxiLiteMemorySession`` (the generated local harness of
``configs/cpus/picorv32_axi/component_profile.json``), and the IP side is the
*real* pinned ZipCPU ``axiluart`` driven through the component-neutral
``axi4lite_register_observe`` member with a declared 8N1 serial peer
(``GeneratedAxi4LiteUartPeerSession``).  Nothing here names device semantics in
Python that the profile does not declare:

* the UART window base/size, the four register offsets and the serial format
  all come from ``configs/peripherals/zipcpu_axiluart/component_profile.json``;
* the CPU's program is an ordinary RV32I image; the instruction fetched is
  whatever the fuzzer's memory image contains;
* the TX byte is read back from *sampled RTL pin samples* by the declared 8N1
  peer, and the RX byte reaches the CPU only through the device's own AXI4-Lite
  RXREG read.

Facts that shape the program below.

* The program writes the baud divisor it wants into the declared read/write
  SETUP register before anything else, and the declared peer decodes at exactly
  that divisor.  Writing SETUP resets the UART state, which is also when the
  pinned receiver restarts the sixteen idle bit times it needs for ``line_synch``
  (see ``IDLE_BITS``).
* The declared RX frame source drives *one* frame per case (the peer refuses a
  byte change while a frame is in flight), and an AXI4-Lite access that would
  land inside the driven RX waveform is refused by the peer session.  The
  program therefore waits the whole waveform out with a fixed sled before it
  polls FIFO_STATUS and reads RXREG.
* The CPU's transmit path is real: the byte it stores to TXREG is shifted out
  by the pinned RTL and decoded by the declared peer from sampled pin levels.

The one committed value is ``tx_byte ^ rx_byte``: the CPU XORs the byte it
transmitted with the byte the device received and stores that to RAM.  That
makes both declared upstream sources genuine joint prerequisites of the value
the checker observes, instead of a sum of two independent single-source
effects.
"""
from __future__ import annotations

from functools import lru_cache
import hashlib
from pathlib import Path

from .ledger import TransactionLedger
from .memory import MemoryRegion, PersistentMemory
from .memory_service import MemoryService
from .ownership import InputField, InputOwner, compile_ownership
from .router import DataflowRouter, DeviceWindow
from .runner import ScenarioRunner
from myfuzz.local_harness.axi4lite_uart_peer_session import (
    GeneratedAxi4LiteUartPeerSession)

ROOT = Path(__file__).resolve().parents[3]

CPU_PROFILE = 'configs/cpus/picorv32_axi/component_profile.json'
UART_PROFILE = 'configs/peripherals/zipcpu_axiluart/component_profile.json'

CPU_COMPONENT = 'cpu'
UART_COMPONENT = 'uart0'
#: The router window is named after the session that really answers it.
UART_DEVICE = UART_COMPONENT

#: Declared UART window.  The base is a fixture choice (the pinned profile
#: declares the 16-byte register window, not where a SoC places it); the base
#: and size must be 4 KiB aligned and must not overlap the RAM region.
UART_BASE = 0x40000
UART_WINDOW = 0x1000

#: Register offsets and their access direction, straight from the profile's
#: ``address.registers`` list: SETUP=0 rw, FIFO_STATUS=4 ro, RXREG=8 rw (a read
#: pops the RX FIFO), TXREG=12 rw (a write pushes the TX FIFO).
UART_SETUP_OFFSET = 0x0
UART_FIFO_STATUS_OFFSET = 0x4
UART_RX_OFFSET = 0x8
UART_TX_OFFSET = 0xC
#: Bit 0 of FIFO_STATUS means "the RX FIFO can be read from", the pinned
#: ``ufifo.v`` status convention the profile's interrupt evidence quotes for
#: this device's receive FIFO.
UART_RX_READY_MASK = 0x1
#: The device's own RX-ready interrupt output, observed on the real pin.
UART_RX_INTERRUPT_PORT = 'o_uart_rx_int'

RAM_BASE = 0
RAM_SIZE = 0x8000
#: ``lui x4, 0x1`` reaches 0x1000 exactly, so the result word lives there.
RESULT_ADDRESS = 0x1000

PROGRAM_IMAGE = 'cpu.program'
UART_RX_INPUT = 'uart_rx_byte'
UART_RX_SOURCE_ID = 'serial_rx_frame'
#: Baud divisor the program writes into SETUP.  The pinned profile's reset
#: value is 25, but SETUP is a declared read/write register whose write resets
#: the UART state, so the program configures the divisor it wants and the
#: declared peer decodes at exactly that rate.  16 is the shortest frame the
#: declared peer admits (``Uart8N1Peer`` requires 16..4096 clocks per bit), and
#: it shortens both the frame and the 16-bit-time receiver synchronization the
#: pinned ``rxuart.v`` needs before it will accept a start bit.
SETUP_DIVISOR = 16
CLOCKS_PER_BIT = SETUP_DIVISOR
#: Idle bit times the declared peer drives before the start bit.  This is not a
#: free parameter: the pinned ``rxuart.v`` holds its state machine in
#: ``RXU_RESET_IDLE`` until ``line_synch`` is observed, and ``line_synch`` needs
#: ``chg_counter >= break_condition`` with ``break_condition = r_setup[23:0] << 4``
#: -- sixteen bit times of continuously idle-high line *after the last reset of
#: the receiver*.  The program's own SETUP write is such a reset (the profile
#: declares ``write_resets_uart_state``), and it lands ~24 ticks in, so the
#: start bit has to be later than 24 + 16 bit times = 280 ticks; 20 idle bits
#: puts it at ~321.
IDLE_BITS = 20

#: Seed values of the two fuzzable sources.  Bit 0 of the immediate is the
#: mutation unit, so every value below is what the seed genome declares.
TX_IMMEDIATE_SEED = 0x41
RX_FRAME_SEED = 0x5A

#: The RX waveform is ``idle_bits + 10`` bit times = 480 local ticks long,
#: starting 321 ticks after the frame source is armed, and the declared peer
#: refuses any AXI4-Lite access that would land inside it.  One sled iteration
#: is two instructions of the real pinned core and advances the core -- and,
#: because the runner steps both harnesses alternately, the device -- by about
#: seventeen local ticks (measured against the pinned RTL; the tick budget is
#: pinned by ``tests/integration/test_scenario_axil_campaign.py``), so 32
#: iterations clear the whole waveform with roughly 1.2x margin.
SLED_ITERATIONS = 32
POLL_ITERATIONS = 20

#: Pinned Genome step budget of each direction (see the campaign provider).  The
#: runner clocks one component per step, so a budget of 2N steps gives each
#: harness N local ticks; both directions need their waveform wait plus the
#: 160 ticks a transmitted byte takes to leave the pin at the declared divisor,
#: and each budget is measured against the pinned RTL with margin.
DIRECTION_SHAPES = {'CPU_TO_IP_TO_CPU': (1400, 0), 'IP_TO_CPU_TO_IP': (1700, 0)}
#: The bound manifest is this provider's CPU-direction seed.
BOUND_SEED_SHAPE = DIRECTION_SHAPES['CPU_TO_IP_TO_CPU']


def _imm_i(value: int) -> int:
    return value & 0xfff


def _lui(rd: int, upper: int) -> int:
    return ((upper & 0xfffff) << 12) | (rd << 7) | 0x37


def _addi(rd: int, rs1: int, immediate: int) -> int:
    return (_imm_i(immediate) << 20) | (rs1 << 15) | (rd << 7) | 0x13


def _andi(rd: int, rs1: int, immediate: int) -> int:
    return (_imm_i(immediate) << 20) | (rs1 << 15) | (7 << 12) | (rd << 7) | 0x13


def _xor(rd: int, rs1: int, rs2: int) -> int:
    return (rs2 << 20) | (rs1 << 15) | (4 << 12) | (rd << 7) | 0x33


def _sw(rs2: int, rs1: int, offset: int) -> int:
    return ((((offset >> 5) & 0x7f) << 25) | (rs2 << 20) | (rs1 << 15)
            | (2 << 12) | ((offset & 0x1f) << 7) | 0x23)


def _lw(rd: int, rs1: int, offset: int) -> int:
    return (_imm_i(offset) << 20) | (rs1 << 15) | (2 << 12) | (rd << 7) | 0x03


def _bne(rs1: int, rs2: int, offset: int) -> int:
    if offset % 2 or not -4096 <= offset <= 4094:
        raise ValueError('branch offset out of range')
    value = offset & 0x1fff
    return (((value >> 12) & 1) << 31 | ((value >> 5) & 0x3f) << 25
            | (rs2 << 20) | (rs1 << 15) | (1 << 12) | ((value >> 1) & 0xf) << 8
            | ((value >> 11) & 1) << 7 | 0x63)


#: Register roles of the program, fixed so the mutation source bit offset and
#: the checker's expectations can name them once.
_TX_REGISTER = 2
_MIX_REGISTER = 8
_LOOP_REGISTER = 7
_POLL_REGISTER = 9


def build_program(tx_immediate: int = TX_IMMEDIATE_SEED, *,
                  sleds: tuple[int, int] = (SLED_ITERATIONS, SLED_ITERATIONS),
                  poll_iterations: int = POLL_ITERATIONS) -> bytes:
    """Assemble the pinned RV32I image this fixture fuzzes."""
    if (not isinstance(sleds, tuple) or len(sleds) != 2
            or any(type(value) is not int or not 0 <= value <= 0xfff
                   for value in sleds)):
        raise ValueError('invalid sled iterations')
    if (type(tx_immediate) is not int or not 0 <= tx_immediate <= 0xfff
            or type(poll_iterations) is not int or not 0 <= poll_iterations <= 0xfff):
        raise ValueError('invalid program constants')
    words: list[int] = []

    def emit(word: int) -> int:
        words.append(word)
        return len(words) - 1

    def sled(iterations: int) -> None:
        if not iterations:
            return
        emit(_addi(_LOOP_REGISTER, 0, iterations))
        decrement = emit(_addi(_LOOP_REGISTER, _LOOP_REGISTER, -1))
        branch = len(words)
        emit(_bne(_LOOP_REGISTER, 0, (decrement - branch) * 4))

    emit(_lui(1, UART_BASE >> 12))                     # x1 = UART window base
    emit(_addi(6, 0, SETUP_DIVISOR))                   # x6 = declared divisor
    emit(_sw(6, 1, UART_SETUP_OFFSET))                 # SETUP <- divisor
    # The mutable TX byte: this addi's immediate field is the memory-image
    # source the campaign mutates (bits [20, 28) of this word).
    emit(_addi(_TX_REGISTER, 0, tx_immediate))
    sled(sleds[0])                                     # wait out any RX waveform
    emit(_sw(_TX_REGISTER, 1, UART_TX_OFFSET))         # CPU -> IP: TXREG = A
    sled(sleds[1])                                     # let A leave the pin
    emit(_addi(_POLL_REGISTER, 0, poll_iterations))
    poll = emit(_lw(5, 1, UART_FIFO_STATUS_OFFSET))    # FIFO_STATUS
    emit(_andi(5, 5, UART_RX_READY_MASK))
    ready_branch = emit(_bne(5, 0, 0))                 # to `ready`
    emit(_addi(_POLL_REGISTER, _POLL_REGISTER, -1))
    emit(_bne(_POLL_REGISTER, 0, (poll - (len(words))) * 4))
    ready = len(words)
    words[ready_branch] = _bne(5, 0, (ready - ready_branch) * 4)
    emit(_lw(3, 1, UART_RX_OFFSET))                    # IP -> CPU: RXREG = Y
    emit(_xor(_MIX_REGISTER, _TX_REGISTER, 3))         # A ^ Y
    emit(_lui(4, RESULT_ADDRESS >> 12))                # x4 = 0x1000
    emit(_sw(_MIX_REGISTER, 4, RESULT_ADDRESS & 0xfff))  # RAM commit of A ^ Y
    emit(0x0000006F)                                   # jal x0, 0
    return b''.join(word.to_bytes(4, 'little') for word in words)


def program_hex(tx_immediate: int = TX_IMMEDIATE_SEED, **kwargs) -> str:
    return build_program(tx_immediate, **kwargs).hex()


#: Per-direction sled budgets.  The wait exists only to keep every AXI4-Lite
#: access out of the driven RX waveform, and which wait is needed follows from
#: who arms the frame source:
#:
#: * CPU direction - the source is armed by the CPU's own TXREG store, so the
#:   waveform starts at that store and only the *following* access has to wait
#:   it out.
#: * IP direction - the source is armed at case start, so the CPU's first
#:   access has to wait the waveform out, and the RX answer is already in the
#:   device's FIFO by the time the CPU polls for it.
DIRECTION_SLEDS = {
    'CPU_TO_IP_TO_CPU': (0, SLED_ITERATIONS),
    'IP_TO_CPU_TO_IP': (SLED_ITERATIONS, 0),
}


def direction_program(direction: str) -> bytes:
    """The pinned program image of one direction (its own sled budget)."""
    if direction not in DIRECTION_SLEDS:
        raise ValueError('unknown mutation direction')
    return build_program(TX_IMMEDIATE_SEED, sleds=DIRECTION_SLEDS[direction])


def direction_program_hex(direction: str) -> str:
    return direction_program(direction).hex()


def program_digest(direction: str) -> str:
    return hashlib.sha256(direction_program(direction)).hexdigest()


#: Absolute bit offset of the mutable TX immediate inside the program image:
#: instruction index 3, immediate bits [20, 28).
TX_IMMEDIATE_INSTRUCTION = 3
TX_IMMEDIATE_BIT_OFFSET = 32 * TX_IMMEDIATE_INSTRUCTION + 20
TX_IMMEDIATE_WIDTH = 8


def _cpu_artifact(base_dir: Path = ROOT):
    from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
                                      render_local_harness, render_local_runtime,
                                      verify_local_source_lock)
    from myfuzz.local_harness.driver_renderer import render_local_driver

    request = load_local_harness_request(dict(
        schema_version='local_harness.v1', profile_path=CPU_PROFILE,
        instance_id=CPU_COMPONENT, reset_assert_ticks=8, reset_release_ticks=8,
        max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=base_dir)
    runtime = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=base_dir), base_dir=base_dir)
    return render_local_driver(runtime, base_dir=base_dir)


def _uart_artifact(base_dir: Path = ROOT, *, peer: bool = True):
    from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
                                      render_local_harness, render_local_runtime,
                                      verify_local_source_lock)
    from myfuzz.local_harness.driver_renderer import render_local_driver

    tuning: dict = {'endpoint_policies': [dict(
        endpoint_id='uart.bus', template_id='target.axi4-lite',
        template_version='1', variant_id='single-outstanding-error-codes',
        max_outstanding=1)]}
    if peer:
        # The RX pin is owned by the declared frame source and the CTS pin is
        # the profile's declared inactive constant; both are declared facts of
        # the pinned profile, not Python-side device knowledge.
        tuning['fixed_inputs'] = [dict(endpoint_id='uart.pins', role='cts_n',
                                       value=0)]
        tuning['environment_bindings'] = [dict(endpoint_id='uart.pins', role='rx',
                                              source_id=UART_RX_SOURCE_ID)]
        tuning['uart_8n1_peers'] = [dict(endpoint_id='uart.pins', rx_role='rx',
                                         tx_role='tx', source_id=UART_RX_SOURCE_ID,
                                         format='8N1', clocks_per_bit=CLOCKS_PER_BIT,
                                         idle_bits=IDLE_BITS)]
    request = load_local_harness_request(dict(
        schema_version='local_harness.v2', profile_path=UART_PROFILE,
        instance_id=UART_COMPONENT, reset_assert_ticks=8, reset_release_ticks=8,
        max_wait_cycles=16, tuning=tuning))
    plan = plan_local_harness(request, base_dir=base_dir)
    runtime = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=base_dir), base_dir=base_dir)
    return render_local_driver(runtime, base_dir=base_dir)


@lru_cache(maxsize=4)
def axil_artifacts(base_dir: Path = ROOT):
    """Both admitted artifacts.  Rendering is deterministic and side-effect free."""
    return _cpu_artifact(base_dir), _uart_artifact(base_dir)


class AxilUartPeerSession(GeneratedAxi4LiteUartPeerSession):
    """The generic AXI4-Lite register member with its declared 8N1 peer.

    Two thin adjustments, both of which only re-state behaviour the parent
    member already documents; no RTL observation is added, replaced or
    weakened.

    * ``artifact_kind`` is declared here because ``myfuzz.scenario.evidence``
      reads that attribute from the class ``__dict__`` to derive the declared
      per-command evidence bound of a generated session, and the peer member
      inherits it rather than declaring it.
    * ``drain_tick_samples`` re-aligns the parent's TX observation cursor.  The
      parent keeps a monotonic cursor into its own sample deque and advances it
      in ``_observe_tx``; ``ScenarioRunner`` drains that deque after *every*
      step, so a surviving cursor points past the end of the next batch, every
      later one-tick sample is silently skipped, and the ticks that do reach
      the declared peer have holes wide enough to raise ``invalid observed
      UART 8N1 frame``.  Under a runner the parent member therefore cannot
      decode a transmitted byte at all.  Resetting the cursor to the drained
      (empty) deque restores the parent's documented behaviour: every sample
      this session collected is fed to the declared peer exactly once, in
      order.
    """

    artifact_kind = 'axi4lite_register_observe'

    def drain_tick_samples(self):
        samples = super().drain_tick_samples()
        self._observed_samples = 0
        return samples


def _uart_session(uart_artifact, *, base_dir: Path, cache_dir: Path):
    """Admit the artifact through the registered factory, then use the member.

    ``create_generated_register_session`` is the single place that re-derives
    the declared peer from the artifact's own tuning and refuses a peer whose
    artifact document disagrees with it.  The returned session's public
    attributes are that admitted declaration, so the subclass below is built
    from facts the factory has already validated rather than from Python-side
    assumptions about this device.
    """
    from myfuzz.local_harness.generated_register_factory import (
        create_generated_register_session)

    admitted = create_generated_register_session(
        uart_artifact, base_dir=base_dir, cache_dir=cache_dir)
    if type(admitted) is not GeneratedAxi4LiteUartPeerSession:
        raise ValueError('AXI4-Lite UART fixture requires the declared 8N1 peer member')
    return AxilUartPeerSession(
        uart_artifact, base_dir=base_dir, cache_dir=cache_dir,
        rx_port=admitted.rx_port, tx_port=admitted.tx_port,
        source_id=admitted.source_id, clocks_per_bit=admitted.peer.clocks_per_bit,
        idle_bits=admitted.idle_bits, setup_writes=admitted.setup_writes)


def axil_uart_session(uart_artifact, *, base_dir: Path = ROOT, cache_dir: Path):
    """The declared generic AXI4-Lite member with this device's declared peer."""
    return _uart_session(uart_artifact, base_dir=base_dir, cache_dir=cache_dir)


def axil_cpu_session(cpu_artifact, *, memory, router, base_dir: Path = ROOT,
                     cache_dir: Path, command_timeout_seconds: float = 10.0):
    """The real pinned PicoRV32 AXI4-Lite CPU over persistent host memory.

    ``defer_mmio`` is declared false on the instance because this session
    answers a routed beat inline, in the same step that accepted it (the
    generated memory session reserves exactly one target access per step); the
    runner consults that declaration when an independent-baseline arm points
    the CPU at a comparison-only local shadow window.
    """
    from myfuzz.local_harness.axi_lite_session import GeneratedAxiLiteMemorySession

    session = GeneratedAxiLiteMemorySession(
        cpu_artifact, base_dir=base_dir, cache_dir=cache_dir, memory=memory,
        router=router, command_timeout_seconds=command_timeout_seconds)
    session.defer_mmio = False
    return session


def axil_uart_ownership():
    """Ownership of the only declared fuzzable input of this fixture.

    The peer member accepts exactly one scenario input, the abstract frame
    source ``uart_rx_byte`` (its own ``validate_scenario_ownership`` refuses
    anything else), and the CPU's generated memory session declares no
    external input at all because the pinned profile holds ``irq`` at its
    declared constant inactive value.
    """
    return compile_ownership(
        (InputField(UART_COMPONENT, UART_RX_INPUT, 8),),
        (InputOwner(UART_COMPONENT, UART_RX_INPUT, 0, 8, 'source',
                    UART_RX_SOURCE_ID),))


def make_axil_uart_cpu_runner(cpu_artifact=None, uart_artifact=None, *,
                             base_dir: Path = ROOT, cache_dir: Path,
                             command_timeout_seconds: float = 10.0):
    """One fresh CPU + real UART pair with the CPU's MMIO routed into the IP."""
    if cpu_artifact is None or uart_artifact is None:
        cpu_artifact, uart_artifact = axil_artifacts(base_dir)
    pair = AxilUartCpuPair(cpu_artifact, uart_artifact, base_dir=base_dir,
                           cache_dir=cache_dir,
                           command_timeout_seconds=command_timeout_seconds)
    return pair.runner()


class AxilUartCpuPair:
    """One admitted AXI4-Lite CPU and IP pair reused by every case of a run.

    A campaign cell executes tens of cases, and admitting a generated local
    harness costs a full build identity check per session per case (host
    closure, toolchain and every input byte).  This pair therefore admits both
    harnesses once and hands out a new runner per case, while each case still
    gets exactly the declared fresh state:

    * ``begin_case`` starts a brand new RTL process for both harnesses (the
      previous one is reaped by ``end_case`` in ``ScenarioRunner.finalize``);
    * the CPU's persistent memory is rebuilt from the genome's own images, so
      no RAM byte, generation or commit sequence survives into the next case;
    * per-case tick counters and the fixture's own observation counters restart
      at zero, matching what a freshly constructed session reports.

    Nothing about the DUT state is shared: what is shared is the admitted
    binary and the session objects that own one process at a time.
    """

    def __init__(self, cpu_artifact=None, uart_artifact=None, *,
                 base_dir: Path = ROOT, cache_dir: Path,
                 command_timeout_seconds: float = 10.0,
                 window_base: int = UART_BASE, window_size: int = UART_WINDOW,
                 window_device: str = UART_DEVICE, window_target=None,
                 reset_window_target=None,
                 independent_baseline: bool = False,
                 initialization_seed: int = 7):
        if cpu_artifact is None or uart_artifact is None:
            cpu_artifact, uart_artifact = axil_artifacts(base_dir)
        self.base_dir = Path(base_dir)
        self.cache_dir = Path(cache_dir)
        self.window_base = window_base
        self.window_size = window_size
        self.window_device = window_device
        self.independent_baseline = independent_baseline
        self.initialization_seed = initialization_seed
        self.uart = axil_uart_session(uart_artifact, base_dir=self.base_dir,
                                      cache_dir=self.cache_dir)
        self._window_target = (window_target if window_target is not None
                               else lambda: self.uart)
        self._reset_window_target = reset_window_target
        # The CPU session is constructed *with* its router so the generated
        # session itself declares the cost of an inline routed access
        # (``max_mmio_target_accesses_per_step = 1``); the runner's tick-bound
        # guard then checks the fixture's real per-step clock advance instead
        # of a number restated here.
        self.router = DataflowRouter((DeviceWindow(
            self.window_device, self.window_base, self.window_size,
            self._window_target()),))
        self.cpu = axil_cpu_session(
            cpu_artifact, memory=self._memory(), router=self.router,
            base_dir=self.base_dir, cache_dir=self.cache_dir,
            command_timeout_seconds=command_timeout_seconds)
        # Admit both harness binaries now, outside every testcase wall clock.
        for session in (self.cpu, self.uart):
            session.prepare_local()
        self.runner()

    def _memory(self):
        return PersistentMemory(
            regions=(MemoryRegion('ram', RAM_BASE, RAM_SIZE),),
            initialization_seed=self.initialization_seed,
            max_initialized_bytes=RAM_SIZE)

    def runner(self) -> ScenarioRunner:
        """A fresh runner over this pair, with every per-case counter reset."""
        cpu, uart = self.cpu, self.uart
        if self._reset_window_target is not None:
            self._reset_window_target()
        memory = self._memory()
        cpu.memory = memory
        cpu.service = MemoryService(memory, TransactionLedger())
        # A fresh router per case: the runner drains each router's delivery
        # stream by list identity, so a router that survived a case would
        # re-present that case's deliveries as new events.  The CPU session
        # keeps the inline-access declaration it made when it was constructed
        # with a router; this fixture refuses to run without it rather than
        # restating the bound.
        if cpu.max_mmio_target_accesses_per_step != 1:
            raise ValueError(
                'routed AXI4-Lite CPU must declare one inline target access per step')
        cpu.router = DataflowRouter((DeviceWindow(
            self.window_device, self.window_base, self.window_size,
            self._window_target()),))
        cpu.mmio_write_count = 0
        cpu.mmio_read_count = 0
        cpu.memory_write_count = 0
        cpu.native_instruction_fetch_count = 0
        cpu.accepted_addresses = []
        cpu.last_samples = ()
        for session in (cpu, uart):
            session.local_ticks = 0
        return ScenarioRunner(
            sessions={CPU_COMPONENT: cpu, UART_COMPONENT: uart},
            ownership=axil_uart_ownership(), bindings=(),
            independent_baseline=self.independent_baseline)
