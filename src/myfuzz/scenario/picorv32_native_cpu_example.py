"""PicoRV32 native ready/valid memory CPU with a real PULP APB3 GPIO in one loop.

This is the scenario-layer fixture for the P6 row-5
(``ready-valid-memory/1``) campaign.  The CPU side is the *real* pinned
``picorv32`` RTL driven through the generated native completion memory session
(``configs/cpus/picorv32/component_profile.json``); the IP side is the *real*
pinned PULP ``apb_gpio`` driven through its generated APB3 session
(``configs/peripherals/pulp_gpio/component_profile.json``).  The CPU's 4 KiB
device window is declared by the fixture and answered by the real GPIO through
a :class:`~myfuzz.scenario.router.DataflowRouter`.

What is new here relative to the directed native-gpio chain test
(``tests/integration/test_native_cpu_pulp_gpio_chain_real.py``)
------------------------------------------------------------------
That test proves one CPU store and one CPU load reach a real GPIO and a real
device answer returns to the CPU.  This row's campaign needs a *two-sided,
two-round, queued* loop that can be replayed case after case:

* :class:`DeferredNativeMemorySession` delivers a beat inside a declared device
  window through :meth:`DataflowRouter.enqueue` instead of
  :meth:`DataflowRouter.transact`.  The CPU therefore stalls until the target
  harness is stepped and the router completes the queued request on that
  target's own local step.  This is real queueing: the response cannot exist
  before the target ran, and the trace records a separate
  ``mmio_acceptance`` (on the CPU step) and ``mmio_delivery`` (on the device
  step).  It is an opt-in subclass: the shared
  ``GeneratedNativeMemorySession`` and every existing identity are untouched.
* The program performs **two** ordered rounds: a CPU store of its own byte to
  ``PADOUT``, a real ``PADIN`` read of the external pin byte, a RAM commit of
  the joint value ``A ^ B``, a second ``PADOUT`` store of that joint value, a
  second ``PADIN`` read and a second RAM commit.  Both declared fuzzable
  sources are therefore joint prerequisites of observed effects.
* The fixture owns no device knowledge it cannot point at: the window size, the
  register offsets and the pin semantics come from the pinned profile.

Honesty notes
-------------
* The profile is the native ``picorv32`` one: one ``processor.memory`` endpoint,
  no interrupt endpoint and no MMIO window of its own.  This fixture therefore
  synthesises no IRQ and declares no IRQ path; ``ENABLE_IRQ`` semantics of other
  PicoRV32 profiles do not apply here.
* PULP ``apb_gpio`` declares ``byte_enable: false``; a partial write fails closed
  in the device session and is never widened by this fixture.
* The device has no output-to-input loopback.  The second ``PADIN`` read must
  return the same external pin byte, not the value the CPU drove out; the
  checker asserts exactly that.
* Nothing here names an RTL signal in Python that the profiles do not declare.
"""
from __future__ import annotations

import copy
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path

from myfuzz.local_harness.native_session import GeneratedNativeMemorySession
from myfuzz.scenario.contracts import ProtocolEnvironmentError
from myfuzz.scenario.genome import Action, MemoryImage, ScenarioGenome, Trigger
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import ScenarioRunner

ROOT = Path(__file__).resolve().parents[3]

CPU_PROFILE = 'configs/cpus/picorv32/component_profile.json'
GPIO_PROFILE = 'configs/peripherals/pulp_gpio/component_profile.json'

CPU_COMPONENT = 'cpu'
GPIO_COMPONENT = 'gpio0'
#: The router window is named after the session that really answers it.
GPIO_DEVICE = GPIO_COMPONENT

#: Fixture placement of the pinned profile's 4 KiB register window.  The
#: profile declares the window size and alignment, not where a SoC places it;
#: the base is a fixture choice and is pinned by the campaign manifests.
GPIO_BASE = 0x40000000
GPIO_WINDOW = 0x1000

#: Register offsets, straight from the pinned profile's ``address.registers``.
PADDIR = 0x00
GPIOEN = 0x04
PADIN = 0x08
PADOUT = 0x0C

RAM_BASE = 0x0
RAM_SIZE = 0x1000
#: Two committed joint values plus a completion marker, all inside RAM.
RESULT_ADDRESS = 0x100
RESULT2_ADDRESS = 0x104
MARKER_ADDRESS = 0x108
MARKER_VALUE = 1

PROGRAM_IMAGE = 'cpu.program'
GPIO_INPUT = 'gpio_in'
#: Input ownership producer for the external pin byte.
GPIO_SOURCE_ID = 'external_gpio_pins'

#: The two declared fuzzable sources of this fixture.
CPU_SOURCE_ID = 'cpu.padout_byte'
IP_SOURCE_ID = 'gpio0.pin_byte'

#: Seed values of the two fuzzable sources.  ``A`` is the byte the CPU drives
#: to PADOUT in round 1; ``B`` is the byte the external world drives on
#: ``gpio_in``.  Bits 0..7 of both are the mutation units.
PADOUT_BYTE_SEED = 0x5A
GPIO_INPUT_SEED = 0x3C
SOURCE_WIDTH = 8

#: Instruction whose immediate field carries the CPU source, and the absolute
#: bit offset of the mutable low byte inside the program image.
PADOUT_IMMEDIATE_INSTRUCTION = 4
PADOUT_BYTE_BIT_OFFSET = 32 * PADOUT_IMMEDIATE_INSTRUCTION + 20

#: Steps between the CPU's store and its pin read.  One sled iteration is two
#: real instructions plus the loop branch; it gives the GPIO's two-stage input
#: synchronizer (``r_gpio_sync0``/``r_gpio_sync1``, enabled by ``GPIOEN``) many
#: more than the two clocks it needs before ``PADIN`` is read.
SLED_ITERATIONS = 12

#: Pinned Genome step budget: the runner alternates one CPU and one GPIO step,
#: the program is ~60 instructions plus two sleds, and the deferred MMIO
#: round trip costs two scheduler steps per device beat.  Measured with margin
#: against the pinned RTL by ``tests/integration/test_scenario_picorv32_native_campaign.py``.
DIRECTION_SHAPES = {'CPU_TO_IP_TO_CPU': (1200, 16), 'IP_TO_CPU_TO_IP': (1200, 16)}
BOUND_SEED_SHAPE = DIRECTION_SHAPES['CPU_TO_IP_TO_CPU']


def _imm_i(value: int) -> int:
    return value & 0xfff


def _lui(rd: int, upper: int) -> int:
    return ((upper & 0xfffff) << 12) | (rd << 7) | 0x37


def _addi(rd: int, rs1: int, immediate: int) -> int:
    return (_imm_i(immediate) << 20) | (rs1 << 15) | (rd << 7) | 0x13


def _xor(rd: int, rs1: int, rs2: int) -> int:
    return (rs2 << 20) | (rs1 << 15) | (4 << 12) | (rd << 7) | 0x33


def _add(rd: int, rs1: int, rs2: int) -> int:
    return (rs2 << 20) | (rs1 << 15) | (0 << 12) | (rd << 7) | 0x33


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


#: Register roles, fixed so the source bit offset and the checker can name them.
_WINDOW_REGISTER = 1
_MASK_REGISTER = 2
_PADOUT_REGISTER = 3
_READ1_REGISTER = 4
_MIX1_REGISTER = 5
_LOOP_REGISTER = 10
_READ2_REGISTER = 7
_MIX2_REGISTER = 8
_MARK_REGISTER = 9


def build_program(padout_byte: int = PADOUT_BYTE_SEED, *,
                  sled: int = SLED_ITERATIONS) -> bytes:
    """Assemble the pinned RV32I image this fixture fuzzes.

    Round 1: PADOUT <- A, PADIN -> CPU, RAM <- A ^ B.
    Round 2: PADOUT <- (A ^ B), PADIN -> CPU, RAM <- (A ^ B) + B, marker.
    """
    if type(padout_byte) is not int or not 0 <= padout_byte <= 0xff:
        raise ValueError('invalid padout byte')
    if type(sled) is not int or not 0 <= sled <= 0xfff:
        raise ValueError('invalid sled iterations')
    words: list[int] = []
    emit = words.append

    def sled_loop(iterations: int) -> None:
        if not iterations:
            return
        emit(_addi(_LOOP_REGISTER, 0, iterations))
        decrement = len(words)
        emit(_addi(_LOOP_REGISTER, _LOOP_REGISTER, -1))
        branch = len(words)
        emit(_bne(_LOOP_REGISTER, 0, (decrement - branch) * 4))

    emit(_lui(_WINDOW_REGISTER, GPIO_BASE >> 12))       # x1 = device window
    emit(_addi(_MASK_REGISTER, 0, -1))                  # x2 = all ones
    emit(_sw(_MASK_REGISTER, _WINDOW_REGISTER, PADDIR))  # PADDIR
    emit(_sw(_MASK_REGISTER, _WINDOW_REGISTER, GPIOEN))  # GPIOEN
    # The mutable CPU source: this addi's immediate low byte is the memory-image
    # source (index 4, absolute bits [148, 156)).
    assert len(words) == PADOUT_IMMEDIATE_INSTRUCTION, len(words)
    emit(_addi(_PADOUT_REGISTER, 0, padout_byte))       # A
    emit(_sw(_PADOUT_REGISTER, _WINDOW_REGISTER, PADOUT))  # round 1 store
    sled_loop(sled)                                     # let the pins settle
    emit(_lw(_READ1_REGISTER, _WINDOW_REGISTER, PADIN))  # B from the device
    emit(_xor(_MIX1_REGISTER, _PADOUT_REGISTER, _READ1_REGISTER))  # C1 = A ^ B
    emit(_sw(_MIX1_REGISTER, 0, RESULT_ADDRESS))        # RAM <- C1
    emit(_sw(_MIX1_REGISTER, _WINDOW_REGISTER, PADOUT))  # round 2 store
    sled_loop(sled)                                     # let the pins settle
    emit(_lw(_READ2_REGISTER, _WINDOW_REGISTER, PADIN))  # B again, never C1
    emit(_add(_MIX2_REGISTER, _MIX1_REGISTER, _READ2_REGISTER))  # C2 = C1 + B
    emit(_sw(_MIX2_REGISTER, 0, RESULT2_ADDRESS))       # RAM <- C2
    emit(_addi(_MARK_REGISTER, 0, MARKER_VALUE))
    emit(_sw(_MARK_REGISTER, 0, MARKER_ADDRESS))        # completion marker
    emit(0x0000006F)                                    # jal x0, 0
    return b''.join(word.to_bytes(4, 'little') for word in words)


def program_hex(padout_byte: int = PADOUT_BYTE_SEED, **kwargs) -> str:
    return build_program(padout_byte, **kwargs).hex()


def direction_program(direction: str) -> bytes:
    """The pinned program image of one direction.

    Both directions execute the same two rounds; only *who initiates* differs,
    and that is the action's trigger, not the program.
    """
    if direction not in DIRECTION_SHAPES:
        raise ValueError('unknown mutation direction')
    return build_program()


def direction_program_hex(direction: str) -> str:
    return direction_program(direction).hex()


def program_digest(direction: str) -> str:
    import hashlib

    return hashlib.sha256(direction_program(direction)).hexdigest()


def joint_value(padout_byte: int, pin_byte: int) -> int:
    """Round-1 committed value, as the pinned program computes it."""
    return (padout_byte ^ pin_byte) & 0xffffffff


def round_two_value(padout_byte: int, pin_byte: int) -> int:
    """Round-2 committed value ``(A ^ B) + B``, as the program computes it."""
    return (joint_value(padout_byte, pin_byte) + pin_byte) & 0xffffffff


def direction_trigger(direction: str) -> Trigger:
    """Who initiates the round: the CPU's first PADOUT store, or the IP pin."""
    if direction == 'CPU_TO_IP_TO_CPU':
        return Trigger('AFTER_OUTPUT', CPU_COMPONENT, 'data_addr',
                       mask=0xffffffff, value=GPIO_BASE + PADOUT, occurrence=1)
    if direction == 'IP_TO_CPU_TO_IP':
        return Trigger('START')
    raise ValueError('unknown mutation direction')


def make_picorv32_native_gpio_genome(direction: str) -> ScenarioGenome:
    """The pinned seed genome of one direction: both sides' sources declared."""
    if direction not in DIRECTION_SHAPES:
        raise ValueError('unknown mutation direction')
    max_steps, quiesce_steps = DIRECTION_SHAPES[direction]
    side = 'cpu' if direction == 'CPU_TO_IP_TO_CPU' else 'ip'
    return ScenarioGenome(
        testcase_id=f'pico-native-pulp-gpio-{side}-roundtrip',
        direction=direction,
        path_id=f'picorv32-native-gpio-{side}-roundtrip',
        schedule_order=(CPU_COMPONENT, GPIO_COMPONENT),
        max_steps=max_steps, quiesce_steps=quiesce_steps,
        encoding_version=3,
        actions=(Action('gpio_pin_byte', GPIO_COMPONENT, GPIO_INPUT,
                        GPIO_INPUT_SEED, direction,
                        direction_trigger(direction),
                        delay_component=GPIO_COMPONENT, delay_ticks=0,
                        bit_offset=0, width=SOURCE_WIDTH),),
        initial_images=(MemoryImage(PROGRAM_IMAGE, CPU_COMPONENT, 0,
                                    direction_program_hex(direction)),))


class DeferredNativeMemorySession(GeneratedNativeMemorySession):
    """Native completion CPU whose declared-window beats are really queued.

    The stock generated session documents that its optional router serves a
    beat *inline* ("deferred (queued) MMIO delivery is deliberately not
    implemented here").  This row needs the queued form, so this subclass
    delivers a beat inside the declared window with
    :meth:`DataflowRouter.enqueue`: the CPU keeps the single outstanding request
    open with no response until the target harness is stepped, the router
    executes the request on that target's own local step, and only its
    completion callback makes the answer available for the next CPU step.

    Only the declared-window branch changes.  RAM/ROM servicing, the handshake
    checks, the physical observation decoding and the strict service identity
    are the stock session's; ``defer_mmio=False`` selects the stock inline
    behaviour so the independent-baseline arm can be built from the same class.
    """

    #: Declared on this class because ``myfuzz.scenario.evidence`` and
    #: ``myfuzz.scenario.contracts`` read it from ``__dict__``.
    artifact_kind = 'native_memory_cpu'

    def __init__(self, artifact, *, base_dir, cache_dir, memory,
                 router: DataflowRouter, defer_mmio: bool = True, **kwargs):
        if type(defer_mmio) is not bool:
            raise ValueError('defer_mmio must be boolean')
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir,
                         memory=memory, router=router, **kwargs)
        self.defer_mmio = defer_mmio
        # The stock session admits one inline target access per local step when
        # a router is present.  A deferred beat runs its target access on the
        # target harness's own step, so this source step admits none.
        self.max_mmio_target_accesses_per_step = 0 if defer_mmio else 1
        self._queued_mmio = False

    def begin_case(self, testcase_id):
        super().begin_case(testcase_id)
        self._queued_mmio = False

    @property
    def pending_responses(self):
        # A queued request is an outstanding response even though no value is
        # available yet, and the runner's quiesce/reset accounting must see it.
        return int(super().pending_responses or self._queued_mmio)

    def _service_accepted_request(self, key, address, write, be, value):
        router = self.router
        if router is None or not self.defer_mmio:
            return super()._service_accepted_request(key, address, write, be, value)
        beat_address = address & ~3
        if not router.owns(beat_address):
            return super()._service_accepted_request(key, address, write, be, value)

        def completed(response):
            if type(response) is not tuple or len(response) != 2:
                raise ProtocolEnvironmentError('native queued target response malformed')
            self._pending = (response[0], key.source_sequence)
            self._queued_mmio = False
            if write:
                self.mmio_write_count += 1
            else:
                self.mmio_read_count += 1

        if not router.enqueue(self.service.ledger, key, address=beat_address,
                              write=bool(write), wdata=value, be=be,
                              beat_bytes=4, callback=completed):
            raise ProtocolEnvironmentError('duplicate native queued MMIO acceptance')
        self._queued_mmio = True
        return None

    def reset_local(self):
        from myfuzz.local_harness.session import GeneratedLocalSession

        cancelled = self.pending_responses
        if self._native_bus_observer is not None:
            self._native_bus_observer.cancel_reset()
        targets = ()
        if self._queued_mmio:
            targets = self.router.cancel_for_ledger(self.service.ledger)
            if len(targets) != 1:
                raise RuntimeError('queued native MMIO request was not cancelled')
            self._queued_mmio = False
        self._pending = None
        # The stock native reset is exactly this call; the base class's own
        # ``reset_local`` would recompute the cancelled count after the queue
        # was already dropped, so its accounting is reproduced here instead.
        GeneratedLocalSession.reset_local(self)
        return {'cancelled_responses': cancelled,
                'cancelled_target_requests': tuple(str(key) for key in targets)}

    def step_local(self, inputs: Mapping[str, int]):
        if not isinstance(inputs, Mapping) or inputs:
            raise ValueError('native memory CPU has no declared external inputs')
        pending = self._pending
        queued = self._queued_mmio
        controls = (self._native_request_ready(pending is None and not queued and not self._quiescing),
                    int(pending is not None), pending[0] if pending else 0, 0)
        receipt = self.command('STEP_MEMORY', controls)
        if receipt.status != 'result' or receipt.new_ticks != 1:
            self._abort()
            raise ProtocolEnvironmentError(
                'native completion fault: ' + str(receipt.error_detail))
        payload = receipt.payload
        pre = payload['pre_backend']
        names = ('m_req_ready', 'm_rsp_valid', 'm_rsp_rdata', 'm_rsp_error')
        if (any(pre[name] != value for name, value in zip(names, controls))
                or payload['samples'][0]['pre']['backend'] != pre):
            raise ProtocolEnvironmentError('native command handshake observation mismatch')
        self.last_samples = tuple(copy.deepcopy(payload['samples']))
        self._observe_verified_memory_edge(receipt)
        self._record_native_bus_receipt(receipt, pending)
        accepted = int(bool(pre['m_req_valid'] and pre['m_req_ready']))
        consumed = int(bool(pre['m_rsp_valid'] and pre['m_rsp_ready']))
        if consumed:
            if pending is None:
                raise ProtocolEnvironmentError('native response without request')
            self._pending = None
        if accepted:
            if pending is not None or queued:
                raise ProtocolEnvironmentError('native concurrent request')
            self._check_native_online_acceptance(pre,payload['samples'][0])
            address = pre['m_req_addr']
            write = pre['m_req_write']
            be = pre['m_req_be']
            value = pre['m_req_wdata']
            if address % 4 or (not write and be != self.read_request_be):
                self._abort()
                raise ProtocolEnvironmentError('native unaligned or incomplete read')
            self._sequence_memory += 1
            key = TransactionKey('local-execution', self._case_id,
                                 self.artifact.plan.request.instance_id,
                                 self.reset_epoch, 'memory', self._sequence_memory)
            try:
                response = self._service_accepted_request(key, address, write, be, value)
            except (ValueError, RuntimeError) as error:
                self._abort()
                raise ProtocolEnvironmentError(
                    'native backend error without completion') from error
            if not self._queued_mmio:
                self._pending = (response, self._sequence_memory)
            self.accepted_addresses.append(address)
            marker = self._artifact_document.get('instruction_identity_observation')
            if marker and payload['samples'][0]['pre']['physical'][marker]:
                if write:
                    self._abort()
                    raise ProtocolEnvironmentError(
                        'instruction marker accompanied a write')
                self.native_instruction_fetch_count += 1
        self.memory.advance_step()
        physical = payload['observations']['physical']
        outputs = {}
        for row in self._artifact_document['physical_exports']:
            if row['direction'] == 'output':
                raw = physical[row['runtime_name']]
                value = int(raw, 16) if row['width'] > 64 else raw
                if type(value) is not int or not 0 <= value < 1 << row['width']:
                    raise ProtocolEnvironmentError('native physical output width mismatch')
                name = row['physical_port']
                outputs[name] = outputs.get(name, 0) | (value << row['bit_lo'])
        return {**outputs, 'data_req_valid': pre['m_req_valid'],
                'data_req_accepted': accepted, 'data_write': pre['m_req_write'],
                'data_addr': pre['m_req_addr'], 'data_wdata': pre['m_req_wdata'],
                'data_be': pre['m_req_be'], 'data_rsp_consumed': consumed,
                'data_rsp_rdata': pending[0] if consumed else 0,
                'data_rsp_source_epoch': self.reset_epoch if consumed else 0,
                'data_rsp_source_sequence': pending[1] if consumed else 0,
                'driver_samples': tuple(copy.deepcopy(self.last_samples)),
                'physical_observations': copy.deepcopy(physical)}


def _artifact(profile: str, instance: str, base_dir: Path = ROOT):
    from myfuzz.local_harness import (load_local_harness_request,
                                      plan_local_harness, render_local_harness,
                                      render_local_runtime,
                                      verify_local_source_lock)
    from myfuzz.local_harness.driver_renderer import render_local_driver

    request = load_local_harness_request(dict(
        schema_version='local_harness.v1', profile_path=profile,
        instance_id=instance, reset_assert_ticks=8, reset_release_ticks=8,
        max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=base_dir)
    runtime = render_local_runtime(
        plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=base_dir),
        base_dir=base_dir)
    return render_local_driver(runtime, base_dir=base_dir)


@lru_cache(maxsize=4)
def native_gpio_artifacts(base_dir: Path = ROOT):
    """Both admitted artifacts.  Rendering is deterministic and side-effect free."""
    return (_artifact(CPU_PROFILE, CPU_COMPONENT, base_dir),
            _artifact(GPIO_PROFILE, GPIO_COMPONENT, base_dir))


def gpio_ownership():
    """The only fuzzable input of the device is the external pin byte.

    Bits 0..7 are the declared source; bits 8..31 are the fixture's constant
    zero (the device's input pads are held low).  The CPU profile declares no
    external input at all, so there is no IRQ field to own.
    """
    return compile_ownership(
        (InputField(GPIO_COMPONENT, GPIO_INPUT, 32),),
        (InputOwner(GPIO_COMPONENT, GPIO_INPUT, 0, SOURCE_WIDTH, 'source',
                    GPIO_SOURCE_ID),
         InputOwner(GPIO_COMPONENT, GPIO_INPUT, SOURCE_WIDTH,
                    32 - SOURCE_WIDTH, 'fixed', 'constant_zero')))


def picorv32_native_gpio_ownership():
    return gpio_ownership()


class PicoNativeGpioPair:
    """One admitted native CPU and PULP GPIO pair reused by every case.

    A campaign cell runs tens of cases, and admitting a generated harness costs
    a build identity check per session per case.  The pair therefore admits both
    harnesses once and hands out a fresh runner per case, while every case still
    gets exactly the declared fresh state:

    * ``begin_case`` starts a brand new RTL process for both harnesses;
    * the CPU's persistent memory is rebuilt from the genome's own images;
    * the CPU's per-case counters and the GPIO session's per-case observations
      restart at zero, and the GPIO's latched pin value returns to the constant
      zero the ownership map declares (a previous case's injected byte must not
      leak into the next case's first steps).

    Nothing about the DUT state is shared: what is shared is the admitted binary
    and the session objects that own one process at a time.
    """

    def __init__(self, cpu_artifact=None, gpio_artifact=None, *,
                 base_dir: Path = ROOT, cache_dir: Path,
                 window_base: int = GPIO_BASE, window_size: int = GPIO_WINDOW,
                 window_device: str = GPIO_DEVICE, window_target=None,
                 reset_window_target=None, independent_baseline: bool = False,
                 defer_mmio: bool = True, initialization_seed: int = 7,
                 command_timeout_seconds: float = 10.0):
        if cpu_artifact is None or gpio_artifact is None:
            cpu_artifact, gpio_artifact = native_gpio_artifacts(Path(base_dir))
        self.base_dir = Path(base_dir)
        self.cache_dir = Path(cache_dir)
        self.window_base = window_base
        self.window_size = window_size
        self.window_device = window_device
        self.independent_baseline = independent_baseline
        self.defer_mmio = defer_mmio
        self.initialization_seed = initialization_seed
        self.cpu_artifact = cpu_artifact
        self.gpio_artifact = gpio_artifact
        self.gpio = self._gpio_session()
        self._window_target = (window_target if window_target is not None
                               else lambda: self.gpio)
        self._reset_window_target = reset_window_target
        self.router = DataflowRouter((DeviceWindow(
            self.window_device, self.window_base, self.window_size,
            self._window_target()),))
        self.cpu = DeferredNativeMemorySession(
            cpu_artifact, memory=self._memory(), router=self.router,
            base_dir=self.base_dir, cache_dir=self.cache_dir,
            defer_mmio=defer_mmio,
            command_timeout_seconds=command_timeout_seconds)
        for session in (self.cpu, self.gpio):
            session.prepare_local()
        self.runner()

    def _gpio_session(self):
        from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession

        return GeneratedPulpGpioSession(self.gpio_artifact,
                                        base_dir=self.base_dir,
                                        cache_dir=self.cache_dir)

    def _memory(self):
        return PersistentMemory(
            regions=(MemoryRegion('ram', RAM_BASE, RAM_SIZE),),
            initialization_seed=self.initialization_seed,
            max_initialized_bytes=RAM_SIZE)

    def runner(self) -> ScenarioRunner:
        """A fresh runner over this pair, with every per-case counter reset."""
        cpu, gpio = self.cpu, self.gpio
        if self._reset_window_target is not None:
            self._reset_window_target()
        memory = self._memory()
        cpu.memory = memory
        cpu.service = MemoryService(memory, TransactionLedger())
        # A fresh router per case: the runner drains each router's acceptance
        # and delivery stream by list identity, so a router that survived a
        # case would re-present that case's events as new ones.  The CPU keeps
        # the per-step admission it declared when it was constructed.
        if self.defer_mmio and cpu.max_mmio_target_accesses_per_step != 0:
            raise ValueError('deferred native CPU must declare no inline target access')
        if not self.defer_mmio and cpu.max_mmio_target_accesses_per_step != 1:
            raise ValueError('inline native CPU must declare one target access per step')
        cpu.router = DataflowRouter((DeviceWindow(
            self.window_device, self.window_base, self.window_size,
            self._window_target()),))
        cpu.mmio_write_count = 0
        cpu.mmio_read_count = 0
        cpu.memory_write_count = 0
        cpu.native_instruction_fetch_count = 0
        cpu.accepted_addresses = []
        cpu.last_samples = ()
        # Per-case observation state of the stock stock GPIO session.  Its
        # ``begin_case`` restarts the RTL process but keeps the Python-side
        # latch and receipt list, so a reused session would carry a previous
        # case's pin byte and old receipts into the next trace.  The reset
        # below is the exact state a freshly constructed session reports.
        gpio.gpio_events.clear()
        # ``access_id`` and the transport receipts embed this monotonic
        # counter; a fresh session starts it at zero, so a reused one must too
        # or a replayed case would carry a different access identity.
        gpio._gpio_access_sequence = 0
        gpio._gpio_in = 0
        gpio._pin_settle_until = 0
        gpio._gpio_step_scope = None
        gpio._gpio_active_context = None
        gpio._active_gpio_input_context = None
        gpio._active_gpio_input_value = None
        gpio._next_gpio_input_context = None
        gpio._samples.clear()
        for session in (cpu, gpio):
            session.local_ticks = 0
        return ScenarioRunner(
            sessions={CPU_COMPONENT: cpu, GPIO_COMPONENT: gpio},
            ownership=gpio_ownership(), bindings=(),
            independent_baseline=self.independent_baseline)


def make_pico_native_gpio_runner(cpu_artifact=None, gpio_artifact=None, *,
                                 base_dir: Path = ROOT, cache_dir: Path,
                                 **kwargs):
    """One fresh CPU + real GPIO pair with the CPU's device window routed."""
    pair = PicoNativeGpioPair(cpu_artifact, gpio_artifact, base_dir=base_dir,
                              cache_dir=cache_dir, **kwargs)
    return pair.runner()
