"""Fixed-instance VexiiRiscv CPU + PULP GPIO chain with a real IRQ ISR round.

This is one fixed instance of two independently built real RTL harnesses:

* the pinned generated ``vexiiriscv_irq`` CPU (the authenticated baseline
  generated RTL plus the declared delta that exposes its real
  ``int_m_external`` pin), whose reduced single-beat AXI4 LSU transfers inside
  the router's window become real APB3 register accesses;
* the pinned PULP ``apb_gpio`` target, which is the real register file and the
  real external interrupt source.

Per round the CPU writes ``PADOUTSET``; the GPIO's own synchronized input
(loopback of its real ``gpio_out`` output, declared below) produces its real
``interrupt`` pulse; the host wire holds that pulse as a level on the core's
real ``int_m_external`` input; the core takes its own trap and fetches from the
``mtvec`` the program installed; the ISR reads ``PADOUT`` and ``INTSTATUS``,
writes ``PADOUTCLR``, stores its observations to RAM and returns with ``mret``;
the main program reads the ISR result from RAM, checks it against the value it
wrote, and starts the next round.

Honesty notes
-------------
* The host is an *interrupt delivery wire*, not an interrupt decision: it only
  converts the GPIO's one-cycle real pulse into the level the core requires and
  drops the level after the ISR's actual ``PADOUTCLR`` APB write is delivered.
  The trap, the vector fetch, the ISR body and ``mret`` are the core's own
  behaviour; no trap, cause or vector is injected anywhere.
* The GPIO's ``interrupt`` output is a transition pulse (profile evidence), and
  the core's entry is level-sensitive; pulse-to-level conversion is this
  scenario's declared host adapter, recorded per event with both component
  ticks.
* The two RTL processes advance on their own clocks. One host round issues one
  CPU edge, then any target APB transaction the CPU accepted, then one GPIO
  edge. An APB transaction itself advances the GPIO by its own real edges, so
  ticks are reported per component and never presented as one shared cycle.
* The program image is fixed per row; per-round data comes from a preloaded RAM
  table. There is no online genome mutation, coverage feedback or arbitrary
  saved-run replay here, and this row is not the P6 campaign framework.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, is_dataclass
import hashlib
import json
from pathlib import Path

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
                                  render_local_driver, render_local_harness,
                                  render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.build import build_local_harness
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.local_harness.vexii_axi_session import GeneratedReducedAxiIrqCpuSession
from .memory import MemoryRegion, PersistentMemory
from .router import DataflowRouter, DeviceWindow

ROOT = Path(__file__).resolve().parents[3]
CPU_PROFILE = 'configs/cpus/vexiiriscv_irq/component_profile.json'
GPIO_PROFILE = 'configs/peripherals/pulp_gpio/component_profile.json'

BOOT = 0x80000000
ISR_ADDRESS = 0x80000200
GPIO_BASE = 0x40000000
GPIO_WINDOW = 0x1000
RAM_SIZE = 0x100000
DONE_MARK = 0x600D

#: RAM words the fixed program and this scenario agree on.
VALUE_ADDRESS = 0x80001000
INDEX_ADDRESS = 0x80001004
FLAG_ADDRESS = 0x80001008
DONE_ADDRESS = 0x80001010
TABLE_ADDRESS = 0x80001100
RESULT_ADDRESS = 0x80001200
STATUS_ADDRESS = 0x80001300
CHECK_ADDRESS = 0x80001400

#: Pinned PULP apb_gpio register offsets used by the program (profile address map).
REG_PADOUT = 12
REG_PADOUTSET = 16
REG_PADOUTCLR = 20
REG_GPIOEN = 4
REG_INTEN = 24
REG_INTTYPE_LOW = 28
REG_INTSTATUS = 36

PAD0 = 0x1
PADOUTCLR_ALL = 0xFFFFFFFF
GPIOEN_ALL = 0xFFFFFFFF
INTEN_PAD0 = 0x1
INTTYPE_RISE_PAD0 = 0x1

CSR_MSTATUS = 0x300
CSR_MIE = 0x304
CSR_MTVEC = 0x305
MIE_MEIE = 0x800
MSTATUS_MIE = 0x8

#: Default row: eight distinct pad0 values. The program always sets pad0, so
#: the driven word is ``value | 1``; the defaults stay distinct after that OR.
DEFAULT_CASES = (0x11, 0x22, 0x33, 0x5A, 0xA5, 0x123, 0x3FF, 0x7F)
MAX_CASES = 16
MAX_HOST_ROUNDS = 4000

SCHEMA = 'vexi_pulp_gpio_irq_fixed_row.v1'


def _signed_12(value: int) -> int:
    value &= 0xFFF
    return value - 0x1000 if value & 0x800 else value


class _ProgramAssembler:
    """Minimal two-pass RV32I encoder for exactly this program's instructions."""

    def __init__(self) -> None:
        self.words: list[int] = []
        self.labels: dict[str, int] = {}
        self.fixups: list[tuple[str, int, tuple[int, ...], str]] = []

    def label(self, name: str) -> None:
        if name in self.labels:
            raise ValueError('duplicate program label')
        self.labels[name] = len(self.words)

    def _i(self, imm: int, rs1: int, funct3: int, rd: int, opcode: int) -> None:
        value = imm & 0xFFF
        self.words.append(((value >> 5) << 25) | ((value & 0x1F) << 20)
                          | ((rs1 & 31) << 15) | (funct3 << 12)
                          | ((rd & 31) << 7) | opcode)

    def _s(self, imm: int, rs2: int, rs1: int, funct3: int, opcode: int) -> None:
        value = imm & 0xFFF
        self.words.append(((value >> 5) << 25) | ((rs2 & 31) << 20)
                          | ((rs1 & 31) << 15) | (funct3 << 12)
                          | ((value & 0x1F) << 7) | opcode)

    def _r(self, rd: int, rs1: int, rs2: int, funct3: int, funct7: int) -> None:
        self.words.append(((funct7 & 0x7F) << 25) | ((rs2 & 31) << 20)
                          | ((rs1 & 31) << 15) | (funct3 << 12)
                          | ((rd & 31) << 7) | 0x33)

    def lui(self, rd: int, imm20: int) -> None:
        self.words.append(((imm20 & 0xFFFFF) << 12) | ((rd & 31) << 7) | 0x37)

    def addi(self, rd: int, rs1: int, imm: int) -> None:
        self._i(imm, rs1, 0b000, rd, 0x13)

    def ori(self, rd: int, rs1: int, imm: int) -> None:
        self._i(imm, rs1, 0b110, rd, 0x13)

    def slli(self, rd: int, rs1: int, shamt: int) -> None:
        if not 0 <= shamt < 32:
            raise ValueError('shift amount')
        self._i(shamt, rs1, 0b001, rd, 0x13)

    def xor(self, rd: int, rs1: int, rs2: int) -> None:
        self._r(rd, rs1, rs2, 0b100, 0x00)

    def add(self, rd: int, rs1: int, rs2: int) -> None:
        self._r(rd, rs1, rs2, 0b000, 0x00)

    def lw(self, rd: int, rs1: int, imm: int) -> None:
        self._i(imm, rs1, 0b010, rd, 0x03)

    def sw(self, rs2: int, rs1: int, imm: int) -> None:
        self._s(imm, rs2, rs1, 0b010, 0x23)

    def csrw(self, csr: int, rs1: int) -> None:
        self._i(csr, rs1, 0b001, 0, 0x73)

    def csrs(self, csr: int, rs1: int) -> None:
        self._i(csr, rs1, 0b010, 0, 0x73)

    def mret(self) -> None:
        self.words.append((0x302 << 20) | 0x73)

    def jal(self, rd: int, label: str) -> None:
        self.fixups.append(('jal', len(self.words), (rd,), label))
        self.words.append(0)

    def beq(self, rs1: int, rs2: int, label: str) -> None:
        self.fixups.append(('branch', len(self.words), (rs1, rs2, 0b000), label))
        self.words.append(0)

    def blt(self, rs1: int, rs2: int, label: str) -> None:
        self.fixups.append(('branch', len(self.words), (rs1, rs2, 0b100), label))
        self.words.append(0)

    def li32(self, rd: int, value: int) -> None:
        value &= 0xFFFFFFFF
        if value >= 0x1000:
            high = ((value + 0x800) >> 12) & 0xFFFFF
            self.lui(rd, high)
            self.addi(rd, rd, _signed_12(value - (high << 12)))
            return
        self.addi(rd, 0, value)

    def finish(self) -> list[int]:
        for kind, index, operands, label in self.fixups:
            if label not in self.labels:
                raise ValueError('unknown program label:' + label)
            offset = (self.labels[label] - index) * 4
            if kind == 'jal':
                value = offset & 0x1FFFFF
                word = (((value >> 20) & 1) << 31) | (((value >> 1) & 0x3FF) << 21) \
                    | (((value >> 11) & 1) << 20) | (((value >> 12) & 0xFF) << 12) \
                    | ((operands[0] & 31) << 7) | 0x6F
            else:
                value = offset & 0x1FFF
                word = (((value >> 12) & 1) << 31) | (((value >> 5) & 0x3F) << 25) \
                    | ((operands[1] & 31) << 20) | ((operands[0] & 31) << 15) \
                    | (operands[2] << 12) | (((value >> 1) & 0xF) << 8) \
                    | (((value >> 11) & 1) << 7) | 0x63
            self.words[index] = word
        return list(self.words)


def _main_words(cases: int) -> list[int]:
    asm = _ProgramAssembler()
    asm.li32(18, GPIO_BASE)
    asm.li32(19, VALUE_ADDRESS)
    asm.li32(21, TABLE_ADDRESS)
    asm.li32(24, RESULT_ADDRESS)
    asm.li32(25, STATUS_ADDRESS)
    asm.li32(27, ISR_ADDRESS)
    asm.csrw(CSR_MTVEC, 27)
    asm.li32(27, MIE_MEIE)
    asm.csrw(CSR_MIE, 27)
    asm.li32(27, MSTATUS_MIE)
    asm.csrs(CSR_MSTATUS, 27)
    asm.li32(22, GPIOEN_ALL)
    asm.sw(22, 18, REG_GPIOEN)
    asm.li32(22, INTEN_PAD0)
    asm.sw(22, 18, REG_INTEN)
    asm.sw(22, 18, REG_INTTYPE_LOW)
    asm.li32(22, PADOUTCLR_ALL)
    asm.sw(22, 18, REG_PADOUTCLR)
    asm.li32(20, 0)
    asm.li32(28, cases)
    asm.label('round')
    asm.lw(22, 21, 0)
    asm.ori(22, 22, PAD0)
    asm.sw(22, 19, 0)
    asm.sw(20, 19, INDEX_ADDRESS - VALUE_ADDRESS)
    asm.sw(0, 19, FLAG_ADDRESS - VALUE_ADDRESS)
    asm.sw(22, 18, REG_PADOUTSET)
    asm.label('wait')
    asm.lw(23, 19, FLAG_ADDRESS - VALUE_ADDRESS)
    asm.beq(23, 0, 'wait')
    asm.slli(23, 20, 2)
    asm.add(23, 24, 23)
    asm.lw(23, 23, 0)
    asm.xor(23, 23, 22)
    asm.li32(30, CHECK_ADDRESS)
    asm.slli(29, 20, 2)
    asm.add(30, 30, 29)
    asm.sw(23, 30, 0)
    asm.addi(21, 21, 4)
    asm.addi(20, 20, 1)
    asm.blt(20, 28, 'round')
    asm.li32(22, DONE_MARK)
    asm.sw(22, 19, DONE_ADDRESS - VALUE_ADDRESS)
    asm.label('done')
    asm.jal(0, 'done')
    return asm.finish()


def _isr_words() -> list[int]:
    asm = _ProgramAssembler()
    asm.lui(5, GPIO_BASE >> 12)
    asm.lw(6, 5, REG_PADOUT)
    asm.lw(7, 5, REG_INTSTATUS)
    asm.li32(9, VALUE_ADDRESS)
    asm.lw(11, 9, INDEX_ADDRESS - VALUE_ADDRESS)
    asm.slli(11, 11, 2)
    asm.li32(10, RESULT_ADDRESS)
    asm.add(10, 10, 11)
    asm.sw(6, 10, 0)
    asm.li32(10, STATUS_ADDRESS)
    asm.add(10, 10, 11)
    asm.sw(7, 10, 0)
    asm.li32(7, PADOUTCLR_ALL)
    asm.sw(7, 5, REG_PADOUTCLR)
    asm.li32(7, 1)
    asm.sw(7, 9, FLAG_ADDRESS - VALUE_ADDRESS)
    asm.mret()
    return asm.finish()


def validate_cases(cases: object) -> tuple[int, ...]:
    if (not isinstance(cases, Sequence) or isinstance(cases, (str, bytes))
            or not cases or len(cases) > MAX_CASES):
        raise ValueError('cases-must-be-a-nonempty-bounded-sequence')
    values = tuple(cases)
    for value in values:
        if type(value) is not int or not 0 <= value < 1 << 32:
            raise ValueError('case-value-must-be-a-uint32')
    driven = tuple(value | PAD0 for value in values)
    if len(set(driven)) != len(driven):
        raise ValueError('case-values-must-stay-distinct-after-pad0')
    return values


def build_program_image(cases: Iterable[int]) -> dict[str, object]:
    """Return the exact initial RAM image and its auditable instruction words."""
    values = validate_cases(cases)
    main = _main_words(len(values))
    isr = _isr_words()
    main_bytes = b''.join(word.to_bytes(4, 'little') for word in main)
    isr_bytes = b''.join(word.to_bytes(4, 'little') for word in isr)
    if BOOT + len(main_bytes) > ISR_ADDRESS:
        raise ValueError('main program overlaps the trap vector')
    image = bytearray()
    image += main_bytes
    image += bytes(ISR_ADDRESS - (BOOT + len(main_bytes)))
    image += isr_bytes
    if ISR_ADDRESS + len(isr_bytes) > TABLE_ADDRESS:
        raise ValueError('ISR overlaps the case table')
    image += bytes(TABLE_ADDRESS - (ISR_ADDRESS + len(isr_bytes)))
    for value in values:
        image += (value & 0xFFFFFFFF).to_bytes(4, 'little')
    return {
        'schema_version': 'vexi_pulp_gpio_irq_program.v1',
        'entry': BOOT,
        'isr_address': ISR_ADDRESS,
        'mtvec_value': ISR_ADDRESS,
        'case_table_address': TABLE_ADDRESS,
        'value_address': VALUE_ADDRESS,
        'index_address': INDEX_ADDRESS,
        'flag_address': FLAG_ADDRESS,
        'done_address': DONE_ADDRESS,
        'result_address': RESULT_ADDRESS,
        'status_address': STATUS_ADDRESS,
        'check_address': CHECK_ADDRESS,
        'done_mark': DONE_MARK,
        'register_offsets': {
            'gpioen': REG_GPIOEN, 'inten': REG_INTEN,
            'inttype_low': REG_INTTYPE_LOW, 'padout': REG_PADOUT,
            'padoutset': REG_PADOUTSET, 'padoutclr': REG_PADOUTCLR,
            'intstatus': REG_INTSTATUS},
        'main_words': main,
        'isr_words': isr,
        'cases': list(values),
        'driven_values': [value | PAD0 for value in values],
        'image_length': len(image),
        'image_sha256': hashlib.sha256(image).hexdigest(),
        'image': bytes(image),
    }


def _render_artifact(profile_path: str, instance_id: str) -> object:
    request = load_local_harness_request(dict(
        schema_version='local_harness.v1', profile_path=profile_path,
        instance_id=instance_id, reset_assert_ticks=12, reset_release_ticks=8,
        max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    structural = render_local_harness(plan)
    verified = verify_local_source_lock(plan.profile, base_dir=ROOT)
    runtime = render_local_runtime(plan, structural, verified, base_dir=ROOT)
    return render_local_driver(runtime, base_dir=ROOT)


def _gpio_artifact() -> object:
    # The two-edge raw tick stream attributes an individual GPIO ``interrupt``
    # pulse to one edge instead of a summary level.
    request = load_local_harness_request(dict(
        schema_version='local_harness.v2', profile_path=GPIO_PROFILE,
        instance_id='gpio', reset_assert_ticks=8, reset_release_ticks=8,
        max_wait_cycles=16,
        tuning={'raw_tick_stream': [{'sampling': 'pre_post'}]}))
    plan = plan_local_harness(request, base_dir=ROOT)
    structural = render_local_harness(plan)
    verified = verify_local_source_lock(plan.profile, base_dir=ROOT)
    runtime = render_local_runtime(plan, structural, verified, base_dir=ROOT)
    return render_local_driver(runtime, base_dir=ROOT)


def chain_artifacts() -> dict[str, object]:
    return {'cpu': _render_artifact(CPU_PROFILE, 'cpu'), 'gpio': _gpio_artifact()}


def _digest(document: object) -> str:
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def _jsonable(value: object) -> object:
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    raise TypeError('evidence value is not JSON serializable: ' + type(value).__name__)


def _artifact_summary(artifact: object) -> dict[str, object]:
    runtime = artifact.runtime_document
    return {'runtime_artifact_digest': runtime['artifact_digest'],
            'kind': runtime['kind'],
            'profile_sha256': artifact.plan.profile_sha256,
            'source_revision': artifact.plan.facts.revision,
            'driver_field_map': dict(runtime.get('driver_field_map') or {}),
            'physical_exports': json.loads(json.dumps(runtime.get('physical_exports') or []))}


class VexiiPulpGpioIrqFixedChain:
    """One fixed CPU+GPIO instance; each ``run`` executes the whole case row."""

    def __init__(self, *, base_dir: Path = ROOT, cache_dir: Path,
                 cases: Iterable[int] = DEFAULT_CASES):
        self.base_dir = Path(base_dir).resolve()
        self.cache_dir = Path(cache_dir).resolve()
        self.cases = validate_cases(tuple(cases))
        self.program = build_program_image(self.cases)
        artifacts = chain_artifacts()
        self.artifacts = artifacts
        self.binaries = {
            name: str(build_local_harness(artifact, base_dir=self.base_dir,
                                          cache_dir=self.cache_dir))
            for name, artifact in artifacts.items()}
        self._executed = False

    # -- one row -----------------------------------------------------------
    def run(self, testcase_id: str) -> dict[str, object]:
        if self._executed:
            raise RuntimeError('one fixed chain instance executes one row')
        self._executed = True
        if type(testcase_id) is not str or not testcase_id:
            raise ValueError('testcase id')
        program = self.program
        image = program['image']
        assert isinstance(image, bytes)
        memory = PersistentMemory(
            regions=(MemoryRegion('ram', BOOT, RAM_SIZE),),
            initialization_seed=0, max_initialized_bytes=0x10000)
        memory.preload(BOOT, image)
        gpio = GeneratedPulpGpioSession(
            self.artifacts['gpio'], base_dir=self.base_dir, cache_dir=self.cache_dir,
            command_timeout_seconds=120)
        gpio.configure_ordinary_apb_access_receipts(max_records=256)
        router = DataflowRouter((DeviceWindow('gpio', GPIO_BASE, GPIO_WINDOW, gpio),))
        cpu = GeneratedReducedAxiIrqCpuSession(
            self.artifacts['cpu'], base_dir=self.base_dir, cache_dir=self.cache_dir,
            memory=memory, mmio_router=router, command_timeout_seconds=120)
        host_events: list[dict[str, object]] = []
        cpu_samples: list[dict[str, object]] = []
        gpio_samples: list[dict[str, object]] = []
        fetch_addresses: list[int] = []
        rounds: list[dict[str, object]] = []
        latch = 0
        loopback = 0
        rise_mark: int | None = None
        current_round: dict[str, object] | None = None
        error = None
        host_rounds = 0
        identity: dict[str, object] = {}
        execution: dict[str, str] = {}
        try:
            gpio.begin_case(testcase_id)
            cpu.begin_case(testcase_id)
            identity = {'cpu': cpu.identity_document(), 'gpio': gpio.identity_document()}
            # Native execution UUIDs are private session state; they are copied
            # only so two fresh runs can be shown to be different processes.
            execution = {'cpu': cpu._execution, 'gpio': gpio._execution}
            for host_round in range(MAX_HOST_ROUNDS):
                host_rounds = host_round + 1
                cpu.step_local({'irq': latch})
                cpu_samples.extend(json.loads(json.dumps(cpu.last_samples)))
                pre = cpu.last_samples[0]['pre']['backend']
                if pre['i_arvalid'] and pre['i_arready']:
                    fetch_addresses.append(pre['i_araddr'])
                    if pre['i_araddr'] == ISR_ADDRESS:
                        host_events.append({'kind': 'isr_vector_fetch',
                                            'cpu_tick': cpu.local_ticks,
                                            'host_round': host_round,
                                            'address': pre['i_araddr']})
                        if current_round is not None:
                            current_round['isr_vector_fetches'] += 1
                for name in router.ready_targets:
                    router.drain_one(name)
                values = gpio.step_local({'gpio_in': loopback})
                gpio_samples.extend(gpio.drain_tick_samples())
                if values['interrupt']:
                    if current_round is not None:
                        current_round['late_pulses'] += 1
                    if not latch:
                        latch = 1
                        rise_mark = len(router.deliveries)
                        current_round = {
                            'index': len(rounds),
                            'value': self.cases[len(rounds)],
                            'driven_value': self.cases[len(rounds)] | PAD0,
                            'rise_cpu_tick': cpu.local_ticks,
                            'rise_gpio_tick': gpio.local_ticks,
                            'rise_gpio_out': values['gpio_out'],
                            'rise_delivery_mark': rise_mark,
                            'fall_delivery_mark': None,
                            'fall_cpu_tick': None,
                            'fall_gpio_tick': None,
                            'isr_vector_fetches': 0,
                            'late_pulses': 0,
                        }
                        rounds.append(current_round)
                        host_events.append({'kind': 'irq_rise',
                                            'host_round': host_round,
                                            'cpu_tick': cpu.local_ticks,
                                            'gpio_tick': gpio.local_ticks,
                                            'gpio_out': values['gpio_out']})
                loopback = values['gpio_out']
                if latch and not (loopback & PAD0):
                    clears = [row for row in router.deliveries[rise_mark:]
                              if row['write'] and row['offset'] == REG_PADOUTCLR]
                    if clears:
                        latch = 0
                        assert current_round is not None
                        current_round['fall_cpu_tick'] = cpu.local_ticks
                        current_round['fall_gpio_tick'] = gpio.local_ticks
                        current_round['fall_delivery_mark'] = len(router.deliveries)
                        host_events.append({'kind': 'irq_fall',
                                            'host_round': host_round,
                                            'cpu_tick': cpu.local_ticks,
                                            'gpio_tick': gpio.local_ticks,
                                            'cleared_after_delivery': clears[0]['delivery_order']})
                        current_round = None
                done = memory.read(DONE_ADDRESS, 4,
                                   transaction_id=f'host-done-{host_round}').value
                if done == DONE_MARK and len(rounds) == len(self.cases):
                    break
            else:
                error = 'host round bound exhausted before the row finished'
        except BaseException as failure:  # evidence must survive a real failure
            error = f'{type(failure).__name__}: {failure}'
        finally:
            try:
                cpu.end_case()
            finally:
                gpio.end_case()
        deliveries = json.loads(json.dumps(router.deliveries, default=_jsonable))
        acceptances = json.loads(json.dumps(router.acceptances, default=_jsonable))
        # Attribute each round's actual APB traffic after the fact: the SET
        # write lands before the IRQ pulse, the ISR reads/clear after it.  The
        # program's one-time configuration writes precede the first SET and are
        # never part of a round.
        previous_fall = next((index for index, row in enumerate(deliveries)
                              if row['write'] and row['offset'] == REG_PADOUTSET),
                             len(deliveries))
        for index, rollup in enumerate(rounds):
            rise = rollup['rise_delivery_mark']
            fall = (rounds[index + 1]['rise_delivery_mark']
                    if index + 1 < len(rounds) else len(deliveries))
            if rollup['fall_delivery_mark'] is not None:
                fall = rollup['fall_delivery_mark']
            window_a = deliveries[previous_fall:rise]
            window_b = deliveries[rise:fall]
            rollup['deliveries'] = [row for row in (*window_a, *window_b)]
            previous_fall = fall
        words = {}
        for name, base in (('result', RESULT_ADDRESS), ('status', STATUS_ADDRESS),
                           ('check', CHECK_ADDRESS)):
            words[name] = [memory.read(base + 4 * index, 4,
                                       transaction_id=f'host-{name}-{index}').value
                           for index in range(len(self.cases))]
        done = memory.read(DONE_ADDRESS, 4, transaction_id='host-done-final').value
        document = {
            'schema_version': SCHEMA,
            'testcase_id': testcase_id,
            'profile_paths': {'cpu': CPU_PROFILE, 'gpio': GPIO_PROFILE},
            'program': {key: value for key, value in program.items() if key != 'image'},
            'memory': memory.identity_document(),
            'artifacts': {'cpu': _artifact_summary(self.artifacts['cpu']),
                          'gpio': _artifact_summary(self.artifacts['gpio'])},
            'irq_entry': json.loads(json.dumps(cpu.irq_entry)),
            'wiring': {
                'schema_version': 'vexi_pulp_gpio_irq_wiring.v1',
                'cpu_entry': 'real int_m_external pin driven by the host wire',
                'pulse_to_level': 'set on actual GPIO interrupt pulse; cleared only '
                                  'after the ISR actual PADOUTCLR APB delivery and a '
                                  'GPIO edge observing gpio_out bit0 low',
                'gpio_loopback': 'gpio_in <- previous GPIO edge gpio_out (declared '
                                 'host loopback of the real output register)',
                'step_order': 'CPU edge, then accepted CPU target APB transaction, '
                              'then one GPIO edge',
                'injects_trap': False,
                'injects_cause': False,
            },
            'binaries': {name: {'path': str(path),
                                'sha256': hashlib.sha256(Path(path).read_bytes()).hexdigest()}
                         for name, path in self.binaries.items()},
            'identities': identity,
            'execution': execution,
            'counts': {
                'cpu_ticks': cpu.local_ticks,
                'gpio_ticks': gpio.local_ticks,
                'host_rounds': host_rounds,
                'irq_rises': sum(1 for event in host_events if event['kind'] == 'irq_rise'),
                'irq_falls': sum(1 for event in host_events if event['kind'] == 'irq_fall'),
                'isr_vector_fetches': sum(1 for address in fetch_addresses
                                          if address == ISR_ADDRESS),
                'apb_deliveries': len(deliveries),
                'trace_events': len(cpu.runtime_events)},
            'rounds': rounds,
            'host_events': host_events,
            'ram': {'result': words['result'], 'status': words['status'],
                    'check': words['check'], 'done': done},
            'fetch_addresses': fetch_addresses,
            'cpu_irq_edges': json.loads(json.dumps(cpu.irq_edges)),
            'deliveries': deliveries,
            'acceptances': acceptances,
            'cpu_samples': cpu_samples,
            'gpio_samples': gpio_samples,
            'error': error,
        }
        document['checks'] = verify_row_document(document)
        document['status'] = ('verified' if not document['error']
                              and all(check['ok'] for check in document['checks'])
                              else 'failed')
        return document


def _check(name: str, ok: bool, detail: object = None) -> dict[str, object]:
    return {'name': name, 'ok': bool(ok), 'detail': detail}


def verify_row_document(document: Mapping[str, object]) -> list[dict[str, object]]:
    """Independent pass over the evidence document; never reads a schedule."""
    checks: list[dict[str, object]] = []
    rounds = document.get('rounds') or []
    program = document.get('program') or {}
    cases = program.get('cases') or []
    driven = program.get('driven_values') or []
    ram = document.get('ram') or {}
    events = document.get('host_events') or []
    checks.append(_check('row-completed-all-cases',
                         document.get('error') is None and len(rounds) == len(cases),
                         {'rounds': len(rounds), 'cases': len(cases),
                          'error': document.get('error')}))
    checks.append(_check('done-marker', ram.get('done') == DONE_MARK, ram.get('done')))
    for index, value in enumerate(cases):
        rollup = rounds[index] if index < len(rounds) else {}
        expected = driven[index] if index < len(driven) else None
        result = (ram.get('result') or [None] * len(cases))[index]
        status = (ram.get('status') or [None] * len(cases))[index]
        check = (ram.get('check') or [None] * len(cases))[index]
        rows = rollup.get('deliveries', ())
        writes = [row for row in rows
                  if row['write'] and row['offset'] == REG_PADOUTSET]
        reads = {row['offset']: row for row in rows if not row['write']}
        clears = [row for row in rows
                  if row['write'] and row['offset'] == REG_PADOUTCLR]
        checks.append(_check(f'case-{index}-irq-round',
                             rollup.get('rise_cpu_tick') is not None
                             and rollup.get('fall_cpu_tick') is not None
                             and rollup.get('isr_vector_fetches', 0) >= 1,
                             {'rise': rollup.get('rise_cpu_tick'),
                              'fall': rollup.get('fall_cpu_tick'),
                              'isr_fetches': rollup.get('isr_vector_fetches')}))
        checks.append(_check(f'case-{index}-padoutset-write',
                             len(writes) == 1 and writes[0]['write_value'] == expected,
                             [row.get('write_value') for row in writes]))
        checks.append(_check(f'case-{index}-padout-readback',
                             REG_PADOUT in reads and reads[REG_PADOUT]['read_value'] == expected,
                             reads.get(REG_PADOUT, {}).get('read_value')))
        checks.append(_check(f'case-{index}-intstatus-latched',
                             REG_INTSTATUS in reads
                             and type(reads[REG_INTSTATUS]['read_value']) is int
                             and reads[REG_INTSTATUS]['read_value'] & PAD0
                             and reads[REG_INTSTATUS]['read_value'] & 1,
                             reads.get(REG_INTSTATUS, {}).get('read_value')))
        checks.append(_check(f'case-{index}-padoutclr-write',
                             len(clears) == 1 and clears[0]['write_value'] == PADOUTCLR_ALL,
                             [row.get('write_value') for row in clears]))
        checks.append(_check(f'case-{index}-isr-result', result == expected, result))
        checks.append(_check(f'case-{index}-status-observed',
                             type(status) is int and bool(status & 1), status))
        checks.append(_check(f'case-{index}-cpu-check-zero', check == 0, check))
        checks.append(_check(f'case-{index}-no-extra-pulse',
                             rollup.get('late_pulses', 0) == 0,
                             rollup.get('late_pulses')))
    rises = [event for event in events if event['kind'] == 'irq_rise']
    falls = [event for event in events if event['kind'] == 'irq_fall']
    checks.append(_check('one-rise-and-fall-per-case',
                         len(rises) == len(cases) and len(falls) == len(cases),
                         {'rises': len(rises), 'falls': len(falls)}))
    trace = document.get('cpu_irq_edges') or []
    checks.append(_check('session-irq-level-trace',
                         [row.get('level') for row in trace] == [1, 0] * len(cases),
                         [row.get('level') for row in trace]))
    checks.append(_check('program-before-irq',
                         all(isinstance(rollup.get('rise_cpu_tick'), int)
                             for rollup in rounds),
                         [rollup.get('rise_cpu_tick') for rollup in rounds]))
    return checks


def _without_run_identity(value: object) -> object:
    """Drop the native execution/testcase ids that two fresh runs must change."""
    if isinstance(value, Mapping):
        return {key: _without_run_identity(item) for key, item in value.items()
                if key not in ('execution_id', 'testcase_id')}
    if isinstance(value, list):
        return [_without_run_identity(item) for item in value]
    return value


def compare_fresh_runs(first: Mapping[str, object],
                       fresh: Mapping[str, object]) -> dict[str, object]:
    """Compare two complete rows from independent operating-system processes."""
    def stable(document):
        retained = {key: document[key] for key in (
            'program', 'memory', 'artifacts', 'irq_entry', 'wiring', 'binaries',
            'rounds', 'host_events', 'ram', 'fetch_addresses', 'cpu_irq_edges',
            'deliveries', 'acceptances', 'checks', 'status', 'counts')
            if key in document}
        return _without_run_identity(retained)
    first_identity = first.get('identities') or {}
    fresh_identity = fresh.get('identities') or {}
    checks = [
        _check('both-runs-verified',
               first.get('status') == 'verified' and fresh.get('status') == 'verified',
               [first.get('status'), fresh.get('status')]),
        _check('artifact-and-build-identity',
               first_identity == fresh_identity and first_identity != {}, None),
        _check('stable-evidence-equal',
               _digest(stable(first)) == _digest(stable(fresh)),
               {'first': _digest(stable(first)), 'fresh': _digest(stable(fresh))}),
        _check('raw-cpu-samples-equal',
               first.get('cpu_samples') == fresh.get('cpu_samples'),
               {'first': _digest(first.get('cpu_samples')),
                'fresh': _digest(fresh.get('cpu_samples'))}),
        _check('raw-gpio-samples-equal',
               first.get('gpio_samples') == fresh.get('gpio_samples'),
               {'first': _digest(first.get('gpio_samples')),
                'fresh': _digest(fresh.get('gpio_samples'))}),
        _check('distinct-native-executions',
               (first.get('execution') or {}).get('cpu') not in (None, '')
               and (fresh.get('execution') or {}).get('cpu') not in (None, '')
               and (first.get('execution') or {}).get('cpu')
               != (fresh.get('execution') or {}).get('cpu')
               and (first.get('execution') or {}).get('gpio')
               != (fresh.get('execution') or {}).get('gpio'),
               {'first': first.get('execution'), 'fresh': fresh.get('execution')}),
    ]
    return {
        'schema_version': 'vexi_pulp_gpio_irq_fresh_replay.v1',
        'matches': all(check['ok'] for check in checks),
        'checks': checks,
        'first_evidence_sha256': _digest(stable(first)),
        'fresh_evidence_sha256': _digest(stable(fresh)),
        'first_execution': first.get('execution'),
        'fresh_execution': fresh.get('execution'),
    }
