"""Pure-software controls for the S2 external descriptor firmware and cases.

Two independent software fixtures are used and neither claims native evidence:

* a minimal RV32I interpreter plus behavioural UART/DMA models executes the
  emitted firmware words, so descriptor decode, RAM source writes, DMA control
  words, the ISR result layout and the multi-case loop are checked without RTL;
* a synthetic journal fixture exercises the same per-case certification joins
  the real gate uses, including every negative reduction (missing frame, pop,
  beat, RAM commit, IRQ take, ISR store or retirement).
"""
import collections
import pytest

from myfuzz.integration import dma_uart_descriptor_runtime as runtime
from myfuzz.integration.dma_uart_descriptor_runtime import (
    CaseWitnesses, DescriptorCase, DescriptorCaseRejected, assert_plan_matches_cases,
    certify_descriptor_case, decode_descriptor, descriptor_windows,
    encode_descriptor, extract_case_witnesses)
from myfuzz.scenario import ibex_dma_uart_descriptor as firmware
from myfuzz.scenario.batch import BatchAdvance, BatchSourceEvent, ScenarioBatchPlan
from myfuzz.scenario.genome import ScenarioGenome

CASE_FIELDS = ('command_start', 'command_end', 'event_start', 'event_end',
               'ticks_before', 'ticks_after', 'prefix_sha256', 'fifo_depth_after',
               'source_start_command', 'source_end_command')


# ---------------------------------------------------------------------------
# A. fixed firmware layout and declared control words
# ---------------------------------------------------------------------------
def test_firmware_layout_stays_inside_the_declared_ram_and_vector_slots():
    assert firmware.MAIN & 0xFF == 0x80
    assert firmware.MAIN + 4 * len(firmware.MAIN_WORDS) <= firmware.MTVEC_BASE
    assert firmware.ISR == firmware.MTVEC_BASE + 44
    assert firmware.ISR + 4 * len(firmware.ISR_WORDS) <= 0x30000
    assert firmware.MTVEC_BASE % 256 == 0
    images = firmware.descriptor_uart_images()
    assert set(images) == {firmware.MAIN, firmware.ISR, firmware.SOURCE_RAM,
                           firmware.DESTINATION, firmware.RESULT}
    assert len(images[firmware.RESULT]) == firmware.RESULT_BYTES
    assert len(images[firmware.SOURCE_RAM]) == 16
    assert len(images[firmware.DESTINATION]) == 16
    # The image is fixed: no testcase input reaches the program bytes.
    assert firmware.descriptor_uart_images() == images


def test_direction_control_words_pin_the_real_wbdmac_address_increment_bits():
    # wbdmac.v: s_data[29]=inc_s_n, s_data[28]=inc_d_n, s_data[27:16]=0xfed,
    # s_data[9:0]=block length.  Multi-word RX/TX need the fixed side.
    assert firmware.CONTROL_WORDS['RX_TO_RAM'] & firmware.CONTROL_INC_S_N
    assert not firmware.CONTROL_WORDS['RX_TO_RAM'] & firmware.CONTROL_INC_D_N
    assert not firmware.CONTROL_WORDS['RAM_TO_RAM'] & firmware.CONTROL_INC_S_N
    assert not firmware.CONTROL_WORDS['RAM_TO_RAM'] & firmware.CONTROL_INC_D_N
    assert firmware.CONTROL_WORDS['RAM_TO_TX'] & firmware.CONTROL_INC_D_N
    assert not firmware.CONTROL_WORDS['RAM_TO_TX'] & firmware.CONTROL_INC_S_N
    for word in firmware.CONTROL_WORDS.values():
        assert (word & firmware.CONTROL_KEY_MASK) >> firmware.CONTROL_KEY_SHIFT \
            == firmware.CONTROL_KEY
        assert word & 0x3FF == firmware.CONTROL_BLOCKLEN


def test_descriptor_program_is_direction_and_window_bounded():
    program = firmware.descriptor_program('RX_TO_RAM', 1, 3)
    assert program['source_words'] == (firmware.UART_RDATA,) * 3
    assert program['destination_words'] == tuple(
        firmware.DESTINATION + 4 * index for index in (1, 2, 3))
    assert program['witness'] == firmware.DESTINATION + 4
    assert program['cpu_source_words'] == ()
    program = firmware.descriptor_program('RAM_TO_RAM', 0, 4)
    assert program['source_words'] == tuple(
        firmware.SOURCE_RAM + 4 * index for index in range(4))
    assert program['cpu_source_words'] == program['source_words']
    program = firmware.descriptor_program('RAM_TO_TX', 3, 2)
    assert program['destination_words'] == (firmware.UART_WDATA,) * 2
    assert program['witness'] == firmware.SOURCE_RAM
    with pytest.raises(ValueError, match='direction'):
        firmware.descriptor_program('ILLEGAL', 0, 1)
    with pytest.raises(ValueError, match='destination words'):
        firmware.descriptor_program('RX_TO_RAM', 3, 2)
    with pytest.raises(ValueError, match='length'):
        firmware.descriptor_program('RX_TO_RAM', 0, 5)
    with pytest.raises(ValueError, match='dst_index'):
        firmware.descriptor_program('RX_TO_RAM', 4, 1)


# ---------------------------------------------------------------------------
# B. descriptor decode, canonical wire encoding and pre-RTL refusal
# ---------------------------------------------------------------------------
def test_decode_masks_the_fixed_descriptor_fields():
    decoded = decode_descriptor((0x04, 0xFF, 0x07, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A))
    assert decoded == dict(direction='RX_TO_RAM', direction_code=0, length=4,
        dst_index=3, payload=0x5A, payload_bytes=(0x5A,) * 4)
    assert decode_descriptor((0x01, 0x00, 0x01, 0x11, 0x11))['direction'] \
        == 'RAM_TO_RAM'
    assert decode_descriptor((0x02, 0x01, 0x02, 0x22, 0x22, 0x22))['direction'] \
        == 'RAM_TO_TX'
    assert decode_descriptor((0x03, 0, 0, 0x33, 0x33))['direction'] == 'ILLEGAL'


def test_decode_requires_the_exact_declared_stream_length():
    with pytest.raises(ValueError, match='four'):
        decode_descriptor((0, 0, 0))
    with pytest.raises(ValueError, match='four descriptor bytes plus len'):
        decode_descriptor((0, 0, 0, 0x11))
    with pytest.raises(ValueError, match='four descriptor bytes plus len'):
        decode_descriptor((0, 0, 0, 0x11, 0x11, 0x11))
    with pytest.raises(ValueError, match='serial byte'):
        decode_descriptor((0, 0, 0, 256, 0x11))


def test_create_encodes_the_canonical_wire_descriptor():
    case = DescriptorCase.create('RAM_TO_TX', dst_index=2, payload=0xA5, length=3)
    assert case.source_bytes == (0x02, 0x02, 0x02, 0xA5, 0xA5, 0xA5, 0xA5)
    assert case.source_count == 7
    assert case.action_ids(4) == ('descriptor-4-0', 'descriptor-4-1',
        'descriptor-4-2', 'descriptor-4-3', 'descriptor-4-4', 'descriptor-4-5',
        'descriptor-4-6')
    assert DescriptorCase.from_wire(case.source_bytes) == case
    assert DescriptorCase.from_document(case.to_document()) == case
    for direction, dst_index, length in (('RX_TO_RAM', 0, 1), ('RAM_TO_RAM', 3, 1),
            ('RAM_TO_TX', 1, 4)):
        assert DescriptorCase.from_wire(
            DescriptorCase.create(direction, dst_index=dst_index,
                payload=0x00, length=length).source_bytes).direction == direction


def test_create_refuses_undeclared_fields_before_any_wire_byte():
    with pytest.raises(DescriptorCaseRejected, match='three declared directions'):
        DescriptorCase.create('ILLEGAL', dst_index=0, payload=0, length=1)
    with pytest.raises(DescriptorCaseRejected, match='length'):
        DescriptorCase.create('RX_TO_RAM', dst_index=0, payload=0, length=0)
    with pytest.raises(DescriptorCaseRejected, match='length'):
        DescriptorCase.create('RX_TO_RAM', dst_index=0, payload=0, length=5)
    with pytest.raises(DescriptorCaseRejected, match='dst_index'):
        DescriptorCase.create('RX_TO_RAM', dst_index=4, payload=0, length=1)
    with pytest.raises(ValueError, match='payload'):
        DescriptorCase.create('RX_TO_RAM', dst_index=0, payload=256, length=1)


def test_declared_case_fields_must_match_the_serial_bytes():
    with pytest.raises(ValueError, match='declared descriptor fields differ'):
        DescriptorCase('RAM_TO_RAM', 0, 0x11, 1, (0x00, 0, 0, 0x11, 0x11),
            dict(direction='RAM_TO_RAM', dst_index=0, payload=0x11, length=1))
    with pytest.raises(ValueError, match='every transferred word'):
        # Declared length 2 but the queued stream carries two different bytes.
        DescriptorCase('RX_TO_RAM', 0, 0x11, 2, (0x00, 0x01, 0, 0x11, 0x11, 0x22),
            dict(direction='RX_TO_RAM', dst_index=0, payload=0x11, length=2))


def test_validate_is_pure_and_refuses_narrowed_or_unknown_windows():
    case = DescriptorCase.create('RX_TO_RAM', dst_index=2, payload=0x5A, length=2)
    assert case.validate()['destination'] == firmware.DESTINATION + 8
    windows = descriptor_windows()
    assert windows['declared_illegal'] == (firmware.ILLEGAL_TARGET,
                                           firmware.ILLEGAL_TARGET + 4)
    narrowed = {**windows, 'destination_ram': (firmware.DESTINATION,
                                               firmware.DESTINATION + 8)}
    with pytest.raises(DescriptorCaseRejected, match='destination_ram'):
        case.validate(narrowed)
    shortened = {**windows, 'descriptor_length': (1, 1)}
    with pytest.raises(DescriptorCaseRejected, match='descriptor_length'):
        case.validate(shortened)
    with pytest.raises(DescriptorCaseRejected, match='descriptor_direction'):
        case.validate({**windows, 'descriptor_direction': (1, 2)})
    with pytest.raises(DescriptorCaseRejected, match='illegal'):
        case.validate({**windows, 'declared_illegal': (0, 4)})
    unknown = dict(windows)
    del unknown['uart_rdata']
    with pytest.raises(DescriptorCaseRejected, match='uart_rdata'):
        case.validate(unknown)
    with pytest.raises(ValueError, match='mapping'):
        case.validate(())


def test_illegal_direction_and_non_complete_outcomes_are_refused_at_construction():
    with pytest.raises(DescriptorCaseRejected, match='three declared directions'):
        DescriptorCase('ILLEGAL', 0, 0x11, 1, (0x03, 0, 0, 0x11, 0x11),
            dict(direction='ILLEGAL', dst_index=0, payload=0x11, length=1))
    case = DescriptorCase.create('RX_TO_RAM', dst_index=0, payload=0x11, length=1)
    with pytest.raises(DescriptorCaseRejected, match='S3'):
        DescriptorCase(case.direction, case.dst_index, case.payload,
            case.length, case.source_bytes, dict(case.descriptor),
            expect='environment_error')


def test_plan_join_binds_every_admitted_byte_to_the_declared_case():
    first = DescriptorCase.create('RX_TO_RAM', dst_index=0, payload=0x5A, length=2)
    second = DescriptorCase.create('RAM_TO_TX', dst_index=1, payload=0xA5, length=1)
    template = ScenarioGenome('descriptor-dma-three-directions', 'IP_TO_CPU',
        'uart-descriptor-dma-ram-tx-cpu-isr', ('dma', 'cpu', 'uart'), 100, ())
    commands = []
    for case_index, case in enumerate((first, second), 1):
        for slot, byte in enumerate(case.source_bytes):
            commands.append(BatchSourceEvent(f'descriptor-{case_index}-{slot}',
                'uart', 'uart_rx_byte', byte, width=8))
        commands.append(BatchAdvance(('dma', 'cpu')))
    plan = ScenarioBatchPlan(template, tuple(commands))
    assert len(assert_plan_matches_cases(plan, (first, second))) == 11
    bad_values = list(commands)
    bad_values[2] = BatchSourceEvent('descriptor-1-2', 'uart', 'uart_rx_byte',
        0xFF, width=8)
    with pytest.raises(DescriptorCaseRejected, match='source commands'):
        assert_plan_matches_cases(ScenarioBatchPlan(template, tuple(bad_values)),
            (first, second))
    bad_ids = list(commands)
    bad_ids[0] = BatchSourceEvent('wrong-id', 'uart', 'uart_rx_byte',
        first.source_bytes[0], width=8)
    with pytest.raises(DescriptorCaseRejected, match='source commands'):
        assert_plan_matches_cases(ScenarioBatchPlan(template, tuple(bad_ids)),
            (first, second))


# ---------------------------------------------------------------------------
# C. minimal RV32I interpreter + behavioural UART/DMA model
# ---------------------------------------------------------------------------
class _ModelFault(RuntimeError):
    """A fatal harness-level failure (for example an empty FIFO pop)."""


class _ModelBusError(RuntimeError):
    """A declared DMA master-target rejection: a real environment error."""


def _sign(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


class _ModelUart:
    def __init__(self):
        self.fifo = collections.deque()
        self.tx = []
        self.pops = []
        self.ctrl = None
        self.status_reads = []

    @property
    def nonempty(self):
        return bool(self.fifo)

    def status(self):
        value = 0 if self.nonempty else firmware.UART_RXEMPTY_MASK
        self.status_reads.append(value)
        return value

    def pop(self):
        if not self.fifo:
            raise _ModelFault('RDATA read on an empty RX FIFO')
        value = self.fifo.popleft()
        self.pops.append(value)
        return value

    def push(self, values):
        self.fifo.extend(values)


class _ModelDma:
    def __init__(self, machine):
        self.machine = machine
        self.source = 0
        self.destination = 0
        self.length = 0
        self.length_readback = 0
        self.status = 0
        self.error = False
        self.beats = []
        self.writes = []
        self.commits = []

    def write(self, offset, value):
        self.writes.append((offset, value))
        if offset == 4:
            self.length = value & 0x3FF
            self.length_readback = self.length
        elif offset == 8:
            self.source = value
        elif offset == 12:
            self.destination = value
        elif offset == 0:
            self.start(value)
        else:
            raise _ModelFault('invalid DMA control offset')

    def read(self, offset):
        if offset == 0:
            return self.status
        if offset == 4:
            return self.length_readback
        raise _ModelFault('invalid DMA control read')

    def start(self, control):
        assert (control >> 16) & 0xFFF == firmware.CONTROL_KEY
        assert control >> 30 == 0
        increment_source = not control & firmware.CONTROL_INC_S_N
        increment_destination = not control & firmware.CONTROL_INC_D_N
        self.beats = []
        self.error = False
        for index in range(self.length):
            source = self.source + (4 * index if increment_source else 0)
            destination = self.destination + (
                4 * index if increment_destination else 0)
            try:
                value = self.machine.read_bus(source)
                self.machine.write_bus(destination, value)
            except _ModelBusError:
                self.error = True
                break
            self.beats.append((source, destination, value))
        self.status = (1 << 30) if self.error else 0
        self.length_readback = self.length if self.error else 0
        self.machine.irq = True


class _Machine:
    def __init__(self):
        self.mem = {}
        for address, image in firmware.descriptor_uart_images().items():
            for offset in range(0, len(image), 4):
                self.mem[address + offset] = int.from_bytes(
                    image[offset:offset + 4], 'little')
        self.regs = [0] * 32
        self.pc = firmware.MAIN
        self.mstatus_mie = False
        self.mie_meie = False
        self.mtvec = None
        self.mcause = 0
        self.mepc = 0
        self.in_trap = False
        self.irq = False
        self.uart = _ModelUart()
        self.dma = _ModelDma(self)
        self.steps = 0

    # -- memory / MMIO -----------------------------------------------------
    def mem_word(self, address):
        return self.mem.get(address, 0)

    def read_bus(self, address):
        if firmware.UART_BASE <= address < firmware.UART_BASE + 0x1000:
            offset = address - firmware.UART_BASE
            if offset == firmware.UART_RDATA_OFFSET:
                return self.uart.pop()
            if offset == firmware.UART_STATUS_OFFSET:
                return self.uart.status()
            raise _ModelBusError(f'UART read of undeclared offset {offset:#x}')
        if firmware.DMA_BASE <= address < firmware.DMA_BASE + 16:
            return self.dma.read(address - firmware.DMA_BASE)
        if 0x10000 <= address < 0x30000:
            return self.mem_word(address)
        raise _ModelBusError(f'unmapped read {address:#x}')

    def write_bus(self, address, value):
        if firmware.UART_BASE <= address < firmware.UART_BASE + 0x1000:
            offset = address - firmware.UART_BASE
            if offset == 0x1C:
                self.uart.tx.append(value & 0xFF)
                return
            if offset == 0x10:
                self.uart.ctrl = value
                return
            raise _ModelBusError(f'UART write of undeclared offset {offset:#x}')
        if firmware.DMA_BASE <= address < firmware.DMA_BASE + 16:
            self.dma.write(address - firmware.DMA_BASE, value)
            return
        if 0x10000 <= address < 0x30000:
            self.mem[address] = value & 0xFFFFFFFF
            return
        raise _ModelBusError(f'unmapped write {address:#x}')

    def read_word(self, address):
        if firmware.UART_BASE <= address < firmware.UART_BASE + 0x1000 \
                or firmware.DMA_BASE <= address < firmware.DMA_BASE + 16:
            return self.read_bus(address)
        return self.mem_word(address)

    def write_word(self, address, value):
        if firmware.UART_BASE <= address < firmware.UART_BASE + 0x1000 \
                or firmware.DMA_BASE <= address < firmware.DMA_BASE + 16:
            self.write_bus(address, value)
            return
        self.mem[address] = value & 0xFFFFFFFF

    # -- execution ---------------------------------------------------------
    def push_rx(self, values):
        self.uart.push(values)

    def step(self):
        if self.irq and self.mstatus_mie and self.mie_meie and not self.in_trap:
            self.mepc = self.pc
            self.mcause = runtime.DMA_IRQ_MCAUSE
            self.mstatus_mie = False
            self.in_trap = True
            self.pc = firmware.ISR
            self.irq = False
        word = self.mem_word(self.pc)
        self.steps += 1
        pc, next_pc = self.pc, self.pc + 4
        opcode = word & 0x7F
        rd = (word >> 7) & 31
        funct3 = (word >> 12) & 7
        rs1, rs2 = (word >> 15) & 31, (word >> 20) & 31
        if opcode == 0x37:                      # LUI
            self._set(rd, word & 0xFFFFF000)
        elif opcode == 0x6F:                    # JAL
            immediate = ((word >> 31) << 20 | ((word >> 21) & 0x3FF) << 1
                         | ((word >> 20) & 1) << 11 | ((word >> 12) & 0xFF) << 12)
            self._set(rd, pc + 4)
            next_pc = pc + _sign(immediate, 21)
        elif opcode == 0x63:                    # BEQ / BNE
            immediate = (((word >> 31) & 1) << 12 | ((word >> 7) & 1) << 11
                         | ((word >> 25) & 0x3F) << 5 | ((word >> 8) & 0xF) << 1)
            take = (self._get(rs1) == self._get(rs2)) if funct3 == 0 else \
                (self._get(rs1) != self._get(rs2))
            if take:
                next_pc = pc + _sign(immediate, 13)
        elif opcode == 0x03:                    # LW
            self._set(rd, self.read_word(self._get(rs1) + _sign(word >> 20, 12)))
        elif opcode == 0x23:                    # SW
            immediate = ((word >> 25) << 5) | ((word >> 7) & 31)
            self.write_word(self._get(rs1) + _sign(immediate, 12), self._get(rs2))
        elif opcode == 0x13:                    # OP-IMM
            immediate = _sign(word >> 20, 12)
            if funct3 == 0:
                self._set(rd, self._get(rs1) + immediate)
            elif funct3 == 7:
                self._set(rd, self._get(rs1) & immediate)
            elif funct3 == 1:
                self._set(rd, self._get(rs1) << ((word >> 20) & 31))
            else:
                raise _ModelFault(f'unsupported OP-IMM funct3 {funct3}')
        elif opcode == 0x33:                    # ADD / OR
            if funct3 == 0:
                self._set(rd, self._get(rs1) + self._get(rs2))
            elif funct3 == 6:
                self._set(rd, self._get(rs1) | self._get(rs2))
            else:
                raise _ModelFault(f'unsupported OP funct3 {funct3}')
        elif opcode == 0x73:                    # CSR / MRET
            if word == 0x30200073:
                self.pc = self.mepc
                self.mstatus_mie = True
                self.in_trap = False
                return
            csr = word >> 20
            if funct3 != 2:
                raise _ModelFault('unsupported CSR instruction')
            value = self._get(rs1)
            if csr == 0x305:
                self.mtvec = value
            elif csr == 0x304:
                self.mie_meie = bool(value & (1 << 11))
            elif csr == 0x300:
                self.mstatus_mie = bool(value & (1 << 3))
            elif csr == 0x342:
                previous, self.mcause = self.mcause, value
                if rd:
                    self._set(rd, previous)
            else:
                raise _ModelFault(f'unsupported CSR {csr:#x}')
        else:
            raise _ModelFault(f'unsupported opcode {opcode:#x} at {pc:#x}')
        self.pc = next_pc

    def _get(self, register):
        return self.regs[register] & 0xFFFFFFFF

    def _set(self, register, value):
        if register:
            self.regs[register] = value & 0xFFFFFFFF


def _run_model(source_bytes, *, counter, machine=None, max_steps=20000):
    machine = machine or _Machine()
    machine.push_rx(source_bytes)
    before = machine.mem_word(firmware.COMPLETED)
    for _ in range(max_steps):
        machine.step()
        if machine.mem_word(firmware.COMPLETED) != before:
            return machine
    raise AssertionError('firmware did not complete the descriptor case')


def _case_result(machine, counter):
    return dict(mcause=machine.mem_word(firmware.RESULT),
        status=machine.mem_word(firmware.RESULT + 4),
        length=machine.mem_word(firmware.RESULT + 8),
        payload=machine.mem_word(firmware.WITNESS),
        counter=machine.mem_word(firmware.COMPLETED),
        witness_pointer=machine.mem_word(firmware.WITNESS_POINTER))


@pytest.mark.parametrize('direction,dst_index,payload,length', [
    ('RX_TO_RAM', 0, 0x5A, 1),
    ('RX_TO_RAM', 1, 0x00, 3),
    ('RAM_TO_RAM', 1, 0xA5, 2),
    ('RAM_TO_RAM', 0, 0x7E, 4),
    ('RAM_TO_TX', 3, 0xFF, 1),
    ('RAM_TO_TX', 1, 0x33, 3),
])
def test_firmware_writes_the_declared_dma_program_and_isr_result(
        direction, dst_index, payload, length):
    case = DescriptorCase.create(direction, dst_index=dst_index, payload=payload,
        length=length)
    program = case.program()
    machine = _run_model(case.source_bytes, counter=1)
    assert machine.mtvec == firmware.MTVEC_BASE
    assert machine.dma.writes == [(8, program['source']),
        (12, program['destination']), (4, program['length']),
        (0, program['control'])]
    assert [(source, destination, value) for source, destination, value
            in machine.dma.beats] == [
        (program['source_words'][i], program['destination_words'][i], payload)
        for i in range(length)]
    # Every serial byte is popped exactly once: descriptor bytes by the CPU,
    # payload bytes by the DMA (RX) or by the CPU drain (RAM/TX).
    assert machine.uart.pops == list(case.source_bytes)
    if direction == 'RAM_TO_TX':
        assert machine.uart.tx == [payload] * length
    else:
        assert machine.uart.tx == []
        assert [machine.mem_word(address)
                for address in program['destination_words']] == [payload] * length
    if direction == 'RX_TO_RAM':
        assert machine.mem_word(firmware.SOURCE_RAM) in (0, payload)
    else:
        assert [machine.mem_word(address)
                for address in program['cpu_source_words']] == [payload] * length
    result = _case_result(machine, 1)
    assert result == dict(mcause=runtime.DMA_IRQ_MCAUSE,
        status=machine.dma.status, length=machine.dma.length_readback,
        payload=payload, counter=1, witness_pointer=program['witness'])


def test_one_boot_runs_three_directions_and_a_multi_word_case_in_order():
    specs = (
        DescriptorCase.create('RX_TO_RAM', dst_index=1, payload=0x11, length=3),
        DescriptorCase.create('RAM_TO_RAM', dst_index=0, payload=0x22, length=2),
        DescriptorCase.create('RAM_TO_TX', dst_index=2, payload=0x33, length=3),
        DescriptorCase.create('RX_TO_RAM', dst_index=3, payload=0x44, length=1),
    )
    machine = None
    for counter, spec in enumerate(specs, 1):
        machine = _run_model(spec.source_bytes, counter=counter, machine=machine)
        result = _case_result(machine, counter)
        assert result['counter'] == counter
        assert result['mcause'] == runtime.DMA_IRQ_MCAUSE
        assert result['payload'] == spec.payload
        assert result['status'] == 0
    assert machine.uart.pops == [byte for spec in specs for byte in spec.source_bytes]
    assert machine.uart.tx == [0x33] * 3
    # Multi-word FIFO: the RX case really popped three distinct queue entries.
    assert machine.uart.tx == [0x33, 0x33, 0x33]


def test_illegal_direction_hook_takes_the_declared_error_path_without_beats():
    # Direction code 3 is the declared S3 hook.  S2 refuses it pre-RTL, so this
    # only proves the emitted program would select the declared illegal target.
    machine = _run_model((0x03, 0x00, 0x00, 0x5A, 0x5A), counter=1)
    assert machine.dma.error is True
    assert machine.dma.beats == []
    assert machine.dma.status & (1 << 30)
    assert machine.dma.writes[-1] == (0, firmware.CONTROL_WORDS['ILLEGAL'])
    result = _case_result(machine, 1)
    assert result['mcause'] == runtime.DMA_IRQ_MCAUSE
    assert result['counter'] == 1
    assert machine.uart.pops == [0x03, 0x00, 0x00, 0x5A, 0x5A]


def test_firmware_dma_read_of_an_unqueued_payload_is_a_model_fault():
    # A descriptor that declares one payload byte but queues none makes the real
    # DMA read pop an empty FIFO.  The pre-RTL guard refuses such a spec instead
    # of consuming RTL, because the harness raises on an empty pop.
    machine = _Machine()
    machine.push_rx((0x00, 0x00, 0x00, 0x5A))
    with pytest.raises(_ModelFault, match='empty RX FIFO'):
        for _ in range(5000):
            machine.step()
    assert machine.mem_word(firmware.COMPLETED) == 0
    case = DescriptorCase.create('RX_TO_RAM', dst_index=0, payload=0x5A, length=1)
    assert case.source_count == 5


# ---------------------------------------------------------------------------
# D. synthetic journal fixture: the real certification joins, in software
# ---------------------------------------------------------------------------
SYNTHETIC_IDENTITY = {'execution_id': 'a' * 32, 'testcase_id': 'descriptor',
    'source_component': 'dma', 'source_epoch': 0, 'channel_id': 'dma-memory'}


class _Rows:
    def __init__(self):
        self.rows = []

    def add(self, kind, **fields):
        row = {'event_id': len(self.rows) + 1, 'kind': kind, **fields}
        self.rows.append(row)
        return row

    def extend(self, kind, count, **fields):
        return [self.add(kind, **fields) for _ in range(count)]


def _transaction(sequence):
    return {**SYNTHETIC_IDENTITY, 'source_sequence': sequence}


def _fifo(depth, head, *, phase):
    return {'probe_uart_fifo_depth': depth, 'probe_uart_fifo_head': head,
        'probe_uart_fifo_rvalid': 1 if phase == 'pre' else 0,
        'probe_uart_fifo_rdata_re': 1 if phase == 'pre' else 0,
        'probe_uart_fifo_under_rst': 0}


def _synthetic_rows(case, case_index=1, *, commit_before_write=False):
    rows = _Rows()
    program = case.program()
    payload = case.payload
    depth = case.source_count
    for slot, byte in enumerate(case.source_bytes):
        rows.add('source_injection', action_id=f'descriptor-{case_index}-{slot}',
            value=byte)
        rows.add('uart_frame_validation', action_id=f'descriptor-{case_index}-{slot}',
            byte=byte, waveform_matched=True, frame_id=f'frame-{slot}')
        # Real pinned UART: the push strobe tick's post sample still shows the
        # pre-push occupancy; the increment is visible on the next tick sample.
        rows.add('uart_tick_observation', post={
            'probe_uart_fifo_wvalid': 1, 'probe_uart_fifo_wready': 1,
            'probe_uart_fifo_depth': slot, 'probe_uart_fifo_data': byte,
            'probe_uart_fifo_head': 0 if slot == 0 else case.source_bytes[0]})
        rows.add('uart_tick_observation', post={
            'probe_uart_fifo_wvalid': 0, 'probe_uart_fifo_wready': 1,
            'probe_uart_fifo_depth': slot + 1, 'probe_uart_fifo_data': byte,
            'probe_uart_fifo_head': case.source_bytes[0]})
    rows.add('mmio_delivery', device_id='uart', offset=firmware.UART_STATUS_OFFSET,
        write=False, read_value=0)
    descriptor = case.source_bytes[:4]
    drained = case.source_bytes[4:]
    for pop_index, byte in enumerate(
            descriptor + (drained if case.direction != 'RX_TO_RAM' else ())):
        depth -= 1
        # The real journal carries the same routed access twice: a top-level
        # uart_rdata_access external event and the nested target_uart_access of
        # the CPU mmio_delivery.  On a step boundary the top-level copy can be
        # absent, so both shapes are real CPU-pop sources.
        access = dict(access_id=f'cpu-access-{pop_index}',
            source_transaction={'channel_id': 'data'},
            raw_offset=firmware.UART_RDATA_OFFSET, status='observed',
            read_value=byte, read_capture={
                'pre': _fifo(depth + 1, byte, phase='pre'),
                'post': _fifo(depth, 0, phase='post')})
        rows.add('uart_rdata_access', **access)
        rows.add('mmio_delivery', device_id='uart',
            offset=firmware.UART_RDATA_OFFSET, write=False, read_value=byte,
            target_uart_access=dict(access, kind='uart_rdata_access'))
    rows.add('memory_write', component='cpu', address=firmware.WITNESS_POINTER,
        value=program['witness'], version=[0, 1])
    for offset, value in ((8, program['source']), (12, program['destination']),
                          (4, program['length']), (0, program['control'])):
        rows.add('mmio_delivery', device_id='dma', offset=offset, write=True,
            write_value=value, read_value=None)
    if case.direction != 'RX_TO_RAM':
        for index, address in enumerate(program['cpu_source_words']):
            rows.add('memory_write', component='cpu', address=address,
                value=payload, version=[0, 2 + index])
    sequence = 1
    for index in range(case.length):
        read = rows.add('dma_edge', accepted=dict(transaction=_transaction(sequence),
            address=program['source_words'][index], write=False, value=0))
        if case.direction == 'RX_TO_RAM':
            depth -= 1
            prefix = 'dma-fifo'
            access = dict(access_id=f'{prefix}-{index}', status='observed',
                read_value=payload, read_capture={
                    'pre': _fifo(depth + 1, payload, phase='pre'),
                    'post': _fifo(depth, 0, phase='post')})
            read['accepted']['target_delivery'] = dict(target_component='uart',
                offset=firmware.UART_RDATA_OFFSET, write=False, value=payload,
                target_uart_access=access)
        else:
            rows.add('dma_edge', response=dict(transaction=_transaction(sequence),
                rdata=payload))
        commit = dict(component='dma',
            address=program['destination_words'][index], value=payload,
            version=[0, 10 + index])
        if case.direction != 'RAM_TO_TX' and commit_before_write:
            # Real journal order for one word: read beat -> memory commit ->
            # write beat (the memory service commits before the edge event).
            rows.add('memory_write', **commit)
        write = rows.add('dma_edge', accepted=dict(transaction=_transaction(sequence + 1),
            address=program['destination_words'][index], write=True, value=payload))
        if case.direction == 'RAM_TO_TX':
            write['accepted']['target_delivery'] = dict(target_component='uart',
                write=True, address=firmware.UART_WDATA, value=payload)
        elif not commit_before_write:
            rows.add('memory_write', **commit)
        sequence += 2
    pulse_tick = 100 + case_index
    rows.add('dma_edge', native_local_tick=pulse_tick,
        payload={'observations': {'physical': {'irq': 1}},
                 'pre_backend': {'mwb_ack': 1, 'mwb_we': 1, 'mwb_err': 0}})
    rows.add('cpu_external_irq_taken', local_tick=120 + case_index)
    rows.add('source_start', source=('dma', 'irq'), target=('cpu', 'irq'),
        source_tick=pulse_tick, source_event_id=1)
    rows.add('cpu_irq_taken', source=('dma', 'irq'), target=('cpu', 'irq'),
        source_event_id=1, cpu_tick=120 + case_index)
    rows.add('memory_write', component='cpu', address=firmware.RESULT,
        value=runtime.DMA_IRQ_MCAUSE, version=[0, 20])
    status_key = {'channel_id': 'data', 'source_component': 'cpu',
                  'source_sequence': 3}
    # wbdmac status bit29/bit28 mirror the inc_s_n/inc_d_n bits written in the
    # last CONTROL word; the other fields are recorded, not assumed.
    status = program['control'] & (
        firmware.CONTROL_INC_S_N | firmware.CONTROL_INC_D_N)
    rows.add('mmio_delivery', device_id='dma', offset=0, write=False,
        read_value=status, source_transaction=status_key)
    rows.add('data_response', transaction=status_key, rdata=status)
    rows.add('cpu_retire', pc_rdata=firmware.ISR_PCS['isr_status'],
        mem_addr=firmware.DMA_BASE, mem_rmask=15, mem_rdata=status, rd_addr=7,
        rd_wdata=status)
    rows.add('cpu_retire', pc_rdata=firmware.ISR_PCS['isr_status'] + 4,
        mem_addr=firmware.RESULT + 4, mem_wmask=15, mem_wdata=status, rs2_addr=7)
    rows.add('memory_write', component='cpu', address=firmware.RESULT + 4,
        value=status, version=[0, 21])
    length_actual = 0
    rows.add('mmio_delivery', device_id='dma', offset=4, write=False,
        read_value=length_actual, source_transaction={'channel_id': 'data',
            'source_component': 'cpu', 'source_sequence': 4})
    rows.add('cpu_retire', pc_rdata=firmware.ISR_PCS['isr_length'],
        mem_addr=firmware.DMA_BASE + 4, mem_rmask=15, mem_rdata=length_actual,
        rd_addr=8, rd_wdata=length_actual)
    rows.add('cpu_retire', pc_rdata=firmware.ISR_PCS['isr_length'] + 4,
        mem_addr=firmware.RESULT + 8, mem_wmask=15, mem_wdata=length_actual,
        rs2_addr=8)
    rows.add('memory_write', component='cpu', address=firmware.RESULT + 8,
        value=length_actual, version=[0, 22])
    rows.add('cpu_retire', pc_rdata=firmware.ISR_PCS['isr_witness_pointer'],
        mem_addr=firmware.WITNESS_POINTER, mem_rmask=15,
        mem_rdata=program['witness'], rd_addr=9, rd_wdata=program['witness'])
    rows.add('cpu_retire', pc_rdata=firmware.ISR_PCS['isr_witness'],
        mem_addr=program['witness'], mem_rmask=15, mem_rdata=payload, rd_addr=9,
        rd_wdata=payload)
    rows.add('cpu_retire', pc_rdata=firmware.ISR_PCS['isr_witness'] + 4,
        mem_addr=firmware.WITNESS, mem_wmask=15, mem_wdata=payload, rs2_addr=9)
    rows.add('memory_write', component='cpu', address=firmware.WITNESS,
        value=payload, version=[0, 23])
    rows.add('cpu_retire', pc_rdata=firmware.ISR_PCS['isr_counter_load'],
        mem_addr=firmware.COMPLETED, mem_rmask=15,
        mem_rdata=case_index - 1, rd_addr=9, rd_wdata=case_index - 1)
    rows.add('cpu_retire', pc_rdata=firmware.ISR_PCS['isr_counter_load'] + 8,
        mem_addr=firmware.COMPLETED, mem_wmask=15, mem_wdata=case_index,
        rs2_addr=9)
    rows.add('memory_write', component='cpu', address=firmware.COMPLETED,
        value=case_index, version=[0, 24])
    return rows.rows


@pytest.mark.parametrize('direction,dst_index,payload,length', [
    ('RX_TO_RAM', 0, 0x5A, 1),
    ('RX_TO_RAM', 1, 0x11, 3),
    ('RAM_TO_RAM', 1, 0xA5, 2),
    ('RAM_TO_RAM', 0, 0x7E, 4),
    ('RAM_TO_TX', 3, 0x33, 1),
    ('RAM_TO_TX', 1, 0xFF, 3),
])
def test_synthetic_journal_certifies_every_direction(direction, dst_index,
        payload, length):
    case = DescriptorCase.create(direction, dst_index=dst_index, payload=payload,
        length=length)
    rows = _synthetic_rows(case)
    witnesses = extract_case_witnesses(rows)
    evidence = certify_descriptor_case(witnesses, case, case_index=1,
        tx_captures=((payload,) * length if direction == 'RAM_TO_TX' else ()))
    assert evidence['completed'] is True
    assert evidence['fifo_origin'] == 'unknown'
    assert evidence['source_authority'] == 'incomplete'
    assert evidence['beat_count'] == 2 * length
    assert evidence['isr']['payload'] == payload
    assert evidence['isr']['counter'] == 1
    assert evidence['tx_capture_count'] == (length if direction == 'RAM_TO_TX' else 0)
    assert len(evidence['fifo']['push_depths']) == length + 4
    # The push tick itself carries the pre-push depth (0 for the first byte);
    # the certified depth comes from the following real tick sample.
    assert evidence['fifo']['push_depths'] == list(range(1, length + 5))
    assert [item['depth_before'] for item in evidence['fifo']['push_chain']] \
        == list(range(length + 4))
    assert [item['depth_after'] for item in evidence['fifo']['push_chain']] \
        == list(range(1, length + 5))
    if direction == 'RX_TO_RAM':
        assert [pop['kind'] for pop in evidence['fifo']['pops']] == ['cpu'] * 4 \
            + ['dma'] * length
        # Both real copies exist for every CPU pop in the journal and must be
        # deduplicated by access_id, not counted twice.
        assert [pop['source'] for pop in evidence['fifo']['pops']
                if pop['kind'] == 'cpu'] == ['top_level'] * 4
        assert all(pop['source'] == 'dma-master'
                   for pop in evidence['fifo']['pops'] if pop['kind'] == 'dma')
        assert [pop['pre_depth'] for pop in evidence['fifo']['pops']][-length:] \
            == list(range(length, 0, -1))
    else:
        assert [pop['kind'] for pop in evidence['fifo']['pops']] == ['cpu'] * (4 + length)
        assert [pop['source'] for pop in evidence['fifo']['pops']] == ['top_level'] * (4 + length)
    if direction == 'RAM_TO_RAM':
        assert [commit['version'] for commit in evidence['ram_commits']] == [
            [0, 10 + index] for index in range(length)]
        assert evidence['cpu_source_versions'] == [
            [0, 2 + index] for index in range(length)]


def _drop(rows, predicate):
    return [row for row in rows if not predicate(row)]


@pytest.mark.parametrize('predicate,message', [
    (lambda row: row.get('kind') == 'uart_frame_validation',
     'matched native serial frame'),
    (lambda row: row.get('kind') == 'uart_rdata_access'
        or (row.get('kind') == 'mmio_delivery'
            and row.get('offset') == firmware.UART_RDATA_OFFSET),
     'CPU must pop exactly'),
    (lambda row: row.get('kind') == 'dma_edge'
        and isinstance(row.get('accepted'), dict) and row['accepted'].get('write'),
     'two real master beats'),
    (lambda row: row.get('kind') == 'memory_write'
        and row.get('component') == 'dma', 'DMA RAM commit'),
    (lambda row: row.get('kind') == 'source_start', 'bound DMA IRQ source start'),
    (lambda row: row.get('kind') == 'cpu_irq_taken', 'bound CPU IRQ take'),
    (lambda row: row.get('kind') == 'cpu_external_irq_taken',
     'real external IRQ take'),
    (lambda row: row.get('kind') == 'dma_edge'
        and isinstance(row.get('accepted'), dict), 'two real master beats'),
])
def test_certifier_refuses_a_missing_real_witness(predicate, message):
    case = DescriptorCase.create('RAM_TO_RAM', dst_index=0, payload=0x22, length=2)
    rows = _drop(_synthetic_rows(case), predicate)
    with pytest.raises(RuntimeError, match=message):
        certify_descriptor_case(extract_case_witnesses(rows), case, case_index=1)


def _tampered_counter(rows):
    rows[-1]['value'] = 99
    return rows


def _tampered_payload_store(rows):
    next(row for row in rows if row.get('kind') == 'memory_write'
         and row.get('address') == firmware.WITNESS)['value'] = 0x00
    return rows


def _tampered_frame(rows):
    rows[1]['byte'] = 0x00
    return rows


def _tampered_pop(rows):
    next(row for row in rows
         if row.get('kind') == 'uart_rdata_access')['read_value'] = 0x00
    return rows


@pytest.mark.parametrize('mutate', [_tampered_counter, _tampered_payload_store,
    _tampered_frame, _tampered_pop])
def test_certifier_refuses_tampered_real_values(mutate):
    case = DescriptorCase.create('RAM_TO_RAM', dst_index=0, payload=0x22, length=2)
    rows = mutate(_synthetic_rows(case))
    with pytest.raises(RuntimeError):
        certify_descriptor_case(extract_case_witnesses(rows), case, case_index=1)


def _push_rows(rows):
    return [index for index, row in enumerate(rows)
            if row.get('kind') == 'uart_tick_observation'
            and (row.get('post') or {}).get('probe_uart_fifo_wvalid') == 1]


def _push_depth_stalled(rows):
    index = _push_rows(rows)[0]
    rows[index + 1]['post']['probe_uart_fifo_depth'] = 0
    return rows


def _push_wrong_data(rows):
    index = _push_rows(rows)[0]
    rows[index]['post']['probe_uart_fifo_data'] = 0xEE
    return rows


def _push_without_following_sample(rows):
    del rows[_push_rows(rows)[0] + 1]
    return rows


def _push_depth_gap(rows):
    index = _push_rows(rows)[1]
    rows[index]['post']['probe_uart_fifo_depth'] += 1
    rows[index + 1]['post']['probe_uart_fifo_depth'] += 1
    return rows


def _push_depth_repeat(rows):
    index = _push_rows(rows)[1]
    rows[index]['post']['probe_uart_fifo_depth'] = 0
    rows[index + 1]['post']['probe_uart_fifo_depth'] = 1
    return rows


def _push_stale_start(rows):
    # A non-empty real FIFO at case start shifts the whole (contiguous) chain.
    for index in _push_rows(rows):
        rows[index]['post']['probe_uart_fifo_depth'] += 1
        rows[index + 1]['post']['probe_uart_fifo_depth'] += 1
    return rows


def _push_missing(rows):
    del rows[_push_rows(rows)[0]]
    return rows


@pytest.mark.parametrize('mutate,message', [
    (_push_depth_stalled, 'did not increment'),
    (_push_wrong_data, 'push data differs'),
    (_push_without_following_sample, 'lacks an intervening tick sample'),
    (_push_depth_gap, 'not contiguous'),
    (_push_depth_repeat, 'not contiguous'),
    (_push_stale_start, 'not exactly 0..n-1'),
    (_push_missing, 'one real UART RX FIFO push per serial byte'),
])
def test_certifier_locks_the_real_push_depth_fields(mutate, message):
    # A regression that reads the push-strobe tick depth (always the pre-push
    # occupancy) or the wrong data field must fail instead of silently passing.
    case = DescriptorCase.create('RX_TO_RAM', dst_index=0, payload=0x5A, length=2)
    rows = mutate(_synthetic_rows(case))
    with pytest.raises(RuntimeError, match=message):
        certify_descriptor_case(extract_case_witnesses(rows), case, case_index=1)


def test_certifier_refuses_a_host_written_case_address():
    case = DescriptorCase.create('RX_TO_RAM', dst_index=0, payload=0x5A, length=1)
    rows = _synthetic_rows(case)
    rows.append({'event_id': len(rows) + 1, 'kind': 'memory_write',
        'component': 'host', 'address': firmware.DESTINATION, 'value': 0x5A,
        'version': [0, 99]})
    with pytest.raises(RuntimeError, match='non-CPU/DMA writer'):
        certify_descriptor_case(extract_case_witnesses(rows), case, case_index=1)


def test_certifier_refuses_a_tx_capture_that_does_not_match_the_payload():
    case = DescriptorCase.create('RAM_TO_TX', dst_index=0, payload=0x33, length=2)
    rows = _synthetic_rows(case)
    with pytest.raises(RuntimeError, match='TX serial capture'):
        certify_descriptor_case(extract_case_witnesses(rows), case, case_index=1,
            tx_captures=(0x33,))
    with pytest.raises(RuntimeError, match='non-TX'):
        certify_descriptor_case(extract_case_witnesses(
            _synthetic_rows(DescriptorCase.create('RX_TO_RAM', dst_index=0,
                payload=0x5A, length=1))),
            DescriptorCase.create('RX_TO_RAM', dst_index=0, payload=0x5A, length=1),
            case_index=1, tx_captures=(0x5A,))


def _remove_last_top_level_pop(rows):
    indices = [index for index, row in enumerate(rows)
               if row.get('kind') == 'uart_rdata_access'
               and (row.get('source_transaction') or {}).get('channel_id') == 'data']
    del rows[indices[-1]]
    return rows


def _strip_last_nested_copy(rows, *, drop_access_id=False):
    deliveries = [row for row in rows
                  if row.get('kind') == 'mmio_delivery'
                  and row.get('offset') == firmware.UART_RDATA_OFFSET
                  and row.get('write') is False]
    nested = deliveries[-1]['target_uart_access']
    if drop_access_id:
        nested.pop('access_id', None)
    else:
        deliveries[-1].pop('target_uart_access', None)
    return rows


def test_certifier_uses_a_nested_target_uart_access_when_top_level_is_absent():
    # Exact real-journal shape from the second gate failure: the fourth CPU
    # RDATA pop (tx13) exists only as mmio_delivery.target_uart_access.
    case = DescriptorCase.create('RX_TO_RAM', dst_index=0, payload=0x5A, length=1)
    rows = _remove_last_top_level_pop(_synthetic_rows(case))
    witnesses = extract_case_witnesses(rows)
    assert len(witnesses.cpu_pops) == 4
    assert [event.get('_pop_source') for event in witnesses.cpu_pops] == [
        'top_level', 'top_level', 'top_level', 'nested']
    evidence = certify_descriptor_case(witnesses, case, case_index=1)
    assert evidence['beat_count'] == 2
    assert [pop['read_value'] for pop in evidence['fifo']['pops']
            if pop['kind'] == 'cpu'] == list(case.source_bytes[:4])
    assert [pop['source'] for pop in evidence['fifo']['pops']
            if pop['kind'] == 'cpu'] == ['top_level', 'top_level', 'top_level',
                                         'nested']


def test_certifier_refuses_a_cpu_pop_with_neither_top_level_nor_nested_copy():
    case = DescriptorCase.create('RX_TO_RAM', dst_index=0, payload=0x5A, length=1)
    rows = _strip_last_nested_copy(_remove_last_top_level_pop(_synthetic_rows(case)))
    with pytest.raises(RuntimeError, match='CPU must pop exactly'):
        certify_descriptor_case(extract_case_witnesses(rows), case, case_index=1)


def test_certifier_requires_a_real_access_id_on_the_nested_copy():
    # Without the real access identity the copy cannot be joined to the FIFO
    # evidence, so it is not guessed into the pop count.
    case = DescriptorCase.create('RX_TO_RAM', dst_index=0, payload=0x5A, length=1)
    rows = _remove_last_top_level_pop(_synthetic_rows(case))
    rows = _strip_last_nested_copy(rows, drop_access_id=True)
    with pytest.raises(RuntimeError, match='CPU must pop exactly'):
        certify_descriptor_case(extract_case_witnesses(rows), case, case_index=1)


def _commit_rows(rows):
    return [row for row in rows if row.get('kind') == 'memory_write'
            and row.get('component') == 'dma']


def _read_rows(rows):
    return [row for row in rows if row.get('kind') == 'dma_edge'
            and isinstance(row.get('accepted'), dict)
            and row['accepted'].get('write') is False]


def _write_rows(rows):
    return [row for row in rows if row.get('kind') == 'dma_edge'
            and isinstance(row.get('accepted'), dict)
            and row['accepted'].get('write') is True]


def test_certifier_accepts_the_real_read_commit_write_shape():
    case = DescriptorCase.create('RAM_TO_RAM', dst_index=0, payload=0x22, length=2)
    rows = _synthetic_rows(case, commit_before_write=True)
    reads, commits, writes = _read_rows(rows), _commit_rows(rows), _write_rows(rows)
    assert len(reads) == len(commits) == len(writes) == 2
    order = [row['event_id'] for row in
             (reads[0], commits[0], writes[0], reads[1], commits[1], writes[1])]
    assert order == sorted(order) and len(set(order)) == len(order)
    evidence = certify_descriptor_case(extract_case_witnesses(rows), case,
        case_index=1)
    assert [commit['version'] for commit in evidence['ram_commits']] == [
        [0, 10], [0, 11]]
    assert [commit['value'] for commit in evidence['ram_commits']] == [0x22, 0x22]
    # length=1 has no next read: its commit interval is closed by the IRQ check.
    single = DescriptorCase.create('RAM_TO_RAM', dst_index=0, payload=0x11, length=1)
    certify_descriptor_case(extract_case_witnesses(
        _synthetic_rows(single, commit_before_write=True)), single, case_index=1)


def _commit_before_its_read(rows):
    _commit_rows(rows)[0]['event_id'] = _read_rows(rows)[0]['event_id'] - 1
    return rows


def _commit_after_the_next_read(rows):
    reads = _read_rows(rows)
    _commit_rows(rows)[0]['event_id'] = reads[1]['event_id'] + 1
    return rows


def _commit_wrong_value(rows):
    _commit_rows(rows)[0]['value'] = 0x00
    return rows


def _commit_repeated_version(rows):
    commits = _commit_rows(rows)
    commits[1]['version'] = list(commits[0]['version'])
    return rows


@pytest.mark.parametrize('mutate,message', [
    (_commit_before_its_read, 'accepted read beat interval'),
    (_commit_after_the_next_read, 'accepted read beat interval'),
    (_commit_wrong_value, 'value differs'),
    (_commit_repeated_version, 'strictly increasing'),
])
def test_certifier_locks_the_real_ram_commit_interval(mutate, message):
    case = DescriptorCase.create('RAM_TO_RAM', dst_index=0, payload=0x22, length=2)
    rows = mutate(_synthetic_rows(case, commit_before_write=True))
    with pytest.raises(RuntimeError, match=message):
        certify_descriptor_case(extract_case_witnesses(rows), case, case_index=1)


def test_witness_extraction_never_reclassifies_a_dma_pop_as_cpu():
    rows = [{'event_id': 1, 'kind': 'uart_rdata_access',
             'source_transaction': None, 'read_value': 0x5A},
            {'event_id': 2, 'kind': 'uart_rdata_access',
             'source_transaction': {'channel_id': 'data'}, 'read_value': 0x5A},
            {'event_id': 3, 'kind': 'uart_tick_observation',
             'post': {'probe_uart_fifo_wvalid': 1, 'probe_uart_fifo_wready': 0}}]
    witnesses = extract_case_witnesses(rows)
    assert len(witnesses.cpu_pops) == 1
    assert witnesses.cpu_pops[0]['event_id'] == 2
    assert witnesses.tick_pushes == ()
    with pytest.raises(ValueError, match='objects'):
        extract_case_witnesses(['not a row'])


# ---------------------------------------------------------------------------
# E. boot object mechanics on a fake runner (no RTL, no native claim)
# ---------------------------------------------------------------------------
def _fake_ids(offset=1):
    return {name: f'{offset + index:032x}'
            for index, name in enumerate(('cpu', 'dma', 'uart', 'runner'))}


class _FakeRouter:
    def __init__(self):
        self.ready = False

    @property
    def ready_targets(self):
        return ('uart',) if self.ready else ()


class _FakeSession:
    def __init__(self, execution):
        self._execution = execution

    def identity_document(self):
        return {'fake_session': self._execution}


class _FakeUart(_FakeSession):
    def __init__(self, execution):
        super().__init__(execution)
        self.source_events = []
        self.peer = type('Peer', (), {'captured': []})()

    def register_access_conflict(self):
        return None


class _FakeRunner:
    def __init__(self, ids, *, fail_isr=False):
        self.sessions = {
            'cpu': _FakeSession(ids['cpu']),
            'dma': _FakeSession(ids['dma']),
            'uart': _FakeUart(ids['uart'])}
        self.sessions['cpu'].router = _FakeRouter()
        self.execution_id = ids['runner']
        self.local_ticks = {'cpu': 0, 'dma': 0, 'uart': 0}
        self.rows = []
        self.failure_status = None
        self.fail_isr = fail_isr

    def set_resource_budget(self, budget):
        self.budget = budget

    @property
    def events(self):
        return tuple(self.rows)

    @property
    def event_count(self):
        return len(self.rows)

    def events_since(self, index):
        return tuple(self.rows[index:])

    def _uncertain_transactions(self):
        return ()

    def append(self, **record):
        self.rows.append({'event_id': len(self.rows) + 1, **record})


class _FakeRecorder:
    instances = []

    def __init__(self, template, runner):
        self.template, self.runner = template, runner
        self._commands = []
        self._finished = False
        self._trace = None
        self._pending = []
        self._case = 0
        self._rounds = 0
        self._completed = False
        _FakeRecorder.instances.append(self)

    @property
    def commands(self):
        return tuple(self._commands)

    @property
    def trace(self):
        return self._trace

    def begin(self):
        self._begun = True

    def submit_source_event(self, event):
        if not self._commands or isinstance(self._commands[-1], BatchAdvance):
            self._case += 1
            self._rounds = 0
            self._completed = False
        self._commands.append(event)
        self._pending.append((event.action_id, event.value))

    def advance(self, schedule):
        self._commands.append(BatchAdvance(tuple(schedule)))
        for component in schedule:
            self.runner.local_ticks[component] += 1
        if schedule == ('uart',):
            if self._pending:
                action_id, value = self._pending.pop(0)
                self.runner.sessions['uart'].source_events.append({
                    'kind': 'uart_source_frame_end', 'action_id': action_id,
                    'waveform_matched': True, 'byte': value})
            elif self._completed:
                self.runner.sessions['uart'].peer.captured.append(self._case & 0xFF)
            return tuple({} for _ in schedule)
        self.runner.sessions['cpu'].router.ready = True
        self.runner.append(kind='scheduler_step', component='cpu')
        if self._pending or self.runner.fail_isr:
            return tuple({} for _ in schedule)
        self._rounds += 1
        if self._rounds == 2 and not self._completed:
            self._completed = True
            self.runner.append(kind='memory_write', component='cpu',
                address=firmware.COMPLETED, value=self._case)
        return tuple({} for _ in schedule)

    def finish(self):
        self._finished = True
        from types import SimpleNamespace
        self._trace = SimpleNamespace(status='complete')
        return self._trace


@pytest.fixture
def fake_boot(monkeypatch):
    _FakeRecorder.instances = []
    monkeypatch.setattr(runtime, 'ScenarioBatchRecorder', _FakeRecorder)
    monkeypatch.setattr(runtime, 'certify_descriptor_case',
        lambda witnesses, case, *, case_index, tx_captures=(), action_ids=None:
            dict(counter=case_index, direction=case.direction,
                 payload=case.payload, completed=True,
                 tx_captures=list(tx_captures)))
    return monkeypatch


def _fake_boot_runner(*, fail_isr=False, ids=None):
    from myfuzz.scenario.contracts import ResourceBudget
    from myfuzz.scenario.genome import ScenarioGenome
    ids = ids or _fake_ids()
    runner = _FakeRunner(ids, fail_isr=fail_isr)
    budget = ResourceBudget(max_wall_time_ms=1000)
    runner.set_resource_budget(budget)
    template = ScenarioGenome('descriptor-dma-three-directions', 'IP_TO_CPU',
        'uart-descriptor-dma-ram-tx-cpu-isr', ('dma', 'cpu', 'uart'), 100000, ())
    boot = runtime.DescriptorBoot(runner, budget=budget, template=template,
        source_pins=runtime._source_pins())
    boot.boot()
    return boot


def test_boot_admits_every_serial_byte_and_chains_case_boundaries(fake_boot):
    boot = _fake_boot_runner()
    first = DescriptorCase.create('RX_TO_RAM', dst_index=0, payload=0x5A, length=2)
    second = DescriptorCase.create('RAM_TO_TX', dst_index=1, payload=0xA5, length=1)
    boot.cases.append(boot.run_case(first, case_index=1))
    boot.cases.append(boot.run_case(second, case_index=2))
    result = boot.finish()
    assert [command.value for command in result.plan.commands
            if isinstance(command, BatchSourceEvent)] == [
        *first.source_bytes, *second.source_bytes]
    assert [command.action_id for command in result.plan.commands
            if isinstance(command, BatchSourceEvent)] == [
        f'descriptor-1-{slot}' for slot in range(first.source_count)] + [
        f'descriptor-2-{slot}' for slot in range(second.source_count)]
    first_case, second_case = result.cases
    for case in result.cases:
        assert set(CASE_FIELDS) <= set(case)
    assert second_case['command_start'] == first_case['command_end']
    assert second_case['event_start'] == first_case['event_end']
    assert second_case['ticks_before'] == first_case['ticks_after']
    assert first_case['prefix_sha256'] != second_case['prefix_sha256']
    assert all(first_case['ticks_after'][name] > first_case['ticks_before'][name]
               for name in ('cpu', 'dma', 'uart'))
    assert result.phase == 'complete' and result.error is None


def test_boot_refuses_a_case_before_recording_any_command(fake_boot):
    boot = _fake_boot_runner()
    case = DescriptorCase.create('RX_TO_RAM', dst_index=2, payload=0x5A, length=1)
    before = (boot.recorder.commands, dict(boot.runner.local_ticks),
              boot.runner.event_count)
    with pytest.raises(DescriptorCaseRejected, match='destination_ram'):
        boot.run_case(case, case_index=1, windows={
            **descriptor_windows(),
            'destination_ram': (firmware.DESTINATION, firmware.DESTINATION + 8)})
    assert boot.recorder.commands == before[0]
    assert boot.runner.local_ticks == before[1]
    assert boot.runner.event_count == before[2]
    assert boot.case_failure is None


def test_boot_keeps_attempted_boundaries_when_the_isr_never_completes(fake_boot):
    boot = _fake_boot_runner(fail_isr=True)
    case = DescriptorCase.create('RX_TO_RAM', dst_index=0, payload=0x5A, length=1)
    started = (boot.recorder.commands, dict(boot.runner.local_ticks),
               boot.runner.event_count)
    with pytest.raises(RuntimeError, match='CPU ISR completion exceeded'):
        boot.run_case(case, case_index=1, max_rounds_per_case=2)
    failure = boot.case_failure
    assert failure is not None and failure['complete'] is False
    assert failure['phase'] == 'isr'
    assert failure['command_start'] == len(started[0])
    assert failure['event_start'] == started[2]
    assert failure['ticks_before'] == started[1]
    assert failure['command_end'] == len(boot.recorder.commands)
    assert failure['event_end'] == boot.runner.event_count
    assert failure['prefix_sha256'] is not None
    assert boot.phase == 'isr'
