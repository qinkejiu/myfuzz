"""Fixed external-serial-descriptor firmware for one-boot three-direction DMA.

The firmware is a fixed program: it contains no expected payload byte and no
testcase constant.  Every case arrives as four real 8N1 serial descriptor bytes
followed by ``len`` real 8N1 payload bytes; the CPU pops the descriptor with its
own ``lw RDATA`` accesses, decodes it, writes the RAM source words and then
writes the real DMA ``SOURCE/LEN/DEST/CONTROL`` registers.  The ISR reads the
real DMA status and length registers and commits ``mcause/status/len/payload/
counter`` without comparing any expected value.

Descriptor decode (fixed by this program)::

    direction = d0 & 3      # 0 RX_TO_RAM, 1 RAM_TO_RAM, 2 RAM_TO_TX, 3 illegal
    len       = (d1 & 3) + 1
    dst_index = d2 & 3
    payload   = d3          # every transferred word equals this byte

Direction code 3 is the declared illegal hook.  It configures the one declared
illegal master target (``ILLEGAL_TARGET``) as both source and destination, so
the real ``wbdmac`` takes its bus-error path (``i_mwb_err``), raises its native
interrupt, and the real ISR records the real status/length/mcause/counter.  S3
enables that case with ``expect='environment_error'``; S2 refused it pre-RTL.

Control word (wbdmac ``wbdmac.v``: bit 29 ``inc_s_n``, bit 28 ``inc_d_n``,
bits 27..16 key 0xfed, bits 9..0 block length 1)::

    RX_TO_RAM   0x2fed0001   # fixed source: every beat reads UART RDATA 0x18
    RAM_TO_RAM  0x0fed0001   # both addresses increment
    RAM_TO_TX   0x1fed0001   # fixed destination: every beat writes UART WDATA 0x1c

The P8 design note quotes a single fixed ``0x0fed0001``.  That word increments
both addresses, so the second beat of a multi-word RX transfer would read
``0x5000001c`` (write-only WDATA) and the second beat of a multi-word TX
transfer would write ``0x50000020`` (undeclared UART offset); both would take
the declared environment-error path instead of moving data.  Multi-word FIFO
reads are a hard S2 requirement, so the control word is direction-dependent and
the bit values are pinned in tests and the S2 report.
"""
from pathlib import Path

from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.opentitan_uart_session import GeneratedOpentitanUartSession
from myfuzz.local_harness.wishbone_dma_scenario_session import GeneratedWishboneDmaScenarioSession
from myfuzz.local_harness.wishbone_dma_session import MasterTargetWindow
from .ibex_dma_example import (DMA_BASE, ROOT, _addi, _artifact, _csr, _lui,
    _lw, _sw)
from .memory import MemoryRegion, PersistentMemory
from .ownership import InputField, InputOwner, compile_ownership
from .router import DataflowRouter, DeviceWindow
from .runner import Binding, ScenarioRunner

# Firmware layout.  Ibex fetches its reset vector at {boot[31:8], 8'h80}, so the
# main loop must start at 0x10080.  Its machine-external interrupt entry is
# {mtvec[31:8], 1'b0, 11, 2'b00}, i.e. mtvec base + 44 (ibex_if_stage.sv).
MAIN = 0x10080
MTVEC_BASE = 0x10400
ISR = MTVEC_BASE + 44
SOURCE_RAM = 0x22000
DESTINATION = 0x23000
RESULT = 0x24000
DEST_WORDS = 4
DESCRIPTOR_WORDS = 4
RESULT_BYTES = 24
COMPLETED = RESULT + 16
WITNESS = RESULT + 12
WITNESS_POINTER = RESULT + 20
BOOT_SEED_WORDS = (0, 0, 0, 0)

# Pinned OpenTitan UART register semantics (uart_reg_pkg.sv / uart_reg_top.sv /
# uart_core.sv): STATUS 0x14 with RXEMPTY=bit5, RDATA 0x18, WDATA 0x1c, and the
# exact CTRL word the fixed fixtures write.
UART_BASE = 0x50000000
UART_STATUS_OFFSET = 0x14
UART_RDATA_OFFSET = 0x18
UART_WDATA_OFFSET = 0x1C
UART_RXEMPTY_MASK = 1 << 5
UART_CTRL_8N1 = 0x80000003
UART_RDATA = UART_BASE + UART_RDATA_OFFSET
UART_WDATA = UART_BASE + UART_WDATA_OFFSET
#: One declared illegal master target.  0x50000020 is inside the UART window but
#: is neither a declared readable nor writable master offset, so the DMA session
#: takes its declared rejection path instead of touching a peripheral.
ILLEGAL_TARGET = UART_BASE + 0x20

DIRECTION_CODES = {'RX_TO_RAM': 0, 'RAM_TO_RAM': 1, 'RAM_TO_TX': 2,
                   'ILLEGAL': 3}
DIRECTIONS = ('RX_TO_RAM', 'RAM_TO_RAM', 'RAM_TO_TX')
#: Every descriptor direction the fixed firmware decodes.  ``ILLEGAL`` is a
#: declared error case, not a dataflow direction: it reaches the real wbdmac
#: bus-error path and is certified as ``environment_error``.
DECLARED_DIRECTIONS = DIRECTIONS + ('ILLEGAL',)
CONTROL_INC_S_N = 1 << 29
CONTROL_INC_D_N = 1 << 28
CONTROL_KEY = 0xFED
CONTROL_KEY_SHIFT = 16
CONTROL_KEY_MASK = 0xFFF << CONTROL_KEY_SHIFT
CONTROL_BLOCKLEN = 1
CONTROL_WORDS = {
    'RX_TO_RAM': 0x2FED0001,
    'RAM_TO_RAM': 0x0FED0001,
    'RAM_TO_TX': 0x1FED0001,
    'ILLEGAL': 0x0FED0001,
}
MAX_LENGTH = 4
MAX_SOURCE_BYTES = DESCRIPTOR_WORDS + MAX_LENGTH

# Declared wbdmac CONTROL/STATUS readback layout, copied from the pinned
# ``third_party/soc-zipcpu/rtl/peripherals/wbdmac.v`` (header comment lines
# 30-60 and the status concatenation near lines 604-608):
#
#   bit 31 busy              (dma_state != DMA_IDLE)
#   bit 30 cfg_err           (stopped after a bus error)
#   bit 29 !cfg_incs / inc_s_n
#   bit 28 !cfg_incd / inc_d_n
#   bit 27 always 0
#   bits 26..16 nread
#   bits 15..10 cfg_on_dev_trigger / cfg_dev_trigger
#   bits 9..0   cfg_blocklen_sub_one
#
# These names let evidence carry the *measured* word plus named bits.  No
# post-error status word is asserted here: the S3 gate must observe it first.
DMA_STATUS_BUSY_BIT = 31
DMA_STATUS_ERROR_BIT = 30
DMA_STATUS_INC_S_N_BIT = 29
DMA_STATUS_INC_D_N_BIT = 28
DMA_STATUS_NREAD_LOW = 16
DMA_STATUS_NREAD_HIGH = 26
DMA_STATUS_BLOCKLEN_LOW = 0
DMA_STATUS_BLOCKLEN_HIGH = 9
DMA_STATUS_LAYOUT = {
    'busy': [DMA_STATUS_BUSY_BIT, DMA_STATUS_BUSY_BIT],
    'error': [DMA_STATUS_ERROR_BIT, DMA_STATUS_ERROR_BIT],
    'inc_s_n': [DMA_STATUS_INC_S_N_BIT, DMA_STATUS_INC_S_N_BIT],
    'inc_d_n': [DMA_STATUS_INC_D_N_BIT, DMA_STATUS_INC_D_N_BIT],
    'nread': [DMA_STATUS_NREAD_LOW, DMA_STATUS_NREAD_HIGH],
    'blocklen_sub_one': [DMA_STATUS_BLOCKLEN_LOW,
                         DMA_STATUS_BLOCKLEN_HIGH],
}


def dma_status_fields(value):
    """Named fields and set-bit positions of one measured DMA status word.

    Pure decomposition of a real 32-bit readback; it starts no RTL and adds no
    expected value.  Evidence stores both the raw word and ``bits`` so a later
    audit can pin the exact post-error reading.
    """
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError('DMA status must be a real 32-bit readback')
    def field(name):
        low, high = DMA_STATUS_LAYOUT[name]
        return (value >> low) & ((1 << (high - low + 1)) - 1)
    return dict(raw=value, bits=[bit for bit in range(32)
                                 if value & (1 << bit)],
        busy=field('busy'), error=field('error'), inc_s_n=field('inc_s_n'),
        inc_d_n=field('inc_d_n'), nread=field('nread'),
        blocklen_sub_one=field('blocklen_sub_one'))


def descriptor_program(direction, dst_index, length):
    """The exact real DMA program the CPU must write for one decoded case.

    Pure function: it starts no RTL and reads no firmware expectation.  It is
    the declared program the journal evidence is checked against, not an input
    the firmware reads.
    """
    if direction not in DECLARED_DIRECTIONS:
        raise ValueError('undeclared descriptor direction')
    if type(dst_index) is not int or not 0 <= dst_index < DEST_WORDS:
        raise ValueError('dst_index is outside the declared destination window')
    if type(length) is not int or not 1 <= length <= MAX_LENGTH:
        raise ValueError('length is outside the declared descriptor window')
    if direction == 'ILLEGAL':
        # The fixed firmware's illegal path writes the declared illegal target
        # into both SOURCE and DEST and drains the queued payload bytes; the
        # first master read is rejected by the declared target environment, so
        # no beat ever delivers data and the destination RAM is never written.
        return dict(direction='ILLEGAL', source=ILLEGAL_TARGET,
            destination=ILLEGAL_TARGET, length=length,
            control=CONTROL_WORDS['ILLEGAL'], witness=DESTINATION,
            source_words=(), destination_words=(), cpu_source_words=(),
            attempted_source_words=(ILLEGAL_TARGET,),
            attempted_destination_words=())
    if direction == 'RX_TO_RAM':
        source = UART_RDATA
        destination = DESTINATION + 4 * dst_index
        witness = destination
        if dst_index + length > DEST_WORDS:
            raise ValueError('destination words exceed the declared RAM window')
        source_words = (UART_RDATA,) * length
        destination_words = tuple(destination + 4 * index
                                  for index in range(length))
    elif direction == 'RAM_TO_RAM':
        source = SOURCE_RAM
        destination = DESTINATION + 4 * dst_index
        witness = destination
        if dst_index + length > DEST_WORDS:
            raise ValueError('destination words exceed the declared RAM window')
        source_words = tuple(SOURCE_RAM + 4 * index for index in range(length))
        destination_words = tuple(destination + 4 * index
                                  for index in range(length))
    else:
        source = SOURCE_RAM
        destination = UART_WDATA
        witness = SOURCE_RAM
        source_words = tuple(SOURCE_RAM + 4 * index for index in range(length))
        # inc_d_n: every master write beat targets the same WDATA register.
        destination_words = (UART_WDATA,) * length
    return dict(direction=direction, source=source, destination=destination,
        length=length, control=CONTROL_WORDS[direction], witness=witness,
        source_words=source_words, destination_words=destination_words,
        cpu_source_words=(tuple(SOURCE_RAM + 4 * index for index in range(length))
                          if direction != 'RX_TO_RAM' else ()))


def _bne(a, b, offset):
    value = offset & 0x1FFF
    return (((value >> 12) & 1) << 31 | ((value >> 5) & 63) << 25
            | b << 20 | a << 15 | 1 << 12 | ((value >> 1) & 15) << 8
            | ((value >> 11) & 1) << 7 | 0x63)


def _beq(a, b, offset):
    value = offset & 0x1FFF
    return (((value >> 12) & 1) << 31 | ((value >> 5) & 63) << 25
            | b << 20 | a << 15 | 0 << 12 | ((value >> 1) & 15) << 8
            | ((value >> 11) & 1) << 7 | 0x63)


def _jal(rd, offset):
    value = offset & 0x1FFFFF
    return (((value >> 20) & 1) << 31 | ((value >> 1) & 0x3FF) << 21
            | ((value >> 11) & 1) << 20 | ((value >> 12) & 0xFF) << 12
            | rd << 7 | 0x6F)


def _andi(rd, rs, immediate):
    return (immediate & 0xFFF) << 20 | rs << 15 | 7 << 12 | rd << 7 | 0x13


def _slli(rd, rs, shift):
    return (shift & 0x1F) << 20 | rs << 15 | 1 << 12 | rd << 7 | 0x13


def _or(rd, rs1, rs2):
    return rs2 << 20 | rs1 << 15 | 6 << 12 | rd << 7 | 0x33


def _add(rd, rs1, rs2):
    return rs2 << 20 | rs1 << 15 | 0 << 12 | rd << 7 | 0x33


_MRET = 0x30200073


class _Assembly:
    """Minimal RV32I assembler with label fixups (pure Python, no RTL)."""

    def __init__(self):
        self.words = []
        self.labels = {}
        self._fixups = []

    def label(self, name):
        if not isinstance(name, str) or not name or name in self.labels:
            raise ValueError('invalid or duplicate firmware label')
        self.labels[name] = len(self.words) * 4

    def emit(self, *words):
        self.words.extend(word & 0xFFFFFFFF for word in words)

    def branch(self, operator, rs1, rs2, label):
        self._fixups.append((len(self.words), operator, rs1, rs2, label))
        self.words.append(0)

    def jump(self, label):
        self._fixups.append((len(self.words), 'jal', 0, 0, label))
        self.words.append(0)

    def encode(self):
        for index, operator, rs1, rs2, label in self._fixups:
            if label not in self.labels:
                raise ValueError(f'undefined firmware label {label}')
            offset = self.labels[label] - index * 4
            if operator == 'bne':
                word = _bne(rs1, rs2, offset)
            elif operator == 'beq':
                word = _beq(rs1, rs2, offset)
            elif operator == 'jal':
                word = _jal(0, offset)
            else:
                raise ValueError('unknown firmware branch operator')
            self.words[index] = word
        return tuple(self.words)


def _main(assembly):
    """Boot plus the descriptor loop; x1/x2/x4/x5 live across cases.

    The ISR owns x6/x7/x8/x9 only, and it can only fire after the CONTROL store
    starts a real DMA transfer, when the main loop uses x10/x11 exclusively.
    """
    emit = assembly.emit
    # Fixed pointers.
    emit(_lui(1, DMA_BASE), _lui(2, UART_BASE), _lui(4, DESTINATION),
         _lui(5, RESULT))
    # Real UART transmitter/receiver enable word.
    emit(_lui(3, 0x80000000), _addi(3, 3, 3), _sw(3, 2, 0x10))
    # Boot source words: the design's "boot writes RAM source words" step.  Four
    # real CPU stores; later cases overwrite them with the decoded payload.
    emit(_lui(7, SOURCE_RAM), _addi(3, 0, 0), _addi(9, 0, DEST_WORDS))
    assembly.label('seed')
    emit(_sw(3, 7, 0), _addi(7, 7, 4), _addi(9, 9, -1))
    assembly.branch('bne', 9, 0, 'seed')
    # Native trap setup: vectored machine-external entry at MTVEC_BASE + 44.
    emit(_lui(7, 0x10000), _addi(7, 7, MTVEC_BASE & 0xFFF))
    emit(_csr(0x305, 7))
    emit(_lui(7, 0x1000), _addi(7, 7, -0x800), _csr(0x304, 7))
    emit(_addi(7, 0, 8), _csr(0x300, 7))
    # One decoded case per loop iteration.
    assembly.label('case')
    for rd, name in ((12, 'd0'), (13, 'd1'), (14, 'd2'), (8, 'd3')):
        assembly.label('poll_' + name)
        emit(_lw(3, 2, UART_STATUS_OFFSET), _andi(3, 3, UART_RXEMPTY_MASK))
        assembly.branch('bne', 3, 0, 'poll_' + name)
        emit(_lw(rd, 2, UART_RDATA_OFFSET))
    emit(_andi(12, 12, 3), _andi(13, 13, 3), _addi(13, 13, 1),
         _andi(14, 14, 3), _slli(14, 14, 2), _add(16, 4, 14))
    assembly.branch('beq', 12, 0, 'path_rx')
    emit(_addi(3, 0, 1))
    assembly.branch('beq', 12, 3, 'path_ram')
    emit(_addi(3, 0, 2))
    assembly.branch('beq', 12, 3, 'path_tx')
    assembly.jump('path_illegal')
    # RX_TO_RAM: source is the real UART RDATA register.
    assembly.label('path_rx')
    emit(_addi(15, 2, UART_RDATA_OFFSET), _sw(16, 5, WITNESS_POINTER - RESULT))
    assembly.jump('configure')
    # RAM_TO_RAM: source is the CPU-written RAM words, destination dst_index.
    assembly.label('path_ram')
    emit(_lui(15, SOURCE_RAM), _sw(16, 5, WITNESS_POINTER - RESULT))
    assembly.jump('ram_source')
    # RAM_TO_TX: source is the CPU-written RAM words, destination UART WDATA.
    assembly.label('path_tx')
    emit(_lui(15, SOURCE_RAM), _sw(15, 5, WITNESS_POINTER - RESULT),
         _addi(16, 2, UART_WDATA_OFFSET))
    # CPU materializes the RAM source words and drains the stream payload bytes.
    assembly.label('ram_source')
    emit(_lui(7, SOURCE_RAM), _add(9, 13, 0))
    assembly.label('write_words')
    emit(_sw(8, 7, 0), _addi(7, 7, 4), _addi(9, 9, -1))
    assembly.branch('bne', 9, 0, 'write_words')
    emit(_add(9, 13, 0))
    assembly.label('drain')
    emit(_lw(3, 2, UART_STATUS_OFFSET), _andi(3, 3, UART_RXEMPTY_MASK))
    assembly.branch('bne', 3, 0, 'drain')
    emit(_lw(11, 2, UART_RDATA_OFFSET), _addi(9, 9, -1))
    assembly.branch('bne', 9, 0, 'drain')
    assembly.jump('configure')
    # Declared illegal hook: S3 error-ISR path; S2 refuses this direction.
    assembly.label('path_illegal')
    emit(_lui(15, UART_BASE), _addi(15, 15, ILLEGAL_TARGET - UART_BASE),
         _add(16, 15, 0), _sw(4, 5, WITNESS_POINTER - RESULT),
         _add(9, 13, 0))
    assembly.label('illegal_drain')
    emit(_lw(3, 2, UART_STATUS_OFFSET), _andi(3, 3, UART_RXEMPTY_MASK))
    assembly.branch('bne', 3, 0, 'illegal_drain')
    emit(_lw(11, 2, UART_RDATA_OFFSET), _addi(9, 9, -1))
    assembly.branch('bne', 9, 0, 'illegal_drain')
    # Program the real DMA registers, then wait for the real ISR counter.
    assembly.label('configure')
    emit(_sw(15, 1, 8), _sw(16, 1, 12), _sw(13, 1, 4))
    emit(_lui(3, 0x0FED0000), _addi(3, 3, 1))
    assembly.branch('beq', 12, 0, 'control_rx')
    emit(_addi(7, 0, 2))
    assembly.branch('bne', 12, 7, 'control_ready')
    emit(_lui(7, 0x10000000), _or(3, 3, 7))
    assembly.jump('control_ready')
    assembly.label('control_rx')
    emit(_lui(7, 0x20000000), _or(3, 3, 7))
    assembly.label('control_ready')
    emit(_lw(10, 5, COMPLETED - RESULT), _sw(3, 1, 0))
    assembly.label('wait')
    emit(_lw(11, 5, COMPLETED - RESULT))
    assembly.branch('beq', 11, 10, 'wait')
    assembly.jump('case')


def _isr(assembly):
    emit = assembly.emit
    assembly.label('isr')
    emit(_csr(0x342, 0, 6), _sw(6, 5, 0))
    assembly.label('isr_status')
    emit(_lw(7, 1, 0), _sw(7, 5, 4))
    assembly.label('isr_length')
    emit(_lw(8, 1, 4), _sw(8, 5, 8))
    assembly.label('isr_witness_pointer')
    emit(_lw(9, 5, WITNESS_POINTER - RESULT))
    assembly.label('isr_witness')
    emit(_lw(9, 9, 0), _sw(9, 5, WITNESS - RESULT))
    # The Runner's 16 CPU-tick IRQ pulse must expire while hardware MIE is clear.
    emit(_addi(9, 0, 32))
    assembly.label('isr_delay')
    emit(_addi(9, 9, -1))
    assembly.branch('bne', 9, 0, 'isr_delay')
    assembly.label('isr_counter_load')
    emit(_lw(9, 5, COMPLETED - RESULT), _addi(9, 9, 1),
         _sw(9, 5, COMPLETED - RESULT), _MRET)


def descriptor_program_words():
    """Encode both routines once and expose their label byte addresses.

    Returns ``(main_words, isr_words, main_labels, isr_labels)``; label values
    are PC offsets inside their own routine, which is what the runtime needs to
    make the RVFI load/store joins from real ``cpu_retire`` records.
    """
    main, isr = _Assembly(), _Assembly()
    _main(main)
    _isr(isr)
    main_words, isr_words = main.encode(), isr.encode()
    if (MAIN & 0xFF) != 0x80 or MTVEC_BASE % 256 or ISR != MTVEC_BASE + 44:
        raise ValueError('firmware trap layout is not Ibex-vector compatible')
    if MAIN + 4 * len(main_words) > MTVEC_BASE:
        raise ValueError('descriptor main loop overlaps the native ISR base')
    if ISR + 4 * len(isr_words) > 0x30000:
        raise ValueError('descriptor ISR exceeds the declared RAM region')
    return main_words, isr_words, dict(main.labels), dict(isr.labels)


_MAIN_WORDS, _ISR_WORDS, _MAIN_LABELS, _ISR_LABELS = descriptor_program_words()
ISR_PCS = {name: ISR + offset for name, offset in sorted(_ISR_LABELS.items())}
MAIN_PCS = {name: MAIN + offset for name, offset in sorted(_MAIN_LABELS.items())}
MAIN_WORDS = _MAIN_WORDS
ISR_WORDS = _ISR_WORDS


def descriptor_uart_images():
    """Fixed byte images for main, ISR and the declared data pages."""
    def encode(words):
        return b''.join(word.to_bytes(4, 'little') for word in words)
    return {MAIN: encode(_MAIN_WORDS), ISR: encode(_ISR_WORDS),
        SOURCE_RAM: bytes(4 * DEST_WORDS), DESTINATION: bytes(4 * DEST_WORDS),
        RESULT: bytes(RESULT_BYTES)}


def make_descriptor_runner(*, cache_dir: Path):
    """One native Ibex/wbdmac/OpenTitan-UART Runner with both master windows.

    The UART is a genome-owned serial source with FIFO observation (RDATA reads
    pop the real RX FIFO) and it also exports the real WDATA write window and
    TX serial pin, so all three DMA directions use the same boot and the same
    source authentication phase.
    """
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0x10000, 0x20000),),
        initialization_seed=17, max_initialized_bytes=0x20000)
    for address, image in descriptor_uart_images().items():
        memory.preload(address, image)
    uart = GeneratedOpentitanUartSession(_artifact(
        'configs/peripherals/opentitan_uart_fifo_local/component_profile.json',
        'uart'), base_dir=ROOT, cache_dir=cache_dir, source=None,
        read_rx_after_source=False, command_timeout_seconds=30)
    target = MasterTargetWindow(component='uart', base=UART_BASE, size=0x1000,
        endpoint=uart, writable_offsets=(UART_WDATA_OFFSET,),
        accepted_write_values=range(256), readable_offsets=(UART_RDATA_OFFSET,))
    dma = GeneratedWishboneDmaScenarioSession(_artifact(
        'configs/peripherals/zipcpu_wbdmac/component_profile.json', 'dma'),
        base_dir=ROOT, cache_dir=cache_dir, memory=memory,
        master_targets=(target,), command_timeout_seconds=30)
    cpu = GeneratedCve2Session(_artifact(
        'configs/cpus/ibex_rvfi_local/component_profile.json', 'cpu'),
        base_dir=ROOT, cache_dir=cache_dir, memory=memory,
        router=DataflowRouter((DeviceWindow('dma', DMA_BASE, 16, dma),
            DeviceWindow('uart', UART_BASE, 0x1000, uart))),
        defer_mmio=True, native_irq_receipts=True, command_timeout_seconds=30)
    binding = Binding('dma', 'irq', 'cpu', 'irq', 1)
    ownership = compile_ownership((InputField('cpu', 'irq', 1),
        InputField('uart', 'uart_rx_byte', 8)),
        (InputOwner('cpu', 'irq', 0, 1, 'bound', 'dma.irq'),
         InputOwner('uart', 'uart_rx_byte', 0, 8, 'source', 'external-serial-byte')))
    return ScenarioRunner(sessions={'cpu': cpu, 'dma': dma, 'uart': uart},
        ownership=ownership, bindings=(binding,), irq_pulses={binding: 16})
