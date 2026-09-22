"""Step 8 unit tests: the generated boot/ISR program, decoded independently.

Nothing here needs a simulator.  The image is decoded by an independent RISC-V
decoder written in this file (the generator's assembler encoders are never
imported), then walked with enough constant tracking to name every MMIO store
target and every CSR write.  The point of the walk is to check the *intent* of
the generated program against the plan:

* the CSRs the requirements name are written with the plan's addresses
  (mtvec, mie.MEIE, mstatus.MIE);
* the MMIO stores land on the absolute addresses the plan declares for the
  peripheral window, the controller window and the RAM report record;
* the mret exists, and the completion flag reaches RAM;
* the same plan and request always produce the same bytes and the same
  document;
* moving a peripheral's fixed address in the request moves the program's
  store target with it, because no address is baked in;
* a plan with no interrupt source is refused instead of silently emitting an
  ISR that could never be entered.
"""
from __future__ import annotations

import json
import unittest
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

from myfuzz.composition.component_profile import (
    load_component_profile,
    load_composition_request,
)
from myfuzz.composition.soc_boot_program import (
    COMPLETION_FLAG,
    HANDLER_SAVED_REGISTERS as HANDLER_SAVES,
    FLAG_OFFSET,
    MAX_PROGRAM_BYTES,
    PROGRAM_SCHEMA,
    REPORT_BYTES,
    REPORT_FIELDS,
    REPORT_OFFSET,
    BootProgramError,
    ProgramRequest,
    build_boot_program,
)
from myfuzz.composition.soc_composition import build_composition
from myfuzz.composition.soc_runtime import MAX_OBSERVED_WORDS, _external_inputs

from .soc_generation_fixture import EXAMPLE, ROOT, example_plan

CSR_NAMES = {0x300: "mstatus", 0x304: "mie", 0x305: "mtvec", 0x341: "mepc",
             0x342: "mcause", 0xB00: "mcycle"}


# ---------------------------------------------------------------------------
# independent decoder (no encoder from the generator is used)
# ---------------------------------------------------------------------------


def _sign(value: int, bits: int) -> int:
    sign_bit = 1 << (bits - 1)
    return (value & (sign_bit - 1)) - (value & sign_bit)


def decode(word: int) -> dict:
    """Decode one 32-bit instruction into its fields, independently."""
    return {
        "word": word,
        "opcode": word & 0x7F,
        "rd": (word >> 7) & 0x1F,
        "funct3": (word >> 12) & 0x7,
        "rs1": (word >> 15) & 0x1F,
        "rs2": (word >> 20) & 0x1F,
        "funct7": (word >> 25) & 0x7F,
        "imm_i": _sign(word >> 20, 12),
        "imm_s": _sign((((word >> 25) & 0x7F) << 5) | ((word >> 7) & 0x1F), 12),
        "imm_b": _sign((((word >> 31) & 1) << 12) | (((word >> 7) & 1) << 11)
                       | (((word >> 25) & 0x3F) << 5) | (((word >> 8) & 0xF) << 1), 13),
        "imm_u": word & 0xFFFFF000,
        "imm_j": _sign((((word >> 31) & 1) << 20) | (((word >> 12) & 0xFF) << 12)
                       | (((word >> 20) & 1) << 11) | (((word >> 21) & 0x3FF) << 1), 21),
    }


def name(ins: dict) -> str:
    """The mnemonic this decoder recognises, or ``unknown``."""
    opcode = ins["opcode"]
    if opcode == 0x37:
        return "lui"
    if opcode == 0x17:
        return "auipc"
    if opcode == 0x6F:
        return "jal"
    if opcode == 0x67:
        return "jalr"
    if opcode == 0x63:
        return {0b000: "beq", 0b001: "bne", 0b100: "blt", 0b101: "bge"}.get(ins["funct3"],
                                                                            "branch")
    if opcode == 0x03:
        return {0b010: "lw"}.get(ins["funct3"], "load")
    if opcode == 0x23:
        return {0b010: "sw"}.get(ins["funct3"], "store")
    if opcode == 0x13:
        return {0b000: "addi", 0b111: "andi", 0b001: "slli", 0b101: "srli"}.get(
            ins["funct3"], "op-imm")
    if opcode == 0x33:
        if ins["funct7"] == 0x20:
            return "sub"
        return {0b000: "add", 0b110: "or", 0b111: "and"}.get(ins["funct3"], "op")
    if opcode == 0x73:
        if ins["funct3"] == 0:
            return {0x302: "mret", 0x000: "ecall", 0x001: "ebreak"}.get(ins["imm_i"],
                                                                        "system")
        return {0b001: "csrrw", 0b010: "csrrs", 0b011: "csrrc"}.get(ins["funct3"], "csr")
    return "unknown"


def body_walk(program) -> dict:
    """Walk the program body (not the entry trampoline and its padding)."""
    body_base = int(program.document["entry"]["hardware_entry"])
    offset = body_base - program.entry_address
    return walk(program.image[offset:], body_base)


def walk(image: bytes, base: int) -> dict:
    """Decode and walk the image, tracking constants to name store targets.

    The walk is linear.  The generated body re-materialises every base register
    inside the block that uses it, so a linear walk names the same targets a
    control-flow-sensitive one would; an unexpected target would simply not
    match the plan-derived addresses the tests assert.
    """
    registers: dict[int, int | None] = {}
    stores: list[dict] = []
    loads: list[dict] = []
    csr_writes: list[dict] = []
    csr_reads: list[dict] = []
    instructions: list[dict] = []
    for index in range(len(image) // 4):
        word = int.from_bytes(image[index * 4:index * 4 + 4], "little")
        ins = decode(word)
        ins["address"] = base + index * 4
        ins["name"] = name(ins)
        instructions.append(ins)
        mnemonic = ins["name"]
        rd, rs1, rs2 = ins["rd"], ins["rs1"], ins["rs2"]

        def value(register: int) -> int | None:
            # x0 is hardwired to zero: a walker that forgot this would lose
            # every ``li`` idiom the generator emits.
            return 0 if register == 0 else registers.get(register)

        if mnemonic == "lui":
            registers[rd] = ins["imm_u"] & 0xFFFF_FFFF
        elif mnemonic == "auipc":
            registers[rd] = None
        elif mnemonic == "addi":
            registers[rd] = None if value(rs1) is None else (value(rs1) + ins["imm_i"]) & 0xFFFF_FFFF
        elif mnemonic == "andi":
            registers[rd] = None if value(rs1) is None else (value(rs1) & ins["imm_i"]) & 0xFFFF_FFFF
        elif mnemonic == "slli":
            shift = (word >> 20) & 0x3F
            registers[rd] = None if value(rs1) is None else (value(rs1) << shift) & 0xFFFF_FFFF
        elif mnemonic == "srli":
            shift = (word >> 20) & 0x3F
            registers[rd] = None if value(rs1) is None else (value(rs1) >> shift) & 0xFFFF_FFFF
        elif mnemonic in ("add", "sub", "or", "and"):
            left, right = value(rs1), value(rs2)
            if left is None or right is None:
                registers[rd] = None
            elif mnemonic == "add":
                registers[rd] = (left + right) & 0xFFFF_FFFF
            elif mnemonic == "sub":
                registers[rd] = (left - right) & 0xFFFF_FFFF
            elif mnemonic == "or":
                registers[rd] = left | right
            else:
                registers[rd] = left & right
        elif mnemonic == "sw":
            stores.append({"address": None if value(rs1) is None else
                           (value(rs1) + ins["imm_s"]) & 0xFFFF_FFFF,
                           "value": value(rs2), "base": value(rs1),
                           "offset": ins["imm_s"], "at": ins["address"]})
        elif mnemonic == "lw":
            loads.append({"address": None if value(rs1) is None else
                          (value(rs1) + ins["imm_i"]) & 0xFFFF_FFFF,
                          "base": value(rs1), "offset": ins["imm_i"],
                          "at": ins["address"]})
            registers[rd] = None                  # memory contents are unknown
        elif mnemonic in ("csrrw", "csrrs", "csrrc"):
            csr = (word >> 20) & 0xFFF
            written = value(rs1)
            if mnemonic == "csrrc" and written is not None:
                written = (~written) & 0xFFFF_FFFF
            csr_writes.append({"csr": csr, "name": CSR_NAMES.get(csr, f"csr:{csr:#x}"),
                               "value": written, "rd": rd, "at": ins["address"]})
            if rd != 0:
                csr_reads.append({"csr": csr, "name": CSR_NAMES.get(csr, f"csr:{csr:#x}"),
                                  "rd": rd, "at": ins["address"]})
                registers[rd] = None
        elif mnemonic in ("jal", "jalr") and rd != 0:
            registers[rd] = None
        elif mnemonic == "unknown":
            raise AssertionError("undecodable word 0x%08x at 0x%08x"
                                 % (word, ins["address"]))
    return {"instructions": instructions, "stores": stores, "loads": loads,
            "csr_writes": csr_writes, "csr_reads": csr_reads,
            "words": len(image) // 4}


# ---------------------------------------------------------------------------
# plan fixtures
# ---------------------------------------------------------------------------


def _example_request_document() -> dict:
    document = json.loads((EXAMPLE / "request.json").read_text(encoding="utf-8"))
    document["peripherals"] = [item for item in document["peripherals"]
                               if item["instance_id"] != "uart1"]
    return document


def _profiles() -> dict:
    profiles: dict = {}
    for path in (ROOT / "examples/soc_generation/profiles").glob("*.json"):
        profile = load_component_profile(path)
        profiles[str(path.relative_to(ROOT))] = profile
        profiles.setdefault(profile.component_id, profile)
    return profiles


def _plan_from(document: dict):
    profiles = _profiles()
    request = load_composition_request(document, profiles=profiles)
    return build_composition(request, base_dir=ROOT)


def _declared_register_rows(plan) -> list[tuple[str, object]]:
    """``(instance_id, declared register)`` for every bound peripheral register."""
    rows: list[tuple[str, object]] = []
    for instance in plan.instances:
        if instance.kind != "peripheral" or instance.profile.address is None:
            continue
        for register in instance.profile.address.registers:
            rows.append((instance.instance_id, register))
    return rows


def _cpu_only_plan():
    document = _example_request_document()
    document["request_id"] = "novacore-alone"
    document["peripherals"] = []
    return _plan_from(document)


def _controller_base(plan) -> int:
    return int(plan.interrupt_document["controller"]["window"]["base"])


def _peripheral_base(plan, instance_id: str) -> int:
    for record in plan.target_records:
        if record.get("instance_id") == instance_id:
            return int(record["window"]["base"])
    raise AssertionError(f"plan has no window for {instance_id}")


class DecoderTests(unittest.TestCase):
    """The decoder itself is checked against hand-encoded instructions."""

    def test_decoder_reads_the_fields_the_tests_assert_on(self) -> None:
        self.assertEqual("lui", name(decode(0x400002B7)))
        self.assertEqual("addi", name(decode(0x00100293)))
        self.assertEqual("sw", name(decode(0x0262A223)))
        self.assertEqual("csrrw", name(decode(0x30529073)))
        self.assertEqual("csrrs", name(decode(0x3042A073)))
        self.assertEqual("mret", name(decode(0x30200073)))
        self.assertEqual(0x305, (0x30529073 >> 20) & 0xFFF)
        self.assertEqual(36, decode(0x0262A223)["imm_s"])


class ProgramShapeTests(unittest.TestCase):
    """The closed-loop program decodes to the required instruction sequence."""

    @classmethod
    def setUpClass(cls):
        cls.plan = example_plan()

    def program(self, request: ProgramRequest = ProgramRequest()):
        return build_boot_program(self.plan, request=request)

    def test_entry_is_the_cpu_profiles_reset_vector_and_the_size_is_bounded(self) -> None:
        program = self.program()
        contract = self.plan.request.cpu.profile.cpu
        self.assertEqual(int(contract.reset_vector), program.entry_address)
        self.assertGreater(len(program.image), 0)
        self.assertLessEqual(len(program.image), MAX_PROGRAM_BYTES)
        rom = self.plan.request.memory[0]
        self.assertLessEqual(len(program.image), 0x10000,
                             "the program must fit the declared ROM region")
        self.assertEqual(0, len(program.image) % 4, "32-bit encodings only")

    def test_program_schema_and_document_identities(self) -> None:
        program = self.program()
        document = program.document
        self.assertEqual(PROGRAM_SCHEMA, document["schema_version"])
        self.assertEqual(self.plan.plan_hash, document["plan_hash"])
        self.assertEqual(program.entry_address, document["entry"]["reset_vector"])
        self.assertEqual(program.flag_address, document["memory"]["flag_address"])
        self.assertEqual(program.report_address, document["memory"]["report_address"])
        # The report record must be inside the runtime's readback window.
        self.assertLessEqual(REPORT_OFFSET + REPORT_BYTES, MAX_OBSERVED_WORDS * 8)
        self.assertEqual(program.flag_address, document["memory"]["flag_address"])
        self.assertEqual(program.flag_address, int(self.plan.request.memory[1].base) + FLAG_OFFSET)
        self.assertEqual(program.report_address,
                         int(self.plan.request.memory[1].base) + REPORT_OFFSET)
        self.assertEqual(len(REPORT_FIELDS), len({offset for _, offset in REPORT_FIELDS}))

    def test_isa_and_extensions_come_from_the_cpu_profile(self) -> None:
        program = self.program()
        contract = self.plan.request.cpu.profile.cpu
        self.assertEqual(str(contract.family), program.document["isa"]["family"])
        self.assertEqual(int(contract.xlen), program.document["isa"]["xlen"])
        self.assertEqual([str(item) for item in contract.extensions],
                         program.document["isa"]["extensions"])
        self.assertFalse(program.document["isa"]["compressed_encodings"])
        self.assertEqual("machine", program.document["isa"]["privilege"])

    def test_required_csr_writes_and_mret_are_present(self) -> None:
        program = self.program()
        body_base = int(program.document["entry"]["hardware_entry"])
        walked = body_walk(program)
        handler = int(program.document["entry"]["handler_address"])
        writes = [(item["name"], item["value"]) for item in walked["csr_writes"]]
        self.assertIn(("mtvec", handler), writes,
                      "mtvec must be written with the generated handler address")
        self.assertIn(("mie", 1 << 11), writes, "mie.MEIE must be set")
        self.assertIn(("mstatus", 1 << 3), writes, "mstatus.MIE must be set")
        self.assertIn(("mcycle", None), [(item["name"], None)
                                         for item in walked["csr_reads"]])
        mnemonics = [ins["name"] for ins in walked["instructions"]]
        self.assertGreaterEqual(mnemonics.count("mret"), 2,
                                "the handler returns with mret and the exception path too")
        # The handler address is inside the body and word aligned.
        self.assertGreaterEqual(handler, body_base)
        self.assertEqual(handler % 4, 0)
        self.assertIn(handler, [ins["address"] for ins in walked["instructions"]])

    def test_the_trap_vector_table_covers_every_convention(self) -> None:
        """mtvec points at a 256-byte-aligned table of jumps to one handler.

        The CPU profile declares no trap-vector convention, so the program must
        not assume one: a direct-mode core jumps to the base, the pinned Ibex
        clears mtvec[7:0] for exceptions and jumps to base + 4*cause for
        interrupts (ibex_if_stage.sv:222-228).  Every entry of the table jumps to
        the same handler, so all of them land in the handler.
        """
        program = self.program()
        entry = program.document["entry"]
        table = int(entry["handler_address"])
        isr = int(entry["isr_address"])
        self.assertEqual(0, table % 256, "the trap vector base must be 256-byte aligned")
        self.assertEqual(table + 256, isr)
        self.assertEqual(64, int(entry["vector_table"]["entries"]))
        walked = body_walk(program)
        by_address = {ins["address"]: ins for ins in walked["instructions"]}
        # Every table entry is a jump to the same handler.
        for index in range(64):
            ins = by_address[table + index * 4]
            self.assertEqual("jal", ins["name"], "entry %d" % index)
            self.assertEqual(0, ins["rd"])
            self.assertEqual(isr, table + index * 4 + ins["imm_j"],
                             "entry %d jumps to the handler" % index)
        # Behind the register saves, the handler reads mcause to dispatch.
        reads = [by_address[isr + index * 4] for index in range(len(HANDLER_SAVES) + 2)]
        self.assertIn((0x342, 6), [(ins["word"] >> 20 & 0xFFF, ins["rd"]) for ins in reads],
                      "the handler reads mcause into x6")

    def test_the_handler_preserves_the_interrupted_flow(self) -> None:
        """The handler saves and restores every register it uses."""
        program = self.program()
        walked = body_walk(program)
        isr = int(program.document["entry"]["isr_address"])
        by_address = {ins["address"]: ins for ins in walked["instructions"]}
        for register in (5, 6, 7, 28, 29, 30, 31):
            self.assertIn(
                (register, 2),  # sw register, 0(sp)
                [(ins["rs2"], ins["rs1"]) for ins in walked["instructions"]
                 if ins["name"] == "sw" and ins["address"] >= isr
                 and ins["address"] < isr + 32],
                "x%d is saved at handler entry" % register)
            self.assertIn(
                (register, 2),
                [(ins["rd"], ins["rs1"]) for ins in walked["instructions"]
                 if ins["name"] == "lw" and ins["address"] >= isr],
                "x%d is restored before mret" % register)
        self.assertLess(by_address[isr]["address"], by_address[isr]["address"] + 4)
        self.assertEqual(len(set(HANDLER_SAVES)), 7, "seven saved registers => 28 bytes")

    def test_mmio_stores_land_on_the_plan_addresses(self) -> None:
        program = self.program()
        walked = body_walk(program)
        stores = [(item["address"], item["value"]) for item in walked["stores"]]
        gpio_base = _peripheral_base(self.plan, "gpio0")
        controller_base = _controller_base(self.plan)
        # The declared peripheral interrupt-enable register, offset from the
        # profile's own register map, at the plan's window base.  Its value is
        # the preserved read-back word with the declared bit OR-ed in, so the
        # store value is only known through the instructions around it.
        enable = [index for index, item in enumerate(walked["stores"])
                  if item["address"] == gpio_base + 0x0C]
        self.assertTrue(enable, "IRQ_EN (offset 0x0c) of the source's declared window")
        enable_index = walked["instructions"].index(next(
            item for item in walked["instructions"]
            if item["address"] == walked["stores"][enable[0]]["at"]))
        nearby = walked["instructions"][max(0, enable_index - 5):enable_index]
        self.assertTrue(any(item["name"] == "or" for item in nearby),
                        "the declared enable bit is OR-ed into the preserved word")
        self.assertTrue(any(item["name"] == "addi" and item["rs1"] == 0
                            and item["imm_i"] == 1 for item in nearby),
                        "the OR-ed mask is the source's declared enable bit (bit 0)")
        self.assertIn(gpio_base + 0x0C, [item["address"] for item in walked["loads"]],
                      "and the register is read back first")
        # The controller's ENABLE word, offset from the plan's register map.  The
        # controller numbers bitmap bit k as source id 32*j+k with bit 0 reserved
        # (soc_irq_controller.sv lines 4-5), so the mask is 1 << (id % 32).
        enabled = [item for item in program.document["sources"]
                   if item["controller_enable"]["enabled"]]
        self.assertEqual(1, len(enabled), "exactly the trigger source is enabled")
        source_id = int(enabled[0]["source_id"])
        self.assertEqual(1 << (source_id % 32), int(enabled[0]["controller_enable"]["mask"]),
                         "controller bitmap bit k is source id 32*j+k, bit 0 reserved")
        self.assertIn((controller_base + 0x24, 1 << (source_id % 32)), stores,
                      "controller ENABLE0 with the source id bit")
        # CLAIM is a read with a side effect, COMPLETE is the write.
        self.assertIn((controller_base + 0x04, 1), stores, "COMPLETE with the claimed id")
        # The completion flag and the report block are written to RAM.
        self.assertIn((program.flag_address, COMPLETION_FLAG), stores,
                      "the completion flag magic must be stored at flag_address")
        report = int(program.report_address)
        claim_offsets = dict(REPORT_FIELDS)
        self.assertIn(report + claim_offsets["claim_id"],
                      [address for address, _ in stores])
        self.assertIn(report + claim_offsets["loop_closed"],
                      [address for address, _ in stores])
        # The declared read-clears operation of the GPIO source is a read.
        loads = [item["address"] for item in walked["loads"]]
        self.assertIn(gpio_base + 0x08, loads,
                      "the ISR clears the GPIO condition through the declared read of "
                      "DATA_IN (offset 0x08)")

    def test_the_enable_register_is_read_modify_written_not_overwritten(self) -> None:
        walked = body_walk(self.program())
        gpio_base = _peripheral_base(self.plan, "gpio0")
        enable_reads = [item for item in walked["loads"] if item["address"] == gpio_base + 0x0C]
        self.assertTrue(enable_reads, "the declared enable register is read back first")
        self.assertTrue(any(item["offset"] == 0x0C for item in walked["stores"]),
                        "and written with the preserved value")

    def test_uart_source_uses_its_own_declared_clear_operation(self) -> None:
        """The second peripheral's declared clear is write-1-to-clear, not a read."""
        program = self.program()
        document = program.document
        uart = next(item for item in document["sources"] if item["instance_id"] == "uart0")
        self.assertEqual("CTRL", uart["enable"]["register"])
        self.assertEqual(0x00, uart["enable"]["offset"])
        self.assertEqual(1, uart["enable"]["bit"])
        self.assertEqual("write_1_to_clear", uart["clear"]["kind"])
        self.assertEqual(0x10, uart["clear"]["offset"])
        walked = body_walk(program)
        base = _peripheral_base(self.plan, "uart0")
        self.assertIn((base + 0x10, 1),
                      [(item["address"], item["value"]) for item in walked["stores"]],
                      "the UART clear writes 1 to its declared IRQ_STATUS register")

    def test_gpio_source_uses_its_own_declared_operands(self) -> None:
        document = self.program().document
        gpio = next(item for item in document["sources"] if item["instance_id"] == "gpio0")
        self.assertEqual("IRQ_EN", gpio["enable"]["register"])
        self.assertEqual(0x0C, gpio["enable"]["offset"])
        self.assertEqual(0, gpio["enable"]["bit"])
        self.assertEqual("IRQ_STATUS", gpio["status"]["register"])
        self.assertEqual(0x10, gpio["status"]["offset"])
        self.assertEqual("read_clears", gpio["clear"]["kind"])
        self.assertEqual(0x08, gpio["clear"]["offset"])

    def test_controller_registers_come_from_the_plan_register_map(self) -> None:
        program = self.program()
        document = program.document
        registers = {item["name"]: item for item in
                     self.plan.interrupt_document["controller"]["register_map"]}
        used = document["controller"]["registers_used"]
        self.assertEqual(registers["CLAIM"]["offset"], used["CLAIM"])
        self.assertEqual(registers["COMPLETE"]["offset"], used["COMPLETE"])
        self.assertEqual(registers["IN_SERVICE"]["offset"], used["IN_SERVICE"])
        self.assertEqual(registers["SOURCE_COUNT"]["offset"], used["SOURCE_COUNT"])
        self.assertEqual(registers["PENDING0"]["offset"], used["PENDING0"])
        self.assertEqual(registers["ENABLE0"]["offset"], used["ENABLE0"])
        self.assertEqual(document["controller"]["base"], _controller_base(self.plan))

    def test_source_ids_come_from_the_plan_and_drive_the_isr_dispatch(self) -> None:
        program = self.program()
        plan_sources = {int(item["source_id"]): item
                        for item in self.plan.interrupt_document["sources"]}
        documented = {int(item["source_id"]): item for item in program.document["sources"]}
        self.assertEqual(sorted(plan_sources), sorted(documented))
        for source_id, record in plan_sources.items():
            self.assertEqual(record["instance_id"], documented[source_id]["instance_id"])
            self.assertEqual(_peripheral_base(self.plan, record["instance_id"]),
                             documented[source_id]["window_base"])
        # Every declared id is compared in the handler dispatch chain.
        walked = body_walk(program)
        compared = [ins["imm_i"] for ins in walked["instructions"] if ins["name"] == "addi"
                    and ins["rd"] == 6 and ins["rs1"] == 0]
        for source_id in plan_sources:
            self.assertIn(source_id, compared)
        self.assertEqual(plan_sources[int(program.observations["claim_id"])]["instance_id"],
                         program.document["trigger"]["instance_id"])

    def test_trigger_is_recorded_as_an_external_event_plan(self) -> None:
        program = self.program()
        trigger = program.document["trigger"]
        self.assertEqual("external_event_plan", trigger["kind"])
        self.assertEqual([], trigger["mmio_writes"])
        self.assertTrue(trigger["applied"])
        runtime_slots = [item["name"] for item in _external_inputs(self.plan)]
        for event in trigger["events"]:
            self.assertEqual(runtime_slots[int(event["slot"])], event["name"],
                             "the recorded slot index must be the runtime's own slot")
        self.assertTrue(trigger["pins"])
        source = next(item for item in self.plan.interrupt_document["sources"]
                      if int(item["source_id"]) == int(trigger["source_id"]))
        for pin in trigger["pins"]:
            self.assertTrue(pin.startswith(source["instance_id"] + "__"),
                            "only the trigger source's own declared pins are driven")

    def test_observations_are_the_values_the_report_layout_declares(self) -> None:
        program = self.program()
        layout = {item["name"]: item for item in program.document["report"]["layout"]}
        # The completion flag is its own word: the plan-declared flag address,
        # not one of the report fields.
        self.assertEqual(program.flag_address, program.document["memory"]["flag_address"])
        for field, value in program.observations.items():
            self.assertIsInstance(value, int)
            if field == "completion_flag":
                continue
            self.assertIn(field, layout)
            self.assertTrue(layout[field]["promised"])
            self.assertEqual(program.report_address + layout[field]["offset"],
                             layout[field]["address"])
        self.assertEqual(int(COMPLETION_FLAG), program.observations["completion_flag"])
        self.assertEqual(len(self.plan.interrupt_document["sources"]),
                         program.observations["source_count"])
        json.dumps(program.document)          # the document must be serialisable

    def test_expect_error_access_adds_one_unmapped_load(self) -> None:
        program = build_boot_program(self.plan,
                                     request=ProgramRequest(expect_error_access=True))
        scenario = program.document["error_scenario"]
        self.assertIsNotNone(scenario)
        windows = self.plan.plan["fabric"]["decode"]["windows"]
        address = int(scenario["address"])
        for row in windows:
            self.assertFalse(int(row["base"]) <= address < int(row["base"]) + int(row["size"]),
                             "the scenario address must decode to no declared window")
        walked = body_walk(program)
        inside_isr = [item for item in walked["loads"]
                      if item["address"] == address]
        self.assertTrue(inside_isr, "the program performs the unmapped load")
        self.assertEqual("load", scenario["access"])
        self.assertIn(scenario["recorded_at"],
                      [program.report_address + offset for _, offset in REPORT_FIELDS])

    def test_without_the_error_scenario_no_unmapped_access_is_emitted(self) -> None:
        program = self.program()
        self.assertIsNone(program.document["error_scenario"])
        walked = body_walk(program)
        windows = self.plan.plan["fabric"]["decode"]["windows"]
        for item in walked["loads"]:
            address = item["address"]
            self.assertTrue(any(int(row["base"]) <= address
                                < int(row["base"]) + int(row["size"]) for row in windows),
                            "every load stays inside a declared window: 0x%08x" % address)


class DeterminismTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan = example_plan()

    def test_same_plan_and_request_give_identical_bytes_and_document(self) -> None:
        first = build_boot_program(self.plan)
        second = build_boot_program(self.plan)
        self.assertEqual(first.image, second.image)
        self.assertEqual(json.dumps(first.document, sort_keys=True),
                         json.dumps(second.document, sort_keys=True))
        self.assertEqual(dict(first.observations), dict(second.observations))
        self.assertEqual(first.steps, second.steps)

    def test_every_request_variant_is_deterministic(self) -> None:
        for request in (ProgramRequest(),
                        ProgramRequest(enable_interrupts=False),
                        ProgramRequest(trigger_event=False),
                        ProgramRequest(expect_error_access=True)):
            with self.subTest(request=request):
                first = build_boot_program(self.plan, request=request)
                second = build_boot_program(self.plan, request=request)
                self.assertEqual(first.image, second.image)
                self.assertEqual(json.dumps(first.document, sort_keys=True),
                                 json.dumps(second.document, sort_keys=True))

    def test_the_image_is_the_documents_listing(self) -> None:
        """The recorded listing is the artifact that was generated."""
        program = build_boot_program(self.plan)
        body_base = int(program.document["entry"]["hardware_entry"])
        words: dict[int, int] = {}
        for line in program.document["listing"]:
            fields = line.split()
            if (len(fields) >= 2 and len(fields[0]) == 8
                    and len(fields[1]) == 8
                    and all(character in "0123456789abcdef" for character in fields[1])):
                words[int(fields[0], 16)] = int(fields[1], 16)
        body_words = int(program.document["body_words"])
        self.assertEqual(body_words, len(words),
                         "the listing must carry exactly one word per body instruction")
        offset = body_base - program.entry_address
        for index in range(body_words):
            address = body_base + index * 4
            self.assertEqual(words[address],
                             int.from_bytes(program.image[offset + index * 4:
                                                          offset + index * 4 + 4], "little"),
                             "listing disagrees with the image at 0x%08x" % address)


class PlanDrivenAddressTests(unittest.TestCase):
    """No address is baked in: the program follows the plan's windows."""

    def test_moving_a_peripheral_address_moves_the_store_target(self) -> None:
        document = _example_request_document()
        moved = deepcopy(document)
        for item in moved["peripherals"]:
            if item["instance_id"] == "gpio0":
                item["address"] = 0x4008_0000
        base_plan = _plan_from(document)
        moved_plan = _plan_from(moved)
        self.assertNotEqual(_peripheral_base(base_plan, "gpio0"),
                            _peripheral_base(moved_plan, "gpio0"))
        base_program = build_boot_program(base_plan)
        moved_program = build_boot_program(moved_plan)
        base_stores = [(item["address"], item["value"])
                       for item in body_walk(base_program)["stores"]]
        moved_stores = [(item["address"], item["value"])
                        for item in body_walk(moved_program)["stores"]]
        # The declared interrupt-enable register is set with a read-modify-write,
        # so its store value is the OR of a loaded word and the declared bit: the
        # walker cannot resolve it and records ``None``.  The software phase also
        # stores into this same declared offset when it probes the peripheral's
        # declared read-only registers (the GPIO DATA_IN/IRQ_STATUS probes), and
        # a probe store carries a constant pattern, so the RMW -- not the bare
        # address -- is what has to follow the plan's window.
        self.assertIn((0x4000_0000 + 0x0C, None), base_stores)
        self.assertNotIn((0x4008_0000 + 0x0C, None), base_stores)
        self.assertIn((0x4008_0000 + 0x0C, None), moved_stores)
        self.assertNotIn((0x4000_0000 + 0x0C, None), moved_stores,
                         "the gpio0 enable read-modify-write still targets the old "
                         "window base; the constant-value stores at that address in the "
                         "moved program belong to the other peripheral's declared "
                         "read-only register probes")
        # The source id and its instance do not change with the address.
        self.assertEqual(base_program.observations["claim_id"],
                         moved_program.observations["claim_id"])
        self.assertEqual(1, base_program.observations["claim_id"])
        source = next(item for item in moved_program.document["sources"]
                      if item["instance_id"] == "gpio0")
        self.assertEqual(0x4008_0000, source["window_base"])
        self.assertEqual(0x4008_0000 + 0x08,
                         source["window_base"] + source["clear"]["offset"])
        moved_clear_loads = [item["address"] for item in body_walk(moved_program)["loads"]]
        self.assertIn(0x4008_0000 + 0x08, moved_clear_loads)

    def test_controller_offsets_follow_the_plan_register_map(self) -> None:
        plan = _plan_from(_example_request_document())
        program = build_boot_program(plan)
        registers = {item["name"]: int(item["offset"]) for item in
                     plan.interrupt_document["controller"]["register_map"]}
        walked = body_walk(program)
        controller_base = _controller_base(plan)
        self.assertIn(controller_base + registers["ENABLE0"],
                      [item["address"] for item in walked["stores"]])
        self.assertIn(controller_base + registers["CLAIM"],
                      [item["address"] for item in walked["loads"]])
        self.assertNotIn(controller_base + 0x24 - 4,
                         [item["address"] for item in walked["stores"]])


class NoSourcePlanTests(unittest.TestCase):
    """A plan whose controller has no sources must not silently get an ISR."""

    @classmethod
    def setUpClass(cls):
        cls.plan = _cpu_only_plan()

    def test_the_plan_really_has_no_controller_and_no_sources(self) -> None:
        self.assertFalse(self.plan.interrupt_document["controller"]["present"])
        self.assertEqual([], list(self.plan.interrupt_document["sources"]))
        self.assertFalse(self.plan.interrupt_plan.present)

    def test_an_interrupt_program_is_refused_by_name(self) -> None:
        """Decision: refuse, and name the reason in the error."""
        with self.assertRaises(BootProgramError) as caught:
            build_boot_program(self.plan)
        self.assertIn("no-interrupt-sources", str(caught.exception))

    def test_a_boot_only_program_is_still_available_and_says_so(self) -> None:
        program = build_boot_program(self.plan, isr=False,
                                     request=ProgramRequest(enable_interrupts=False))
        self.assertFalse(program.document["request"]["isr"])
        self.assertIn("interrupt program omitted", "\n".join(program.steps))
        walked = body_walk(program)
        mnemonics = [ins["name"] for ins in walked["instructions"]]
        self.assertNotIn("mret", mnemonics)
        self.assertEqual([], walked["csr_writes"])
        self.assertNotIn("mtvec", program.document["entry"])
        self.assertIsNone(program.document["controller"])
        self.assertIn((program.flag_address, COMPLETION_FLAG),
                      [(item["address"], item["value"]) for item in walked["stores"]])
        self.assertEqual(program.observations["claim_id"], 0)
        self.assertEqual(program.observations["main_completed"], 1)

    def test_enabling_interrupts_without_an_isr_is_rejected(self) -> None:
        with self.assertRaises(BootProgramError) as caught:
            build_boot_program(self.plan, isr=False)
        self.assertIn("interrupts-enabled-without-isr", str(caught.exception))

    def test_a_request_object_is_required(self) -> None:
        with self.assertRaises(BootProgramError):
            build_boot_program(self.plan, request={"enable_interrupts": True})
        with self.assertRaises(BootProgramError):
            build_boot_program(self.plan, isr="yes")


class RequestVariantTests(unittest.TestCase):
    """``enable_interrupts`` is the switch the lifecycle negative case uses."""

    @classmethod
    def setUpClass(cls):
        cls.plan = example_plan()

    def test_disabled_interrupts_leave_every_enable_at_its_reset_value(self) -> None:
        program = build_boot_program(self.plan,
                                     request=ProgramRequest(enable_interrupts=False))
        walked = body_walk(program)
        writes = [(item["name"], item["value"]) for item in walked["csr_writes"]]
        self.assertNotIn(("mie", 1 << 11), writes)
        self.assertNotIn(("mstatus", 1 << 3), writes)
        self.assertIn(("mtvec", int(program.document["entry"]["handler_address"])), writes,
                      "the handler is still installed; only delivery is disabled")
        controller_base = _controller_base(self.plan)
        self.assertNotIn(controller_base + 0x24,
                         [item["address"] for item in walked["stores"]],
                         "the controller ENABLE word keeps its reset value")
        gpio_base = _peripheral_base(self.plan, "gpio0")
        self.assertIn(gpio_base + 0x0C,
                      [item["address"] for item in walked["stores"]],
                      "the peripheral's own interrupt-enable bit is still programmed")
        self.assertFalse(program.document["enablement"]["controller_enable_written"])
        self.assertFalse(program.document["enablement"]["cpu_enable_written"])
        self.assertFalse(program.document["sources"][0]["controller_enable"]["enabled"])
        self.assertEqual(0, program.observations["claim_id"])
        self.assertEqual(0, program.observations["handler_entries"])
        self.assertEqual(1, program.observations["status_latched_by_poll"],
                         "the CPU still observes the peripheral condition")
        enabled = [item for item in program.document["sources"]
                   if item["controller_enable"]["mask"]]
        self.assertEqual(int(enabled[0]["controller_enable"]["mask"]),
                         program.observations["pending_seen_by_main"],
                         "and the source's own bitmap bit is still pending at the controller")

    def test_without_the_trigger_no_wait_can_succeed(self) -> None:
        program = build_boot_program(self.plan, request=ProgramRequest(trigger_event=False))
        self.assertFalse(program.document["trigger"]["applied"])
        self.assertEqual(0, program.observations["claim_id"])
        self.assertEqual(0, program.observations["status_latched_by_poll"])
        self.assertIn("trigger: do NOT apply the recorded external events",
                      "\n".join(program.steps))

    def test_multi_source_request_records_all_triggerable_sources(self) -> None:
        """The generated program can deliberately exercise every source.

        The normal lifecycle request keeps the historical one-source contract;
        this opt-in request is the bounded multi-source closure used to verify
        controller arbitration and repeated claim/complete service.
        """
        program = build_boot_program(
            self.plan, request=ProgramRequest(exercise_all_sources=True))
        source_ids = [int(item["source_id"])
                      for item in self.plan.interrupt_document["sources"]]
        self.assertGreaterEqual(len(source_ids), 2)
        self.assertEqual(source_ids, list(program.document["trigger"]["source_ids"]))
        self.assertEqual(source_ids, [int(item["source_id"])
                                      for item in program.document["sources"]
                                      if item["controller_enable"]["enabled"]])
        self.assertEqual(len(source_ids), len(program.document["trigger"]["source_ids"]))
        self.assertEqual(len(source_ids), program.observations["interrupt_completions"])
        self.assertIn("all_sources_closed", dict(REPORT_FIELDS))
        walked = body_walk(program)
        controller_base = _controller_base(self.plan)
        expected_mask = sum(1 << (source_id % 32) for source_id in source_ids)
        self.assertIn((controller_base + 0x24, expected_mask),
                      [(item["address"], item["value"]) for item in walked["stores"]])
        report = program.report_address
        self.assertIn(report + dict(REPORT_FIELDS)["interrupt_completions"],
                      [item["address"] for item in walked["stores"]])
        self.assertIn(report + dict(REPORT_FIELDS)["all_sources_closed"],
                      [item["address"] for item in walked["stores"]])

    def test_multi_source_request_can_stagger_external_events(self) -> None:
        program = build_boot_program(
            self.plan,
            request=ProgramRequest(exercise_all_sources=True, stagger_sources=True))
        self.assertTrue(program.document["trigger"]["staggered"])
        by_source_pin = {}
        for event in program.document["trigger"]["events"]:
            by_source_pin.setdefault(event["name"], []).append(int(event["cycle"]))
        self.assertGreaterEqual(len(by_source_pin), 2)
        high_cycles = sorted({max(cycles) for cycles in by_source_pin.values()})
        self.assertGreaterEqual(len(high_cycles), 2,
                                "staggered mode must create distinct source windows")

    def test_staggering_without_multi_source_mode_is_rejected(self) -> None:
        with self.assertRaises(BootProgramError) as caught:
            build_boot_program(self.plan, request=ProgramRequest(stagger_sources=True))
        self.assertIn("stagger-sources-requires-exercise-all-sources", str(caught.exception))


# ---------------------------------------------------------------------------
# the declared-register software phase
# ---------------------------------------------------------------------------

#: The report offsets the program published before the software phase existed.
#: They are frozen here: the phase may only append fields, so a run that read
#: this block by offset keeps working.
FROZEN_REPORT_OFFSETS = {
    "claim_id": 0x00, "handler_entries": 0x04, "complete_accepted": 0x08,
    "final_in_service": 0x0C, "source_count": 0x10, "pending_before_claim": 0x14,
    "cause_before_clear": 0x18, "cause_after_clear": 0x1C,
    "status_raw_before_clear": 0x20, "status_raw_after_clear": 0x24,
    "pending_word_0_before_claim": 0x28, "pending_word_1_before_claim": 0x2C,
    "pending_word_after_complete": 0x30, "prologue_cycle": 0x34,
    "status_latched_by_poll": 0x38, "pending_seen_by_main": 0x3C,
    "error_access_requested": 0x40, "error_cause": 0x44, "unknown_claim": 0x48,
    "loop_closed": 0x4C, "main_completed": 0x50,
}


class DeclaredSoftwarePhaseTests(unittest.TestCase):
    """The phase the generator emits from the profiles' register declarations."""

    @classmethod
    def setUpClass(cls):
        cls.plan = example_plan()

    def program(self, request: ProgramRequest = ProgramRequest()):
        return build_boot_program(self.plan, request=request)

    def bases(self) -> dict[str, int]:
        return {instance.instance_id: _peripheral_base(self.plan, instance.instance_id)
                for instance in self.plan.instances if instance.kind == "peripheral"}

    # -- layout -----------------------------------------------------------

    def test_the_existing_report_offsets_did_not_move(self) -> None:
        layout = dict(REPORT_FIELDS)
        for name, offset in FROZEN_REPORT_OFFSETS.items():
            self.assertEqual(offset, layout[name], "%s moved" % name)
        self.assertEqual(len(REPORT_FIELDS), len(set(layout.values())),
                         "two report fields share an offset")

    def test_the_whole_report_block_is_inside_the_runtime_readback(self) -> None:
        self.assertLessEqual(REPORT_OFFSET + REPORT_BYTES, MAX_OBSERVED_WORDS * 8)
        program = self.program()
        self.assertEqual(REPORT_BYTES, program.document["memory"]["report_bytes"])
        for entry in program.document["report"]["layout"]:
            self.assertEqual(program.report_address + int(entry["offset"]),
                             int(entry["address"]))

    def test_every_software_step_has_a_report_field(self) -> None:
        layout = {name for name, _ in REPORT_FIELDS}
        for name in ("software_phase", "software_registers", "software_skipped",
                     "software_init_writes", "software_reads", "software_read_traps",
                     "software_traps", "software_writeback_checks",
                     "software_writeback_matches", "software_writeback_mask",
                     "software_side_effects", "software_side_effects_confirmed",
                     "software_side_effect_mask", "software_status_checks",
                     "status_0", "permission_probes", "permission_errors",
                     "permission_error_mask", "rom_write_requested", "rom_write_cause",
                     "rom_unchanged", "unmapped_store_cause", "exception_count"):
            self.assertIn(name, layout)

    # -- coverage ---------------------------------------------------------

    def test_the_phase_covers_every_declared_register(self) -> None:
        program = self.program()
        document = program.document["software"]
        rows = _declared_register_rows(self.plan)
        self.assertTrue(rows, "the example plan declares no register")
        covered = {(item["instance_id"], register["name"], register["offset"])
                   for item in document["peripherals"] for register in item["registers"]}
        expected = {(instance_id, register.name, int(register.offset))
                    for instance_id, register in rows}
        self.assertEqual(expected, covered)
        self.assertEqual(len(rows), int(document["totals"]["registers"]))
        self.assertEqual(len(rows), program.observations["software_registers"])

    def test_the_totals_are_what_the_declarations_imply(self) -> None:
        rows = _declared_register_rows(self.plan)
        totals = self.program().document["software"]["totals"]
        readable = [item for _, item in rows if item.access in ("ro", "rw")]
        plain_rw = [item for _, item in rows
                    if item.access == "rw" and item.side_effect == "none"]
        initialised = [item for item in plain_rw if item.reset_value is not None]
        clearing = [item for _, item in rows
                    if item.side_effect in ("read_clears", "write_1_to_clear")
                    and item.clears_register is not None]
        unobservable = [item for _, item in rows
                        if item.side_effect in ("read_clears", "write_1_to_clear")
                        and item.clears_register is None]
        self.assertEqual(len(readable), int(totals["reads"]))
        self.assertEqual(len(plain_rw), int(totals["writebacks"]))
        self.assertEqual(len(initialised), int(totals["init_writes"]))
        self.assertEqual(len(clearing), int(totals["side_effects"]))
        self.assertEqual(len(self.program().document["software"]["peripherals"]),
                         int(totals["status_checks"]),
                         "one declared status register is re-read per peripheral")
        self.assertEqual(0, int(totals["probes"]), "the faulting probes are opt-in")
        skipped = self.program().document["software"]["skipped"]
        self.assertEqual(sorted(item.name for item in unobservable),
                         sorted(str(entry["register"]) for entry in skipped))

    def test_a_peripheral_that_declares_no_registers_is_a_note_only(self) -> None:
        """Requirement 7: no invented accessors, a coverage note instead.

        ``gpio1`` is a real bound instance of a profile whose register table is
        empty and which is not an interrupt source, so the generated program must
        say so and touch none of its window.
        """
        document = _example_request_document()
        raw = json.loads((EXAMPLE / "profiles/novagpio.json").read_text(encoding="utf-8"))
        raw["address"]["registers"] = []
        raw["interrupts"] = []
        raw["endpoints"] = [item for item in raw["endpoints"]
                            if item["endpoint_id"] != "gpio.irq"]
        profiles = _profiles()
        profiles["fixture-no-registers"] = load_component_profile(raw)
        document["request_id"] = "one-peripheral-declares-no-register"
        document["peripherals"].append({"instance_id": "gpio1",
                                        "profile": "fixture-no-registers",
                                        "parameters": {}, "address": 0x4000_2000})
        request = load_composition_request(document, profiles=profiles)
        plan = build_composition(request, base_dir=ROOT)
        window = next(int(record["window"]["base"]) for record in plan.target_records
                      if record.get("instance_id") == "gpio1")
        program = build_boot_program(plan)
        skipped = program.document["software"]["skipped"]
        self.assertIn(("gpio1", "no-registers-declared"),
                      [(item["instance_id"], item["reason"]) for item in skipped])
        self.assertEqual(len(skipped), program.observations["software_skipped"])
        self.assertEqual([], [item for item in program.document["software"]["peripherals"]
                              if item["instance_id"] == "gpio1"],
                         "the phase must not describe a peripheral it cannot access")
        walked = body_walk(program)
        for kind in ("loads", "stores"):
            self.assertEqual([], [item for item in walked[kind]
                                  if item["address"] is not None
                                  and window <= item["address"] < window + 0x1000],
                             "no %s may target the window of a register-less peripheral"
                             % kind)

    def test_a_peripheral_without_an_mmio_window_is_a_note(self) -> None:
        document = _example_request_document()
        raw = json.loads((EXAMPLE / "profiles/novagpio.json").read_text(encoding="utf-8"))
        profiles = _profiles()
        profiles["fixture-unnamed"] = load_component_profile(raw)
        for item in document["peripherals"] + [document["cpu"]]:
            if item.get("instance_id") == "gpio0":
                item["profile"] = "fixture-unnamed"
        document["peripherals"] = [item for item in document["peripherals"]
                                   if item["instance_id"] != "gpio0"]
        request = load_composition_request(document, profiles=profiles)
        plan = build_composition(request, base_dir=ROOT)
        program = build_boot_program(plan)
        rows = _declared_register_rows(plan)
        self.assertFalse([item for item in rows if item[0] == "gpio0"])
        self.assertEqual(len(rows), int(program.document["software"]["totals"]["registers"]))

    # -- the emitted code -------------------------------------------------

    def test_the_declared_reset_value_is_written_during_init(self) -> None:
        program = self.program()
        document = program.document["software"]
        stores = {(item["address"], item["value"]) for item in body_walk(program)["stores"]}
        bases = self.bases()
        for item in document["peripherals"]:
            for register in item["registers"]:
                if not register["init"]:
                    continue
                address = bases[item["instance_id"]] + int(register["offset"])
                self.assertIn((address, int(register["reset_value"])), stores,
                              "the declared reset value of %s must be written"
                              % register["name"])

    def test_the_writeback_pattern_is_offset_derived_and_declared_masked(self) -> None:
        program = self.program()
        document = program.document["software"]
        walked = body_walk(program)
        stores = [(item["address"], item["value"]) for item in walked["stores"]]
        loads = [item["address"] for item in walked["loads"]]
        bases = self.bases()
        checked = 0
        for item in document["peripherals"]:
            for register in item["registers"]:
                if not register["writeback"]:
                    continue
                address = bases[item["instance_id"]] + int(register["offset"])
                value = int(register["write_value"])
                mask = int(register["writable_mask"])
                self.assertNotEqual(0, value & mask, "a vacuous pattern is not a check")
                self.assertEqual(value, value & mask, "the pattern must fit the declaration")
                self.assertIn((address, value), stores,
                              "the offset-derived pattern for %s" % register["name"])
                self.assertIn(address, loads, "and it must be read back")
                checked += 1
        self.assertEqual(int(document["totals"]["writebacks"]), checked)
        self.assertGreater(checked, 0)

    def test_the_declared_clear_checks_use_the_declared_probe(self) -> None:
        program = self.program()
        document = program.document["software"]
        walked = body_walk(program)
        stores = [(item["address"], item["value"]) for item in walked["stores"]]
        loads = [item["address"] for item in walked["loads"]]
        bases = self.bases()
        cleared = 0
        for item in document["peripherals"]:
            base = bases[item["instance_id"]]
            for register in item["registers"]:
                kind = register["side_effect_check"]
                if kind is None:
                    continue
                cleared += 1
                probe = base + int(register["side_effect_probe_offset"])
                self.assertIn(probe, loads, "the declared probe must be re-read")
                if kind == "write_1_to_clear":
                    self.assertIn((base + int(register["offset"]),
                                   int(register["side_effect_mask_value"])), stores,
                                  "the declared write-1-to-clear access")
                else:
                    self.assertIn(base + int(register["offset"]), loads,
                                  "the declared read-clears access")
        self.assertEqual(int(document["totals"]["side_effects"]), cleared)
        self.assertGreater(cleared, 0)

    def test_the_declared_status_register_is_re_read_per_peripheral(self) -> None:
        program = self.program()
        document = program.document["software"]
        loads = [item["address"] for item in body_walk(program)["loads"]]
        bases = self.bases()
        for item in document["peripherals"]:
            status = item["status"]
            self.assertIsNotNone(status, item["instance_id"])
            self.assertIn(bases[item["instance_id"]] + int(status["offset"]), loads)
        self.assertEqual(len(document["peripherals"]),
                         int(document["totals"]["status_checks"]))

    def test_the_phase_is_emitted_before_the_final_spin(self) -> None:
        program = self.program()
        listing = program.document["listing"]
        spin = next(index for index, line in enumerate(listing)
                    if line.rstrip().endswith("_spin:"))
        phase = next(index for index, line in enumerate(listing)
                     if "declared-register software phase" in line)
        self.assertLess(phase, spin)

    # -- the opt-in faulting checks ---------------------------------------

    def test_the_direction_probes_and_rom_write_are_off_by_default(self) -> None:
        program = self.program()
        document = program.document["software"]
        self.assertEqual([], document["permission_probes"])
        self.assertIsNone(document["rom_check"])
        self.assertFalse(document["checks"]["permission_probes"])
        self.assertEqual(0, program.observations["permission_probes"])
        self.assertEqual(0, program.observations["rom_write_requested"])

    def test_the_direction_probes_follow_the_declared_access_of_each_register(self) -> None:
        program = self.program(request=ProgramRequest(probe_permissions=True))
        document = program.document["software"]
        rows = _declared_register_rows(self.plan)
        expected = {(instance_id, register.name):
                    ("write" if register.access == "ro" else "read")
                    for instance_id, register in rows if register.access in ("ro", "wo")}
        self.assertEqual(expected,
                         {(item["instance_id"], item["register"]): item["probe"]
                          for item in document["permission_probes"]})
        self.assertEqual(len(expected), program.observations["permission_probes"])
        walked = body_walk(program)
        stores = {(item["address"], item["value"]) for item in walked["stores"]}
        loads = [item["address"] for item in walked["loads"]]
        bases = self.bases()
        for item in document["permission_probes"]:
            address = bases[item["instance_id"]] + int(item["offset"])
            if item["probe"] == "write":
                self.assertTrue(any(candidate == address for candidate, _ in stores),
                                "the read-only register must really be written")
            else:
                self.assertIn(address, loads, "the write-only register must really be read")

    def test_the_rom_write_check_targets_the_plans_read_only_region(self) -> None:
        program = self.program(request=ProgramRequest(probe_permissions=True))
        check = program.document["software"]["rom_check"]
        regions = {str(item["region_id"]): item
                   for item in self.plan.plan["address_map"]["memory_regions"]}
        region = regions[str(check["region_id"])]
        self.assertTrue((region.get("permissions") or {}).get("execute"))
        self.assertFalse((region.get("permissions") or {}).get("write"))
        self.assertEqual(int(region["base"]), int(check["address"]))
        self.assertEqual(1, program.observations["rom_write_requested"])
        self.assertEqual(7, program.observations["rom_write_cause"])
        self.assertEqual(1, program.observations["rom_unchanged"])
        stores = [(item["address"], item["value"]) for item in body_walk(program)["stores"]]
        self.assertIn((int(check["address"]), int(check["value"])), stores)

    def test_a_plan_without_a_read_only_region_records_the_gap(self) -> None:
        document = _example_request_document()
        for region in document["memory"]:
            if region["region_id"] == "rom0":
                # A writable ROM is refused by the request contract, so the
                # region is declared preloaded instead: executable, writable and
                # therefore not something the plan claims is protected.
                region["permissions"]["write"] = True
                region["initialization_policy"] = "preload"
        plan = _plan_from(document)
        program = build_boot_program(plan, request=ProgramRequest(probe_permissions=True))
        self.assertIsNone(program.document["software"]["rom_check"])
        self.assertEqual(0, program.observations["rom_write_requested"])
        self.assertTrue(any("no executable, non-writable region" in note
                            for note in program.document["software"]["notes"]))

    def test_the_faulting_checks_need_an_interrupt_program(self) -> None:
        plan = _cpu_only_plan()
        program = build_boot_program(plan, isr=False,
                                     request=ProgramRequest(enable_interrupts=False,
                                                            probe_permissions=True))
        self.assertEqual([], program.document["software"]["permission_probes"])
        self.assertIsNone(program.document["software"]["rom_check"])

    def test_the_phase_can_be_switched_off(self) -> None:
        program = self.program(request=ProgramRequest(verify_peripherals=False))
        document = program.document["software"]
        self.assertFalse(document["enabled"])
        self.assertEqual([], document["peripherals"])
        self.assertEqual(0, program.observations["software_phase"])
        self.assertEqual(0, program.observations["software_reads"])
        walked = body_walk(program)
        self.assertNotIn(program.report_address + dict(REPORT_FIELDS)["software_phase"],
                         [item["address"] for item in walked["stores"]])

    def test_the_software_document_is_serialisable_and_deterministic(self) -> None:
        request = ProgramRequest(probe_permissions=True)
        first = self.program(request=request)
        second = self.program(request=request)
        json.dumps(first.document["software"])
        self.assertEqual(json.dumps(first.document["software"], sort_keys=True),
                         json.dumps(second.document["software"], sort_keys=True))
        self.assertEqual(first.image, second.image)


if __name__ == "__main__":
    unittest.main()
