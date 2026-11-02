"""Profile, generator, determinism and F1-interoperability tests."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from myfuzz.isa.constraints import IsaContract
from myfuzz.riscv.encoding import EncodingError, encode
from myfuzz.riscv.profile import (
    ProfileError, load_profile, profile_from_mapping,
)
from myfuzz.riscv.program import (
    InstructionNotAvailable, generate_program, make_instruction,
)
from myfuzz.scenario.rv32i_sources import validate_instruction_bytes

ROOT = Path(__file__).resolve().parents[2]
CPU = ROOT / "configs" / "cpus"


def _cpu(name):
    return load_profile(CPU / name / "component_profile.json")


def _f1_isa(profile):
    extensions = ("I",) + tuple(
        ext for ext in ("M", "C") if ext in profile.extensions)
    return IsaContract(profile.xlen, extensions,
                       instruction_alignment=profile.instruction_alignment)


@pytest.mark.parametrize(("name", "xlen", "extensions", "align", "registers",
                          "reset"), [
    ("ibex", 32, {"I", "M", "C"}, 2, 32, 65536),
    ("picorv32", 32, {"I"}, 4, 32, 0),
    ("cv32e20_rv32e", 32, {"E", "M", "C"}, 2, 16, 65536),
    ("boom", 64, {"A", "C", "D", "F", "I", "M"}, 2, 32, 65600),
    ("vexiiriscv", 32, {"I"}, 4, 32, 2147483648),
])
def test_profile_facts(name, xlen, extensions, align, registers, reset):
    profile = _cpu(name)
    assert profile.xlen == xlen
    assert profile.extensions == extensions
    assert profile.instruction_alignment == align
    assert profile.register_count == registers
    assert profile.reset_vector == reset


def test_profile_rejects_non_riscv_and_inconsistent_profiles(tmp_path):
    with pytest.raises(ProfileError):
        _cpu("zipaxi")
    with pytest.raises(ProfileError, match="instruction_alignment"):
        profile_from_mapping({"cpu": {"family": "riscv", "xlen": 32,
                                      "extensions": ["i", "c"],
                                      "instruction_alignment": 4}})
    with pytest.raises(ProfileError, match="RV32E"):
        profile_from_mapping({"cpu": {"family": "riscv", "xlen": 64,
                                      "extensions": ["e"]}})
    profile = profile_from_mapping(
        {"cpu": {"family": "riscv", "xlen": 32, "extensions": ["I", "zba"]}})
    assert profile.extensions == {"I", "ZBA"}
    assert profile.instruction_alignment == 4


def test_seed_is_deterministic_and_distinguishes_seeds():
    profile = _cpu("ibex")
    first = generate_program(profile, seed=7, count=24,
                             ram_base=0x10000, ram_size=256)
    again = generate_program(profile, seed=7, count=24,
                             ram_base=0x10000, ram_size=256)
    other = generate_program(profile, seed=8, count=24,
                             ram_base=0x10000, ram_size=256)
    assert first.as_dict() == again.as_dict()
    assert first.records != other.records


def test_records_are_accepted_by_the_existing_f1_validator():
    windows = {
        "ibex": (0x10000, 256),
        "picorv32": (0, 256),
        "cv32e20_rv32e": (0x10000, 64),
        "boom": (0x10000, 256),
    }
    for name, (base, size) in windows.items():
        profile = _cpu(name)
        isa = _f1_isa(profile)
        for seed in range(4):
            program = generate_program(profile, seed=seed, count=16,
                                       ram_base=base, ram_size=size)
            assert len(program.records) == 16
            for record in program.records:
                assert len(record) == 8
                validate_instruction_bytes(bytes.fromhex(record), isa=isa)
            assert program.f1_records == tuple("F1:" + r for r in program.records)


def test_compressed_records_are_packed_legal_pairs():
    profile = _cpu("ibex")
    isa = _f1_isa(profile)
    program = generate_program(profile, seed=3, count=12, compressed=True)
    assert len(program.records) == 12
    assert len(program.instructions) == 24
    for record in program.records:
        raw = bytes.fromhex(record)
        assert len(raw) == 4
        for half in (int.from_bytes(raw[:2], "little"),
                     int.from_bytes(raw[2:], "little")):
            assert half & 3 != 3
        validate_instruction_bytes(raw, isa=isa)
    assert all(item.width == 2 for item in program.instructions)


def test_extension_and_xlen_gating():
    picorv32 = _cpu("picorv32")
    ibex = _cpu("ibex")
    boom = _cpu("boom")
    with pytest.raises(InstructionNotAvailable, match="LR.W"):
        make_instruction(picorv32, "LR.W", rd=1, rs1=2)
    with pytest.raises(InstructionNotAvailable, match="LR.W"):
        make_instruction(ibex, "LR.W", rd=1, rs1=2)
    with pytest.raises(InstructionNotAvailable, match="C.ADDI"):
        make_instruction(picorv32, "C.ADDI", rd=12, imm=1)
    with pytest.raises(InstructionNotAvailable, match="MUL"):
        make_instruction(picorv32, "MUL", rd=1, rs1=2, rs2=3)
    with pytest.raises(InstructionNotAvailable, match="xlen 64"):
        make_instruction(picorv32, "ADDIW", rd=1, rs1=2, imm=0)
    with pytest.raises(EncodingError, match="xlen 64"):
        encode("ADDIW", rd=1, rs1=2, imm=0)
    spec, word = make_instruction(boom, "ADDIW", rd=1, rs1=2, imm=-1)
    assert spec.name == "ADDIW" and word == 0xFFF1009B
    with pytest.raises(ValueError, match="compressed"):
        generate_program(picorv32, seed=0, count=4, compressed=True)


def test_rv32e_limits_generated_registers_to_x0_x15():
    profile = _cpu("cv32e20_rv32e")
    program = generate_program(profile, seed=5, count=32,
                               ram_base=0x10000, ram_size=64)
    assert any(item.width == 2 for item in program.instructions)
    for item in program.instructions:
        for name, value in item.operands.items():
            if name in ("rd", "rs1", "rs2"):
                assert 0 <= value < 16, item.assembly
        if "rd" in item.operands:
            assert item.operands["rd"] != 0, item.assembly


def test_memory_accesses_stay_in_the_declared_window_and_are_aligned():
    profile = _cpu("ibex")
    program = generate_program(profile, seed=11, count=40,
                               ram_base=0x10000, ram_size=256)
    memory = [item for item in program.instructions if item.address is not None]
    assert memory
    for item in memory:
        assert item.address % 4 == 0, item.assembly
        assert 0x10000 <= item.address
        assert item.address + 4 <= 0x10000 + 256
        assert item.operands["imm"] % 4 == 0
    without_ram = generate_program(profile, seed=11, count=8)
    assert all(item.address is None for item in without_ram.instructions)


def test_generator_rejects_bad_counts_and_windows():
    profile = _cpu("ibex")
    with pytest.raises(ValueError, match="seed"):
        generate_program(profile, seed=-1, count=4)
    with pytest.raises(ValueError, match="count"):
        generate_program(profile, seed=0, count=0)
    with pytest.raises(ValueError, match="4-aligned"):
        generate_program(profile, seed=0, count=4, ram_base=2, ram_size=64)
    with pytest.raises(ValueError, match="4-aligned"):
        generate_program(profile, seed=0, count=4, ram_base=0, ram_size=6)
    with pytest.raises(ValueError, match="prologue"):
        generate_program(profile, seed=0, count=1, ram_base=0x1004,
                         ram_size=256)
    # RV32 lui+addi wrap is exact at the top of the address space.
    top = generate_program(_cpu("picorv32"), seed=2, count=4,
                           ram_base=0xFFFFF800, ram_size=4)
    assert top.instructions[0].word == 0x00000FB7  # lui x31, 0
    assert top.instructions[1].word == 0x800F8F93  # addi x31, x31, -2048
    with pytest.raises(ValueError, match="sign-extend"):
        generate_program(_cpu("boom"), seed=0, count=4,
                         ram_base=0x7FFFF800, ram_size=4)


def test_non_f1_pool_reaches_rv64_and_atomic_words():
    boom = generate_program(_cpu("boom"), seed=0, count=64,
                            ram_base=0x10000, ram_size=256,
                            include_non_f1=True)
    opcodes = {item.word & 0x7F for item in boom.instructions if item.width == 4}
    assert opcodes & {0x1B, 0x3B, 0x2F}, "expected RV64 or atomic words"
    ibex = generate_program(_cpu("ibex"), seed=0, count=64,
                            ram_base=0x10000, ram_size=256,
                            include_non_f1=True)
    assert not {item.word & 0x7F for item in ibex.instructions} & {0x1B, 0x2F}
    # Control transfers (jal/jalr/branches/ecall) are never generated.
    control = {0x6F, 0x67, 0x63, 0x73}
    assert not {item.word & 0x7F for item in ibex.instructions} & control
    assert not {item.word & 0x7F for item in boom.instructions} & control


def test_cli_writes_program_json_and_assembly(tmp_path):
    output = tmp_path / "generated"
    environment = dict(os.environ, PYTHONPATH=f"{ROOT / 'src'}:{ROOT}")
    command = [sys.executable, str(ROOT / "scripts" / "generate_riscv_program.py"),
               "--profile", str(CPU / "ibex" / "component_profile.json"),
               "--seed", "7", "--count", "8", "--ram-base", "0x10000",
               "--ram-size", "256", "--output", str(output)]
    done = subprocess.run(command, capture_output=True, text=True,
                          env=environment, check=True)
    assert "first record: F1:" in done.stdout
    data = json.loads((output / "program.json").read_text())
    assert len(data["records"]) == 8
    assert data["records"] == [r for r in data["records"]]
    assert data["f1_records"][0] == "F1:" + data["records"][0]
    assert (output / "program.S").read_text().count(".word") >= 1
    assert json.loads((output / "records.json").read_text()) == data["f1_records"]
    for record in data["records"]:
        validate_instruction_bytes(bytes.fromhex(record), isa=_f1_isa(_cpu("ibex")))
    repeated = subprocess.run(command, capture_output=True, text=True,
                              env=environment)
    assert repeated.returncode == 2
    assert "already exists" in repeated.stderr
