"""Cycle-for-cycle equivalence of the contract reference and generated RTL.

Inputs and combinational handshake outputs are sampled before each rising edge;
that edge commits the reference step. No internal memory or FSM signals are used.
"""

from dataclasses import dataclass, replace
import random
import shutil
import subprocess

import pytest

from myfuzz.composition.contract_transducer import ContractRuntime, compile_contract_transducer
from myfuzz.composition.cycle_input import CycleInputLayout, TestHeader
from myfuzz.composition.protocol_transducer import ProcessorBeatRequest
from myfuzz.composition.transducer_rtl import render_transducer_rtl
from myfuzz.isa.constraints import IsaContract
from myfuzz.isa.transducer import RiscvInstructionTransducer


pytestmark = pytest.mark.skipif(not (shutil.which("iverilog") and shutil.which("vvp")),
                                reason="Icarus Verilog (iverilog and vvp) is required for RTL traces")


def plan_for(**overrides):
    args = dict(isa=IsaContract(32, ("I", "M", "C"), instruction_alignment=2),
                protocol=("processor-memory-beat", "1"), address_width=32,
                data_width=32, max_wait_cycles=3,
                memory_domains={"instruction_memory_master": "main", "data_memory_master": "main"})
    return compile_contract_transducer(**(args | overrides))


def header_for(plan, **overrides):
    return TestHeader(**(dict(schema_version="cycle_test.v1", layout_hash=plan.cycle_layout.layout_hash,
                             contract_hash=plan.contract_hash, reset_cycles=2, execution_cycles=100000,
                             boot_address=0x80, hart_id=0) | overrides))


def request(plan, address=0x80, *, instruction=False, **kwargs):
    function = "instruction_memory_master" if instruction else "data_memory_master"
    return ProcessorBeatRequest(address, function, dict(plan.memory_domains)[function], **kwargs)


def raw(plan, **values):
    assert set(values) <= {f.name for f in plan.cycle_layout.fields}
    return sum(values.get(f.name, 0) << f.raw_lo for f in plan.cycle_layout.fields)


@dataclass(frozen=True)
class Cycle:
    entropy: int = 0
    request: ProcessorBeatRequest | None = None
    reset: bool = False
    begin: TestHeader | None = None


def transaction(plan, req, **values):
    return [Cycle(raw(plan, response_choice=1), req),
            Cycle(raw(plan, **({"response_choice": 2} | values)))]


def run_python_trace(plan, trace):
    runtime = ContractRuntime(plan)
    results = []
    for cycle in trace:
        if cycle.begin is not None:
            runtime.begin_test(cycle.begin)
            results.append((0, 0, 0, 0))
            continue
        result = runtime.step(cycle.entropy, {"request": cycle.request, "reset": cycle.reset})
        results.append((int(result.req_ready), int(result.rsp_valid), result.rsp_data,
                        int(result.rsp_error)))
    return results


def compile_and_run_iverilog(tmp_path, plan, trace):
    dw, aw, rw = plan.data_width, plan.address_width, plan.cycle_layout.raw_width
    statements = []
    for index, cycle in enumerate(trace):
        req = cycle.request
        # Header pins deliberately change outside test_begin: the backend must latch them.
        header = cycle.begin or header_for(plan, boot_address=0x42, illegal_instruction=True)
        be = (1 << (dw // 8)) - 1 if req is None or req.byte_enable is None else req.byte_enable
        statements.append(f"""
        reset_i = 1'b{int(not cycle.reset)}; test_begin_i = 1'b{int(cycle.begin is not None)};
        test_boot_address_i = {aw}'h{header.boot_address:x};
        test_illegal_instruction_i = 1'b{int(header.illegal_instruction)};
        rfuzz_cycle_bits = {rw}'h{cycle.entropy:x}; req_valid_i = 1'b{int(req is not None)};
        req_instruction_i = 1'b{int(req is not None and req.function == 'instruction_memory_master')};
        req_addr_i = {aw}'h{req.address if req else 0:x};
        req_write_i = 1'b{int(req is not None and req.write)};
        req_wdata_i = {dw}'h{req.write_data if req else 0:x}; req_be_i = {dw // 8}'h{be:x};
        #4; $display("TRACE {index} %0d %0d %0h %0d", req_ready_o, rsp_valid_o, rsp_data_o, rsp_error_o);
        clock_i = 1; #5; clock_i = 0; #1;
        """)
    bench = f"""
    module tb;
      logic clock_i = 0, reset_i = 1, test_begin_i = 0;
      logic [{aw-1}:0] test_boot_address_i, req_addr_i;
      logic test_illegal_instruction_i, req_valid_i, req_instruction_i, req_write_i;
      logic [{rw-1}:0] rfuzz_cycle_bits;
      logic [{dw-1}:0] req_wdata_i, rsp_data_o;
      logic [{dw//8-1}:0] req_be_i;
      logic req_ready_o, rsp_valid_o, rsp_error_o;
      myfuzz_contract_transducer dut (.*);
      initial begin
        {''.join(statements)}
        $finish;
      end
    endmodule
    """
    rtl, tb, executable = tmp_path / "backend.sv", tmp_path / "tb.sv", tmp_path / "simulation.vvp"
    rtl.write_text(render_transducer_rtl(plan), encoding="utf-8")
    tb.write_text(bench, encoding="utf-8")
    compiled = subprocess.run([shutil.which("iverilog"), "-g2012", "-s", "tb", "-o", str(executable),
                               str(rtl), str(tb)], capture_output=True, text=True, timeout=60)
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    simulated = subprocess.run([shutil.which("vvp"), str(executable)],
                               capture_output=True, text=True, timeout=60)
    assert simulated.returncode == 0, simulated.stdout + simulated.stderr
    lines = [line.split() for line in simulated.stdout.splitlines() if line.startswith("TRACE ")]
    assert len(lines) == len(trace), simulated.stdout
    return [(int(line[2]), int(line[3]), int(line[4], 16), int(line[5])) for line in lines]


def assert_equivalent(tmp_path, plan, trace):
    expected = run_python_trace(plan, trace)
    actual = compile_and_run_iverilog(tmp_path, plan, trace)
    assert actual == expected, next(((i, trace[i], got, want)
                                     for i, (got, want) in enumerate(zip(actual, expected))
                                     if got != want), "trace lengths differ")
    return expected


@pytest.mark.parametrize("data_width", [32, 64])
def test_rtl_matches_reference_for_accept_repeat_read_and_write(tmp_path, data_width):
    plan = plan_for(data_width=data_width)
    data, instr = request(plan), request(plan, instruction=True)
    trace = [Cycle(begin=header_for(plan))]
    trace += transaction(plan, instr, instruction_payload=0xFEDCBA98)
    trace += transaction(plan, data, response_data=0xDEADBEEF)
    trace += transaction(plan, replace(data, write=True, write_data=0x12345678, byte_enable=5))
    trace += transaction(plan, instr, instruction_payload=0)
    trace += transaction(plan, replace(data, address=0x83), response_data=0)
    assert_equivalent(tmp_path, plan, trace)


@pytest.mark.parametrize("max_wait", [1, 2, 5])
def test_stalls_force_bounded_acceptance_and_response_with_single_outstanding(tmp_path, max_wait):
    plan = plan_for(max_wait_cycles=max_wait)
    req = request(plan)
    trace = [Cycle(begin=header_for(plan)), Cycle(raw(plan, response_choice=7))]
    trace += [Cycle(0, req) for _ in range(max_wait)]
    # Changing requests while pending cannot replace the accepted request.
    trace += [Cycle(raw(plan, response_data=0xFEED), replace(req, address=0x90))
              for _ in range(max_wait)]
    trace += transaction(plan, req, response_data=0xDEAD)
    trace += [Cycle(0, req), Cycle(), Cycle(0, req), Cycle(reset=True)]
    trace += transaction(plan, req)
    result = assert_equivalent(tmp_path, plan, trace)
    assert result[1 + max_wait][0] == 1
    assert result[1 + 2 * max_wait] == (0, 1, 0xFEED, 0)


@pytest.mark.parametrize("max_wait", [(1 << 32) + 1, (1 << 63) + 1])
def test_large_wait_configuration_is_not_truncated_to_systemverilog_integer(tmp_path, max_wait):
    plan = plan_for(max_wait_cycles=max_wait)
    req = request(plan)
    trace = [Cycle(begin=header_for(plan)), Cycle(0, req), Cycle(0, req), Cycle()]
    trace += [Cycle(raw(plan, response_choice=1), req), Cycle(), Cycle()]
    trace += [Cycle(raw(plan, response_choice=2, response_data=0xFEED))]
    assert_equivalent(tmp_path, plan, trace)


@pytest.mark.parametrize("allow_error", [False, True])
def test_error_provenance_partial_and_empty_writes_and_lifetimes(tmp_path, allow_error):
    plan = plan_for(memory_capacity_entries=3, allow_error=allow_error)
    data, instr = request(plan), request(plan, instruction=True)
    trace = [Cycle(begin=header_for(plan))]
    trace += transaction(plan, data, response_data=0xDEADBEEF)
    trace += transaction(plan, replace(data, write=True, byte_enable=0))
    trace += [Cycle(reset=True)]
    trace += transaction(plan, instr)
    trace += transaction(plan, data)
    trace += transaction(plan, replace(data, write=True, write_data=0xAA00, byte_enable=2),
                         response_choice=6, response_data=0xBEEF)
    trace += transaction(plan, instr)
    trace += transaction(plan, replace(data, write=True, write_data=0xCC00, byte_enable=2))
    trace += transaction(plan, instr)
    trace += transaction(plan, replace(data, address=0x90, write=True, write_data=0x550000, byte_enable=4))
    trace += transaction(plan, replace(instr, address=0x90), response_data=0x12345678)
    trace += transaction(plan, replace(instr, address=0x90), response_data=0xFFFFFFFF)
    trace += [Cycle(raw(plan, response_choice=1), replace(data, address=0xA0)), Cycle(reset=True)]
    trace += [Cycle(raw(plan, response_choice=2))]
    trace += transaction(plan, replace(instr, address=0xA0))
    trace += [Cycle(raw(plan, response_choice=1), data), Cycle(begin=header_for(plan), reset=True)]
    trace += [Cycle(raw(plan, response_choice=2))]
    trace += transaction(plan, instr)
    assert_equivalent(tmp_path, plan, trace)


@pytest.mark.parametrize("capacity", [1, 3, 256])
def test_full_capacity_has_no_eviction_or_hash_collisions(tmp_path, capacity):
    plan = plan_for(memory_capacity_entries=capacity, allow_error=False)
    trace = [Cycle(begin=header_for(plan))]
    # Addresses deliberately share low bits: a direct-mapped replacement is not equivalent.
    for i in range(capacity):
        trace += transaction(plan, request(plan, i * 0x1000), response_data=i + 1)
    trace += transaction(plan, request(plan, 0xFFFFF000), response_data=0xAA)
    trace += transaction(plan, request(plan, 0xFFFFF000, write=True, write_data=3))
    trace += transaction(plan, request(plan, 0xFFFFF000, write=True, byte_enable=0))
    trace += transaction(plan, request(plan, 0), response_data=0xBB)
    trace += [Cycle(reset=True)]
    trace += transaction(plan, request(plan, 0xFFFFF000))
    trace += [Cycle(begin=header_for(plan))]
    trace += transaction(plan, request(plan, 0xFFFFF000), response_data=0xCC)
    assert_equivalent(tmp_path, plan, trace)


def test_error_and_empty_write_do_not_consume_capacity(tmp_path):
    plan = plan_for(memory_capacity_entries=1)
    trace = [Cycle(begin=header_for(plan))]
    trace += transaction(plan, request(plan), response_choice=6, response_data=0xBAAD)
    trace += transaction(plan, request(plan, 0x90, write=True, byte_enable=0))
    trace += transaction(plan, request(plan, 0xA0), response_data=0xBEEF)
    assert_equivalent(tmp_path, plan, trace)


@pytest.mark.parametrize("data_width", [32, 64])
def test_domains_alignment_and_reordered_external_fields(tmp_path, data_width):
    plan = plan_for(data_width=data_width, address_width=64, memory_capacity_entries=2,
                    memory_domains={"instruction_memory_master": "code", "data_memory_master": "data"},
                    external_inputs={"mode": 13, "reset": 1})
    fields = plan.cycle_layout.fields
    plan = replace(plan, cycle_layout=CycleInputLayout.build([*fields[-2:], *fields[:-2]]))
    trace = [Cycle(begin=header_for(plan))]
    trace += transaction(plan, request(plan, 0xFFFFFFFFFFFFFFFF), response_data=0x12345678,
                         **{"external.mode": 8191, "external.reset": 1})
    trace += transaction(plan, request(plan, 0xFFFFFFFFFFFFFFFF, instruction=True), instruction_payload=0)
    trace += transaction(plan, request(plan, 0xFFFFFFFFFFFFFFFC), response_data=0xDEADBEEF)
    trace += transaction(plan, request(plan, 0xFFFFFFFFFFFFFFFB), response_data=0xDEADBEEF)
    assert_equivalent(tmp_path, plan, trace)


@pytest.mark.parametrize("data_width", [32, 64])
@pytest.mark.parametrize("halfword", ["request", "boot"])
def test_halfword_entry_forces_compressed_and_header_is_latched(tmp_path, data_width, halfword):
    plan = plan_for(data_width=data_width)
    trace = [Cycle(begin=header_for(plan, boot_address=0x82 if halfword == "boot" else 0x80)),
             Cycle(reset=True)]
    trace += transaction(plan, request(plan, 0x80 if halfword == "boot" else 0x82, instruction=True),
                         instruction_compressed=0, instruction_payload=(1 << data_width) - 1)
    trace += transaction(plan, request(plan, 0x80, instruction=True), instruction_payload=0)
    trace += transaction(plan, request(plan, 0x90, instruction=True), instruction_compressed=0)
    trace += [Cycle(begin=header_for(plan, boot_address=0x80))]
    trace += transaction(plan, request(plan, instruction=True), instruction_compressed=0)
    assert_equivalent(tmp_path, plan, trace)


@pytest.mark.parametrize("xlen,data_width,has_c", [(32, 32, False), (32, 64, False),
                                                   (32, 32, True), (32, 64, True), (64, 64, True)])
def test_all_selectors_independent_slots_compressed_repairs_and_illegal_mode(tmp_path, xlen, data_width, has_c):
    plan = plan_for(isa=IsaContract(xlen, ("I", "M", "C") if has_c else ("I", "M"),
                                   instruction_alignment=2 if has_c else 4), data_width=data_width)
    trace = []
    rng = random.Random(129)
    selectors = [f for f in plan.cycle_layout.fields if f.name.startswith("instruction_selector")]
    for illegal in (False, True):
        for compressed in ((0, 1) if has_c else (0,)):
            for payload in (0, (1 << data_width) - 1, rng.getrandbits(data_width)):
                trace.append(Cycle(begin=header_for(plan, illegal_instruction=illegal)))
                for selector in range(256):
                    values = {f.name: (selector + index * 67) % 256 for index, f in enumerate(selectors)}
                    values["instruction_payload"] = payload
                    if has_c:
                        values["instruction_compressed"] = compressed
                    trace += transaction(plan, request(plan, 0x1000 + selector * (data_width // 8), instruction=True),
                                         **values)
    assert_equivalent(tmp_path, plan, trace)


@pytest.mark.parametrize("data_width", [32, 64])
def test_seeded_mixed_cycle_trace_matches_reference(tmp_path, data_width):
    plan = plan_for(data_width=data_width, memory_capacity_entries=7, max_wait_cycles=4)
    rng = random.Random(0xBEA7)
    trace = [Cycle(begin=header_for(plan))]
    for i in range(1200):
        req = None
        if rng.randrange(4):
            instruction = bool(rng.randrange(2))
            req = request(plan, 0x80 + rng.randrange(16) * 4, instruction=instruction,
                          write=not instruction and bool(rng.randrange(2)),
                          write_data=rng.getrandbits(data_width), byte_enable=rng.getrandbits(data_width // 8))
        trace.append(Cycle(rng.getrandbits(plan.cycle_layout.raw_width), req,
                           reset=i % 71 == 70,
                           begin=header_for(plan, boot_address=0x82, illegal_instruction=bool(i % 2))
                           if i % 139 == 138 else None))
    assert_equivalent(tmp_path, plan, trace)


@pytest.mark.parametrize("xlen", [32, 64])
def test_compressed_repair_exhausts_every_template_free_bit_combination(tmp_path, xlen):
    plan = plan_for(isa=IsaContract(xlen, ("I", "M", "C"), instruction_alignment=2), data_width=64)
    instruction = RiscvInstructionTransducer(plan.isa)
    templates = [template for template in instruction.templates if template.width == 16]
    trace, beat_index = [], 0
    for template_index, template in enumerate(templates):
        selector = (template_index * 256 + len(templates) - 1) // len(templates)
        free_bits = [bit for bit in range(16) if not template.fixed_mask >> bit & 1]
        combinations = 1 << len(free_bits)
        for first in range(0, combinations, 4):
            if beat_index % 256 == 0:
                trace.append(Cycle(begin=header_for(plan)))
            payload = 0
            for slot in range(4):
                combination = min(first + slot, combinations - 1)
                word = sum(((combination >> index) & 1) << bit for index, bit in enumerate(free_bits))
                # Constrained raw bits must also be ignored by the repair.
                word |= template.fixed_mask if combination % 2 else 0
                payload |= word << (16 * slot)
            trace += transaction(plan, request(plan, 0x1000 + (beat_index % 256) * 8, instruction=True),
                                 instruction_compressed=1, instruction_payload=payload,
                                 instruction_selector=selector, instruction_selector_1=selector,
                                 instruction_selector_2=selector, instruction_selector_3=selector)
            beat_index += 1
    assert_equivalent(tmp_path, plan, trace)


@pytest.mark.skipif(not shutil.which("yosys"), reason="Yosys is required for synthesis structure verification")
def test_generated_default_capacity_store_synthesizes_without_latches(tmp_path):
    rtl = tmp_path / "backend.sv"
    rtl.write_text(render_transducer_rtl(plan_for(data_width=64)), encoding="utf-8")
    result = subprocess.run([shutil.which("yosys"), "-Q", "-T", "-p",
                             f"read_verilog -sv {rtl}; hierarchy -check -top myfuzz_contract_transducer; "
                             "proc; opt; memory_collect; check -assert; select -assert-none t:$dlatch"],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
