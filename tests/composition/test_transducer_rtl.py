"""Contract-derived renderer shape, field ownership, and validation."""

from dataclasses import replace
import re

import pytest

from myfuzz.composition.contract_transducer import compile_contract_transducer
from myfuzz.composition.cycle_input import CycleInputLayout
from myfuzz.composition.transducer_rtl import render_transducer_rtl
from myfuzz.isa.constraints import IsaContract


def plan_for(**overrides):
    args = dict(isa=IsaContract(32, ("I", "M", "C"), instruction_alignment=2),
                protocol=("processor-memory-beat", "1"), address_width=32,
                data_width=32, memory_domains={"instruction_memory_master": "main",
                                             "data_memory_master": "main"})
    return compile_contract_transducer(**(args | overrides))


def test_renderer_exposes_only_generic_beat_and_entropy_names():
    plan = plan_for(external_inputs={"outside_signal": 5})
    source = render_transducer_rtl(plan)
    assert "module myfuzz_contract_transducer" in source
    for port in ("clock_i", "reset_i", "test_begin_i", "test_boot_address_i",
                 "test_illegal_instruction_i", "rfuzz_cycle_bits", "req_instruction_i",
                 "req_valid_i", "req_ready_o", "req_addr_i", "req_write_i",
                 "req_wdata_i", "req_be_i", "rsp_valid_o", "rsp_data_o", "rsp_error_o"):
        assert re.search(rf"\b{port}\b", source)
    assert not any(cpu in source.lower() for cpu in ("ibex", "cva6", "boom", "top.u_"))
    assert "outside_signal" not in source
    assert "always_ff" in source
    assert "localparam integer MEMORY_CAPACITY = 256;" in source
    assert "[0:MEMORY_CAPACITY-1]" in source
    assert not any(token in source for token in ("$readmem", "$random", "initial begin"))


@pytest.mark.parametrize("data_width", [32, 64])
def test_offsets_follow_plan_even_with_reordered_external_fields(data_width):
    plan = plan_for(data_width=data_width, external_inputs={"outside": 7})
    fields = plan.cycle_layout.fields
    plan = replace(plan, cycle_layout=CycleInputLayout.build([fields[-1], *fields[:-1]]))
    source = render_transducer_rtl(plan, module_name="custom_backend")
    assert "module custom_backend" in source
    for field in plan.cycle_layout.fields:
        selection = f"rfuzz_cycle_bits[{field.raw_hi}:{field.raw_lo}]"
        assert (selection in source) == (not field.name.startswith("external."))
    assert f"input logic [{plan.cycle_layout.raw_width - 1}:0] rfuzz_cycle_bits" in source


def test_rendering_is_deterministic_and_configuration_is_plan_derived():
    plan = plan_for(address_width=64, data_width=64, memory_capacity_entries=3,
                    max_wait_cycles=1, allow_error=False)
    source = render_transducer_rtl(plan)
    assert source == render_transducer_rtl(plan)
    assert "localparam integer MEMORY_CAPACITY = 3;" in source
    assert "localparam logic [0:0] MAX_WAIT_MINUS_ONE = 1'h0;" in source
    assert "input logic [63:0] req_addr_i" in source
    assert plan.contract_hash in source


@pytest.mark.parametrize("name", ["", "bad name", "9module", "bad;endmodule", "a.b"])
def test_invalid_module_name_is_rejected(name):
    with pytest.raises(ValueError, match="module_name"):
        render_transducer_rtl(plan_for(), module_name=name)


@pytest.mark.parametrize("capacity", [True, False, 0, -1, 1.5, 4097, (1 << 32) + 1])
def test_renderer_revalidates_capacity_in_manually_changed_plan(capacity):
    plan = replace(plan_for(), memory_capacity_entries=capacity)
    with pytest.raises(ValueError, match="memory_capacity_entries"):
        render_transducer_rtl(plan)


@pytest.mark.parametrize("capacity", [1, 256, 4096])
def test_renderer_preserves_supported_capacity_constants_without_truncation(capacity):
    source = render_transducer_rtl(plan_for(memory_capacity_entries=capacity))
    assert f"localparam integer MEMORY_CAPACITY = {capacity};" in source
    assert "integer hit_index, free_index, store_index;" in source


@pytest.mark.parametrize("name", ["module", "endmodule", "logic", "always_ff", "assign",
                                 "always_comb", "interface", "package", "function", "endfunction",
                                 "input", "output", "wire", "reg", "generate", "endgenerate",
                                 "assert", "property", "checker", "class", "rand", "nettype"])
def test_systemverilog_keyword_module_names_are_rejected(name):
    with pytest.raises(ValueError, match="module_name"):
        render_transducer_rtl(plan_for(), module_name=name)


@pytest.mark.parametrize("name", ["custom_backend", "Module", "logic_core", "assign_1", "_backend$2"])
def test_nonkeyword_identifiers_remain_compatible(name):
    assert f"module {name} (" in render_transducer_rtl(plan_for(), module_name=name)
