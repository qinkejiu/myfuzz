"""Render a contract-derived, single-outstanding coherent memory backend."""

from __future__ import annotations

from functools import lru_cache
import re
from typing import TYPE_CHECKING

from .contract_transducer import ContractTransducerPlan, MAX_MEMORY_CAPACITY_ENTRIES

if TYPE_CHECKING:
    from myfuzz.isa.transducer import InstructionTemplate, RiscvInstructionTransducer


# Reserved words cannot be used as the unescaped module identifier we emit.
# Matching is case-sensitive, like SystemVerilog identifiers and keywords.
_SYSTEMVERILOG_KEYWORDS = frozenset("""
accept_on alias always always_comb always_ff always_latch and assert assign assume
automatic before begin bind bins binsof bit break buf bufif0 bufif1 byte case casex
casez cell chandle checker class clocking cmos config const constraint context
continue cover covergroup coverpoint cross deassign default defparam design disable
dist do edge else end endcase endchecker endclass endclocking endconfig endfunction
endgenerate endgroup endinterface endmodule endpackage endprimitive endprogram
endproperty endspecify endsequence endtable endtask enum event eventually expect
export extends extern final first_match for force foreach forever fork forkjoin
function generate genvar global highz0 highz1 if iff ifnone ignore_bins illegal_bins
implements implies import incdir include initial inout input inside instance int
integer interconnect interface intersect join join_any join_none large let liblist
library local localparam logic longint macromodule matches medium modport module
nand negedge nettype new nexttime nmos nor noshowcancelled not notif0 notif1 null or
output package packed parameter pmos posedge primitive priority program property
protected pull0 pull1 pulldown pullup pulsestyle_ondetect pulsestyle_onevent pure
rand randc randcase randsequence rcmos real realtime ref reg reject_on release
repeat restrict return rnmos rpmos rtran rtranif0 rtranif1 s_always s_eventually
s_nexttime s_until s_until_with scalared sequence shortint shortreal showcancelled
signed small soft solve specify specparam static string strong strong0 strong1
struct super supply0 supply1 sync_accept_on sync_reject_on table tagged task this
throughout time timeprecision timeunit tran tranif0 tranif1 tri tri0 tri1 triand
trior trireg type typedef union unique unique0 unsigned until until_with untyped
use uwire var vectored virtual void wait wait_order wand weak weak0 weak1 while
wildcard wire with within wor xnor xor
""".split())


def _literal(width: int, value: int) -> str:
    return f"{width}'h{value:x}"


def _decision_expression(bits: tuple[int, ...], values: tuple[int, ...]) -> str:
    """Reduce a truth table to a Shannon expression over payload bits.

    Compressed templates have at most eleven free bits. Enumerating only that
    small subspace lets the ISA reference remain the single source of nonzero
    operand / reserved-encoding repairs; no operation-name rules live here.
    Equal branches are folded, so this emits logic, not a 65536-word ROM.
    """
    if all(value == values[0] for value in values):
        return f"1'b{values[0]}"
    midpoint = len(values) // 2
    low = _decision_expression(bits[:-1], values[:midpoint])
    high = _decision_expression(bits[:-1], values[midpoint:])
    if low == high:
        return low
    condition = f"payload[{bits[-1]}]"
    if low == "1'b0" and high == "1'b1":
        return condition
    if low == "1'b1" and high == "1'b0":
        return f"~{condition}"
    return f"({condition} ? {high} : {low})"


def _compressed_corrections(instruction: RiscvInstructionTransducer,
                            template: InstructionTemplate) -> list[str]:
    free_bits = tuple(bit for bit in range(template.width) if not template.fixed_mask >> bit & 1)
    before, after = [], []
    for combination in range(1 << len(free_bits)):
        payload = sum(((combination >> index) & 1) << bit for index, bit in enumerate(free_bits))
        before.append(template.repair(payload))
        after.append(instruction.repair_for_operation(template.name, payload).word)
    changed = 0
    for original, repaired in zip(before, after):
        changed |= original ^ repaired
    return [f"word[{bit}] = {_decision_expression(free_bits, tuple(value >> bit & 1 for value in after))};"
            for bit in range(template.width) if changed >> bit & 1]


@lru_cache(maxsize=32)
def _instruction_functions(isa) -> str:
    from myfuzz.isa.transducer import RiscvInstructionTransducer

    instruction = RiscvInstructionTransducer(isa)
    functions = []
    for width in sorted({template.width for template in instruction.templates}):
        templates = [template for template in instruction.templates if template.width == width]
        illegal = instruction.repair((1 << instruction.selector_width) - 1, 0, width=width, illegal=True)
        branches = []
        for index, template in enumerate(templates):
            keep = ((1 << width) - 1) & ~template.fixed_mask
            corrections = _compressed_corrections(instruction, template) if width == 16 else []
            branches.append(f"""
        {index}: begin // {template.name}
          word = (payload & {_literal(width, keep)}) | {_literal(width, template.fixed_value)};
          {' '.join(corrections)}
        end""")
        functions.append(f"""
  function automatic [{width-1}:0] repair_{width}(
      input [{instruction.selector_width-1}:0] selector, input [{width-1}:0] payload,
      input illegal_mode);
    integer selected;
    reg [{width-1}:0] word;
    begin
      selected = (selector * (illegal_mode ? {len(templates)+1} : {len(templates)})) >> {instruction.selector_width};
      case (selected)
        {''.join(branches)}
        default: word = (payload & {_literal(width, illegal.free_mask)}) | {_literal(width, illegal.word)};
      endcase
      repair_{width} = word;
    end
  endfunction
""")
    return "".join(functions)


def render_transducer_rtl(plan: ContractTransducerPlan,
                          module_name: str = "myfuzz_contract_transducer") -> str:
    """Emit synthesizable SystemVerilog for valid normalized contract requests.

    ``reset_i`` is active-low. ``test_begin_i`` is synchronous, clears the store
    even during DUT reset, and latches the boot/illegal header controls. The host
    must validate the full TestHeader with ContractRuntime before asserting it.
    No operation is permitted before the first test begin.

    ``req_instruction_i`` selects instruction (1) or data (0); memory domains
    are derived from the plan's function bindings. Only bound functions and
    legal requests are permitted, as with ContractRuntime's request validation.
    An omitted reference byte_enable is represented by all enabled lanes.

    Outputs describe the current cycle before its rising edge, which commits
    the request/response and memory effects. Responses have no backpressure,
    matching ProcessorBeatTransducer.step. Cycle entropy must remain stable
    through that edge. The accepting cycle cannot also respond. External input
    fields belong to the composition caller and are never consumed here.
    """
    if not isinstance(plan, ContractTransducerPlan):
        raise ValueError("plan must be a ContractTransducerPlan")
    if (not isinstance(module_name, str)
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_$]*", module_name)
            or module_name in _SYSTEMVERILOG_KEYWORDS):
        raise ValueError("module_name must be a non-keyword SystemVerilog identifier")
    if (type(plan.memory_capacity_entries) is not int
            or not 1 <= plan.memory_capacity_entries <= MAX_MEMORY_CAPACITY_ENTRIES):
        raise ValueError(f"memory_capacity_entries must be between 1 and {MAX_MEMORY_CAPACITY_ENTRIES}")
    plan.cycle_layout.validate()
    aw, dw = plan.address_width, plan.data_width
    byte_count = dw // 8
    address_mask = ((1 << aw) - 1) & ~(byte_count - 1)
    wait_width = max(1, (plan.max_wait_cycles - 1).bit_length())
    domain_ids = {domain: index for index, domain in enumerate(sorted(set(dict(plan.memory_domains).values())))}
    function_domains = {function: domain_ids[domain] for function, domain in plan.memory_domains}
    fields = {field.name: field for field in plan.cycle_layout.fields}
    wires = []
    for field in fields.values():
        if not field.name.startswith("external."):
            wires.append(f"  wire [{field.width-1}:0] rfuzz_{field.name} = "
                         f"rfuzz_cycle_bits[{field.raw_hi}:{field.raw_lo}];")
    compressed = "instruction_compressed" in fields
    slots = {}
    for width in ((32, 16) if compressed else (32,)):
        assignments = []
        for index in range(dw // width):
            selector = "instruction_selector" if index == 0 else f"instruction_selector_{index}"
            assignments.append(f"instruction_data[{index*width} +: {width}] = repair_{width}("
                               f"rfuzz_{selector}, rfuzz_instruction_payload[{index*width} +: {width}], illegal_q);")
        slots[width] = "\n      ".join(assignments)
    instruction_data = slots[32]
    if compressed:
        instruction_data = f"""if (rfuzz_instruction_compressed || (pending_addr_q % 4 == 2) ||
        ((pending_base == (boot_address_q & ADDRESS_MASK)) && (boot_address_q % 4 == 2))) begin
      {slots[16]}
    end else begin
      {slots[32]}
    end"""
    return f"""// Contract {plan.contract_hash}
// Pre-edge outputs; rising edge commits one Python ContractRuntime.step.
module {module_name} (
  input logic clock_i,
  input logic reset_i,
  input logic test_begin_i,
  input logic [{aw-1}:0] test_boot_address_i,
  input logic test_illegal_instruction_i,
  input logic [{plan.cycle_layout.raw_width-1}:0] rfuzz_cycle_bits,
  input logic req_valid_i,
  input logic req_instruction_i,
  input logic [{aw-1}:0] req_addr_i,
  input logic req_write_i,
  input logic [{dw-1}:0] req_wdata_i,
  input logic [{byte_count-1}:0] req_be_i,
  output logic req_ready_o,
  output logic rsp_valid_o,
  output logic [{dw-1}:0] rsp_data_o,
  output logic rsp_error_o
);
  localparam integer MEMORY_CAPACITY = {plan.memory_capacity_entries};
  localparam logic [{wait_width-1}:0] MAX_WAIT_MINUS_ONE = {_literal(wait_width, plan.max_wait_cycles-1)};
  localparam integer BYTE_COUNT = {byte_count};
  localparam logic ALLOW_ERROR = 1'b{int(plan.allow_error)};
  localparam logic INSTRUCTION_DOMAIN = 1'b{function_domains.get('instruction_memory_master', 0)};
  localparam logic DATA_DOMAIN = 1'b{function_domains.get('data_memory_master', 0)};
  localparam logic [1:0] INSTRUCTION_GENERATED = 2'd0;
  localparam logic [1:0] DATA_GENERATED = 2'd1;
  localparam logic [1:0] CPU_WRITTEN = 2'd2;
  localparam logic [{aw-1}:0] ADDRESS_MASK = {_literal(aw, address_mask)};
{chr(10).join(wires)}

  logic pending_q, pending_instruction_q, pending_write_q, pending_domain_q;
  logic [{aw-1}:0] pending_addr_q, boot_address_q;
  logic [{dw-1}:0] pending_wdata_q;
  logic [BYTE_COUNT-1:0] pending_be_q;
  logic [{wait_width-1}:0] wait_q, accept_wait_q;
  logic illegal_q;
  wire [{aw-1}:0] pending_base = pending_addr_q & ADDRESS_MASK;

  // Full tags and first-free allocation preserve arbitrary-address capacity.
  // Per-byte validity preserves partial CPU writes before the first read.
  logic memory_valid_q [0:MEMORY_CAPACITY-1];
  logic [{aw-1}:0] memory_tag_q [0:MEMORY_CAPACITY-1];
  logic memory_domain_q [0:MEMORY_CAPACITY-1];
  logic [{dw-1}:0] memory_data_q [0:MEMORY_CAPACITY-1];
  logic [BYTE_COUNT-1:0] memory_bytes_q [0:MEMORY_CAPACITY-1];
  logic [1:0] memory_provenance_q [0:MEMORY_CAPACITY-1];

  integer hit_index, free_index, store_index;
  integer lookup_index, lane_index, clear_index;
  logic store_enable;
  logic [{dw-1}:0] store_data, instruction_data, initial_data;
  logic [BYTE_COUNT-1:0] store_bytes;
  logic [1:0] store_provenance;
{_instruction_functions(plan.isa)}
  always @* begin
    {instruction_data}
  end

  always @* begin
    hit_index = -1;
    free_index = -1;
    for (lookup_index = 0; lookup_index < MEMORY_CAPACITY; lookup_index = lookup_index + 1) begin
      if (memory_valid_q[lookup_index]) begin
        if (memory_tag_q[lookup_index] == pending_base &&
            memory_domain_q[lookup_index] == pending_domain_q)
          hit_index = lookup_index;
      end else if (free_index == -1) free_index = lookup_index;
    end
  end

  always @* begin
    req_ready_o = 1'b0;
    rsp_valid_o = 1'b0;
    rsp_error_o = 1'b0;
    rsp_data_o = '0;
    store_enable = 1'b0;
    store_index = hit_index == -1 ? free_index : hit_index;
    store_data = '0;
    store_bytes = '0;
    store_provenance = pending_instruction_q ? INSTRUCTION_GENERATED : DATA_GENERATED;
    initial_data = pending_instruction_q ? instruction_data : rfuzz_response_data;
    if (hit_index != -1) begin
      store_data = memory_data_q[hit_index];
      store_bytes = memory_bytes_q[hit_index];
      store_provenance = memory_provenance_q[hit_index];
      if (store_provenance == CPU_WRITTEN) initial_data = rfuzz_response_data;
    end
    if (reset_i && !test_begin_i) begin
      if (!pending_q) begin
        req_ready_o = req_valid_i && (rfuzz_response_choice[0] || accept_wait_q == MAX_WAIT_MINUS_ONE);
      end else if (rfuzz_response_choice[1] || wait_q == MAX_WAIT_MINUS_ONE) begin
        rsp_valid_o = 1'b1;
        if (ALLOW_ERROR && rfuzz_response_choice[2]) begin
          rsp_error_o = 1'b1;
          rsp_data_o = rfuzz_response_data;
        end else if (pending_write_q && pending_be_q == 0) begin
          // Empty writes neither allocate nor change provenance, even when full.
          rsp_data_o = '0;
        end else if (store_index == -1) begin
          rsp_error_o = 1'b1;
        end else if (!pending_write_q && pending_instruction_q &&
                     hit_index != -1 && store_provenance == DATA_GENERATED) begin
          rsp_error_o = 1'b1;
        end else begin
          store_enable = 1'b1;
          if (pending_write_q) begin
            store_provenance = CPU_WRITTEN;
            for (lane_index = 0; lane_index < BYTE_COUNT; lane_index = lane_index + 1) begin
              if (pending_be_q[lane_index]) begin
                store_data[lane_index*8 +: 8] = pending_wdata_q[lane_index*8 +: 8];
                store_bytes[lane_index] = 1'b1;
              end
            end
          end else begin
            for (lane_index = 0; lane_index < BYTE_COUNT; lane_index = lane_index + 1) begin
              if (!store_bytes[lane_index])
                store_data[lane_index*8 +: 8] = initial_data[lane_index*8 +: 8];
            end
            store_bytes = '1;
            rsp_data_o = store_data;
          end
        end
      end
    end
  end

  // These state elements have a test lifetime, independent of DUT reset.
  always_ff @(posedge clock_i) begin
    if (test_begin_i) begin
      boot_address_q <= test_boot_address_i;
      illegal_q <= test_illegal_instruction_i;
      for (clear_index = 0; clear_index < MEMORY_CAPACITY; clear_index = clear_index + 1)
        memory_valid_q[clear_index] <= 1'b0;
    end else if (store_enable) begin
      memory_valid_q[store_index] <= 1'b1;
      memory_tag_q[store_index] <= pending_base;
      memory_domain_q[store_index] <= pending_domain_q;
      memory_data_q[store_index] <= store_data;
      memory_bytes_q[store_index] <= store_bytes;
      memory_provenance_q[store_index] <= store_provenance;
    end
  end

  always_ff @(posedge clock_i or negedge reset_i) begin
    if (!reset_i) begin
      pending_q <= 1'b0;
      wait_q <= '0;
      accept_wait_q <= '0;
    end else if (test_begin_i) begin
      pending_q <= 1'b0;
      wait_q <= '0;
      accept_wait_q <= '0;
    end else if (pending_q) begin
      accept_wait_q <= '0;
      if (rsp_valid_o) begin
        pending_q <= 1'b0;
        wait_q <= '0;
      end else wait_q <= wait_q + 1'b1;
    end else begin
      wait_q <= '0;
      if (req_ready_o) begin
        pending_q <= 1'b1;
        pending_addr_q <= req_addr_i;
        pending_instruction_q <= req_instruction_i;
        pending_domain_q <= req_instruction_i ? INSTRUCTION_DOMAIN : DATA_DOMAIN;
        pending_write_q <= req_write_i;
        pending_wdata_q <= req_wdata_i;
        pending_be_q <= req_be_i;
        accept_wait_q <= '0;
      end else if (req_valid_i) accept_wait_q <= accept_wait_q + 1'b1;
      else accept_wait_q <= '0;
    end
  end
endmodule
"""


__all__ = ["render_transducer_rtl"]
