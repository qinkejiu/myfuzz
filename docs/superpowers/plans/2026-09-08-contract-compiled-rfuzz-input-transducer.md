# Contract-Compiled RFuzz Input Transducer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace fixed boot-memory instruction delivery with a CPU-independent, contract-compiled transducer that turns equal-width RFuzz cycle records into legal ISA instructions, legal protocol responses, coherent data, and the remaining DUT functional inputs.

**Architecture:** Keep CPU-specific code at the existing physical-port binding boundary. Compile ISA and protocol facts into a typed constraint plan, evaluate the same plan in Python for proofs, and render its stateful processor-memory-beat portion into RTL for live simulation; existing OBI/AXI/TL-UL adapters translate that normalized behavior to the CPU interface. A per-test sparse coherent memory makes the first RFuzz-derived value for an address stable until a byte-enabled write changes it.

**Tech Stack:** Python 3.12 dataclasses and unittest, canonical JSON hashing, generated SystemVerilog, Icarus/Verilator, existing RFuzz shared-memory client.

## Global Constraints

- RFuzz is the only source of variable instruction, response-data, timing-choice, interrupt, debug, and remaining functional-input bits.
- Clock is testbench-generated; reset duration, boot address, Hart ID, feature flags, and hashes are fixed test-header/configuration values.
- Default instruction generation uses only the declared ISA; `illegal_instruction` is explicit and disabled by default.
- Protocol-defined error responses are legal choices; illegal handshakes and field combinations are repaired.
- Repeated reads of one address within a test return the stored value; byte-enabled writes update later reads.
- Repeated instruction fetches from one address return the same RFuzz-derived instruction.
- No generic constraint rule may branch on a CPU name or implementation hierarchy.
- The existing fixed boot-RAM Ibex example is replaced, not retained as the instruction source.
- Same raw input, header, contract hashes, and initial state must reproduce the same DUT-input trace.
- Do not modify `.superpowers/sdd/task-2-report.md` or add/remove anything under `third_party/`.

---

## File Structure

- `src/myfuzz/composition/constraint_ir.py`: typed, width-checked Boolean/select IR and deterministic evaluator.
- `src/myfuzz/composition/cycle_input.py`: fixed test header, equal-width cycle records, layout identity, and parsing.
- `src/myfuzz/isa/transducer.py`: ISA-capability-derived operation templates and minimal instruction repair.
- `src/myfuzz/composition/coherent_memory.py`: per-test byte-addressed memory domains.
- `src/myfuzz/composition/protocol_transducer.py`: normalized request/response state and RFuzz choice application.
- `src/myfuzz/composition/contract_transducer.py`: compile and execute the complete Python reference transducer.
- `src/myfuzz/composition/transducer_rtl.py`: render the normalized stateful backend used by RTL simulation.
- `src/myfuzz/integration/rfuzz_simulator.py`: publish, hash, compile, and drive constrained-backend artifacts.
- `src/myfuzz/integration/real_cpu_campaign.py`: build the real CPU campaign without a fixed boot image.
- `examples/real_ibex_rfuzz/*`: updated input, commands, results, and Chinese explanation.

### Task 1: Width-Checked Constraint IR

**Files:**
- Create: `src/myfuzz/composition/constraint_ir.py`
- Modify: `src/myfuzz/composition/__init__.py`
- Test: `tests/composition/test_constraint_ir.py`

**Interfaces:**
- Produces: `Expr(op, width, args)`, `ConstraintProgram(outputs)`, `select_balanced(raw, raw_width, choices)`, `evaluate(expr, inputs)`.
- Consumes: no later-task interfaces.

- [ ] **Step 1: Write failing truth-table, width, and balanced-selection tests**

```python
def test_mux_and_boolean_nodes_preserve_width():
    expr = mux(ref("s", 1), ref("a", 4), ref("b", 4))
    assert evaluate(expr, {"s": 1, "a": 0xA, "b": 0x3}) == 0xA
    assert evaluate(expr, {"s": 0, "a": 0xA, "b": 0x3}) == 0x3

def test_balanced_selection_differs_by_at_most_one_preimage():
    counts = [0] * 5
    for raw in range(256):
        counts[select_balanced(raw, 8, tuple(range(5)))] += 1
    assert max(counts) - min(counts) <= 1

def test_width_mismatch_and_cycle_fail_closed():
    with pytest.raises(ConstraintIrError, match="width"):
        bit_and(ref("a", 2), ref("b", 3))
```

- [ ] **Step 2: Run the new test and confirm the imports fail**

Run: `python -m pytest tests/composition/test_constraint_ir.py -q`

Expected: FAIL because `myfuzz.composition.constraint_ir` does not exist.

- [ ] **Step 3: Implement immutable IR nodes and validation**

```python
@dataclass(frozen=True, slots=True)
class Expr:
    op: str
    width: int
    args: tuple[object, ...]

@dataclass(frozen=True, slots=True)
class ConstraintProgram:
    outputs: tuple[tuple[str, Expr], ...]

def select_balanced(raw: int, raw_width: int, choices: Sequence[T]) -> T:
    if (type(raw) is not int or type(raw_width) is not int or raw_width <= 0
            or not 0 <= raw < 1 << raw_width or not choices):
        raise ConstraintIrError("invalid selection")
    domain = 1 << raw_width
    return choices[min(len(choices) - 1, raw * len(choices) // domain)]

def mux(select: Expr, when_true: Expr, when_false: Expr) -> Expr:
    if select.width != 1 or when_true.width != when_false.width:
        raise ConstraintIrError("mux width mismatch")
    return Expr("mux", when_true.width, (select, when_true, when_false))
```

Implement `const`, `ref`, `bit_and`, `bit_or`, `bit_not`, `equal`, `slice_bits`, `concat`, DAG validation, canonical document generation, and recursive evaluation with masking after every node.

- [ ] **Step 4: Run focused tests**

Run: `python -m pytest tests/composition/test_constraint_ir.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/myfuzz/composition/constraint_ir.py src/myfuzz/composition/__init__.py tests/composition/test_constraint_ir.py
git commit -m "feat: add typed constraint expression IR"
```

### Task 2: Fixed Header and Equal-Width Cycle Records

**Files:**
- Create: `src/myfuzz/composition/cycle_input.py`
- Modify: `src/myfuzz/composition/rfuzz_transport.py`
- Test: `tests/composition/test_cycle_input.py`
- Test: `tests/composition/test_rfuzz_transport.py`

**Interfaces:**
- Consumes: canonical hashing from `myfuzz.contracts`.
- Produces: `TestHeader`, `CycleField`, `CycleInputLayout`, `CycleTestCase`, `parse_cycle_payload(payload, layout, header)`.

- [ ] **Step 1: Write failing format and truncation tests**

```python
def test_payload_is_split_into_equal_records_without_padding():
    layout = CycleInputLayout.build((CycleField("instruction_entropy", 32), CycleField("response", 2)))
    transport = RfuzzInputTransport(layout.raw_width, layout.layout_hash)
    records = (transport.pack(1), transport.pack(2))
    case = parse_cycle_payload(b"".join(records) + b"x", layout, header(layout, cycles=3))
    assert case.raw_cycles == (1, 2)
    assert case.truncated_bytes == 1

def test_header_hash_mismatch_is_rejected():
    with pytest.raises(CycleInputError, match="layout hash"):
        parse_cycle_payload(record, layout, replace(header(layout), layout_hash="wrong"))
```

- [ ] **Step 2: Run the new test and confirm it fails**

Run: `python -m pytest tests/composition/test_cycle_input.py -q`

Expected: FAIL because `cycle_input` is absent.

- [ ] **Step 3: Implement immutable header/layout/test-case records**

```python
@dataclass(frozen=True, slots=True)
class TestHeader:
    schema_version: str
    layout_hash: str
    contract_hash: str
    reset_cycles: int
    execution_cycles: int
    boot_address: int
    hart_id: int
    illegal_instruction: bool = False

@dataclass(frozen=True, slots=True)
class CycleTestCase:
    header: TestHeader
    raw_cycles: tuple[int, ...]
    truncated_bytes: int
```

Build fields in declared order with contiguous offsets; hash the full layout document. Parse only complete `RfuzzInputTransport.byte_count` records and cap them at `execution_cycles`.

- [ ] **Step 4: Run transport and input-format tests**

Run: `python -m pytest tests/composition/test_cycle_input.py tests/composition/test_rfuzz_transport.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/myfuzz/composition/cycle_input.py src/myfuzz/composition/rfuzz_transport.py tests/composition/test_cycle_input.py tests/composition/test_rfuzz_transport.py
git commit -m "feat: define RFuzz cycle input format"
```

### Task 3: ISA Operation Selection and Minimal Repair

**Files:**
- Create: `src/myfuzz/isa/transducer.py`
- Modify: `src/myfuzz/isa/__init__.py`
- Modify: `src/myfuzz/composition/runtime_projection.py`
- Test: `tests/isa/test_instruction_transducer.py`
- Test: `tests/composition/test_runtime_projection.py`

**Interfaces:**
- Consumes: `IsaContract`, `RiscvInstructionProvider`, `select_balanced`.
- Produces: `InstructionTemplate`, `InstructionChoice`, `RiscvInstructionTransducer.repair(raw_selector, raw_payload, *, illegal=False) -> InstructionChoice`.

- [ ] **Step 1: Write failing legality and retained-entropy tests**

```python
def test_rv32im_repair_selects_multiple_legal_operations():
    tx = RiscvInstructionTransducer(IsaContract(32, ("I", "M")))
    choices = [tx.repair(selector, 0xFEDCBA98) for selector in range(64)]
    assert len({item.operation for item in choices}) >= 10
    assert all(tx.provider.is_legal_word(item.word) for item in choices)

def test_addi_repairs_only_fixed_bits():
    tx = RiscvInstructionTransducer(IsaContract(32, ("I",)))
    result = tx.repair_for_operation("ADDI", 0xFFFFFFFF)
    assert result.word & 0x7F == 0x13
    assert (result.word >> 12) & 7 == 0
    assert result.word & result.free_mask == 0xFFFFFFFF & result.free_mask

def test_illegal_class_is_disabled_by_default_and_explicit_when_enabled():
    assert tx.repair(0xFF, 0).legal
    assert not tx.repair(0xFF, 0, illegal=True).legal
```

- [ ] **Step 2: Run the ISA tests and confirm failure**

Run: `python -m pytest tests/isa/test_instruction_transducer.py -q`

Expected: FAIL because the transducer API is absent.

- [ ] **Step 3: Implement capability-filtered RV32 I/M/C templates**

```python
@dataclass(frozen=True, slots=True)
class InstructionTemplate:
    name: str
    width: int
    extension: str
    fixed_mask: int
    fixed_value: int

    def repair(self, raw: int) -> int:
        word_mask = (1 << self.width) - 1
        return ((raw & ~self.fixed_mask) | self.fixed_value) & word_mask
```

Define templates for all operation forms already accepted by `RiscvInstructionProvider`, including RV32I ALU/load/store/branch/jump/system, M operations, and supported C forms. Add operation-specific predicates for reserved combinations such as zero immediates; repair only the predicate's necessary bits. Change `RuntimeProjector` legal instruction projection from NOP fallback to this selector/template repair.

- [ ] **Step 4: Exhaust selector ranges and run legacy legality tests**

Run: `python -m pytest tests/isa/test_instruction_transducer.py tests/composition/test_runtime_projection.py -q`

Expected: PASS; no illegal default output and more than one repaired instruction for varying raw input.

- [ ] **Step 5: Commit**

```bash
git add src/myfuzz/isa/transducer.py src/myfuzz/isa/__init__.py src/myfuzz/composition/runtime_projection.py tests/isa/test_instruction_transducer.py tests/composition/test_runtime_projection.py
git commit -m "feat: minimally repair RFuzz instructions by ISA"
```

### Task 4: Per-Test Coherent Memory

**Files:**
- Create: `src/myfuzz/composition/coherent_memory.py`
- Test: `tests/composition/test_coherent_memory.py`

**Interfaces:**
- Produces: `CoherentMemoryState.read(domain, address, width_bytes, initializer)`, `write(domain, address, value, byte_enable, width_bytes)`, `reset_test()`.
- Consumes: an initializer callable invoked only for previously absent bytes.

- [ ] **Step 1: Write failing coherence tests**

```python
def test_first_read_initializes_once_and_repeated_read_is_stable():
    memory = CoherentMemoryState()
    calls = []
    first = memory.read("main", 0x1000, 4, lambda: calls.append(1) or 0x12345678)
    second = memory.read("main", 0x1000, 4, lambda: calls.append(2) or 0)
    assert (first, second, calls) == (0x12345678, 0x12345678, [1])

def test_byte_enable_write_updates_selected_bytes():
    memory.seed("main", 0, 0x11223344, 4)
    memory.write("main", 0, 0xAABBCCDD, 0b0101, 4)
    assert memory.read("main", 0, 4, lambda: 0) == 0x11BB33DD
```

- [ ] **Step 2: Run the memory tests and confirm failure**

Run: `python -m pytest tests/composition/test_coherent_memory.py -q`

Expected: FAIL because the memory module is absent.

- [ ] **Step 3: Implement sparse byte storage with domain isolation**

```python
class CoherentMemoryState:
    def __init__(self):
        self._bytes: dict[tuple[str, int], int] = {}

    def write(self, domain, address, value, byte_enable, width_bytes):
        for index in range(width_bytes):
            if byte_enable >> index & 1:
                self._bytes[(domain, address + index)] = value >> (8 * index) & 0xFF
```

Validate bounded nonnegative addresses, little-endian values, positive widths, and byte-enable range. `read` must call the initializer once for an absent span, seed the entire returned word, then assemble bytes.

- [ ] **Step 4: Run focused tests**

Run: `python -m pytest tests/composition/test_coherent_memory.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/myfuzz/composition/coherent_memory.py tests/composition/test_coherent_memory.py
git commit -m "feat: add coherent per-test RFuzz memory"
```

### Task 5: Contract Compiler and Stateful Reference Transducer

**Files:**
- Create: `src/myfuzz/composition/protocol_transducer.py`
- Create: `src/myfuzz/composition/contract_transducer.py`
- Modify: `src/myfuzz/composition/__init__.py`
- Test: `tests/composition/test_protocol_transducer.py`
- Test: `tests/composition/test_contract_transducer.py`

**Interfaces:**
- Consumes: `CycleInputLayout`, `IsaContract`, `RiscvInstructionTransducer`, `CoherentMemoryState`.
- Produces: `ProcessorBeatRequest`, `ProcessorBeatInputs`, `ProtocolState`, `ContractTransducerPlan`, `compile_contract_transducer(...)`, `ContractRuntime.begin_test(header)`, `step(raw_cycle, dut_outputs)`.

- [ ] **Step 1: Write failing OBI-normalized state and end-to-end tests**

```python
def test_response_cannot_precede_an_accepted_request():
    tx = ProcessorBeatTransducer(data_width=32, max_wait_cycles=16)
    idle = tx.step(raw_choice=0b11, raw_data=7, request=None)
    assert not idle.req_ready and not idle.rsp_valid

def test_repeated_instruction_address_returns_first_rfuzz_instruction():
    runtime = runtime_for_rv32imc_obi()
    runtime.begin_test(header)
    first = runtime.step(raw_cycle_a, instruction_request(0x80))
    second = runtime.step(raw_cycle_b, instruction_request(0x80))
    assert first.response_data == second.response_data
    assert first.response_data_source == "stored"
```

- [ ] **Step 2: Run focused tests and confirm failure**

Run: `python -m pytest tests/composition/test_protocol_transducer.py tests/composition/test_contract_transducer.py -q`

Expected: FAIL because compiler/runtime modules are absent.

- [ ] **Step 3: Implement normalized single-outstanding request/response state**

```python
@dataclass(frozen=True, slots=True)
class ProtocolState:
    pending: ProcessorBeatRequest | None = None
    age: int = 0

def step(self, raw_choice, raw_data, request):
    ready = request is not None and self.state.pending is None and bool(raw_choice & 1)
    respond = self.state.pending is not None and bool(raw_choice & 2)
    error = respond and bool(raw_choice & 4)
```

Accept at most one request, retain it until a response, allow contract-defined error, and force a response at `max_wait_cycles` so a legal random stall cannot make every test permanently useless.

- [ ] **Step 4: Compile a CPU-name-independent full plan and runtime**

```python
plan = compile_contract_transducer(
    isa=IsaContract(32, ("I", "M", "C"), instruction_alignment=2),
    protocol=("processor-memory-beat", "1"),
    address_width=32,
    data_width=32,
    memory_domains={"instruction_memory_master": "main", "data_memory_master": "main"},
)
```

The plan allocates selector, instruction payload, response timing/error/data, and external functional-input fields. The runtime uses ISA repair only when first initializing an instruction address and caches the repaired word. It resets protocol state at every test boundary but keeps memory through an in-test DUT reset.

- [ ] **Step 5: Run state, determinism, and name-invariance tests**

Run: `python -m pytest tests/composition/test_protocol_transducer.py tests/composition/test_contract_transducer.py -q`

Expected: PASS, including equal traces for equal input and equal plan hashes after changing only a CPU profile name.

- [ ] **Step 6: Commit**

```bash
git add src/myfuzz/composition/protocol_transducer.py src/myfuzz/composition/contract_transducer.py src/myfuzz/composition/__init__.py tests/composition/test_protocol_transducer.py tests/composition/test_contract_transducer.py
git commit -m "feat: compile stateful RFuzz input transducers"
```

### Task 6: Render and Verify the Stateful RTL Backend

**Files:**
- Create: `src/myfuzz/composition/transducer_rtl.py`
- Test: `tests/composition/test_transducer_rtl.py`
- Test: `tests/integration/test_constrained_backend_rtl.py`

**Interfaces:**
- Consumes: `ContractTransducerPlan` and its cycle-field offsets.
- Produces: `render_transducer_rtl(plan, module_name="myfuzz_contract_transducer") -> str`.

- [ ] **Step 1: Write failing source-shape and Icarus trace tests**

```python
def test_renderer_exposes_only_generic_beat_and_entropy_names():
    source = render_transducer_rtl(plan)
    assert "module myfuzz_contract_transducer" in source
    assert "rfuzz_cycle_bits" in source
    assert "ibex" not in source.lower()

def test_rtl_matches_reference_for_accept_repeat_read_and_write(tmp_path):
    expected = run_python_trace(plan, trace)
    actual = compile_and_run_iverilog(tmp_path, render_transducer_rtl(plan), trace)
    assert actual == expected
```

- [ ] **Step 2: Run tests and confirm the renderer is absent**

Run: `python -m pytest tests/composition/test_transducer_rtl.py tests/integration/test_constrained_backend_rtl.py -q`

Expected: FAIL because `transducer_rtl` is absent.

- [ ] **Step 3: Render a synthesizable bounded coherent store and protocol FSM**

```systemverilog
assign req_ready_o = reset_i && !pending_q && rfuzz_accept;
assign rsp_valid_o = rsp_valid_q;
always_ff @(posedge clock_i or negedge reset_i) begin
  if (!reset_i) begin
    pending_q <= 1'b0;
    rsp_valid_q <= 1'b0;
  end else begin
    if (req_valid_i && req_ready_o) begin
      pending_q <= 1'b1;
      pending_addr_q <= req_addr_i;
    end
    if (pending_q && (rfuzz_respond || wait_q == MAX_WAIT-1)) begin
      rsp_valid_q <= 1'b1;
      pending_q <= 1'b0;
    end
  end
end
```

Use a bounded valid/tag/byte array sized by the plan's memory capacity. On first absent instruction word, render the selected template mask/value repair. Preserve entries across in-test reset and clear them only on explicit `test_begin_i`; clear protocol state on reset and test begin.

- [ ] **Step 4: Run Python/RTL equivalence traces**

Run: `python -m pytest tests/composition/test_transducer_rtl.py tests/integration/test_constrained_backend_rtl.py -q`

Expected: PASS when Icarus is installed; compile test is skipped with an explicit reason otherwise.

- [ ] **Step 5: Commit**

```bash
git add src/myfuzz/composition/transducer_rtl.py tests/composition/test_transducer_rtl.py tests/integration/test_constrained_backend_rtl.py
git commit -m "feat: render stateful constrained memory backend"
```

### Task 7: Integrate the Transducer With Live RFuzz Simulation

**Files:**
- Modify: `src/myfuzz/integration/rfuzz_simulator.py`
- Modify: `src/myfuzz/composition/protocol_composer.py`
- Modify: `src/myfuzz/integration/rfuzz_live.py`
- Test: `tests/integration/test_rfuzz_simulator.py`
- Test: `tests/integration/test_rfuzz_live.py`
- Test: `tests/composition/test_protocol_composer.py`

**Interfaces:**
- Consumes: `ContractTransducerPlan`, rendered RTL, existing processor execution/backend plans.
- Produces: `build_simulator(..., contract_transducer=plan)` and artifacts whose hashes bind the header, cycle layout, constraint plan, RTL, and fixed controls.

- [ ] **Step 1: Write failing simulator-publication tests**

```python
artifact = build_simulator(
    plan, out, base_dir=root, coverage_ports=coverage,
    contract_transducer=transducer_plan,
)
assert (out / "contract_transducer.json").is_file()
assert (out / "contract_transducer.sv").is_file()
assert artifact.transport.raw_width == transducer_plan.cycle_layout.raw_width
assert not any(arg.startswith("+riscv_boot_image=") for arg in artifact.simulator_args)
```

- [ ] **Step 2: Run integration tests and confirm the keyword is unsupported**

Run: `python -m pytest tests/integration/test_rfuzz_simulator.py tests/integration/test_rfuzz_live.py -q`

Expected: FAIL because `build_simulator` lacks `contract_transducer`.

- [ ] **Step 3: Add the constrained-backend composition mode**

When a processor execution plan and contract transducer are present, expose `rfuzz_cycle_bits` and `test_begin` to the generated top, connect the transducer to `backend_target_*`, and omit address-decoded fixed memory/peripheral target drivers. Preserve the existing mode when no transducer is passed so unrelated generic composition tests remain compatible.

```python
def build_simulator(..., contract_transducer=None):
    cycle_layout = contract_transducer.cycle_layout if contract_transducer else legacy_layout
    transducer_source = render_transducer_rtl(contract_transducer) if contract_transducer else None
```

- [ ] **Step 4: Bind replay identity to complete transducer metadata**

```python
inputs = {
    "raw_sha256": _hash_bytes(raw_payload),
    "layout_hash": artifact.layout.layout_hash,
    "constraint_hash": artifact.projector.constraint_hash,
    "transducer_hash": artifact.transducer_hash,
    "header_hash": artifact.header_hash,
    "binary_sha256": binary_hash,
}
```

Reject corpus replay if any saved identity differs. Drive `test_begin` once per RFuzz test before reset and consume exactly one equal-width record per execution cycle.

- [ ] **Step 5: Run simulator, live transport, and composition regressions**

Run: `python -m pytest tests/integration/test_rfuzz_simulator.py tests/integration/test_rfuzz_live.py tests/composition/test_protocol_composer.py -q`

Expected: PASS in both legacy and constrained modes.

- [ ] **Step 6: Commit**

```bash
git add src/myfuzz/integration/rfuzz_simulator.py src/myfuzz/composition/protocol_composer.py src/myfuzz/integration/rfuzz_live.py tests/integration/test_rfuzz_simulator.py tests/integration/test_rfuzz_live.py tests/composition/test_protocol_composer.py
git commit -m "feat: drive live CPU inputs through contract transducer"
```

### Task 8: Replace the Real Ibex Example and Run Acceptance

**Files:**
- Modify: `src/myfuzz/integration/real_cpu_campaign.py`
- Modify: `examples/real_ibex_rfuzz/input/ibex-scratch.json`
- Modify: `examples/real_ibex_rfuzz/run_example.py`
- Modify: `examples/real_ibex_rfuzz/commands.sh`
- Modify: `examples/real_ibex_rfuzz/README.zh-CN.md`
- Modify: `examples/real_ibex_rfuzz/系统能力与工作原理.md`
- Modify: `examples/real_ibex_rfuzz/expected/bounded-result.json`
- Modify: `tests/examples/test_real_ibex_rfuzz_example.py`
- Test: `tests/integration/test_ibex_protocol_campaign_smoke.py`

**Interfaces:**
- Consumes: `compile_contract_transducer`, constrained `build_simulator`, live/replay APIs.
- Produces: a real Ibex example in which initial instructions, data responses, timing choices, interrupts, and debug inputs are RFuzz-derived.

- [ ] **Step 1: Write failing example-schema and no-boot-image assertions**

```python
config, _ = load_example(INPUT)
assert config["input_mode"] == "contract_transducer"
assert config["memory_domains"] == {
    "instruction_memory_master": "main",
    "data_memory_master": "main",
}
artifact, proof = build_candidate(ROOT, output, config, personality)
assert proof["instruction_source"] == "rfuzz_contract_transducer"
assert "boot_sha256" not in proof
```

- [ ] **Step 2: Run the example tests and confirm old schema/boot behavior fails**

Run: `python -m pytest tests/examples/test_real_ibex_rfuzz_example.py tests/integration/test_ibex_protocol_campaign_smoke.py -q`

Expected: FAIL because the current example requires `memory_module` and a boot image.

- [ ] **Step 3: Replace boot-memory construction with a compiled transducer**

```python
transducer = compile_contract_transducer(
    isa=isa,
    protocol=("processor-memory-beat", "1"),
    address_width=32,
    data_width=32,
    memory_domains=config["memory_domains"],
    external_fields=plan.layout.fields,
)
artifact = build_simulator(
    plan, output / "sim", base_dir=root,
    coverage_inputs=coverage_inputs,
    coverage_signals=coverage_signals,
    contract_transducer=transducer,
    simulator="verilator",
)
```

Remove `build_minimal_boot_image`, `+riscv_boot_image`, fixed first-fetch comparison, and the boot-memory component. Replace progress acceptance with observed instruction request/response, at least two distinct first-time instruction-address initializations, zero transducer/protocol errors, and deterministic replay.

- [ ] **Step 4: Update the standalone example and documentation**

Document the exact header, bit ranges, instruction selection/repair example, OBI handshake repair, repeated-address behavior, composition command, bounded test command, and replay command. Clearly state that every first-time instruction value comes from RFuzz and that the old fixed boot RAM path has been removed.

- [ ] **Step 5: Run focused Python regression**

Run: `python -m pytest tests/composition/test_constraint_ir.py tests/composition/test_cycle_input.py tests/isa/test_instruction_transducer.py tests/composition/test_coherent_memory.py tests/composition/test_protocol_transducer.py tests/composition/test_contract_transducer.py tests/composition/test_transducer_rtl.py tests/integration/test_constrained_backend_rtl.py tests/examples/test_real_ibex_rfuzz_example.py -q`

Expected: PASS.

- [ ] **Step 6: Run real compose and bounded official RFuzz acceptance**

Run:

```bash
python examples/real_ibex_rfuzz/run_example.py compose --input examples/real_ibex_rfuzz/input/ibex-scratch.json --output runs/examples/contract-rfuzz-compose
python examples/real_ibex_rfuzz/run_example.py test --input examples/real_ibex_rfuzz/input/ibex-scratch.json --client runs/rfuzz_client_native_build/release/rfuzz-client --output runs/examples/contract-rfuzz-5s --seconds 5
python examples/real_ibex_rfuzz/run_example.py inspect --output runs/examples/contract-rfuzz-5s
```

Expected: all commands exit 0; summary records nonzero tests, instruction requests/responses, new corpus entries when coverage is discovered, equal replay count, zero remaining shared-memory segments, and matching layout/constraint/transducer hashes.

- [ ] **Step 7: Run full regression and repository checks**

Run: `python -m pytest -q`

Expected: all non-environment-skipped tests PASS.

Run: `git diff --check`

Expected: no output.

- [ ] **Step 8: Commit**

```bash
git add src/myfuzz/integration/real_cpu_campaign.py examples/real_ibex_rfuzz tests/examples/test_real_ibex_rfuzz_example.py tests/integration/test_ibex_protocol_campaign_smoke.py
git commit -m "feat: run real Ibex from RFuzz-derived instructions"
```

### Task 9: Final Evidence, Documentation Consistency, and Push

**Files:**
- Modify: `examples/real_ibex_rfuzz/expected/bounded-result.json`
- Modify: `examples/real_ibex_rfuzz/README.zh-CN.md`
- Modify: `项目目标与后续任务交接.md`

**Interfaces:**
- Consumes: verified Task 8 output summaries and commit hashes.
- Produces: reproducible handoff and remote branch containing all implementation commits.

- [ ] **Step 1: Copy only measured acceptance values into documentation**

Record the actual layout, constraint, transducer, binary, input, and replay hashes plus test/corpus/protocol counters. Do not retain obsolete boot-image or interrupt-only claims.

- [ ] **Step 2: Verify documentation examples against CLI help**

Run: `python examples/real_ibex_rfuzz/run_example.py --help`

Expected: documented `compose`, `test`, and `inspect` commands exist.

- [ ] **Step 3: Run the final focused and full verification commands again**

Run: `python -m pytest tests/composition tests/isa tests/examples/test_real_ibex_rfuzz_example.py tests/integration/test_rfuzz_simulator.py tests/integration/test_rfuzz_live.py -q`

Expected: PASS except explicitly reported environment skips.

Run: `git diff --check && git status --short`

Expected: no whitespace errors; only intended tracked changes plus the preserved user-owned `.superpowers/sdd/task-2-report.md` and `third_party/` files.

- [ ] **Step 4: Commit documentation and push the current feature branch**

```bash
git add examples/real_ibex_rfuzz/expected/bounded-result.json examples/real_ibex_rfuzz/README.zh-CN.md 项目目标与后续任务交接.md
git commit -m "docs: record contract-transducer RFuzz acceptance"
git push origin feature/ibex-protocol-longrun
```

Expected: remote branch advances to the final documentation commit.
