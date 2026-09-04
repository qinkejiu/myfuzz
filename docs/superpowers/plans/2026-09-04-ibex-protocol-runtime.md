# Ibex Protocol Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add executable APB4, AXI4-Lite, and TileLink-UL single-beat runtime contracts, reference models, and synthesizable SystemVerilog bridges without breaking the existing abstract protocol bindings.

**Architecture:** Keep the current `ProtocolCatalog` as the declaration layer and add an explicit runtime compilation path. Each runtime bridge exposes a common one-request/one-response MMIO boundary and owns protocol-specific handshake state, while small target adapters connect that boundary to the existing component modules.

**Tech Stack:** Python 3 standard library, JSON plugin declarations, SystemVerilog-2012, Icarus Verilog for focused bridge tests, existing unittest suite.

## Global Constraints

- Runtime support is limited to APB4, AXI4-Lite, and TileLink-UL single-beat transfers.
- APB4, AXI4-Lite, and TileLink-UL response completion is bounded by 16 cycles.
- AXI4-Lite has at most one outstanding read and one outstanding write; bursts are rejected.
- TileLink-UL supports only `Get`, `PutFullData`, and `PutPartialData` with one source.
- Existing abstract protocol bindings remain valid when a newly declared field is marked `runtime_required` but not `required`.
- Bridges must keep address, data, mask, and VALID signals stable until the corresponding handshake.
- Error, denied, corrupt, unsupported-opcode, and timeout conditions become deterministic MMIO errors.
- No protocol bridge uses unbounded queues, dynamic allocation, waveform dumping, or random X propagation.

---

### Task 1: Extend protocol declarations with runtime requirements

**Files:**
- Modify: `src/myfuzz/protocols/model.py`
- Modify: `src/myfuzz/protocols/catalog.py`
- Modify: `src/myfuzz/protocols/compiler.py`
- Modify: `src/myfuzz/protocols/plugins/apb4.json`
- Modify: `src/myfuzz/protocols/plugins/axi4_lite.json`
- Modify: `src/myfuzz/protocols/plugins/tl_ul.json`
- Modify: `schemas/protocol.v1.schema.json`
- Test: `tests/protocols/test_protocol_catalog.py`

**Interfaces:**
- Add `FieldSpec.runtime_required: bool = False` and parse optional JSON key `runtime_required` with a default of `False`.
- Add `compile_runtime_protocol(binding, facts, catalog) -> CompiledProtocol` in `compiler.py`; it calls the existing compiler with runtime-required field enforcement.
- Preserve `compile_protocol(binding, facts, catalog)` behavior for abstract bindings.

- [ ] **Step 1: Write failing tests**

Add tests that assert the three runtime field sets and that an abstract APB4 binding without `pprot` still compiles while `compile_runtime_protocol` rejects it. Assert the new AXI response/strobe fields and TL param/size/source/mask/corrupt/denied/sink fields are present.

- [ ] **Step 2: Run focused tests and verify failure**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.protocols.test_protocol_catalog -v
```

Expected: failure because `FieldSpec` has no runtime metadata and the runtime compiler does not exist.

- [ ] **Step 3: Implement the declaration and compiler changes**

Use the following enforcement shape in `compiler.py`:

```python
def compile_protocol(binding, facts, catalog, *, require_runtime=False):
    ...
    required = field.required or (require_runtime and field.runtime_required)
    if required and missing_port:
        raise ProtocolCompilationError(...)
    ...

def compile_runtime_protocol(binding, facts, catalog):
    return compile_protocol(binding, facts, catalog, require_runtime=True)
```

Add `runtime_required` to the three plugin JSON files. APB4 adds `pprot`; AXI4-Lite adds `awprot`, `wstrb`, `bresp`, `arprot`, and `rresp`; TL-UL adds `a_param`, `a_size`, `a_source`, `a_mask`, `a_corrupt`, `d_param`, `d_size`, `d_source`, `d_sink`, `d_denied`, and `d_corrupt`. Keep legacy required fields unchanged. Extend the schema with a boolean `runtime_required` property for channel fields.

- [ ] **Step 4: Run focused and regression tests**

Run the focused command above and then:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -s tests
```

Expected: all existing tests pass and the new runtime tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/myfuzz/protocols schemas/protocol.v1.schema.json tests/protocols/test_protocol_catalog.py
git commit -m "feat: declare runtime protocol fields"
```

### Task 2: Add executable Python bridge models

**Files:**
- Create: `src/myfuzz/protocols/bridge.py`
- Modify: `src/myfuzz/protocols/__init__.py`
- Test: `tests/protocols/test_bridge_models.py`

**Interfaces:**
- `MmioRequest(address: int, write: bool, wdata: int = 0, byte_enable: int = 0xF)`.
- `MmioResponse(done: bool, rdata: int = 0, error: bool = False)`.
- `BridgeCycle(phase: str, protocol_fields: Mapping[str, int], target_valid: bool, target_request: MmioRequest | None, response: MmioResponse | None, error: str | None)`.
- `Apb4BridgeModel`, `Axi4LiteBridgeModel`, and `TileLinkUlBridgeModel` each expose `reset()` and `step(request=None, *, target_ready=True, target_rdata=0, target_error=False, response_ready=True) -> BridgeCycle`.
- Model constructors accept `address_width=32`, `data_width=32`, and `max_wait_cycles=16` and reject nonpositive widths or a wait bound outside `1..16`.

- [ ] **Step 1: Write failing model tests**

Cover APB setup/access/stable fields and response error, AXI independent AW/W handshakes plus held B/R responses, TL opcode/mask mapping and denied response, and the 16-cycle timeout. Assert all models return deterministic `error` text on invalid requests.

- [ ] **Step 2: Run the focused test and verify failure**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.protocols.test_bridge_models -v
```

Expected: module import failure.

- [ ] **Step 3: Implement the bounded state machines**

Use explicit enum-like string phases (`idle`, `setup`, `access`, `write_address`, `write_data`, `write_response`, `read_address`, `read_response`, `a_channel`, `d_channel`, `error`) and a cycle counter. Capture request fields once, never mutate captured fields while VALID is waiting, and clear state only after response-ready. Reject misaligned addresses and byte-enable masks wider than `data_width // 8`.

- [ ] **Step 4: Run focused tests and regression tests**

Run the focused model test followed by the full unittest discovery command. Expected: PASS with no changes to legacy protocol tests.

- [ ] **Step 5: Commit**

```bash
git add src/myfuzz/protocols/bridge.py src/myfuzz/protocols/__init__.py tests/protocols/test_bridge_models.py
git commit -m "feat: add bounded protocol bridge models"
```

### Task 3: Implement APB4 RTL bridge and target adapter

**Files:**
- Create: `src/myfuzz/protocols/rtl/apb4_mmio_bridge.sv`
- Create: `src/myfuzz/protocols/rtl/apb4_mmio_target.sv`
- Test: `tests/protocols/test_apb4_rtl.py`

**Interfaces:**
- `apb4_mmio_bridge` accepts `req_valid_i`, `req_write_i`, `req_addr_i`, `req_wdata_i`, `req_be_i`, and `rsp_ready_i`; it returns `req_ready_o`, `rsp_valid_o`, `rsp_rdata_o`, `rsp_error_o` and drives the complete APB4 master fields.
- `apb4_mmio_target` accepts complete APB4 slave fields and exposes the existing component contract `valid_o`, `write_o`, `addr_o`, `wdata_o`, `be_o`, `rdata_i`, `ready_i`, `error_i`.
- Both modules use `ADDRESS_WIDTH`, `DATA_WIDTH`, and `MAX_WAIT_CYCLES` parameters with defaults `32`, `32`, and `16`.

- [ ] **Step 1: Add a self-contained Icarus testbench test**

Compile a generated testbench that starts one read and one byte-masked write, holds `PREADY=0` for two cycles, checks setup then access sequencing, checks stable APB fields while waiting, and drives `PSLVERR=1` for a deterministic error response.

- [ ] **Step 2: Run the test and verify failure**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.protocols.test_apb4_rtl -v
```

Expected: missing RTL source or failed compilation.

- [ ] **Step 3: Implement the two modules**

Use a three-state bridge (`IDLE`, `SETUP`, `ACCESS`) and a bounded wait counter. The target asserts `PREADY` only when the component is ready; it forwards `PSTRB` as byte enables and maps `PSLVERR` from `error_i`. Hold all request signals through ACCESS and clear the response only after `rsp_ready_i`.

- [ ] **Step 4: Run the Icarus test and full regression**

Run the focused test and `python3 -m unittest discover -s tests`. Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/myfuzz/protocols/rtl/apb4_mmio_bridge.sv src/myfuzz/protocols/rtl/apb4_mmio_target.sv tests/protocols/test_apb4_rtl.py
git commit -m "feat: add APB4 MMIO bridge"
```

### Task 4: Implement AXI4-Lite RTL bridge and target adapter

**Files:**
- Create: `src/myfuzz/protocols/rtl/axi4_lite_mmio_bridge.sv`
- Create: `src/myfuzz/protocols/rtl/axi4_lite_mmio_target.sv`
- Test: `tests/protocols/test_axi4_lite_rtl.py`

**Interfaces:**
- The master bridge exposes all AXI4-Lite fields named in the design document and the same native request/response boundary as Task 3.
- The target adapter accepts complete AXI4-Lite slave channels and drives the unified component contract.

- [ ] **Step 1: Write the failing Icarus test**

Exercise a write where AW and W arrive on different cycles, hold both VALID payloads until READY, delay BVALID while BREADY is low, then exercise a read with delayed RREADY and an error `BRESP/RRESP`.

- [ ] **Step 2: Run the focused test and verify failure**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.protocols.test_axi4_lite_rtl -v
```

Expected: missing RTL source or failed compilation.

- [ ] **Step 3: Implement bounded independent read/write state**

Capture AW and W independently, accept at most one of each, submit one unified write only after both are present, and hold BVALID/BRESP until BREADY. Do the analogous AR/R path. Reject burst-only fields by keeping the module interface Lite-only. Map `WSTRB` to component byte enables and use `2'b10` as the deterministic slave-error response.

- [ ] **Step 4: Run focused and regression tests**

Expected: the focused handshake test and the complete unittest suite pass.

- [ ] **Step 5: Commit**

```bash
git add src/myfuzz/protocols/rtl/axi4_lite_mmio_bridge.sv src/myfuzz/protocols/rtl/axi4_lite_mmio_target.sv tests/protocols/test_axi4_lite_rtl.py
git commit -m "feat: add AXI4-Lite MMIO bridge"
```

### Task 5: Implement TileLink-UL RTL bridge and target adapter

**Files:**
- Create: `src/myfuzz/protocols/rtl/tl_ul_mmio_bridge.sv`
- Create: `src/myfuzz/protocols/rtl/tl_ul_mmio_target.sv`
- Test: `tests/protocols/test_tl_ul_rtl.py`

**Interfaces:**
- The master bridge exposes complete single-beat A and D channels with `opcode`, `param`, `size`, `source`, `address`, `mask`, `data`, `corrupt`, `denied`, and `sink` fields.
- The target adapter exposes the common component contract and returns `d_denied`/`d_corrupt` on invalid or errored requests.

- [ ] **Step 1: Write the failing Icarus test**

Exercise `Get`, `PutFullData`, and `PutPartialData`, assert byte mask preservation, hold A payload through A handshake, hold D payload until DREADY, and check unsupported opcode and target error mapping.

- [ ] **Step 2: Run the focused test and verify failure**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.protocols.test_tl_ul_rtl -v
```

Expected: missing RTL source or failed compilation.

- [ ] **Step 3: Implement one-source bounded A/D state**

Accept one A request only in IDLE, validate opcode and `size <= $clog2(DATA_WIDTH/8)`, forward A mask as byte enables, and emit exactly one D response after the target response. Set `denied` for target errors and `corrupt` for malformed input; use deterministic zero data on error.

- [ ] **Step 4: Run focused and regression tests**

Expected: focused TL tests and the complete unittest suite pass.

- [ ] **Step 5: Commit**

```bash
git add src/myfuzz/protocols/rtl/tl_ul_mmio_bridge.sv src/myfuzz/protocols/rtl/tl_ul_mmio_target.sv tests/protocols/test_tl_ul_rtl.py
git commit -m "feat: add TileLink UL MMIO bridge"
```

### Task 6: Publish the runtime bridge API and static checks

**Files:**
- Modify: `src/myfuzz/protocols/__init__.py`
- Create: `tests/protocols/test_runtime_protocol_api.py`
- Create: `src/myfuzz/protocols/rtl/README.md`

- [ ] **Step 1: Write failing import and source inventory tests**

Assert all three model classes, `compile_runtime_protocol`, and six RTL source files import or exist, and that every module contains `MAX_WAIT_CYCLES` and no `$random`.

- [ ] **Step 2: Implement exports and documented source inventory**

Export the public model dataclasses/classes and runtime compiler. Document the native MMIO boundary and the exact protocol limitations in the RTL README.

- [ ] **Step 3: Run all runtime tests**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -s tests/protocols
```

Expected: all protocol tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/myfuzz/protocols tests/protocols
git commit -m "docs: publish runtime protocol bridge API"
```
