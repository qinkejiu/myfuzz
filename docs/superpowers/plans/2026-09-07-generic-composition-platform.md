# Generic Source-Annotated Composition Platform Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the fixed Ibex-plus-peripherals path with a generic, source-annotated composition pipeline that supports multiple CPU designs, multiple protocol families, dependency-aware peripherals, and generated RFuzz input layouts.

**Architecture:** The input manifest supplies endpoint purpose and source-location information. A low-resource source crawler verifies a pinned local checkout or content revision, extracts HDL declarations and observable timing, and annotates the supplied endpoint semantics with exact modules, ports, widths, directions, clock/reset domains, and evidence. A protocol/capability matcher then selects legal adapter paths and components; a renderer consumes only the resulting intermediate representation and emits the top-level HDL, source list, and generated RFuzz layout. CPU identifiers select declarative ISA metadata only and never select renderer branches.

**Tech Stack:** Python 3 standard library, JSON contract documents, deterministic SHA-256 canonicalization, existing Verilator frontend facts, SystemVerilog-2012, existing RFuzz/harness ABI, and serialized low-resource builds.

## Global Constraints

- Input interface descriptions provide endpoint function, requiredness, hierarchy/source hints, aliases, and optional protocol expectations; HDL analysis provides physical direction, width, signedness, clock/reset membership, and observable handshake timing.
- A source locator must contain a reproducible pin: a verified Git commit/tag or a verified `sha256:` source-tree content digest. Source paths and include paths must remain inside the declared source root.
- Explicit endpoint purpose is authoritative; HDL declarations are authoritative for physical field facts; source documentation corroborates; structural protocol analysis validates; naming heuristics are last-resort evidence and cannot resolve an ambiguous required endpoint alone.
- Required endpoints fail closed when they are missing, ambiguous, direction-inverted, width-incompatible, protocol-inconsistent, or contradicted by the selected source revision.
- No production renderer, adapter selector, input mapper, or top-level template may branch on a CPU name. CPU profiles contain data and ISA contracts only.
- Canonical documents are path-independent and deterministic. The same semantic input, source content, catalogs, and tool revision produce identical hashes and field ordering.
- Existing Ibex v1 composition and fixed 395-bit harness remain available as a compatibility path until the generated layout path has a passing migration test.
- New tests use one Python/build worker by default, avoid network access, avoid waveforms, and do not require RFuzz binaries when testing analysis and generation.
- Runtime adapters must declare supported protocol features, widths, ordering, and temporal projections. Unsupported burst, ID, ordering, or latency projections are rejected rather than silently reduced.

---

## File Map

The first four tasks establish the generic contract and a testable vertical slice. Tasks 5–8 connect that slice to composition, protocol RTL, CPU profiles, peripheral profiles, and low-resource smoke tests.

```text
Create:  schemas/interface_description.v1.schema.json
Create:  schemas/interface_annotations.v1.schema.json
Modify:  src/myfuzz/contracts/validation.py
Create:  src/myfuzz/composition/interface_description.py
Create:  src/myfuzz/composition/source_crawler.py
Create:  src/myfuzz/composition/endpoint_capabilities.py
Create:  src/myfuzz/composition/input_layout.py
Modify:  src/myfuzz/composition/__init__.py
Modify:  src/myfuzz/isa/model.py
Create:  src/myfuzz/isa/constraints.py
Modify:  src/myfuzz/isa/__init__.py
Modify:  src/myfuzz/composition/auto.py
Modify:  src/myfuzz/composition/protocol_manifest.py
Modify:  src/myfuzz/composition/protocol_composer.py
Modify:  scripts/generate_composition.py
Modify:  src/myfuzz/protocols/catalog.py
Create:  src/myfuzz/protocols/plugins/axi4.json
Create:  src/myfuzz/protocols/plugins/wishbone.json
Create:  src/myfuzz/protocols/rtl/apb3_mmio_bridge.sv
Create:  src/myfuzz/protocols/rtl/obi_mmio_bridge.sv
Create:  src/myfuzz/protocols/rtl/wishbone_mmio_bridge.sv
Create:  src/myfuzz/protocols/rtl/axi4_mmio_bridge.sv
Create:  configs/cpus/cva6/interface_description.json
Create:  configs/cpus/boom/interface_description.json
Create:  configs/cpus/cva6/README.md
Create:  configs/cpus/boom/README.md
Modify:  src/myfuzz/isa/profiles/cva6.json
Modify:  src/myfuzz/isa/profiles/boom.json
Modify:  src/myfuzz/components/model.py
Modify:  src/myfuzz/components/catalog.py
Modify:  src/myfuzz/components/profiles/clint.json
Modify:  src/myfuzz/components/profiles/plic.json
Modify:  src/myfuzz/components/profiles/pwm.json
Modify:  src/myfuzz/components/profiles/i2c.json
Modify:  src/myfuzz/components/profiles/dma.json
Create:  tests/contracts/test_interface_contracts.py
Create:  tests/composition/test_interface_description.py
Create:  tests/composition/test_source_crawler.py
Create:  tests/composition/test_endpoint_capabilities.py
Create:  tests/composition/test_input_layout.py
Create:  tests/composition/test_generic_auto.py
Create:  tests/isa/test_instruction_constraints.py
Create:  tests/protocols/test_additional_protocol_catalog.py
Create:  tests/protocols/test_additional_protocol_rtl.py
Create:  tests/integration/test_generic_composition.py
Create:  tests/integration/test_cpu_profile_interfaces.py
Create:  tests/integration/test_low_resource_generic_smoke.py
```

## Task 1: Define semantic interface and source-locator contracts

**Files:**
- Create: `schemas/interface_description.v1.schema.json`
- Modify: `src/myfuzz/contracts/validation.py`
- Create: `src/myfuzz/composition/interface_description.py`
- Modify: `src/myfuzz/composition/__init__.py`
- Test: `tests/contracts/test_interface_contracts.py`
- Test: `tests/composition/test_interface_description.py`

**Interfaces:**

```python
@dataclass(frozen=True, slots=True)
class SourceLocator:
    source_root: str
    revision: str
    top_module: str
    files: tuple[str, ...] = ()
    filelist: str | None = None
    include_roots: tuple[str, ...] = ()

@dataclass(frozen=True, slots=True)
class FieldHint:
    role: str
    aliases: tuple[str, ...] = ()
    required: bool = True

@dataclass(frozen=True, slots=True)
class EndpointDescription:
    endpoint_id: str
    function: str
    required: bool = True
    module: str | None = None
    hierarchy: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    protocol: tuple[str, str] | None = None
    fields: tuple[FieldHint, ...] = ()

@dataclass(frozen=True, slots=True)
class InterfaceDescription:
    source: SourceLocator
    endpoints: tuple[EndpointDescription, ...]

def load_interface_description(document_or_path: object) -> InterfaceDescription: ...
def interface_description_document(value: InterfaceDescription) -> dict[str, object]: ...
```

The input schema contains semantic endpoint roles and field roles/aliases. It does not require `direction`, `width`, `signed`, or timing fields. `validate_contract` accepts `interface_description.v1` and rejects missing source pins, duplicate endpoint/field roles, invalid paths, and empty functions while accepting unknown forward-compatible members.

- [ ] **Step 1: Write the failing contract and model tests.**

```python
def test_direction_width_and_timing_are_not_required_in_input(self) -> None:
    document = {
        "schema_version": "interface_description.v1",
        "source": {
            "root": "third_party/cpu",
            "revision": "sha256:" + "a" * 64,
            "top_module": "cpu_top",
        },
        "endpoints": [{
            "endpoint_id": "cpu.memory_master",
            "function": "memory_master",
            "fields": [{"role": "address", "aliases": ["opaque_addr"]}],
        }],
    }
    validate_contract(document, "interface_description.v1")
    value = load_interface_description(document)
    self.assertEqual(value.endpoints[0].fields[0].role, "address")

def test_missing_revision_is_rejected(self) -> None:
    document = valid_interface_document()
    del document["source"]["revision"]
    with self.assertRaisesRegex(ContractError, "interface_description.v1:source:revision:missing"):
        validate_contract(document, "interface_description.v1")
```

- [ ] **Step 2: Run the focused tests and verify the failure.**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.contracts.test_interface_contracts tests.composition.test_interface_description -v
```

Expected: FAIL because `interface_description.v1` is not registered and the typed loader does not exist.

- [ ] **Step 3: Implement the contract registration and typed loader.**

Register the two new schemas in `contracts.validation._SCHEMAS`. Validate the source object, endpoint IDs, field roles, aliases, optional protocol pairs, and relative path strings. Keep paths as input strings in the document; resolve them only at source-crawl time. The loader returns immutable tuples and sorts neither endpoints nor fields until canonical serialization, preserving semantic input order for diagnostics.

- [ ] **Step 4: Run focused and existing contract tests.**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.contracts.test_interface_contracts tests.composition.test_interface_description tests.contracts.test_contracts -v
```

Expected: all focused tests pass, all pre-existing contract tests pass, and no existing schema accepts an invalid new document by accident.

- [ ] **Step 5: Commit.**

```bash
git add schemas/interface_description.v1.schema.json src/myfuzz/contracts/validation.py src/myfuzz/composition/interface_description.py src/myfuzz/composition/__init__.py tests/contracts/test_interface_contracts.py tests/composition/test_interface_description.py
git commit -m "feat: add semantic interface description contract"
```

## Task 2: Crawl pinned HDL and emit source-backed interface annotations

**Files:**
- Create: `schemas/interface_annotations.v1.schema.json`
- Modify: `src/myfuzz/contracts/validation.py`
- Create: `src/myfuzz/composition/source_crawler.py`
- Modify: `src/myfuzz/composition/__init__.py`
- Test: `tests/composition/test_source_crawler.py`

**Interfaces:**

```python
@dataclass(frozen=True, slots=True)
class SourcePortFact:
    module: str
    name: str
    direction: str
    width: int
    signed: bool
    source_file: str
    line: int
    column: int

@dataclass(frozen=True, slots=True)
class TimingObservation:
    kind: str
    fields: tuple[str, ...]
    clock: str | None
    source_file: str
    line: int

@dataclass(frozen=True, slots=True)
class SourceSnapshot:
    revision: str
    content_hash: str
    files: tuple[str, ...]
    modules: tuple[str, ...]
    ports: tuple[SourcePortFact, ...]
    timing: tuple[TimingObservation, ...]

def source_tree_hash(root: Path, files: Sequence[Path]) -> str: ...

class SourceCrawler:
    def crawl(self, locator: SourceLocator, *, base_dir: Path) -> SourceSnapshot: ...
    def annotate(
        self,
        snapshot: SourceSnapshot,
        description: InterfaceDescription,
        *,
        protocol_catalog: ProtocolCatalog | None = None,
    ) -> dict[str, object]: ...

def annotate_interfaces(
    description: InterfaceDescription,
    *,
    base_dir: Path,
    protocol_catalog: ProtocolCatalog | None = None,
) -> dict[str, object]: ...
```

`crawl` expands only declared files/filelists, rejects paths outside `source_root`, verifies `git:<full-commit>` against the checkout or `sha256:<tree-digest>` against `source_tree_hash`, and parses ANSI/non-ANSI module declarations with the existing source-only parser helpers extended for repeated declarations and signed ports. It extracts direction and width from HDL declarations. It scans clocked/combinational assignments and handshake conditions to emit observable facts such as `sequential_assignment`, `transfer_accept`, `stall_holds_payload`, and `response_after_request`.

`annotate` maps endpoint and field semantics using explicit aliases, source documentation tags, exact role labels, and finally unique name evidence. A required endpoint or field with zero or multiple candidates fails closed. The output contains exact source file/module/port locations, derived direction/width/signedness, timing observations, protocol candidates, evidence kinds, confidence, and diagnostics. It never contains a renderer choice.

- [ ] **Step 1: Write failing synthetic HDL tests.**

Use arbitrary signal names so a CPU-specific name table cannot satisfy the test:

```systemverilog
module opaque_tile(
  input  logic clk_x,
  input  logic rst_x,
  output logic [31:0] q_addr,
  output logic q_valid,
  input  logic q_ready,
  output logic [31:0] q_wdata,
  input logic [31:0] q_rdata
);
  always_ff @(posedge clk_x) begin
    if (q_valid && !q_ready) q_wdata <= q_wdata;
  end
endmodule
```

Test that an input description naming `memory_master` and aliases `q_addr/q_valid/q_ready/q_wdata/q_rdata` yields HDL-derived directions and widths, a clock association, and a stall observation. Add tests for a content-hash pin, a missing alias, an ambiguous alias, an unsafe `../` file, and a source/input semantic conflict.

- [ ] **Step 2: Run focused tests and verify the failure.**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.composition.test_source_crawler -v
```

Expected: FAIL because `source_crawler` and `interface_annotations.v1` do not exist.

- [ ] **Step 3: Implement safe source materialization and deterministic hashing.**

Implement `source_tree_hash` over sorted relative path bytes followed by file content bytes. Accept only the two pin formats. Use `subprocess.run(["git", "-C", root, "rev-parse", "--verify", f"{revision}^{{commit}}"])` for Git pins and compare the declared digest for content pins. Do not run clone/fetch from the library; remote acquisition is a separate caller operation that must materialize a pinned checkout before calling the crawler.

- [ ] **Step 4: Implement declaration and timing extraction.**

Reuse comment/string masking and balanced delimiter helpers from `source_only_frontend.py`; extend the port parser so every declared name in a comma group is emitted with the declaration width and signedness. Record one-based line/column locations. Derive sequential signals from `always_ff` and `always @(posedge/negedge ...)` assignments. Derive handshake observations from mapped signal expressions and retain source locations; do not claim a latency bound when the RTL does not expose one.

- [ ] **Step 5: Implement annotation matching and contract serialization.**

Resolve the endpoint module from `endpoint.module`, otherwise `source.top_module`; resolve each field by aliases, source documentation tags of the form `myfuzz: endpoint=<id> field=<role>`, exact semantic labels, then a unique normalized-name candidate. Reject unresolved required members and contradictory declared protocol fingerprints. Emit `interface_annotations.v1` and call `validate_contract` before returning.

- [ ] **Step 6: Run focused, contract, and deterministic-path tests.**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.composition.test_source_crawler tests.contracts.test_interface_contracts tests.contracts.test_contracts -v
```

Expected: all focused tests pass; moving the fixture directory changes no content hash; changing a source byte changes the content hash and invalidates the old content pin.

- [ ] **Step 7: Commit.**

```bash
git add schemas/interface_annotations.v1.schema.json src/myfuzz/contracts/validation.py src/myfuzz/composition/source_crawler.py src/myfuzz/composition/__init__.py tests/composition/test_source_crawler.py
git commit -m "feat: crawl HDL into source-backed interface annotations"
```

## Task 3: Normalize endpoint capabilities and perform generic protocol matching

**Files:**
- Create: `src/myfuzz/composition/endpoint_capabilities.py`
- Modify: `src/myfuzz/composition/constraints.py`
- Modify: `src/myfuzz/composition/ir.py`
- Modify: `src/myfuzz/composition/__init__.py`
- Test: `tests/composition/test_endpoint_capabilities.py`

**Interfaces:**

```python
@dataclass(frozen=True, slots=True)
class EndpointFieldFact:
    role: str
    port: str
    direction: str
    width: int
    signed: bool

@dataclass(frozen=True, slots=True)
class EndpointCapability:
    endpoint_id: str
    function: str
    side: str
    protocol: tuple[str, str] | None
    fields: tuple[EndpointFieldFact, ...]
    clock: str | None
    reset: str | None
    timing: tuple[Mapping[str, object], ...]

@dataclass(frozen=True, slots=True)
class AdapterCapability:
    adapter_id: str
    source_protocol: tuple[str, str]
    target_protocol: tuple[str, str]
    features: tuple[str, ...]
    max_latency: int | None
    allows_width_projection: bool

def normalize_annotations(document: Mapping[str, object]) -> tuple[EndpointCapability, ...]: ...
def validate_protocol_fingerprint(endpoint: EndpointCapability, protocol: CompiledProtocol) -> tuple[str, ...]: ...
def match_endpoint_pair(source: EndpointCapability, target: EndpointCapability, adapters: Sequence[AdapterCapability]) -> tuple[dict[str, object], ...]: ...
```

Direction is translated relative to endpoint side (`output` from an initiator is host-to-device; `input` from a target is host-to-device). Matching checks protocol version, required fields, direction, exact or declared width projection, clock/reset domain, and observed temporal relations. All rejected alternatives are retained with a reason and source evidence. Extend the existing constraint graph without changing the behavior of legacy `DeclarationSet` callers.

- [ ] **Step 1: Write failing arbitrary-name matching tests.**

Create two annotations whose source ports are named `left_17` and `right_42`, but whose input roles are `address`, `valid`, `ready`, and `data`. Verify a compatible protocol produces one candidate independent of identifier names. Verify a target direction inversion, a width mismatch without an adapter, an unsupported AXI burst feature, and different clock domains produce no candidates with explicit reasons.

- [ ] **Step 2: Run focused tests and verify the failure.**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.composition.test_endpoint_capabilities -v
```

Expected: FAIL because the normalized endpoint capability API is not present.

- [ ] **Step 3: Implement normalization and protocol fingerprint validation.**

Use `ProtocolCatalog.require` and the existing compiled field rules. Treat a protocol expectation in the input as a constraint; when absent, retain structurally validated candidates and reject only ambiguity at generation time. Convert source-backed annotation records to immutable capabilities without exposing identifier names to ranking.

- [ ] **Step 4: Implement candidate matching and IR evidence.**

Add capability records and rejected reasons to the path-free IR serializer. Rank exact protocol matches, complete evidence, fewer adapters, fewer width projections, and lower uncertainty in that order. Keep old candidate-search IDs and hashes stable for documents that do not contain the new annotation section.

- [ ] **Step 5: Run focused and legacy composition tests.**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.composition.test_endpoint_capabilities tests.composition.test_constraints tests.composition.test_ir tests.integration.test_name_firewall -v
```

Expected: all new tests and all listed legacy tests pass.

- [ ] **Step 6: Commit.**

```bash
git add src/myfuzz/composition/endpoint_capabilities.py src/myfuzz/composition/constraints.py src/myfuzz/composition/ir.py src/myfuzz/composition/__init__.py tests/composition/test_endpoint_capabilities.py
git commit -m "feat: match source-backed endpoint capabilities generically"
```

## Task 4: Generate generic RFuzz input layouts and separate RISC-V ISA constraints

**Files:**
- Create: `src/myfuzz/composition/input_layout.py`
- Create: `src/myfuzz/isa/constraints.py`
- Modify: `src/myfuzz/isa/model.py`
- Modify: `src/myfuzz/isa/__init__.py`
- Test: `tests/composition/test_input_layout.py`
- Test: `tests/isa/test_instruction_constraints.py`

**Interfaces:**

```python
@dataclass(frozen=True, slots=True)
class LayoutField:
    field_id: str
    owner: str
    role: str
    width: int
    raw_lo: int
    raw_hi: int
    encoding: str
    constraint: Mapping[str, object]
    dependency_group: str | None = None

@dataclass(frozen=True, slots=True)
class InputLayout:
    schema_version: str
    raw_width: int
    fields: tuple[LayoutField, ...]
    layout_hash: str

def build_input_layout(
    annotations: Mapping[str, object],
    *,
    component_constraints: Sequence[Mapping[str, object]] = (),
    isa: IsaContract | None = None,
) -> InputLayout: ...
def input_layout_document(layout: InputLayout) -> dict[str, object]: ...

@dataclass(frozen=True, slots=True)
class IsaContract:
    xlen: int
    extensions: tuple[str, ...]
    privilege_modes: tuple[str, ...] = ("M",)
    instruction_alignment: int = 4

class RiscvInstructionProvider:
    def __init__(self, contract: IsaContract): ...
    def constrain_word(self, value: int, *, compressed: bool = False) -> int: ...
    def is_legal_word(self, value: int, *, compressed: bool = False) -> bool: ...
```

The layout collects input-capable annotated ports, protocol projections, component constraints, and optional instruction fields. It packs fields in stable semantic order, emits the generated raw width, and can be converted to the existing `RawBitAbi`. It must not assume 395 bits. The ISA provider consumes XLEN/extensions/alignment and validates opcode/funct/register encodings independently of bus protocol. RV32IMC, RV64IMAFDC, and raw-instruction fallback are separate explicit modes.

- [ ] **Step 1: Write failing layout and ISA tests.**

Verify two semantically equal annotation documents with different JSON ordering produce equal layout hashes. Verify an APB address receives a 4-byte alignment constraint, a 64-bit address changes `raw_width`, and a missing optional field does not shift required field IDs unexpectedly. Verify `RiscvInstructionProvider(IsaContract(32, ("I",)))` accepts a legal `ADDI`, rejects an `MUL`, and `RV64IMAFDC` accepts the same extension family at XLEN 64. Verify no ISA provider is invoked for a non-instruction field.

- [ ] **Step 2: Run focused tests and verify the failure.**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.composition.test_input_layout tests.isa.test_instruction_constraints -v
```

Expected: FAIL because generated layout and ISA provider APIs do not exist.

- [ ] **Step 3: Implement deterministic layout packing and constraint projections.**

Represent bit ranges as contiguous, non-overlapping `[raw_lo, raw_hi]` intervals. Apply protocol alignment, byte-enable width, valid/ready gating, peripheral address ranges, and dependency groups before packing. Reject invalid widths, unbounded expressions, and contradictory projections. Use `myfuzz.contracts.canonical_bytes` for `layout_hash`.

- [ ] **Step 4: Implement the ISA contract and legal-word validator.**

Support the base `I` encoding plus `M` and `C` in the first provider. Decode opcode and funct fields, check XLEN-dependent legality, extension availability, and instruction alignment. Preserve raw bytes for unsupported extensions but mark the layout mode `raw_instruction` instead of claiming ISA legality.

- [ ] **Step 5: Run focused, harness, and regression tests.**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.composition.test_input_layout tests.isa.test_instruction_constraints tests.harness.test_compiler tests.harness.test_projection -v
```

Expected: all new tests pass and existing fixed-layout harness tests remain green.

- [ ] **Step 6: Commit.**

```bash
git add src/myfuzz/composition/input_layout.py src/myfuzz/isa/constraints.py src/myfuzz/isa/model.py src/myfuzz/isa/__init__.py tests/composition/test_input_layout.py tests/isa/test_instruction_constraints.py
git commit -m "feat: generate generic input layouts with ISA constraints"
```

## Task 5: Route generic annotations through auto-composition and top-level generation

**Files:**
- Modify: `src/myfuzz/composition/auto.py`
- Modify: `src/myfuzz/composition/protocol_manifest.py`
- Modify: `src/myfuzz/composition/protocol_composer.py`
- Modify: `scripts/generate_composition.py`
- Create: `tests/composition/test_generic_auto.py`
- Create: `tests/integration/test_generic_composition.py`

**Interfaces:**

```python
@dataclass(frozen=True, slots=True)
class GenericCompositionRequest:
    interface_description: InterfaceDescription
    component_types: tuple[str, ...]
    protocol_preferences: tuple[tuple[str, str], ...] = ()
    isa: IsaContract | None = None
    seed: int = 7

def plan_generic_composition(
    request: GenericCompositionRequest,
    *,
    base_dir: Path,
    component_catalog: ComponentCatalog | None = None,
    protocol_catalog: ProtocolCatalog | None = None,
) -> GenericCompositionPlan: ...

def write_generic_composition(
    plan: GenericCompositionPlan,
    output_dir: Path,
    *,
    base_dir: Path,
) -> dict[str, object]: ...
```

Keep `plan_auto_composition` and the legacy Ibex manifest behavior intact. Add a generic branch selected by the presence of `interface_description`, not by `cpu_id`. Remove the generic path's assumptions corresponding to `_RUNTIME_ADAPTERS`, `_MANIFEST_COMPONENT_TYPES`, fixed 32-bit widths, fixed top module text, and fixed input slices. The renderer takes source-backed annotations, endpoint capabilities, selected adapters, generated address/IRQ records, and `InputLayout` from the plan. Generated top-level ports use opaque stable identifiers while source bindings retain exact source locations in evidence.

- [ ] **Step 1: Write failing generic composition tests.**

Use two synthetic CPU modules with different names and the same semantic manifest. Assert both produce a top-level module, source list, IR, and generated layout; assert changing the module/signal names changes source evidence but does not require a CPU-specific branch. Assert the same request produces byte-identical IR/layout hashes in two output directories and that a missing annotation prevents any output publication.

- [ ] **Step 2: Run focused tests and verify the failure.**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.composition.test_generic_auto tests.integration.test_generic_composition -v
```

Expected: FAIL because the generic request/planner/writer path is not exposed.

- [ ] **Step 3: Implement request dispatch and source-backed planning.**

Load the interface description, crawl and annotate the pinned source, normalize capabilities, select component profiles and adapter paths, allocate aligned non-overlapping address regions and IRQs, and record every rejected candidate in diagnostics. Publish only after annotation, IR, source-list, top-level parse, and layout validation succeed.

- [ ] **Step 4: Implement generic top and source-list rendering.**

Render instances and connections from IR records. Port declarations are generated from HDL-derived widths and directions; no string match against `cpu_id` is allowed. Include only selected CPU files, peripheral files, adapter files, and generated files. Validate all paths against the source roots and invoke the existing frontend/lint boundary when configured.

- [ ] **Step 5: Add CLI and preserve legacy behavior.**

Add `scripts/generate_composition.py --interface-description <path> --out-dir <path> --base-dir <path>`. Keep `--protocol-manifest` and existing candidate-search modes unchanged. Return `schema_version`, `interface_annotation_hash`, `composition_ir_hash`, `layout_hash`, `top_path`, `source_list_path`, and `complete` in the generic summary.

- [ ] **Step 6: Run focused and full Python composition regression.**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.composition.test_generic_auto tests.integration.test_generic_composition tests.composition.test_auto tests.composition.test_protocol_manifest tests.composition.test_protocol_composer -v
```

Expected: all listed tests pass; existing legacy Ibex outputs are unchanged byte-for-byte.

- [ ] **Step 7: Commit.**

```bash
git add src/myfuzz/composition/auto.py src/myfuzz/composition/protocol_manifest.py src/myfuzz/composition/protocol_composer.py scripts/generate_composition.py tests/composition/test_generic_auto.py tests/integration/test_generic_composition.py
git commit -m "feat: route source annotations through generic composition"
```

## Task 6: Add protocol definitions and runtime adapters beyond the current three

**Files:**
- Modify: `src/myfuzz/protocols/catalog.py`
- Create: `src/myfuzz/protocols/plugins/axi4.json`
- Create: `src/myfuzz/protocols/plugins/wishbone.json`
- Create: `src/myfuzz/protocols/rtl/apb3_mmio_bridge.sv`
- Create: `src/myfuzz/protocols/rtl/obi_mmio_bridge.sv`
- Create: `src/myfuzz/protocols/rtl/wishbone_mmio_bridge.sv`
- Create: `src/myfuzz/protocols/rtl/axi4_mmio_bridge.sv`
- Test: `tests/protocols/test_additional_protocol_catalog.py`
- Test: `tests/protocols/test_additional_protocol_rtl.py`

**Interfaces:**

Add catalog entries for `axi4@1` and `wishbone@classic`; retain `apb@3`, `apb@4`, `axi4-lite@1`, `tl-ul@1`, `obi@1`, and `ready-valid-mmio@1`. Each definition lists fields, channel relations, temporal rules, projection actions, legal adapters, and capability limits. Each RTL bridge exposes a canonical request/response boundary with explicit `ADDRESS_WIDTH`, `DATA_WIDTH`, and `MAX_WAIT_CYCLES` parameters.

- [ ] **Step 1: Write failing catalog and lint tests.**

Assert all eight protocol families load, required fields have correct direction/width expressions, unsupported burst/ID projections are rejected, and each new bridge has a wrapper fixture that can be linted when `verilator` is available.

- [ ] **Step 2: Run focused tests and verify the failure.**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.protocols.test_additional_protocol_catalog tests.protocols.test_additional_protocol_rtl -v
```

Expected: catalog tests fail for missing `axi4`/`wishbone`; RTL tests report missing bridge files before implementation.

- [ ] **Step 3: Add exact protocol documents.**

Define AXI4 read/write channels, IDs, burst length/size/type, response, and ordering capability. Define Wishbone Classic cycle/strobe/write/address/data/select/ack/err/stall behavior. Keep field IDs stable and use the existing protocol compiler for width expressions.

- [ ] **Step 4: Implement minimal safe bridges.**

Implement single-beat canonical projections first. AXI4 bridge accepts only `AWLEN=0`/`ARLEN=0` unless a declared splitter is instantiated; Wishbone bridge holds `CYC/STB` until `ACK/ERR`; OBI bridge preserves request/grant/response; APB3 bridge omits APB4-only protection/strobe fields. Include deterministic timeout/error responses and no unbounded wait state.

- [ ] **Step 5: Run catalog, RTL, and model tests.**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.protocols.test_additional_protocol_catalog tests.protocols.test_additional_protocol_rtl tests.protocols.test_protocol_catalog tests.protocols.test_bridge_models -v
```

Expected: all protocol tests pass; RTL tests skip only when Verilator is unavailable and otherwise lint/execute their directed handshake cases.

- [ ] **Step 6: Commit.**

```bash
git add src/myfuzz/protocols/catalog.py src/myfuzz/protocols/plugins/axi4.json src/myfuzz/protocols/plugins/wishbone.json src/myfuzz/protocols/rtl tests/protocols/test_additional_protocol_catalog.py tests/protocols/test_additional_protocol_rtl.py
git commit -m "feat: add AXI4 Wishbone and additional runtime adapters"
```

## Task 7: Register CVA6/BOOM and reusable peripheral capabilities without CPU-specific branches

**Files:**
- Create: `configs/cpus/cva6/interface_description.json`
- Create: `configs/cpus/boom/interface_description.json`
- Create: `configs/cpus/cva6/README.md`
- Create: `configs/cpus/boom/README.md`
- Modify: `src/myfuzz/isa/profiles/cva6.json`
- Modify: `src/myfuzz/isa/profiles/boom.json`
- Modify: `src/myfuzz/components/model.py`
- Modify: `src/myfuzz/components/catalog.py`
- Create: `src/myfuzz/components/profiles/clint.json`
- Create: `src/myfuzz/components/profiles/plic.json`
- Create: `src/myfuzz/components/profiles/pwm.json`
- Create: `src/myfuzz/components/profiles/i2c.json`
- Create: `src/myfuzz/components/profiles/dma.json`
- Test: `tests/integration/test_cpu_profile_interfaces.py`

Add `interface_description` and `source_locator` metadata to CPU profiles. The CVA6 and BOOM documents identify semantic instruction/data memory, interrupt, debug, clock, and reset endpoints; exact port widths/directions remain crawler output. Their README files state the required pinned source checkout and the expected protocol/ISA contract. Catalog profiles are executable only when their source locator and annotation validation succeed; reference-only profiles remain selectable for analysis but not runtime publication.

Extend peripheral profiles with endpoint role, protocol feature, external-pin, dependency, and parameter metadata. Add CLINT, PLIC, PWM, I2C, and DMA profiles with explicit dependencies and reference/implemented status. No profile may contain a CPU-specific signal name or renderer selector.

- [ ] **Step 1: Write failing profile/annotation tests.**

Verify CVA6 and BOOM profiles expose RV64 ISA metadata and an interface-description path, verify their interface documents contain no direction/width/timing requirements, and verify the five new peripheral profiles load with dependencies and protocol capability data. Use synthetic pinned source fixtures to validate the same generic crawler path for both CPU names.

- [ ] **Step 2: Run focused tests and verify the failure.**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_cpu_profile_interfaces tests.isa.test_catalog tests.components.test_catalog -v
```

Expected: FAIL because the profile metadata and generic interface fixtures are absent.

- [ ] **Step 3: Add CPU interface manifests and profile metadata.**

Use only semantic roles, aliases/source anchors, expected protocol constraints, and pinned-source placeholders that are explicitly marked unavailable until materialized. Do not mark a CPU implemented merely because a profile file exists.

- [ ] **Step 4: Add generic peripheral endpoint metadata.**

Represent register targets, memory masters, streams, interrupt sources, external pins, parameter ranges, and declared dependencies as catalog data. Keep existing five implemented profiles compatible with their current loader and use optional fields for the new contract.

- [ ] **Step 5: Run profile and catalog regression tests.**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_cpu_profile_interfaces tests.isa.test_catalog tests.components.test_catalog -v
```

Expected: all new tests pass; missing upstream sources are reported as dependency-unavailable rather than treated as implemented.

- [ ] **Step 6: Commit.**

```bash
git add configs/cpus src/myfuzz/isa/profiles/cva6.json src/myfuzz/isa/profiles/boom.json src/myfuzz/components/model.py src/myfuzz/components/catalog.py src/myfuzz/components/profiles tests/integration/test_cpu_profile_interfaces.py
git commit -m "feat: register generic CVA6 BOOM and peripheral capabilities"
```

## Task 8: End-to-end validation and low-resource execution

**Files:**
- Create: `tests/integration/test_low_resource_generic_smoke.py`
- Modify: `src/myfuzz/integration/low_resource_smoke.py`
- Modify: `src/myfuzz/experiments/resource_policy.py`
- Create: `docs/generic-composition-usage.md`
- Modify: `docs/README.md`

- [ ] **Step 1: Write failing end-to-end tests.**

Use a local synthetic CPU plus RAM, UART, GPIO, CLINT, and PLIC descriptions. Assert the pipeline emits annotations, capabilities, IR, top-level HDL, source list, and generated layout, then runs a bounded lint/smoke command when the toolchain exists. Assert missing source, ambiguous endpoints, invalid protocol features, address overlap, and dependency cycles publish no artifacts.

- [ ] **Step 2: Run focused tests and verify the failure.**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_low_resource_generic_smoke -v
```

Expected: FAIL because the generic low-resource integration entrypoint is not connected.

- [ ] **Step 3: Connect resource policy.**

Default to one active build, one frontend worker, bounded queues, no waveform output, per-process-group RSS limits, and explicit timeout propagation. Keep resource-policy results separate from functional diagnostics.

- [ ] **Step 4: Run full verification.**

Run the complete Python suite with the known source-dependency condition recorded:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test_*.py'
```

Run the generic smoke with one worker:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src JOBS=1 python3 -m unittest tests.integration.test_low_resource_generic_smoke -v
```

If external CVA6/BOOM/RFuzz sources or Verilator are absent, report `dependency-unavailable:<name>` and retain the analysis/contract results; do not call the system complete for that target.

- [ ] **Step 5: Document the generic workflow.**

Document the minimal semantic input, source pin, generated annotation, capability matching, generated layout, ISA modes, supported protocols, low-resource controls, and failure diagnostics. Include a complete synthetic example and commands that do not require network access.

- [ ] **Step 6: Commit.**

```bash
git add src/myfuzz/integration/low_resource_smoke.py src/myfuzz/experiments/resource_policy.py tests/integration/test_low_resource_generic_smoke.py docs/generic-composition-usage.md docs/README.md
git commit -m "test: validate generic composition under low resource policy"
```

## Verification and handoff

After Task 8, create a review package from the branch merge base through `HEAD`, dispatch the whole-branch reviewer, resolve every Critical/Important finding, and rerun the complete verification commands. Report separately:

- generic analysis/annotation status;
- supported protocol definitions versus executable RTL adapters;
- CPU profiles whose pinned sources were actually available;
- implemented versus reference-only peripherals;
- generated input layout and ISA legality mode;
- RTL smoke evidence and RFuzz campaign evidence;
- dependency-unavailable results.
