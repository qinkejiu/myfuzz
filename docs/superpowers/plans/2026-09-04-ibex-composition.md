# Ibex Declarative Composition Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a strict `protocol_composition.v1` manifest, a controlled component registry, deterministic composition IR generation, and a real-Ibex wrapper/Harness target using the three runtime bridge families.

**Architecture:** The composer accepts only registered component types and explicit addresses/protocol versions. It validates the manifest, emits a path-free `composition_ir.v1` plus a generated SystemVerilog wrapper and source list, and records stable hashes. Existing candidate-search composition remains unchanged and is not used as a second runtime IR.

**Tech Stack:** Python 3 standard library, JSON Schema-shaped contracts, deterministic JSON hashing, SystemVerilog-2012, existing Ibex and common-IP RTL layout.

## Global Constraints

- The first target is real `ibex_core` with one clock and one active-low synchronous reset boundary.
- Registered components are exactly `ram`, `timer`, `gpio`, `uart`, and `spi` for the first manifest.
- Address windows are 4 KiB aligned and non-overlapping.
- Runtime protocol choices are APB4, AXI4-Lite, and TileLink-UL only.
- Generated files are written below the requested output directory; source RTL and default configs are not rewritten.
- Same manifest, catalog, registry, and tool version produce byte-identical IR, wrapper text, source list, and hashes.
- The wrapper uses the existing unified component signals behind protocol bridges and routes IRQs deterministically.
- Unknown component, unknown protocol, invalid parameter, address overlap, IRQ conflict, and missing source fail before RTL generation.

---

### Task 1: Define the composition manifest and component registry

**Files:**
- Create: `schemas/protocol_composition.v1.schema.json`
- Create: `src/myfuzz/composition/registry.py`
- Create: `src/myfuzz/composition/protocol_manifest.py`
- Modify: `src/myfuzz/composition/__init__.py`
- Test: `tests/composition/test_protocol_manifest.py`

**Interfaces:**
- `ComponentRegistration(component_type: str, module_name: str, source_files: tuple[str, ...], supported_protocols: tuple[tuple[str, str], ...], parameter_defaults: Mapping[str, int], parameter_limits: Mapping[str, tuple[int, int]], irq_capable: bool)`.
- `ComponentRegistry.require(component_type: str) -> ComponentRegistration`.
- `default_component_registry(root: Path) -> ComponentRegistry`.
- `CompositionComponent(component_id: str, component_type: str, protocol_id: str, protocol_version: str, base: int, size: int, irq: int | None, parameters: Mapping[str, int], external_input: bool)`.
- `ProtocolCompositionManifest(target_kind: str, base_config: str, address_width: int, data_width: int, components: tuple[CompositionComponent, ...], seed: int, duration_seconds: int, checkpoint_seconds: int)`.
- `load_protocol_composition(path: Path) -> ProtocolCompositionManifest` and `validate_protocol_composition(manifest, catalog, registry) -> None`.

- [ ] **Step 1: Write failing manifest tests**

Cover the approved five-component manifest, duplicate IDs, unknown types/protocols, invalid alignment/size, overlap, duplicate IRQ, parameter-limit violations, zero duration, and deterministic component sorting.

- [ ] **Step 2: Run focused tests and verify failure**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.composition.test_protocol_manifest -v
```

Expected: import failure because the new contract does not exist.

- [ ] **Step 3: Implement strict parsing and registry**

Use a closed top-level key set with required `schema_version`, `target`, `components`, and `runtime`. Register the existing modules and source files under `configs/designs/ibex_multicomponent_ip/rtl/`; expose only `WORDS` for RAM and no arbitrary compiler arguments. Validate addresses as `base % 0x1000 == 0`, require `size == 0x1000` for peripherals and `0x10000` for RAM, require unique IDs/IRQs, and require the component protocol tuple to be in the registration.

- [ ] **Step 4: Run focused and full composition tests**

Expected: focused manifest tests pass and existing `tests/composition` tests remain green.

- [ ] **Step 5: Commit**

```bash
git add schemas/protocol_composition.v1.schema.json src/myfuzz/composition tests/composition/test_protocol_manifest.py
git commit -m "feat: add protocol composition manifest registry"
```

### Task 2: Generate deterministic composition IR and wrapper sources

**Files:**
- Create: `src/myfuzz/composition/protocol_composer.py`
- Modify: `src/myfuzz/composition/ir.py`
- Modify: `src/myfuzz/composition/__init__.py`
- Test: `tests/composition/test_protocol_composer.py`

**Interfaces:**
- `CompositionArtifact(ir: Mapping[str, object], wrapper_path: Path, source_list_path: Path, content_hash: str, source_hash: str)`.
- `compose_protocol_composition(manifest: ProtocolCompositionManifest, output_dir: Path, *, root: Path, catalog: ProtocolCatalog | None = None, registry: ComponentRegistry | None = None) -> CompositionArtifact`.
- `write_protocol_composition(manifest_path: Path, output_dir: Path, *, root: Path) -> dict[str, object]`.

- [ ] **Step 1: Write failing generator tests**

Assert that the approved fixture produces `composition_ir.v1`, five component instances, five address regions, three adapter kinds, one clock/reset domain, stable endpoint bindings, a wrapper top named `ibex_protocol_composition_top`, and identical hashes on two output directories. Assert that path strings are absent from IR metadata.

- [ ] **Step 2: Run focused tests and verify failure**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.composition.test_protocol_composer -v
```

Expected: import failure.

- [ ] **Step 3: Implement deterministic IR generation**

Build stable integer IDs from `canonical_id`, sort components by `component_id`, emit endpoint bindings for each selected protocol and component, emit adapter records with bridge module names, and compute `sha256:` hashes from canonical JSON. Emit the fixed regions from the design: RAM at `0x00000000/0x10000`, Timer at `0x80010000/0x1000`, GPIO at `0x80020000/0x1000`, UART at `0x80030000/0x1000`, and SPI at `0x80040000/0x1000`.

- [ ] **Step 4: Implement wrapper and source-list rendering**

Render a wrapper that instantiates `ibex_core`, the instruction/data RAM, each selected component, the APB4/AXI4-Lite/TL-UL bridge and target adapter pairs, and deterministic IRQ OR logic. Render a legal RV32I boot ROM function in the wrapper’s instruction path that loops through RAM, Timer, GPIO, UART, SPI, then RAM. Write `composition_ir.json`, `ibex_protocol_composition_top.sv`, and `sources.f` only below `output_dir`.

- [ ] **Step 5: Run focused tests and inspect generated output**

Run the focused test and:

```bash
python3 -m json.tool /tmp/ibex-composition-test/composition_ir.json >/dev/null
```

Expected: PASS, stable hashes, and no absolute source paths in IR.

- [ ] **Step 6: Commit**

```bash
git add src/myfuzz/composition tests/composition/test_protocol_composer.py
git commit -m "feat: generate deterministic Ibex protocol composition"
```

### Task 3: Add the approved Ibex composition fixture and local validation

**Files:**
- Create: `configs/designs/ibex_protocol_composition/manifest.json`
- Create: `configs/designs/ibex_protocol_composition/README.md`
- Create: `configs/designs/ibex_protocol_composition/scripts/check_local.py`
- Test: `tests/integration/test_ibex_protocol_composition_config.py`

- [ ] **Step 1: Write failing fixture tests**

Assert the fixture selects `ibex_core`, exactly the five components, the three protocol families, the fixed map, one seed, a 3600-second default, and a 30-second checkpoint. Assert `check_local.py` reports missing upstream Ibex as a dependency-unavailable result rather than silently treating the target as compiled.

- [ ] **Step 2: Add the fixture and checker**

Create the manifest with explicit fields and the address table from the design. The checker verifies all local bridge/component source files, JSON structure, and address/IRQ invariants; it prints `dependency-unavailable: third_party/rfuzz/upstream/ibex` when the upstream checkout is absent and exits `2`, while a complete local checkout exits `0`.

- [ ] **Step 3: Run fixture tests and checker**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_ibex_protocol_composition_config -v
python3 configs/designs/ibex_protocol_composition/scripts/check_local.py; test "$?" -eq 2
```

Expected: tests pass; the current machine reports the explicit dependency-unavailable status.

- [ ] **Step 4: Commit**

```bash
git add configs/designs/ibex_protocol_composition tests/integration/test_ibex_protocol_composition_config.py
git commit -m "feat: add Ibex protocol composition fixture"
```

### Task 4: Connect composition generation to the design flow

**Files:**
- Modify: `src/myfuzz/scripts/run_design_flow.py`
- Modify: `scripts/generate_composition.py`
- Test: `tests/composition/test_flow.py`
- Test: `tests/integration/test_ibex_protocol_composition_config.py`

**Interfaces:**
- Add CLI mode `scripts/generate_composition.py --protocol-manifest ... --out-dir ... --root ...`.
- Add `composition.kind == "protocol_composition"` handling in `stage_composition` while retaining current declaration `kind == "candidate_search"` behavior.
- Produce the returned summary keys `schema_version`, `manifest_hash`, `ir_path`, `wrapper_path`, `source_list_path`, and `complete`.

- [ ] **Step 1: Add failing dispatch tests**

Patch `write_protocol_composition` and assert the design-flow stage forwards the resolved manifest/output/root paths. Assert the CLI help mentions `--protocol-manifest` and the legacy composition path still works.

- [ ] **Step 2: Implement dispatch and summary validation**

Select the new branch only when `composition.kind` equals `protocol_composition`; reject missing or mixed configuration before writing output. Keep existing stage order and default behavior unchanged.

- [ ] **Step 3: Run flow tests and full regression**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.composition.test_flow tests.integration.test_ibex_protocol_composition_config -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -s tests
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/myfuzz/scripts/run_design_flow.py scripts/generate_composition.py tests/composition/test_flow.py tests/integration/test_ibex_protocol_composition_config.py
git commit -m "feat: connect protocol composition to design flow"
```
