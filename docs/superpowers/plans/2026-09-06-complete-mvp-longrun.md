# Complete CPU/Peripheral Composition MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the runnable dependency-aware CPU/peripheral composition MVP, expose a low-resource campaign entrypoint, and produce reproducible local evidence while fail-closing when real CPU/RFuzz dependencies are absent.

**Architecture:** Keep the existing protocol catalog, fixed-width RFuzz ABI, protocol bridges, and deterministic Ibex wrapper as the runtime foundation. Add two closed metadata catalogs—CPU profiles and peripheral capabilities—and a deterministic planner that validates protocol, width, source, address, IRQ, and dependency constraints before materialization. Add a campaign CLI that can either invoke the real design flow or run a bounded local metric producer through the existing RSS/process-group supervisor.

**Tech Stack:** Python 3 standard library, strict JSON metadata, SystemVerilog bridge RTL, `unittest`, Verilator/Icarus when installed, and the existing RFuzz/design-flow scripts.

## Global Constraints

- The existing RFuzz input ABI geometry is immutable; Ibex baseline remains 56 input bytes projected to 395 raw bits, and no random field may be appended.
- Runtime protocol support is limited to the already verified APB4, AXI4-Lite, and TileLink-UL single-beat profiles; AXI4 burst, full TileLink, CHI, and other reference-only profiles must fail closed.
- CPU and peripheral catalog records distinguish `implemented` local sources from `reference` metadata; a catalog entry alone never authorizes RTL execution.
- Automatic composition is deterministic: identical catalog, request, manifest, and tool version produce identical candidate IDs, address assignments, diagnostics, and hashes.
- Every generated address is aligned, non-overlapping, inside the declared address width, and every IRQ is unique and within the Ibex external IRQ range.
- Default campaign execution uses one build slot, one worker, no waveform, 512 MiB soft RSS, 768 MiB hard RSS, a 64 MiB token budget, and a 3600-second duration; development runs pass an explicit shorter duration.
- RSS and process-group supervision must be verified before starting a child; missing `/proc` or unsafe process-group support is a startup error.
- Checkpoints and reports are bounded and atomically published; an unavailable upstream dependency is reported as `dependency-unavailable`, never as a successful compile or fuzz run.
- New production behavior follows TDD: each feature has a failing test observed before its implementation and a focused regression run afterward.

---

### Task 1: Add strict CPU/ISA profile catalog

**Files:**
- Create: `src/myfuzz/isa/__init__.py`
- Create: `src/myfuzz/isa/model.py`
- Create: `src/myfuzz/isa/catalog.py`
- Create: `src/myfuzz/isa/profiles/ibex.json`
- Create: `src/myfuzz/isa/profiles/cva6.json`
- Create: `src/myfuzz/isa/profiles/boom.json`
- Create: `src/myfuzz/isa/profiles/rocket.json`
- Create: `src/myfuzz/isa/profiles/picorv32.json`
- Create: `src/myfuzz/isa/profiles/cv32e40p.json`
- Test: `tests/isa/__init__.py`
- Test: `tests/isa/test_catalog.py`

**Interfaces:**
- `CpuProfile(cpu_id: str, vendor: str, xlen: tuple[int, ...], extensions: tuple[str, ...], core_native_protocols: tuple[tuple[str, str], ...], integration_protocols: tuple[tuple[str, str], ...], source_status: str, source_paths: tuple[str, ...], implemented: bool)`.
- `CpuCatalog.require(cpu_id: str) -> CpuProfile` and `.profiles -> tuple[CpuProfile, ...]`.
- `CpuCatalog.compatible_protocols(cpu_id: str, *, runtime_only: bool = True) -> tuple[tuple[str, str], ...]`.
- `load_cpu_catalog(path: str | Path) -> CpuCatalog` and cached `load_builtin_cpu_catalog() -> CpuCatalog`.

- [ ] **Step 1: Write the failing catalog tests.**

  Assert all six profiles load, exact identities are unique, Ibex/CVA6/BOOM have their documented native/integration distinctions, unknown IDs and duplicate JSON keys fail closed, and `runtime_only=True` returns only protocol pairs backed by an `implemented` source profile rather than treating reference metadata as executable.

- [ ] **Step 2: Run the focused tests and observe the expected failure.**

  Run:

  ```bash
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.isa.test_catalog -v
  ```

  Expected: import failure because `myfuzz.isa` does not exist.

- [ ] **Step 3: Implement the minimal immutable model and strict loader.**

  Parse only the declared fields, reject unknown keys, duplicate profile IDs, invalid XLEN/protocol tuples, invalid status values, and path traversal in source paths. Keep profile records metadata-only unless `implemented` is true and all declared source paths exist under the supplied root.

- [ ] **Step 4: Add the six profile documents and rerun focused tests.**

  Use the existing ISA reference document as the source of the extension sets. Mark the local Ibex profile as implemented only for the checked-in `ibex_multicomponent_ip` scaffold; mark CVA6, BOOM, Rocket, PicoRV32, and CV32E40P as reference unless their complete sources are present. Confirm the tests pass and no existing test regresses.

- [ ] **Step 5: Commit.**

  ```bash
  git add src/myfuzz/isa tests/isa
  git commit -m "feat: add strict CPU ISA profile catalog"
  ```

### Task 2: Add peripheral capability and dependency catalog

**Files:**
- Create: `src/myfuzz/components/__init__.py`
- Create: `src/myfuzz/components/model.py`
- Create: `src/myfuzz/components/catalog.py`
- Create: `src/myfuzz/components/profiles/ram.json`
- Create: `src/myfuzz/components/profiles/timer.json`
- Create: `src/myfuzz/components/profiles/gpio.json`
- Create: `src/myfuzz/components/profiles/uart.json`
- Create: `src/myfuzz/components/profiles/spi.json`
- Create: `src/myfuzz/components/profiles/pwm.json`
- Create: `src/myfuzz/components/profiles/i2c.json`
- Create: `src/myfuzz/components/profiles/dma.json`
- Create: `src/myfuzz/components/profiles/clint.json`
- Create: `src/myfuzz/components/profiles/plic.json`
- Create: `src/myfuzz/components/profiles/ethernet_mac.json`
- Test: `tests/components/__init__.py`
- Test: `tests/components/test_catalog.py`

**Interfaces:**
- `PeripheralProfile(component_type: str, module_name: str, protocols: tuple[tuple[str, str], ...], address_alignment: int, default_size: int, irq_capable: bool, requires: tuple[str, ...], source_status: str, source_paths: tuple[str, ...], implemented: bool, parameter_limits: Mapping[str, tuple[int, int]])`.
- `ComponentCatalog.require(component_type: str) -> PeripheralProfile`, `.profiles`, and `available(component_type: str, *, root: Path, protocol: tuple[str, str] | None = None) -> PeripheralProfile`.
- `load_component_catalog(path: str | Path) -> ComponentCatalog` and cached `load_builtin_component_catalog() -> ComponentCatalog`.

- [ ] **Step 1: Write the failing capability tests.**

  Assert the catalog contains at least the ten named common peripherals, RAM/timer/GPIO/UART/SPI expose the three runtime protocol bindings used by the Ibex fixture, DMA/PLIC/ethernet are reference-only without local sources, dependency names are unique and known, and invalid protocols, duplicate component types, unknown fields, and path traversal fail closed.

- [ ] **Step 2: Run the focused tests and observe the expected failure.**

  ```bash
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.components.test_catalog -v
  ```

  Expected: import failure because `myfuzz.components` does not exist.

- [ ] **Step 3: Implement the closed capability model and loader.**

  Do not accept arbitrary HDL paths or compiler flags from metadata. Resolve source paths only relative to the explicitly supplied repository root, return reference profiles from `.profiles`, and make `available()` reject missing sources or unsupported protocol/version pairs with a typed error.

- [ ] **Step 4: Add profiles and rerun focused/regression tests.**

  Point the five implemented profiles at existing local Ibex component RTL and point reference profiles at stable descriptive source paths without claiming availability. Verify deterministic ordering and content hashes through the existing canonical JSON helper.

- [ ] **Step 5: Commit.**

  ```bash
  git add src/myfuzz/components tests/components
  git commit -m "feat: add peripheral capability catalog"
  ```

### Task 3: Implement deterministic CPU/peripheral auto-composition planning

**Files:**
- Create: `src/myfuzz/composition/auto.py`
- Modify: `src/myfuzz/composition/__init__.py`
- Test: `tests/composition/test_auto.py`

**Interfaces:**
- `AutoCompositionRequest(cpu_id: str, component_types: tuple[str, ...], protocol_preferences: tuple[tuple[str, str], ...], address_width: int = 32, data_width: int = 32, base_address: int = 0x80010000, window_size: int = 0x1000, irq_start: int = 1)`.
- `AutoCompositionPlan(cpu: CpuProfile, components: tuple[Mapping[str, object], ...], dependencies: tuple[tuple[str, str], ...], diagnostics: tuple[str, ...], complete: bool, content_hash: str)`.
- `plan_auto_composition(request: AutoCompositionRequest, *, cpu_catalog: CpuCatalog | None = None, component_catalog: ComponentCatalog | None = None, root: Path) -> AutoCompositionPlan`.
- `write_auto_composition_manifest(plan: AutoCompositionPlan, path: Path) -> None` writes a strict `protocol_composition.v1`-compatible manifest only when `plan.complete` is true and all selected components have local runtime sources.

- [ ] **Step 1: Write failing planner tests.**

  Assert an Ibex request for `timer,gpio,uart,spi` deterministically selects APB4/APB4/AXI4-Lite/AXI4-Lite, assigns aligned non-overlapping windows and unique IRQs, and records dependency edges. Assert duplicate components, missing protocol preferences, unsupported CPU/protocol pair, unknown component, width mismatch, and reference-only component produce `complete=False` or a typed validation error without writing a manifest. Assert two output directories have equal plans and hashes.

- [ ] **Step 2: Run the focused tests and observe the expected failure.**

  ```bash
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.composition.test_auto -v
  ```

  Expected: import failure because `myfuzz.composition.auto` does not exist.

- [ ] **Step 3: Implement deterministic candidate selection and dependency checks.**

  Normalize component IDs as `<type>0`, sort by type/ID, choose the first preferred protocol that is present in both catalogs and backed by local sources, assign addresses in sorted order, and derive the existing Ibex manifest shape. Reject any candidate that would require AXI4 bursts, multiple outstanding transactions, full TileLink, a missing source, or an unsupported CPU native/integration contract.

- [ ] **Step 4: Implement guarded manifest publication and rerun focused/regression tests.**

  Use atomic replacement and canonical JSON; never write a partial manifest or silently downgrade a requested protocol. Confirm existing fixed `ibex_protocol_composition` behavior and all composition tests remain green.

- [ ] **Step 5: Commit.**

  ```bash
  git add src/myfuzz/composition/auto.py src/myfuzz/composition/__init__.py tests/composition/test_auto.py
  git commit -m "feat: plan dependency-aware CPU peripheral compositions"
  ```

### Task 4: Add the low-resource Ibex campaign CLI and local evidence smoke

**Files:**
- Create: `configs/designs/ibex_protocol_composition/config.json`
- Create: `configs/designs/ibex_protocol_composition/campaign.json`
- Create: `scripts/run_ibex_protocol_campaign.py`
- Create: `scripts/run_ibex_protocol_campaign_smoke.py`
- Modify: `src/myfuzz/integration/campaign.py`
- Modify: `configs/designs/ibex_protocol_composition/README.md`
- Test: `tests/integration/test_ibex_protocol_campaign_cli.py`
- Test: `tests/integration/test_ibex_protocol_campaign_smoke.py`

**Interfaces:**
- `build_ibex_campaign_command(root: Path, config_path: Path, output_dir: Path, duration_seconds: int, seed: int) -> tuple[str, ...]`.
- `run_ibex_campaign(config_path: Path, output_dir: Path, *, duration_seconds: int | None = None, seed: int | None = None, checkpoint_seconds: int | None = None, command: tuple[str, ...] | None = None, dry_run: bool = False, max_restarts: int | None = None) -> Mapping[str, object]`.
- CLI options: `--config`, `--output-dir`, `--duration-seconds`, `--seed`, `--checkpoint-seconds`, `--command`, `--dry-run`, `--local-smoke`, `--max-restarts`.
- Local smoke emits bounded JSON lines covering `tl-ul`, `apb`, `axi4-lite`, `ram`, `timer`, `gpio`, `uart`, `spi`, and one coverage point; it does not claim RTL compilation.

- [ ] **Step 1: Write failing CLI and smoke tests.**

  Assert the default config is one worker with waveforms disabled and the documented memory limits; command construction contains `--stage all`, `--jobs 1`, `--fuzz-seconds`, and `--seed`; duration `0`, invalid memory order, non-one worker, mixed config fields, and unknown CLI command mode fail closed. Assert local smoke publishes a parseable atomic report with nonzero iterations, all three protocol counters, all five component counters, coverage, checkpoint, RSS, and an explicit upstream dependency status.

- [ ] **Step 2: Run focused tests and observe the expected failure.**

  ```bash
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_ibex_protocol_campaign_cli tests.integration.test_ibex_protocol_campaign_smoke -v
  ```

  Expected: missing config/script/module failures.

- [ ] **Step 3: Implement strict config loading and command construction.**

  Use only explicit CLI overrides, validate all memory values against the conservative ceiling, force one worker, resolve paths beneath the repository root, and use the existing `run_supervised_command()` plus atomic campaign report functions. The normal command must run the design-flow config only when the upstream source list is present; otherwise return `dependency-unavailable` before spawning a child.

- [ ] **Step 4: Implement the local producer smoke and documentation.**

  Keep the producer deterministic by seed, emit one metric line per required protocol/component, and invoke it under the same supervisor with a short explicit duration. Document the real-target command, the dependency-unavailable outcome, the 10–60 second prerequisite, and the exact report fields before a 3600-second run.

- [ ] **Step 5: Run focused tests and the 10-second local smoke.**

  ```bash
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_ibex_protocol_campaign_cli tests.integration.test_ibex_protocol_campaign_smoke -v
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 scripts/run_ibex_protocol_campaign.py --config configs/designs/ibex_protocol_composition/campaign.json --local-smoke --duration-seconds 10 --output-dir runs/ibex_protocol_campaign_smoke
  ```

  Expected: both test modules pass; the command returns a completed report with nonzero local metrics, while real-target dry-run reports `dependency-unavailable` when the upstream checkout is absent.

- [ ] **Step 6: Commit.**

  ```bash
  git add configs/designs/ibex_protocol_composition scripts src/myfuzz/integration/campaign.py tests/integration
  git commit -m "feat: add low-resource Ibex campaign entrypoint"
  ```

### Task 5: End-to-end verification, long-run start, and evidence audit

**Files:**
- Create: `docs/reports/ibex_protocol_campaign_validation_20260906.md`
- Modify: `docs/README.md`

- [ ] **Step 1: Run the local composition and protocol checks.**

  Run the fixed manifest checker, generate the deterministic composition into a temporary output directory, lint each bridge and target with Verilator, and execute the existing Icarus protocol bridge tests. Record exact return codes and dependency status.

- [ ] **Step 2: Run the full regression suite.**

  ```bash
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -s tests -t .
  ```

  Record the fresh test count and zero-failure result in the validation report.

- [ ] **Step 3: Start a conservative bounded soak test.**

  Start the local deterministic producer with one supervised worker for at least 60 seconds, retain its checkpoint/report under `runs/`, and verify the report remains parseable while the run is active and after completion. Do not start a real Ibex/RFuzz process without the upstream source list and RFuzz executable.

- [ ] **Step 4: Run the real-target preflight.**

  Run `configs/designs/ibex_protocol_composition/scripts/check_local.py`. If the upstream directory or `sources.f` is absent, record exit code `2` and `dependency-unavailable`; if present, run the generated source list through Verilator lint and then the 10–60 second real campaign before any hour-level command.

- [ ] **Step 5: Write the audit report and link it from docs.**

  The report must separate implemented runtime evidence, metadata-only profiles, generated-artifact evidence, and blocked external dependencies. Include commands, timestamps, commit IDs, report paths, hashes, peak RSS, counters, and the exact next command for a machine with the missing upstream checkout.

- [ ] **Step 6: Commit the evidence report.**

  ```bash
  git add docs/reports/ibex_protocol_campaign_validation_20260906.md docs/README.md
  git commit -m "test: record complete MVP campaign validation"
  ```

## Plan self-review checklist

- Coverage: Tasks 1–2 provide machine-readable CPU/peripheral capabilities; Task 3 consumes them for dependency-aware composition; Task 4 starts both real and local campaigns; Task 5 verifies the full branch and records external dependency limits.
- ABI safety: no task changes `src/myfuzz/harness/abi.py`, the 395-bit Ibex projection geometry, or existing harness slices.
- Protocol safety: reference-only AXI4/AHB/Wishbone/Avalon/CHI entries remain metadata and cannot reach runtime generation without a verified bridge/source profile.
- Resource safety: all actual runs are single-worker, bounded, wave-free, RSS-supervised, and use explicit short durations during development.
- Determinism: catalog ordering, IDs, address assignment, manifest publication, campaign seed, and report hashes are specified explicitly.
