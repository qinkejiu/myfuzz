# P7 D4 PULP Native Route Consumption Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the existing PULP APB3 D4 topology binding actively gate each native DMA beat and preserve a fresh-replayed RAM-to-PADOUT transaction chain.

**Architecture:** Separate PULP path preparation from its legacy bind/install wrapper. Add a composite admission that checks the D4-bound route before delegating to the existing one-word beat policy. Bind D4 exactly once in the real native fixture and join read and write beats separately by their exact `TransactionKey` values.

**Tech Stack:** Python 3.12, pytest, generated local harness artifacts, `PreparedRuntimePathContract`, `BoundDmaIntentTopology`, native ZipCPU Wishbone DMA and PULP GPIO APB3 sessions.

**Execution note (2026-10-21):** The prepare API RED failed at the missing entry point as planned. The prepare API and compatibility wrapper were then implemented together; the compile delegation spy passed in its first run, so there is no separately recorded wrapper-specific RED. The native legacy-flow assertion failed with zero D4 route matches before fixture integration. The first wrong-offset run exposed an old test observer shadowing a sealed provider method; the observer was removed and the refusal gate now uses provider/APB event evidence.

## Global Constraints

- Keep `compile_pulp_gpio_dma_runtime_paths(...)` compatible for existing callers.
- Native D4 setup uses one exact prepared graph and one `PreparedRuntimePathContract.bind(...)` call.
- A RAM read and later PADOUT write have distinct `TransactionKey` values; join each beat's own target activity and native response, then verify the write value equals the read response.
- Route lookup must run in the DMA admission hook before `MemoryService` or the GPIO provider can observe the beat.
- Preserve the D2/D3 route rows and keep P7-C F6 `unsupported` with no added `DMA_MASTER_TRANSFER` compile edge.
- Keep the D4 tier `topology_bound`; runtime joins live in the separate native evidence.
- Do not claim a physical Wishbone-to-APB bridge, CPU DMA programming/retirement, multiword DMA, generic F6, remote verification, or overall six-CPU/four-IP completion.
- Preserve the shared dirty worktree; do not stage, commit, reset, or clean it.

---

### Task 1: Split PULP preparation from binding

**Files:**
- Modify: `src/myfuzz/scenario/pulp_gpio_dma_paths.py`
- Modify: `tests/scenario/test_pulp_gpio_dma_paths.py`

**Interfaces:**
- Add `prepare_pulp_gpio_dma_runtime_paths(runner, *, gpio_base=0x40001000, gpio_size=0x1000, memory_component='cpu', resource_id='ram', image_id='dma_payload', image_address=None, direction=DEFAULT_DIRECTION)`.
- Return `PulpGpioDmaRuntimePaths` with the same graph, contract, path, prepared object, beat admission and source bindings as today, but `compiled is None`; do not bind or configure the runner.
- Keep `compile_pulp_gpio_dma_runtime_paths(...)` with its current signature and behavior: call prepare once, bind that returned prepared object once, install its beat admission once, and return the paths with `compiled` populated.
- Make `PulpGpioDmaRuntimePaths.document()` fail with a clear `ValueError` while `compiled is None`, matching the existing ZipCPU prepared-path behavior.

- [x] **Step 1: Add a failing preparation test**

```python
def test_prepare_builds_pulp_paths_without_binding_or_installing_admission():
    import myfuzz.scenario.pulp_gpio_dma_paths as pulp_paths

    prepare = getattr(pulp_paths, 'prepare_pulp_gpio_dma_runtime_paths', None)
    assert callable(prepare)
    runner = _Runner()

    paths = prepare(runner)

    assert paths.compiled is None
    assert runner.dma._route_validator is None
    assert runner.dma.route_admission is None
    assert paths.admission.image_address == RAM_BASE
```

- [x] **Step 2: Run the test and verify the expected missing-API failure**

Run: `PYTHONPATH=src python3 -m pytest -q tests/scenario/test_pulp_gpio_dma_paths.py::test_prepare_builds_pulp_paths_without_binding_or_installing_admission --tb=short`

Expected: FAIL at `callable(prepare)` because the preparation entry point does not exist yet.

- [x] **Step 3: Implement the pure preparation entry point**

Move the current declaration construction through `PreparedRuntimePathContract(...)` and `PulpGpioDmaBeatAdmission(...)` into `prepare_pulp_gpio_dma_runtime_paths(...)`. Return `compiled=None`; leave `prepared.bind(...)` and `configure_dma_route_admission(...)` out of this function. Change the paths dataclass annotation to `CompiledRuntimePathContract | None`, import `replace` from `dataclasses`, and make `document()` reject the unbound preparation with a clear `ValueError`.

Run: `PYTHONPATH=src python3 -m pytest -q tests/scenario/test_pulp_gpio_dma_paths.py::test_prepare_builds_pulp_paths_without_binding_or_installing_admission --tb=short`

Expected: PASS; preparation returns the expected typed graph and leaves both runner hooks unset.

- [x] **Step 4: Add a test that compile delegates to preparation exactly once**

Add this test to `tests/scenario/test_pulp_gpio_dma_paths.py`:

```python
def test_compile_pulp_paths_binds_prepared_object_once_and_installs_legacy_admission():
    from unittest.mock import patch
    import myfuzz.scenario.pulp_gpio_dma_paths as pulp_paths

    runner = _Runner()
    prepared_objects = []
    bound_objects = []
    original_prepare = pulp_paths.prepare_pulp_gpio_dma_runtime_paths
    original_bind = PreparedRuntimePathContract.bind

    def prepare_spy(*args, **kwargs):
        paths = original_prepare(*args, **kwargs)
        prepared_objects.append(paths)
        return paths

    def bind_spy(prepared, *args, **kwargs):
        bound_objects.append(prepared)
        return original_bind(prepared, *args, **kwargs)

    with patch.object(pulp_paths, 'prepare_pulp_gpio_dma_runtime_paths', prepare_spy), \
         patch.object(PreparedRuntimePathContract, 'bind', bind_spy):
        paths = pulp_paths.compile_pulp_gpio_dma_runtime_paths(runner)

    assert len(prepared_objects) == 1
    assert len(bound_objects) == 1
    assert bound_objects[0] is prepared_objects[0].prepared is paths.prepared
    assert paths.compiled is not None
    assert runner.dma.route_admission is paths.admission
```

- [x] **Step 5: Run the compile delegation test**

Run: `PYTHONPATH=src python3 -m pytest -q tests/scenario/test_pulp_gpio_dma_paths.py::test_compile_pulp_paths_binds_prepared_object_once_and_installs_legacy_admission --tb=short`

Expected: the test proves the compile wrapper calls preparation once and binds its exact prepared object once. The implementation wrapper landed in the same patch as the prepare API, so this test's pre-wrapper RED was not captured separately; its final run passed.

- [x] **Step 6: Implement the compatibility compile wrapper**

Make the existing compile function call preparation once, bind that returned `paths.prepared` once, configure that returned `paths.admission` once, and return `replace(paths, compiled=compiled)`.

- [x] **Step 7: Run preparation and compatibility tests**

Run: `PYTHONPATH=src python3 -m pytest -q tests/scenario/test_pulp_gpio_dma_paths.py --tb=short`

Expected: all tests in this module pass, including the no-bind preparation test and all existing compile behavior tests.

---

### Task 2: Make the beat admission consume D4 route matches

**Files:**
- Modify: `src/myfuzz/scenario/pulp_gpio_dma_paths.py`
- Modify: `tests/integration/test_p7b_p7c_dma_route_intent.py`
- Read: `src/myfuzz/scenario/dma_intent_topology_binding.py`

**Interfaces:**
- Add `PulpGpioD4RouteAdmission(beat_admission, bound_topology, *, path_id, read_route, write_route)` implementing `identity_document()`, `begin_case(...)`, `accepted(...)`, `completed(...)`, and a `state` property delegated to the beat policy.
- On `accepted`, select the read route for `write is False` and the PADOUT route for `write is True`; call `bound_topology.match_dma_master_route(...)` with the route identity, actual address/operation/byte-enable/value, and the exact `TransactionKey` before delegating to `beat_admission.accepted(...)`.
- Refuse a `None` or non-exact route match before delegating. After the beat policy accepts, retain a detached route match document keyed by that exact `TransactionKey`.
- On `begin_case`, clear route-match observations and delegate reset to the existing beat policy. On `completed`, delegate unchanged one-word response validation.
- The composite identity must include the D4 binding identity, path ID, both selected route hashes, and the existing beat-policy identity.

- [x] **Step 1: Add a failing test for route match before beat-state mutation**

Extend `test_pulp_apb3_d2_d3_route_binds_existing_typed_topology` after it builds `bound`:

```python
import myfuzz.scenario.pulp_gpio_dma_paths as pulp_paths

admission_type = getattr(pulp_paths, 'PulpGpioD4RouteAdmission', None)
assert callable(admission_type)
PulpGpioD4RouteAdmission = admission_type

read_route, write_route = prepared.contract.dma_master_routes
window, = runner.sessions['dma'].master_targets
beat = PulpGpioDmaBeatAdmission(image_address=read_route.base,
                                gpio_window=window)
admission = PulpGpioD4RouteAdmission(beat, bound,
    path_id=prepared.path_ids[0], read_route=read_route, write_route=write_route)
read_key = TransactionKey('native-read-run', 'native-case', 'dma', 0,
                          'dma-memory', 1)
admission.accepted(read_key, address=0x1000, write=False, value=0,
                   byte_enable=15, target=None)
admission.completed(read_key, rdata=0x5aa55aa5, error=0)
assert len(admission.route_matches) == 1
assert admission.route_matches[0]['transaction'] == vars(read_key)

wrong_write_key = TransactionKey('native-read-run', 'native-case', 'dma', 0,
                                 'dma-memory', 2)
with pytest.raises(ValueError):
    admission.accepted(wrong_write_key, address=0x40001010, write=True,
                       value=0x5aa55aa5, byte_enable=15, target=window)
assert beat.state == 'expect_write'
assert len(admission.route_matches) == 1
```

- [x] **Step 2: Run the test and verify the expected missing-class assertion**

Run: `PYTHONPATH=src python3 -m pytest -q tests/integration/test_p7b_p7c_dma_route_intent.py::test_pulp_apb3_d2_d3_route_binds_existing_typed_topology --tb=short`

Expected: FAIL at `callable(admission_type)` because the composite admission class is not implemented.

- [x] **Step 3: Implement the composite admission and sealed identity**

Implement `PulpGpioD4RouteAdmission` in `pulp_gpio_dma_paths.py`. Require exact `DmaMasterRouteMatch` output whose `edge_key`, `route_sha256`, path, operation, target and transaction key equal the selected prepared route and accepted beat. Serialize keys with `dataclasses.asdict`. Store detached match rows only after the existing beat admission succeeds. Delegate `state` to the existing beat admission for current runtime callers. Keep F6 and the prepared runtime graph unchanged.

- [x] **Step 4: Run the D4 route integration and path tests**

Run: `PYTHONPATH=src python3 -m pytest -q tests/scenario/test_pulp_gpio_dma_paths.py tests/integration/test_p7b_p7c_dma_route_intent.py::test_pulp_apb3_d2_d3_route_binds_existing_typed_topology --tb=short`

Expected: all selected tests pass; an unselected offset leaves the one-word admission state at `expect_write` and does not add a route-match record.

---

### Task 3: Bind D4 once in the real native PULP DMA gate

**Files:**
- Modify: `tests/integration/test_p7b_p7c_dma_route_intent.py`
- Modify: `tests/integration/test_dma_pulp_gpio_real.py`
- Modify: `tests/scenario/test_pulp_gpio_dma_paths.py`

**Interfaces:**
- Parameterize `_generate_pulp_gpio_dma_route_d2_d3(...)` with `ram_base` and `ram_size`, retaining defaults `0x1000` and `0x1000`; place its declared ROM after the requested RAM aperture so real native geometry can be represented without overlap.
- Change the real native fixture to use a generated local CPU artifact session sharing the exact `PersistentMemory`, and derive `artifact_links` from the exact generated DMA session.
- Change `_make_pair(cache_dir, d3_wiring)`, `_run_one(cache_dir, d3_wiring)`, and `_run_unselected_destination(cache_dir, d3_wiring)` to use the same generated D2/D3 wiring; replace the eager compile call in `_make_pair(...)` with pure preparation, `prepare_dma_intent_binding(...)`, one `bind_dma_intent_topology(...)`, one `PulpGpioD4RouteAdmission`, and one admission installation.
- Keep the native read and write keys distinct; include D4 binding document and serialized read/write route matches in the captured run evidence.

- [x] **Step 1: Add failing native assertions before changing the fixture**

In `tests/integration/test_dma_pulp_gpio_real.py`, add these checks to `_run_one` after the two accepted beats and their responses have been found:

```python
route_matches = getattr(dma._dma_route_admission, 'route_matches', ())
assert len(route_matches) == 2
assert {row['edge_key'] for row in route_matches} == {(0, 0), (2, 0)}
assert {json.dumps(row['transaction'], sort_keys=True)
        for row in route_matches} == {
            json.dumps(read_key, sort_keys=True),
            json.dumps(write_key, sort_keys=True)}
assert dma._dma_route_admission.identity_document()['schema_version'] == \
    'pulp_gpio_d4_route_admission.v1'
```

- [x] **Step 2: Run the opt-in native test and verify the expected missing-integration failure**

Run: `PYTHONPATH=src MYFUZZ_DMA_PULP_REAL=1 MYFUZZ_DMA_PULP_CACHE=/tmp/myfuzz-pulp-d4-native-cache-20261020 MYFUZZ_DMA_PULP_EVIDENCE=/tmp/myfuzz-pulp-d4-native-red-20261020 timeout 1800 python3 -m pytest -xq tests/integration/test_dma_pulp_gpio_real.py::test_real_dma_to_pulp_padout_and_independent_fresh_replay`

Expected: FAIL because the eager legacy admission has no D4 `route_matches`; the first assertion sees zero rows.

- [x] **Step 3: Align D2/D3 and native RAM route geometry**

Add keyword parameters `ram_base=0x1000` and `ram_size=0x1000` to `_generate_pulp_gpio_dma_route_d2_d3`. Use them in the route intent, declared RAM resource and D2/D3 compile request. Place `rom0` at `max(0x10000, ram_base + ram_size)` with its existing size. Keep the module fixture's defaults unchanged. In the opt-in native test, generate D2/D3 material once under `tmp_path / 'pulp-d2-d3'` with `ram_base=RAM_BASE` and `ram_size=RAM_SIZE`, then pass `request.wiring` to `_run_one`, `_run_unselected_destination`, and `_make_pair` so the static intent exactly matches the live `PersistentMemory` region.

- [x] **Step 4: Replace the CPU placeholder and bind the prepared route**

In `_make_pair`, use `linked_dma = generated_instance('dma')`, instantiate `GeneratedWishboneDmaSession(linked_dma.artifact, ...)`, and set `artifact_links = {'dma': linked_dma.endpoint_links_document()}`. Instantiate `GeneratedLocalSession(_local_artifact(CPU_PROFILE, 'cpu'), base_dir=ROOT, cache_dir=cache_dir)`, assign `cpu.memory = memory`, and register it as `runner.sessions['cpu']`. Keep the real PULP session. Set the PULP `MasterTargetWindow.accepted_write_values` to `(SOURCE_WORD,)`, then call `prepare_pulp_gpio_dma_runtime_paths(...)`.

Build `declaration = _pulp_d4_declaration(d3_wiring, paths.prepared, artifact_links)`, call `bind_dma_intent_topology(declaration, runner, artifact_links=artifact_links)` exactly once, then unpack `read_route, write_route = paths.prepared.contract.dma_master_routes` and install `PulpGpioD4RouteAdmission(paths.admission, bound, path_id=paths.path_id, read_route=read_route, write_route=write_route)`. Spy on `PreparedRuntimePathContract.bind` around the D4 call and record `{'bind_count': 1, 'same_prepared_object': calls[0] is paths.prepared}`. Set the returned paths' compiled object with `dataclasses.replace(paths, compiled=bound.runtime_compilation)`; do not call `prepared.bind` or the old compile wrapper again.

- [x] **Step 5: Join route matches to existing native witnesses**

For each read match, assert its transaction dictionary equals the accepted read beat key and join that key to one MemoryService `memory_read` and one native response with the selected source address/value and `error == 0`. For the write match, assert the distinct key equals the accepted write key and join it to one target-provider receipt with APB3 access/effect at `PADOUT_ADDRESS` and one native response with `error == 0`. Keep the existing beat-admission check that the write data equals the read response.

Include `bound.document()`, `bind_count`, `same_prepared_object`, and both route-match rows in the positive typed evidence. Let `_normalize_execution_ids(...)` normalize the nested match keys, then compare first and fresh runs.

- [x] **Step 6: Preserve the wrong-offset native refusal**

Use the same D4 setup in `_run_unselected_destination`. Require the attempted `PADOUT_ADDRESS + 4` request to produce no route-match row, refuse before the PULP provider, leave APB access/request/response counts at zero, and leave `PADOUT` at zero. Do not treat aperture membership as route acceptance.

- [x] **Step 7: Run the two native gate tests**

Run: `PYTHONPATH=src MYFUZZ_DMA_PULP_REAL=1 MYFUZZ_DMA_PULP_CACHE=/tmp/myfuzz-pulp-d4-native-cache-20261021 MYFUZZ_DMA_PULP_EVIDENCE=docs/reports/evidence/p7-d4-pulp-native-route-consumption-20261021 timeout 1800 python3 -m pytest -xq tests/integration/test_dma_pulp_gpio_real.py`

Actual: `2 passed in 116.38 seconds`; the evidence directory contains reference, fresh, comparison, manifest, and unselected-offset refusal JSON artifacts.

---

### Task 4: Record evidence and run the scoped acceptance gate

**Files:**
- Create: `docs/reports/p7-d4-pulp-native-route-consumption-20261021.md`
- Modify: `docs/CURRENT_PROGRESS.md`
- Modify: `docs/reports/README.md`
- Modify: `docs/superpowers/plans/README.md`
- Modify: `docs/superpowers/plans/2026-10-13-p7-automatic-onboarding-implementation.md`
- Modify: `docs/superpowers/specs/2026-10-20-p7-d4-pulp-native-route-consumption-design.md`
- Evidence: `docs/reports/evidence/p7-d4-pulp-native-route-consumption-20261021/`

- [x] **Step 1: Write passing native evidence to the report evidence directory**

Run the opt-in gate with `MYFUZZ_DMA_PULP_EVIDENCE=docs/reports/evidence/p7-d4-pulp-native-route-consumption-20261021` and `MYFUZZ_DMA_PULP_CACHE=/tmp/myfuzz-pulp-d4-native-cache-20261021`.

- [x] **Step 2: Write a report with exact scope and evidence paths**

Record the native command, gate counts, D2/D3 route identity, D4 credential tier/hash, exact prepared-object single-bind evidence, read/write transaction keys, MemoryService read, APB3 provider/effect receipt, both native responses, fresh comparison, and wrong-offset refusal. State that the run is transaction-level process composition and retains the limits in the spec.

- [x] **Step 3: Update current progress and indexes**

Link the report from `docs/reports/README.md`, add a dated P7-D4 entry to `docs/CURRENT_PROGRESS.md`, index this implementation plan, and state in the P7 onboarding plan that the PULP D4 route is now consumed by the local native gate while F6 and the full P7-E generic onboarding gate remain open.

- [x] **Step 4: Run the joint software regression gate**

Run:

```bash
PYTHONPATH=src python3 -m pytest -q \
  tests/local_harness/test_dma_artifact_endpoint_links.py \
  tests/scenario/test_dma_intent_topology_binding.py \
  tests/scenario/test_runtime_path_contract.py \
  tests/scenario/test_runtime_edge_index.py \
  tests/integration/test_dma_intent_binding_replay.py \
  tests/integration/test_dma_master_route_replay_readers.py \
  tests/integration/test_p7b_p7c_dma_route_intent.py \
  tests/integration/test_route_intent_reader_boundaries.py \
  tests/scenario/test_pulp_gpio_dma_paths.py --tb=short
```

Actual: **236 passed, 61 subtests passed in 343.76 seconds**. This includes the previous D4 joint gate plus pure prepare/compile compatibility, D4 route-consumption, and source/response join checks.

- [x] **Step 5: Run source checks and capture the final verification record**

Run:

```bash
python3 -m py_compile src/myfuzz/scenario/pulp_gpio_dma_paths.py tests/scenario/test_pulp_gpio_dma_paths.py tests/integration/test_p7b_p7c_dma_route_intent.py tests/integration/test_dma_pulp_gpio_real.py
git diff --check -- src/myfuzz/scenario/pulp_gpio_dma_paths.py tests/scenario/test_pulp_gpio_dma_paths.py tests/integration/test_p7b_p7c_dma_route_intent.py tests/integration/test_dma_pulp_gpio_real.py
```

Expected: both commands exit 0. Also run this scoped trailing-whitespace scan because `git diff --check` does not inspect untracked files:

```bash
python3 - <<'PY'
from pathlib import Path
paths = [
    'src/myfuzz/scenario/pulp_gpio_dma_paths.py',
    'tests/scenario/test_pulp_gpio_dma_paths.py',
    'tests/integration/test_p7b_p7c_dma_route_intent.py',
    'tests/integration/test_dma_pulp_gpio_real.py',
    'docs/superpowers/specs/2026-10-20-p7-d4-pulp-native-route-consumption-design.md',
    'docs/superpowers/plans/2026-10-20-p7-d4-pulp-native-route-consumption.md',
    'docs/reports/p7-d4-pulp-native-route-consumption-20261021.md',
    'docs/CURRENT_PROGRESS.md',
    'docs/reports/README.md',
    'docs/superpowers/plans/README.md',
    'docs/superpowers/plans/2026-10-13-p7-automatic-onboarding-implementation.md',
]
bad = [(name, number) for name in paths
       for number, line in enumerate(Path(name).read_text(encoding='utf-8').splitlines(), 1)
       if line.rstrip() != line]
if bad:
    raise SystemExit(f'trailing whitespace: {bad}')
print(f'no trailing whitespace in {len(paths)} files')
PY
```

Record exact command outputs, test count, native runtime, evidence paths, and any still-open remote or higher-level P6/P7/P8 gate without upgrading those statuses.

Actual: `py_compile` exited 0; `git diff --check` exited 0; the scoped scan found no trailing whitespace in all 11 listed source/spec/plan/report/index files. Native evidence is stored under `docs/reports/evidence/p7-d4-pulp-native-route-consumption-20261021/`. F6 and full P6/P7/P8 acceptance remain open.
