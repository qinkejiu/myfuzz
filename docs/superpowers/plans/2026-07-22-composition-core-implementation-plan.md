# Dependency-Aware Composition Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the project-local Verilator frontend into a generic facts, constraint-search, Top-K Composition IR, and Verilator AST/emitter pipeline that never uses RTL identifier text as semantic evidence.

**Architecture:** The existing frontend manifest remains backward compatible. A separate C++ facts API emits `hdl_facts.v2`; Python owns declarative input validation, connection/address search, and `composition_ir.v1`; a C++ builder consumes validated IR and constructs a fresh Verilator source-like AST, validates it with existing link/width passes, and emits SystemVerilog through version-matched `V3EmitV`.

**Tech Stack:** C++20, vendored Verilator AST/link passes, CMake, Python 3 standard library, JSON contracts, `pytest`.

## Global Constraints

- No Pyverilog and no reference-top transformation.
- No module-name, port-name, directory-name, target-name, keyword, regex, prefix, suffix, or abbreviation heuristic.
- Every semantic role and protocol field binding is explicit input; missing declarations fail.
- Facts, inferred edges, assumptions, and rejected alternatives carry provenance.
- Top-K generation is deterministic, deduplicated by normalized graph hash, and streamed.
- Only one candidate AST is resident at a time; the build script uses `JOBS=1` by default.
- Every node ends with targeted tests, `git diff --check`, atomic commit, and GitHub push.

## File Map

- Modify: `src/myfuzz/frontend/CMakeLists.txt`, `MyFuzzFrontend.cpp`, `MyFuzzFrontendApi.cpp`, and `MyFuzzFrontendStubs.cpp`.
- Create: `src/myfuzz/frontend/src/MyFuzzFrontendFacts.h` and `.cpp`.
- Create: `src/myfuzz/frontend/src/MyFuzzCompositionAstBuilder.h` and `.cpp`.
- Create: `src/myfuzz/frontend/src/MyFuzzCompositionApi.cpp`.
- Create: `src/myfuzz/composition/ids.py`, `facts.py`, `declarations.py`, `constraints.py`, `address.py`, `search.py`, `ir.py`, and `manifest.py`.
- Create: `src/myfuzz/scripts/composition_api.py` and `scripts/generate_composition.py`.
- Create: `tests/fixtures/rtl/small_mmio/*.sv`, `tests/frontend/*.py`, and `tests/composition/*.py`.

## Task A0: Consume Published Contracts

Use the schemas and fixtures from integration node I0. Do not modify shared schema files in this branch.

- [ ] **Step 1:** Create `tests/composition/conftest.py` with fixtures loading valid `hdl_facts.v2` and explicit role/protocol declarations.
- [ ] **Step 2:** Run `python3 -m pytest tests/contracts tests/composition -q`; expected PASS for the published contract tests and FAIL only for composition tests that have no implementation.
- [ ] **Step 3:** Commit and push:

```bash
git add tests/composition/conftest.py
git commit -m "test(composition): [A0] consume frozen contracts" -m "Node: A0\nTests: python3 -m pytest tests/contracts tests/composition -q"
git push -u origin feature/composition-core
```

## Task A1: Independent Verilator Facts API

**Files:** create `MyFuzzFrontendFacts.h/.cpp`; modify `MyFuzzFrontend.cpp`, `MyFuzzFrontendApi.cpp`, and `CMakeLists.txt`; test `tests/frontend/test_facts_api.py`.

**Interface:** add `std::string frontendFactsJson(const std::vector<std::string>& args)` and C ABI `myfuzz_frontend_facts_json(int argc, const char* const* argv)`. Keep `frontendManifestJson` output unchanged.

- [ ] **Step 1:** Write the failing ctypes test using `FrontendLibrary.facts()` against `tests/fixtures/rtl/small_mmio/sources.f`. Assert stable IDs, explicit roles, pin bindings, data/control edges, and structural clock/reset evidence.
- [ ] **Step 2:** Run `python3 -m pytest tests/frontend/test_facts_api.py -q`; expected FAIL because the API is absent.
- [ ] **Step 3:** Implement extraction by walking linked AST nodes and source locations. Extract only structure around already-bound ports and protocol fields. Do not classify identifier text.
- [ ] **Step 4:** Add the C ABI using the malloc-owned string and last-error pattern from `MyFuzzFrontendApi.cpp`; add sources to CMake.
- [ ] **Step 5:** Run `JOBS=1 src/myfuzz/frontend/scripts/build_frontend.sh && python3 -m pytest tests/frontend/test_facts_api.py -q`; expected PASS.
- [ ] **Step 6:** Commit and push:

```bash
git add src/myfuzz/frontend tests/frontend/test_facts_api.py
git commit -m "feat(frontend): [A1] expose hdl_facts.v2" -m "Node: A1\nTests: JOBS=1 frontend build; facts pytest"
git push origin feature/composition-core
```

## Task A2: Declarative Input and Stable IDs

**Files:** create `src/myfuzz/composition/ids.py`, `facts.py`, `declarations.py`; test `tests/composition/test_declarations.py` and `test_identifier_invariance.py`.

**Interfaces:** `load_declarations(path) -> DeclarationSet`, `normalize_facts(raw) -> HdlFacts`, and `canonical_id(kind, declared_id) -> int`.

- [ ] **Step 1:** Write tests for valid declarations, missing role failure, duplicate ID failure, misleading names, and neutral source renames with updated explicit bindings.
- [ ] **Step 2:** Run `python3 -m pytest tests/composition/test_declarations.py tests/composition/test_identifier_invariance.py -q`; expected FAIL.
- [ ] **Step 3:** Implement frozen dataclasses for `ComponentDecl`, `PortDecl`, `ProtocolBinding`, `ClockResetDecl`, and `DeclarationSet`. Missing declarations are errors. `canonical_id` hashes opaque declared IDs without tokenizing them.
- [ ] **Step 4:** Run the tests and commit:

```bash
git add src/myfuzz/composition tests/composition/test_declarations.py tests/composition/test_identifier_invariance.py
git commit -m "feat(composition): [A2] validate explicit roles and stable IDs" -m "Node: A2\nTests: declarations and identifier invariance pytest"
git push origin feature/composition-core
```

## Task A3: Typed Connection Graph

**Files:** create `src/myfuzz/composition/constraints.py`; test `tests/composition/test_constraints.py`.

**Interfaces:** `build_constraint_graph(facts, declarations, protocols) -> ConstraintGraph`, `reject_hard_conflicts(graph) -> list[Conflict]`, and `candidate_edges(graph) -> Iterator[EdgeCandidate]`.

- [ ] **Step 1:** Write tests for direction/width mismatch, required endpoint cardinality, domain mismatch, protocol mismatch, legal adapters, and no identifier-text effect.
- [ ] **Step 2:** Run `python3 -m pytest tests/composition/test_constraints.py -q`; expected FAIL.
- [ ] **Step 3:** Implement integer-ID graph arrays, hard conflicts, protocol compatibility, RTL dataflow evidence, optional external endpoints, and forbidden edges. No semantic name access.
- [ ] **Step 4:** Run and publish:

```bash
python3 -m pytest tests/composition/test_constraints.py -q
git add src/myfuzz/composition/constraints.py tests/composition/test_constraints.py
git commit -m "feat(composition): [A3] build typed constraint graph" -m "Node: A3\nTests: constraints pytest"
git push origin feature/composition-core
```

## Task A4: Address Constraint Allocator

**Files:** create `src/myfuzz/composition/address.py`; test `tests/composition/test_address.py`.

**Interfaces:** `extract_local_regions(facts, declarations) -> tuple[LocalRegion, ...]` and `allocate_regions(regions, constraints) -> tuple[AddressRegion, ...]`.

- [ ] **Step 1:** Write tests for fixed-base preservation, alignment, non-overlap, width overflow, equal-solution determinism, local offsets from a bound address field, and conflict diagnostics.
- [ ] **Step 2:** Run `python3 -m pytest tests/composition/test_address.py -q`; expected FAIL.
- [ ] **Step 3:** Implement extraction only around declared address fields. Use bounded backtracking for region placement, opaque component IDs for equal-solution ordering, and explicit unsatisfiable conflicts.
- [ ] **Step 4:** Run and publish:

```bash
python3 -m pytest tests/composition/test_address.py -q
git add src/myfuzz/composition/address.py tests/composition/test_address.py
git commit -m "feat(composition): [A4] allocate inferred address regions" -m "Node: A4\nTests: address allocator pytest"
git push origin feature/composition-core
```

## Task A5: Deterministic Top-K and Composition IR

**Files:** create `src/myfuzz/composition/search.py`, `ir.py`, `manifest.py`, `tests/composition/test_search.py`, and `test_ir.py`.

**Interfaces:** `compose_topk(facts, declarations, protocols, limit) -> Iterator[CompositionCandidate]`, `composition_ir(candidate) -> dict`, and `candidate_manifest(candidate, emitted) -> dict`.

- [ ] **Step 1:** Write tests for limit, graph-hash deduplication, repeated-run order, evidence/assumption provenance, rejected alternatives, and hard-conflict rejection.
- [ ] **Step 2:** Run `python3 -m pytest tests/composition/test_search.py tests/composition/test_ir.py -q`; expected FAIL.
- [ ] **Step 3:** Implement a bounded heap over the specification's lexicographic score vector, stable tie-breaking, streaming release of rejected frontier state, and JSON serialization with no process pointers or absolute temp paths.
- [ ] **Step 4:** Run and publish:

```bash
python3 -m pytest tests/composition/test_search.py tests/composition/test_ir.py -q
git add src/myfuzz/composition tests/composition/test_search.py tests/composition/test_ir.py
git commit -m "feat(composition): [A5] stream deterministic Top-K IR" -m "Node: A5\nTests: search and IR pytest"
git push origin feature/composition-core
```

## Task A6: Verilator Source-Like AST Builder

**Files:** create `MyFuzzCompositionAstBuilder.h/.cpp` and `MyFuzzCompositionApi.cpp`; modify `CMakeLists.txt`; test `tests/frontend/test_ast_builder_smoke.py`.

**Interface:** `CompositionBuildResult buildCompositionAst(const CompositionIr& ir)` returns emitted source text and structured diagnostics. The C ABI accepts a validated IR payload and returns the same result.

- [ ] **Step 1:** Add a failing one-source/one-target fixture and assert module/cell/pin structure and no unresolved diagnostic.
- [ ] **Step 2:** Run `python3 -m pytest tests/frontend/test_ast_builder_smoke.py -q`; expected FAIL.
- [ ] **Step 3:** Construct fresh `AstModule`, `AstCell`, `AstVar`, `AstVarRef`, `AstPin`, and adapter assignment nodes following `V3LinkLevel::wrapTop()` and `wrapTopCell()`. Do not mutate an optimized DUT tree.
- [ ] **Step 4:** Run existing link, pin, width, and dtype checks. Reject undeclared ports, multiple drivers, width conflicts, and undeclared CDC.
- [ ] **Step 5:** Build and test: `JOBS=1 src/myfuzz/frontend/scripts/build_frontend.sh && python3 -m pytest tests/frontend/test_ast_builder_smoke.py -q`.
- [ ] **Step 6:** Commit and push:

```bash
git add src/myfuzz/frontend tests/frontend/test_ast_builder_smoke.py
git commit -m "feat(frontend): [A6] build composition AST from IR" -m "Node: A6\nTests: frontend build; AST builder smoke pytest"
git push origin feature/composition-core
```

## Task A7: Version-Matched V3EmitV

**Files:** restore/create `src/myfuzz/frontend/vendor/verilator/src/V3EmitV.cpp`; modify `MyFuzzFrontendStubs.cpp` and `CMakeLists.txt`; test `tests/frontend/test_emitter_smoke.py`.

**Interface:** `V3EmitV::emitvFiles()` emits source-like SystemVerilog from the fresh composition AST. The placeholder methods are removed only after the matching implementation is linked.

- [ ] **Step 1:** Write a test asserting emitted source is not debug `prettyTypeName()` text and reparses successfully.
- [ ] **Step 2:** Run `python3 -m pytest tests/frontend/test_emitter_smoke.py -q`; expected FAIL with the current stub.
- [ ] **Step 3:** Restore the implementation matching `config_rev.h` and add it explicitly to CMake. Remove duplicate stub definitions only.
- [ ] **Step 4:** Run `JOBS=1 src/myfuzz/frontend/scripts/build_frontend.sh && python3 -m pytest tests/frontend/test_emitter_smoke.py -q`; expected PASS.
- [ ] **Step 5:** Commit and push:

```bash
git add src/myfuzz/frontend/vendor/verilator/src/V3EmitV.cpp src/myfuzz/frontend/src/MyFuzzFrontendStubs.cpp src/myfuzz/frontend/CMakeLists.txt tests/frontend/test_emitter_smoke.py
git commit -m "feat(frontend): [A7] restore version-matched V3EmitV" -m "Node: A7\nTests: frontend build; emitter smoke pytest"
git push origin feature/composition-core
```

## Task A8: Composition CLI and Reparse Gate

**Files:** create `src/myfuzz/scripts/composition_api.py` and `scripts/generate_composition.py`; modify `src/myfuzz/scripts/frontend_api.py` and `run_design_flow.py`; test `tests/composition/test_cli.py`.

**Command:** `python3 scripts/generate_composition.py --config <declared-input.json> --frontend <hdl-facts.json> --top-k 3 --out-dir <candidate-dir>` writes one directory per valid candidate with `composition_ir.json`, `generated_top.sv`, `candidate_manifest.json`, diagnostics, and graph hash.

- [ ] **Step 1:** Write the failing CLI test for valid output, deterministic hashes, missing-role rejection, and fewer-than-K valid candidates.
- [ ] **Step 2:** Implement orchestration only: load declarations, call facts API, search Top-K, call C++ builder/emitter, reparse through the existing frontend, and write manifests. No target-specific condition belongs here.
- [ ] **Step 3:** Run `python3 -m pytest tests/composition tests/frontend -q`; expected PASS with the single-core frontend build present.
- [ ] **Step 4:** Commit and push:

```bash
git add src/myfuzz/scripts src/myfuzz/composition scripts/generate_composition.py tests/composition
git commit -m "feat(composition): [A8] add Top-K composition CLI" -m "Node: A8\nTests: composition and frontend pytest"
git push origin feature/composition-core
```

## Task A9: Composition Lane Gate

- [ ] **Step 1:** Run `python3 scripts/check_identifier_policy.py --paths src/myfuzz/composition src/myfuzz/frontend/src/MyFuzzCompositionAstBuilder.cpp src/myfuzz/frontend/src/MyFuzzFrontendFacts.cpp`.
- [ ] **Step 2:** Run `JOBS=1 src/myfuzz/frontend/scripts/build_frontend.sh && python3 -m pytest tests/contracts tests/composition tests/frontend -q`.
- [ ] **Step 3:** Publish the completion node:

```bash
git commit --allow-empty -m "test(composition): [A9] pass composition lane gate" -m "Node: A9\nTests: identifier policy; frontend build; contracts/composition/frontend pytest"
git push origin feature/composition-core
```

The lane is eligible for integration node I4 only after the remote commit is visible.
