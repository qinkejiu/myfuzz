# Local Protocol Template Contract Registry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Register versioned read-only contracts for five CPU-facing protocols and three native target families without enabling a runtime.

**Architecture:** Frozen contracts declare protocol/direction, required/optional roles, field shapes, typed profile predicates and finite limits. Selection uses protocol, endpoint function, resolved roles/directions/widths and typed capabilities, never component identifiers or physical port-name heuristics. Native completion requires explicit selection because port shapes cannot prove handshake meaning. V2 endpoint policies record selected contract identity with runtime_effective=false.

**Tech Stack:** Python 3.12, frozen dataclasses, unittest, ProfileBinding and pure tuning validation.

## Global Constraints

- No runtime_renderer, driver, build or session modifications.
- No Generated/RTL operational claim; selection proves configuration compatibility only.
- Missing/unknown roles, inconsistent optional groups, wrong widths/directions and absent typed semantic facts refuse.
- No source/RTL mutations, component-name branches or parsing semantic prose.
- Native completion is explicit-only; real DUT adherence remains untested.
- Target Wishbone address units/select implementation/CYC-ACK semantics require typed profile facts.

### Task 1: Registry and Selection

**Files:** Create src/myfuzz/local_harness/template_contracts.py and tests/local_harness/test_template_contracts.py.

**Interfaces:** list_template_contracts() -> tuple[ProtocolTemplateContract,...]; select_template_contract(endpoint, capabilities, *, template_id=None, template_version=None, variant_id=None) -> SelectedTemplateContract. Explicit IDs must be supplied together. Selected document/hash includes physical bindings and finite boundaries.

- [ ] Write failing inventory and selection tests using resolved fields with arbitrary physical names.
- [ ] Register CPU OBI read-only/read-write, AXI4 single-beat, AXI4-Lite no-response-code, Wishbone no-err-stall and explicit native completion. Register target TL-UL with required integrity/user, APB3 full-word-only, and typed word-addressed/addressless Wishbone.
- [ ] Enforce scalar controls, address/data consistency, byte lanes and ID/source response roundtrip; unknown/missing roles refuse. State future runtime policies for unsupported bursts, exclusives, atomics and sidebands.
- [ ] Run `PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_template_contracts -q`.

### Task 2: V2 Configuration-only Endpoint Policy

**Files:** Modify tuning.py and extend test_template_contracts.py; update only an unavailable-contract negative in test_tuning.py if necessary.

**Interfaces:** validate_local_harness_tuning adds selected contract evidence to its canonical document. Exact registry IDs/version/variant and max_outstanding=1 are required; other unavailable tuning remains refused.

- [ ] Test accepted OBI policy still has runtime_effective=false; wrong version/variant and >1 outstanding refuse.

```python
policy = {'endpoint_id': 'memory', 'template_id': 'cpu.obi',
          'template_version': '1', 'variant_id': 'read-write', 'max_outstanding': 1}
```

- [ ] Observe failure before enabling registry-backed policy validation, then add minimal selection branch.
- [ ] Assert actual bound shape and selected variant affect contract/configuration identity.
- [ ] Run local_harness regressions with explicit source-fixture ROOT overrides if needed; no source symlinks.

### Task 3: Evidence and Commit

**Files:** Create docs/reports/local-template-contracts-20261004.md.

- [ ] Select contracts against current full CPU/IP profiles and bindings; record actual acceptances/refusals and native explicit-only behavior.
- [ ] Record test counts, exact boundaries and remaining runtime work.
- [ ] Run `git diff --check`, confirm prohibited files unchanged, commit with `git commit -m 'feat: register versioned local protocol template contracts'`; do not push.

Approved semantic refinement: CPU Wishbone without a typed address_units fact also refuses automatic selection; explicit byte-address policy remains contract-only. Target registered-ACK variants use a one-cycle STB pulse and distinguish held CYC versus CYC ignored. Contradictory typed optional semantics refuse even under explicit selection.
