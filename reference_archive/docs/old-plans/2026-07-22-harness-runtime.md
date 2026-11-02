# Protocol, Harness, and Experiment Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the target-independent Terminal B pipeline that compiles declared protocol semantics, derives compact dependency views, emits fair RFuzz harness bundles, schedules jobs within a low-memory budget, and reports per-candidate experiments.

**Architecture:** Terminal B consumes frozen `composition_ir.v1` and `candidate_manifest.v1` JSON contracts through the shared contract API, never through Terminal A internals. Declarative protocol documents compile to immutable Python records; those records feed a 32-bit-ID CSR dependency graph, reversible replay confidence overlay, deterministic harness compiler, memory-token scheduler, and per-candidate experiment/report pipeline. RFuzz and Verilator are invoked only through injected commands, so all unit and contract tests run with Python 3.12 even when `third_party/rfuzz` is absent.

**Tech Stack:** Python 3.12 standard library (`dataclasses`, `enum`, `hashlib`, `heapq`, `json`, `pathlib`, `resource`, `subprocess`, `tomllib`, `unittest`), generated SystemVerilog, JSON configuration and reports, existing RFuzz command-line flow.

## Global Constraints

- Work only in `.worktrees/harness-runtime` on branch `feature/harness-runtime`; never implement a node in the shared `main` working tree.
- Terminal B owns only `src/myfuzz/protocols/**`, `src/myfuzz/harness/**`, `src/myfuzz/experiments/**`, `configs/experiments/**`, `tests/protocols/**`, `tests/harness/**`, and `tests/experiments/**`.
- Treat `tests/contracts/**` as frozen, read-only fixtures. Consume `tests/contracts/hdl_facts.v2.valid.json`, `tests/contracts/protocol.v1.valid.json`, `tests/contracts/composition_ir.v1.valid.json`, and `tests/contracts/candidate_manifest.v1.valid.json`; do not edit, copy, regenerate, or normalize them in place.
- Import the shared contract API exactly as `from myfuzz.contracts import canonical_bytes, content_hash, validate_contract`; its signatures are `validate_contract(document: object, schema_id: str) -> None`, `canonical_bytes(document: object) -> bytes`, and `content_hash(document: object) -> str`.
- The only semantic inference inputs are stable integer IDs, explicitly declared component/port roles, explicitly declared protocol field bindings, RTL structural/dataflow facts, and protocol constraints. Module, instance, port, net, file, directory, target, and `component_id` text are opaque and must never be parsed, matched, scored, or dispatched on.
- Core source must contain no target lookup table, module-name table, identifier keyword table, fixed RVX/OpenTitan address, or branch such as `if target == "rvx"`. Target-specific selections exist only in `configs/experiments/**` data.
- Protocol plugins are selected only by the explicit protocol ID in input data; component role must not implicitly select a plugin.
- Initial protocol IDs are exactly `ready-valid-mmio`, `apb`, `axi4-lite`, `obi`, and `tl-ul`. TL-UL is limited to one outstanding transaction with no source-ID reordering; AXI burst and full TileLink are rejected capabilities.
- The three harness groups are exactly `flat-direct`, `candidate-direct`, and `candidate-depaware`. Only the latter two may be used to attribute a coverage difference to the harness.
- `candidate-direct` and `candidate-depaware` use the identical candidate, instrumented RTL, coverage universe, raw-bit width, seed set, mutation parameters, and wall-clock or cycle budget. `flat-direct` has a separately reported coverage universe.
- Every raw bit has a deterministic, manifest-recorded purpose. A projector may fold, gate, mask, or remap entropy, but may not drop a sample, draw another random value, wait indefinitely, or extend the fixed cycle budget.
- Static dependency edges are never deleted. Dynamic replay creates an active confidence view; reset-unstable, timed-out, crashed, or non-reproducible observations are inconclusive and cannot count as negative evidence.
- Static graphs use unsigned 32-bit stable IDs and CSR arrays. Dynamic processing handles at most 64 field groups per batch. Replay queues, event logs, and diagnostic buffers are bounded.
- Default low-memory policy is one full Verilator build at a time, no VCD/FST, and fuzz concurrency based on measured/estimated RSS rather than CPU count.
- The current host budget is approximately 7.3 GiB RAM plus 2 GiB swap; the checked-in experiment defaults reserve 6,000,000,000 bytes as the soft usage limit and 7,000,000,000 bytes as the hard usage limit.
- Use only Python 3.12 standard-library `unittest`; do not add `pytest` or another package dependency.
- Each node `B<n>` is one atomic commit. Before committing run the node's tests, `git diff --check`, and `git diff --cached --stat`; stage only owned files for that node.
- Commit messages use exactly `<type>(<area>): [B<n>] <result>` followed by a blank line, `Node: B<n>`, and `Tests: <commands actually run>`.
- Push every completed node to GitHub. For B1 use `git push -u origin feature/harness-runtime`; for B2 and later use `git push origin feature/harness-runtime`. Verify with `git ls-remote --exit-code origin refs/heads/feature/harness-runtime` and `git merge-base --is-ancestor HEAD origin/feature/harness-runtime`.
- A node is incomplete until tests, local commit, push, and remote verification all succeed. On push failure retain the local commit, record `pending-push`, do not amend/rebase/force-push, and do not start a dependent node.
- Never use `git push --force` or `--force-with-lease`; after first publication, absorb a changed shared baseline with a merge commit.
- Do not commit credentials, machine-specific absolute paths, build outputs, binaries, VCD/FST files, complete corpora, or large raw logs. Small deterministic fixtures, manifests, summaries, and reproducer commands are allowed.

## Frozen Cross-Terminal Data Boundary

Terminal B reads these `hdl_facts.v2` members for static dependency evidence and flat aggregation:

```text
schema_version: "hdl_facts.v2"
modules[]: {id: uint32, ports: [uint32]}
ports[]: {id: uint32, module_id: uint32, direction: "input" | "output" | "inout", width: positive int, signed: bool}
instances[]: {id: uint32, parent_module_id: uint32, module_id: uint32, pin_bindings: [{port_id: uint32, expression_id: uint32}]}
dataflow_edges[]: {source_id: uint32, target_id: uint32, kind: string, provenance: "rtl"}
control_edges[]: {source_id: uint32, target_id: uint32, kind: string, provenance: "rtl"}
local_address_decode[]: {address_field_port_id: uint32, state_id: uint32, offset: uint64, size: positive int}
```

Original RTL names and source paths retained elsewhere in `hdl_facts.v2` are diagnostics/emission metadata and are not graph or policy inputs.

Terminal B compiles this concrete `protocol.v1` shape:

```text
schema_version: "protocol.v1"
protocol_id: string
plugin_version: semantic-version string
channels[]: {
  id: uint32,
  role: string,
  fields[]: {
    id: uint32,
    role: string,
    direction: "initiator_to_target" | "target_to_initiator",
    width: {min: positive int, max: positive int},
    required: bool
  }
}
temporal_rules[]: {
  id: uint32,
  kind: "stable_until_handshake" | "response_after_request" | "phase_sequence",
  antecedent_field_id: uint32,
  consequent_field_id: uint32,
  min_cycles: nonnegative int,
  max_cycles: int in 0..65535
}
dependency_edges[]: {source_field_id: uint32, target_field_id: uint32, kind: string}
legal_adapters[]: string
projection_actions[]: {
  id: uint32,
  kind: "direct" | "fold_xor" | "gate" | "mask" | "event_select" | "delay_select",
  field_ids: list[uint32],
  category: "protocol_legality" | "progress" | "dependency_consistency" | "bounded_event_rarity" | "address_validity" | "direct",
  max_state_bits: int in 0..4096
}
capability_limits: object with scalar boolean/integer/string values
```

Unknown compatible members survive canonical hashing but are ignored by the v1 compiler. A changed major schema is rejected by the shared contract validator.

Terminal B reads the following `composition_ir.v1` members and no Verilator objects:

```text
schema_version: "composition_ir.v1"
candidate_id: string
parent_input_hash: lowercase hex string
graph_hash: lowercase hex string
components[]: {id: uint32, module_id: uint32, role: string}
nets[]: {id: uint32, width: positive int, driver_port_id: uint32, sink_port_ids: list[uint32]}
endpoint_bindings[]: {
  endpoint_id: uint32,
  component_id: uint32,
  protocol_id: string,
  side: "initiator" | "target",
  fields[]: {field_role: string, port_id: uint32}
}
address_regions[]: {component_id: uint32, base: uint64, size: positive int, provenance: string}
external_ports[]: {port_id: uint32, direction: "input" | "output" | "inout", width: positive int, semantic_role: string}
evidence[]: object
assumptions[]: object
```

Terminal B reads these `candidate_manifest.v1` members:

```text
schema_version: "candidate_manifest.v1"
candidate_id: string
composition_ir_hash: lowercase hex string
top: {module: string, source: string, content_hash: lowercase hex string}
top_port_abi[]: {port_id: uint32, emitted_name: string, direction: string, width: positive int}
validation: {status: "valid" | "invalid", parse: string, link: string, width: string, compile: string, smoke: string}
coverage_universe[]: {
  point_id: uint32,
  stable_source_id: string,
  component_id: uint32,
  component_role: string,
  source: {file_id: uint32, line: positive int, column: nonnegative int}
}
build_cache_key: string
```

Names such as `top.module`, `top_port_abi[].emitted_name`, and source labels may be copied into generated SV or diagnostics. They must not affect protocol selection, dependency edges, projection policy, scheduling priority, result ranking, or experiment grouping.

Terminal B returns a deterministic manifest fragment merged later by the integration node:

```text
harnesses: {
  "flat-direct": {source: string, module: string, content_hash: string, raw_width: int, destinations: list[RawDestination], mapping: list[RawBitUse]},
  "candidate-direct": {source: string, module: string, content_hash: string, raw_width: int, destinations: list[RawDestination], mapping: list[RawBitUse]},
  "candidate-depaware": {source: string, module: string, content_hash: string, raw_width: int, destinations: list[RawDestination], mapping: list[RawBitUse]}
}
dependency_graph: {source: string, content_hash: string, node_count: int, edge_count: int}
runtime: {build_cache_key: string, peak_rss_bytes: int | null, status: string}
```

`RawBitUse` has exactly:

```python
@dataclass(frozen=True, slots=True)
class RawBitUse:
    raw_lo: int
    raw_hi: int       # inclusive
    destination_id: int
    destination_lo: int
    action: str       # direct | fold_xor | gate | mask | event_select | delay_select
    category: str     # protocol_legality | progress | dependency_consistency | bounded_event_rarity | address_validity | direct
```

`RawDestination` has exactly `destination_id: uint32`, `component_id: uint32 | null`, `port_id: uint32`, and `width: positive int`. For candidate harnesses `destination_id` is the top ABI `port_id`; for flat-direct it is a dense integer assigned after sorting `(component_id, port_id)` pairs and is resolved only through the adjacent destinations array.

---

## Execution Preflight

Before B1, use the `using-git-worktrees` skill to create or verify `.worktrees/harness-runtime`, then run:

```bash
test "$(git branch --show-current)" = "feature/harness-runtime"
test -z "$(git status --porcelain)"
test -f tests/contracts/hdl_facts.v2.valid.json
test -f tests/contracts/protocol.v1.valid.json
test -f tests/contracts/composition_ir.v1.valid.json
test -f tests/contracts/candidate_manifest.v1.valid.json
PYTHONPATH=src python3 -c 'from myfuzz.contracts import canonical_bytes, content_hash, validate_contract; print("contracts-ready")'
git merge-base --is-ancestor c3171af HEAD
```

Expected: every `test` and `git merge-base` exits 0, the import command prints `contracts-ready`, and the worktree is clean. If the frozen-contract baseline is newer than `c3171af`, merge that published baseline before running this preflight; never recreate the fixtures from Terminal B.

### Task B1: Protocol DSL Compiler and Ready/Valid MMIO Plugin

**Files:**
- Create: `src/myfuzz/protocols/__init__.py`
- Create: `src/myfuzz/protocols/model.py`
- Create: `src/myfuzz/protocols/compiler.py`
- Create: `src/myfuzz/protocols/builtin.py`
- Create: `src/myfuzz/protocols/plugins/__init__.py`
- Create: `src/myfuzz/protocols/plugins/ready_valid_mmio.json`
- Create: `tests/protocols/__init__.py`
- Create: `tests/protocols/test_compiler.py`

**Interfaces:**
- Consumes: `validate_contract(document, "protocol.v1")`, `canonical_bytes(document)`, and frozen `tests/contracts/protocol.v1.valid.json`.
- Produces: `compile_protocol(document: object) -> ProtocolSpec`, `load_builtin_protocol(protocol_id: str) -> ProtocolSpec`, `ProtocolSpec.fields_by_role(side: EndpointSide) -> tuple[FieldSpec, ...]`, and `ProtocolSpec.document_hash: str`.
- `compile_protocol` rejects booleans where integers are required, duplicate channel/field/rule IDs, field widths outside `1..2**31-1`, undeclared dependency endpoints, temporal bounds outside `0..65535`, and unsupported capability requests.

- [ ] **Step 1: Write the failing compiler tests**

Create `src/myfuzz/protocols/plugins/__init__.py` and both test package marker files empty, then put this executable test shape in `tests/protocols/test_compiler.py`:

```python
from __future__ import annotations

import json
import unittest
from pathlib import Path

from myfuzz.protocols import EndpointSide, ProtocolError, compile_protocol, load_builtin_protocol


ROOT = Path(__file__).resolve().parents[2]


class ProtocolCompilerTest(unittest.TestCase):
    def test_frozen_contract_compiles_deterministically(self) -> None:
        document = json.loads((ROOT / "tests/contracts/protocol.v1.valid.json").read_text())
        left = compile_protocol(document)
        right = compile_protocol(dict(reversed(list(document.items()))))
        self.assertEqual(left, right)
        self.assertEqual(left.document_hash, right.document_hash)

    def test_ready_valid_plugin_has_explicit_roles_and_bounded_response(self) -> None:
        spec = load_builtin_protocol("ready-valid-mmio")
        roles = {field.role for field in spec.fields_by_role(EndpointSide.INITIATOR)}
        self.assertGreaterEqual(roles, {"request.valid", "request.ready", "request.address", "response.valid"})
        self.assertTrue(all(rule.max_cycles <= 65535 for rule in spec.temporal_rules))

    def test_unknown_plugin_is_rejected_without_name_guessing(self) -> None:
        with self.assertRaisesRegex(ProtocolError, "unsupported protocol ID: opaque-7"):
            load_builtin_protocol("opaque-7")

    def test_duplicate_field_id_is_rejected(self) -> None:
        document = json.loads((ROOT / "src/myfuzz/protocols/plugins/ready_valid_mmio.json").read_text())
        document["channels"][0]["fields"].append(dict(document["channels"][0]["fields"][0]))
        with self.assertRaisesRegex(ProtocolError, "duplicate field ID"):
            compile_protocol(document)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the tests and confirm the red state**

Run:

```bash
PYTHONPATH=src python3 -m unittest tests.protocols.test_compiler -v
```

Expected: `ERROR` with `ImportError: cannot import name 'EndpointSide' from 'myfuzz.protocols'`.

- [ ] **Step 3: Implement the immutable model and compiler**

Implement these exact public types in `src/myfuzz/protocols/model.py`:

```python
class ProtocolError(ValueError):
    """Raised when a declared protocol document is inconsistent."""
class EndpointSide(str, Enum):
    INITIATOR = "initiator"
    TARGET = "target"

@dataclass(frozen=True, slots=True)
class FieldSpec:
    id: int
    channel_id: int
    role: str
    direction: str
    width_min: int
    width_max: int
    required: bool

@dataclass(frozen=True, slots=True)
class TemporalRule:
    id: int
    kind: str
    antecedent_field_id: int
    consequent_field_id: int
    min_cycles: int
    max_cycles: int

@dataclass(frozen=True, slots=True)
class DependencySpec:
    source_field_id: int
    target_field_id: int
    kind: str

@dataclass(frozen=True, slots=True)
class ProjectionAction:
    id: int
    kind: str
    field_ids: tuple[int, ...]
    category: str
    max_state_bits: int

@dataclass(frozen=True, slots=True)
class ProtocolSpec:
    protocol_id: str
    plugin_version: str
    fields: tuple[FieldSpec, ...]
    temporal_rules: tuple[TemporalRule, ...]
    dependencies: tuple[DependencySpec, ...]
    projection_actions: tuple[ProjectionAction, ...]
    legal_adapters: tuple[str, ...]
    capability_limits: tuple[tuple[str, int | bool | str], ...]
    document_hash: str

    def fields_by_role(self, side: EndpointSide) -> tuple[FieldSpec, ...]:
        if not isinstance(side, EndpointSide):
            raise TypeError("side must be EndpointSide")
        return self.fields
```

`compile_protocol(document: object) -> ProtocolSpec` must first call `validate_contract(document, "protocol.v1")`, then validate cross-references and bounds, sort every repeated object by its integer ID, freeze capability entries by key, and set `document_hash=content_hash(document)`. It may read only DSL keys and declared role strings; it must not inspect any RTL identifier.

Implement `load_builtin_protocol(protocol_id: str) -> ProtocolSpec` by scanning `importlib.resources.files("myfuzz.protocols.plugins").iterdir()` in filename order, compiling every `.json` document, rejecting duplicate declared `protocol_id` values, and selecting by exact equality with the requested ID. Filenames and protocol-ID substrings never participate in matching. Cache the immutable compiled tuple after the first scan. This makes a new protocol a data-only plugin addition and avoids a Python protocol/target dispatch table.

Create `ready_valid_mmio.json` with this exact content:

```json
{
  "schema_version": "protocol.v1",
  "protocol_id": "ready-valid-mmio",
  "plugin_version": "1.0.0",
  "channels": [
    {
      "id": 0,
      "role": "request",
      "fields": [
        {"id": 0, "role": "request.valid", "direction": "initiator_to_target", "width": {"min": 1, "max": 1}, "required": true},
        {"id": 1, "role": "request.ready", "direction": "target_to_initiator", "width": {"min": 1, "max": 1}, "required": true},
        {"id": 2, "role": "request.address", "direction": "initiator_to_target", "width": {"min": 1, "max": 64}, "required": true},
        {"id": 3, "role": "request.write", "direction": "initiator_to_target", "width": {"min": 1, "max": 1}, "required": false},
        {"id": 4, "role": "request.data", "direction": "initiator_to_target", "width": {"min": 1, "max": 1024}, "required": false},
        {"id": 5, "role": "request.byte_enable", "direction": "initiator_to_target", "width": {"min": 1, "max": 128}, "required": false}
      ]
    },
    {
      "id": 1,
      "role": "response",
      "fields": [
        {"id": 6, "role": "response.valid", "direction": "target_to_initiator", "width": {"min": 1, "max": 1}, "required": true},
        {"id": 7, "role": "response.ready", "direction": "initiator_to_target", "width": {"min": 1, "max": 1}, "required": true},
        {"id": 8, "role": "response.data", "direction": "target_to_initiator", "width": {"min": 1, "max": 1024}, "required": false},
        {"id": 9, "role": "response.error", "direction": "target_to_initiator", "width": {"min": 1, "max": 1}, "required": false}
      ]
    }
  ],
  "temporal_rules": [
    {"id": 0, "kind": "stable_until_handshake", "antecedent_field_id": 0, "consequent_field_id": 1, "min_cycles": 0, "max_cycles": 16},
    {"id": 1, "kind": "response_after_request", "antecedent_field_id": 0, "consequent_field_id": 6, "min_cycles": 1, "max_cycles": 16},
    {"id": 2, "kind": "stable_until_handshake", "antecedent_field_id": 6, "consequent_field_id": 7, "min_cycles": 0, "max_cycles": 16}
  ],
  "dependency_edges": [
    {"source_field_id": 0, "target_field_id": 1, "kind": "handshake"},
    {"source_field_id": 0, "target_field_id": 6, "kind": "request_response"},
    {"source_field_id": 2, "target_field_id": 6, "kind": "address_response"},
    {"source_field_id": 6, "target_field_id": 7, "kind": "handshake"}
  ],
  "legal_adapters": ["same-protocol-width-extension"],
  "projection_actions": [
    {"id": 0, "kind": "gate", "field_ids": [0, 1], "category": "protocol_legality", "max_state_bits": 1},
    {"id": 1, "kind": "delay_select", "field_ids": [0, 6], "category": "progress", "max_state_bits": 5},
    {"id": 2, "kind": "fold_xor", "field_ids": [2, 4, 8], "category": "dependency_consistency", "max_state_bits": 0},
    {"id": 3, "kind": "mask", "field_ids": [2], "category": "address_validity", "max_state_bits": 0}
  ],
  "capability_limits": {"max_outstanding": 1, "reordering": false, "bursts": false}
}
```

- [ ] **Step 4: Export the API and run tests**

Export only these names from `src/myfuzz/protocols/__init__.py`:

```python
from .builtin import load_builtin_protocol
from .compiler import compile_protocol
from .model import EndpointSide, ProtocolError, ProtocolSpec

__all__ = ["EndpointSide", "ProtocolError", "ProtocolSpec", "compile_protocol", "load_builtin_protocol"]
```

Run:

```bash
PYTHONPATH=src python3 -m unittest tests.protocols.test_compiler -v
```

Expected: four tests report `ok` and the command ends with `OK`.

- [ ] **Step 5: Check identifier opacity and commit B1**

Run:

```bash
rg -n -i 'rvx|ibex|opentitan|uart|gpio|rv_timer|module_name|port_name|instance_name|signal_name' src/myfuzz/protocols
git diff --check
git add src/myfuzz/protocols tests/protocols
git diff --cached --stat
git commit -m "feat(protocols): [B1] compile declared ready-valid protocol" -m "Node: B1" -m "Tests: PYTHONPATH=src python3 -m unittest tests.protocols.test_compiler -v"
git push -u origin feature/harness-runtime
git ls-remote --exit-code origin refs/heads/feature/harness-runtime
git merge-base --is-ancestor HEAD origin/feature/harness-runtime
```

Expected: `rg` has exit code 1 and no output; diff checks succeed; exactly the B1 files are committed; both remote verification commands exit 0.

### Task B2: APB, AXI4-Lite, OBI, and Limited TL-UL Plugins

**Files:**
- Create: `src/myfuzz/protocols/plugins/apb.json`
- Create: `src/myfuzz/protocols/plugins/axi4_lite.json`
- Create: `src/myfuzz/protocols/plugins/obi.json`
- Create: `src/myfuzz/protocols/plugins/tl_ul.json`
- Create: `tests/protocols/test_builtins.py`

**Interfaces:**
- Consumes: `load_builtin_protocol(protocol_id: str) -> ProtocolSpec` from B1.
- Produces: all five explicit protocol IDs with complete field, bounded temporal, dependency, adapter, projection, and capability declarations.
- APB capability profile supports APB3 and APB4 via declared capability `profile`; AXI4-Lite rejects burst fields; TL-UL requires single outstanding and no source-ID reordering.

- [ ] **Step 1: Write the failing built-in matrix tests**

Create `tests/protocols/test_builtins.py`:

```python
from __future__ import annotations

import unittest

from myfuzz.protocols import load_builtin_protocol


class BuiltinProtocolTest(unittest.TestCase):
    def test_all_declared_plugins_compile(self) -> None:
        expected = {
            "ready-valid-mmio": {"request.valid", "request.address", "response.valid"},
            "apb": {"request.select", "request.enable", "request.address", "response.ready"},
            "axi4-lite": {"write_address.valid", "write_data.valid", "read_address.valid", "read_data.valid"},
            "obi": {"request.req", "request.gnt", "request.address", "response.rvalid"},
            "tl-ul": {"a.valid", "a.opcode", "a.address", "d.valid", "d.opcode"},
        }
        for protocol_id, required_roles in expected.items():
            with self.subTest(protocol_id=protocol_id):
                spec = load_builtin_protocol(protocol_id)
                self.assertGreaterEqual({field.role for field in spec.fields}, required_roles)
                self.assertTrue(spec.dependencies)
                self.assertTrue(spec.projection_actions)

    def test_limited_profiles_are_explicit(self) -> None:
        axi = dict(load_builtin_protocol("axi4-lite").capability_limits)
        tl = dict(load_builtin_protocol("tl-ul").capability_limits)
        apb = dict(load_builtin_protocol("apb").capability_limits)
        self.assertFalse(axi["bursts"])
        self.assertEqual(tl["max_outstanding"], 1)
        self.assertFalse(tl["source_id_reordering"])
        self.assertEqual(apb["profiles"], "APB3,APB4")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Confirm missing plugin documents fail**

Run:

```bash
PYTHONPATH=src python3 -m unittest tests.protocols.test_builtins -v
```

Expected: four subtests fail with `ProtocolError: unsupported protocol ID` for `apb`, `axi4-lite`, `obi`, and `tl-ul`.

- [ ] **Step 3: Add complete declarative documents**

For each file, provide every required `protocol.v1` member and use these exact semantic field sets:

```text
apb request: select, enable, write, address, write_data, byte_enable
apb response: ready, read_data, slave_error
axi4-lite write address: valid, ready, address, protection
axi4-lite write data: valid, ready, data, strobe
axi4-lite write response: valid, ready, response
axi4-lite read address: valid, ready, address, protection
axi4-lite read data: valid, ready, data, response
obi request: req, gnt, address, write, byte_enable, write_data
obi response: rvalid, read_data, error
tl-ul a: valid, ready, opcode, param, size, source, address, mask, data
tl-ul d: valid, ready, opcode, param, size, source, sink, denied, data, corrupt
```

Every handshake gets an explicit dependency edge and a finite response bound. Projection actions must be limited to legality, progress, dependency consistency, bounded event rarity, and address validity. Declare legal adapters by protocol capability, never by component or target. In `tl_ul.json`, set `max_outstanding` to `1`, `source_id_reordering` to `false`, and `coherence` to `false`; in `axi4_lite.json`, set `bursts` and `ids` to `false`.

Assign field IDs consecutively from zero in the displayed field order and channel IDs consecutively in channel order. Scalar handshake/control/error fields are exactly one bit; AXI response fields are two bits; AXI protection is three bits; TL-UL opcode/param/size are three bits; addresses allow widths `1..64`; data allows `8..1024`; byte-enable/strobe/mask allows `1..128`; TL source/sink allows `1..16`. Use `max_cycles=16` for every harness response/progress rule. APB has a `phase_sequence(select, enable)` rule and request-to-ready rule. AXI4-Lite has stable-until-handshake for all five valid/ready pairs plus write-address/write-data-to-write-response and read-address-to-read-data rules. OBI has request-to-grant and grant-to-response rules. TL-UL has stable-until-handshake for A and D plus A-to-D response. Each address field gets one `mask/address_validity` action, each valid/ready pair gets one `gate/protocol_legality` action, each response gets one `delay_select/progress` action, and payload fields get one `fold_xor/dependency_consistency` action. These are normative protocol declarations; do not add branch-targeting actions.

- [ ] **Step 4: Run the complete protocol suite**

Run:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests/protocols -v
```

Expected: all protocol tests report `ok`; final status is `OK`.

- [ ] **Step 5: Check for target tables, commit, and push B2**

Run:

```bash
rg -n -i 'rvx|ibex|opentitan|uart|gpio|rv_timer|module_name|port_name|instance_name|signal_name' src/myfuzz/protocols tests/protocols
git diff --check
git add src/myfuzz/protocols/plugins tests/protocols/test_builtins.py
git diff --cached --stat
git commit -m "feat(protocols): [B2] add common bus protocol profiles" -m "Node: B2" -m "Tests: PYTHONPATH=src python3 -m unittest discover -s tests/protocols -v"
git push origin feature/harness-runtime
git ls-remote --exit-code origin refs/heads/feature/harness-runtime
git merge-base --is-ancestor HEAD origin/feature/harness-runtime
```

Expected: `rg` has exit code 1 and no output; the suite is green; the B2 commit is visible on the remote branch.

### Task B3: Compact Static Dependency CSR Graph

**Files:**
- Create: `src/myfuzz/harness/__init__.py`
- Create: `src/myfuzz/harness/dependency_graph.py`
- Create: `tests/harness/__init__.py`
- Create: `tests/harness/test_dependency_graph.py`

**Interfaces:**
- Consumes: validated `hdl_facts.v2`, validated `composition_ir.v1`, and compiled `ProtocolSpec` values selected by explicit endpoint protocol IDs.
- Produces: `build_static_graph(hdl_facts: object, composition_ir: object, protocols: Mapping[str, ProtocolSpec]) -> CsrGraph`.
- `CsrGraph` exposes `node_ids: tuple[int, ...]`, `row_offsets: tuple[int, ...]`, `column_indices: tuple[int, ...]`, `edge_kinds: tuple[str, ...]`, `neighbors(node_id: int) -> tuple[int, ...]`, `has_edge(source_id: int, target_id: int) -> bool`, and `to_document() -> dict[str, object]`.

- [ ] **Step 1: Write failing CSR tests against the frozen IR**

Create `tests/harness/test_dependency_graph.py` with tests that load and validate the frozen facts and IR, load only protocol IDs explicitly present in `endpoint_bindings`, call `build_static_graph`, and assert:

```python
self.assertEqual(graph.node_ids, tuple(sorted(graph.node_ids)))
self.assertEqual(len(graph.row_offsets), len(graph.node_ids) + 1)
self.assertEqual(graph.row_offsets[0], 0)
self.assertEqual(graph.row_offsets[-1], len(graph.column_indices))
self.assertEqual(len(graph.column_indices), len(graph.edge_kinds))
self.assertTrue(all(0 <= node_id <= 0xFFFF_FFFF for node_id in graph.node_ids))
self.assertEqual(graph, build_static_graph(reordered_facts, reordered_ir, protocols))
```

Also add tests where duplicate edges collapse deterministically, an ID of `0x1_0000_0000` raises `DependencyGraphError`, and copying only identifier text fields to deliberately misleading strings leaves `to_document()` unchanged.

- [ ] **Step 2: Run and confirm the graph API is absent**

Run:

```bash
PYTHONPATH=src python3 -m unittest tests.harness.test_dependency_graph -v
```

Expected: import fails because `myfuzz.harness.dependency_graph` does not exist.

- [ ] **Step 3: Implement graph construction**

Use `import bisect` and these exact records in `dependency_graph.py`:

```python
class DependencyGraphError(ValueError):
    """Raised when stable IDs cannot form a valid compact graph."""

@dataclass(frozen=True, order=True, slots=True)
class DependencyEdge:
    source_id: int
    target_id: int
    kind: str
    provenance: str

@dataclass(frozen=True, slots=True)
class CsrGraph:
    node_ids: tuple[int, ...]
    row_offsets: tuple[int, ...]
    column_indices: tuple[int, ...]
    edge_kinds: tuple[str, ...]
    provenances: tuple[str, ...]
    graph_hash: str

    def neighbors(self, node_id: int) -> tuple[int, ...]:
        index = bisect.bisect_left(self.node_ids, node_id)
        if index == len(self.node_ids) or self.node_ids[index] != node_id:
            return ()
        return self.column_indices[self.row_offsets[index]:self.row_offsets[index + 1]]

    def has_edge(self, source_id: int, target_id: int) -> bool:
        return target_id in self.neighbors(source_id)

    def to_document(self) -> dict[str, object]:
        return {
            "schema_version": "dependency_graph.v1",
            "node_ids": list(self.node_ids),
            "row_offsets": list(self.row_offsets),
            "column_indices": list(self.column_indices),
            "edge_kinds": list(self.edge_kinds),
            "provenances": list(self.provenances),
            "graph_hash": self.graph_hash,
        }
```

Call `validate_contract(hdl_facts, "hdl_facts.v2")` and `validate_contract(composition_ir, "composition_ir.v1")`. Derive edges only from numeric RTL dataflow/control facts, numeric endpoint/field bindings, numeric net driver/sink relationships, declared local/absolute address regions, and protocol dependency records. Import `bisect` for stable CSR lookup. Intern protocol/edge kind text once, deduplicate `DependencyEdge`, sort by `(source_id, target_id, kind, provenance)`, build CSR offsets, serialize only integers and edge metadata, and calculate `graph_hash=content_hash(document_without_hash)`.

Do not include or access module names, port names, component IDs as text, top names, file paths, or target labels. Use an explicit numeric namespace tag in the high four bits when deriving field-state nodes, and fail if an input ID already occupies reserved namespace bits.

- [ ] **Step 4: Export and run graph tests**

Export `CsrGraph`, `DependencyGraphError`, and `build_static_graph` from `src/myfuzz/harness/__init__.py`, then run:

```bash
PYTHONPATH=src python3 -m unittest tests.harness.test_dependency_graph -v
```

Expected: every CSR, ordering, overflow, duplicate, and misleading-name test reports `ok`.

- [ ] **Step 5: Commit and publish B3**

Run:

```bash
rg -n -i 'module_name|port_name|instance_name|signal_name|file_name|target_name|rvx|ibex|opentitan' src/myfuzz/harness/dependency_graph.py
git diff --check
git add src/myfuzz/harness tests/harness
git diff --cached --stat
git commit -m "feat(harness): [B3] build compact static dependency graph" -m "Node: B3" -m "Tests: PYTHONPATH=src python3 -m unittest tests.harness.test_dependency_graph -v"
git push origin feature/harness-runtime
git ls-remote --exit-code origin refs/heads/feature/harness-runtime
git merge-base --is-ancestor HEAD origin/feature/harness-runtime
```

Expected: identifier scan has no matches; only B3 files are committed; remote checks exit 0.

### Task B4: Reversible Replay Confidence Overlay

**Files:**
- Create: `src/myfuzz/harness/replay.py`
- Create: `tests/harness/test_replay.py`

**Interfaces:**
- Consumes: immutable `CsrGraph` and field-group observations with at most 64 groups.
- Produces: `ReplayObservation`, `ConfidenceModel`, `ConfidenceModel.observe(observation: ReplayObservation) -> None`, `ConfidenceModel.active_view() -> ActiveDependencyView`, and bounded `ReplayQueue`.
- An edge is active when `positive_count > 0` or `negative_count < negative_threshold`; static membership is immutable and always available through `ActiveDependencyView.static_graph`.

- [ ] **Step 1: Write failing confidence and bounded-memory tests**

Create `tests/harness/test_replay.py` covering these exact transitions:

```python
model = ConfidenceModel(graph, negative_threshold=3)
model.observe(ReplayObservation(0, 0, edge, True, True, False, False, frozenset({"coverage"})))
self.assertTrue(model.active_view().is_active(edge))

for sequence in range(3):
    model.observe(ReplayObservation(sequence + 1, 0, edge, True, True, False, False, frozenset()))
self.assertFalse(model.active_view().is_active(edge))
self.assertTrue(graph.has_edge(*edge))

before = model.snapshot()
model.observe(ReplayObservation(4, 0, edge, False, False, True, False, frozenset()))
after = model.snapshot()
self.assertEqual(before["edges"][0]["negative_count"], after["edges"][0]["negative_count"])
self.assertEqual(before["edges"][0]["inconclusive_count"] + 1, after["edges"][0]["inconclusive_count"])
```

Add cases for timeout, crash, reset instability, non-reproducibility, a positive observation reactivating an edge, `field_group_id=64` rejection, deterministic snapshots, `make_replay_pair` changing only the requested inclusive bit range, `classify_replay` comparing coverage/state/protocol digests, and `ReplayQueue(capacity=2)` retaining only the newest two observations.

- [ ] **Step 2: Run and verify the missing replay module**

Run:

```bash
PYTHONPATH=src python3 -m unittest tests.harness.test_replay -v
```

Expected: import error for `myfuzz.harness.replay`.

- [ ] **Step 3: Implement the exact replay model**

Implement:

```python
@dataclass(frozen=True, slots=True)
class ReplayObservation:
    sequence: int
    field_group_id: int
    edge: tuple[int, int]
    reproducible: bool
    reset_stable: bool
    timed_out: bool
    crashed: bool
    changed_digests: frozenset[str]

@dataclass(frozen=True, slots=True)
class ReplayPair:
    baseline: bytes
    variant: bytes
    raw_lo: int
    raw_hi: int

@dataclass(frozen=True, slots=True)
class ReplayDigests:
    coverage: bytes
    state: bytes
    protocol_events: bytes

@dataclass(frozen=True, slots=True)
class EdgeConfidence:
    positive_count: int = 0
    negative_count: int = 0
    inconclusive_count: int = 0

@dataclass(frozen=True, slots=True)
class ActiveDependencyView:
    static_graph: CsrGraph
    active_edges: frozenset[tuple[int, int]]
    epoch: int
    def is_active(self, edge: tuple[int, int]) -> bool:
        return edge in self.active_edges

class ConfidenceModel:
    def __init__(self, static_graph: CsrGraph, negative_threshold: int = 3) -> None:
        if negative_threshold < 2:
            raise ValueError("negative_threshold must be >= 2")
        self.static_graph = static_graph
        self.negative_threshold = negative_threshold
        self._edges: dict[tuple[int, int], EdgeConfidence] = {}
        self._epoch = 0

    def observe(self, observation: ReplayObservation) -> None:
        if not 0 <= observation.field_group_id < 64:
            raise ValueError("field_group_id must be in 0..63")
        if not self.static_graph.has_edge(*observation.edge):
            raise ValueError("observation edge is not in the static graph")
        old = self._edges.get(observation.edge, EdgeConfidence())
        conclusive = (
            observation.reproducible and observation.reset_stable
            and not observation.timed_out and not observation.crashed
        )
        if not conclusive:
            new = replace(old, inconclusive_count=old.inconclusive_count + 1)
        elif observation.changed_digests:
            new = EdgeConfidence(old.positive_count + 1, 0, old.inconclusive_count)
        else:
            new = replace(old, negative_count=old.negative_count + 1)
        self._edges[observation.edge] = new
        self._epoch += 1

    def active_view(self) -> ActiveDependencyView:
        active: set[tuple[int, int]] = set()
        for row, source_id in enumerate(self.static_graph.node_ids):
            start, stop = self.static_graph.row_offsets[row:row + 2]
            for target_id in self.static_graph.column_indices[start:stop]:
                edge = (source_id, target_id)
                score = self._edges.get(edge, EdgeConfidence())
                if score.positive_count > 0 or score.negative_count < self.negative_threshold:
                    active.add(edge)
        return ActiveDependencyView(self.static_graph, frozenset(active), self._epoch)

    def snapshot(self) -> dict[str, object]:
        rows = [
            {"source_id": source, "target_id": target, **asdict(score)}
            for (source, target), score in sorted(self._edges.items())
        ]
        return {"epoch": self._epoch, "edges": rows}

class ReplayQueue:
    def __init__(self, capacity: int) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self.capacity = capacity
        self._items: deque[ReplayObservation] = deque(maxlen=capacity)

    def append(self, observation: ReplayObservation) -> None:
        self._items.append(observation)

    def items(self) -> tuple[ReplayObservation, ...]:
        return tuple(self._items)
```

Import `asdict` and `replace` from `dataclasses`, plus `deque` from `collections`. Implement `make_replay_pair(stimulus: bytes, raw_lo: int, raw_hi: int) -> ReplayPair` exactly as follows: reject `raw_lo < 0`, `raw_hi < raw_lo`, or `raw_hi >= len(stimulus) * 8`; convert the little-endian bytes to an integer, XOR `((1 << (raw_hi - raw_lo + 1)) - 1) << raw_lo`, convert back to the original byte length, and return both byte strings. Implement `classify_replay(baseline: ReplayDigests, variant: ReplayDigests) -> frozenset[str]` by comparing each corresponding digest and returning the frozen set of changed labels. An observation is conclusive only when reproducible, reset-stable, not timed out, not crashed, and its edge exists in the static graph. A nonempty `changed_digests` is positive; an empty set is negative. A positive observation resets the edge's negative count to zero. Inconclusive observations increment only `inconclusive_count`. Store confidence by edge tuple, not by strings; use `collections.deque(maxlen=capacity)` for the queue.

- [ ] **Step 4: Run harness tests and a memory bound check**

Run:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests/harness -v
PYTHONPATH=src python3 -c 'from myfuzz.harness.replay import ReplayQueue; q=ReplayQueue(128); print(q.capacity)'
```

Expected: all harness tests pass and the second command prints `128`.

- [ ] **Step 5: Commit and publish B4**

Run:

```bash
git diff --check
git add src/myfuzz/harness/replay.py tests/harness/test_replay.py src/myfuzz/harness/__init__.py
git diff --cached --stat
git commit -m "feat(harness): [B4] add reversible replay confidence model" -m "Node: B4" -m "Tests: PYTHONPATH=src python3 -m unittest discover -s tests/harness -v"
git push origin feature/harness-runtime
git ls-remote --exit-code origin refs/heads/feature/harness-runtime
git merge-base --is-ancestor HEAD origin/feature/harness-runtime
```

Expected: the B4 commit contains only replay API/tests/export; remote verification succeeds.

### Task B5: Deterministic Raw-Bit ABI and Direct Harnesses

**Files:**
- Create: `src/myfuzz/harness/abi.py`
- Create: `src/myfuzz/harness/sv_emit.py`
- Create: `tests/harness/test_direct_harness.py`

**Interfaces:**
- Consumes: validated `hdl_facts.v2`, validated `composition_ir.v1`, validated `candidate_manifest.v1`, and stable numeric top-port ABI.
- Produces: `RawDestination`, `RawBitUse`, `RawBitAbi`, `build_candidate_direct_abi(composition_ir: object, candidate_manifest: object) -> RawBitAbi`, `build_flat_direct_abi(hdl_facts: object, composition_ir: object) -> RawBitAbi`, and `emit_direct_harness(kind: str, hdl_facts: object, composition_ir: object, candidate_manifest: object, raw_abi: RawBitAbi) -> EmittedHarness`.
- Direct maps are contiguous stable-ID-ordered slices with `action="direct"` and `category="direct"`; they never invoke protocol projection.

- [ ] **Step 1: Write failing direct ABI and emitter tests**

In `tests/harness/test_direct_harness.py`, load all three frozen facts/IR/manifest contracts and assert:

```python
abi = build_candidate_direct_abi(composition_ir, manifest)
self.assertEqual([use.raw_lo for use in abi.uses], sorted(use.raw_lo for use in abi.uses))
self.assertEqual(sum(use.raw_hi - use.raw_lo + 1 for use in abi.uses), abi.raw_width)
self.assertEqual({use.action for use in abi.uses}, {"direct"})
self.assertEqual(abi, build_candidate_direct_abi(reordered_ir, reordered_manifest))

emitted = emit_direct_harness("candidate-direct", hdl_facts, composition_ir, manifest, abi)
self.assertIn(f"input logic [{abi.raw_width - 1}:0] rfuzz_input_bits", emitted.source_text)
self.assertNotIn("always_ff", emitted.source_text)
self.assertEqual(emitted.content_hash, content_hash({"source_text": emitted.source_text}))
```

Also assert flat-direct includes every declared component external input, candidate-direct includes only candidate external inputs, output-only ports consume no raw bits, zero input width is rejected, every raw bit belongs to exactly one inclusive interval, and renaming diagnostic/emitted symbols while maintaining bindings changes emitted spelling but not `RawBitAbi`.

- [ ] **Step 2: Confirm direct APIs are absent**

Run:

```bash
PYTHONPATH=src python3 -m unittest tests.harness.test_direct_harness -v
```

Expected: import error for `myfuzz.harness.abi` or `myfuzz.harness.sv_emit`.

- [ ] **Step 3: Implement raw ABI records and builders**

Implement in `abi.py`:

```python
@dataclass(frozen=True, slots=True)
class RawDestination:
    destination_id: int
    component_id: int | None
    port_id: int
    width: int

@dataclass(frozen=True, slots=True)
class RawBitUse:
    raw_lo: int
    raw_hi: int
    destination_id: int
    destination_lo: int
    action: str
    category: str

@dataclass(frozen=True, slots=True)
class RawBitAbi:
    raw_width: int
    destinations: tuple[RawDestination, ...]
    uses: tuple[RawBitUse, ...]
    abi_hash: str
    def validate_total_use(self) -> None:
        if self.raw_width <= 0:
            raise ValueError("raw_width must be positive")
        cursor = 0
        for use in sorted(self.uses, key=lambda item: item.raw_lo):
            if use.raw_lo != cursor or use.raw_hi < use.raw_lo:
                raise ValueError("raw-bit mapping must be contiguous and nonempty")
            cursor = use.raw_hi + 1
        if cursor != self.raw_width:
            raise ValueError("raw-bit mapping does not cover raw_width")
```

Implement `build_candidate_direct_abi` by validating both contracts, joining `external_ports` to `top_port_abi` on numeric `port_id`, selecting declared input/inout ports except explicitly declared `clock` and `reset` semantic roles, sorting by `port_id`, and assigning consecutive slices. Implement `build_flat_direct_abi` by validating facts/IR, joining every declared component's numeric `module_id` to its numeric port records, selecting input/inout ports except ports explicitly bound to declared clock/reset roles, sorting `(component_id, port_id)`, assigning dense local destination IDs, and assigning consecutive slices. Both calculate `abi_hash=content_hash(document_without_hash)`. They may use emitted names only later in SV output lookup, never to select or order ports.

- [ ] **Step 4: Implement pure direct SystemVerilog emission**

Implement in `sv_emit.py`:

```python
@dataclass(frozen=True, slots=True)
class EmittedHarness:
    kind: str
    module_name: str
    source_text: str
    content_hash: str
    raw_abi: RawBitAbi
    counters: tuple[str, ...]
```

Implement the exact public signature `emit_direct_harness(kind: str, hdl_facts: object, composition_ir: object, candidate_manifest: object, raw_abi: RawBitAbi) -> EmittedHarness`. Accept only `candidate-direct` or `flat-direct`. Emit a deterministic module name derived from the first 16 hex digits of `graph_hash`, instantiate the declared generated top for candidate-direct or each declared component for flat-direct, and emit continuous slice assignments only. Drive declared clock/reset ports from dedicated harness `clock`, `reset`, and `io_meta_reset` inputs; these controls never consume raw entropy. Escape/copy Verilog identifiers as syntax; do not interpret their text. Sort declarations and pins by numeric IDs. Use `content_hash({"source_text": source_text})` and end the file with one newline.

- [ ] **Step 5: Run, commit, and push B5**

Run:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests/harness -v
git diff --check
git add src/myfuzz/harness/abi.py src/myfuzz/harness/sv_emit.py src/myfuzz/harness/__init__.py tests/harness/test_direct_harness.py
git diff --cached --stat
git commit -m "feat(harness): [B5] emit deterministic direct harnesses" -m "Node: B5" -m "Tests: PYTHONPATH=src python3 -m unittest discover -s tests/harness -v"
git push origin feature/harness-runtime
git ls-remote --exit-code origin refs/heads/feature/harness-runtime
git merge-base --is-ancestor HEAD origin/feature/harness-runtime
```

Expected: all harness tests pass; only B5 files are in the commit; remote checks exit 0.

### Task B6: Dependency-Aware Projection and Harness Bundle Compiler

**Files:**
- Create: `src/myfuzz/harness/projection.py`
- Create: `src/myfuzz/harness/compiler.py`
- Create: `tests/harness/test_projection.py`
- Create: `tests/harness/test_compiler.py`

**Interfaces:**
- Consumes: `ProtocolSpec`, `CsrGraph`, optional `ActiveDependencyView`, frozen facts/composition/manifest contracts, and direct ABI from B5.
- Produces: `ProjectionPlan`, `project_sample(plan: ProjectionPlan, raw_value: int, state: ProjectionState) -> ProjectionResult`, `compile_harness_bundle(hdl_facts: object, composition_ir: object, candidate_manifest: object, protocols: Mapping[str, ProtocolSpec], active_view: ActiveDependencyView | None = None) -> HarnessBundle`, and `write_harness_bundle(bundle: HarnessBundle, output_dir: Path) -> dict[str, Path]`.
- `HarnessBundle.manifest_fragment() -> dict[str, object]` returns exactly the mergeable fragment defined above, including all three harness hashes and mappings.

- [ ] **Step 1: Write failing projector property tests**

Create table-driven tests in `tests/harness/test_projection.py` that use fixed integer samples, never Python randomness, and assert:

```python
first = project_sample(plan, raw_value=0xA5A5, state=ProjectionState.initial(plan))
second = project_sample(plan, raw_value=0xA5A5, state=ProjectionState.initial(plan))
self.assertEqual(first, second)
self.assertEqual(first.cycles_consumed, 1)
self.assertEqual(first.sample_consumed, True)
self.assertLessEqual(first.next_state.value.bit_length(), plan.max_state_bits)
self.assertEqual(plan.raw_abi.raw_width, direct_abi.raw_width)
self.assertEqual({bit for use in plan.raw_abi.uses for bit in range(use.raw_lo, use.raw_hi + 1)}, set(range(plan.raw_abi.raw_width)))
```

Cover each allowed category, valid request/response ordering for all five plugins, inactive edges reducing priority without fixing a field forever, excess entropy folding via XOR, no extra random source, maximum one output step per input sample, and rejection when a temporal rule lacks a finite bound.

- [ ] **Step 2: Write failing bundle fairness tests**

In `tests/harness/test_compiler.py`, load frozen contracts and explicitly selected plugins, compile twice with semantically reorderable JSON arrays, update the copied manifest's `composition_ir_hash` with `content_hash(reordered_ir)`, and assert identical `HarnessBundle`. Assert candidate-direct and candidate-depaware have equal raw widths; all three keys exist; candidate harnesses reference the same top content hash and coverage universe hash; the manifest fragment contains mapping rows, graph counts, hashes, and no in-memory object addresses or absolute temporary paths. Under `tempfile.TemporaryDirectory`, call `write_harness_bundle` and assert it writes exactly `flat-direct.sv`, `candidate-direct.sv`, `candidate-depaware.sv`, `dependency_graph.v1.json`, and `harness_manifest_fragment.json`; re-read each file and verify its recorded hash.

- [ ] **Step 3: Run and confirm projection/compiler imports fail**

Run:

```bash
PYTHONPATH=src python3 -m unittest tests.harness.test_projection tests.harness.test_compiler -v
```

Expected: import errors for `myfuzz.harness.projection` and `myfuzz.harness.compiler`.

- [ ] **Step 4: Implement bounded deterministic projection**

Implement in `projection.py`:

```python
@dataclass(frozen=True, slots=True)
class ProjectionState:
    value: int
    width: int
    @classmethod
    def initial(cls, plan: "ProjectionPlan") -> "ProjectionState":
        return cls(value=0, width=plan.max_state_bits)

@dataclass(frozen=True, slots=True)
class ProjectionPlan:
    raw_abi: RawBitAbi
    field_order: tuple[int, ...]
    actions: tuple[ProjectionAction, ...]
    max_state_bits: int
    max_temporal_cycles: int
    plan_hash: str

@dataclass(frozen=True, slots=True)
class ProjectionResult:
    driven_fields: tuple[tuple[int, int], ...]
    next_state: ProjectionState
    correction_counts: tuple[tuple[str, int], ...]
    protocol_events: tuple[tuple[int, str], ...]
    cycles_consumed: int
    sample_consumed: bool
```

Implement `project_sample(plan: ProjectionPlan, raw_value: int, state: ProjectionState) -> ProjectionResult`. Reject raw values outside the unsigned `plan.raw_abi.raw_width` range or a state width mismatch. Compile actions in stable numeric field/action order. Use only fixed-width bit slicing, XOR folding, masks, counters, and declared finite temporal rules. An inactive dynamic edge changes stable priority order but leaves a fixed exploration slot selected from existing raw bits; it never removes the static edge. Reject `max_state_bits > 4096`, more than 64 field groups in one batch, and any unbounded rule. Always return `cycles_consumed=1` and `sample_consumed=True`.

Derive the depaware ABI by copying the candidate-direct destination and slice geometry, then changing only `action` and `category` on existing `RawBitUse` rows. Reject any attempt to add, remove, or resize a row. This is the fairness gate that makes the two candidate harnesses consume identical raw width and entropy positions.

- [ ] **Step 5: Implement depaware SV emission and bundle compilation**

Implement in `compiler.py`:

```python
@dataclass(frozen=True, slots=True)
class HarnessBundle:
    flat_direct: EmittedHarness
    candidate_direct: EmittedHarness
    candidate_depaware: EmittedHarness
    dependency_graph: CsrGraph
    coverage_universe_hash: str
```

Implement `HarnessBundle.manifest_fragment(self) -> dict[str, object]` using only canonical JSON primitives and implement the exact `compile_harness_bundle` signature from the Interfaces block. Validate all three contracts, reject a manifest whose `validation.status` is not `valid`, and require the manifest's `composition_ir_hash` to equal `content_hash(composition_ir)`. Require every explicitly declared endpoint protocol ID to be present in `protocols`; never infer it from a role or identifier. Build the static graph from facts and IR, build both direct ABIs, derive a depaware plan with exactly the candidate-direct raw width, emit bounded SV state and correction/event counters, and include `projection_rate`, correction categories, protocol event count, timeout count, violation count, and no-progress count in `EmittedHarness.counters`. Never emit VCD/FST directives.

Implement `write_harness_bundle` with `Path.mkdir(parents=True, exist_ok=True)` and same-directory temporary files followed by `Path.replace` so interrupted generation never leaves a partial named artifact. Write UTF-8 with `newline="\n"`, JSON with `sort_keys=True`, `indent=2`, and a final newline. Return a dict keyed by the five exact filenames. Store only filenames in the manifest fragment, never the absolute `output_dir`.

- [ ] **Step 6: Run all Terminal B tests, commit, and push B6**

Run:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests/protocols -v
PYTHONPATH=src python3 -m unittest discover -s tests/harness -v
rg -n -i 'if .*target|if .*design|rvx|ibex|opentitan|uart|gpio|rv_timer' src/myfuzz/harness src/myfuzz/protocols
git diff --check
git add src/myfuzz/harness tests/harness
git diff --cached --stat
git commit -m "feat(harness): [B6] compile bounded dependency-aware harnesses" -m "Node: B6" -m "Tests: PYTHONPATH=src python3 -m unittest discover -s tests/protocols -v; PYTHONPATH=src python3 -m unittest discover -s tests/harness -v"
git push origin feature/harness-runtime
git ls-remote --exit-code origin refs/heads/feature/harness-runtime
git merge-base --is-ancestor HEAD origin/feature/harness-runtime
```

Expected: both suites end in `OK`; target/name scan has no matches; the B6 commit is remotely visible.

### Task B7: Memory-Token Scheduler and RFuzz Command Adapter

**Files:**
- Create: `src/myfuzz/experiments/__init__.py`
- Create: `src/myfuzz/experiments/model.py`
- Create: `src/myfuzz/experiments/scheduler.py`
- Create: `src/myfuzz/experiments/rfuzz_adapter.py`
- Create: `tests/experiments/__init__.py`
- Create: `tests/experiments/test_scheduler.py`
- Create: `tests/experiments/test_rfuzz_adapter.py`

**Interfaces:**
- Consumes: `ExperimentJob`, observed RSS samples, configured soft/hard byte limits, and an injected command runner.
- Produces: `MemoryTokenScheduler(soft_limit_bytes: int, hard_limit_bytes: int, token_bytes: int = 64_000_000)`, `MemoryTokenScheduler.admit(job: ExperimentJob) -> Admission`, `MemoryTokenScheduler.record_peak_rss(cache_key: str, peak_rss_bytes: int) -> None`, `MemoryTokenScheduler.update_available_memory(available_bytes: int, swap_growth_bytes: int) -> Admission`, `MemoryTokenScheduler.release(job_id: str) -> None`, and `RfuzzAdapter.command(job: ExperimentJob) -> tuple[str, ...]`.
- Build jobs use an exclusive build token. Fuzz estimates use the latest same-cache-key RSS, falling back to the declared estimate.

- [ ] **Step 1: Write failing scheduler tests with no subprocesses**

Create `tests/experiments/test_scheduler.py` with immutable jobs and assert one build is admitted, a second concurrent build is denied even with free bytes, fuzz jobs are admitted until the soft limit, a hard-limit update yields `stop_lowest_priority`, release restores capacity, RSS learning is keyed by build cache key, and CPU count never changes admission. Use byte values `soft_limit=6_000_000_000`, `hard_limit=7_000_000_000`, `token_bytes=64_000_000`.

In `tests/experiments/test_rfuzz_adapter.py`, assert the adapter returns a tuple invoking `sys.executable`, `src/myfuzz/scripts/run_design_flow.py`, `--stage fuzz`, `--jobs 1`, a relative config path, fixed seconds/seed/cycle parameters, and no `--trace`/VCD/FST flag. Assert `availability()` returns structured `available=False` when the RFuzz checkout or executable is absent rather than failing import.

- [ ] **Step 2: Run and confirm experiment modules are absent**

Run:

```bash
PYTHONPATH=src python3 -m unittest tests.experiments.test_scheduler tests.experiments.test_rfuzz_adapter -v
```

Expected: import error for `myfuzz.experiments`.

- [ ] **Step 3: Implement job and admission records**

In `model.py`, define:

```python
class JobKind(str, Enum):
    BUILD = "build"
    FUZZ = "fuzz"
    REPLAY = "replay"

@dataclass(frozen=True, slots=True)
class ExperimentJob:
    job_id: str
    target_id: str
    candidate_id: str
    harness: str
    seed: int
    budget_kind: str
    budget_value: int
    build_cache_key: str
    config_path: str
    estimated_rss_bytes: int
    priority: int
    kind: JobKind

@dataclass(frozen=True, slots=True)
class Admission:
    admitted: bool
    token_count: int
    reason: str
    action: str
```

`target_id`, `candidate_id`, and `job_id` are opaque identity strings. They may be copied and compared for equality, but never parsed or used to select behavior.

- [ ] **Step 4: Implement deterministic token accounting and command construction**

Add immutable `RfuzzAvailability(available: bool, missing_paths: tuple[str, ...])`. Implement the exact `MemoryTokenScheduler` and `RfuzzAdapter` method signatures from the Interfaces block, plus `MemoryTokenScheduler.update_available_memory(available_bytes: int, swap_growth_bytes: int) -> Admission` and `RfuzzAdapter.availability() -> RfuzzAvailability`.

Use ceiling division for tokens. Maintain one `dict[job_id, allocation]` and one bounded insertion-ordered `dict[cache_key, latest_peak]`; cap RSS history at 128 keys. Reject nonpositive limits, `soft_limit_bytes >= hard_limit_bytes`, duplicate active job IDs, negative RSS, and release of an unknown job. Deny a second build while a build is active. Delay new work when reserved bytes would exceed the soft usage limit. When reserved bytes exceed the hard limit or positive swap growth is observed across three consecutive updates, return `action="stop_lowest_priority"` with the numerically lowest priority and then lexically smallest opaque job ID as deterministic tie-break; do not classify it as a DUT crash. The adapter checks only fixed RFuzz tool paths beneath `repo_root`, constructs commands only, and never imports RFuzz Python modules.

- [ ] **Step 5: Run scheduler tests and commit B7**

Run:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests/experiments -v
git diff --check
git add src/myfuzz/experiments tests/experiments
git diff --cached --stat
git commit -m "feat(experiments): [B7] schedule jobs by measured memory" -m "Node: B7" -m "Tests: PYTHONPATH=src python3 -m unittest discover -s tests/experiments -v"
git push origin feature/harness-runtime
git ls-remote --exit-code origin refs/heads/feature/harness-runtime
git merge-base --is-ancestor HEAD origin/feature/harness-runtime
```

Expected: all experiment tests pass; B7 is visible on the remote branch.

### Task B8: Declarative Experiment Planner and Target Configurations

**Files:**
- Create: `src/myfuzz/experiments/planner.py`
- Create: `configs/experiments/rvx.json`
- Create: `configs/experiments/ibex_opentitan.json`
- Create: `tests/experiments/test_planner.py`

**Interfaces:**
- Consumes: experiment configuration data plus one or more validated candidate manifests; reference artifacts are optional evaluation-only records and are never passed to composition/harness APIs.
- Produces: `plan_experiment(config: object, candidate_manifests: Sequence[object]) -> ExperimentPlan` and stable jobs for `target x candidate x harness x seed x time-budget`.
- `ExperimentPlan` contains immutable `jobs`, randomized-but-seed-deterministic run blocks, fairness assertions, and a plan hash.

- [ ] **Step 1: Write failing planning and isolation tests**

Create `tests/experiments/test_planner.py`. Load both configs and the frozen candidate manifest, then assert:

```python
plan = plan_experiment(config, [manifest])
self.assertEqual(plan, plan_experiment(config, [manifest]))
self.assertEqual({job.harness for job in plan.jobs if job.candidate_id == manifest["candidate_id"]},
                 {"flat-direct", "candidate-direct", "candidate-depaware"})
self.assertTrue(plan.fairness.candidate_pair_has_equal_budget)
self.assertTrue(plan.fairness.candidate_pair_has_equal_seeds)
self.assertTrue(plan.fairness.candidate_pair_has_equal_raw_width)
```

Also assert the RVX config has `reference.mode="evaluation-only"`; remove that member and verify generated-candidate jobs are unchanged. Assert Ibex + OpenTitan has no reference job. Assert shuffled input manifests produce the same plan. Replace target/component display strings with misleading text while preserving stable IDs and assert graph/harness selection and job resources remain unchanged. Reject configs that compare coverage percentages across different universes or schedule two build jobs concurrently.

- [ ] **Step 2: Run and confirm planner is absent**

Run:

```bash
PYTHONPATH=src python3 -m unittest tests.experiments.test_planner -v
```

Expected: import error for `myfuzz.experiments.planner`.

- [ ] **Step 3: Add data-only experiment configs**

Both JSON files must declare `schema_version="experiment.v1"`, stable opaque target ID, candidate selection, the three harness groups, identical candidate pair seeds `[1, 7, 19]`, smoke budget `1000` cycles, short budget `300` seconds, long budget `3600` seconds, `K=3`, fixed RFuzz mutation parameters, `build_concurrency=1`, `waveforms=false`, `replay_queue_capacity=128`, `event_ring_capacity=4096`, `field_groups_per_batch=64`, `soft_memory_bytes=6000000000`, `hard_memory_bytes=7000000000`, and `token_bytes=64000000`.

`rvx.json` declares a reference group only as:

```json
"reference": {
  "mode": "evaluation-only",
  "allowed_stage": "report",
  "comparison": "shared-stable-source-id"
}
```

It must not contain a reference-top path. `ibex_opentitan.json` declares component roles as data for one CPU, UART, GPIO, and timer plus OBI/TL-UL adapter, interconnect, and memory endpoint requirements. Those declarations are experiment input, not executable lookup tables. It has no `reference` key and excludes SPI from initial acceptance.

- [ ] **Step 4: Implement plan validation, fairness blocks, and stable ordering**

Implement in `planner.py`:

```python
@dataclass(frozen=True, slots=True)
class FairnessAudit:
    candidate_pair_has_equal_budget: bool
    candidate_pair_has_equal_seeds: bool
    candidate_pair_has_equal_raw_width: bool
    shared_instrumented_rtl: bool
    shared_coverage_universe: bool

@dataclass(frozen=True, slots=True)
class ExperimentPlan:
    jobs: tuple[ExperimentJob, ...]
    run_blocks: tuple[tuple[str, ...], ...]
    fairness: FairnessAudit
    plan_hash: str
```

Implement the exact `plan_experiment(config: object, candidate_manifests: Sequence[object]) -> ExperimentPlan` signature. Validate manifests through `validate_contract`. Sort candidates by opaque ID equality/order only. Create flat-direct jobs with their own universe tag; pair candidate-direct/depaware jobs by candidate/seed/budget. Interleave pair order using `hashlib.sha256(canonical_bytes({"seed": seed, "candidate_id": candidate_id}))`, not ambient randomness. A reference record may create report-stage metadata only and must never enter `compile_harness_bundle`, build cache keys, address data, or candidate scoring.

- [ ] **Step 5: Run, scan, commit, and push B8**

Run:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests/experiments -v
rg -n -i 'if .*rvx|if .*ibex|if .*opentitan|fixed_address|reference_top' src/myfuzz/experiments
git diff --check
git add src/myfuzz/experiments/planner.py src/myfuzz/experiments/__init__.py configs/experiments tests/experiments/test_planner.py
git diff --cached --stat
git commit -m "feat(experiments): [B8] plan fair declarative fuzz comparisons" -m "Node: B8" -m "Tests: PYTHONPATH=src python3 -m unittest discover -s tests/experiments -v"
git push origin feature/harness-runtime
git ls-remote --exit-code origin refs/heads/feature/harness-runtime
git merge-base --is-ancestor HEAD origin/feature/harness-runtime
```

Expected: all tests pass; source scan has no matches; the two target names occur only in data file names/content; remote checks exit 0.

### Task B9: Per-Candidate Coverage and Runtime Reporting

**Files:**
- Create: `src/myfuzz/experiments/report.py`
- Create: `tests/experiments/test_report.py`

**Interfaces:**
- Consumes: `ExperimentPlan`, candidate manifests, bounded JSONL sample summaries, replay/projection counters, and optional evaluation-only reference summary.
- Produces: `build_report(plan: ExperimentPlan, candidate_manifests: Sequence[object], samples: Sequence[object], reference_summary: object | None = None) -> dict[str, object]`.
- Reports candidate-direct versus candidate-depaware on one shared universe; flat-direct separately; optional RVX reference only by shared stable source IDs.

- [ ] **Step 1: Write failing report tests from deterministic samples**

Create `tests/experiments/test_report.py` with two candidates and fixed samples at times `0`, `10`, and `20`. Assert the report contains, per candidate and harness: covered/common-total, coverage-over-time, trapezoidal area, first discovery time, discovery count, direct-only/depaware-only/overlap IDs, component-role grouping, tests/s, cycles/s, peak RSS, projection rate, correction distribution, protocol event count, no-progress cycles, generation count, validation rate, and failure reasons.

Assert candidate coverage sets remain separate and there is no union-as-candidate result. Assert the candidate pair uses one denominator; flat-direct has a distinct universe and no percentage subtraction. Provide a reference summary with extra source IDs and assert comparison uses only the intersection of `stable_source_id`. Pass samples in reverse order and require byte-identical canonical output.

- [ ] **Step 2: Run and confirm report builder is absent**

Run:

```bash
PYTHONPATH=src python3 -m unittest tests.experiments.test_report -v
```

Expected: import error for `myfuzz.experiments.report`.

- [ ] **Step 3: Implement deterministic aggregation**

Implement:

```python
class ReportError(ValueError):
    """Raised when result samples violate experiment fairness contracts."""
```

Implement the exact `build_report(plan: ExperimentPlan, candidate_manifests: Sequence[object], samples: Sequence[object], reference_summary: object | None = None) -> dict[str, object]` signature. Validate manifests and sample numeric bounds. Key candidate results by opaque `candidate_id`, never merge their coverage sets. Sort samples by `(candidate_id, harness, seed, elapsed_seconds, sequence)`. Calculate AUC using trapezoids over covered-point count, not percentages with different denominators. Calculate direct-only/depaware-only/overlap only within one candidate shared universe. Group points by the explicitly declared `component_role` field. Include `comparison_scope` values `harness-attribution`, `structure-and-projection`, or `reference-descriptive`. Treat `resource_terminated` separately from `dut_crash`.

- [ ] **Step 4: Run all Terminal B tests and deterministic repeat**

Run:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests/protocols -v
PYTHONPATH=src python3 -m unittest discover -s tests/harness -v
PYTHONPATH=src python3 -m unittest discover -s tests/experiments -v
PYTHONPATH=src python3 -m unittest tests.experiments.test_report -v >/tmp/myfuzz-report-test-1.txt
PYTHONPATH=src python3 -m unittest tests.experiments.test_report -v >/tmp/myfuzz-report-test-2.txt
cmp /tmp/myfuzz-report-test-1.txt /tmp/myfuzz-report-test-2.txt
```

Expected: all three suites finish with `OK`; `cmp` exits 0.

- [ ] **Step 5: Commit and publish B9**

Run:

```bash
git diff --check
git add src/myfuzz/experiments/report.py src/myfuzz/experiments/__init__.py tests/experiments/test_report.py
git diff --cached --stat
git commit -m "feat(experiments): [B9] report per-candidate fuzz results" -m "Node: B9" -m "Tests: PYTHONPATH=src python3 -m unittest discover -s tests/protocols -v; PYTHONPATH=src python3 -m unittest discover -s tests/harness -v; PYTHONPATH=src python3 -m unittest discover -s tests/experiments -v"
git push origin feature/harness-runtime
git ls-remote --exit-code origin refs/heads/feature/harness-runtime
git merge-base --is-ancestor HEAD origin/feature/harness-runtime
```

Expected: B9 is a single report-focused commit and exists remotely.

### Task B10: Fixture-to-Plan Vertical Smoke and Source Guard

**Files:**
- Create: `src/myfuzz/experiments/pipeline.py`
- Create: `tests/harness/test_identifier_opacity.py`
- Create: `tests/experiments/test_pipeline.py`

**Interfaces:**
- Consumes: all four frozen contract fixtures, explicit experiment config, explicit protocol IDs, repository execution root, and Terminal B APIs from B1-B9.
- Produces: `prepare_candidate_runtime(hdl_facts: object, composition_ir: object, candidate_manifest: object, experiment_config: object, repo_root: Path) -> PreparedCandidateRuntime` with harness bundle, experiment plan, manifest fragment, RFuzz availability, and no heavy subprocess side effect.
- This node does not invoke Verilator or RFuzz; integration nodes use the returned command/jobs after Terminal A output is available.

- [ ] **Step 1: Write a failing end-to-end in-memory smoke test**

Create `tests/experiments/test_pipeline.py` that loads frozen facts/composition/manifest fixtures and `configs/experiments/ibex_opentitan.json`, passes an empty temporary repository root, calls `prepare_candidate_runtime`, and verifies three harness sources, equal candidate raw widths, valid static graph hash, at least one job for every seed/group, `build_concurrency=1`, no waveform directive, bounded queues, `runtime.rfuzz_availability.available is False`, at least one exact missing path, and a deterministic manifest fragment. Call it twice after reversing every safely reorderable input array, set the copied manifest's `composition_ir_hash=content_hash(reordered_ir)`, and require equality.

Create `tests/harness/test_identifier_opacity.py` that parses the Terminal B Python source with `ast`, fails on attribute/subscript access to forbidden semantic keys (`module_name`, `instance_name`, `port_name`, `net_name`, `file_name`, `directory_name`, `target_name`) outside `sv_emit.py` diagnostic/emission allowlist, and fails on string comparisons against `rvx`, `ibex`, `opentitan`, `uart`, `gpio`, or `rv_timer`. Add a behavioral test replacing all diagnostic identifier text in copied fixtures while preserving numeric bindings and assert identical protocol choice, graph document, raw ABI, projection plan, job resources, and coverage grouping IDs.

- [ ] **Step 2: Run and confirm pipeline/guard imports fail**

Run:

```bash
PYTHONPATH=src python3 -m unittest tests.experiments.test_pipeline tests.harness.test_identifier_opacity -v
```

Expected: import error for `myfuzz.experiments.pipeline` before the tests can pass.

- [ ] **Step 3: Implement the side-effect-free vertical coordinator**

Implement:

```python
@dataclass(frozen=True, slots=True)
class PreparedCandidateRuntime:
    harness_bundle: HarnessBundle
    experiment_plan: ExperimentPlan
    manifest_fragment: dict[str, object]
    rfuzz_availability: RfuzzAvailability

def prepare_candidate_runtime(
    hdl_facts: object,
    composition_ir: object,
    candidate_manifest: object,
    experiment_config: object,
    repo_root: Path,
) -> PreparedCandidateRuntime:
    validate_contract(hdl_facts, "hdl_facts.v2")
    validate_contract(composition_ir, "composition_ir.v1")
    validate_contract(candidate_manifest, "candidate_manifest.v1")
    protocol_ids = sorted({item["protocol_id"] for item in composition_ir["endpoint_bindings"]})
    protocols = {protocol_id: load_builtin_protocol(protocol_id) for protocol_id in protocol_ids}
    bundle = compile_harness_bundle(hdl_facts, composition_ir, candidate_manifest, protocols)
    plan = plan_experiment(experiment_config, [candidate_manifest])
    availability = RfuzzAdapter(repo_root).availability()
    return PreparedCandidateRuntime(bundle, plan, bundle.manifest_fragment(), availability)
```

Use the shown body exactly after importing its named dependencies. Tests pass a temporary root and must not depend on `Path.cwd()`. Collect exact protocol IDs from explicit `endpoint_bindings`, call `load_builtin_protocol` for those IDs, compile the bundle, call `plan_experiment`, and query `RfuzzAdapter.availability()`. Do not inspect component roles to choose protocols. Do not read a reference top. Do not launch a subprocess or create a build directory. Merge only the Terminal B manifest fragment in memory.

- [ ] **Step 4: Run the complete low-memory verification gate**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests/protocols -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests/harness -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests/experiments -v
rg -n -i 'if .*target|if .*design|rvx|ibex|opentitan|uart|gpio|rv_timer|fixed.*address|reference.*top' src/myfuzz/protocols src/myfuzz/harness src/myfuzz/experiments
find src/myfuzz/protocols src/myfuzz/harness src/myfuzz/experiments configs/experiments tests/protocols tests/harness tests/experiments -type f \( -name '*.vcd' -o -name '*.fst' -o -perm -111 \)
```

Expected: every suite ends with `OK`; the semantic source scan has no output; the artifact scan shows no newly generated binary or waveform under owned directories. Absence of `third_party/rfuzz` is reported by `RfuzzAvailability` tests and does not skip or fail these tests.

- [ ] **Step 5: Commit and publish B10**

Run:

```bash
git diff --check
git add src/myfuzz/experiments/pipeline.py src/myfuzz/experiments/__init__.py tests/harness/test_identifier_opacity.py tests/experiments/test_pipeline.py
git diff --cached --stat
git commit -m "test(runtime): [B10] verify fixture-to-experiment pipeline" -m "Node: B10" -m "Tests: PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests/protocols -v; PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests/harness -v; PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests/experiments -v"
git push origin feature/harness-runtime
git ls-remote --exit-code origin refs/heads/feature/harness-runtime
git merge-base --is-ancestor HEAD origin/feature/harness-runtime
git status --short
```

Expected: all remote checks exit 0 and `git status --short` is empty. Record the terminal handoff as branch `feature/harness-runtime` plus the B10 commit hash; do not merge into `main` from this terminal.

## Integration Handoff

After B10, Terminal B hands the integration terminal:

```text
branch: feature/harness-runtime
required head: B10 remote commit hash
consumes: composition_ir.v1, candidate_manifest.v1, tests/contracts/*.valid.json
produces: HarnessBundle.manifest_fragment(), ExperimentPlan, build_report()
heavy validation performed: none by design
next gate: merge Terminal A first, merge Terminal B second, run frozen contract tests against real A producer output, then serialize Verilator/RFuzz smoke through the shared memory-token lock
```

Do not report Terminal B complete if any node is `pending-push`, any frozen fixture was modified, or any heavy RFuzz/Verilator process remains running.
