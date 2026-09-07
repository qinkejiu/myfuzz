# Task 6 Independent Review Fix Report

## Scope

This follow-up changes only Task 6 protocol/catalog/projection files and its
catalog test. Task 5 composition/CLI files were not changed. The pre-existing
modified `.superpowers/sdd/task-2-report.md` and untracked `third_party/` were
preserved and are not staged.

## RED

Added focused regressions, then ran:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.protocols.test_additional_protocol_catalog -v
```

Result: `FAILED (failures=4, errors=10)`.

- The AXI4 binding reached `build_projection_plan` and failed with
  `ValueError: unsupported projection action kind: reject`.
- `ProtocolPlugin` had no `channel_relations` or `capability_limits` fields.
- The loader accepted dangling/duplicate channel relations and a floating
  capability value.

## GREEN

- Added a bounded `constant` projection action with an explicit non-negative,
  destination-width-checked `constant_value`; catalog parsing, harness action
  compilation, plan hashing, and runtime sample projection all carry it.
- AXI4 now projects `AWLEN`, `ARLEN`, `AWID`, and `ARID` to zero and `WLAST`
  to one. Runtime-only unsupported burst/nonzero-ID behavior remains declared
  as explicit capability rejection and enforced by the existing AXI4 bridge.
- Added immutable channel-relation and scalar capability-limit records. The
  loader fails closed on metadata type errors, duplicate relation IDs,
  duplicate/dangling relation field IDs, unsupported projection kinds, and bad
  capability values.
- All eight bundled protocol plugins now declare stable channel relations and
  `byte_enable`/`partial_write` capability status. APB3 and OBI declare both
  unsupported and retain their bounded write-data projection; their existing
  runtime bridges reject non-full canonical byte enables. RTL was unchanged
  because the existing bridge tests already verify that behavior.

## Verification

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.protocols.test_additional_protocol_catalog \
  tests.protocols.test_additional_protocol_rtl \
  tests.protocols.test_protocol_catalog \
  tests.protocols.test_bridge_models \
  tests.harness.test_projection -v
# Ran 48 tests ... OK

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  discover -s tests/protocols -t . -v
# Ran 49 tests ... OK

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.harness.test_projection tests.harness.test_harness tests.harness.test_compiler -v
# Ran 34 tests ... OK

git diff --check
# exit 0
```

Verilator is available (`Verilator 5.051 devel rev vUNKNOWN-built20260806-e413e67`):
the Task 6 wrapper-lint test passed. Icarus is available (`Icarus Verilog
version 14.0 (devel)`): all Task 6 bridges compiled and the directed Wishbone
STALL/ACK simulation passed. No simulator test was skipped.
