# Task 6 Third Review Fix Report

## Scope

Only Task 6 protocol/catalog/projection/compiler files and Task 6 harness and
protocol tests were changed. The concurrent Task 5 files,
`.superpowers/sdd/task-2-report.md`, and `third_party/` were preserved and
were not staged.

## RED

The following focused regressions were added before their respective fixes and
observed failing:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.harness.test_harness.HarnessTest.test_depaware_sv_emits_constant_action_without_a_raw_input_expression \
  tests.protocols.test_additional_protocol_catalog.AdditionalProtocolCatalogTest.test_catalog_rejects_duplicate_json_keys_and_invalid_known_capabilities \
  tests.protocols.test_additional_protocol_catalog.AdditionalProtocolCatalogTest.test_partial_write_profiles_emit_fixed_full_byte_enable_constraints -v
```

- The generated depaware assignment for a `constant` action still used
  `rfuzz_input_bits`.
- Valid sorted capability arrays were rejected, and the parser did not reject
  duplicate JSON keys.
- APB3 and OBI `ProjectionPlan` instances had no fixed full-byte-enable
  constraint.

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.protocols.test_additional_protocol_catalog.AdditionalProtocolCatalogTest.test_catalog_rejects_dangling_references_duplicate_fields_and_invalid_widths -v
```

- A projection action with duplicate `field_ids` loaded successfully.

## GREEN

- Depaware RTL now emits constant projection expressions using the declared
  width/value, never the raw input slice; direct, mask, gate, delay-select,
  and fold-xor behavior remains unchanged.
- Catalog parsing uses `object_pairs_hook` recursively and rejects every
  duplicate JSON object key. Projection action and channel-relation field IDs
  must be unique and declared.
- Known capability keys now have strict bounded/type/enum validation:
  `max_wait_cycles` is 1..16, supported ID/burst arrays are ordered and
  unique, ordering and completion values are closed enums, and boolean keys
  cannot be supplied as integers. Unknown keys require the explicit `x-`
  extension prefix and a bounded scalar; nested/array extension values remain
  fail-closed.
- A `partial_write: false` protocol derives a fixed full-byte-enable canonical
  constraint from its declared `data_width` host field. The constraint is in
  the plan hash and depaware RTL emits an all-ones constant rather than a raw
  byte-enable sample. APB3 and OBI are covered directly; this is metadata
  driven, with no CPU or signal-name specialization.

## Verification

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -s tests/protocols -t . -v
# Ran 51 tests ... OK

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -s tests/harness -t . -v
# Ran 64 tests ... OK
```

The Task 6 RTL suite ran its original Verilator wrapper lint, Icarus compile,
and directed Wishbone STALL/ACK simulation successfully. `git diff --check`
was also clean.

## Unresolved issues

None.
