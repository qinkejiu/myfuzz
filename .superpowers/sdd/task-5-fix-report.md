# Task 5 Fix Report

## Scope

Follow-up for Task 5 baseline `bf2c8bb` on
`feature/ibex-protocol-longrun`. This commit changes only the requested Task 5
implementation, tests, CLI, and this report. It deliberately does not stage or
modify the pre-existing `.superpowers/sdd/task-2-report.md` change or the
untracked `third_party/` tree.

## Inherited interrupted work

The interrupted worktree already contained edits to `auto.py`,
`test_generic_auto.py`, and `test_generic_composition.py`. Kept and corrected
the useful parts:

- component HDL crawling and source-backed target binding;
- planner topology records and source/protocol ambiguity checks;
- initial regressions for source proof, APB `paddr`, source-list stability,
  and publish restoration.

The inherited state was not complete: width-expression inspection called the
wrong helper, `SourceLocator` lacked its required `top_module`, generic HDL
still instantiated only the source CPU, publication replaced files one at a
time, and the CLI discarded every generic option.

## RED / GREEN evidence

### Critical: source-backed component topology and renderer

RED (before this follow-up implementation):

```text
tests.composition.test_generic_auto tests.integration.test_generic_composition
Ran 20 tests: 4 failures, 9 errors
```

The errors included the invalid width-expression call; the renderer test could
not reach the required component/adapter rendering path. GREEN after the
source locator correction and generic renderer:

```text
Ran 23 tests: OK
```

The planner crawls each profile's HDL, requires protocol field-ID ports with
the target-facing direction, emits explicit instance/adapter/binding/address
region/IRQ-route IR, and fails closed on missing target evidence. The renderer
instantiates the actual `profile.module_name`, a bounded zero-latency generic
bridge (`MAX_WAIT_CYCLES = 16`), source-to-bridge-to-target wires, address
decode, and source-proven IRQ routing. It does not branch on CPU names or
signal spellings.

### Critical: transactional bounded publication

RED in the inherited integration test showed that a replacement failure left
`composition_ir.json` from the new plan while another artifact was old.
GREEN uses an injected `os.replace` failure after the old output directory is
moved aside; the byte snapshot of every original artifact is restored.

Publication now stages all four artifacts, validates/reparses the staged JSON
and top, then replaces the output directory as one unit. The output must
resolve beneath `base_dir`.

### Important: protocol widths and ambiguity

RED initially raised `AttributeError: 'str' object has no attribute 'items'`
for an APB `paddr` expression. GREEN parses protocol width-expression names,
recognizes every field whose expression contains `address_width` (including
APB `paddr`, AXI `awaddr`/`araddr`, OBI `addr`, and TL `a_address`), and
rejects zero or conflicting widths.

The focused tests prove APB's 24-bit `paddr`, multiple same-protocol initiator
rejection, and multiple-protocol rejection without a preference. The latter
also proves ordered preferences select `opaque@2`/`cpu.b` ahead of
`opaque@1`/`cpu.a`.

### Important: CLI and reproducible source lists

RED for `test_cli_generic_options_are_forwarded_to_the_request` was argparse
rejecting all five new option kinds as unrecognized. GREEN proves repeatable
component and protocol options, RV64 ISA extensions, and seed are forwarded to
`GenericCompositionRequest`.

`sources.f` now contains only base-relative plan sources and the fixed
`generic_composition_top.sv` name. Two different output directories therefore
produce identical bytes; an external output path is rejected.

## Verification

Passed:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.composition.test_generic_auto tests.integration.test_generic_composition \
  tests.composition.test_auto tests.composition.test_protocol_manifest \
  tests.composition.test_protocol_composer -v

51 passed; 1 environmental failure described below

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.composition.test_endpoint_capabilities tests.composition.test_source_crawler \
  tests.composition.test_input_layout -v

Ran 55 tests: OK

git diff --check
exit 0
```

The requested combined command ran 52 tests. The only failure was
`test_builtin_ibex_plan_is_incomplete_when_upstream_is_absent`: its premise is
false in this worktree because the pre-existing untracked `third_party/`
provides the upstream path. No `third_party/` content was created, removed,
edited, or staged by this work.

## Compatibility

Legacy auto-composition and protocol-composition public APIs and generated
bytes are untouched. The generic no-component renderer retains its prior top
shape; its `sources.f` intentionally changes to the required stable relative
form.
