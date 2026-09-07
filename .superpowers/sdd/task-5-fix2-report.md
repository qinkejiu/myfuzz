# Task 5 Fix 2 Report

Baseline: `2aafa63`.  This change is limited to the approved Task 5 files.
The pre-existing `.superpowers/sdd/task-2-report.md` edit and untracked
`third_party/` directory were not modified or staged.

## RED / GREEN

1. **Output boundary and transactional publication.** RED:
`test_writer_rejects_base_and_source_overlap_before_any_publish` showed the
old writer moving `base_dir` before detecting the conflict.  GREEN rejects an
external output, `base_dir`, any source root, and any source file before a
staging directory or destination mutation.  Directory replacement remains
stage -> backup -> publish, restoring the previous file or directory on a
publish failure.

2. **Stale source/IR evidence.** RED:
`test_writer_rejects_stale_source_evidence_and_mutated_ir` published after
HDL bytes changed and accepted a forged `instances` record.  GREEN re-crawls
and re-annotates with the original catalog, compares annotations/source lists,
and checks the canonical IR hash before rendering or publication.

3. **Bounded source-backed topology and routing.** RED:
`test_single_channel_profile_requires_real_controls_and_records_adapter_contract`
could not plan a complete source-backed control path, and
`test_writer_renders_stateful_bounded_adapter_with_real_control_nets` had no
FSM/timeout implementation.  GREEN accepts only profiles with actual protocol
pins plus `clock`/`reset`, stores a single-target/single-channel contract in
IR, instantiates every selected component, and generates a stateful adapter
with latched request/response data, `MAX_WAIT_CYCLES`, and a timeout `error`
response.  IRQ is a real direct source-to-target net.  More than one target
for a source endpoint and protocols without the bounded `valid`/`ready`/`error`
contract fail closed; this includes AXI-style multi-channel protocols until a
dedicated declared adapter is available.

4. **CLI mode isolation.** RED:
an explicit `--seed 7` in protocol mode was silently accepted.  GREEN uses an
unset parser default, passes seed 7 only in generic mode, and rejects every
explicit generic-only option in protocol/legacy modes.

## Verification

Passed:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.composition.test_generic_auto tests.integration.test_generic_composition -v
git diff --check
```

Focused result: 29 tests passed.  The legacy composition command was also
run.  It has one pre-existing environmental failure:
`test_builtin_ibex_plan_is_incomplete_when_upstream_is_absent` is false
because the protected, pre-existing untracked `third_party/` tree supplies the
upstream source list.  The other 28 legacy tests passed.

## Deliberate fail-closed scope

Built-in profiles such as `timer` lack a source-declared generic field/control
mapping, so generic composition rejects them rather than claiming a completed
binding.  Dependency wiring also rejects until profile source mappings expose
actual dependency ports.  No CPU-name, signal-name, fixed-width, fixed-layout,
or AXI channel guessing was added.
