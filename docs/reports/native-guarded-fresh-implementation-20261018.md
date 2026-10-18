# Guarded native fresh construction: source implementation

Implements the bounded construction seam proposed in
`native-guarded-fresh-design-20261018.md`. `replay_online_session` now accepts
keyword-only `native_max_cases=None`. None retains ordinary ScenarioSession
construction and reservation declaration. Explicit selection requires a strict
integer1..96 (bool refused) and uses only code-owned NativePacketSession.
The native runtime passes its own max_cases to this branch.

Before runner factory invocation the selected branch requires the fixed native
bootstrap template, the exact ordered97 reservations from0x200 to0xe00 with
stride32/count1, and case count within the selected bound. Register runtime,
reset plans and serialized terminal failures are refused. Construction itself
performs the actual once-only declarations; replay compares its retained slot
list exactly and never declares the same slots again.

Existing plan hash, schema/case/provenance checks, runtime topology and manifest
checks remain. Replay retains every saved warmup advance, all saved cases,
guarded submit pre/post checks, single final finish and complete event/status/
ticks/admission/semantic/manifest comparison. No candidate redraw, decoder
commit, extra warmup clocks or event normalization was added. The observation
opt-in retained in the original factory remains independent of this selector.

Remaining limitations: max_cases is still caller-supplied rather than bound
in a packet-specific persisted plan/manifest; native guard and decoder-commit
failure serialization is not implemented. Terminal-failure native replay is
therefore refused here. Fresh observation nonce differences remain exact
comparison mismatches pending a separately reviewed policy. This does not
claim full C4 acceptance or a passing fresh native run.

Static review inspected the exact diff and parsed both changed files with
standard-library AST; `git diff --check` passed. SHA256 at review:

- `src/myfuzz/scenario/session_runtime.py`: `708d3b1c2fa712d147f604e205267f09e8f96587cab2725ac6688ad904abe61d`
- `src/myfuzz/integration/picorv32_native_online.py`: `8b8a101464ca164cb1ec38c68503e1a2f8e456d3e9a2bfdb15f0d0729f38cfcb`

No project imports, tests, frontend/build/model, native process or remote
operation were performed. Source-only implementation has no new actual pass;
previous passes do not certify the changed source identity. Independent review
and subsequent separately authorized validation remain necessary.
