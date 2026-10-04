# Independent Local Harness Source Lock Gate

The explicit `verify_local_source_lock(profile, base_dir=...)` API verifies normalized source identity, effective parameters and defines against the matching lock record and authenticated elaboration closure. It reuses the existing single-record Git, selected-byte, artifact and closure verifier with document-wide owner/dependency context and `replay=False`.

This API is not automatically called by an artifact builder yet. Planning and wrapper rendering remain unchanged; successful structural generation does not imply trusted source verification or executable harness acceptance. The implementation requires a repository checkout with `scripts/verify_soc_sources.py` beside `src/`; standalone installed packages are not supported by this loader.

## Validation

- Test-first missing module failure observed; semantic normalization positive case initially failed under strict dictionary comparison and then passed after implementation.
- `PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_source_lock -q`: 13 tests passed.
- Local request/planner tests and existing source-lock tests: 63 tests passed when excluding the known existing `test_manifest_has_all_components_and_separate_statuses` assertion of 9 components against the current 17-component lock. The excluded assertion remains unchanged and fails in the complete suite.
- Regression execution used code and tests from `/tmp/myfuzz-local-source-lock`, with module ROOT/SCRIPT constants pointed at `/home/qinkejiu/myfuzz` to use existing checked-out submodule source bytes. No source-tree symlinks or network fetches were used.
- Actual API checks passed for CV32E20, PicoRV32 native/AXI/Wishbone and PULP GPIO. The current lock SHA256 is `e55b3ace8426ac4db78c1560c7caf2503de998237c20a7a87ae89046fab092a7`.
- Negative cases cover changed root source facts, revision/files/top/include/elaboration settings, missing and duplicate records, unverified closure, dirty selected bytes, changed closure evidence, unowned closure roots, dirty closure-only pinned dependencies, and unlocked parameter/define/frontend overrides.

No compiler replay, complete lock replay, renderer modification or runtime capability promotion occurs in this milestone.

Review fix: the gate canonically reparses source_document with the same source locator parser as load_component_profile, and requires equality with the actual profile.source dataclass, including elaboration. Five negative variations (revision, root, files, top and elaboration substitution) first passed incorrectly, then were refused after this consistency check. Real CVE2/Pico/PULP verification remained passing.
