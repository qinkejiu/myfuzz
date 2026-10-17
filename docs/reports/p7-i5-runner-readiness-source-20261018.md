# P7 I5 runner: lock and write-path source audit

Status: **source inspection only; no imports, tests, tools or native execution**.

## Concrete cache preflight defect and correction

The runner originally passed the new path `output/native-cache` without
creating it. Production `_compiled_session_preflight` requires that the cache
directory already exists and otherwise refuses `build-cache-missing` before a
session. The runner now creates its own new empty external cache directory
before launching the CLI. It does not borrow a historical cache or claim a
prebuilt harness. Actual cold build cost and run outcome remain unmeasured.

## Lock scope

The controller holds the caller-selected external canonical lock with
`LOCK_NB`. The inner CLI separately uses
`base/.superpowers/sdd/stage2-heavy-worker.lock`, also with `LOCK_NB`.
That private empty file must exist before source freeze. The preparer supplies
it explicitly; opening an existing file with append mode does not add source
bytes. The two locks must be different inodes. The controller rejects a
canonical path resolving inside the snapshot; its whole source map rejects
multiply linked private files. An outer lock alias to the private lock cannot
therefore be accepted by these checks. Neither lock file's mere existence
establishes availability or authorizes execution.

## Frontend and fixture writes

Both supervised `SourceCrawler` elaboration and direct profile/module
elaboration create `TemporaryDirectory(..., dir=source_root)`. Consequently
external TMPDIR does **not** make all frontend writes external. Those bounded
temporary directories are cleaned by their context managers; the exact final
whole-source comparison remains necessary and must fail for any leftovers or
other source changes. No claim of an entirely read-only source run follows
from equal before/after maps.

The selected negative fixtures construct their generated outputs beneath
pytest `tmp_path` / `tmp_path_factory`; the controller supplies external TMPDIR
and disables pytest cacheprovider and Python bytecode. Real source elaboration
and source-lock reads still occur. In particular, the N4 timer fixture's old
"no frontend" docstring is not evidence of execution scope: its real
`generate_harness_set` path can invoke elaboration. No source mutation exception
or saved-facts substitution is added here.

The build toolchain also selects `make`, alongside Verilator, `c++`, and `ar`.
The operator's reviewed tool manifest should include `make` and the actual
Verilator backend; the controller's minimum named-tool set alone is not a
transitive closure proof. Actual native build manifests and wrapper dependency
review remain required. No runtime/admission code was changed by this audit.

Any overlay of the corrected runner into an already staged snapshot requires
an explicit file/hash receipt and a new final whole freeze. A prior map cannot
describe the intentionally modified snapshot.
