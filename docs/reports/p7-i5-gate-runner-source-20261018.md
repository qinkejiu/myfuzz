# P7 I5 auditable runner design and source record

Status: **source implementation only; not executed or accepted**.

The runner requires explicit independent `--base-dir`, an already reviewed
`--freeze-map` and its SHA256, exact Git `--expected-commit`, external
`--output`, `--client-binary` plus `--client-sha256`, and the operator-selected canonical
`--lock-file`. Without `--execute` it prints a plan and launches no process.
The map is a JSON object keyed by relative file path with `sha256`, `bytes`,
and `mode` (permission bits as an integer) per regular file, including Git metadata; links and multiply linked
files are refused. It must describe the whole supplied source snapshot.

Execution acquires the lock once with `LOCK_NB`; an occupied lock fails without
queuing. It creates a new output directory, records full maps/Git HEAD/dirty
status before and after, checks the caller's freeze, and sequentially runs the
eight named negative selectors followed by a new CV32E20 + timer compiled F4
RFuzz gate. Source-first nonoptimized Python imports, no bytecode, and external
temporary/cache directories prevent intended runtime writes to the snapshot.

Every child has a recorded argv, PID, stdout/stderr files, observation log and
actual terminal return code. Observation timeouts retain the same child and
continue waiting; there is no kill or restart. No shell command is used. JUnit
results require each selected negative fixture to execute with no failures,
errors or skips. Existing mapped reports cannot substitute for execution.

The native rerun must produce new reports, actual full fresh replay identities
and matching typed prefix digests, a nonempty all-certified receipt join and
lossless receipts. Gate summaries retain source and generated output hashes.
This runner is a collection and conservative structural acceptance layer;
independent detailed certificate/provenance audit remains necessary before
declaring formal P7 completion.

The runner does not change production admission, relax unsupported paths, or
launch remote work. N3 uses the dedicated source fixture from `1194b32`.
No tests or native gate have been run for this implementation.

`--expected-commit` must be the full Git HEAD object ID. A dirty tree is not
implicitly rejected or accepted: every byte must match the separately reviewed
full map, and the actual porcelain/submodule status is retained. HEAD equality
alone is insufficient. Store the freeze map outside the snapshot (a map cannot
contain its own final hash). `--pythonlib` optionally names the external
dependency directory after snapshot `src/` and root on the child import path;
an inherited old-workspace `PYTHONPATH` is discarded. External interpreter and
client hashes are documentary provenance; the operator must independently
approve the dependency/tool installation before execution.

The output status is `collected_pending_independent_audit`, never a declaration
of formal P7 completion. An occupied lock, mismatching source map, nonzero child
exit, skipped fixture, source mutation, or invalid fresh/join document fails.
The script has not been launched, including its plan-only mode.

The mandatory `--tool-freeze` / `--tool-freeze-sha256` preflight checks, without
executing any tool, a caller-reviewed JSON object keyed by executable name.
Each entry contains absolute `path` and `sha256`; at minimum `git`, `verilator`,
`c++`, and `ar` must be present. Resolved PATH selection, executability, and
file hashes must match before any child launch. Compiler/archiver flag and
command environment overrides are removed from children, tool hashes are
checked again afterward, and generated actual build manifests remain required
for the independent tool/provenance audit. The manifest checks named tool
entry points, not every transitive executable or shared library. An unmet or
unreviewed transitive closure still blocks operator execution authorization.
In particular, hashing a `c++` wrapper cannot approve its hard-coded old
workspace dependency or TMPDIR override. Those wrapper dependencies must be
reviewed before authorizing the operation.

All child log files are opened before spawn. Once spawned, metadata/observation
write failures and interruptions preserve the first exception and still wait
for that same child to exit; terminal recording is attempted before re-raising
the original exception. No such failure permits a restart or lock release
while the child is still being awaited.
