# P7 I5 prepared tool environment: source review

Status: **two layout prerequisites found; no execution performed**.

Inputs were the frozen runner under `/tmp/myfuzz-p7-i5-source-6b40ef4`,
the saved `remote-environment-receipt.json`, and
`create-isolated-environment.py` read directly from the retained preparation
archive. No remote inventory, executable/version query, project import, test
or native process was run by this review. The saved receipt says
`prepared_not_executed` and `tool_transitive_closure_verified=false`.

## 1. Adjacent Verilator backend

`local_harness/build.py::_toolchain` resolves the selected `verilator` path
and requires a real file at its sibling `verilator_bin`, independently of
`VERILATOR_BIN`. The prepared selection is an ordinary script at
`operations/environment-20261018-attempt1/bin/verilator`. Its creation code
does not create an adjacent backend, and that file is absent from the saved
receipt. Therefore that prepared layout does not satisfy the source-level
backend check, even though the wrapper exports the actual installed backend
path. Root must inventory and prepare a coherent pinned layout before a gate.
This finding concerns the recorded preparation, not an assertion about any
later unobserved change on the server.

## 2. Frontend standard-source identity

`composition/source_elaboration.py::_tool_source_allowlist` also derives
its include candidates from the resolved selected executable: only
`../share/verilator/include` or `../include` relative to its bin directory.
For the operation wrapper those candidates are beneath the environment
operation, whereas its explicit `VERILATOR_ROOT` selects
`myfuzz/tools/verilator-5.051/share/verilator`.

If frontend metadata contains `<verilated_std>` or
`<verilated_std_waiver>`, their real paths must equal the corresponding
allowlisted files or admission refuses. Copying equivalent header bytes into
the operation prefix alone cannot prove equal real paths. A reviewed layout
must consistently bind the selected launcher, backend, installed share
directory, and metadata identities. The source check is not relaxed here;
whether this frontend emits those pseudo-files remains unmeasured.

## Remaining operation prerequisites

- The actual build selects `make` as well as Verilator, `c++` and `ar`.
  Wrapper/backend/header/system compiler dependencies need actual inventory
  and pins; the runner's minimum named-tool set is insufficient by itself.
- Build tool queries pass only PATH and LC_ALL. The saved Verilator wrapper
  correctly re-exports its intended installed share root and backend, so
  relying only on exports in the outer environment would be insufficient.
- The saved environment sets empty global Git config, no system config,
  no lazy fetch and no optional locks. The runner inherits other Git control
  variables; root must verify that ambient Git directory/worktree/object-store
  and `GIT_CONFIG_COUNT` overrides are absent before authorizing execution.
- N1–N8 need pytest in the actual selected interpreter/dependency directory.
  The live RFuzz path uses standard-library ctypes plus Linux SysV shared
  memory and `/proc/sysvipc/shm`; its source does not require `posix_ipc`.
  A prepared pythonlib path alone does not establish imports or IPC support.

The private source lock and external native-cache directory were addressed in
earlier source fixes; this review adds no duplicate cache change. No production
or admission code was changed, and none of these observations grants native
execution approval or closes P7.
