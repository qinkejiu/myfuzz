# P6 native/PULP directed gate: independent remote preparation plan

Status: read-only source/retained-receipt investigation and prospective operation plan. No new remote commands, project imports, tests, frontend, build or model were run. Gate source `c924aac` and its independent review `6ed62be` are source evidence, not actual P6 passage.

## 1. Why the existing P7 snapshot is insufficient

Retained P7 ready receipt identifies remote project `/root/fanzehui/myfuzz/operations/p7-i5-independent-6b40ef4-20261018-attempt1/project`, file-map SHA `b6372fcdb7ca1e93c289f850b0d53bc421c571204a65b86bd828815eb1f13dd2`,15,333 files. The independently matched local copy `/tmp/myfuzz-p7-i5-source-6b40ef4` contains `configs/cpus/picorv32/component_profile.json` but **does not contain** `third_party/picorv32_upstream_reference`. Its selected closure audit covered Ibex/CV32E40P/CV32E20/PULP GPIO/timer, not Pico. Thus the recorded remote copy cannot serve the Pico profile's declared source root. This conclusion is from the archived equal full-map evidence/local copy, not a new remote inventory or a claim about an unobserved later change.

The P7 copy already has PULP GPIO's selected source/license/Bender closure, but contains native runtime overlay `52de02c` only and predates the actual gate `c924aac`. Do not edit it or repurpose its ready marker. A new P6 operation/source snapshot must explicitly add Pico provenance and the reviewed gate, and freeze its own combined bytes. It need not carry the RFuzz client, pytest fixtures, BOOM/Chipyard, CVW, DMA or P7 timer proof.

## 2. Minimum source inputs and identity preservation

A practical **source-minimal selection**, retaining complete canonical host-code/config discovery rather than hand-pruning Python imports, is:

| Selection | Reason |
|---|---|
| Entire `src/myfuzz/` (Python, protocol JSON/RTL and both driver headers), excluding generated pycache only | `local_harness.__init__` eagerly imports many session modules; build._discover_host_sources records existence/import closure. Missing modules could alter identity or admission even if their RTL is not selected. |
| Entire `configs/` | Keeps canonical profiles/lock/closure paths and discovery facts. Only two selected upstream RTL roots are needed; this does not grant other profiles runtime availability. |
| `scripts/verify_soc_sources.py` and reviewed `scripts/verify_picorv32_native_online.py` | Actual source verifier is imported from beside the implementation, never borrowed from another project. Gate is the explicit operation entry. |
| `.gitmodules`, project `.git` plus necessary independent metadata | Source verifier checks durable tracked closure evidence and Git blob provenance. Full root Git metadata is a conservative reproducible superset; do not hand-prune Git object reachability without a separately reviewed exporter. |
| `third_party/picorv32_upstream_reference/{picorv32.v,COPYING,.git/}` | Actual profile selects picorv32.v; lock additionally verifies license against pinned Git blob. Embedded .git must be independent/reachable. |
| `third_party/soc-pulp-apb-gpio/{rtl/apb_gpio.sv,Bender.yml,LICENSE,.git/}` | Complete selected source and all three lock artifacts; preserve original pinned owner. |
| `agent.md`, chosen README/preparation declaration and reviewed source-freeze metadata | Preserve execution rules and document snapshot basis/explicit overlays. |

No literal HDL includes occur in the selected Pico/PULP files. Both closure records have empty include roots and no extra repository dependencies. This is a source-level selected closure, not an elaboration or dynamic tool dependency proof.

Do not copy only the two RTL files: `verify_local_source_lock`→`verify_soc_sources.verify_record` validates every declared artifact, source-tree hash, closure evidence SHA and Git blobs; root Git also checks closure evidence trackedness. The Pico and PULP embedded Git object stores/refs/config and their **empty directory layout** must survive the copy. The reviewed preparer directory-preservation fix `601964f` is relevant: ordinary-file equality alone cannot prove Git layout. Refuse external alternates/commondir/worktree links, symlinks and multiply linked selected files; preserve exact modes and independent copies. No hardlinks followed by overwrite.

### Exact selected identity anchors (read-only hashes)

| File / source | Identity |
|---|---|
| Pico revision | `git:ef203c2b0a3fb793280f5114941416c425c5b461` |
| Pico profile | `1ea9ccf03fde49e92bd3281ee482364bcc6b652f71d881005a2362ea6866a48c` |
| picorv32.v | `0836050971b3c6cdd28ac3b1e5719a67fb645161912bef1e472e63995ceb0622` |
| COPYING | `041ebc727233e5bf096dd41260cbb81014d3d29ca007a15f3b1807d4e9ff288e` |
| Pico closure JSON | `4482caf02fdaa0c5ad8f9e0dcbb6501d392b2b0ec85b02c86084a952acab9ef3` |
| PULP GPIO revision | `git:f82caeb7f7d89427f05e9af5ed31e0675efe0d83` |
| PULP GPIO profile | `2268967fa909658fbc079fc41112a10bba88e7484909153cbc1a5a1b222a0b56` |
| rtl/apb_gpio.sv | `1e271914da4d25c87acd12121dde60a6ed955033870fd7a6730b2c9bafcbcaef` |
| Bender.yml | `daf613df168fe9ef65a58919acc1537e42e266c1b520eb861f1b67f485d53b04` |
| LICENSE | `8632e4ec6001a712686e34f7955879a65d249b43b95b253f29a348f32804487a` |
| PULP GPIO closure JSON | `1a37ff739ae34b7ff16866186c09bf235d3654220e38a15077b93495ae9787e7` |
| Reviewed gate script c924aac | `7180463cc397b7c0be6a1c9ab25a9b5e0db01e2587b4c8bcd6f8a33db0ae9184` |

Selected Pico is native memory completion/RV32, ENABLE_PCPI=0/ENABLE_IRQ=0, COMPRESSED_ISA default0/PROGADDR_RESET default0; selected GPIO is APB3 full-word with12-bit address/32 pads/4-bit pad config. Online CPU request max_wait_cycles1024 and128 CPU operations per case are **new prospective build/operation policy**, not inheritance from the old16-cycle campaign binary. GPIO remains16; no IRQ or retirement grant is added.

## 3. Freeze/preparation gates before execution

1. Root freezes all writers/commits and records full local source/Git basis plus explicit selected-file overlays. Build the new independent source tree, with no imported caches/binaries or ignored pycache. Prepare external full-file SHA/bytes/modes map and full directory/mode map, including independent Git metadata and required empty dirs; retain source/snapshot maps and transfer-archive SHA. Freeze map cannot contain its own final digest.
2. Static selected read-set audit verifies the two source roots, all lock artifacts, both closure documents, profile parameters and protocol/header inputs against that map. Preserve Git revision HEAD/ref/object reachability as evidence; any preparer Git metadata query requires a separate exact read-only authorization, never native/frontend as a copy smoke test.
3. Transfer/unpack to a **new** operation path, restore recorded modes/directories, compare full source/file/directory maps and tools before issuing a ready marker. Any missing Pico file is a preparation failure, not a reason to borrow the P7 project or switch CPU/protocol. Do not overlay the frozen P7 attempt.
4. Gate script does not itself enforce a caller-approved full source/tool manifest. Root's surrounding operation controller must check whole maps, actual selected executable/transitive tool closure and Python dependency directory before launch, retain before/after maps and actual process/exit records. A script hash and same HEAD alone are insufficient.
5. Original/fresh models build under a dedicated external native cache with current source/build identity; former scalar/campaign/native binaries cannot inherit slots/packet behavior. Any actual build failure is retained as that attempt; no source edits or automatic retry under its label.

## 4. Tool/environment prerequisites

Read the new `/root/fanzehui/myfuzz/README.md` before preparation. The old environment attempt1 and its [tool-layout review](p7-i5-tool-layout-source-review-20261018.md) are historical: root subsequently prepared **environment-20261018-attempt3** with the coherent installed Verilator prefix and actually completed the tool metadata query. Reuse the reviewed attempt3 environment after checking its current hashes for this new source; do not reuse the broken attempt1 wrapper layout.

Actual `build._toolchain` selects Verilator, c++, make and ar, hashes executables, requires a real adjacent verilator_bin and derives runtime include hashes from actual `verilator -V`. Frontend allowlists real standard include paths relative to the selected Verilator prefix. Attempt3 selects `/root/fanzehui/myfuzz/tools/verilator-5.051/bin/verilator` with adjacent backend and matching share/include paths, and compiler/make/ar wrappers under `/root/fanzehui/myfuzz/operations/environment-20261018-attempt3/bin`. Build subprocesses pass only PATH/LC_ALL, which this coherent selection supports.

Retained actual query controller PID2936380 is terminal0: nine child queries (Verilator --version/-V, backend, c++, make, ar, git, perl, Python) all exit0, tools/source unchanged. Measured versions are Verilator5.051 devel, GCC13.3.0, Make4.3, ar2.42, Git2.43.0, Perl5.38.2 and Python3.12.3; actual Verilator runtime root is `/root/fanzehui/myfuzz/tools/verilator-5.051/share/verilator`. Attempt3 environment SHA is `9141ae65b8af8a0a1fdd891b64afb6bfc1cf4497a686bf14e35f0d926574f15c`,11-entry tool manifest SHA `6591a2023be5c4564d72d4a224d8c6c4b543fd811884f540355273eefbd63b4b`. These facts are read from [the actual P7 operation archive](evidence/p7-i5-attempt1-terminal-20261018/archive-receipt.json) and the latest [preparation report](p7-i5-remote-independent-preparation-20261018.md), not newly executed here. They establish queried selection/layout, not a frontend/build/native result or automatic approval for changed source. Root must recheck current tool files/transitive inputs and bind them to the P6 snapshot's own freeze.

Use selected nonoptimized Python with source-first PYTHONPATH pointing to the new project, then the approved `/root/fanzehui/myfuzz/pythonlib` only if needed. Do not inherit an old project PYTHONPATH or Git directory/worktree/object-store/config-count overrides; set no bytecode/no optional Git locks/no system Git config/empty global config/no lazy fetch. Remove compiler flag overrides and pytest options. This script does not require a pytest/RFuzz client invocation or SysV IPC gate; Python/stdlib/import closure still needs actual selected-interpreter validation under root's rules.

## 5. Prospective exact native invocation (NOT executed)

Proposed new operation base:
`/root/fanzehui/myfuzz/operations/p6-native-online-c924aac-20261018-attempt1/`

Its `project/` is the new independently verified snapshot, `run/` must be absent, `native-cache/` and `tmp/` external to project, and `control/` retains freeze/tool/controller receipts. After root approves the actual environment and maps, the payload command is:

```bash
MYFUZZ_SOURCE_ROOT=/root/fanzehui/myfuzz/operations/p6-native-online-c924aac-20261018-attempt1/project
export MYFUZZ_SOURCE_ROOT
source /root/fanzehui/myfuzz/operations/environment-20261018-attempt3/environment.sh
PYTHONDONTWRITEBYTECODE=1 PYTHONOPTIMIZE=0 \
PYTHONPATH=/root/fanzehui/myfuzz/operations/p6-native-online-c924aac-20261018-attempt1/project/src:/root/fanzehui/myfuzz/operations/p6-native-online-c924aac-20261018-attempt1/project:/root/fanzehui/myfuzz/pythonlib \
python3 /root/fanzehui/myfuzz/operations/p6-native-online-c924aac-20261018-attempt1/project/scripts/verify_picorv32_native_online.py \
  --output /root/fanzehui/myfuzz/operations/p6-native-online-c924aac-20261018-attempt1/run \
  --cache-dir /root/fanzehui/myfuzz/operations/p6-native-online-c924aac-20261018-attempt1/native-cache \
  --heavy-lock /root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock
```

`python3` here must resolve to the separately pinned interpreter; PATH, TMPDIR and sanitized Git/tool settings must already be installed by the root-approved environment. The existing canonical lock is shown to preserve coordination; root must confirm current README/worker policy rather than invent a second lock under the new project. The script is the sole nonblocking lock owner; controller must **not** acquire the same lock around it. Controller observation timeouts retain and await the same PID, no kill/restart/retry or queued second worker. All target operations stay beneath `/root/fanzehui`; jumpserver is transit only.

## 6. Expected bounded evidence and open limits

Success requires positive3 CPU/IP/CPU packets plus full fresh, controlled response corruption1 packet plus controlled full fresh, two actual model processes per run (eight total) reaped0, exact same original process/nonce/epoch across cases and distinct fresh identities. Preserve all plan/events/raw receipts and actual readback→CPU response→joint RAM/GPIO joins; per-runner failure namespaces and original primary error remain authoritative on failure.

Only after independent evidence audit may the result be called this bounded directed gate passed. It does not complete18-cell campaigns, RFuzz searched, authenticated retirement/source authority, four feedback hit classes, throughput/P8 or P7. No actual command/exit/model count is claimed by this plan.

## 7. Local Pico Git metadata inspection (filesystem only)

After the tool-status correction, independently inspected the local `third_party/picorv32_upstream_reference/.git` filesystem/config/refs using standard-library reads/lstat and plain file hashes. No Git executable, project import, model, build or test was invoked; no metadata was changed.

- `.git` is an embedded directory, not a worktree pointer. It has29 regular files totalling287,634 bytes and17 directories including its root. All regular files have nlink1; no symlinks or special files were observed.
- Empty directories are `branches`, `objects/info` and `refs/tags`. Preserve them explicitly. `objects/` and `refs/` both exist, unlike the failed remote Ibex metadata layout.
- No `.promisor` pack, alternates, commondir/gitdir pointer, partialclone/promisor/worktree/alternate/extensions config token or external config include was found. Actual config contains only normal core settings, origin URL/fetch and main branch tracking. The remote URL is documentary provenance, not permission to fetch.
- This is a **shallow** source checkout: `.git/shallow` contains exactly `ef203c2b0a3fb793280f5114941416c425c5b461`. HEAD is `ref: refs/heads/main`; the actual loose ref contains the same selected revision. A shallow boundary is distinct from promisor/lazy external object storage and is preserved, not silently removed.
- HEAD SHA256 `28d25bf82af4c0e2b72f50959b2beb859e3e60b9630a5e8c603dad4ddb2b6e80`; shallow/loose-main-ref bytes each SHA256 `f7bb154b9816ed9fe06cbf857323a3c90c7a705e9c62247afebd31f4c123798d`; config SHA256 `944102eeb7d237ec4dc827a40176e8ebbc9d4b6e0fb3e6adfc0a83ac123e01dc`; packed-refs SHA256 `5dca083a1dd1ab25583256f233aa60f5c85686cdf102c7806c5bb1d530b859ea`.

Filesystem findings permit preparing an independent byte copy without first rewriting/promisor-materializing this Pico metadata. They do **not** prove pack connectivity or that every pinned blob is present: those require root-approved exact Git source-verification/preparation operations against the copied tree. Preserve full `.git` files/modes and all17 directories, freeze source before/after and copy without hardlinks; do not assume the PULP/root Git metadata shares Pico's clean layout. No remote copy or connectivity command was performed by this inspection.

## 8. Pure selected-input copy prepared

Created `/tmp/p6-native-online-inputs-20261018/` with reviewed gate plus Pico `picorv32.v`/COPYING and its entire independent `.git`:32 regular files/401,427 bytes,20 explicit directories including all17 Git directories and empty dirs. Source before/after maps are equal (SHA `37594cd6812360a390cb52f2aabc90f8fc720360d39b76ae68fd57d8fb05c725`); new `unpacked/` independently matches every SHA/size/mode/nlink and directory mode, with different source/copy inodes. Archive `pico-native-gate-inputs.tar.gz` is276,926 bytes, SHA `d33a208f5808800b9d9686f250a3a5de8937998126e66635aaf102b72aa7a077`; `receipt.json` and the three detailed maps remain beside it. This is a **selected-input preparation**, not the full P6 source snapshot or Git connectivity/native evidence. No Git command, project import, test/frontend/build/model or remote action ran; P7 snapshot and Pico source were unchanged.
