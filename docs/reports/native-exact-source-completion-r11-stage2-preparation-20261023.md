# r11 Stage 2 local package preparation — 2026-10-23

## Status

A complete local Stage 2 operation package exists at

`/home/qinkejiu/.native-gate/r11-stage2-5a6bfbeb4188/`

with operation root

`/root/fanzehui/myfuzz/operations/r11-native-completion-20261023-5a6bfbeb4188`

(recorded target paths; the local package mirrors that workspace layout). The
package was built only from the committed HEAD tree
`8485893482bea029998e3738057d310bfb499a6c` plus the one checked-out gitlink the
selected gate reads. Its Stage 2 manifest raw SHA-256 is

`54c61ce9ad87e1064c048114f98d8c90371cf8584d2b63f05e19b463f4fa4706`

The frozen controller's own admission path (`main` → `execute`, unmodified
bytes) passed against a disposable byte-copy of the package inside a mount
namespace that exposes the package at the exact recorded target paths. The last
step before child launch — `claimed_run` — was replaced by a recorder, so **no
gate process, no `native-cache`, no gate log, and no evidence directory were
created**. This is admission software evidence only; it is not a gate run and
not an independent audit.

The package has **not** been uploaded to `/root/fanzehui/myfuzz/`. That path is
unreachable for this session (see [Blockers](#blockers)). No gate, runner, or
auditor was executed.

## Frozen identity

| field | value |
| --- | --- |
| HEAD | `8485893482bea029998e3738057d310bfb499a6c` |
| operation id | `r11-native-completion-20261023-5a6bfbeb4188` |
| gate run id | `5a6bfbeb4188b4fec4f7e07eb82f42c47550a7436b0ddf530e4738e046103930` |
| workspace | `/root/fanzehui/myfuzz` |
| operation dir | `/root/fanzehui/myfuzz/operations/r11-native-completion-20261023-5a6bfbeb4188` |
| evidence dir | `/root/fanzehui/myfuzz/evidence/r11-native-completion-20261023-5a6bfbeb4188` |
| Stage 2 manifest | `control/stage2-manifest.v1.json`, raw SHA `54c61ce9ad87e1064c048114f98d8c90371cf8584d2b63f05e19b463f4fa4706`, 4,690 member rows, 824,678 bytes |
| manifest self row | `{path: control/stage2-manifest.v1.json, kind: file, mode: 0644, size: 824678, sha256: 54c61ce9…a4706}` |
| package inventory | 4,271 files + the manifest (4,272 files), 419 directories including the operation root, 0 symlinks, 127,054,293 bytes |

Frozen gate invocation (recorded in `control/intent.v1.json` and
`control/run-plan.v1.json`):

```
argv[0] python3 -B /root/fanzehui/myfuzz/operations/r11-native-completion-20261023-5a6bfbeb4188/project/scripts/verify_picorv32_native_online.py
        --output /root/fanzehui/myfuzz/evidence/r11-native-completion-20261023-5a6bfbeb4188
        --cache-dir /root/fanzehui/myfuzz/operations/r11-native-completion-20261023-5a6bfbeb4188/native-cache
        --heavy-lock /root/fanzehui/myfuzz/.superpowers/heavy-worker.lock
        --gate-run-id 5a6bfbeb4188b4fec4f7e07eb82f42c47550a7436b0ddf530e4738e046103930
        --native-completion-observation --native-source-binding --native-source-completion
cwd     /root/fanzehui/myfuzz/operations/r11-native-completion-20261023-5a6bfbeb4188/project
```

Key control-file hashes:

| file | SHA-256 |
| --- | --- |
| `control/intent.v1.json` | `02958c82ca7fb8013cceafc860c33df727300be17d94abf970fcb80a85b81619` |
| `control/run-plan.v1.json` | `0f03a1e0d4eae546b5dd49bed3b31bcf08913f474aab2dd7854b25972f4f814a` |
| `control/controller-receipt.v1.json` | `88cc4bb2ff0c105b6f51a84913587e13bcea1adffa6ee471c0b63c00e6cef70f` |
| `control/environment.v1.json` | `3505256f7a2c03c73c227c36cc256e1b9d8aed491d769135b37c0e8e2faa0a9c` |
| `control/tool-freeze.v1.json` | `9c1f142c2f012778a516572d7cc5cbeed25558b6cc86e3e6315e0f97743c9f46` |
| `control/source-manifest.v1.json` | `80d9c968b054aa79a760e76408ac01703530bdddac878cbdb51bf7bdf6aa5edf` |
| `control/source-snapshot-map.v1.json` | `e24efb66ac4841344890dbe9db9916bbbc64b4b6d79aeab979c19fbaa666d061` |
| `control/submodule-manifest.v1.json` | `662414d919e670d87d8edaf353f344b81d8798af05c326d5386bf34e3cde3e79` |
| `control/r11-static-code-manifest.v1.json` | `a944ef09f414642541854d36955a81b906f213b4705b2e09cc96372de7f84059` |

## Source snapshot

Built with `git archive 8485893` into `project/`, which is byte-exact committed
content (not the dirty working tree). Exactly four top-level directories are
excluded, each recorded with an exact path and reason in
`control/source-snapshot-map.v1.json#exclusions`:

- `docs` — report/evidence archive (454 MiB of prior evidence tarballs and logs); no selected native-source gate input
- `.superpowers` — progress/checkpoint state, not a source or execution input for the selected gate
- `examples` — sample scenario bundles, not part of the selected gate execution closure
- `runs` — saved run outputs, not source input for the selected gate

The snapshot contains 3,354 entries (3,033 regular files). `control/source-manifest.v1.json`
lists every regular file (3,033 rows), including
`project/scripts/verify_picorv32_native_online.py`, whose bytes equal the frozen
Stage 1 `r11-gate-script.v1.py` (SHA `1422dc3f595eb97f181a6a875d271af238031d7fbd7d5f9a2914c54ab4cc7124`).
`intent.source.task5_files` pins the 11 files of the selected gate's execution
closure (gate script, `scripts/verifier/native_completion_gate_checks.py`, the
picorv32 online integration/scenario modules, session runtime, contracts,
local-harness session, the picorv32 component profile, and `picorv32.v`).

All 23 committed gitlinks are recorded in `control/submodule-manifest.v1.json`.
Only `third_party/picorv32_upstream_reference` is materialised — extracted from
its recorded commit `ef203c2b0a3fb793280f5114941416c425c5b461`, which equals the
profile's pinned `git:` revision — and its 248 selected entries hash-join the
snapshot map. The other 22 gitlinks are recorded as `checked_out=false` with
`checked_out_head=null` and zero selected entries: their checkouts are not read
by the selected gate and are excluded from the snapshot, not silently ignored.

The `control/source-snapshot-map.v1.json` entries are an exact no-follow rescan
of `project/` (including mode and the `.` root row), so the controller's
preflight comparison is an equality, not a normalization.

## Workspace-local Python/tool closure

The package carries its own interpreter and runtime rather than resolving the
ambient host PATH/PYTHONPATH:

- `tools/python3`, `tools/python3-controller`, `tools/python3-auditor` — three
  distinct singly linked copies of `/usr/bin/python3.12` (CPython 3.12.3),
  `tools/python3` is frozen as `tool_freeze.python3` and is the gate/auditor
  interpreter; the controller interpreter is a separate file.
- `tools/pythonlib/lib/python3.12/**` — 1,201 stdlib files copied from
  `/usr/lib/python3.12` (`sitecustomize.py` and the build config directory are
  omitted); `PYTHONHOME` points at `tools/pythonlib`, `PYTHONPATH` at its
  `lib/python3.12` directory.
- `tools/lib/` — the ELF loader plus 18 shared libraries resolved from
  `ldd` of the interpreter and every `lib-dynload/*.so`; `LD_LIBRARY_PATH`
  points here. The loader is recorded as a closure file; the interpreter's
  `PT_INTERP` is still the host loader path, which is noted under limits.
- Frozen child environment in `control/environment.v1.json`: `PATH`,
  `PYTHONHOME`, `PYTHONPATH`, `LD_LIBRARY_PATH`, `PYTHONDONTWRITEBYTECODE=1`,
  `PYTHONNOUSERSITE=1`, `PYTHONHASHSEED=0`, `LC_ALL/LANG=C.UTF-8`, `TZ=UTC`,
  `TMPDIR/TMP/TEMP/XDG_CACHE_HOME/PYTHONPYCACHEPREFIX` =
  `<operation>/native-cache`.

Every PATH/PYTHONPATH directory is an exact Stage 2 directory row; every
interpreter, runtime-closure, and resolved-command file is an exact Stage 2 file
row under `<operation>/tools/`; `python3` resolves to
`interpreters.gate` as the first executable in frozen PATH order. `native-cache`
is absent and excluded from the manifest; the controller creates it privately
(mode 0700) after claim.

## Built files and build receipt

Builder: `scripts/task5_native_completion_r11/r11-stage2-builder.v1.py`
(new, committed). It performs the snapshot, gitlink materialisation, tool copy,
manifest and intent/plan/receipt generation, and writes:

- `stage2-build-receipt.v1.json` (SHA `30fa04b64d17c232b33353639f47b7fc888084bbff3ce6647ac3c9c464670b38`)
- `stage2-package-identity.v1.json` (SHA `06b952bdafa06ccb8cc8bde3e859f409595d87753657a0d3e29b643cfe5d84b6`)
- `stage2-package-verification.v1.json` (SHA `57249ec6d572cc43631254c874eaf24d284864ba8e619a04ea6bc3474d0462ad`)
- `stage2-preflight-admission.v1.json` (SHA `a64b04b3714bb10cfedc1e458f5f6b21b8d66b0c64b9636072f3df6901b72395`)

These receipts live at the local workspace-mirror root, outside the operation
tree, and are therefore not Stage 2 members and do not affect its digest.

## Admission preflight evidence

Harness: `scripts/task5_native_completion_r11/r11-local-admission-check.v1.py`
(new, committed). It imports the frozen controller by path with
`sys.dont_write_bytecode = True`, replaces only `claimed_run` with a recorder,
then calls `controller.main()` with the exact recorded argv. The run happens in
`unshare -rm` with a tmpfs on `/root`, a bind mount of a `cp -a` copy of the
package at `/root/fanzehui/myfuzz`, and an empty
`/root/fanzehui/system-20261016`; the harness runs with the frozen environment
(`env -i` plus `environment.v1.json#vars`).

Result: `status = "admission_preflight_passed"`, `gate_launched = false`,
`claimed_run_stubbed = true`. Verified checks (all true): controller return code
0, `claimed_run` called exactly once, operation/evidence/workspace identity,
run-id propagation, Stage 2 SHA in claim, plan/intent/controller joins, exact
argv in claim, preflight protected/submodule maps written, and **absence** of
`launch-intent`, `native-cache`, gate logs, evidence directory, gate-end and
post-run receipts.

The disposable copy is at `/tmp/r11-preflight-5a6bfbeb4188/`; the deliverable
was not mutated (its claim and all dynamic leaves remain absent). The exact
controller `main` invocation used for a real target run is recorded in
`stage2-build-receipt.v1.json#preflight_argv` (minus the harness substitution).

Limits of this evidence: `claimed_run` (dynamic-cache creation, spawn,
process-group observation, collection, success receipts) was not exercised
here; the protected roots in the namespace are locally created empty
directories, not the real target baselines; and this is not an independent
audit.

## Independent exact-digest reviews

Two independent reviewer agents were asked to recompute the raw manifest SHA and
read back every member (uid/gid/nlink included) without trusting package
receipts, and to write:

- `docs/reports/evidence/native-completion-r11/reviews/stage2-preupload-review-a.json`
- `docs/reports/evidence/native-completion-r11/reviews/stage2-preupload-review-b.json`

Status: **both reviews accepted, independently and without reading any package
receipt.** Each reviewer recomputed the manifest raw SHA as
`54c61ce9ad87e1064c048114f98d8c90371cf8584d2b63f05e19b463f4fa4706`, read back
all 4,691 rows (4,690 members plus the manifest self row) with no-follow
`stat`/`readlink`, re-hashed every file, re-walked the operation root, re-scanned
`project/`, and re-hashed all 3,033 source-manifest rows. Both report
`verdict = accepted` with no findings; reviewer A also reproduced the result
through a second tool path.

| review | reviewer id | review file SHA-256 | reviewed_at | verdict |
| --- | --- | --- | --- | --- |
| A | `r11-stage2-preupload-review-a` | `b4e0fe0c052b1f3430ee87e6c4223cd4d6311238afb137d30cb9825b20c6a666` | 2026-10-22T22:44:43Z | accepted, 0 findings |
| B | `r11-stage2-preupload-review-b` | `b152921e2076953fa9544c4d465d6f8927008e9ccb5140fb34f055d0e66d2d52` | 2026-10-22T22:44:07Z | accepted, 0 findings |

The two reviewer IDs are distinct and the two files are separate exact-digest
records of the same package bytes. They are operator evidence outside the
operation tree; they are not cryptographic signatures and do not substitute for
the missing target-upload reviews or the post-gate identity review. Both review
files were validated after writing against the manifest: exact top-level key
set, `subject_kind = stage2_preupload`, equal subject/observed digest, accepted
verdict, unique and sorted 4,691 rows, per-kind key sets, self-row digest and
size, and row-by-row equality with the manifest members.

The `stage2-package-identity.v1.json` record was written before these reviews
finished and therefore still carries `status_at_record_time = pending`; the
review files above are authoritative for the review outcome.

## Blockers / missing checks

1. **Target upload is impossible from this session.** `/root` is `0700
   root:root`; uid 1000 cannot traverse it, so `/root/fanzehui/myfuzz/operations/`
   and `/root/fanzehui/system-20261016/` are unreachable (`EACCES`,
   `os.access(..., W_OK) == False`). `sudo` requires a password and approval
   prompts are disabled in this session. No target write, no target readback,
   no `stage2-upload-review-{a,b}.json` ownership/link-count review, and no
   post-upload byte comparison are possible. The package therefore stays local.
2. **Two target/upload reviews are missing** (`stage2-upload-review-a.json`,
   `stage2-upload-review-b.json`), by construction: they require the uploaded
   on-target bytes plus target owner/link-count readback. The two preupload
   reviews above do not substitute for them.
3. **The post-gate audit identity SHA is missing** and cannot be produced: the
   final `control/audit-identity.v1.json` hashes dynamic claim/launch/start/end/
   post receipts, gate stdout/stderr, three branch gzip results, and the
   summary. Fabricating it before a gate would be false evidence. Its separate
   review file `audit-identity-sha-review.json` is likewise post-gate.
4. **The one-shot gate was not run** (per instruction and because the package is
   not uploaded/reviewed). The controller's dynamic-cache/spawn/wait/
   process-group/collection path and the runner/auditor joins remain unexercised
   against a real operation.
5. **Tool-identity limits remain unchanged.** The frozen interpreter's
   `PT_INTERP` still names the host loader (`/lib64/ld-linux-x86-64.so.2`), even
   though that loader and the 18 libraries are copied and hashed in the
   package; the auditor's `external_tool_bytes_verified` and
   `gate_executable_identity_verified` remain false. `source_tree_closure_verified`
   also remains false. No new claim is made.

## Next steps once target access exists

1. Copy the local package byte-for-byte to
   `/root/fanzehui/myfuzz/operations/r11-native-completion-20261023-5a6bfbeb4188`
   with exclusive no-follow creation and target readback (bytes, SHA, size,
   mode, owner, link count).
2. Recompute the Stage 2 manifest SHA on target and obtain the two
   `stage2-upload-review-{a,b}.json` reviews.
3. Run the one-shot controller once with
   `--stage2-manifest-sha256 54c61ce9ad87e1064c048114f98d8c90371cf8584d2b63f05e19b463f4fa4706
   --execute` (exact argv above), then the two-phase runner (`prepare`, then
   `audit --identity-sha256 <independently reviewed identity SHA>`).
4. Only after the independent audit returns `passed` should any completion
   claim be made.
