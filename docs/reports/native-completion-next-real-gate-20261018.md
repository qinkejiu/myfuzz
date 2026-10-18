# Native completion next directed real gate (2026-10-18)

## 后续源码推进（尚未实际开跑）

本文初始 NOT READY 清单之后，CLI `9b04f8d`、guarded fresh
`29048b3`/`ae13270` 及 typed nonce full-comparison `b7c8087`/`16e9b12`
已完成源码增量。独立源码复核关闭 fresh 清理 Important，未发现新重要项。
对应显式 HARNESS v2 闭包现为69路径，须包含 native_replay_identity.py。
下文68及未接线描述是设计冻结时状态。仍需独立 raw 指标与负例、新源码冻结、
工具/目录闭包审查及新实际门；没有原/fresh pass 可继承，不得据源码宣布 READY。


Status: read-only source design; **NOT READY TO LAUNCH**. No tests, project imports, frontend, build, model, tool query or remote command ran for this report. P6/P7/P8 remain OPEN. The old bounded directed evidence validates its own frozen source only; it cannot validate the new opt-in, observer, guarded session or host identity.

Source basis: [persistent-search plan](../superpowers/plans/2026-10-18-p6-native-persistent-search.md), [observer source](native-bus-completion-observer-source-20261018.md), [opt-in](native-online-completion-optin-20261018.md), [68-path host identity](native-host-identity-20261018.md), and current `scripts/verify_picorv32_native_online.py`, `scenario/native_cpu_events.py`, `scenario/native_packet_session.py`, `scenario/session_runtime.py`, and both native-online assembly modules. This is a future bounded directed observation gate, not RFuzz/four-feedback acceptance.

## Launch prerequisites

1. Freeze and independently review the final changed source, including any concurrent edits. Record commit plus exact bytes; a commit label alone cannot identify a dirty snapshot. Preserve both complete file and directory maps, including empty Git directories, in a new operation. Do not overwrite the old P6/P7 worksets.
2. Add an explicit boolean opt-in to the gate script and forward `native_completion_observation=True` into `make_picorv32_native_online_runtime`. Current script constructs the runtime without that keyword and has only `--output`, `--cache-dir`, `--heavy-lock`; it therefore exercises the legacy path. Passing an invented CLI flag to it is invalid. CPU must use admitted v2 PRE/POST tuning; GPIO remains its existing v1 artifact.
3. Resolve guarded full fresh before launching. Current runtime calls `replay_online_session`, whose online reconstruction instantiates plain `ScenarioSession`. Require a closed native-packet dispatcher that rebuilds `NativePacketSession`, all 97 reservations, immutable tails, 32-byte stride, source grammar, schedule and configured case bound. Preserve before/after physical guards during fresh; no per-case reset or replacement RAM. A runner factory forwarding the opt-in alone does not fix this.
4. Add narrowly typed fresh normalization for the new actual driver/observer scope fields. Preserve raw original/fresh nonce/PID documents; normalize only verified identity fields in semantic comparison. Never erase arbitrary `execution` keys or remove native observations to force equality. Resolve source/nonce-bearing identity handling before running a fresh that is already known to mismatch.
5. Extend the gate's checker to require the new actual completion evidence and all transaction joins below. Existing `check_case` checks backend consumption and arithmetic; those checks alone do not accept native completion.
6. Independently review and qualify lifecycle/negative controls and failure cleanup. Required software/control verification must be explicitly scheduled separately; none was run here. The gate must persist the first error, complete prefix, boundary snapshot and actual reaped process receipts even on original/fresh begin, submit, decoder commit, finish or evidence-write failure.
7. Reconcile all 68 explicit HARNESS v2 host paths with the exact new snapshot; none missing/duplicate and no stale pinned digest. Include the actual transitive build host-source closure as well: 68 explicit paths are not the whole dependency set. Include full `scripts/` host-identity dependencies, profile/interface/lock/proof/RTL and Git metadata, Python dependencies, native templates and drivers. Recheck tool files/transitive runtime inputs against the operation's own tool freeze. Existing 63-path/legacy source receipts are insufficient.
8. Confirm the prior heavy operation is terminal from its durable receipts, then take the canonical nonblocking lock once. Lock contention is a terminal not-started outcome, not permission to start another cache/build. Use a fresh output/cache outside frozen project. No repeated old heavy gate is needed to establish a baseline.

## Exact launch contract after prerequisites

The existing gate command shape is valid only after the script has a reviewed explicit opt-in option. The following specifies that future interface; **the option is not implemented by the current script**. Proposed new operation is `/root/fanzehui/myfuzz/operations/p6-native-completion-20261018-attempt1`; every path remains under `/root/fanzehui`.

```bash
/root/fanzehui/myfuzz/operations/environment-20261018-attempt3/bin/python3 \
  /root/fanzehui/myfuzz/operations/p6-native-completion-20261018-attempt1/project/scripts/verify_picorv32_native_online.py \
  --output /root/fanzehui/myfuzz/operations/p6-native-completion-20261018-attempt1/run-directed \
  --cache-dir /root/fanzehui/myfuzz/operations/p6-native-completion-20261018-attempt1/native-cache \
  --heavy-lock /root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock \
  --native-completion-observation
```

Before making this concrete command executable, confirm the actual Python wrapper path against the newly frozen environment; this report did not query it. Use the existing reviewed source-first environment, `PYTHONDONTWRITEBYTECODE=1`, operation-owned TMPDIR and preserved empty global Git config. A parent controller must retain argv, cwd, selected environment identities, PID/start/end, stdout/stderr bytes+SHA and actual exit status. The SSH path is `ssh jumpserver 'ssh root@192.168.5.70 …'`; jumpserver only forwards. Do not execute this draft.

Directed inputs remain three deterministic selections `cpu.instructions → gpio0.pin_byte → cpu.instructions`, max_cases=3, CPU128 operations/case and unchanged GPIO schedule. `select_raw` uses at most4096 SHA proposals from `native-three-case:{wanted}:{attempt}`; retain all accepted raw8 bytes, decoded source/action IDs, instruction word/pin byte, plan and actual packet addresses. Recompute selection for the new freeze; old raw examples are historical, not authoritative new inputs. Bound CPU wait1024, GPIO wait16 and reset8/8 unchanged. Positive and one-case controlled-response execution each get their own original and full fresh runner pair; the controlled target-read perturbation remains XOR1 exactly once per original/fresh, with original target samples preserved.

## Native evidence acceptance

Retain complete verified DriverReceipt and raw PRE/POST frames, command nonce/sequence, local ticks, reset epoch, native role metadata and artifact/build/source identity. Require actual native `mem_valid && mem_ready` **PRE**, instruction marker, address, read strobes and actual `mem_rdata`. Backend response consumption at tick T precedes native completion PRE at exactly T+1; response-tick POST ready/rdata is only an offer. Completion POST may already show the next CPU tuple. Raw native/backend samples and emitted observations must agree.

Reconstruct a single outstanding transaction sequence from **every** accepted request, including instruction fetches, ordinary RAM data reads/writes and routed MMIO; never count instruction-marked requests alone. Join accepted backend request → actual RAM immutable ReadSnapshot or actual Router/target response → backend response pending epoch/sequence → native completion. Match returned data and preserve full transaction keys and raw event references. Use the actual new counts, not the old 47-request example. Validate no sequence gaps/duplicates, request/marker instability, orphan response/completion, reset-scope crossing or pending transfer hidden between response and native handshake.

Instruction marker1 means instruction bus transfer, marker0 means data bus transfer. Neither grants source-byte consumption automatically. Current observer has transfer-only scope, source-authority=false and retirement=false; exact admitted four-byte writer/source joins and GPIO byte source consumption remain separate prerequisites for feedback. No APB-phase, retirement, IRQ or four-feedback authority is inferred.

## Required controls and durable receipts

- Saved-data controls independently remove/change ready, valid, rdata, PRE/POST phase, marker, address/strobes, request/response sequence, epoch/nonce, writer lane and snapshot reference. Substituting marker0 data traffic or support NOP must not certify admitted instruction-source consumption. Offline controls cannot issue live tokens.
- Lifecycle controls cover a pending request, backend response consumed but native completion not yet sampled, reset cancellation, close with incomplete transfer, poisoned observer retry, abort/re-submit, failure after physical submit but before decoder commit, and original/fresh begin/finish failures. Pending accounting must remain nonzero until actual native completion; cancellation never emits completion. Capture real process exits on each exercised branch.
- Guard controls cover malformed pure rejection with no effect/cursor use, packet cursor/queue mismatch before injection, post-case pending state, duplicate case identity, limit exhaustion and terminal failure retry. Preserve attempted plan and physical prefix; do not add clocks to satisfy a boundary.
- Retain `positive/plan.json`, per-case JSON, complete first/fresh bundles, comparison document, controlled-response records, all `runner-N-partial` bundles on failure, boundary/packet failure snapshots and independent check output. Explicitly retain original/fresh CPU+GPIO Popen identities, nonce, epoch, artifact digest and actual wait/poll return code after reaping: eight DUT rows for normal positive/control plus their fresh pairs. Process absence is not an exit-code receipt.
- Parent/controller and every invoked child need terminal receipts. Before/after full source file+directory, all68 host paths/transitive closure, tools and declared client/input maps must compare equal. Download control/run evidence through read-only tar, excluding cache/project binaries; retain archive/member SHA and durable local control under `.superpowers/sdd/`, never only `/tmp` or an ephemeral tool handle.

Accept only full warmup→all cases→finish replay with new PID/nonces, identical artifacts and declared normalization; compare all native observations and terminal queues. Any unresolved prerequisite leaves this gate NOT READY. Even a future passing directed gate closes only actual native transfer observation and its bounded replay/control scope; persistent RFuzz source grants, all four feedback classes, campaign/throughput and overall P6/P7/P8 remain OPEN.
