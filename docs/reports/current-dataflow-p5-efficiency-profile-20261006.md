# P5 efficiency profile: Ibex + dual PULP GPIO

## Scope and commands

The current P5 gate requires a 600 second search, equal-budget persistent versus per-testcase startup comparison, useful chain throughput, replay, and separate host/RTL costs. This report records a focused current-worktree profile and audits existing artifacts; it does not claim the full P5 gate.

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m cProfile \
  -o /tmp/myfuzz-p5-profile-20261006.pstats \
  scripts/run_ibex_pulp_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir /tmp/myfuzz-online-cache-20261006 \
  --output /tmp/myfuzz-p5-profile-20261006 \
  --seconds 40 --max-tests 100 --seed 20261006
```

Exit 0. The run produced 100/100 `complete` receipts, 0 invalid/timeouts/findings, 32.985 seconds of *profiled* effective search, 10,192 independent local ticks (CPU 3,200; GPIO A 3,396; GPIO B 3,596), and 18 distinct new interaction feature labels in the receipts. Its selected sources were 99 GPIO B pins and 1 CPU instruction. The plan SHA-256 is `95e5c20c4342a9ecaa37fb57fca9ab00a33140458d7c64420143b88f478d64cc`. Artifacts are in `/tmp/myfuzz-p5-profile-20261006` and the pstats file above. The trace is normal terminal evidence, but fresh replay was not run for this profiling sample. cProfile changes wall-time behavior; 100/32.985 = 3.03 cases/s is not an uninstrumented throughput result.

The previous frozen-worktree 600 second persistent run at `runs/ibex-pulp-online-20261006-balanced-600s` reports 8,723/8,723 `complete` receipts in 600.125 effective seconds, 14.54 valid cases/s, and 20 distinct new interaction feature labels. Source choices were 2,650 CPU and 6,073 GPIO B. Its event log and trace metadata are retained there. The older 30-case cold baseline at `runs/ibex-pulp-cold-baseline-20261006.json` records 30/30 complete and matching source/path choices, with 525.046 seconds total and 522.554 seconds in initialization. It only compares startup cost: independent cold sessions erase RAM, IRQ, prior coverage and search history. The cold baseline and persistent run cannot establish equal checker/replay quality or useful chain throughput by themselves.

## Profile result and proposed optimization

The full cProfile call tree took 108.949 seconds: one-time runtime creation 65.539 seconds (including source admission, compilation, initialization, and manifest construction), and RFuzz live execution 33.446 seconds. These cumulative times overlap and must not be added. Within live execution, `ScenarioRfuzzExecutor._execute_online_batch` took 33.228 seconds and `ScenarioSession.submit_case` 26.186 seconds. The latter drives real RTL; `ScenarioRunner.execute_step` took 21.553 seconds over 9,759 calls, including subprocess polling and receipt processing.

Host copies are a concrete hot-path cost. `deepcopy` accumulated 32.168 seconds across the full profile (overlapping its callers). `ScenarioRunner.events_since` took 4.058 seconds over 153 calls, and `ScenarioRunner.event_by_id` took 5.635 seconds over 72,318 calls. The `event_by_id` callers were `InteractionFeedback.ingest` (47,843 lookups, 3.857 seconds) and its witness lookup (24,475 lookups, 1.778 seconds). Almost all of `event_by_id` time was its detached `deepcopy` (5.431 seconds). `InteractionFeedback.ingest` itself took 6.301 seconds.

After the concurrent P2 source-identity gate finished, the online executor was changed to pass the Runner's private `_event_ref_by_id` lookup to `InteractionFeedback`. This synchronous trusted reader compares events and does not mutate or retain the borrowed journal record; public `event_by_id` still deep-copies. The new test failed first with `AttributeError` for the absent lookup, then passed after implementation. It covers a chunk spill, public mutation isolation, feedback ingestion, and mismatch rejection. A second red-to-green test confirms the executor wires the private lookup. The focused suite command below passed with `52 passed, 23 subtests passed`:

```bash
PYTHONPATH=src:. python3 -m pytest \
  tests/scenario/test_dep03_consumption_cursor.py \
  tests/scenario/test_interaction_feedback_incremental.py \
  tests/integration/test_rfuzz_runtime_path_preflight.py \
  tests/scenario/test_event_journal.py \
  tests/scenario/test_interaction_edge_provenance.py -q
```

For a same-process lookup comparison, the first 30,000 real events from the 100-case trace were appended to an `EventJournal(chunk_size=2048)`. Each lookup read IDs 1..30,000 in order, three times, with the same checksum (`1,350,045,000`). Public detached lookup took 0.7125/0.5635/0.5794 seconds; private borrowed lookup took 0.0826/0.0825/0.0867 seconds. Median time fell from 0.5794 to 0.0826 seconds, about 7.0× for this lookup operation. This microbenchmark does not measure whole-case speed or identical feedback/checker behavior under a 600 second run. The original profiled 5.431 seconds of `event_by_id` deep-copy time is an upper bound on possible 100-case cProfile savings, not a predicted wall-time gain.

Post-change real RTL smoke used the same client/cache/seed with `--seconds 30 --max-tests 20 --output /tmp/myfuzz-p5-borrowed-smoke-20261006`; exit 0, 20/20 `complete`, 1.732 effective search seconds. Fresh replay with its saved `online_plan.json` and `online_final_trace.json` exited 0 with `matches=true`, `first_difference=null`. Plan SHA-256: `6b3a1d3eb4ac6117c87392d7507d65461a6c8dea71562bfcd43ebab48d419986`; trace SHA-256: `5ab3d6d6ffe0b130ea3bdc27f36b0f7c487f0660246a284e8685277773ab1e00`. This checks semantics for a short current-source session; it is not the ten-minute efficiency gate.

## First 600 second post-optimization run: retained identity failure

A 600 second real run was saved in `runs/current-dataflow-p5-optimized-600s` with seed `20261006`, new cache, and maximum 20,000 tests. Command exit was 0; `report.json` records 600.208 effective search seconds, 5,243/5,243 complete receipts, 639 feedback exchanges, 523,560 summed independent local ticks, and zero status-level failures. This is 8.74 complete receipts per effective second. The source choices recorded in receipts were 2,625 GPIO B external-pin cases, 2,308 CPU instruction cases, and 310 entries with no applied source ID. Twenty distinct new interaction feature labels appeared; receipt labels alone do not prove twenty completed causal chains. The saved trace metadata records 2,108,463 events; its JSONL is 2.1 GiB.

This run overlapped a P2 real gate, and `runner.py`, `host_identity.py`, `session_runtime.py`, and `uart_operand_seed.py` changed after the run started in a separate workspace process. Fresh replay with the saved plan and trace metadata exited 1 at `harness host source identity mismatch`, before claiming any comparison. The run is retained as throughput and storage-cost diagnostic evidence only. Its 8.74 receipts/s cannot be compared causally with the older 14.54 receipts/s sample because source identity and concurrent load differ. A new frozen-source 600 second run is required for P5 acceptance.

A second original-worktree run, `runs/current-dataflow-p5-optimized-600s-finalfreeze`, also completed with exit 0 and 5,387/5,387 complete cases in 600.664 effective seconds (8.97 receipts/s). It logged 2,166,075 events, 537,928 summed local ticks, 20 distinct new feature labels, 2,697 GPIO B selections, 2,371 CPU instruction selections, and 319 receipts without an applied source ID. The workspace changed `runner.py`, `host_identity.py`, and `session_runtime.py` during this run, despite an intended freeze. Its replay likewise exited 1 at `harness host source identity mismatch`. Both original-worktree long runs are diagnostic, not replay-verified P5 gates. The authorized isolated snapshot at `/home/qinkejiu/myfuzz_snapshot_p5_20261006` has a 1,170-file source/config/script/schema manifest `runs/current-dataflow-frozen-snapshot-20261006.sha256` (SHA-256 `be9c25d70a2ef2b766a954a049b486da0688d5fd51aa7a49504dfde1031e082d`); its independent ten-minute gate follows in a separate output directory.

## Isolated snapshot 600 second run

The same seed `20261006` was run from the isolated source snapshot with a new cache and output `runs/current-dataflow-p5-snapshot-600s`. The command exited 0 and `report.json` records 600.979 effective search seconds, 5,563/5,563 complete cases (9.257 receipts/s), 679 feedback exchanges, and zero other receipt statuses. The 5,563 receipts include 2,785 GPIO B external-pin choices, 2,448 CPU instruction choices, and 330 without an applied source ID. They contain 20 distinct new interaction feature labels; these labels are not a count of completed causal chains. The saved full trace has 2,236,544 events and 555,492 summed independent local ticks. Online run identity SHA-256 is `8ea499e2142cbc2d76dbbd1c47d3f0aaf9cad5b2fc4497e94fc734fb315557cf`; trace semantic SHA-256 is `4c1b76ca5f63f3723eeb0a94088b05c164dd843e3fdf0d3538329708d310f0c4`.

Fresh replay was started from the **same snapshot** with a separate new cache, using `scripts/run_ibex_pulp_online.py replay --plan runs/current-dataflow-p5-snapshot-600s/online_plan.json --trace runs/current-dataflow-p5-snapshot-600s/online_final_trace.meta.json`. It exited 0 with `matches=true`, `first_difference=null`, `difference_context=null`. All 1,170 files in the snapshot manifest were rehashed after the run and replay: **zero differences**. The full event JSONL occupies about 2.2 GiB, and end-of-run evidence serialization and full fresh replay each took several additional minutes beyond the 600.979 seconds of effective search. These costs are visible bottlenecks; the current report lacks separately instrumented exact finalization/replay wall times. This run proves persistent real RTL search and full-prefix replay for this snapshot, while the original worktree may contain later edits.

## P5 gate limits

### 同源码冷启动对照（2026-10-07）

在上述 600 秒持续搜索所用的同一独立快照 `/home/qinkejiu/myfuzz_snapshot_p5_20261006` 中，按其 `receipts.jsonl` 的前 30 个精确八字节输入和保存的在线权重，逐例新建 Ibex＋双 GPIO runtime、执行、终结；使用新的构建缓存目录。命令为 `python3 scripts/bench_ibex_pulp_cold_start.py --receipts /home/qinkejiu/myfuzz/runs/current-dataflow-p5-snapshot-600s/receipts.jsonl --cache-dir /home/qinkejiu/myfuzz/runs/current-dataflow-p5-snapshot-cold-20261007-cache --output /home/qinkejiu/myfuzz/runs/current-dataflow-p5-snapshot-cold-20261007.json --count 30`。结果保存在[冷启动逐例计时](../../runs/current-dataflow-p5-snapshot-cold-20261007.json)：30/30 `complete`、0 错误、30/30 源选择和路径身份与原回执一致；总耗时 598.988 秒，其中初始化累计 595.208 秒、执行累计 2.501 秒、终结累计 1.262 秒。每例总时延 p50 为 19.264 秒，线性插值 p95 为 21.026 秒；初始化 p50 为 19.144 秒、p95 为 20.917 秒。快照 1,170 个清单文件在对照后复核，0 个差异。

与同快照约 600 秒的持续搜索相比，冷启动吞吐为 30/598.988＝0.0501 个完成例/秒，持续会话为 5,563/600.979＝9.257 个完成例/秒，计数吞吐约 184.8 倍。两边均使用真实 RTL 和默认场景 checker，冷启动程序明确标记其比较范围为 `startup_cost_only_not_coverage_equivalence`：每例重建状态，不能保持持续运行中的 RAM、IRQ 和覆盖历史。因此这个数字证明了避免逐例初始化的时间收益，不证明两组有相同因果链覆盖或相同故障发现能力。冷启动只取原始前 30 例，约 599 秒为实测耗时，并非固定 600 秒预算截断。

After the snapshot long run, the live report writer gained `finalization_timing_seconds` for `session_finish`, `plan_write`, `trace_write`, `identity_write`, and total time before report publication. The focused terminal-identity test failed first because the field was absent, then passed; the complete file ran with `15 passed, 2 subtests passed`. These counters add no event serialization and leave the existing trace and identity fields intact. The snapshot run predates this instrumentation, so its finalization phases cannot be recovered precisely from that report; a new GPIO run is needed to measure that workload's several-minute evidence cost.

An instrumented 2026-10-07 Ibex+UART four-case real run from a separate frozen source snapshot measured `session_finish=2.460s`, `plan_write=0.002s`, `trace_write=2.943s`, `identity_write=0.191s`, and `total_before_report=5.633s` for a roughly 90 MB JSON trace. Its 27,031-event full fresh replay matched. This is a concrete phase measurement for UART, not a measurement of the earlier 2.2 GiB GPIO run. The trace-write failure test now patches both JSON and JSONL writers so it checks elapsed time regardless of the selected format.

The snapshot 600 second run and its full fresh replay establish persistent real RTL search for one fixed source/profile identity. The new same-source cold baseline measures a roughly equal wall-time startup comparison, but does not preserve the same RAM/IRQ/search state. It therefore does not establish equal useful-chain or fault-detection quality. Per-case p50/p95 admission, RTL, Router/Scheduler, feedback, checker and evidence timings remain incomplete. A subsequent [streaming audit of the original 600-second trace](current-dataflow-p5-chain-audit-20261007.md) proves 4 first-seen local target bits, or 0.00665581 new bits/s, but shows that strict complete causal-chain throughput cannot be determined: IRQ, MMIO, and Store observations do not carry a source-admission link. No natural DUT finding was observed; controlled injection evidence remains separate from natural findings. P5 remains open until useful-chain metrics and the remaining timing/quality gates are verified, and GPIO evidence finalization overhead is addressed or bounded.
