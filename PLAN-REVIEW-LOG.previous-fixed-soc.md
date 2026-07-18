# 计划审查日志：CPU + 多 AXI-Lite IP 的 RFUZZ 系统生成与三方案对比

Act 1（grill）已完成，计划已与用户锁定。MAX_ROUNDS=6（用户在第 5 轮后明确扩展一次复核）。

本文件将在 Act 2 中逐轮记录只读 Codex 对抗审查、主审回应和最终 verdict。

## Round 1 - Codex

1. **UltraEmbedded cannot execute the proposed external ROM.** The current wrapper instantiates `riscv_tcm_top`, whose reset vector is internal TCM at `0x2000`, while its TCM loader port is tied idle; therefore Slice 4's shared external-ROM boot assumption is false.  
Fix: Lock either a pre-reset TCM image-loader protocol or an instruction-fetch-to-AXI adapter, and require identical boot RTL and initialization semantics across A/B/C.

2. **The “real RFUZZ campaign” dependency does not exist in this checkout.** `run_design_flow.py` imports and executes `third_party/rfuzz`, but that directory is absent and not tracked.  
Fix: Add an early dependency slice that pins the RFUZZ/kfuzz source revision, hashes, license, build procedure, and an end-to-end campaign smoke gate.

3. **Timeout recovery has no exactly-once record ownership contract.** The plan resets the whole SoC after timeout while advancing to the next record, but does not say which non-reset component retains the record index, timeout acknowledgement, or completion sequence. This permits dropped, duplicated, or permanently replayed records.  
Fix: Put a sequence-numbered record queue and terminal `completed/timed_out` acknowledgement in a harness-owned reset-exempt domain, with assertions for exactly-once advancement.

4. **PicoRV32 software cannot report AXI errors as required.** Its wrapper deliberately discards `BRESP/RRESP`, so ROM code cannot distinguish `OKAY`, `SLVERR`, or `DECERR`, contradicting Slice 4's error-reporting acceptance criterion.  
Fix: Capture response status in an external transaction monitor keyed to the active record, or expose it through a CPU-specific adapter and mailbox ABI.

5. **The common coverage digest is not currently invariant under A/B/C hierarchy changes.** Existing point IDs hash the concrete elaborated hierarchy, so flat-shell and generated-SoC instance paths produce different IDs even from identical instrumented sources.  
Fix: Define and test a canonical component-instance identity independent of variant top paths, then derive a common-only catalog, offset map, and digest from that identity.

6. **RawBits equality does not establish equal experimental input units.** RawBits v2 is cycle-indexed, while A consumes one value per cycle and B/C consume one value per completed transaction; “same bytes, records, and SHA” therefore compares different amounts of simulated behavior.  
Fix: Pre-register separate primary endpoints for equal accepted records and equal simulated cycles, with explicit mappings from each superset slot to each variant and no claim that SHA equality alone provides pairing.

7. **The campaign adapter requires a deeper server contract than the plan specifies.** The current harness asserts `raw_bits_ready_o` continuously during `ST_RUN` and consumes every valid cycle; transaction-paced backpressure, variable run length, mutation, replay, minimization, and termination are not covered by merely adding mailbox metadata.  
Fix: Make the versioned ready/consume adapter an explicit prerequisite with replay, mutation, minimization, end-of-input, timeout, and crash-recovery conformance tests against the pinned kfuzz server.

8. **The statistical success criteria are not actually pre-registered.** They omit the primary checkpoint, paired-versus-unpaired CI method, handling of censored failures, and multiple-comparison policy; C-vs-B also switches post hoc between coverage, completion rate, and timeout outcomes.  
Fix: Name one primary endpoint per comparison, use paired seed differences with a specified CI/test, define failure censoring, and declare all fallback metrics secondary with multiplicity control.

9. **Reset correctness is underspecified for outstanding AXI transactions.** “Whole-SoC reset” does not define pulse length, reset polarity conversion, slave inclusion, post-reset quiescence, or when late responses are considered impossible, despite mixed active-high and active-low wrappers.  
Fix: Add a reset-domain contract requiring every master, fabric, mailbox, watchdog, and slave to reset together for a profile-qualified duration, followed by an asserted response-free quarantine before restart.

VERDICT: REVISE

### Codex 主审回应

九项均采纳。计划改为由 CPU execution profile 选择 ROM 安装后端：PicoRV32 使用 fabric 上的外部 ROM，UltraEmbedded 在 CPU reset 保持期间通过现有 AXI target loader 写入内部 TCM；B/C 的映像和安装语义一致，A 不提供生成 ROM。RFUZZ 依赖与 transaction-paced server contract 前移为 Slice 0。记录所有权、终止确认、错误响应监视和 coverage 累计放入 harness-owned reset-exempt control domain，并增加 exactly-once 与 reset quarantine 合同。公共 coverage ID 改用 variant-independent component instance ID。输入槽与仿真周期成为两个明确不同的预算，SHA 只证明原始输入配对。统计固定主终点、paired bootstrap、失败处理和 Holm 多重比较；C-vs-B 不再事后切换指标。

## Round 2 - Codex

The prior nine findings are substantially addressed. New material issues remain:

1. **The post-reset quarantine can deadlock immediately.** It requires all AXI valid signals to remain idle after CPU reset release, but PicoRV32 begins issuing ROM instruction-fetch requests as soon as reset is released.  
Fix: Perform stale-response quarantine while the CPU remains reset, then release the CPU only after fabric/slave response channels and transaction state are clean.

2. **Coverage lifetime across persistent campaign testcases is unspecified.** The accumulator survives execution-domain resets, but current coverage points are process-initialized sticky state; without a testcase epoch reset, later kfuzz inputs inherit all earlier coverage and corrupt per-input feedback and minimization.  
Fix: Define coverage as cleared at each testcase start but preserved across watchdog resets within that testcase, and add persistent-server tests proving per-input coverage isolation.

3. **The AXI response monitor is not sufficiently correlated to the intended record access.** PicoRV32 ROM fetches, mailbox operations, and target accesses share the same bus, so assigning responses merely to the current sequence can treat an instruction-fetch response as record completion.  
Fix: Arm the monitor only after matching the expected decoded target, address, direction, and complete AW/W or AR handshake, then associate exactly one corresponding B/R response.

4. **The Holm-Bonferroni procedure is not executable as specified.** The plan defines percentile bootstrap CIs but no hypothesis-specific p-value calculation, while B-vs-A requires only a positive observed mean and C-vs-A tests significance against zero despite claiming a ten-point improvement.  
Fix: Define each null margin and paired p-value method explicitly, apply Holm to those p-values, and distinguish practical effect thresholds from statistical rejection criteria.

VERDICT: REVISE

### Codex 主审回应

四项均采纳。quarantine 移到 CPU reset 仍保持有效的阶段，先清空 fabric/slave 状态再释放 CPU。公共插装 ABI 增加独立 `coverage_epoch_reset_i`，每个 testcase 开始清零、watchdog reset 不清零，并增加 persistent-server 隔离测试。AXI monitor 只有在 fabric route、地址、方向和请求握手全部匹配活动记录后才 arm。统计把实际收益门槛与显著性拆开：六个 paired comparison 都用相对零边界的一侧 exact sign-flip p-value，Holm 校正；10/0/1 个百分点及胜率是另外的 practical gates。

## Round 3 - Codex

The prior quarantine ordering, AXI response correlation, testcase coverage isolation, and six-hypothesis Holm procedure are now addressed. Three material problems remain:

1. **Coverage epoch reset has no implementable single-writer design.** The plan requires clearing every sticky point, but the current instrumenter writes those signals inside arbitrary `always`, `initial`, and `final` processes and only declaration-initializes them; adding a reset process would create multiple procedural writers, while `initial`/`final` points cannot be reset through their original process.  
Fix: Specify a single-writer transformation for resettable points, exclude unsupported process kinds from the common ABI, version the changed reset semantics, and add compile plus two-epoch tests.

2. **The “exact” sign-flip test does not test the stated null without an unjustified symmetry/exchangeability assumption.** Exhaustively enumerating `2^20` flips makes computation exact, but coverage differences are bounded and potentially skewed, so it does not yield an exact test of paired mean `<= 0` merely because all flips are enumerated.  
Fix: Use a preregistered valid mean test such as a studentized paired bootstrap with multiplicity adjustment, or change the estimand to win probability and use an exact paired sign/binomial test.

3. **Last-observation-carried-forward for process/infrastructure failures can manufacture favorable endpoint results.** The plan conflates DUT crashes with harness/process failures and still allows imputed runs into success gates, so a variant with systematic late failures can retain high coverage without completing the experiment.  
Fix: Classify DUT and infrastructure failures separately, invalidate and rerun the complete paired group for infrastructure failures, and preregister a conservative DUT-failure outcome plus an acceptable failure-rate gate.

VERDICT: REVISE

### Codex 主审回应

三项均采纳。放弃给所有点增加第二个清零 writer，改为 `CoverageABI v2` epoch-tag 设计：每个可重入 sticky point 仍只在原过程内写自己的 epoch tag，输出通过 tag 与当前 testcase epoch 比较；表达式点由 epoch-scoped harness OR 累加器收集；`initial/final` 点排除出公共 ABI。统计改为固定 10,000 次 null-centered studentized paired bootstrap，并明确零方差规则。失败分成事务 timeout、可复现 DUT failure 和 infrastructure failure；基础设施失败整组三方案重跑，DUT failure 按零覆盖计并设置失败率门。

## Round 4 - Codex

The three prior findings are addressed in principle. New material issues remain:

1. **The zero-variance bootstrap fallback is invalid.** A positive mean with zero observed standard error is automatically assigned `p=1/(B+1)` and a zero-width CI; this manufactures significance based on the bootstrap iteration count while ignoring sampling uncertainty.  
Fix: Use a valid bounded-mean procedure for zero variance, or conservatively set `p=1` and prohibit a significance claim.

2. **Combinational coverage is no longer true execution coverage.** The proposed `always_comb`/latch hit signal is cleared on every process activation and sampled only by a clocked harness accumulator; a branch taken during an earlier delta cycle can be overwritten before sampling, making results scheduler-dependent.  
Fix: Capture every combinational activation with an event-preserving single-writer mechanism, or exclude combinational/latch points from the common ABI.

3. **Terminal-cycle sequential hits can be lost.** An epoch tag updated by nonblocking assignment and an accumulator sampling on the same edge will expose the hit only after the NBA region, but the plan permits immediate terminal acknowledgement and testcase completion without a required coverage flush.  
Fix: Require an explicit coverage-flush acknowledgement or a full post-update drain edge before committing each terminal result, with a last-cycle-only-hit test.

4. **The C-B seed gate is not reproducible as written.** “70% seed non-inferior” has no defined margin or tie treatment.  
Fix: Define the predicate exactly, for example `C-B >= 0 pp` for at least `14/20` paired seeds, including how failed seeds count.

VERDICT: REVISE

### Codex 主审回应

四项均采纳。零方差时使用保守 `p=1` 和完整参数范围 CI，不允许显著性结论。为避免调度相关漏点，主 `CoverageABI v2` 只包含可证明为 edge-triggered sequential 过程的 epoch-tag 点；组合、latch、expression、initial/final 点仅列入 auxiliary/exclusion 报告。terminal ack 后保持同一 epoch，经过两拍 coverage flush acknowledgement 才提交结果或推进记录。C-B non-inferior 明确定义为保守 endpoint 上 `C-B >= 0 pp`，至少 `14/20`，tie 计入；C-A win 使用严格大于。

## Round 5 - Codex

All four prior findings are addressed textually. Three material issues remain:

1. **The coverage flush can itself create coverage and unfairly favors B/C.** Holding the sequence while running two additional rising edges still advances the CPU/IP execution domain, so post-terminal branches can enter the endpoint; A has no equivalent per-slot terminal phase.  
Fix: Capture coverage after NBA/settle without another DUT clock, or gate the DUT clock and use a separate harness capture clock identically across A/B/C.

2. **The bootstrap algorithm remains underspecified for discrete data.** The plan handles zero observed standard error but not zero-SE bootstrap replicates, which can be common for repeated discrete differences; it also appears to use null-centered resamples for both testing and the bootstrap-t CI, although the CI requires uncentered resampling around the observed estimate.  
Fix: Specify separate null-centered test and uncentered CI algorithms, including deterministic conservative handling of every zero-SE resample.

3. **Campaign failures still have no endpoint or rerun policy.** Replay failures are rigorously classified, but a full campaign may merely have an “explicit failure record”, leaving the 600-second endpoint, paired comparison, downtime accounting, and success eligibility undefined.  
Fix: Extend the DUT/infrastructure failure taxonomy and paired rerun rules to campaigns, and define the endpoint value and wall-clock accounting for every failure class.

VERDICT: REVISE

### Codex 主审回应（原 MAX_ROUNDS=5 后，等待扩展复核）

三项均采纳并写入最终候选计划。取消额外 DUT flush clock，改为每个正常 rising edge 完成 NBA/settle 后由 host OR 收集覆盖，terminal edge 在不推进 DUT 时完成最后一次采样并确认。统计拆成 null-centered studentized bootstrap 单侧检验与 uncentered percentile bootstrap CI；零 SE test replicate 一律计入拒绝显著性的尾部。campaign 继承配对 triplet 重跑、DUT/基础设施失败分类、600 秒 wall-clock 和保守 0% endpoint。用户随后明确将上限扩展到第 6 轮，由同一评审线程复核这些修订。

## Round 6 - Codex

The three Round 5 findings are fully addressed:

- Coverage is captured host-side after NBA/settle without advancing the DUT clock.
- Bootstrap testing and CI use separate algorithms with conservative zero-SE handling.
- Campaign DUT/infrastructure failures now have explicit endpoints, wall-clock treatment, paired reruns, and invalidation rules.

I found no remaining material implementation blockers. Residual feasibility risks, particularly RFUZZ integration and finding six qualifying sequentially instrumentable IP types, are correctly placed behind fail-closed qualification gates.

VERDICT: APPROVED

### Codex 主审结论

计划在第 6 轮收敛。最终实现必须保持 qualification fail-closed：RFUZZ transaction-paced conformance 未通过或不足 6 种具有非零主 ABI 时序点的 IP 时，不得进入正式 A/B/C 覆盖率结论。
