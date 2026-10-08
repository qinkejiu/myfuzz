# P4 slot 不可变性 sweep：10 个已保存运行的只读逐例判定（9 immutable、0 violated、1 unavailable）

日期：2026-10-08。对应验收要求：**"真实 Store/取指后的程序字节不能被后例变异"**。

本文用 shipped 只读门禁 `myfuzz.scenario.slot_immutability` 的**逐例判定**，扫过一份**声明**的 10 个已保存运行目录：8 个新算子运行（路径切换 OFF/ON/长枝、初始 RAM 数据 OFF/ON、指令插入/删除、CPU 侧覆盖）+ 2 个此前已知良好的运行（p3 lane-selectivity2、p4 shift-fuzz），并产出一份带版本的文档 `p4_slot_immutability_sweep.v1`。

执行者是只读脚本 `scripts/report_p4_slot_immutability_sweep.py`。**本次没有运行任何 Verilator/RTL/fuzz 作业**，只读已保存 trace；`proof_scope.rtl_executed_by_checker=false`。逐例判定完全来自 shipped 门禁，sweep 自己**不新增任何判定规则**。

## 0. 一句话结论

**9/10 个运行给出 shipped `immutable` 判定：0 violated、0 insufficient_evidence，合计 36,985 个程序字节全部 immutable。** 第 10 个运行 `runs/p4-cpu-side-coverage-20261008-online` **没有判定**（`unavailable`：既没有 `decoder_manifest.json` 声明程序区，也没有任何可流式读取的 trace 产物），按门禁规则它既不算 immutable、也不算 0 slot。因此 sweep 自身结论是 `unavailable`、退出码 2——即"清单内 9 个运行全 immutable"成立，但**清单里仍有一个运行未被证明**，这一条不被抹平。

## 1. 方法与判据

### 1.1 shipped 门禁本身

```bash
PYTHONPATH=src python3 -m myfuzz.scenario.slot_immutability RUN_DIR ... --json-out <file>
# 退出码：0 immutable / 1 violated / 2 insufficient_evidence / 3 参数错误
```

门禁只读一个已保存运行目录：程序区取 `decoder_manifest.json` 声明的在线指令预留（本清单中有 decoder manifest 的 9 例均为 `[69632, 196096)` = 126,464 字节；第 8 例无 manifest，故没有判定）加每个声明 `initial_image` 区；slot 全集是这些区内**至少被一个事件物化或读取过**的字节；`instruction_source`/`initial_image`/`memory_initialization`/带完整 `memory_write_commit` 回执且 `performed_effect=true` 的真实 Store 才算物化；`memory_read` 与非写非错的 `instr_response` 才算读取证据。读取先于物化、读了但从未物化、Store 缺完整回执、记录畸形一律 `insufficient_evidence`，绝不记为通过。重复物化**同一个值**是 `reassertion`，不算违反（`tests/scenario/test_p4_slot_immutability_sweep.py::test_sweep_keeps_the_shipped_reassertion_rule` 钉住该语义）。

### 1.2 本次 sweep 的两条读取路径（逐例显式记录 `verdict_reader`）

| 路径 | 何时使用 | 实现 | 说明 |
|---|---|---|---|
| `shipped_cli_path` | 运行有 `online_events.jsonl` | `slot_immutability.report_for_run`（CLI `main()` 自己调用的函数） | 3 例（路径切换长枝、p3 lane-selectivity2、p4 shift-fuzz） |
| `shipped_stream_path` | 运行没有 `online_events.jsonl`，但有 shipped 流式产物（`online_final_trace.json` / `online_final_trace.meta.json` + `online_events.jsonl` / `online_events.zlib`） | `acceptance_metrics.TraceEventStream` 流式读 + `slot_immutability.analyze_events` 判定 | 6 例（路径切换 OFF/ON、初始 RAM OFF/ON、序列插入/删除） |

第 2 条路径不是"另一个判定器"：判定函数与程序区来源（`program_range_from_run`）都是 shipped 的，只是素材由 shipped 有界读取器流式读出。文档对每一例都显式记录 **shipped CLI 默认调用读不到该运行**（`exit_code.shipped_cli_default_invocation = 3`），以免把该结论误当成 CLI 默认路径的结论。

### 1.3 trace 完整性（判定必须站在它声明的那份 trace 上）

每个给出判定的运行都会用 shipped 读取器再流式读一遍（常量内存），核对：

- 声明的 `event_count` 与实际流出的条数；
- 实际流出条数与判定所覆盖的事件条数（`events_judged`）；
- trace 声明的 canonical `semantic_sha256` 与 shipped 读取器复算值。

三者任一不一致，该例结论被**拒绝**为 `unavailable`（`trace_integrity.status=failed`，逐条写明原因），绝不写成 immutable；trace 本身不声明摘要时记为缺失（`null`），这只是证据更弱，不等于失败。本次 9 个有判定的运行**全部 9/9 `status=verified`、`semantic_sha256_verified=true`**（`totals.runs_with_verified_trace_semantic_sha256=9`、`runs_without_declared_trace_digest=0`）。

### 1.4 unavailable 的规则（不得当成通过）

`unavailable` = 两条路径都没能给出 shipped 判定。此时该例 `slot_count/immutable/violated/insufficient_evidence/proof_scope/gate_line` **全为 `null`（不是 0）**，并逐条列出阻塞原因；逐例退出码取 2（与 `insufficient_evidence` 同档，绝不取 0）；`totals` 只累加有判定的运行并在 `counts_note` 中写明。

### 1.5 确定性

文档不含时钟、主机名、未声明的绝对路径，JSON 以 `sort_keys=true` 输出；`tests/scenario/test_p4_slot_immutability_sweep.py` 用合成运行与真实运行各钉了一次"重复 sweep 逐字节相同"，并且本报告内**整轮 10 例 sweep 重复执行过一次**：同一清单、同一最终脚本字节，输出文档与首次 `cmp` **逐字节相同**。

## 2. 声明清单与逐例判定

例数取自各运行自己的 `receipts.jsonl` 行数与其 `status` 分布（`complete` / `input_invalid`）。"未触及声明字节"= 声明程序区内没有任何事件物化或读取的字节数，门禁只报计数、不报通过。

| # | 运行目录（`runs/` 下） | 算子/枝 | 例数 | trace 产物 | 读取路径 | shipped 判定 | slots | immutable | violated | insufficient | 读证据事件 | 未触及声明字节 | 事件数 | trace 完整性 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `current-dataflow-p4-path-switch-off-20261007-online` | 路径切换 **OFF** | 96（94+2 input_invalid） | `online_final_trace.json` 38,387,167 B | stream | **immutable** | 1436 | 1436 | 0 | 0 | 839 | 125,264 | 37,270 | verified |
| 2 | `current-dataflow-p4-path-switch-on-20261007-online` | 路径切换 **ON** | 96（91+5） | `online_final_trace.json` 37,277,898 B | stream | **immutable** | 1376 | 1376 | 0 | 0 | 823 | 125,324 | 36,229 | verified |
| 3 | `current-dataflow-p4-path-switch-long-on-20261007-online` | 路径切换 **长枝 2400 例** | 2400（2275+125） | `online_events.jsonl` 897,592,336 B | CLI | **immutable** | 27624 | 27624 | 0 | 0 | 17726 | 99,076 | 859,412 | verified |
| 4 | `current-dataflow-p4-initial-ram-off-20261007-online` | 初始 RAM 数据 **OFF** | 96（94+2） | `online_final_trace.json` 38,387,167 B | stream | **immutable** | 1436 | 1436 | 0 | 0 | 839 | 125,264 | 37,270 | verified |
| 5 | `current-dataflow-p4-initial-ram-on-20261007-online` | 初始 RAM 数据 **ON** | 96（94+2） | `online_final_trace.json` 38,386,659 B | stream | **immutable** | 1437 | 1437 | 0 | 0 | 839 | 125,264 | 37,270 | verified |
| 6 | `p4-sequence-edit-insert-20261008-online` | 指令**插入**（+XORI，12B） | 8（8 complete） | `online_final_trace.json` 5,701,573 B | stream | **immutable** | 336 | 336 | 0 | 0 | 178 | 126,364 | 4,131 | verified |
| 7 | `p4-sequence-edit-delete-20261008-online` | 指令**删除**（−ADDI，4B） | 8（8 complete） | `online_final_trace.json` 5,672,322 B | stream | **immutable** | 328 | 328 | 0 | 0 | 174 | 126,372 | 4,107 | verified |
| 8 | `p4-cpu-side-coverage-20261008-online` | CPU 侧覆盖 cell（cpu_only，300 s） | — | **无 trace 产物** | 无 | **unavailable** | `null` | `null` | `null` | `null` | `null` | `null` | `null` | `null`（未判定） |
| 9 | `p3-lane-selectivity2-20261007-online` | 此前已知良好（p3） | 118（117+1） | `online_events.jsonl` 746,939,252 B | CLI | **immutable** | 1716 | 1716 | 0 | 0 | 1714 | 124,984 | 168,917 | verified |
| 10 | `p4-shift-fuzz-20261007-online` | 此前已知良好（p4 移位模糊） | 83（83 complete） | `online_events.jsonl` 536,633,868 B | CLI | **immutable** | 1296 | 1296 | 0 | 0 | 1420 | 125,404 | 118,963 | verified |

**合计（`totals`）**：声明 10 例；`immutable=9`、`violated=0`、`insufficient_evidence=0`、`unavailable=1`；`slot_count=36985`、`immutable_slots=36985`、`violated_slots=0`、`insufficient_slots=0`；`runs_with_a_shipped_verdict=9`、`runs_without_a_verdict=1`；`runs_with_verified_trace_semantic_sha256=9`。**sweep 结论 `unavailable`，退出码 2。**

### 2.1 与既有证据的交叉核对

- 例 9、10 的只读判定与本仓库此前记录的两次演示**逐值相同**：p3 `1716/1716`（读证据 1714、未触及 124,984）、p4 `1296/1296`（读证据 1420、未触及 125,404），见 [路径/源切换算子与 slot 不可变性](current-dataflow-p4-path-switch-operators-20261007.md)。
- 例 3 的未触及字节 `99,076` 与 [live 路径切换报告](current-dataflow-p4-path-switch-live-20261007.md) 记录的"长枝指令预留余量 99,076 字节"一致：两处指的是同一个声明预留区 `[69632, 196096)`。
- 例 1 与例 4（两个 OFF 枝）的**事件流语义摘要完全相同**（`semantic_sha256=6df5b940…`、事件数同为 37,270、slot 统计同为 1436/839），但 trace 文件 sha256 不同（`d0db1bc0…` vs `ee39fe47…`）：逐字节比对显示二者只在文件末尾的 `manifest_sha256` 字段不同（第 38,386,995 字节起、共 63 字节），即两条 OFF 枝事件流相同、各自绑定到不同会话声明（`9861e39c…` vs `e208547b…`）。sweep 的身份证据（文件 sha256）把二者区分开，没有把"语义相同"误当成"同一份产物"。

### 2.2 新算子运行（清单第 1–7 例）的判定细节

- **路径切换**：OFF 1436/1436、ON 1376/1376、长枝 27624/27624，`violated=0`、`insufficient_evidence=0`；ON 枝切换后的事件流没有任何"同一程序字节被后例写成/读回不同值"的记录。
- **初始 RAM 数据**：OFF 1436/1436、ON 1437/1437。ON 枝比 OFF 枝多 1 个被物化并判定的字节——与"初始 RAM 数据算子在**会话启动前**把一个未知字节物化一次、CPU 首次读取它"的语义一致；该字节没有被任何后续事件改写或读回不同值。
- **指令插入/删除**：插入 336/336、删除 328/328，均 0 violated／0 insufficient。逐字节对照两枝的 slot 全集（本轮另用 shipped 流式读取器 + `analyze_events` 对这两枝各做一次只读逐 slot 复算）：删除枝的 328 个 slot 是插入枝的子集，插入枝**多出的 8 个字节正好是 `69724..69731`**（预留区 `[69632,196096)` 内偏移 92..99），由同一条 `instruction_source` 物化事件（event_id 3592）写入，字节值为 `13 00 00 00 13 00 00 00`；其中 4 字节随后被两条取指读证据（event 3646、3665）按**相同值**读回，另 4 字节只被物化。两枝的 `initial_image` 区 slot 数完全相同（bootstrap 96、direct_vector 4、external_vector 4、isr 68、end 64），slot 全集的差异**只**落在声明指令预留区（插入 100 vs 删除 92）。即：插入枝多出来的那 8 个程序字节既没有被后例改写，也没有被读回不同值。
- 七个新算子的运行**共享同一份 decoder manifest 文件**（文件 sha256 `5d1379ce…`，见下表），即它们的程序区声明完全一致，判定差异只来自各自的事件流。

## 3. 身份证据（每例）

"文件 sha256"列由 sweep 自己对保存产物逐字节流式计算。第 3、5 列是运行**自己声明**的摘要（`report.json:decoder_manifest_sha256` 与 trace 文档/trace meta 里的 `manifest_sha256`），sweep 用 shipped 规范化规则（canonical JSON，无结尾换行）复算核对，9 例全部相等。

| # | 运行 | decoder manifest 文件 sha256 | 运行声明摘要与复算一致 | session manifest 文件 sha256 | trace 声明摘要与复算一致 | trace 文件 sha256 |
|---|---|---|---|---|---|---|
| 1 | path-switch-off | `5d1379ce49fc8c0300aecedbd4a930ab818eafd377cf856dcebbc74e3cb8f2f6` | ✅ `625710f4…a0e64` | `9861e39c9ae405697a539c835f84413019ecc9fe87247d48f849ad325e28f0b8` | ✅ `987189fe…71240` | `d0db1bc0fcb113c61a33ce8f2a18e1b477660c79def7b43bc20665d263f69e68` |
| 2 | path-switch-on | `5d1379ce49fc8c0300aecedbd4a930ab818eafd377cf856dcebbc74e3cb8f2f6` | ✅ `625710f4…a0e64` | `9861e39c9ae405697a539c835f84413019ecc9fe87247d48f849ad325e28f0b8` | ✅ `987189fe…71240` | `cbac97edb4891579bc4bd4c5dbb3fec1f811d31ae9e883c7463f9c92fdb3bef2` |
| 3 | path-switch-long | `5d1379ce49fc8c0300aecedbd4a930ab818eafd377cf856dcebbc74e3cb8f2f6` | ✅ `625710f4…a0e64` | `9861e39c9ae405697a539c835f84413019ecc9fe87247d48f849ad325e28f0b8` | ✅ `987189fe…71240` | `08a1034f760e9a64ba2641aa5c9d2ea5df96952e3dae6b0d84b1f91c2c9c8b26` |
| 4 | initial-ram-off | `5d1379ce49fc8c0300aecedbd4a930ab818eafd377cf856dcebbc74e3cb8f2f6` | ✅ `625710f4…a0e64` | `e208547b4cb15783c6f9f70c49930f802c3b0fc44b6325d5553f797d6eb67f94` | ✅ `215792b9…83d13` | `ee39fe475313c787210d799f6b71c841f686214e1daef1f25ba1f0e28f6fcf25` |
| 5 | initial-ram-on | `5d1379ce49fc8c0300aecedbd4a930ab818eafd377cf856dcebbc74e3cb8f2f6` | ✅ `625710f4…a0e64` | `e208547b4cb15783c6f9f70c49930f802c3b0fc44b6325d5553f797d6eb67f94` | ✅ `215792b9…83d13` | `084b3eb0abac5eb3353000ce88f5e8d2a4919350d878b896306b20018537fae2` |
| 6 | sequence-edit-insert | `5d1379ce49fc8c0300aecedbd4a930ab818eafd377cf856dcebbc74e3cb8f2f6` | ✅ `625710f4…a0e64` | `ce1f1f901cadd11bd8cae69c84baae7848b0c3dea02540b3356c088c012fbd03` | ✅ `a1dbcbac…8eb91` | `a023924e773d7701818dfe4e7b05d5f573c844d5caea90741993b07e614182a5` |
| 7 | sequence-edit-delete | `5d1379ce49fc8c0300aecedbd4a930ab818eafd377cf856dcebbc74e3cb8f2f6` | ✅ `625710f4…a0e64` | `ce1f1f901cadd11bd8cae69c84baae7848b0c3dea02540b3356c088c012fbd03` | ✅ `a1dbcbac…8eb91` | `93d00861d4e1f0185f97a934f0ebdefd5a964c80eb075c65fb92f2aa929e2ede` |
| 8 | cpu-side-coverage | **不存在** | — | **不存在** | — | **不存在** |
| 9 | p3-lane-selectivity2 | `b3bcc7e9d1ba5b3fba769a114b053ebba9fdb947320a6bb94dc9f1f6473a0d84` | ✅ `77cd6b18…36d5d` | `2a4ebe46e0921b5dd640f65d96719f45d4d1671a1b1e9022b4f43c0e04d5dede` | ✅ | `412d811a798e431fec86d0776b4c6422a3cd7df7fbc3768ca9ab52a268d247a5` |
| 10 | p4-shift-fuzz | `02e3bb74a21ec72cf2a82d142b6ce97f350ca7adf0c3f565d5a8269702a453d9` | ✅ `b68042f0…d769` | `9cc5bdc434c4233d016f21f902cd20c6b4a5c39985547de19d44b48321332d70` | ✅ | `1e70151e4f0cdbe5a9b2edbabc6bacde509ca913b95e64b0ca39a0c5deaf5ec7` |

补充说明（均为可复算事实）：

- 第 1–7 例声明的 decoder manifest 规范化摘要 `625710f477121c08abdae046710efe5e168948f50b073aba6f0e95fd051a0e64` 与 [序列编辑真实门禁报告](current-dataflow-p4-sequence-edit-real-gate-plan-20261008.md) 记录的冻结 shipped Ibex 在线声明完全一致：这 7 个新算子运行站在同一份声明的程序区上。
- 第 9、10 例的 decoder manifest 是各自运行自己的文件（`b3bcc7e9…`、`02e3bb74…`，13,918 B / 12,619 B），与其他运行不同——本 sweep 不做跨运行声明等价性的推断。
- 第 3、9、10 例（`jsonl.v1`）的 trace 同时声明 `event_count`（859,412 / 168,917 / 118,963），与 sweep 实际流出条数、判定覆盖条数**三者相等**；第 1、2、4–7 例（monolithic `json.v1`）没有 `event_count` 字段，sweep 记录的是实际流出条数（`null` 表示"该格式不声明"，不是 0）。
- 第 8 例没有 `online_session_manifest.json`、没有 `online_run_identity.json`、没有任何 trace 产物。

## 4. 唯一未判定的运行：`p4-cpu-side-coverage-20261008-online`

`verdict=unavailable`、`slot_count=null`，两条路径各自的**原始原因**（文档 `runs[7].unavailable_reasons`）：

| stage | 原始原因 |
|---|---|
| `shipped_cli_path` | `runs/p4-cpu-side-coverage-20261008-online has no decoder_manifest.json to declare the program range` |
| `shipped_stream_path` | `no online_final_trace.meta.json, online_events.jsonl, online_events.zlib or online_final_trace.json in runs/p4-cpu-side-coverage-20261008-online`；`runs/p4-cpu-side-coverage-20261008-online has no decoder_manifest.json to declare the program range` |

该目录是 CPU 侧覆盖 cell 的 campaign 产物（`report.json` 自述 `schema_version=soc_result.v1`、`mode=cpu_only`、`execution_kind=official_rfuzz_source_backed_soc`、`effective_fuzz_seconds≈300.0`、`final_status=failed-acceptance`、`status=incomplete-evidence`、`evidence_missing=["source_transactions","target_transactions"]`、`client_result.actual_rtl_execution.tests=59753`、`coverage_records=33173`）。它**不是**一个声明了在线指令预留并保存了在线事件流的 dataflow 会话：目录里只有 `build/`、`live/`（`checkpoints.jsonl`、`report.json`、`corpus/` 等）与 `rebuild/`。门禁在缺少 `decoder_manifest.json` 时按 shipped 契约拒绝为程序区不明确，sweep 因此把它记成 `unavailable`，**没有**用 `live/checkpoints.jsonl` 或任何外部声明替代，也**没有**把它算进 immutable 或 0 slot。

这是一条**真实的证据缺口**，不是"通过"：本次 sweep 无法对这 300 秒 CPU 侧覆盖运行给出任何程序字节不可变性的结论。要补上它需要该 campaign 保存声明程序区的 `decoder_manifest.json` 与在线事件流（或一个明确声明程序区与事件来源的等价产物），再由同一门禁判定。

## 5. 本 sweep 证明了什么

1. 在**清单内 9 个运行**的已保存事件流上，"真实 Store/取指后的程序字节被后例变异"**没有发生**：36,985 个被物化/读取的声明程序字节全部 `immutable`，`violated=0`、`insufficient_evidence=0`、`conflicts_by_kind` 两类冲突均为 0、`insufficient_by_reason` 为空。
2. 这些判定覆盖了本轮的新算子：**路径切换**（OFF/ON/长枝 2400 例）、**初始 RAM 数据**（OFF/ON）、**指令序列插入/删除**（各 8 例）——即"最可能改写程序字节"的算子运行都给出了 `immutable`。
3. 判定站在**运行自己声明的身份**上：9/9 运行的 trace 声明的 canonical 摘要被 shipped 读取器复算通过（`semantic_sha256_verified=true`），3 个 `jsonl.v1` 运行的声明事件数与实际流出/判定条数三者相等，decoder manifest 与会话 manifest 的声明摘要均可由文件复算。
4. 同一门禁对 p3/p4 两个既有运行复现了此前的 `1716/1716`、`1296/1296`，说明本轮 sweep 与既有证据使用同一判据。
5. 门禁的 fail-closed 语义在本轮被真实执行：`unavailable` 的例子计数为 `null`、退出码 2、sweep 结论不可能为 `immutable`。

## 6. 本 sweep **不**证明什么（限制）

1. **只覆盖清单内这 10 个运行目录的已保存 trace**；对任何其它运行、其它批次的运行、或将来重跑得到的 trace 不作任何推断。
2. **只覆盖被事件触及过的字节**：每例"未触及声明字节"为 99,076–126,372 字节（声明区 126,464 字节）。这些字节没有任何事件物化或读取，门禁只报计数；本 sweep 对**它们**不声称任何东西。插入/删除两枝尤其薄：336/328 个 slot 只占声明区的约 0.27%。
3. **"immutable" 是对已保存事件流的只读判定**，不是 RTL 层面的保证：本次没有编译、渲染或启动任何 RTL/Verilator，也没有运行任何 fuzz 作业；`proof_scope.rtl_executed_by_checker=false`。若 trace 写入器本身丢事件或写错事件，本 sweep 无法发现（它只能发现"trace 声明的事件数/摘要与实际内容不一致"）。
4. **读取路径不同**：6 个 monolithic `json.v1` 运行的判定由 shipped 流式读取器 + shipped 判定函数给出，**shipped CLI 的默认调用在这些运行上退出码 3（读不到 `online_events.jsonl`）**；文档逐例记录了这一点。它不是 CLI 默认路径的结论。
5. **`jsonl.v1` 的 CLI 路径按 shipped 门自己的界不校验 meta 的语义摘要**；本 sweep 另外用常量内存的流式复算补上了这项核对（9/9 通过），但这仍不改变门禁本身的判定规则。
6. **第 8 例没有结论**：`p4-cpu-side-coverage-20261008-online` 无 decoder manifest、无 trace，sweep 结论为 `unavailable`（退出码 2）。任何"10/10 全部 immutable"的说法都是错的。
7. **不比较算子收益**：本 sweep 只回答"程序字节是否被后例变异"，不回答路径切换/初始 RAM/序列编辑是否带来覆盖或链收益（后者见 [算子收益同预算对照](current-dataflow-p4-operator-benefit-comparison-20261008.md)）。
8. 运行开销：`jsonl.v1` 路径按 shipped 门自己的界把事件物化在内存中，本轮最大一例（897 MB trace、859,412 事件）峰值 RSS 约 **4.47 GB**、整轮 wall time 约 **1 分 34–35 秒**（两次整轮执行均为该量级）。整轮 sweep 已重复执行一次并逐字节相同，但"同一输入必然同一输出"只对**已保存且未被改动的产物**成立。

## 7. 复现

```bash
cd /home/qinkejiu/myfuzz
PYTHONPATH=src python3 scripts/report_p4_slot_immutability_sweep.py \
  runs/current-dataflow-p4-path-switch-off-20261007-online \
  runs/current-dataflow-p4-path-switch-on-20261007-online \
  runs/current-dataflow-p4-path-switch-long-on-20261007-online \
  runs/current-dataflow-p4-initial-ram-off-20261007-online \
  runs/current-dataflow-p4-initial-ram-on-20261007-online \
  runs/p4-sequence-edit-insert-20261008-online \
  runs/p4-sequence-edit-delete-20261008-online \
  runs/p4-cpu-side-coverage-20261008-online \
  runs/p3-lane-selectivity2-20261007-online \
  runs/p4-shift-fuzz-20261007-online \
  --json-out docs/reports/current-dataflow-p4-slot-immutability-sweep-20261008/p4_slot_immutability_sweep.v1.json
# 退出码 2（清单内有一个 unavailable）；stdout/stderr 全文见同目录 sweep.log
```

产物（只读脚本写出的唯一文件 + 其运行日志）：

- `docs/reports/current-dataflow-p4-slot-immutability-sweep-20261008/p4_slot_immutability_sweep.v1.json`（schema `p4_slot_immutability_sweep.v1`，53,488 B，sha256 `a21d1274620c7db91d7d4b296452561a0c8416f4722c85f783f9c53cf571161f`）
- `docs/reports/current-dataflow-p4-slot-immutability-sweep-20261008/sweep.log`（逐例 gate line + unavailable 原因 + `/usr/bin/time -v` 峰值，sha256 `45dd08b4cce91d147e8ef86b78e2d5a8e44e1d94fc775a847783865ae4b9d257`）

## 8. 测试（TDD：先 RED 后 GREEN）

`tests/scenario/test_p4_slot_immutability_sweep.py`（19 项）在本轮**先写、先失败**，再实现脚本：

```bash
cd /home/qinkejiu/myfuzz && PYTHONPATH=src python3 -m pytest \
  tests/scenario/test_p4_slot_immutability_sweep.py -q -p no:randomly
```

- **RED（实现前，当时文件里 14 项用例）**：`14 errors in 0.18s`，每一项都是 `AssertionError: missing sweep script /home/qinkejiu/myfuzz/scripts/report_p4_slot_immutability_sweep.py`；实现后按同一 spec 扩充到 19 项（新增 trace 完整性 3 项、reassertion 语义 1 项、双阻塞声明 1 项）。
- **GREEN（实现后）**：`19 passed in 1.51s`（最终一次复跑 `19 passed in 1.60s`；期间脚本只删过两个未被引用的常量，判定行为不变）。

覆盖内容：合成四类判定（immutable / violated / insufficient_evidence / unavailable）的聚合与 violated slot 地址/事件号、insufficient 原因计数、**unavailable 绝不计入 immutable 也绝不为 0 slot**、缺失目录与缺失产物各自的精确原因、`unavailable_reasons` 里逐条列出每个阻塞声明、shipped CLI 退出码一致性（含"CLI 对读不到的运行整体退 3、sweep 记 unavailable 但永不放过"）、monolithic trace 走 shipped 流式读取器且显式记录 CLI 默认读不到、JSONL 存在但损坏时**不回退**到别的产物、trace 完整性三条 fail-closed 规则（声明事件数不符 / 摘要不符 / 摘要缺失不算失败）、身份证据与退出码语义、重复 sweep 逐字节相同（合成与真实运行各一次）、以及两个真实运行的只读判定（`p4-sequence-edit-insert-20261008-online` 与 `current-dataflow-p5-streamed-short-20261007-online`：判定 immutable、`slot_count>0`、`semantic_sha256_verified=true`、运行目录树在 sweep 前后逐文件大小/mtime 不变）。
