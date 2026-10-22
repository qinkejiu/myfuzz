# DMA Master Route v2 与 OpenTitan UART S4 实测报告（2026-10-19）

## 本轮范围

本轮完成版本化 DMA master route 契约的首个真实消费者迁移：OpenTitan UART RX FIFO → ZipCPU `wbdmac` → RAM。新运行路径明确记录 UART read 与 RAM write 两种 DMA master route，把 endpoint/window/RAM 身份绑定进拓扑与 digest，并在 saved-plan/fresh replay 中保留 v2 route。适配结论只覆盖这个有界 S4 场景；PULP、ZipCPU UART、Caliptra 的 DMA provider adapter 仍未实现。

历史 `9cbc323` S4 运行（生产源码在 `ade3fe6` 未变）及其证据仍按原身份保留。本报告中的新 `008bac…` 基线与 overlay 是独立新运行，未复用旧 S4 结果作为 v2 证据。

## 实现与本地验证

- 生产实现增加 strict `runtime_path_contract.v2` / `prepared_runtime_paths.v2` / `runtime_path_compilation.v2` / `runtime_edge_index.v2` / `dma_runtime_paths.v2` route 数据；不带 DMA route 的 v1 序列化保持原字节形式。route 必须匹配显式 `DMA_MASTER_TRANSFER` edge，缺失、歧义、拓扑身份变化和权限/aperture 不符均拒绝。
- UART S4 为 UART master RDATA 与 RAM master write 建立独立 route edge。一次读或写各自的 accepted request、真实 target operation 和单个 native response 使用同一个 `TransactionKey`；读写是不同的相邻 key，并以观测值配对。RAM 只凭真实 `memory_write` / version event 记账，不授未启用的 service commit receipt。
- 修复 fresh replay 对 case 证据的 raw equality：现在使用类型化 first-difference 比较，规范化每次运行自己的 execution ID 及 tuple/list 序列形状，同时保留 route identity、地址、source sequence 等语义字段的严格比较。三个相关 real gate（S4、S3 error ISR、UART descriptor）都改用同一比较器。
- 定向本地 suite：**264 passed、5 skipped、61 subtests passed**。5 个 skip 是本机未启用的 opt-in native gate；本轮真实 S4 在远程单独执行。runtime 与相关 tests 的 `py_compile`、`git diff --check` 通过。route helper 与三处 real-gate 比较器经独立代码审查，没有 blocker。

执行的 scoped 命令：

```bash
PYTHONPATH=src python3 -m pytest -q \
  tests/scenario/test_dependency_mutation.py \
  tests/local_harness/test_wishbone_dma_session.py \
  tests/scenario/test_runtime_path_contract.py \
  tests/scenario/test_runtime_edge_index.py \
  tests/scenario/test_dma_runtime_paths.py \
  tests/scenario/test_uart_consumption_dma_master.py \
  tests/integration/test_dma_source_authority.py \
  tests/integration/test_dma_error_isr.py \
  tests/integration/test_dma_error_isr_real.py \
  tests/integration/test_dma_prefix_replay.py \
  tests/integration/test_dma_master_route_replay_readers.py \
  tests/integration/test_dma_uart_descriptor.py \
  tests/integration/test_dma_uart_descriptor_real.py \
  tests/integration/test_dma_prefix_replay_real.py
```

## 新远程 S4 真实门

- 操作副本：`/root/fanzehui/myfuzz/operations/dma-master-route-contract-20261019-attempt4/`；证据：`/root/fanzehui/myfuzz/evidence/dma-master-route-contract-20261019-attempt4/attempt1/`。二者均位于 `agent.md` 允许的 `/root/fanzehui/**` 下。原远程项目 HEAD 在运行前后均为 `42a9ce99cc7d1b11d37f44b90e4753563691c44b`；操作副本基于 `008bac008575b15e3fc98b3ca8943e23758e48cf`，再叠加 preflight 中逐文件 SHA 固定的五个本地文件。
- 原生工具身份：pytest 9.1.1、Verilator 5.051 devel `vUNKNOWN-built20260806-e413e67`、OpenJDK 21.0.12.1；Ibex、OpenTitan、ZipCPU、WBUART 子模块分别固定在 `34b0705`、`fca045d`、`42606d2`、`f43a6b8`。`HOME`、`TMPDIR`、cache 和 evidence 均位于该 attempt 的 operation/evidence 目录；preflight 实测 `tempfile.gettempdir()` 等于 operation-local `TMPDIR`。
- 命令：`timeout 1800 python3 -m pytest -xq tests/integration/test_dma_prefix_replay_real.py`，使用证据目录中 `run-gate.sh` 保存的完整环境。UTC `2026-10-19 06:19:32` 开始，`06:39:22` 结束，pytest **1 passed in 1188.92s**，`pytest.exit=0`。
- 一次 boot 中有两条成功 RX→RAM case 和两条声明的非法目标 case。成功 word transfer 如下：

| Case | Read→write sequence | 数据 | RAM version |
|---|---:|---:|---|
| 1 | 1→2 | `0x5a` | `[0,7]` |
| 1 | 3→4 | `0x5a` | `[0,9]` |
| 2 | 5→6 | `0xa5` | `[0,18]` |

每个 word 的 read/write key 共用 testcase、DMA source、epoch、channel 与 execution identity；sequence 相邻但不同。UART read route 实测地址为 `0x50000018`；RAM 写入地址为 `0x23000` / `0x23004`。source read 的真实 RDATA、destination write payload、target effect 与 RAM version row 的值逐项相等；request/target/response 依 key 一对一连接。

实际 route/topology 身份（取自 case authority）：

| 身份 | SHA-256 / ID |
|---|---|
| path ID | `e058cf51c246c6112609f585aad4a31b9e4df093dd8686520bd7c92654845bc7` |
| route contract | `608d22dc4b4b704d964cbc56e5702e9478903b202c616b8b731abab81cedfed1` |
| graph | `25836eeb73fa94eca913f149e4e26e505da87f35c98153e143bdb50a65bd9c4b` |
| runtime edge index | `fb8bca30557f887ee3107255083a112e8aed83f00136302eba83302fb3431944` |
| topology | `bf68054273ce660f8037216a4eee9735f5e96b21ab6ebea12139cd7ae91c4486` |
| UART read route | `6d97b91fa7af81d2bdfe6e2d4a94f26587621c648e910e0d6373a264a2bdce67` |
| RAM write route | `8ed21c9a9d61a6574e4c3515b7290509e8c22a4c7e6369544ab6244d4baac2f5` |
| UART target identity | `87415b2790338c96466d75f6e4d73264a2cfbed2b905c5fda55ee5a3705734f0` |
| RAM target identity | `f22accbaa39ad3918e687b2469d240dc5ae7dbc6ad758be851084bebab215be1` |

UART route binds the `read_master` endpoint and its identity to a 4 KiB window at `0x50000000` with readable offset `0x18` and writable offset `0x1c`. RAM route binds `write_master` to persistent RAM at `0x10000`, size `0x20000`. The shared endpoint identity is `d29775e40bbc36d989791ac2232a22adf35198cded0b0488d5102a32dc08e952`.

### Controlled failure

Cases 3 and 4 each issued the real illegal `read_master` request at `0x50000020` (UART route offset `0x20`, outside its only readable offset `0x18`). The evidence records `target_rejection=declared_master_target_access`, a real environment-error receipt (`error=1`, `target_effect=false`) and one native error response (`error=1`, `rdata=0`). The error response edge is joined to the native error IRQ and ISR. Both cases have zero target delivery, zero DMA FIFO pop, zero accepted data beats, zero RAM commits and no UART transmit capture; measured DMA status is `0x40000000` (bit 30 set, busy clear). Neither error case produces a successful transfer certificate.

### Independent fresh-prefix replay

Fresh CPU/DMA/Runner/UART execution IDs all differ from the reference IDs. The typed case comparator reports no difference for all four cases, and the gate records four typed prefix digests:

| Prefix | SHA-256 |
|---:|---|
| 1 | `01d7b44bbd283f120dcebe2723a173b3ddf75589f47869b5f1c95606644404a9` |
| 2 | `dbb87156fc8176063f03a4877da252b979c7c0a0cd64647229e6201a4a338b49` |
| 3 | `6220fdac8856ef4a86008c69b5f20d4a868395d4ddc72e21fd393ae44ca0f992` |
| 4 | `d562079881648b38186af62207ac6cad7a007b7ca88db200203702e2223fe05b` |

The saved-case consistency audit `postrun-audit.py` checks stored route hashes for cross-case consistency and selected saved keys, values, versions and event references. It uses the production typed case comparator and the prefix digests recorded by the gate; it does not independently recompute route digests or reconstruct every request/target/response join from raw events. The passing native gate supplies those full joins and typed-prefix checks. The audit exits 0. `artifact-sha256.txt` verifies 28 evidence files; its companion hash is `db5feabdaeeec06801eecc215706e8a811e79156d5d5d1e51890a5efc080a132`.

## 远程尝试记录

所有失败尝试均保留在各自 evidence 目录，没有覆盖：

| Attempt | 结果 | 记录 |
|---|---|---|
| 1 | pytest exit 1，206.48s；编译 route index 时 `compiled DMA route index lacks its declaration`，未产出 S4 case certificate。 | 此次漏设 operation-local `TMPDIR`，pytest 默认在 `/tmp/pytest-of-root` 创建临时路径。该路径之后未被访问或清理；后续 attempt 全部将 `HOME/TMPDIR` 放在 operation 目录。 |
| 2 | 日志为 `1 failed in 971.27s`；`pytest.exit` 记 1，但 `failure-summary.json` 的 `command_exit_code` 记 2，两个外层收据不一致。失败点是 replay 内对 case 使用 raw `!=`，先于 typed comparator 拒绝了执行 ID 与 tuple/list 规范差异。 | descriptor 已保存，fresh 未保存；不授 runtime-observed/replay-verified。 |
| 3 | pytest exit 1，986.83s；内部 replay 已完成，fresh 已保存；外层测试仍用 `fresh.cases == result.cases` raw equality。原始比较为 false，但 typed difference 为 null。 | 修正三个受影响 real gate 的外层比较后启动新目录。 |
| 4 | pytest exit 0，1 passed in 1188.92s；独立证据审计 exit 0。 | 本报告记录的新身份与证据。 |

## 能力等级与未完成项

| 状态 | 本轮结论 | 依据 |
|---|---|---|
| `declared` | 已达到 | route contract v2、两个显式 selected route edge 及闭合字段 |
| `topology_bound` | 已达到 | 真实 session endpoint、UART window、RAM resource、permissions 与 topology/edge digests |
| `runtime_observed` | 已达到 | 三个成功 word transfer、真实目标事件/响应/RAM version，以及两条受控 native error/no-effect case |
| `replay_verified` | 已达到 | 新鲜 execution IDs、四个 typed prefix、四个 case typed difference 均为 null |

本轮不授 P7 `PathWiring`/D3 F6：它仍是 `unsupported`，拒绝原因仍为 `dma-master-route-undeclared`。PULP、ZipCPU UART、Caliptra DMA provider adapter 未接入。P6/P7/P8、六颗 CPU 整体适配、持续 DMA fuzz、P8 5× 目标、全局 cycle timing、CPU decode/retirement 均未由此报告关闭或证明。RAM 结论仅基于实际 `memory_write`/version event，不包含 service commit receipt 授权。

## 证据索引

新运行文件均在远程目录 `/root/fanzehui/myfuzz/evidence/dma-master-route-contract-20261019-attempt4/attempt1/`：

- 运行命令与环境：`run-gate.sh`、`preflight-metadata.json`、`pytest-version.txt`、`verilator-version.txt`、`java-version.txt`、`submodule-pins.txt`。
- 终态与原始运行：`run-start-utc.txt`、`run-end-utc.txt`、`pytest.log`、`pytest.exit`、`manifest.json`。
- 正例/负例和 pinned input：`descriptor.json.gz`、`fresh.json.gz`、`cases.json`、`source_pins.json`、`prefix-digests.json`。
- 保存数据独立核对：`postrun-audit.py`、`postrun-audit.json`、`postrun-audit.exit`、`artifact-sha256.txt`、`artifact-sha256.sha256`。`postrun-audit.run.log` 中的 `d49ba…` 是审计脚本运行期间生成的初始哈希快照；wrapper 写完 audit exit/log 后重新生成并验证了最终 SHA 清单，最终哈希见 `artifact-sha256.sha256`。审计脚本自身前三次 metric 假设失败的日志也保存在同目录 `postrun-audit-attempt{1,2,3}.log/.exit` 中；它们不影响 pytest 通过结果。
- attempt1–3 的原始运行、失败摘要和诊断分别位于 `/root/fanzehui/myfuzz/evidence/dma-master-route-contract-20261019-attempt{1,2,3}/attempt1/`。
