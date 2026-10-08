# P4 合法"初始 RAM 数据"算子（会话启动前变异）

日期：2026-10-07（软件）；真实门禁补于 2026-10-08。P4 清单第 2 项要求"合法 CPU 指令替换/插入/删除/操作数/立即数、**初始 RAM 数据**、外设环境源、因果序列、合法路径切换操作子；初始数据在会话启动前变异；会话内仅未知数据字节的首次读取可物化一次；每种操作子保存采用/拒绝原因"。本报告先交付**软件**部分与**已准备、未运行**的真实门禁；作者当时没有运行任何 Verilator/RTL 作业，因此原文不含真实 RTL 结果。

> **后续真实门禁（2026-10-08，root 串行执行）：** `bash runs/current-dataflow-p4-initial-ram-20261007-logs/initial_ram_arms.sh` 四步全部退出码 0，只读门禁 `initial_ram_gate.py` 报 `ok=true`、`failures=[]`。真实 Ibex 会话里：OFF 枝（无开关）不声明算子、默认模板等于 shipped 声明；ON 枝在**任何读取之前**把 `initial-ram-data.ram.6`（地址 `0x100E6`、值 `148 = 0x94`）作为初始镜像写入 trace（event_id 6，`initial_image`），CPU 首次读该四字节（event 774、lane 2、`c0d894d8`）的 lane 值正是 `0x94`，其 writer 并列 `["init:ram:228","init:ram:229","initial-image","init:ram:231"]`／kinds `["FIRST_READ","FIRST_READ","INITIAL_IMAGE","FIRST_READ"]`；该字节在 `slot_immutability` 下判 `immutable`（run_conclusion `immutable`、0 violated）。被抽中的地址与取值可由运行自己的 `seed.bin`（raw sha256 `af5570f5…`）加重算域摘要复现（`draw.address=65766`、`draw.value=148`）；ON 枝 fresh replay `matches=true`。门禁自述作用域：只覆盖这两个运行目录的产物与这一个声明字节，`rtl_executed_by_gate=false`。

## 算子规则

- 模块：`src/myfuzz/scenario/initial_ram_data.py`。开关：`MYFUZZ_INITIAL_RAM_DATA`（构造参数 `initial_ram_data`，`--initial-ram-data`）。`None`+未设置=完全未声明，算子不运行、不产生任何状态；显式 `0`/`off`（或 `--initial-ram-data` 之外的显式关闭）会**声明并记录**为 `enabled=false`，便于 A/B 两枝自述。
- 声明：`TrustedInitialRamDataDeclaration`（受信 profile/模板侧声明，内容寻址 `declaration_id`）。字段：`scope`（窗口来源）、`component`/`memory_id`（会话已声明的内存）、`base`+`byte_count`（有界字节窗口）、`value_base`+`value_mask`（有界取值域，`0x00..0xFF` 的 mask/range 语义与既有 feedback/ownership 声明一致）、`image_id`。请求不能放宽声明：地址由窗口取模得出、越界地址按"未声明字节"拒绝。
- 取值抽取：`sha256(b"myfuzz.online.initial_ram_data.v1\0" + raw)`，前 8 字节在声明窗口内选字节、次 8 字节在声明 mask 内选值；只依赖该例 raw 记录与声明，不看时钟、计数器或搜索状态，故回放提议同一字节。域分隔与 shipped `_apply_path_switch` 的 `myfuzz.online.path_switch.v1\0` 不同。
- 物化方式：采用后**不是在会话内写内存**，而是把该字节作为一张新的初始镜像追加进会话模板（`MemoryImage`），由 `begin()` 与其它已声明镜像一起 `preload_image`。因此：会话启动前决定；镜像是 `initial_image` 事件；CPU 首次读该字节即返回变异值；fresh replay 只需 `online_plan.json` 里的模板即可重建（算子不必重放）。
- Ibex＋双 GPIO 的声明来源：`declared_initial_ram_data_window(bootstrap)` 只用该 wiring 自己的声明推导：`cpu.stream.bootstrap` 固定程序镜像结束处到下一个已声明段之间的**空隙**（当前 0x100e0..0x10100，32 字节，上限 `INITIAL_RAM_DATA_WINDOW_LIMIT=256`）。该空隙由固定固件留着不物化，真实 Ibex 的预取正好读它——shipped 运行里 0x100e0/0x100e4 就是以 `FIRST_READ` 物化的未知字节读。布局异常（缺段、越界、与指令预留重叠、超上限）一律抛错，不猜窗口。
- raw 记录：在线路径启动前可用的 raw 就是 RFuzz 客户端的种子记录。CLI 把同一串字节同时交给算子（`--initial-ram-record`，默认 `0000000000000000`）和 `run_scenario_rfuzz_live(seed_records=...)`，运行时把它原样存进 `seed.bin`，所以任何人都能从运行产物重算被选中的字节。

## 拒绝原因（复用 shipped `candidate_rejection.v1`，未新增码）

算子自己的稳定 `reason` 词表与 `online_path_switch_refusal.v1` 同形（算子命名原因，shipped 码原样保留）：

| reason | shipped code@pointer | 触发条件 |
|---|---|---|
| `adopted` | —（`rejection=null`） | 采用该声明字节 |
| `operator_disabled` | —（`rejection=null`） | 显式声明为关 |
| `malformed_raw` | `decode.malformed_record@initial_ram.raw` | raw 非非空 `bytes` |
| `undeclared_byte` | `mmio.out_of_window@initial_ram.address` | 抽中字节不在会话声明内存窗口内（`byte_offset=null`，不给猜测值） |
| `fixed_image_byte` | `ownership.fixed_input@initial_ram.address` | 该字节已被会话模板的固定镜像确定（detail 带 occupant 镜像 id） |
| `bound_slot_byte` | `ownership.bound_input@initial_ram.byte_offset` | 该字节属于已预留、尚未填充的在线指令槽（真实取指将决定它） |
| `materialized_byte` | `slot.materialized@initial_ram.byte_offset` | 该字节已由真实读/Store/镜像确定（detail 带 occupant writer kind，`STORE`/`FIRST_READ`/…） |
| `already_adopted` | `slot.already_consumed@initial_ram.byte_offset` | 同一算子已决定过该字节（未知一次，绝不二次物化），detail 记录已采用值与本次提议值 |
| `budget_exhausted` | `budget.exhausted@initial_ram.max_bytes` | 已采用字节数达到声明上限 `max_bytes` |

未新增拒绝码，因此 `rejection_code_catalog_sha256` 与两个冻结摘要测试（`tests/scenario/test_rv32i_rejection_codes.py`、`tests/scenario/test_online_candidate_rejection_receipt.py`）**未改动**。

## 身份论证（默认关闭）

- 未声明（默认 CLI/默认构造）时，`ScenarioSession` 不产生任何算子状态：`initial_ram_data_state()` 返回 `None`，live 报告不新增 `initial_ram_data` 键，`run_config` 不新增字段。会话模板、`encode_plan()`、`decoder_manifest.json`、`online_session_manifest.json` 的**文档内容**与未引入该特性的同树实现逐字节相同（测试：`test_default_off_identity_of_manifest_plan_and_candidate_ids`）。
- "与今天逐字节相同"的实测锚点：`test_default_declaration_still_matches_the_shipped_run_plan` 把当前 `make_ibex_pulp_dual_source_stream_bootstrap().template` 与已归档真实运行 `runs/current-dataflow-p4-path-switch-on-20261007-online/online_plan.json` 的 `template` 逐字节比较（现树通过）。
- 候选身份不变：算子不接触 decoder/source/`_sequence`/指令预留，显式关枝与未声明枝的 `candidate_id`/`source_id`/manifest 逐例相同（同一测试）。
- 新模块**没有**加入 `session_runtime._ONLINE_SOURCE_PATHS`：加入会让每一次运行（包括关闭枝）的 `online_source_files` 变化，直接违反"关闭时 session manifest 不变"。算子源码身份改由运行态 `initial_ram_data.operator.source.sha256` 记录，门禁脚本把它与当前树模块摘要做同一性比对（不是身份绑定，边界见下）。
- 开启时：只有 `online_plan.json` 的 `template.initial_images` 多一张镜像、trace 多一条 `initial_image` 事件；session manifest / decoder manifest / candidate_id 仍不变。

## 测试（软件，无 RTL）

命令与结果：

```bash
cd /home/qinkejiu/myfuzz && PYTHONPATH=src python3 -m pytest \
  tests/scenario/test_initial_ram_data_operator.py -q -p no:randomly
# RED（实现前，模块不存在）：ModuleNotFoundError: No module named 'myfuzz.scenario.initial_ram_data'
# GREEN：26 passed, 18 subtests passed
```

覆盖：合法变异（会话启动前、采用后内存无副作用）、首次未知读返回变异值（关闭对照=shipped 摘要值 + `FIRST_READ`；开启=变异值 + `INITIAL_IMAGE`/`initial-image`、其余同字车道仍按首次读物化一次且不再重物化）、未声明/固定/预留槽/已物化（`STORE` 与一次性未知读两种）/重复采用/预算/坏 raw 的拒绝、启动后（含 `finish()` 后）错相位拒绝、抽取确定性与域分隔、回放（`online_plan.json` 重建 + 篡改字节被 plan 身份拒绝）、默认关闭身份、slot 不可变性正向与反向对照（把读回的变异车道改错→`violated`/`later_read_different_value`）、Ibex 声明推导与 CLI 接线（同一 raw 同时给算子与客户端；坏 hex 在任何 harness 之前失败）。

## 真实门禁（已准备，未运行）

```bash
cd /home/qinkejiu/myfuzz
bash runs/current-dataflow-p4-initial-ram-20261007-logs/initial_ram_arms.sh
```

脚本内三条命令（同 BIN/同 `--seed 20261007`/同 150 秒/96 例/各自全新 cache）：

```bash
python3 scripts/run_ibex_pulp_online.py run --client-binary $BIN \
  --cache-dir runs/p4-initial-ram-off-20261007-cache \
  --output runs/current-dataflow-p4-initial-ram-off-20261007-online \
  --seconds 150 --max-tests 96 --seed 20261007 \
  --run-id current-dataflow-p4-initial-ram-off-20261007            # OFF（默认，未声明）

MYFUZZ_INITIAL_RAM_DATA=1 python3 scripts/run_ibex_pulp_online.py run --client-binary $BIN \
  --cache-dir runs/p4-initial-ram-on-20261007-cache \
  --output runs/current-dataflow-p4-initial-ram-on-20261007-online \
  --seconds 150 --max-tests 96 --seed 20261007 \
  --run-id current-dataflow-p4-initial-ram-on-20261007             # ON

python3 scripts/run_ibex_pulp_online.py replay \
  --cache-dir runs/p4-initial-ram-replay-cache-20261007 \
  --plan runs/current-dataflow-p4-initial-ram-on-20261007-online/online_plan.json \
  --trace runs/current-dataflow-p4-initial-ram-on-20261007-online/online_final_trace.json
```

只读门禁（`runs/current-dataflow-p4-initial-ram-20261007-logs/initial_ram_gate.py`，不编译、不启动 RTL、流式/有界读取）将证明：

1. 从**该运行自己的** `seed.bin` + 当前树推导出的受信声明重算抽中字节（地址/值/image_id），与 `online_plan.json` 里唯一一张 `initial-ram-data.*` 镜像逐字段相等；
2. `report.json` 的 `initial_ram_data` 状态（声明 id、enabled/source、attempts/adopted、采用字节、拒绝与拒绝码计数）与重算一致，且其中记录的算子源码摘要等于当前树模块摘要；
3. trace 中有该 image_id/地址/值的 `initial_image` 事件（启动前物化，不靠后续输入）；
4. **首个**返回该字节的读，其车道 `writer_event_ids[lane] == "initial-image"` 且车道值等于变异值——按读自身的 writer 身份连接（报告 event_id/producer_event_id/lane/事务通道），不是事件相邻推断；
5. `slot_immutability` 把该字节判为 `first_materialization_kind=initial_image`、`immutable`，且该 run 无 `violated` slot；
6. OFF 对照枝：报告没有 `initial_ram_data` 键、plan 模板等于 shipped 声明，且同一字节若被读则是 shipped 首次读路径（不是本算子）。

**不会证明**：其他字节/其他 run 的可变性；算子的搜索收益（本门禁不做同预算覆盖/性能对照）；"未知 RAM 首次物化"以外的通用数据流传播；任何 P5/P6/P7/P8 结论。另外该字节位于固定固件留空的**取指空隙**，真实 Ibex 会**推测预取**它：变异值因此是"会被真实取指读到的 RAM 数据字节"，不是经 ISA 校验的指令操作子（shipped 运行中同一地址本就是摘要随机字节，全部用例正常完成）；这一边界必须在报告里原样保留。

**当前限制（软件门禁只做到这里）**：作者已用 shipped 真实产物对门禁做过反向自检——对 `runs/current-dataflow-p4-path-switch-off/on-20261007-online` 运行该门禁，它给出 4~5 条精确失败（ON 枝没有算子），同时验证了重算路径与身份连接可用，并证明 OFF 枝 plan 模板等于 shipped 声明、0x100e6 车道确由真实 Ibex 以 `FIRST_READ`（writer `init:ram:230`，事件 774，通道 `instr`）读过。ON 枝的真实结论必须由 root 跑出后才能填写，本报告不预写。
