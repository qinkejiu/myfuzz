# P2 · CPU-only 通用指令程序 fuzz（2026-11-03）

本报告对应 P2 工作流的 **A 条**：把 CPU-only 的 `--fuzz` 从「固定程序 + 数据变异」改成
**通用指令程序 fuzz**，减少对预构建 artifact 的依赖，并把 CPU/协议覆盖扩到 Wishbone 与
AXI4-Lite。所有结论都有 `runs/p2-cpu-only-20261103/` 里的真实 batch 行支撑。

## 1. 做了什么

1. **每例一条真实 RV32 程序**（不是同一程序的输入字）。复用仓库既有能力，不另造编码器：
   * 生成：`myfuzz.fuzz.rv32_program.generate_program(profile, seed, max_words, window_size,
     style='mixed', allow_auipc=False)`；
   * 门禁：`myfuzz.fuzz.f1_program_gate.validate_f1_program_record`（F1 程序门禁，1..16 字直线）；
   * 参考：`myfuzz.fuzz.f1_program_gate.f1_reference_expectation`（参考退休轨迹 + 数据窗口 + 写回）；
   * 组装：preable/trailer/sled 由 `myfuzz.scenario.rv32i_sources.Rv32iInstruction` 编码，
     停机器用文件里既有的 `jal x0, 0` 常量。
2. **保留旧形状**：`--fuzz-mode data` 就是上一轮的「固定轮询程序 + 32 位 mailbox 字」，
   逐字不变（见 §5）；模块 API 里 `fuzz` 映射不带 `mode` 时仍走 data（老调用方不被静默改变），
   入口 `--fuzz-mode` 默认 `program`。
3. **artifact 从 profile 现场解析**：渲染 → 按 `artifact_digest` 命中/构建 → 复用；
   summary 如实写 `artifact.source/cache_hit/compiled_this_invocation` 与
   `build_digest/artifact_digest`。P2 的四个 scenario 都不写死 `cpu_cache_digest`
   （P0 的两个 scenario 仍走 pinned 路径，语义未变）。
4. **总线扩到三种**（按 artifact 角色表分派，不按器件名分支）：
   OBI i/d（Ibex、CV32E40P）/ classic Wishbone（PicoRV32）/ AXI4-Lite（PicoRV32）。
   缺 RVFI 的模型 `retires/trap=unknown`，总线流照跑，判据降级为「完成字 + 数据窗口」并写明 `basis`。
5. **断言与失败分类不变**：DUT 内部断言 → `assertion_failed` + `returncode=3` + 保存
   file/line/scope/text；超时 → `environment_failed` + `returncode=4` + `reason=case_timeout`。

## 2. Hunk 清单（文件 + 函数 + 行为）

### `scripts/inprocess_cpu_only.py`（840 → 约 1500 行）

| 位置 | 改动 |
|---|---|
| 模块常量（`_FAULT_PROGRAM_WORDS` 之后） | 新增 `_HALT_WORD`、`PROGRAM_DATA_WORDS/PROGRAM_MAX_WORDS/PROGRAM_CASE_STRIDE/PROGRAM_SLED_WORDS/PROGRAM_DONE_OFFSET/PROGRAM_DONE_SENTINEL/PROGRAM_DONE_VALUE`、`BUS_PROTOCOLS`、`_BUS_ROLES`、`_BUS_DEFINES`、`_BUS_MACROS` |
| `load_cpu_only_config` | 校验新可选键 `cpu_artifact_source`、`max_wait_cycles`、`program_data_address`、`program_data_words`、`program_max_words` |
| `_artifact_cache_root` | 新增 `create=` 参数：profile 解析路径可创建缓存根，pinned 路径语义不变 |
| `find_cpu_artifact` | 未改动（P0 pinned 路径继续使用） |
| **新增** `_harness_request` / `render_profile_artifact` / `_cache_artifacts` / `resolve_cpu_artifact` | profile → 渲染 local-harness artifact（plan/structural/runtime/driver），按 `artifact_digest` 命中；未命中用 `build_local_harness_with_receipt` 构建并发布；返回 `source/cache_hit/compiled_this_invocation/observation`；在编译前先做总线形状拒绝 |
| `_check_bus_shape`（重写）/ **新增** `_bus_document` | 三种总线形状分派；不可服务时报 `cpu-only-bus-endpoint-unsupported:<endpoint…>` 或 `cpu-only-bus-shape-unsupported:<protocol>:<缺少角色>` |
| `_header` / `_link_host` | 按协议发 `CPU_BUS_*`/`CPU_BUS_NAME` 与各协议角色宏；签名加 `bus` |
| `build_cpu_only` | 改用 `resolve_cpu_artifact`；结果新增 `artifact`、`bus`、`compiled_this_invocation`、`cache_hit`；schema 升为 `p2_cpu_only_build.v1` |
| `_fuzz_records` | 保留原 `random.Random(seed).getrandbits(32)`；文档补 `mode='data'`、`program_basis`、`mutation_basis` |
| **新增** `_program_isa` / `_hi_lo` / `_program_preamble` / `_program_completion_store` / `_program_nop` / `_fnv32` / `_program_batch` | 生成整批程序 + 参考期望 + firmware image + `programs.txt` 元数据；RV32-only 与 image 边界在此拒绝 |
| **新增** `_fuzz_batch` / `_register_mask` / `_program_checks` | 归一化 fuzz 形状（data/program）；逐例对比（program_hash、program_words、done、两个数据窗口哈希、data_changed，以及有 RVFI 时的 retires/trace_count/trace_hash/rd_mask/pc_order/insns_match） |
| `run_cpu_only` | 新增 `fuzz_mode=` 关键字与 `mode` 键；program 分支写 `programs.txt` 并传 `--programs`；fault 在非 OBI 上按名拒绝；结果新增 `fuzz_mode/program_basis/mutation_basis/programs/program_checks/failure/bus/artifact/compiled_this_invocation/cache_hit/programs_file` |

### `scripts/inprocess_cpu_only_host.cpp`（392 → 约 800 行）

| 位置 | 改动 |
|---|---|
| 头注释 | 说明三种总线与两种输入形状 |
| **新增** `fnv32::{step,entry,offset_basis}`、`window_hash`、`ProgramCase`、`parse_programs` | 与 Python/shared host 同一个 FNV-1a 32；解析 `prog …` 元数据行 |
| `Bench::tick` | 拆成 `drive_bus()`（上升沿前驱动）+ `settle_bus()`（沿后记账）+ `sample_retirement()`；RVFI 采样顺序与原来一致 |
| `Bench::drive_bus` | `CPU_BUS_OBI` 分支保留原逻辑（只是搬位置，并加了 `bus_reads_/bus_writes_` 计数）；新增 `CPU_BUS_WISHBONE`（cyc/stb + 一周期 ack、必须看到 cyc/stb 撤销才接受下一笔）与 `CPU_BUS_AXI4LITE`（AR/R + AW/W/B，一次一笔，响应晚一拍、握手后撤销） |
| `Bench::settle_bus` / `clear_inputs` | 各协议握手后的状态清理与新输入初值 |
| **新增** `retired_this_tick/last_rd/last_wdata/bus_reads/bus_writes` | 逐拍退休与总线计数（供程序模式的逐例统计） |
| `main` | 新增 `--programs`；fault 路径 `#!OBI` 时按名拒绝；**程序模式循环**：每例在 `[start,end)` 内累计退休数/`rd_mask`/FNV trace、校验 `insns_match` 与 `pc_order`，以「完成字 == done_value」判定该例结束，打印一行 `case … program_hash/program_words/retires/pc/insn/trace/trace_count/writebacks/rd_mask/pc_order/insns_match/last_rd/last_wdata/done/data_hash_*/data_changed/bus_reads/bus_writes/ticks/wall_us`，`summary` 追加 `programs=N bus=<协议>` |

### 其它

* `configs/scenarios/p2-cpu-only-{ibex,cv32e40p,picorv32-wb,picorv32-axi}.json`（新增）：
  profile 解析（无 `cpu_cache_digest`）、`program_data_address/program_data_words/program_max_words`；
  AXI 与 CV32E40P 的 `required_observations=[]`（这两颗没有 RVFI）。
* `scripts/run_inprocess_f1f6.py`：**两处最小改动** —— 新增 `--fuzz-mode {program,data}`
  （默认 `program`，help 里限定只对 `--mode cpu-only` 生效）；cpu-only 调用点把
  `mode=args.fuzz_mode` 放进已有 `fuzz=` 映射。未触碰别的函数。
* `tests/integration/test_p2_cpu_only_program_fuzz.py`（新增，15 例）。

## 3. 真实结果（`runs/p2-cpu-only-20261103/`）

10 条批次 + 6 条探针，全部 `observations_passed`（探针按预期断言/环境/拒绝）。要点：

* `program-ibex`（8 例，OBI，RVFI 可观测）：实机 retires 与参考逐例相等（2/8/1/6/1/8/4/1），
  trace 哈希逐例相等，`insns_match=1`，4 例真实写数据窗口（`data_changed` 依次为 0/2/0/1/0/2/1/0）。
* `program-picorv32-wb`（8 例，Wishbone）：同样有真实退休与 trace 对比；总 tick 795。
* `program-picorv32-axi`（8 例，AXI4-Lite）：**无 RVFI**，`retires/trace=unknown`，
  8 例全部以「完成字 + 数据窗口」通过，`bus_reads/bus_writes` 是真实总线计数。
* `program-cv32e40p`（8 例，OBI）：同上，`retires=unknown`。
* `fixed-*`（4 条）与 `data-*`（2 条）：旧形状仍工作，`data-*` 就是 `--fuzz-mode data`。
* artifact：四个 scenario 首次运行都 `source=profile`，随后 `cache_hit=True /
  compiled_this_invocation=False`；冷/暖两条探针给出 `compiled_this_invocation=true → false` 的对照。

## 4. 测试

* `tests/integration/test_p2_cpu_only_program_fuzz.py`：**15 passed**（约 18 s，缓存暖）。
* `tests/integration/test_p0_cpu_only.py`：**10 passed**（不回归）。
* `tests/integration/test_inprocess_f1f6_entry.py`：182 passed / 14 failed —— 14 个失败**全部**是
  同一处 `KeyError: 'device_capabilities'`（`scripts/run_inprocess_f1f6.py:5199`，DMA 能力
  头部渲染），属于并行代理 E2 正在改的 DMA 区域，与本条改动无关（本条在入口只有 `--fuzz-mode`
  与 cpu-only 调用点两处）。已在父代理报告里点名。
* 既有失败基线（根 `README.md` 链接、`tests/composition/` 的 setsid）未触碰。

## 5. 不回归与被保留的语义

* `records=` 与 config `records` 的固定批次 case 行逐字不变（只 `wall_us` 变）；
  `test_data_mode_reproduces_the_p0_case_lines` 用**改动前**记录的三行做断言。
* `fuzz` 映射不带 `mode` → data 形状（P0 调用方语义不变）；带 `mode='program'` 或入口
  `--fuzz-mode program` 才走程序 fuzz。两种形状在 `result.fuzz_mode` 里显式区分。
* 断言捕获（file/line/scope/text）与「超时归 environment」未改；fault 仅在 OBI 上提供。

## 6. 仍拒绝 / 仍未知

**仍拒绝（具名）**：
`cpu-only-fault-bus-unsupported:<protocol>`（fault 只在 OBI）、
`cpu-only-program-isa-not-rv32:<xlen>`（RV64 profile）、
`cpu-only-bus-endpoint-unsupported:<endpoint…>`（打包 64 位 AXI4：CVA6/BOOM/VexiiRiscv 的
`noc_req_o/noc_resp_i`）、
`cpu-only-bus-shape-unsupported:<protocol>:<缺失角色…>`（角色表不完整）、
`cpu-only-fuzz-mode:<name>`、`cpu-only-fuzz-mode-conflict`。

**仍未知（如实写 unknown，不填 0）**：
`picorv32_axi` 与 `cv32e40p` 的 retirement/trap（无 RVFI 端口）——这些批次没有调用轨迹级对比，
只证明完成字与数据窗口；总线成功从不被当作退休。

**已知限制**（README §10 有完整列表）：同值写回不可区分（靠哨兵完成字兜底）、部分 case 是
ALU-only（`data_changed=0`）、程序形状限于 F1 直线子集（分支/压缩/循环未启用）、
单时钟单 reset、32 位端口。

## 7. 需要别的代理配合

* **E2 / DMA**：`scripts/run_inprocess_f1f6.py:5199` 的 `dma["device_capabilities"]` 让
  `tests/integration/test_inprocess_f1f6_entry.py` 14 例失败；这不是本条引入的，但会让
  「入口测试全绿」无法声明，请 E2 完成后由父代理复跑该文件。
* **C / D / F**：本条的 `_check_bus_shape` 只按 artifact 角色表分派三条总线；如果以后
  AHB-Lite 目标或相位时钟要接进 cpu-only 的单 CPU 总线服务，需要在本模块扩展
  `_BUS_ROLES`/`_BUS_MACROS` 与宿主 `drive_bus`，不要在共享宿主里加 cpu-only 分支。
