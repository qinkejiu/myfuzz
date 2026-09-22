# 阶段 A 剩余 + 阶段 B/C 实施记录（2026-09-21）

计划：`docs/superpowers/plans/2026-09-20-soc-composition-assurance-plan.md`。
本文件只记录**实际执行过**的命令与结果；未执行或无法验证的事项单列在最后一节。

## 0. 本轮开始时的环境变化

`third_party/` 与 `external_designs/` 子模块在本轮已就绪（约 660 MB）。因此：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 scripts/verify_soc_sources.py   # exit 0
```

全部 9 条锁定记录 `source_verified`，7 条 `elaboration_verified`。原先因缺源码失败的 12 个用例恢复；步骤 1 的基线报告见 `docs/reports/soc-step1-baseline-20260921.md`。

## 1. 新增实现与测试

| 步骤 | 新模块 | 测试模块 | 用例数 | 结果 |
| --- | --- | --- | --- | --- |
| 2 | `composition/component_profile.py` | `tests.composition.test_component_profile` | 16 | OK |
| 3 | `composition/soc_port_dispositions.py` | `tests.composition.test_soc_port_dispositions` | 13 | OK |
| 4 | `composition/soc_composition.py`、`soc_profile_renderer.py` | `tests.composition.test_soc_composition` | 20 | OK |
| 4A | `composition/soc_interrupt_plan.py`、`protocols/rtl/soc_irq_controller.sv` | `tests.composition.test_soc_interrupt_plan`、`tests.protocols.test_soc_irq_controller_rtl` | 13 + 5 | OK |
| 5 | `composition/soc_runtime.py`、`soc_profile_renderer.py` | `tests.composition.test_soc_composition`（RawLayout）、`tests.integration.test_soc_custom_port_drivers` | 含上 | OK |
| 6 | `protocols/rtl/soc_special_input_driver.sv`、`composition/soc_runtime.py` | `tests.protocols.test_soc_special_input_driver_rtl`、`tests.integration.test_soc_custom_port_drivers` | 6 + 12 | OK |
| 6A | `composition/input_constraints.py` | `tests.composition.test_soc_dependency_policy` | 32 | OK |
| 6B | `composition/soc_image.py`、`soc_instruction_stimulus.py`（+`flush`/`byte_image`） | `tests.composition.test_soc_image` | 16 | OK |
| 6C | `composition/soc_failure_evidence.py`（重放） | `tests.integration.test_soc_dependency_replay` | 20（默认 6 + 真实 14） | OK |
| 7 | `composition/soc_structure_audit.py` | `tests.composition.test_soc_structure_audit` | 16 | OK |
| 8 | `composition/soc_boot_program.py`、`configs/cpus/ibex/component_profile.json`、`examples/soc_generation/request-ibex.json` | `tests.composition.test_soc_boot_program`、`tests.composition.test_ibex_component_profile`、`tests.integration.test_soc_interrupt_lifecycle` | 29 + 16 + 4 | 全部 OK（真实闭环 4/4） |
| 9 | `composition/soc_failure_evidence.py`（归因、缩减） | `tests.integration.test_soc_failure_evidence` | 15（默认 9 + 真实 6） | OK |
| 10 | `scripts/generate_soc.py` | `tests.integration.test_soc_assurance_acceptance` | 15 | OK |

真实仿真模式（`MYFUZZ_SOC_REAL=1`）下 6C/9 的 35 个用例零跳过全通过（`runs/soc-dependency-replay/final-real.txt`）。

## 2. 端到端生成证据（当前可复现）

```bash
PYTHONPATH=src:. python3 scripts/generate_soc.py \
  --request examples/soc_generation/request.json \
  --profile examples/soc_generation/profiles/novacore.json \
  --profile examples/soc_generation/profiles/novauart.json \
  --profile examples/soc_generation/profiles/novagpio.json \
  --output runs/soc-generation/cli-check        # exit 0, audit pass

PYTHONPATH=src:. python3 scripts/generate_soc.py \
  --request examples/soc_generation/request-ibex.json \
  --profile configs/cpus/ibex/component_profile.json \
  --profile examples/soc_generation/profiles/novauart.json \
  --profile examples/soc_generation/profiles/novagpio.json \
  --output runs/soc-generation/ibex-demo        # exit 0, audit pass
```

第二条即 1.11 的“**已有 CPU + 首次输入外设**”场景：真实 Ibex（43 文件闭包 + 4 个 include root，`git:34b0705…` 固定）与两个首次输入外设组合，10/10 结构检查通过，2 项显式 `unknown`（内存模型参数、协议行为）。

## 3. 本轮由独立审计/集成测试发现并修复的真实缺陷

计划要求“在计划不变时故意改错，检查器必须检出”。实际发生过 4 次同类事件，全部已修复并加了回归：

1. **分离取指/数据接口的 CPU 被接错**（`soc_profile_renderer._cpu_adapter_roles` 把两个 OBI 主接口的角色合并成一张表，data 覆盖 instruction）。由审计的 `cpu_adapter_wiring` 检出；改为按 endpoint 作用域的角色表 + 兼容回退。
2. **审计无法展开真实 CPU**（`source_list` 只发布顶层所在文件、审计不转发 include 路径）。改为发布 profile 声明的完整闭包与 include root，并让审计转发 `-I`。
3. **运行时测试平台没有真正的复位沿**（`rst_ni` 上电即为 0，异步复位块永不触发）。真实 Ibex 因此以 U 模式启动、`csrw mtvec` 触发 illegal instruction。改为上电为释放电平、初始块内显式拉低。
4. **中断控制器窗口未做地址窄化**（路由转发全局地址，控制器按窗口内偏移译码，导致所有寄存器不可达而单元测试与结构审计都通过）。改为：控制器 `ADDRESS_WIDTH` = 窗口本地宽度、渲染时接 `t_addr[idx][w-1:0]`、计划记录窄化证明、审计新增该切片的独立检查。

第 3、4 条是“结构通过但真实运行失败”的典型，说明 1.10.3 的“能组合 ≠ 能运行”门槛是必要的。

## 4. 覆盖与局限（不得写成已验证）

- 首期仍是单核、单时钟域、全局单未完成事务的 beat 互联；并发/乱序行为未覆盖。
- `bfm_isolated`（`mmio_only`）模式下没有 CPU 执行证据；`contention`（`mixed`）下两个真实主接口共享单事务互联。
- Ibex profile 的 4 个顶层聚合端口（`ram_cfg_icache_*`）无法被当前前端展开，已在 `evidence.unknown` 记录，未分类。
- 结构审计只证明结构；协议行为、复位释放时序、时钟域跨越、多核一致性均未证明。
- 内存回读窗口目前是每个存储实例前 32 个字（256 字节）；超出该窗口的观测点需要显式扩展，不能靠移动程序地址规避。
- 12 个既有用例依赖 RFuzz 自带的 Verilator 5.020（`third_party/rfuzz/upstream/.tools/...`，未随子模块发布），在本机持续失败，与本轮改动无关。

## 5. 未执行/未验证

- `tests.integration.test_soc_matrix_runtime` 的完整八格套件未在 `MYFUZZ_SOC_REAL=1` 下整轮执行（步骤 1 只对 4 个 cell × 3 模式做了等价复现）。
- 真实中断闭环**已通过**（本节初稿写于修复前，现更新）：单源 lifecycle 的 `MYFUZZ_SOC_REAL=1 python3 -m unittest tests.integration.test_soc_interrupt_lifecycle` 正例/负例/错误访问闭环通过；同一入口的双 `novagpio` 多源类另通过 5 tests，覆盖同周期、staggered 和 `enable_interrupts=False` 屏蔽。真实 Ibex 执行引导程序、外设条件 latch、控制器 pending 置位、CLAIM 返回与计划源表一致的 id、ISR 按声明的清除操作解除条件、COMPLETE 被接受、完成标志写回 RAM。负例（控制器 ENABLE 保持复位值）为：源已 latch 且控制器已采样为 pending，但 claim_id=0、handler 从未进入。错误访问场景记录 mcause=5（load access fault）后继续。
- 缩减与归因的“注入真实组件缺陷”未能执行：示例组合的 CPU 是确定性骨架，注入缺陷需要修改 DUT，被规则禁止；因此分类分支用真实观测 + 合成判据覆盖，并已在测试中标明。

## 6. 2026-09-21 续做：生产入口的实际收口

上一版记录把 profile RFuzz 路径写成了“动态镜像尚未接入”。本节覆盖续做后的实际状态：

- `RtlSimulator.run_test` 现在支持可选的批量 `project_records`。profile artifact 会先投影特殊输入，再对每个 test 的 raw records 做有限的指令/数据检查，最多接受一个完整对齐 32 位指令候选和一个数据候选；多候选、压缩镜像和跨记录依赖仍明确拒绝。
- 生成的 protocol-2 testbench 先缓存整组 records，在 CPU 复位期间把投影后的候选写入对应 memory model 的 `initial_memory`，保持复位时钟让 RTL 自己复制到 `memory`，再释放 CPU。日志带 `MYFUZZ_IMAGE` 地址、值和复位电平，读回的是工作内存而不是 Python 旁路状态。
- 指令/数据地址默认按声明窗口做确定性字槽投影；`image_address_policy=strict` 保留拒绝越界输入的负例模式。修复次数进入 projector 计数和 artifact provenance/hash。
- profile campaign 已接入现有 RFuzz protocol-2 transport、真实 Verilator 分支反馈、重启隔离和正式 `run_soc_campaign` 入口。相同组合/layout/policy/镜像/源码闭包/工具版本可通过 `build_cache_dir` 命中内容寻址编译缓存；样本变化不会触发 RTL 编译。
- APB3 `HAS_PSTRB=0` 现在由通用桥以显式未连接输出处理；结构审计从展开 AST 的参数常量读取 `WINDOW_BASE/WINDOW_SIZE/HAS_PSTRB`。真实 PULP GPIO profile 仅将脉冲 IRQ 作为 observe，不宣称电平中断闭环。
- 增加了 `soc_boundary_replay.py` 稳定入口、命名的 boot/layout/boundary 测试，以及独立能力和验收记录。能力表见 `docs/reports/soc-capability-matrix-20260921.md`，验收记录见 `docs/reports/soc-design-acceptance-20260921.md`。

续做回归证据：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.integration.test_soc_profile_rfuzz_build \
  tests.integration.test_soc_campaign_matrix \
  tests.integration.test_soc_rfuzz_live \
  tests.integration.test_soc_rfuzz_build \
  tests.integration.test_rfuzz_live
# 65 tests, 10 explicit opt-in skips, OK

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.composition.test_component_profile \
  tests.composition.test_soc_composition \
  tests.composition.test_soc_image \
  tests.composition.test_soc_structure_audit \
  tests.composition.test_real_peripheral_component_profiles \
  tests.composition.test_ibex_component_profile \
  tests.integration.test_soc_boot_contract \
  tests.integration.test_soc_boundary_replay
# 128 tests, OK
```

仍未通过验收的项目没有被续做掩盖：`bfm_isolated`/`contention` 尚无可进入 RFuzz 语料的生成 BFM 主接口；UART/SPI/GPIO peer 已进入 profile raw ABI、persistent testbench、独立 oracle 和重放路径，并有独立 peer RTL 回归；UART+GPIO、SPI+GPIO 均有一次真实异构中断运行和单样本 EvidencePackage 重放，但线级协议判据、持续多源 campaign 和 PULP GPIO 电气双向仍未完成；程序依赖扩展、完整软件覆盖和内部 bug 归因仍是能力缺口或后续阶段。

## 7. 生产边界与三方对照机制

- profile artifact 生成前新增独立 `soc_structure_audit.v1` 重展开门。审计实际读取生成 top、发布的源码闭包和 include root；任一结构 finding 为 fail，构建不返回 artifact。缓存命中还要验证审计文件的内容 hash 和 `summary.status=pass`。
- `run_soc_campaign` 报告新增 `artifact` 边界记录，分别标出 generator、adapter、profile、software、environment 的证据状态；这些字段只说明边界证据，不把失败直接命名为组件内部 bug。
- `RtlSimulator` 和 RFuzz live report 记录有界的 raw/projected 样本数、唯一值数、投影拒绝数和修复计数；这些计数不进入 RTL coverage。
- `myfuzz.integration.soc_comparison.compare_soc_campaign_arms` 与 `scripts/compare_soc_campaigns.py` 提供 1.10.2 的 `direct_input`、`constrained_baseline`、`dependency_repair` 三方比较。它要求组合/layout/coverage identity 与结构审计一致，缺测保留为缺测，不以有效率上升单独宣称成功；报告中的 `component_bug_claim` 固定为 `not-claimed`。

新增回归：`tests.integration.test_soc_campaign_comparison`，以及 profile artifact provenance/cache 测试中的结构审计文件和 hash 检查。

## 6. profile 前端缺陷（第 8 项真实 profile 过程中发现，已修复）

为真实组件补 `component_profile.v1` 时，前端暴露了三个只在特定输入下才出现的缺陷。三者都不在 profile 侧，均已修复并加回归：

1. **隐式类型端口无法定位**。`input clk_i;`（无显式类型）的默认类型由 verilator 放在自己的 `verilated_std.sv` 里，而该文件不属于任何组件闭包，于是 `_Reader.physical_type` 报 `compiler location has no source mapping`。修复：三处 verilator 调用（`_direct_elaboration`、`elaborate_rtl_module`、`run_verilator_elaboration`）加 `--no-std-package`，隐式类型改用使用点位置。
2. **Verilog 网络型端口被静默丢弃**。`extract_physical_ports` 只接受 `varType == "PORT"`，而 Verilog-2001 的 `input wire i_clk` 会发出 `varType == "WIRE"`。修复后 `ziptimer` 从 2 个端口变为 12 个，`wbuart` 从失败变为 19 个。
3. **包含目录里的无关符号链接导致整个闭包被拒**。`_closure` 在目录遍历中对**任何**符号链接报错，而 pinned OpenTitan 树里 `hw/ip/tlul/rtl/tlul_adapter_shim.sv -> tlul_adapter_vh.sv` 位于 include root 内，于是受监督路径下 `opentitan_uart/gpio` 在 verilator 运行前就失败（直连路径不经过 `_closure`，所以同一个 profile 会随调用环境成功或失败）。修复：树内符号链接按其解析目标加入闭包（仍然对目标做哈希），只有逃出源码根或非普通文件才拒绝；逃逸用例仍有专门验证。

验证：`tests.composition.{test_source_elaboration,test_source_crawler,test_component_profile,test_ibex_component_profile}` + `tests.integration.test_soc_assurance_acceptance` → 114 用例 OK。
