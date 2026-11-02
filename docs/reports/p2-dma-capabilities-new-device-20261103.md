# P2 · E2：DMA 能力扩展与真不同 DMA 器件（2026-11-03）

本报告是 P2 轮并行子代理 **E2** 的交付报告。工作规约见
`docs/reports/p2-workplan-20261103.md`；证据包见 `runs/p2-dma-20261103/`
（`README.md` + `run.sh` + `campaign.log` + 逐字 case 行）。

## 1. 结论

1. **真不同器件**：树内只有两颗 DMA **RTL**（`zipdma`、`wbdmac`）。`wbdmac`
   （`configs/peripherals/zipcpu_wbdmac`，RTL `third_party/soc-zipcpu/rtl/peripherals/
   wbdmac.v`）现在在统一入口的 F6 里**自主跑通真实搬运**：控制口配置（keyed start
   `0x0fed0004`）→ 真实 read beat → 真实 write beat → 器件自己的完成脉冲 →
   CPU 读回器件状态字。4 字与 8 字两种块都执行过，目标块由 CPU 事后逐字读回。
   `configs/peripherals/inprocess_generality_wbdmac` 经核对与 `zipcpu_wbdmac`
   **是同一份 RTL 的不同 profile**（同 revision/files/parameters/CSR 行），因此
   **不**当作新器件，也没有用它当证据。
2. **能力扩展**：真正被执行的方向是**块深度**（wbdmac 4 → 8 字，RTL 块长度字段是
   start word 低 10 位）。多通道、8 字节 beat、多 outstanding 三个方向都没有可执行的
   pinned 器件支持，全部按器件事实**具名拒绝**；其中多 outstanding 是**实测**不行，
   不是猜的（见 §4）。
3. **case 行可区分**：F6 行新增 `dma_device` / `dma_channels` / `dma_channel` /
   `dma_beat_bytes` / `dma_max_outstanding` / `dma_outstanding_peak` 组，只在器件不是
   「单通道/4 字节/深度 1 的 ZipDMA 历史形状」时打印，因此既有 ZipDMA 行逐字节不变，
   而任何带这一组的行都不可能来自 ZipDMA。
4. **回归**：改动前后，12 个既有 ZipDMA F6 场景的 47 条 `case` 行（含四种目标路由
   协议、APB3 FIFO 写/读、PRESCALER 读、aperture 读、master error 注入、4/8 字 RAM
   块、F1–F6 六流批次）**逐字节一致**（只删 `seconds`）。

## 2. 精确 hunk 清单

### 2.1 `src/myfuzz/composition/dma_transfer.py`（规划层，E2 区域）

| 位置 | 行为变化 |
|---|---|
| `MAX_OUTSTANDING`（约 73-81） | 1 → 2，并注释说明：这是**本模块声明的主机深度**，不再是「设备只有 1」的同义词；设备事实仍然是绑定上界 |
| `DEVICE_FACTS['zipdma']['capability_evidence']`（新增） | 四个能力轴各自的 RTL/参数锚点（`zipdma.v:52-96,69-75,403-411`；profile 的 `BUS_WIDTH=32`；`zipdma_s2mm.v:81,205-233`） |
| `DEVICE_FACTS['wbdmac']['capability_evidence']`（新增） | 同上（`wbdmac.v:167-179,110-120/137-143,551-561,410-456/472-533`） |
| `DEVICE_FACTS['wbdmac']['max_outstanding']` | 保持 **1**，注释改为「看起来可流水线（request/ack 计数器分开数）但 burst 终止条件把请求计数当 ack 计数（`wbdmac.v:472-491`），实测两响应环境搬运错误」，并指向证据目录 |
| `_device_declaration` | profile 里 `max_outstanding` 的**严格相等**检查（原来报 `dma-profile-source-drift`）改为：允许「声明 < 器件」（收窄），「声明 > 器件」由通用能力循环报 `dma-profile-capability-beyond-device`；非 1.. 报 `dma-profile-capability-invalid`。设备声明新增 `capability_evidence` 字段 |
| `dma_transfer_declaration` | `outstanding-beyond-one` 的 detail 变精确：`host:<n>><MAX_OUTSTANDING>` 或 `<family>:<n>><device>`（**名字沿用**，既有测试不动） |
| `_HOST_LIMITS['max_outstanding']`（新增）+ `_host_limits()` | 新 host 限制码 `host-outstanding-cap`；当 plan 深度 > 1 时以 `限制 = min(MAX_OUTSTANDING, artifact.environment_max_outstanding)` 报告，而不是把它当设备拒绝 |
| `validate_transfer_plan` | 删掉「plan 深度 > 生成 edge 环境的 `environment_max_outstanding` 就硬拒」的分支：那是某个执行器的能力，改由 `_host_limits` 上报、由拥有该数字的执行器回答；plan/设备两级上界仍报 `outstanding-beyond-one` |

### 2.2 `scripts/run_inprocess_f1f6.py`（统一入口，DMA/F6 区）

| 位置 | 行为变化 |
|---|---|
| `CASE_OBSERVATION_KEYS['F6']` | +6 键：`dma_device`、`dma_channels`、`dma_channel`、`dma_beat_bytes`、`dma_max_outstanding`、`dma_outstanding_peak` |
| `DMA_PROVEN_BLOCK_WORDS` | `wbdmac` 4 → `DMA_MAX_BLOCK_WORDS`（8），注释给出 RTL 依据（`wbdmac.v:264-266`） |
| `DMA_DEVICE_FACTS_DEFAULT`（新增常量） | 手工拼装的 F6 声明缺 `device_capabilities` 时回落到历史形状（单通道/4 字节），保证既有合成用例不受影响 |
| `DMA_HOST_CAPABILITY` + `dma_host_limits` | 新增 `host-outstanding-cap: 2` 与对应分支：满足时以「`DMA_MASTER_OUTSTANDING` 深度 + `dma_outstanding_peak` 实测」为证据上报，不满足时按名拒绝 |
| `dma_declaration` 返回值 | 新增 `device_capabilities`（`plan['device']['device_capabilities']`）与 `device_reported`（器件≠历史 ZipDMA 形状，或深度≠1） |
| 生成头渲染 | 新增 `#define DMA_MASTER_OUTSTANDING`、`DMA_DEVICE_CHANNELS`、`DMA_DEVICE_BEAT_BYTES`、`DMA_DEVICE_FAMILY`、`DMA_DEVICE_REPORTED` |
| edge contract 检查 | `environment_max_outstanding != 1` → 「非整数或 < 1」；生成 edge 环境的深度不再被当作本宿主的深度 |

### 2.3 `scripts/inprocess_obi_apb_f1f4_spike.cpp`（共享宿主，DMA 驱动区）

| 位置 | 行为变化 |
|---|---|
| 宏区 | 新增 `DMA_MASTER_OUTSTANDING`（默认 1）+ `#error` 保护 |
| 常量区 | `kDmaOutstanding`、`DMA_DEVICE_CHANNELS/BEAT_BYTES/FAMILY/REPORTED` |
| `Observation` | 新增 `dma_outstanding_peak`（实测并发响应峰值） |
| `Master master` → 响应环 | `Master master_ring[kDmaOutstanding]` + `master_head/master_count` + 访问器 `master_head_entry/master_pending/master_full/master_head_delay/master_push/master_pop`；设备复位清空整环 |
| 驱动段 | `mwb_stall = master_full()`（环满才拉高）、`mwb_ack` 由**队首**的 delay 决定、`mwb_dat_r`/`mwb_err` 取自队首；`dma_stall_*` 语义不变（有响应未回即计一 tick） |
| 「master 丢掉 pending 周期」不变式 | 仅在 `kDmaOutstanding == 1` 下成立（流水线 master 合法地在 burst 结束后掉 cyc） |
| 服务段 | 只给队首递减 delay；ack 时统计等待并 `master_pop()`；accept 时 `master_push()` 并记录峰值 |
| 路由读回填 | 捕获的 target 数据写进**队首**记录 |
| 空闲判据 / 路由 ack 门 | 改用 `master_pending()` / 队首 `routed` |
| F6 case 打印 | `#if DMA_DEVICE_REPORTED` 下新增器件/通道/beat/深度组 |

深度 1（默认）下以上全部与历史行为逐字节等价——由 §5 的 47 条行 diff 证明。

### 2.4 新增配置（E2 区域，未触碰他人 profile）

* 正例场景：`configs/scenarios/p2-wbdmac-f6-ram.json`、
  `p2-wbdmac-f6-ram-len8.json`（都钉 canonical `configs/peripherals/zipcpu_wbdmac`）。
* 正例 behavior：`configs/behaviors/p2-wbdmac_f6_status.json`（只声明 busy/err 位，
  块长度留给场景）。
* 负例场景：`p2-wbdmac-refusal-{channel2,beat8,burst2,outstanding2,
  capability-outstanding2}.json`、`p2-zipdma-refusal-{outstanding2,
  two-channel-profile}.json`。
* 负例 behavior：`configs/behaviors/p2-wbdmac_refusal_{channels2,beat8,burst2,
  outstanding2}.json`。

### 2.5 测试

* 新增 `tests/integration/test_p2_dma_capabilities.py`（25 个用例，全绿）：器件集合
  （两颗 RTL / 8 个 profile）、两个 wbdmac profile 同源、四个能力轴的 RTL 锚点存在且
  行号在文件内、四个能力拒绝、两个设备的深度 2 拒绝、profile 级两通道拒绝、
  plan 复核、三条 wbdmac 真实搬运证据、ZipDMA 行无新组、12 对日志逐字节回归、
  窄 beat 执行、七个负例的具名拒绝。
* 未改动 `tests/composition/` 任何既有文件结构（只跑它）。

## 3. 真实结果（来自本次运行）

| 批次 | 场景 | 结果 |
|---|---|---|
| wbdmac 4 字 | `p2-wbdmac-f6-ram.json` | `observations_passed`；`dma_reads 4 dma_writes 4`；`dst0..3 = 0110c000,08000000,deadbeef,12345678`；`isr_flag 1` |
| wbdmac 8 字 | `p2-wbdmac-f6-ram-len8.json` | `observations_passed`；8/8 beat；`dma_start_word 0x0fed0008`；`dst0..7` 全对；`dma_lane_written 32` |
| wbdmac 六流批次 | `p2-wbdmac-f6-ram.json` | `observations_passed`（F1/F2/F3/F6 共 4 例，F6 同上） |
| 窄 beat（ZipDMA） | `inprocess-obi-apb-ibex-timer-zipdma-byteen-f1f6.json` | `observations_passed`；16/16 一字节 beat；`dma_master_beats_per_word 4`、`dma_master_partial 1` |
| 多 outstanding 实测 | `wbdmac-outstanding2-mismatch/{no-delay,delay-1}` | 两次 `failed`：4 字块 7 读 2 写 / 4 读 0 写，目标块未写全，`wait_timeout 1`；`delay-1` 达到 `dma_outstanding_peak 2`（宿主环真的工作了） |
| 七个负例 | `refusals/*` | 全部在声明/规划阶段按名拒绝，不产生 case 行 |

## 4. 多 outstanding 的精确结论

*宿主* 能同时持有 2 个 master 响应（`delay-1` 实测 `dma_outstanding_peak 2`）；
*器件* 不能：pinned wbdmac 的读突发终止条件
（`last_read_request <= (nracks+1 == cfg_blocklen_sub_one) || (bus_nracks == cfg_len-2)`，
`third_party/soc-zipcpu/rtl/peripherals/wbdmac.v:483-488`）把 `nracks`
（`wbdmac.v:410-420` 数**已接受请求**）与块长度比较，而 `nread`
（`wbdmac.v:422-432` 数 ack）才是它的「已完成」计数。宿主一旦不等 ack 就接受第二个
请求，4 字块就读成 7 个 beat、只写 2 个 beat，目标块只有第 0 字正确，传输不完成。
因此 `DEVICE_FACTS['wbdmac']['max_outstanding']` 保持 1，深度 2 的拒绝名是
`outstanding-beyond-one:wbdmac:2>1`（计划级）与
`dma-capability-beyond-device:max_outstanding:2>1`（声明级）。

## 5. 仍拒绝 / 仍未知

| 项 | 精确拒绝名（入口打印） | RTL 依据 |
|---|---|---|
| 多通道（wbdmac） | `dma-capability-beyond-device:channels:2>1` | `wbdmac.v:167-179`（一套 `cfg_raddr/cfg_waddr/dma_state`），CSR 只有 4 字 |
| 8 字节 beat（wbdmac） | `dma-capability-beyond-device:beat_bytes:8>4` | `wbdmac.v:110-120`（`BUS_WIDTH=32`）、`137-143`（无 SEL 引脚） |
| 2 beat burst（wbdmac） | `dma-capability-beyond-device:burst_beats:2>1` | `wbdmac.v:551-561`（每拍一个 `cyc/stb`，无 burst 长度信号） |
| 深度 2（wbdmac 计划级） | `outstanding-beyond-one:wbdmac:2>1` | `wbdmac.v:472-491` + §4 实测 |
| 深度 2（ZipDMA 计划级） | `outstanding-beyond-one:zipdma:2>1` | `zipdma.v:403-411`（单请求单 ack；无请求/ack 计数对） |
| 两通道 profile（ZipDMA） | `dma-profile-capability-beyond-device:zipdma:channels:2>1` | 同上，profile 声明超出 pinned RTL |

仍未知（不声明已支持）：

1. wbdmac 的 `busy` 位没有被真实观测到拉高（本包 case 里 `busy_before/after 0`）；
   `dma_status_bits` 来自行为声明（`wbdmac.v:600-609` 的读回拼接），不是本包测量值。
2. wbdmac 的 native master error 未注入过（本包只对 ZipDMA 侧的历史 error 用例做了
   回归；wbdmac 的 `cfg_err` 路径未跑）。
3. wbdmac 的 `halt` / `abort` 两种控制字**在 RTL 里存在**并被译码：
   `s_data == 32'hffed0000` 在非 idle 时置 `abort`、`32'hafed0000` 置 `user_halt`
   （`third_party/soc-zipcpu/rtl/peripherals/wbdmac.v:645-676`），但本包**没有**执行过
   它们——F6 只写规划层的 start word，中止/暂停不是本规划语法里的能力，也没有跑过
   真实批次。要宣称它，得先有一条真实"中途写 halt/abort → 观察 RTL 进 IDLE"的 case。
4. 8 字节 beat / 多通道需要新 RTL，本包不引入。

## 6. 测试数与状态

| 套件 | 结果 |
|---|---|
| `tests/integration/test_p2_dma_capabilities.py`（新增） | **25 passed** |
| `tests/composition/test_dma_transfer.py` | 59 passed |
| `tests/integration/test_inprocess_dma_route_protocols.py` | 24 passed |
| `tests/integration/test_inprocess_f1f6_entry.py`（动了入口） | 196 passed |
| `tests/integration/test_p1_replacement_configs.py` + `test_p7b_p7c_dma_route_intent.py` | 42 passed |
| 合计本次运行 | **346 passed / 0 failed** |

运行方式（`PYTHONPATH=src:.`）：

```
python3 -m pytest tests/integration/test_p2_dma_capabilities.py \
                 tests/composition/test_dma_transfer.py \
                 tests/integration/test_inprocess_dma_route_protocols.py -q
python3 -m pytest tests/integration/test_inprocess_f1f6_entry.py -q
```

## 7. 需要别人配合的地方

1. **索引行**（父代理统一插入 `docs/reports/README.md` 的 2026-11-02/03 分组表；
   本代理按并发纪律**没有**改那个文件）：

   `docs/reports/README.md` 现在用的是两列样式（`| 范围 | 入口 |`），所以这一行按
   那个样式写；请插在 2026-11-02/03 分组里（不要重排别人的行）：

   ```
   | wbdmac 真不同 DMA RTL 在统一入口 F6 跑通 4/8 字真实搬运；多通道/8 字节 beat/多 outstanding 按器件事实具名拒绝（深度 2 有实测失败证据）；ZipDMA 47 条既有 case 行逐字节不变 | [p2 DMA 报告](p2-dma-capabilities-new-device-20261103.md)、[证据](../../runs/p2-dma-20261103/README.md) |
   ```
2. **并发写同一颗树导致的运行级失败**：本包三次撞上别的代理正在编辑
   `scripts/inprocess_obi_apb_f1f4_spike.cpp` / `scripts/run_inprocess_f1f6.py`
   （`in-process link inputs changed during compilation`、一次 `SyntaxError`）。
   `campaign.log` 里逐段有 `(retry...)` 标注，交付块是重试后的结果。后续若还有人
   动宿主，建议先跑完自己的批次再改，或接受这种重试。
3. **AHB 目标（C）与 F6 的交集**：本包的 `dma_route` 复检没有被改动，所以 C 的
   AHB 目标若将来要接 F6 路由，需要在
   `scripts/run_inprocess_f1f6.py::dma_route_support` 里扩 `DMA_ROUTE_PROTOCOLS`，
   本包不动那一块。
4. **时钟（F）**：本包运行期间 `test_a_clock_rate_mismatch_...` 一例曾红过，属 F 的
   区域，最后一次运行已绿；与我改动无关（我只动 DMA/F6 段）。
