# 扩展总线适配：TL-UL / AXI4-Lite / AHB-Lite IP 目标（2026-10-31）

范围：在 APB3、Wishbone 之外，为 **IP 目标侧**增加三种总线的一次性适配；CPU 侧六颗目标 CPU 的评估单独列在第 5 节。宿主仍只负责传输与观察，不判定 DUT 内部正确性。

## 1. 共享接缝（每总线一次，不按 CPU×IP 组合）

- `src/myfuzz/integration/extension_plugins.py`：按 artifact kind 选择目标/CPU 扩展模块，缺失即“未适配”，不伪造。
- `compiled_mmio._target_adapter` 与 `mmio_cpu_adapter.select_mmio_cpu`：先询问扩展模块，再走内置 APB/WB/OBI/WB/AHB/AXI-Lite。
- `runtime/compiler.py`：新增 `tlul.mmio.v1`、`axi4lite.mmio.v1`、`ahb-lite.mmio.v1` 三种 target expectation。
- `runtime/registry.py`：登记三种 target adapter（模板、能力、completion）。
- `runtime/admission.py`：新增扩展 target 的源码/角色校验；已验证的 target `address_width` 改为 **窗口相对宽度**（`log2(window_size)`），与 path 的 `_target_address_width` 同域。
- `runtime/binding.py` + `runtime/adapters/extended_mmio.py`：三种 target 的 bound adapter，session 类型/语义契约必须匹配。
- `runtime/flows/mmio.py`：join 的原生 sample 名从“只认 APB/Wishbone”改为按 `native_{apb,wishbone,axi4lite,ahb,tlul}_*` 选择，仍要求恰好一对 request/response。

## 2. AXI4-Lite 目标：真实 RTL 通过（F2/F4）

- 模块：`src/myfuzz/integration/target_axi4lite.py`（`target_adapter`/bank/observer）。
- IP：`configs/peripherals/zipcpu_axiluart`，寄存器 `SETUP` offset 0，`rw`，mask `0x7fffffff`，`write_policy=full_word_reserved_zero`，bit31 不存储。
- 描述符：`configs/scenarios/compiled-f2-f4-axil-axiluart-picorv32/`，CPU `picorv32_axi`（AXI4-Lite），F2 记录 `00100040`，F4 记录 `55000000/2a000000/34120000`。
- 远程真实 RTL（`/root/fanzehui/myfuzz-profile-batch22-20261030/runs/axil-uart-target`）：6 例（F4/F2×3）original exit 0、75.7 s；独立新进程 fresh `replay_matches=true`、81.3 s；无 protocol violation。
- 本地同 worktree 也完成 original 29.5 s + fresh 30.3 s（`runs/picorv32-axil-axi4lite-uart-20261030`，6 例；注意该组合只声明 F2/F4，无 F1/F3）。

## 3. AHB-Lite 目标：真实 RTL 通过（F2）

- 模块：`src/myfuzz/integration/target_ahb_lite.py`。
- IP：`configs/peripherals/caliptra_sha256`，寄存器 `NAME0` offset 0，`ro`，RTL 常量 `0x61327368`。
- 描述符：`configs/scenarios/compiled-f2-ahb-sha256-mmio/`，CPU `cv32e20`（OBI），F2 记录 `00000040`。
- 远程真实 RTL（`runs/remote-batch22-20261031b/ahb-sha-target`）：1 例 F2 original 65.1 s、fresh 55.7 s `matches=true`；本地 original 30.3 s + fresh 30.3 s（`runs/cvw-ahb-ahb-sha-20261031`）。
- **F4 缺口（明确）**：该 profile 没有 32 位读写寄存器（`CTRL`/`BLOCK*` 为 wo，读回 0），现有 F4 需要写后读回同一字，因此只声明 F2；不伪造 F4。

## 4. TL-UL 目标：真实 RTL 通过（F2/F4）

- 模块：`src/myfuzz/integration/target_tlul.py` + `src/myfuzz/scenario/target_bus_pins.py`（把 target mmio endpoint 的 A/D 输入识别为“已声明总线 pin”，生成 `external_pin_paths`，不塞进 prepared graph；无 pin 时缺省空列表）。
- 描述符：`configs/scenarios/compiled-f2-f4-obi-tlul-gpio/`（Ibex OBI → OpenTitan GPIO，`INTR_ENABLE` rw，0x40000000，128B）。
- 运行结果：本机 full F4/F2 ×3 共 6 例 original 48.5 s + fresh 48.6 s 匹配（`runs/ibex-obi-tlul-gpio-20261031`）；远程同一快照 90.4 s + fresh 95.4 s 匹配（`runs/remote-batch22-20261031b/tlul-gpio-run`、`tlul-gpio-target`）。早期 2 例 F2/F4 子集证据在 `runs/ibex-obi-tlul-gpio-f2f4-20261031`（无 fresh，仅作最小验证）。
- 关键限制：F4 候选 layout 为 **18 字节**（4 字节寄存器流 + 10 个目标总线 pin 的 fuzzable 切片），`compiled_mmio` 忽略 pin 值；RTL 的 A/D 通道由 target session 的 `write_register/read_register` 经 `beat_to_tlul` 内部驱动。长期应由 D3 不再把这些已适配总线输入当 entropy。
- 回归：无 pin 的 APB/WB/AXI4-Lite/AHB-Lite 目标不受影响（`external_pin_paths` 缺省空）。

## 5. 六颗 CPU 的现状

| CPU | 协议 | 状态 |
|---|---|---|
| Ibex | OBI | 已适配，F1–F4 真实通过（含 fresh） |
| CVW（RV32 AHB-Lite 配置） | AHB-Lite | 已适配，F1–F4 真实通过（含 fresh；64 字节取指粒度） |
| CV32E40P | OBI | 已适配，F1–F4 真实通过（远程 6 例、fresh 匹配） |
| PicoRV32 WB / AXI4-Lite | Wishbone / AXI4-Lite | 已适配，F1–F4 真实通过 |
| VexiiRiscv | AXI4（受限双通道，非 Lite） | **已适配且真实通过 F1–F4**：wrapper `cpu_axi4.SESSION_WRAPPERS` → `GeneratedVexiiAxiMmioSession`；F2/F4 见 descriptor `configs/scenarios/compiled-f2-f4-axi4-apb-i2c-vexii/`（`runs/vexii-axi4-apb-i2c-20261031`），F1–F4 见 descriptor `configs/scenarios/compiled-f1-f4-axi4-apb-i2c-vexii/`（`runs/vexii-f1f4-20261031`），均 6 例 + fresh 匹配 |
| ZipCPU ZipAXI | AXI4（非 Lite，i/d 双口） | **未接入**：session 无每拍 AXI4 观测，需新写 AXI4 observer（burst/WLAST/ID）+ router/slot/park |
| CVA6 | AXI4（64 位 packed） | **F1–F4 已真实通过（走通用 `compiled_mmio`）**：`runs/cva6-f1f4-20261031` 6+6 + fresh（descriptor `configs/scenarios/compiled-f1-f4-axi4-apb-i2c-cva6/`；`campaign.json` bound adapters = `['apb3.mmio.v1','cva6.axi4.cpu.v1']`）；取指身份为 ARID/RID 声明（`instruction_id_map {arid:0,rid:0,granule:8,rsize:3}`），F3/F1 为 `submitted`、F4/F2 joins=2/1、hops=6 |
| BOOM | TileLink coherent | **Phase A 完成但未准入**：harness 生成 + 真 RTL `verilator --lint-only` exit 0 无 warning（`runs/boom-tl-harness-lint/`，`source_verification=null`）；拒绝点前移为 `component-render-refused` ← `local-source-lock-missing-component:boom`；F2/F4 仍只有 `directed_standard_runner_router` 各 6 例 + fresh（`compiled_mmio_admitted=false`）；剩余 Phase B 约 850–1120 行 |

详见 [完整 AXI4 CPU 可行性](full-axi4-cpu-f1-f4-feasibility-20261031.md)；BOOM 的通用执行器拒绝证据与 directed F2/F4 结果见该文末「同日后续」。

## 5.1 VexiiRiscv（完整 AXI4 CPU）：F2/F4 已真实通过（F1–F4 见 §5.2）

- wrapper、`cpu_axi4` adapter、descriptor 和 plan 接线完成（55 项单测）。
- 真实运行根因（已修复）：`configs/cpus/vexiiriscv/generated/manifest.json` 只声明 RAM `0x80000000+0x100000` 与 I/O `0x40000000+0x1000`；原 descriptor 把 I2C 放在 `0x40001000`（region 外），核心在发出任何 AXI 拍之前 fault，表现为 i 面 9 次取指后停住、d 面 256 拍全 0。改为 `0x40000000` 后恢复正常。
- **真实结果（`runs/vexii-axi4-apb-i2c-20261031`）**：descriptor `configs/scenarios/compiled-f2-f4-axi4-apb-i2c-vexii/`（PULP I2C `PRESCALER`），6 例 F4/F2 交替；original `observed`、`wall_seconds=33.65`，独立新进程 fresh `replay_matches=true`、`wall_seconds=36.98`。F4 依次写 `0x55`/`0xaa`/`0x1234` 并读回相同值（`read_value`=85/170/4660），F2 依次读回同一寄存器（85/170/4660），`result = read_value ^ 0x5a5`（1520/1295/6033）；每例 F4 joins=2、F2 joins=1，park 边界正常触发。
- 早先 `--mode fresh` 因 `reduced_axi_source_operation.content_digest` 含每次运行随机 execution nonce 而不匹配，现已在 `compiled_f6._normalized_f6_prefix` 中按进程本地身份归一化，fresh 通过。
- ZipAXI/CVA6/BOOM 分级不变。

## 5.2 VexiiRiscv 的 F1–F4（内存流）：已真实通过

- **代码**：`src/myfuzz/local_harness/vexii_axi_mmio_session.py` 现接受并实现 `memory_commit_receipts` / `memory_readback_receipts` / `physical_tick_samples`（`self.service` 换成带 commit stream 与 readback authority 的 `MemoryService`），并在 `identity_document()` 声明 `memory_commit_stream` / `memory_read_issuance` / `cpu_physical_tick_stream`；执行器侧接线在 `src/myfuzz/runtime/adapters/axi4_cpu.py` 与 `src/myfuzz/runtime/flows/memory.py`；新增测试 `tests/local_harness/test_vexii_memory_flows.py`（13 passed）。
- **descriptor**：`configs/scenarios/compiled-f1-f4-axi4-apb-i2c-vexii/`，`flow_ids=['F1','F2','F3','F4']`、`executors` 全为 `compiled_mmio`、`rounds=256`；记录顺序 `F3:55000000`、`F1:03200000`、`F4:55000000`、`F2:00000040`、`F4:aa000000`、`F2:00000040`。
- **真实结果（`runs/vexii-f1f4-20261031/{original,fresh}`）**：各 6 例；original `wall_seconds=31.6`、fresh `wall_seconds=35.92`，`replay_matches=true`，两进程 `returncode=0`。
- **逐例**：F3/F1 为 `submitted`（这是既有语义——F1/F3 以提交记录 + 内存事件为证据，不产生 join 证书；Ibex 基线 `runs/ibex-obi-apb-i2c-20261030` 的 F3/F1 同为 `submitted`），F4 `observed`、joins=2，F2 `observed`、joins=1。
- **事件层（`original/events.json`）**：`instruction_source` 6、`memory_read` 61、`memory_write` 5、`mmio_delivery` 6、`mmio_acceptance` 6，无 protocol violation；与 Ibex 基线逐项相同。
- 早先的 F2/F4 记录（§5.1）保留为独立证据；`flow_ids=['F2','F4']` 的 descriptor 仍可单独使用，但 Vexii 的验收口径以本节的 F1–F4 为准。

## 6. 测试

```sh
PYTHONPATH=src:. python3 -m pytest \
  tests/integration/test_target_axi4lite.py \
  tests/integration/test_target_ahb_lite.py \
  tests/integration/test_target_tlul.py \
  tests/runtime/test_fragment_boundary_park.py \
  tests/scenario/test_park_wait_budget.py -q
# 78 passed
```

另：`tests/integration/test_cpu_axi4.py` 27 passed（合成数据）；全部新增适配均未修改既有 APB/WB 行为，原 F1–F4 组合回归通过。

## 7. unknown 与边界

- TL-UL 真实运行已通过（F2/F4，6 例 + fresh，`runs/ibex-obi-tlul-gpio-20261031`），但该组合只声明 F2/F4，无 F1/F3 记录。
- VexiiRiscv 的 F1–F4 已真实通过（`runs/vexii-f1f4-20261031`，6 例 + fresh，§5.2）；F1/F3 的证书状态是 `submitted`（以提交记录 + 内存事件为证据，不产生 join），**不是** observed/verified 级 join 证书。
- AHB SHA 的 F4 不可用（无 rw 寄存器）；只证明 F2。
- AXI4-Lite UART 的 `BRESP/RRESP` 在 RTL 中恒为 OKAY；非 OKAY 仅合成单测覆盖。
- CVA6 的 F1–F4 已通过（`runs/cva6-f1f4-20261031`），但取指身份是 ARID/RID **声明**且只对当前 pinned WT 配置成立：AMO 的 `ar.id[1]` 不作取指 hop，48 字节片段第 9–12 字无权威快照（`not-in-declared-window`），`retirement`/内部版本/跨例来源仍 unknown。BOOM 的 F2/F4 走 `directed_standard_runner_router`（`compiled_mmio_admitted=false`），Phase A 仅生成 + lint（`source_verification=null`），不是通用执行器准入。
- 退休、RAM 版本、跨例来源、IP 内部状态和副作用仍未知；DUT 断言未编译（无 `--assert`）。
- CPU×IP 组合仍无专用代码：三种 target 的适配均按目标 artifact kind 选择，与 CPU 总线无关。
