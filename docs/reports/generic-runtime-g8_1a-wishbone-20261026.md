# 通用运行框架 G8.1a：Wishbone storage source 与目标传输切片

本报告只记录 G8.1 的**第一片**（source + 真实 Wishbone target 传输）。它不是
G8.1 PASS，也不关闭 G8.2–G8.10、F5/F6/DMA 或 P7-E。完整 scope、候选比较和
阻塞见 `runs/generic-runtime/G8/G8.1-SCOPE.md` 与三份只读 survey。

## 状态

| 项 | 结论 |
|---|---|
| source 决策 | 采用 **WBUART `SETUP` @ word index 0**（用户选择 A），只声明该 32 位字的稳定存储；UART RX/TX/FIFO/IRQ/serial 明确不声明 |
| source contract | `zipcpu-wbuart.setup.storage.v1`，digest `3dc8b5e2…f088`；pinned `wbuart` revision + 4 个精确文件字节 |
| profile/capability | `configs/peripherals/zipcpu_uart_storage/`；复用 `zipcpu_uart` source lock/closure，fingerprint `sha256:ca28aba0…` |
| 真实 target | **1 passed**（`MYFUZZ_SCENARIO_REAL=1`）：SETUP 写 `0x55` 后读回 `0x55`，2 笔事务、2 个 `reg_target_stb` pre 样本、fresh replay 匹配 |
| 软件 source 测试 | **64 passed**：source bytes/profile/endpoint/capability/address/register 漂移、错误寄存器、tamper、symlink、word index |
| 真实 CPU→target | **2 passed**：单例 write/read；以及同一 target session 上 3 次持久写 `0x55/0xaa/0x12345678` + 读回 + CPU 存 RAM，第二次运行新 PID/session 复现。仍不是 generic F4 plan/consumer |
| D3 计划 | Wishbone F4/F2 已 `executable`（artifact `wishbone_register_observe` + `wishbone_cpu`） |
| G8.1 完整门 | **未 PASS**：D4 仍拒绝 `compiled-F4-CPU-protocol-unsupported` / `register-word-shape:`；无 Wishbone adapter/consumer/executor、无 CPU→target 持久/fresh |

## 门

```bash
# 软件门：77 passed, 2 skipped, 26 subtests passed (skip 不计通过)
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m pytest -q \
  tests/local_harness/test_wishbone_storage_source_contract.py \
  tests/local_harness/test_wishbone_storage_real.py \
  tests/local_harness/test_wishbone_cpu.py tests/local_harness/test_wishbone_cpu_irq.py \
  tests/local_harness/test_runtime_template_identity.py \
  tests/local_harness/test_generic_wishbone_register_real.py

# 真实 SETUP target：1 passed (21.76s, exit 0)
MYFUZZ_SCENARIO_REAL=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. \
  python3 -m pytest -q tests/local_harness/test_wishbone_storage_real.py
```

日志：`runs/generic-runtime/G8/wishbone-software-gate.log`、
`runs/generic-runtime/G8/wishbone-setup-real.log`；报告：
`runs/generic-runtime/G8/G8.1a-report.json`。

## 新增 source facts

`third_party/soc-zipcpu-wbuart/rtl/wbuart.v`（sha256 `9733247c…1ce9`）：

- `i_wb_addr[1:0]` 是 **word index**，`UART_SETUP=2'b00`；窗口 16 B；无 byte-offset 位。
- `uart_setup[30:0]` 只在 `i_wb_stb && i_wb_addr==SETUP && i_wb_we` 时按
  `i_wb_sel[0..3]` 逐字节写入；bit31 从不存储，读回 `{1'b0, uart_setup}`。
- 读为延迟地址 `r_wb_addr` 的寄存 mux，读 SETUP 无副作用。
- `o_wb_stall=0`；无 `err` 引脚；ACK 在 T+2，CYC 必须保持到 ACK 周期。
- 写入 SETUP 会重置 UART RX/TX 状态（`wbuart.v:284,406`）；source contract 的
  `storage_scope` 明确只声明 SETUP 字值，UART 行为不声明。

## 计划/场景

- profile：`configs/peripherals/zipcpu_uart_storage/component_profile.json`
  （`component_id=zipcpu_uart`，capability token 带 `address_units=word`）。
- capability：`configs/peripherals/zipcpu_uart_storage/test_capability.json`
  （只列 SETUP，`write_resets_uart_state`，reset 25，read/write mask `0x7fffffff`）。
- scenario：`configs/scenarios/compiled-f4-obi-wb-uart-setup/`；CPU
  `picorv32_wb`（`cpu.wishbone/no-err-stall`），target `uart.bus`，base
  `0x60000000`，size 16；fixed `rx=1`、`cts_n=0`。
- 为了让 classic Wishbone CPU 的模板选择不含糊，给 `picorv32_wb` /
  `picorv32_wb_irq` 的能力块加了声明 token `address_units: "byte"`；source
  identity 未变。这是接口/profile 修正，不是 source 改名。

D3 prepare（`runs/generic-runtime/G8/scratch-wb/prep4/`）已产出：

```
F4 executable F4:ram.image  sources: instruction_image, cpu_mmio_stream SETUP
F2 executable F2:ram.image  sources: instruction_image, cpu_load_stream SETUP
artifact peripheral kind=wishbone_register_observe
artifact processor  kind=wishbone_cpu
```

## G8.1b 软件层（已接线，未 native 计划）

- Probe：`wishbone_storage_probe_contract.py` / `..._verification.py`；renderer 在
  `wishbone_register_observe` 上生成 `wishbone_storage_probe.v1` 11 个端口；
  probe 保持 prospective，hierarchy/native 全 false。
- Evidence：`WishboneStorageRegisterVersionAuthority`（process-local single-use）、
  `generated_wishbone_storage_consumer.py`（CPU accept→Router→native pre/post/ACK→
  token→RAM）。
- Adapter：`runtime/adapters/wishbone_storage.py`、`wishbone_cpu.py`；
  registry 新增 `wishbone.storage.v1`、`wishbone.cpu.v1`，binding factory、
  admission verifier（`wishbone_register_observe`/`wishbone_cpu`）和
  `(role, protocol)` keyed compiler expectation 已接线。
- Tests：renderer **15 passed**；source contract **64 passed**；admission **24
  passed**；plan compiler **22 passed**；transport real 单例 1 + 持久/fresh 1；
  probe/version/consumer/adapter/registry/compiler 合并软件门 **383 passed**
  （`runs/generic-runtime/G8/G8.1b-software-gate.log`，208.53s）。

剩余阻塞（因此仍 NOT_PASS）：

1. 没有 Wishbone F4 producer row/executor：`compiled-F4` 仍以
   `compiled-F4-CPU-protocol-unsupported` 拒绝，无法生成 generic plan/3-case。
2. authority 目前要求精确 `GeneratedWishboneRegisterSession` 类；要 mint
   routed context 的 subclass/hook 需要 lead 批准的 sibling 规则。
3. consumer 要求 completion ACK sample 与请求同一 producer event id；B 的
   provider/session 采样形状需确认。
4. consumer 要求 `candidate.access.word_index`；producer row 尚未发出。
5. 没有 producer-fed authority journal 和 committed Wishbone hierarchy/native
   proof；authority 在真实 producer 前拒绝 issuance。
6. 无 saved bundle、无 generic persistent/fresh、无 G8.1 PASS。

## 并行子代理结果

| 子代理 | 产物 | 实际测试 |
|---|---|---|
| A：probe/authority/consumer | `wishbone_storage_probe_contract.py`、`..._verification.py`、`scenario/wishbone_storage_register_version.py`、`integration/generated_wishbone_storage_consumer.py` | **213 passed**（probe 31、version 50、consumer 68、source 64） |
| B：adapters | `runtime/adapters/wishbone_storage.py`、`wishbone_cpu.py` | **81 passed**（37 storage adapter、19 CPU adapter、25 原有 APB provider） |
| C：renderer/tuning | `runtime_renderer.py`、`wishbone_register_template.py`、`tuning.py`、scenario request | **15 passed**（probe generation）；Wishbone register real 2 passed/1 skipped |
| Lead 集成 | registry 4 rows、binding factories、admission verifiers、compiler keyed expectation、unified master dedup | registry **28 passed**、admission **24 passed**、plan compiler **22 passed** |

证据报告：`agent-probe-consumer.md`、`agent-adapters.md`、`agent-renderer.md`。

阻塞 native 的关键点（子代理明确列出）：

1. `native_reset_producer_contract` 只 seal GPIO/APB 类，
   `check_producer()` 对真实 `GeneratedWishboneRegisterSession` 直接拒绝；session 的
   native command 也只 dispatch APB issuer。
2. 没有 `generic_wishbone_storage_abi` producer row/binding/build/executor；
   `compiled-F4` 仍拒绝。
3. authority 目前只接受精确 `GeneratedWishboneRegisterSession` 类；要 mint
   routed context 的 subclass/hook 需要 lead 批准的 sibling 规则。
4. consumer 要求 completion ACK sample 与请求同一 `producer_event_id`；
   producer 尚未接出该采样。
5. declaration 需新增 `candidate.access.word_index`。
6. 没有 producer-fed authority journal 和 committed Wishbone hierarchy/native
   proof；无 saved bundle。

## 明确未做 / 未声明

- 没有 Wishbone `storage adapter`、probe、consumer、version authority、executor；
  `create_compiled_execution` 仍只有 `compiled_f4_obi_apb`/`compiled_f2_obi_apb`。
- 没有 CPU→target 真实持久/fresh；target-only test 与单例 CPU→target transport test 都不等于 G6 持久门。CPU→target 日志：`runs/generic-runtime/G8/wishbone-cpu-to-setup-real.log`（1 passed, 24.98s）。
- 没有改 `runtime/engine.py`、`compiler.py`、registry 匹配、APB3 adapter、
  storage kernel 或 saved schema。
- 不支持：`sel != 4'b1111`、STALL、ERR/RTY、bursts/CTI/BTE、outstanding>1、
  FIFO_STATUS/RXREG/TXREG、UART serial/IRQ、ZipCPU Wishbone master、addressless
  target、G8.2–G8.10、F5/F6/DMA。
- 未提交、未 reset/clean；G6/G7 归档保持原样。

## 共享 core 变动（已声明）

- `src/myfuzz/runtime/admission.py:_operations_of` 增加 Wishbone write 派生：
  `{stb,we,dat_w}` 也产生 `write`，不再把 Wishbone target 静默降成只读。APB/OBI
  分支未改；该文件是 verifier pin 的一部分，因此新编译计划会得到新的 verifier
  identity。G6/G7 归档计划/bundle 不重写、不 re-baseline；变更后重新跑
  `test_generic_storage_gpio_native.py` + `test_generic_storage_native.py`：
  **17 passed**。
- CPU profile 的 `picorv32_wb`/`picorv32_wb_irq` 增加 `address_units: "byte"`
  声明 token；source identity 未变，Wishbone CPU 回归门通过。

## 下一步

1. 先修两个共享派生 bug：`admission.py` CPU `address_units` 必须读取声明值；
   `_operations_of` 必须从 `{stb,we,dat_w}` 派生 write，而不是静默只读。
2. Wishbone source/probe/verification/version authority/consumer sibling 模块。
3. registry/binding/admission/compiler 的 Wishbone 分支与 keyed expectation；
   声明新 kernel/verifier identity 和 G6/G7 plan 的 drift。
4. producer row/executor + 真实 CPU→target 3 例持久/fresh；只有那时才能声称
   G8.1 PASS。
