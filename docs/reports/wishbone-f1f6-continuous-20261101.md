# PicoRV32 Wishbone 连续 F1–F6（2026-11-01）

状态：选定范围内的 Wishbone 六路径已固定通过并连续运行；不是所有 Wishbone CPU 的通用结论，也没有覆盖率/证书/完整 replay。

## 结论

- 固定六路径（Ibex 级别记录对应的 Wishbone 版本）：6/6 `observations_passed`，真实 IRQ 接受、DMA 4 读 4 写、ISR 读状态并清除。
- 连续 fuzz：120 例 seed 23 中 116 通过（3 个正常未触发、1 个跨例 level IRQ `state_contamination`）；80 例 seed 29 全部通过。55 次 IRQ 接受、196 次 DMA 读写；没有 host 崩溃。
- 第 11 例 tick 超限的根因是**预算不匹配**：F5 无触发时 256 轮等待 × 约 34 tick/轮 ≈ 8,700 tick，超过写死的 4,000 tick/case 守卫。不是设备挂死，也不是中断处理错误。
- 修正：`handler_wait_iterations` 与 `case_tick_budget` 都可声明；Wishbone six 用 64/12000。summary 的 `handler_wait` 报告两者。
- 换 APB IP：同一 Wishbone CPU + PULP I2C，60/60 F1–F4，只改声明，无 CPU×IP 代码。

## 证据

- `runs/stage2-wb-six-20261101/README.md`（详细逐例）
- `fixed-six/`、`fuzz-120b/`、`fuzz-80-seed29/`、`i2c-wb-60/`
- 旧失败对照：`runs/wb-generic-fuzz-test/`（无 summary，最后一行 `case exceeded its tick budget`）

## 支持边界

仅 PicoRV32 custom IRQ ABI（配置声明的 bit + 真实 EOI 端口）；没有 EOI/clear 的 level IRQ 可跨 case 再次交付，现按 `state_contamination` 记录；一个 Wishbone DMA、全字对齐、单通道；没有 RVFI 的 Wishbone CPU 不能沿用 F1 结论；F5/F6 其他设备行为仍需声明与验证。
