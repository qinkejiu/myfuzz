# CVW / AHB：为什么本轮仍不声称 RVFI 退休或 F5

日期：2026-11-02。范围：`configs/cpus/cvw/component_profile.json` 所声明的
CORE-V Wally（CVW）AHB-Lite CPU 边界。结论：**没有可用的退休观察，也没有在
该边界上导出的中断输入；F1/F5 继续按名拒绝，F6 也没有 AHB DMA master。**
这不是一次运行通过，而是对 pinned RTL 和已声明边界的证伪记录。

## 已声明的边界

`configs/cpus/cvw/cvw_ahb_cpu_top.sv` 是仓库自有的 typed top，只导出
`cvw_ahb_cpu_top` 的 AHB-Lite 端口（`HADDR/HWDATA/HWSTRB/HTRANS/HSIZE/HBURST/
HPROT/HWRITE/HMASTLOCK` 与 `HRDATAEXT/HREADYEXT/HRESPEXT` 及 `HSELEXT`），
外加 `clk/reset_ext`。profile 的 `port_actions` 对这些端口逐位处置；
`configs/soc/closures/cvw.json` 记录了这个边界的 elaboration。

## RTL 事实

- `third_party/cvw_upstream_reference/src/wally/wallypipelinedsoc.sv:31-66`
  的端口只有时钟/复位、AHB、`TIMECLK`、GPIO/UART/SPI/SDC/PWM；**没有
  `irq`/`MExtInt`/`MTimerInt` 输入，也没有退休/commit 输出。**
- 同一文件的 `:73-95` 显示 `MTimerInt/MSwInt/MExtInt/SExtInt` 是 **内部
  uncore/PLIC 驱动**的局部信号，`wallypipelinedcore` 的这四个中断输入由
  `uncore` 产生，不能从 SoC 端口注入。
- `third_party/cvw_upstream_reference/src/wally/wallypipelinedcore.sv:31-53`
  确实有 `MTimerInt, MExtInt, SExtInt, MSwInt` 输入，但这是 **core** 的端口，
  不是已声明的 `wallypipelinedsoc` 边界；`wallypipelinedcore` 也没有
  `rvfi_*`/commit 输出。它的 `PCM/InstrValidM/InstrM/RdM/RegWriteM/TrapM`
  是模块内部信号（`:63-93` 一带），不是端口。
- 上游的 RVVI 合成器 `src/rvvi/rvvisynth.sv:30-48` 需要
  `PCM, InstrValidM, InstrRawD, Mcycle, Minstret, TrapM, PrivilegeModeW,
  GPRWen/GPRAddr/GPRValue, FPRWen/... , CSRArray` 等 **core 内部**信号；
  它本身也不是已声明边界的一部分，`configs/cpus/cvw/component_profile.json`
  没有 RVVI 端点。
- 因此，仅靠现有 `cvw_ahb_cpu_top` 的端口无法构造退休记录；把
  `wallypipelinedcore` 的内部信号或 `rvvisynth` 接出来，只能通过修改 pinned
  CVW 源、替换一个 core 副本，或依赖未声明的层次化引用。这些都不是本轮
  “用一个真实、未修改的 pinned 边界”能声称的。

## 对 F1/F5/F6 的后果

- **F1**：AHB 边界没有退休/commit/trap witness。总线取指不是退休，ISR 的
  store 也不能证明某条指令退休；所以 `unsupported-f1:no-retirement-observation:
  ahb_cvw` 仍然成立。`rvvisynth` 的存在不改变这一点，除非把它接进边界并
  重新声明。
- **F5**：边界没有中断输入；即使内部 `wallypipelinedcore.MExtInt` 存在，
  已声明的 SoC 边界也不暴露它，宿主没有可驱动的线。因此
  `unsupported-f5:cpu-irq-unexported:ahb_cvw` 仍然成立；不能从 ISR 的
  内存副作用反推“CPU 接受了中断”。
- **F6**：统一入口的 AHB 分支没有 DMA master/控制端口；`dma_model` 在 AHB
  构建中被按名拒绝。DMA 的 RAM 读写需要在 AHB 上增加第二个 master/仲裁，
  本轮没有做。

## 如果要继续

需要一个新的、明确声明的 CVW 组合边界：导出 `MExtInt`/`MTimerInt`（并说明
PLIC/CLINT 由谁驱动），以及一个真实的退休/commit 或 RVVI 记录流（`rvvisynth`
或等价 monitor），并为该边界重新生成 profile/closure。那将是另一个 CPU 组合
的声明工作，不能沿用当前“pinned `cvw_ahb_cpu_top` + AHB only”的证据。

本文件只陈述上述 RTL/边界事实；没有覆盖率、证书或 replay 声明。
