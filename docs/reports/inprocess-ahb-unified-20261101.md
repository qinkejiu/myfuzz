# CVW AHB-Lite CPU 接入统一循环：F2–F4 真实运行（2026-11-01）

状态：**已接入统一入口并通过 F2/F3/F4 固定与连续运行**；F1/F5/F6 按名拒绝。不是通用 AHB CPU 结论，也没有覆盖率/证书/replay。

## 结论

- 统一入口新增 `ahb` CPU 总线分支：生成物 `ahb_lite_cpu` 内部实例化 `ahb_lite_memory_target`，宿主驱动它的 `m_req_*`/`m_rsp_*` beat face，并用 CPU 的 manager-domain `HREADY`（aggregate，不是 `HREADYEXT`）、`HRESETn` 和地址相位 `HPROT[0]` 区分取指/数据。
- 固定批次：14/14 `observations_passed`（F2 6、F3 3、F4 5），AHB beats 118、真实取指 47；`retirement_evidence=missing`。
- 连续 fuzz：80/80 通过，0 finding，71 个反馈特征、39 条 corpus。连续 case 不重置 CPU/RAM；F2–F4 只改 RAM/邮箱数据，不改 trampoline 槽。
- F1 按名拒绝：`unsupported-f1:no-retirement-observation:ahb_cvw`。CVW 生成物没有 RVFI/commit 引脚；取指 beat 不是退休，不能冒充。
- F5 按名拒绝：`unsupported-f5:cpu-irq-unexported:ahb_cvw`（AHB 边界没有中断输入）；F6：`unsupported-f6:no-dma-model:APB`。

## 为什么 F1 不能做

`runs/stage2-ahb-unified-20261101/probe-cpu/artifact.json` 的 physical exports 只有 `manager_ready` 和 `bus_reset_n`；CVW wrapper/`wallypipelinedsoc` 没有导出 RVFI/commit。入口因此明确拒绝 F1，summary 的 `retirement_evidence` 保持 missing；F2–F4 的 case 行只报告真实总线/寄存器和 `fetch` 观察。

## 地址与身份

CVW 的 external-memory 窗口是 `0xC0000000..0xCFFFFFFF`；APB target 不能放 `0x40000000`，否则 `HSELEXT` 不成立。配置使用 RAM `0xC0000000 + 64 KiB`、APB timer `0xC8000000 + 4 KiB`。CVW 启动向量固定 `0xC0000000`。
取指/数据身份来自地址相位 `HTRANS/HSEL/HADDR/HWRITE/HPROT` 在 manager `HREADY` 时采样；未采到地址相位的首个 beat 仍被服务但计为 `ahb_unknown`/`ahb_unknown_reset`，不算取指。

## 指令缓存

CVW 保留指令缓存。本批只运行 F2–F4：固件代码在 boot 后固定，case 只改 RAM 参数/邮箱，不改程序槽，因此不需要缓存失效；报告不声称 F1 的在线改码或 fence.i 一致性与统一入口已解决。

## 环境注意事项

CVW 的 source-lock elaboration 使用 `run_supervised_command`。在本机 bwrap PID namespace 中 `os.getpgrp()` 为 0，会以 `cannot verify the parent process group`/`startup-error` 失败；在 `setsid` 下运行入口后 pgid==pid>0，CVW 构建/建模成功。这不是树上的代码改动。

## 运行

```sh
setsid python3 scripts/run_inprocess_f1f6.py \
  --config configs/scenarios/inprocess-ahb-cvw-apb-timer-f1f4.json \
  --cache runs/stage2-ahb-unified-20261101/cache \
  --output runs/stage2-ahb-unified-20261101/fixed-f2f4 \
  --records 'F2:c8000000,...,F3:c0004000:0badf00d,F4:c8000008:0fffffff'
```

（实际命令/记录见 `runs/stage2-ahb-unified-20261101` 与入口 JSON；连续批次 `--fuzz --cases 80`。）

## 限制

- 只支持这一个 CVW 配置和它的 AHB-Lite manager；没有其他 AHB CPU 的普适性。
- 没有 F1（无退休）、F5（无 IRQ）、F6（无 DMA）。
- 只有一个 outstanding beat；无 burst、无第二个 target 窗口；无 AXI/AHB 目标适配。
- `retirement_evidence=missing` 是真实状态，不是通过。
- 归档/生成的 source identity 以本次构建为准；未做独立 replay。
