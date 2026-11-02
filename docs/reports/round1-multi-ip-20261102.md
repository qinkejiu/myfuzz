# 多 IP 地址路由：一个 CPU 访问两个真实 APB3 IP（2026-11-02）

状态：**已接入统一单进程执行器并通过真实 RTL 固定/连续批次**。不是混合协议、不是两个 F5 源、不是 DMA→IP 路由的证明。

## 声明与组装

场景 `configs/scenarios/inprocess-obi-apb-two-ip-timer-i2c-f1f6.json` 使用新增的 `targets` 列表：

| index | name | profile | window | F5 |
|---|---|---|---|---|
| 0 | timer | `configs/peripherals/pulp_timer_irq` | `0x40001000` + 4 KiB | 是（`irq_o[0]` pulse 16，status 0） |
| 1 | i2c | `configs/peripherals/pulp_i2c` | `0x40002000` + 4 KiB | 否（`interrupt_o` 只观察，scl/sda 固定 1） |

CPU：Ibex RVFI OBI；RAM `0x10000..0x30000`；ZipDMA 控制窗口 `0x40003000` + 16 B。声明层是 `src/myfuzz/composition/multi_target.py`（83 tests）：`declared_targets` 归一化新旧两种写法，`target_windows` 做全窗口/RAM/DMA 重叠检查，`route_address` 返回 `(index, offset)`，`target_for_f5` 只允许一个 F5 目标，两个就按 `unsupported-f5:multiple-target-irq-sources` 拒绝。

统一入口为每个 target 构建独立 artifact/模型；header 输出 `IP_COUNT`、`IP_MODEL_n`、`IP_BASE_n`、`IP_REQ_*_n`、`IP_TRACE_*_n`、`IP_HAS_F5_n`、`IP_HAS_IRQ_n`、`IP_FIXED_INPUTS_n` 和生成的 `IpTarget<n>` trait；`IP_COUNT==1` 时保留全部旧扁平宏，旧场景/日志不变。宿主用 `std::tuple<std::unique_ptr<IP_MODEL_n>...>` + `for_each_ip` 遍历，所有目标都时钟/复位/eval，只有被路由的目标收到 `req_valid`；case 行增加 `target_index`/`target<n>_*`，summary 增加每目标 totals 和 `delivered|observe_only|none`。

## 真实固定批次：6/6

```sh
python3 scripts/run_inprocess_f1f6.py \
  --config configs/scenarios/inprocess-obi-apb-two-ip-timer-i2c-f1f6.json \
  --cache runs/stage2-stepD2-cache --output runs/round1-multi-ip/fixed \
  --records 'F2:40001000,F4:40001008:0fffffff,F5:00000001:00000000:ffffffff,F2:40002008,F4:40002010:0000005a,F3:00014004:0badf00d'
```

| 例 | flow/record | target_index | 选中目标 reads/writes | 另一目标 |
|---|---|---|---|---|
| 0 | F2:40001000 | 0 | 1/0 | target1 0/0 |
| 1 | F4:40001008:0fffffff | 0 | 0/1 | target1 0/0 |
| 2 | F5:1:0:ffffffff | 0 | 1/3 | target1 0/0 |
| 3 | F2:40002008 | 1 | 1/0 | target0 0/0 |
| 4 | F4:40002010:0000005a | 1 | 0/1 | target0 0/0 |
| 5 | F3:00014004:0badf00d | -1（RAM） | 0/0 | 两者 0/0 |

F5：`isr_read_addr 0x40001000`、`irq_edges 1`、`irq_takes 1`、`isr_flag 1`、`wait_timeout 0`。summary：`ip_count 2`、`target0_irq delivered`、`target1_irq observe_only`、`failures 0`。

## 连续 fuzz 与换 IP

- `runs/round1-multi-ip/fuzz-30`：`--fuzz --cases 30 --seed 5`，30 执行、27 通过、3 个 F5 `not_triggered`（随机触发值未产生 timer 溢出），0 finding，correspondence 27/27；F1 7/F2 8/F3 2/F4 4/F5 6/F6 3；路由 target0 11、target1 4、RAM 15，无跨目标读写。
- `runs/round1-multi-ip/swapped-target1`：交换 target0/target1（timer 放到 0x40002000）后 5/5；F5 `irq_base`/`isr_read_addr` 自动变为 0x40002000，宿主源码没有 timer/i2c 名字分支。

## 回归

| 批次 | 结果 | 位置 |
|---|---|---|
| AXI4 CVA6 fixed F2–F4 | 3/3 | `runs/round1-multi-ip/axi4-regression` |
| IRQ 多 link timer | 7/7 | `runs/round1-multi-ip/irq-multilink` |
| GPIO 因果引脚 F5 | 3/3 | `runs/round1-multi-ip/gpio-cause` |
| 旧单目标 F1–F4 | 4/4 | `runs/round1-multi-ip/legacy-f1f4` |
| required pytest | 1123 passed | `tests/fuzz` + behavior + entry + multi_target |

旧单目标日志在去掉 wall-clock 字段后与先前保存行逐字节一致；`case_tick_budget` 现在真正传入 `render_bindings`（此前声明 12000/80000 但宿主仍是 4000）。

## 性能

- warm cache 固定 6.35 s（host 0.0054 s）；link rebuild 12.47 s；fuzz 30 12.49 s（host 0.0259 s）。
- AXI4 regression 19.16 s（含 adapter 重新 Verilate），IRQ multilink 12.52 s，GPIO 13.68 s。

## 限制

1. 目标协议必须相同；当前验证的是两个 APB3。混合 APB3+AXI4-Lite 按 `unsupported-targets:mixed-protocol` 拒绝；两个 AXI4-Lite 目标未运行、不声称。
2. 只允许一个 F5 目标（CPU 一根 IRQ 线，ISR 一组 status/result/clear cell）；第二个目标的 IRQ 可以观察但不交付。
3. 多目标 pin 模型按名拒绝；当前 pin 仍是单目标功能。
4. DMA 仍是 session-wide、RAM-only；没有 DMA→target 路由。
5. 一个 host tick 驱动所有模型；没有多时钟域建模。
