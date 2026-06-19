# 候选组件项目检查：RVX / CV32E40P / CORE-V MCU / PULP

生成时间：2026-06-17

本文记录本地浅克隆并检查的几个候选项目，用于判断它们是否适合“没有固定 XSTop/TestHarness，由我们自己写 scheme5 multi-component harness”的研究路线。

## 1. 本地源码位置

```text
/home/qinkejiu/test/myfuzz/external_designs/rvx
/home/qinkejiu/test/myfuzz/external_designs/cv32e40p
/home/qinkejiu/test/myfuzz/external_designs/core-v-mcu
/home/qinkejiu/test/myfuzz/external_designs/pulpissimo
/home/qinkejiu/test/myfuzz/external_designs/pulp
```

当前浅克隆 commit：

| 项目 | Commit |
|---|---|
| RVX | `38bdee0` |
| CV32E40P | `6033d2b` |
| CORE-V MCU | `254f12c` |
| PULPissimo | `bfc3d9a` |
| PULP | `b6ae547` |

## 2. 总体判断

| 项目 | 类型 | 是否有固定 top | 是否有 CPU + 多 IP | 是否适合自定义 scheme5 harness | 结论 |
|---|---|---:|---:|---:|---|
| RVX | 小型 RISC-V MCU IP | 有 `rvx` top，但很小且组件清晰 | 是 | 高 | 最适合优先研究 |
| CV32E40P | 工业级 RISC-V CPU core | 只有 example TB，不是 SoC top | 否，主要是 CPU | 中高 | 适合作为 CPU core，与外部 IP 组合 |
| CORE-V MCU | MCU SoC | 有 `core_v_mcu` top 和 TB | 是 | 中 | IP 很丰富，但已有完整 SoC 封装 |
| PULPissimo | 单核 SoC top-level project | 有 `pulpissimo` / `soc_domain` | 是 | 中低 | 更像已有 SoC，适合拆 IP，不是首选 |
| PULP | 多核/cluster SoC | 有 `pulp` / `soc_domain` | 是 | 中低 | 复杂系统项目，后期再看 |

## 3. RVX 详细判断

RVX 的硬件目录非常清楚：

```text
hardware/rvx.v
hardware/rvx_core.v
hardware/rvx_bus.v
hardware/rvx_ram.v
hardware/rvx_uart.v
hardware/rvx_mtimer.v
hardware/rvx_gpio.v
hardware/rvx_spi.v
```

`rvx.v` 是一个小型 MCU top，已经把 CPU、bus、RAM、UART、timer、GPIO、SPI 接起来。

连接结构大致是：

```text
rvx
  +-- rvx_core
  +-- rvx_bus
  +-- rvx_ram
  +-- rvx_uart
  +-- rvx_mtimer
  +-- rvx_gpio
  +-- rvx_spi
```

地址映射写在 `rvx.v`：

```text
RAM    : 0x0000_0000
UART   : 0x8000_0000
MTIMER : 0x8001_0000
GPIO   : 0x8002_0000
SPI    : 0x8003_0000
```

关键文件：

```text
/home/qinkejiu/test/myfuzz/external_designs/rvx/hardware/rvx.v
```

### 3.1 为什么 RVX 适合

RVX 虽然有 `rvx` top，但这个 top 很简单，且每个组件是独立 Verilog module。

这很适合方案五：

```text
baseline:
  对 rvx top 外部 pins 或各子模块输入随机打 bit

scheme5:
  raw bits -> 自定义 scenario -> core/bus/ram/uart/timer/gpio/spi 协调输入
```

可以选择两种用法：

```text
1. 直接用 rvx top 作为 DUT，方案五主要驱动 uart_rx/gpio_input/poci/halt/reset 等外部环境；
2. 不用 rvx.v，自己写 scheme5_rvx_custom_top，把 rvx_core、rvx_bus、rvx_ram、rvx_uart、rvx_mtimer、rvx_gpio、rvx_spi 重新接起来。
```

第二种更符合用户目标，因为它能体现“我们自己写多组件 harness”。

## 4. CV32E40P 详细判断

CV32E40P 本地结构：

```text
rtl/
example_tb/
docs/
bhv/
sva/
```

它主要是 CPU core，不是 CPU + 多 IP 集合。

适合这样组合：

```text
cv32e40p core
  + custom bus/memory model
  + timer
  + UART/SPI/GPIO from RVX/OpenTitan/PULP/IP library
  + interrupt controller
```

优点：

```text
CPU core 质量更高
OpenHW/PULP 生态成熟
适合严肃 CPU-level experiment
```

缺点：

```text
需要额外 IP 才能形成多组件系统。
```

## 5. CORE-V MCU 详细判断

CORE-V MCU 目录中有大量可拆 IP：

```text
rtl/udma/udma_uart
rtl/udma/udma_i2c
rtl/udma/udma_qspi
rtl/apb_timer_unit
rtl/apb_gpio
rtl/apb_adv_timer
rtl/apb_node
rtl/vendor/openhwgroup_cv32e40p
rtl/vendor/pulp_platform_axi
rtl/core-v-mcu/soc
rtl/core-v-mcu/top
```

它也有完整 top：

```text
rtl/core-v-mcu/top/core_v_mcu.sv
tb/core_v_mcu_tb.sv
rtl/simulation/top.sv
```

因此它不是“没有统一 top”的项目。

但它非常适合拆 IP：

```text
cv32e40p
APB GPIO
APB timer
uDMA UART/I2C/QSPI
AXI/APB components
debug module
```

用于后续自定义 scheme5 top。

## 6. PULPissimo / PULP 判断

PULPissimo 有：

```text
hw/pulpissimo.sv
hw/soc_domain.sv
target/sim/tb
target/fpga/*
```

PULP 有：

```text
rtl/pulp/pulp.sv
rtl/pulp/soc_domain.sv
rtl/tb
fpga/*
```

所以它们都是已有 SoC/top-level project。

适合后续做：

```text
已有 SoC top 的方案五环境模型
```

但不适合作为第一批“没有固定 top、自己组多组件 harness”的目标。

## 7. 推荐优先级

按当前研究目标排序：

```text
1. RVX
   - 最快进入 CPU + bus + RAM + UART/timer/GPIO/SPI 多组件实验。

2. CV32E40P + RVX/OpenTitan/CORE-V MCU/PULP IP
   - 更严肃的 CPU core，适合后续替换 RVX core。

3. CORE-V MCU 拆 IP
   - IP 丰富，但已有完整 MCU top，工程复杂度更高。

4. PULPissimo / PULP
   - 更像已有 SoC，后期再做。
```

建议下一步先做：

```text
scheme5_rvx_custom_top
  + rvx_core
  + rvx_bus
  + rvx_ram
  + rvx_uart
  + rvx_mtimer
  + rvx_gpio
  + rvx_spi
```

并设计两种对照：

```text
baseline:
  对 custom top 的外部 pins / scenario bits 做低层随机

scheme5:
  raw bits -> bus transaction / UART frame / SPI peripheral / timer interrupt / GPIO pattern
```
