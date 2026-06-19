# RTL Work Area

This directory will hold the first local smoke target:

```text
sources.f
multicomponent_cpu_ip_top.sv
toy_cpu.sv
toy_bus.sv
toy_ram.sv
toy_timer.sv
toy_gpio.sv
toy_uart.sv
toy_spi.sv
```

Keep this stage small. The purpose is to validate the baseline-vs-dependency
comparison mechanics before replacing the toy modules with RVX or other real
components.
