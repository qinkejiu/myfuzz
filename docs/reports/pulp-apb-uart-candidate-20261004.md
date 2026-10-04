# PULP APB UART source candidate (pending)

`pulp-platform/apb_uart` at commit `8182a85d234417db46fe833533f8536644d3bee3` is a distinct candidate. Its `apb_uart` top has 21 physical ports: clock/reset, eight APB3 fields, `INT`, four modem outputs, four modem inputs, and `SIN`/`SOUT`. `PADDR[2:0]` is a word address that the top shifts left by two, so the existing 12-bit byte-address APB adapter does not directly match this top.

The repository's `Bender.yml` selects `src/apb_uart.sv`, `src/apb_uart_wrap.sv`, and `src/reg_uart_wrap.sv`, and declares four external packages: `apb` 0.2.4, `obi` 0.1.7, `obi_peripherals` 0.1.1, and `register_interface` 0.3.6. The top instantiates `apb_to_obi` and `obi_uart` through those packages. A complete pinned HDL, package, and include closure has not been assembled or elaborated in this task. There is no `pulp_uart` source lock, profile, generated driver, peer, or operational claim here.

The separate PULP `apb_i2c` four-file source was selected for real APB3 serial acceptance instead.
