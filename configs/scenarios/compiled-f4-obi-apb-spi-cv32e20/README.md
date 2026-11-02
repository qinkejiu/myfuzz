# CV32E20 + PULP SPI

Configuration-only adaptation of the existing OBI CPU and APB storage executors.
Supports the declared F2 read and F4 write paths. The CV32E20 profile selects the physical OBI adapter; the peripheral retains its existing source-backed storage contract.

F5/F6 native IRQ/ISR/MRET proof is not declared for this CPU. Runtime and fresh evidence must be collected separately from preparation.

The descriptor uses the common scenarios root to reference the existing IP capability and execution supplement. The compose document references the existing peripheral request. F2 uses an explicit record because the descriptor loader only supports a fixed root/f2_read_records.json sidecar path.
