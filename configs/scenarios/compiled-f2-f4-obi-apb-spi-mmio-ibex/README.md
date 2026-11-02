# PULP SPI through the common APB MMIO executor

This configuration selects the existing SPI profile and its APB `spi.bus`
endpoint without the optional SPICMD internal-storage observation. The
declared target is the 32-bit SPICMD register at offset 8; the pinned RTL
`spi_master_apb_if.sv` writes PWDATA to `spi_cmd` and reads that value back.
The four input pads are held low. These cases do not start a serial transfer.

The Ibex OBI and PicoRV32 AXI4-Lite scenarios share the same target request,
capability and `compiled_mmio` executor. Their CPU requests are reused from
the existing I2C scenarios. F2/F4 report actual bus transport; they do not
establish internal version ownership, cross-case attribution or rewards.
The other four flows are not declared. Static preparation is not a native
execution result.

With the source tree frozen, run each case root sequentially using a single
build worker. For example, for either scenario directory `D`:

```sh
PYTHONPATH=src:. MYFUZZ_BUILD_JOBS=1 python3 scripts/run_generic_scenario.py \
  --descriptor "$D/generic_scenario.json" --flow mixed --mode original \
  --case NEW_CASE_ROOT --cache runs/config-driven-20261028/cache \
  --records-file "$D/acceptance_sequence.json" --record-local-commands
PYTHONPATH=src:. MYFUZZ_BUILD_JOBS=1 python3 scripts/run_generic_scenario.py \
  --descriptor "$D/generic_scenario.json" --flow mixed --mode fresh \
  --case NEW_CASE_ROOT --cache runs/config-driven-20261028/cache \
  --records-file "$D/acceptance_sequence.json" --record-local-commands
```

Expected reads for the fixed workload are 85, 85, 170 and 170. These are
expected values for the chosen register, not a claim that every MMIO target
returns the last written word. Full native and fresh checks remain pending.
