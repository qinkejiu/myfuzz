# Ibex OBI + OpenTitan GPIO TL-UL target (F2/F4)

This is a configuration-only F2/F4 combination.  It uses the existing Ibex OBI
processor request, the pinned `opentitan_gpio_local` RTL/profile and the
protocol-independent `compiled_mmio` executor for both flows.  The target is the
real generated `tlul_register_observe` session; the adapter is
`myfuzz.integration.target_tlul`.

## Selected register

`INTR_ENABLE` at profile offset `4` (`gpio_reg_top.sv:223-247,807-809,895`) is
the declared 32-bit `rw` register with side effect `none`.  The capability
sidecar therefore declares full read/write masks.  Writes only enable/disable
the GPIO interrupt bits and do not start an external transfer.  `DATA_IN` is
`ro`, so it is deliberately not used for F4.

MMIO base is `0x40000000` with the profile's 128-byte window:
absolute register address `0x40000004`.

## Records

```json
{
  "f4_records": ["550000000000000000000000000000000000", "aa0000000000000000000000000000000000", "341200000000000000000000000000000000"],
  "f2_records": ["04000040"]
}
```

F4 records are 18 bytes: the first 4 bytes are the register stream word and the
remaining 14 bytes are the declared target bus-pin slices (all zero). `F4:55000000...`
writes `0x00000055` to `INTR_ENABLE`; the `aa`/`3412` records write their values.  The F2 record is the
little-endian address `0x40000004`.  The target register is RW with a full
32-bit mask, so the directed acceptance sequence is write/read, write/read.

## Target observation

`target_tlul.observe_tlul_mmio_bus` joins each routed CPU delivery to the target
step's own `local_tick_sample` events (`phase=pre`, matching
`producer_event_id`) and reads only the declared TL-UL trace signals:

- request: `a_valid`, `a_ready`, `a_opcode`, `a_size`, `a_address`, `a_mask`,
  `a_data`, `a_source`
- response: `d_valid`, `d_ready`, `d_opcode`, `d_size`, `d_source`, `d_data`,
  `d_error`

For F4 the write's A/D handshakes must precede the readback's A/D handshakes.
The dependent RAM store is matched after the read.  Internal storage version,
cross-case origin and reward eligibility remain `unknown`, `unknown`, `false`.

## Commands

```sh
PYTHONPATH=src python3 -m pytest tests/integration/test_target_tlul.py -q

PYTHONPATH=src python3 scripts/run_generic_scenario.py \
  --descriptor configs/scenarios/compiled-f2-f4-obi-tlul-gpio/generic_scenario.json \
  --flow mixed --mode original --case CASE \
  --records-file configs/scenarios/compiled-f2-f4-obi-tlul-gpio/acceptance_sequence.json
```

The descriptor loads, prepares both flows and admits the TL-UL target bank and
observer through `mmio_support`.  No Verilator/RTL execution is part of these
local checks; native acceptance requires the remote runner.

At the time of this delivery the shared static-plan checker compares the
TL-UL profile's 32-bit `address_width` capability with the byte-window width
(`log2(128) = 7`) and refuses at
`/components/peripheral/endpoints/widths`.  The adapter/descriptor are ready;
the full `run_generic_scenario` path needs that shared width-domain check
resolved by its owner.  This README records the exact local scope and does not
claim a completed native run.
