# Ibex + PULP I2C through the public APB MMIO adapter

This is a configuration-only F2/F4 combination. It uses the existing Ibex OBI
processor request, pinned `pulp_i2c` RTL/profile and the protocol executor
`compiled_mmio_obi_apb` for both flows. It adds no IP executor, I2C peer,
internal-state probe or storage-version source contract.

The declared transfer is a 32-bit APB word at `0x40001000`, PRESCALER offset0.
Actual `apb_i2c.sv` stores `PWDATA[15:0]` in `r_pre`, reads `{16'h0,r_pre}` and
resets it to zero. The capability therefore uses a 32-bit word with read/write
mask `0xffff`; configured values 0x55, 0xaa and 0x1234 all fit that mask. CTRL
remains at reset zero, so this does not start a serial transfer or request IRQ.
CMD is self-clearing and RX/STATUS are read-only; none is falsely declared
stable writable storage in this configuration.

HCLK is the existing 50 MHz core clock, HRESETn asynchronous active low, with
2 asserted / 3 release ticks. SCL/SDA input pads are explicitly held at1 to
represent idle high for this MMIO-only scope. No electrical input response or
I2C transaction is synthesized. The profile's existing no-timing policy applies
to upstream delayed assignments.

`acceptance_sequence.json` is the ordered four-case smoke: write0x55 → read →
write0xaa → read. Required evidence is actual CPU OBI plus APB write/read
completion and actual read values 0x55/0xaa. The public MMIO result is
`compiled_mmio_case.v1`, status observed. Internal storage version, instruction
operand origin and cross-case consumption authority remain unknown; no live
relation reward is justified from MMIO completion alone.

```sh
PYTHONPATH=src python3 scripts/run_dependency_search.py --scenario configs/search/i2c-ibex.json --preflight
PYTHONPATH=src python3 scripts/run_generic_scenario.py --descriptor configs/scenarios/compiled-f2-f4-obi-apb-i2c-ibex/generic_scenario.json --flow mixed --mode original --case NEW_OUTPUT --cache CACHE --records-file configs/scenarios/compiled-f2-f4-obi-apb-i2c-ibex/acceptance_sequence.json --record-local-commands
PYTHONPATH=src python3 scripts/run_generic_scenario.py --descriptor configs/scenarios/compiled-f2-f4-obi-apb-i2c-ibex/generic_scenario.json --flow mixed --mode fresh --case NEW_OUTPUT --cache CACHE --records-file configs/scenarios/compiled-f2-f4-obi-apb-i2c-ibex/acceptance_sequence.json
```

The search catalog also contains 0x1234. The directed smoke fixes the corpus;
search choices remain in the common search CLI. Native acceptance is pending
until a new original/fresh run completes on this configuration. Existing
Timer/SPI, I2C standalone-peer or another CPU's results do not supply that run.
