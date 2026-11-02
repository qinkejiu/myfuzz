# PicoRV32 Wishbone CPU + the same APB I2C target

Configuration-only protocol reuse: the CPU request is referenced directly from
`compiled-f4-obi-wb-uart-setup/requests/processor.json`; the peripheral request,
capability, execution supplement and acceptance sequence are directly shared
with `compiled-f2-f4-obi-apb-i2c-ibex`. No target implementation, internal probe
or CPU×IP executor is copied. F2/F4 both select the public `compiled_mmio` executor.

The real CPU endpoint is `processor.memory`, a unified Wishbone-classic memory
master using byte addresses and the existing cpu.wishbone/no-err-stall adapter.
RAM starts at0 to include this CPU's actual reset vector0; using the Ibex RAM
base65536 would be wrong. The unchanged I2C APB3 window is0x40001000/4096,
PRESCALER offset0, a32-bit APB word with low16 writable/readable mask0xffff.
Values0x55/0xaa/0x1234 remain unchanged. No Wishbone target-word address shift
is applied: this CPU's byte-address contract is distinct from some Wishbone
peripherals' word-address contracts.

This is an explicit host transaction-normalized route: real CPU Wishbone
request/ACK → the existing MemoryService/router → actual target APB
request/response. It does not generate an RTL WB/APB bridge or claim a
cycle-accurate bus fabric. Target rdata, CPU instruction fetches, completion and
dependent result writes still require native evidence from both actual adapters.
The CPU has no native ERR/STALL pins; none is fabricated. IRQ/F5/F6 support,
internal storage version and cross-origin reward are not granted.

```sh
PYTHONPATH=src python3 scripts/run_dependency_search.py --scenario configs/search/i2c-picorv32-wishbone.json --preflight
PYTHONPATH=src python3 scripts/run_generic_scenario.py --descriptor configs/scenarios/compiled-f2-f4-wb-apb-i2c-picorv32/generic_scenario.json --flow mixed --mode original --case NEW_OUTPUT --cache CACHE --records-file configs/scenarios/compiled-f2-f4-obi-apb-i2c-ibex/acceptance_sequence.json --record-local-commands
PYTHONPATH=src python3 scripts/run_generic_scenario.py --descriptor configs/scenarios/compiled-f2-f4-wb-apb-i2c-picorv32/generic_scenario.json --flow mixed --mode fresh --case NEW_OUTPUT --cache CACHE --records-file configs/scenarios/compiled-f2-f4-obi-apb-i2c-ibex/acceptance_sequence.json
```

Actual compose/request/profile-bound capability declarations and reset-vector
RAM membership were checked without executing a DUT. Production CPU-protocol
selection is integrated separately in the same public MMIO runtime. Native
original/fresh acceptance on this third combination remains pending; the two
OBI CPU I2C runs do not prove this Wishbone CPU path.
