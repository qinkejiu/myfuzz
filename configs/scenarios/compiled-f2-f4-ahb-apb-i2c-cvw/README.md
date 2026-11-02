# CVW AHB-Lite CPU + the same APB I2C MMIO target (declaration only)

This reuses the actual request from `cvw-pulp-gpio/requests/cpu.json` without
changing its source configuration: RV32 I/M/A/F/C/Zicsr/Zifencei subset,
`cpu.external_bus`, actual34-bit HADDR and32-bit data. Reset is8/8 ticks and
boots at the configured external address0xC0000000. No AHB×APB executor is added;
F2/F4 select the existing protocol-neutral `compiled_mmio` identifier.

The same I2C request, capability and supplement are directly shared from
`compiled-f2-f4-obi-apb-i2c-ibex`. Target PRESCALER remains offset0 with a32-bit
APB word/low16 mask0xffff. This CPU's declared external-memory decode covers
0xC0000000..0xCFFFFFFF, so the old OBI/Pico target0x40001000 is not reused.
Declared RAM is0xC0000000..0xC000FFFF; I2C is0xC0010000..0xC0010FFF. These do not
overlap and both lie in the actual external region. `F2:000001c0` encodes that
real byte address. The local four-case sequence writes55/aa and reads each.
Keep code/cache-line fills in RAM; do not put executable bytes in the I2C window.

Actual compose/request/profile-bound capability declarations were validated,
including XLEN/ISA, boot-vector membership, address encoding and nonoverlap.
This is **not current runtime/native support**: AHB's synchronous routed MMIO
still needs a separately reviewed deferred enqueue/completion/error integration.
The production CPU-protocol adapter remains a separate task. Do not infer
retirement, IRQ/F5/F6, storage-version authority or relation rewards.

Future completion evidence must retain real manager HREADY acceptance separately
from subordinate HREADYEXT, HSELEXT/data phase, HRESP and response data; the
actual target callback's error must not be discarded or turned into success.
No cycle-accurate RTL AHB/APB bridge is generated.

After that integration is accepted, the intended common commands are:

```sh
PYTHONPATH=src python3 scripts/run_dependency_search.py --scenario configs/search/i2c-cvw-ahb.json --preflight
PYTHONPATH=src python3 scripts/run_generic_scenario.py --descriptor configs/scenarios/compiled-f2-f4-ahb-apb-i2c-cvw/generic_scenario.json --flow mixed --mode original --case NEW_OUTPUT --cache CACHE --records-file configs/scenarios/compiled-f2-f4-ahb-apb-i2c-cvw/acceptance_sequence.json --record-local-commands
PYTHONPATH=src python3 scripts/run_generic_scenario.py --descriptor configs/scenarios/compiled-f2-f4-ahb-apb-i2c-cvw/generic_scenario.json --flow mixed --mode fresh --case NEW_OUTPUT --cache CACHE --records-file configs/scenarios/compiled-f2-f4-ahb-apb-i2c-cvw/acceptance_sequence.json
```
