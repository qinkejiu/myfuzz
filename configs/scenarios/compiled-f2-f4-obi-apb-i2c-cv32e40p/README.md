# CV32E40P + the same public I2C MMIO configuration

Only the CPU request/compose/descriptor change from the Ibex configuration.
The processor request is copied byte-for-byte from the tested
`compiled-f4-obi-apb-timer-cv32e40p` request: the existing CV32E40P OBI profile,
instance `processor`, reset assert/release8/8. No CPU/IP-specific code is added.

The compose directly references the Ibex I2C variant's actual peripheral
request. The descriptor directly references that variant's capability and
execution supplement; they are not copied or forked. PRESCALER remains offset0
at0x40001000, APB32 word with low16 read/write mask0xffff and reset0. Both flows
use exactly `compiled_mmio_obi_apb`, with no internal probe/version authority.
The original `acceptance_sequence.json` is reused unchanged.

```sh
PYTHONPATH=src python3 scripts/run_dependency_search.py --scenario configs/search/i2c-cv32e40p.json --preflight
PYTHONPATH=src python3 scripts/run_generic_scenario.py --descriptor configs/scenarios/compiled-f2-f4-obi-apb-i2c-cv32e40p/generic_scenario.json --flow mixed --mode original --case NEW_OUTPUT --cache CACHE --records-file configs/scenarios/compiled-f2-f4-obi-apb-i2c-ibex/acceptance_sequence.json --record-local-commands
PYTHONPATH=src python3 scripts/run_generic_scenario.py --descriptor configs/scenarios/compiled-f2-f4-obi-apb-i2c-cv32e40p/generic_scenario.json --flow mixed --mode fresh --case NEW_OUTPUT --cache CACHE --records-file configs/scenarios/compiled-f2-f4-obi-apb-i2c-ibex/acceptance_sequence.json
```

Actual compose/request and profile-bound capability declaration checks passed.
The shared MMIO backend is being integrated separately; full preparation,
admission, original and fresh native evidence are not claimed here. Future
native acceptance must check actual writes and reads55/aa, CPU/APB completion
and dependent result evidence, while keeping internal version/cross-origin
unknown and granting no storage reward. CV32E40P's missing bus-error pins are
not fabricated by switching CPU. No I2C serial/IRQ/F5/F6 support is implied.
