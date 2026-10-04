# Ibex and OpenTitan pattgen real dataflow acceptance

## Scope

This acceptance scenario keeps Ibex and OpenTitan pattgen in separate generated
RTL harnesses. Ibex runs a real OBI program. The scenario router forwards only
accepted CPU MMIO transactions to the independent TL-UL pattgen session and
returns read values produced by pattgen RTL. It does not instantiate a SoC,
bus fabric, bridge, arbiter, PLIC, or global cycle-accurate schedule.

The CPU program configures both pattgen channels, enables them, polls the real
`INTR_STATE` register until both completion bits are set, then stores the
observed mask in persistent CPU RAM. The scenario runs two program variants,
`0xa5` and `0x5a`, as the channel 0 data source. Channel 1 remains configured
with `0x16`.

## Checked behavior

- All ten setup/start register writes appear in the expected order and carry a
  real CPU OBI data transaction identity with full byte enables.
- Each source variant appears in the CPU MMIO write accepted by pattgen.
- Both channels emit the configured serial bits least-significant bit first;
  their observed rising-edge periods are 4 and 6 pattgen-local clocks.
- Pattgen's native completion outputs assert, and the real status read returns
  both completion bits (`0b11`) to the CPU. The matching OBI response carries
  `0b11` and the CPU stores it at `0x20000`.
- There is no in-test reset barrier and both harness reset epochs remain zero.
- Each recorded run is replayed using fresh CPU and pattgen session objects;
  the replay also stores `0b11` in its fresh persistent RAM.
- The two source variants produce different observed channel 0 bitstreams and
  different semantic trace hashes.

The pattgen completion outputs are observed as actual RTL outputs. This test
does not bind them to the CPU interrupt input and makes no claim about CPU IRQ
handler or PLIC behavior.

## Verification

The real integration acceptance passed both variants and both fresh replays:

```sh
MYFUZZ_SCENARIO_REAL=1 \
MYFUZZ_LOCAL_SOURCE_ROOT=/path/to/myfuzz \
MYFUZZ_IBEX_PATTGEN_CACHE=/tmp/myfuzz-ibex-pattgen-cache \
PYTHONPATH=src:. \
python3 -m unittest \
  tests.integration.test_scenario_ibex_opentitan_pattgen_generated_real -v
```

The final 220-step bound passed both variants and fresh replays in 93.2 seconds
with the generated harness cache populated. A focused adjacent regression
command passed all five tests in 113.8 seconds:

```sh
MYFUZZ_SCENARIO_REAL=1 \
python3 -m unittest \
  tests.local_harness.test_generated_opentitan_pattgen \
  tests.integration.test_scenario_ibex_opentitan_rv_timer_generated_real -v
```

The adjacent tests cover pattgen's source contract, independent real TL-UL
register execution, and the existing Ibex/OpenTitan RV Timer IRQ chain. The
implementation changes only the integration test and this report; it does not
change DUT RTL, generic harness code, profiles, or source locks.
