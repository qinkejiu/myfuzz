# Generated OpenTitan pattgen TL-UL adapter

## Authorized design and implementation plan

Goal: use the existing generated TL-UL register template to configure the real
checkout's pattgen and observe both native pattern channels and completion IRQs.
The pinned checkout already supplies its generated register package and register
top, so no register generation or upstream edits are required.

Alternatives considered: registering the packed upstream top would leave typed
alert inputs outside the generic scalar boundary; selecting another IP would
lose the available dual-channel pattern behavior. The selected design adds a
complete scalar wrapper with the source-defined default alert receiver, a fixed
profile, and an authenticated local source closure. Existing profiles and the
global source lock remain untouched. The generic build snapshot accepts the
closure record returned by this dedicated verifier.

1. Add contract and real RTL tests, then observe RED for the absent profile.
2. Add a scalar wrapper/profile with all TL-UL, pattern, IRQ and alert outputs.
3. Run Verilator lint and pin the successful command plus every compilation and
   include byte in a closure manifest; authenticate it in a dedicated verifier.
4. Admit that manifest at the build snapshot boundary.
5. Run the new tests and nearby generic TL-UL regressions. Confirm exact LSB-first
   pattern bits, both divider periods, completion IRQs and fresh session replay.
6. Document measured results and limits, then commit only this task's files.

RED: `PYTHONPATH=src python3 -m unittest
tests.local_harness.test_generated_opentitan_pattgen -v` failed both contract
tests with `pinned pattgen profile is missing`. The separately enabled real test
failed at the same explicit missing-profile assertion.

## Implemented boundary

The profile uses OpenTitan checkout `fca045df919a26c47e71616b9dac917b1ea4fd07`.
Its 61 compilation files include all six checked-in pattgen RTL files and the
new scalar wrapper. The 265-file closure additionally pins the common include
directories used by the existing OpenTitan adapters. This is a conservative
common support superset, rather than a dependency-minimized source list.
No upstream generation, source edits or DUT substitutions were needed.

The source revision is
`sha256:0556df8dade8869dde4540eb3f3fb6d719295043c1fb0db5977864d60533a581`.
The local closure manifest is pinned by the dedicated verifier; the source
lock and existing IP profiles are not changed by this adapter. Build snapshots
capture the manifest, every source/include byte and authenticated lint log.
Profile changes, RTL changes and new include files are rejected.

The request declares only the existing `target.tl-ul` / `user-integrity`
protocol policy. Register setup is owned by the existing generic session and
included in its replay identity. Every native pattern data/clock/enable, both
completion IRQs and the fatal alert pair are observed.

## Measured acceptance

Verilator 5.051 lint exited 0. The recorded nonfatal `WIDTHEXPAND` warning is
from upstream `prim_diff_decode.sv:162`; its one-bit skew counter is compared to
an integer parameter. No waiver or upstream patch was added.

The real test writes the registers through generated TL-UL transactions:
INTR_ENABLE=3, PREDIV_CH0=1, PREDIV_CH1=2, DATA_CH0=0xa5, DATA_CH1=0x16,
SIZE=7|(1<<6)|(4<<16), then CTRL=3. Readback checks both data registers and SIZE.

| Native channel | Bits checked on rising output clock | Full output period | Completion |
| --- | --- | --- | --- |
| 0 | `[1,0,1,0,0,1,0,1]` repeated twice | 4 input clocks | IRQ 0 held high |
| 1 | `[0,1,1,0,1]` once | 6 input clocks | IRQ 1 held high |

Both channels return their data and clock outputs to configured inactive zero;
all four output enables remain one. The evidence bundle is saved and replayed
inside a temporary test directory with a newly constructed session and process.
Fresh replay matches the complete captured scenario; the compiled binary cache
can be reused. Bundles are removed by the test's temporary directory cleanup.

Verification commands, all successful:

```text
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src python3 -m unittest \
  tests.local_harness.test_generated_opentitan_pattgen \
  tests.local_harness.test_generic_tlul_register_real -v
9 tests passed in 96.958s, including real pattgen, spi_device, rv_timer, GPIO and fresh replay.

PYTHONPATH=src python3 -m unittest tests.local_harness.test_source_lock -v
13 tests passed in 0.353s.

PYTHONPATH=src python3 -m unittest tests.local_harness.test_build_identity -v
10 tests passed in 33.277s, including actual build/cache and corrupt binary refusal.
```

## Coverage limits

These checks cover ordinary valid TL-UL configuration, two independent short
LSB-first patterns, two dividers, one repetition field and native completion.
They do not cover inverted clock polarity, nonzero inactive levels, the upper
32 pattern bits, maximum lengths/repetition counts, mid-pattern configuration,
early disable, IRQ acknowledgement/rearming or fault/alert handshake injection.
There is no external receiving peripheral or CPU interrupt route in this test.
