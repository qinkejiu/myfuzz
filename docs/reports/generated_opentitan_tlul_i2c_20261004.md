# Generated OpenTitan TL-UL I2C acceptance (2026-10-04)

## Source and harness boundary

The upstream `i2c` RTL is pinned at `third_party/soc-opentitan` revision
`fca045df919a26c47e71616b9dac917b1ea4fd07`. The existing
`opentitan_i2c` source lock and elaboration closure authenticate the selected
upstream files. The new local source gate additionally pins the complete
scalar wrapper, the local and upstream profiles, the 68 declared source files,
and the include-root byte union. Verilator elaborates the wrapper with all
33 physical ports selected. They comprise the 20 TL-UL fields, six SCL/SDA
pad signals, 15 interrupt bits, alert output, RACL error output, RAM
configuration response, local trigger, clock and reset. The wrapper uses
source-defined defaults for alert receiver, RACL policy and RAM configuration.

`render_local_runtime` selects the typed `tlul_i2c` variant and emits one
independent TL-UL target adapter with integrity encoding and a 128-byte
decoded register window. The generated driver retains the real I2C RTL
process and local clock state for one testcase. The C++ peer models one
7-bit target at address `0x50`, ACKs the address, and supplies one testcase
response byte. It can only pull SDA low; the controller's real enable outputs
and the peer pull-down resolve SCL/SDA inputs. Fuzzer actions can select the
response byte once per testcase. The resolved pad inputs are Bound Inputs
and direct injection into `scl_i` or `sda_i` is rejected. An FDATA command
is rejected until the response source is selected; it cannot use the peer's
internal default byte as an undeclared fuzzing source.

## Real RTL observations

`MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src python3 -m unittest
tests.integration.test_local_opentitan_i2c_generated_real -v` passed **2/2**
in 50.285 seconds. The local test read the real STATUS reset value, wrote and
read CTRL through TL-UL, observed idle released pads, rejected direct pad
injection and a second distinct peer byte, then configured timing and issued
the two FDATA commands for an I2C read. Native SCL and SDA enables toggled;
the real command-complete IRQ asserted; the real RDATA register returned
`0x5a`. A separate source-owned idle-pad testcase saved an evidence bundle
and matched fresh replay.

`MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src python3 -m unittest
tests.integration.test_scenario_cve2_opentitan_i2c_generated_real -v` passed
**1/1** in 99.538 seconds. A generated CV32E20 CPU executed a persistent
program that wrote the real I2C timing, interrupt-enable and FDATA registers,
polled the real interrupt state, read real RDATA, and stored `0x5a` in
persistent RAM. The testcase's upstream source was the one-byte external
peer response. The trace records MMIO delivery, native IRQ and RAM write, and
the entire serial transfer matched replay with new CPU and I2C RTL processes.

The CPU test polls I2C interrupt state; it does **not** claim CPU interrupt
delivery or ISR execution. The peer currently supports one response byte,
one address and no clock stretching. Other I2C target modes, multi-byte
streams, arbitration, alerts and RACL policy behavior require separate
variants and real acceptance. The two harnesses do not instantiate a SoC
bus, crossbar or global cycle-accurate schedule.
