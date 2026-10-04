# Generated OpenTitan SPI Host: first real TL-UL stage

The pinned OpenTitan `spi_host` source is present at
`third_party/soc-opentitan` revision `fca045df919a26c47e71616b9dac917b1ea4fd07`.
Its existing typed closure fixes alert, RACL, and passthrough inputs. A new
scalar boundary exposes every TL-UL member, the four-bit SPI data input,
SCK/CSB/data/output-enable pins, and both native IRQ outputs. The full top has
29/29 classified physical ports. Source admission checks the original selected
lock record, its elaboration closure, both wrapper hashes, and the complete
union of upstream files and include bytes.

The generated local runtime uses the existing `beat_to_tlul` adapter and an
independent real RTL process. The bounded testcase writes CONTROL and
CONFIGOPTS, reads both back through TL-UL, reads the real STATUS.READY bit,
and records pad and IRQ observations on local ticks. The five local register
transactions are counted against `max_transactions=5`; replay starts a fresh
RTL process and matches the semantic evidence. The testcase keeps the same RTL
instance for all its local ticks, with no per-step reset.

Current scope: the generated session deliberately permits only configuration,
status, and interrupt register accesses. It does not issue `COMMAND`, `TXDATA`,
or `RXDATA`, so this result establishes real TL-UL register behavior and
observable SPI pins but does not establish a serial data transfer, SPI peer
byte propagation, or CPU interrupt servicing. Those need a per-tick peer path
during command execution; returning expected RX bytes from a model would not
satisfy the project rule that intermediate results come from real RTL.

Acceptance command:

```sh
PYTHONPATH=src MYFUZZ_SCENARIO_REAL=1 python3 -m unittest \
  tests.local_harness.test_opentitan_spi_host_generated_real -v
```
