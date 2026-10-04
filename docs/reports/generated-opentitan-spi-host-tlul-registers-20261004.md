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

The next stage adds a constrained four-byte standard mode-0 read. The generated
session accepts one final `COMMAND=0x68` after CONTROL and CONFIGOPTS setup. A
stateful serial peer owns the four input bytes, drives SD1 (MISO), and advances
only on real selected SCK edges. The `COMMAND` TL-UL write was measured to
complete in four local ticks with CSB high and SCK low throughout, so no peer
edge is lost during the non-interactive access command. The Host subsequently
produces 32 selected rising edges and its real `RXDATA` register returns the
four source bytes in little-endian word order. The generated session records
that RTL read as one counted local register transaction. Both a constructor
source and a genome-owned 32-bit `spi_source_word` are accepted. The latter is
selected by a dependency path targeting real RXDATA, mutated at the source,
locked for the testcase, and replayed in a fresh RTL process. A changed source
changes the real RTL readback.

The serial stage is intentionally limited to one four-byte command, one chip
select, standard SPI single-line mode 0, CONFIGOPTS=8, and an 8-bit source
byte stream. No `TXDATA`, chained commands, nonzero chip selects, or alternate
clock modes are admitted. The external peer is a host-side input model; the
RXDATA and IRQ observations come from real RTL. No CPU interrupt servicing is
claimed.

Acceptance command:

```sh
PYTHONPATH=src MYFUZZ_SCENARIO_REAL=1 python3 -m unittest \
  tests.local_harness.test_opentitan_spi_host_generated_real -v
```
