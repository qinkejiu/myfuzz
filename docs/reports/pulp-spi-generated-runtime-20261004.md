# Generated PULP SPI local runtime

The pinned `apb_spi_master` now has a generated APB3 runtime, a per-HCLK
external mode-0 peer, and a persistent local session. The artifact source gate
admits the exact seven-file union only after authenticating the two separately
owned source-lock records, the elaboration closure, parameters, profile hash,
and bytes. Full-word APB setup/access/idle behavior comes from the existing
`beat_to_apb` adapter. `SOURCE_SPI` supplies literal peer bits before a
transfer; the driver drives SDI1 before each HCLK and advances its source only
on observed selected SCK rising edges. SDI0/2/3 are explicitly zero. All pins,
both native event bits, APB receipts, and internal command ticks are retained.

The generated session declares its literal source, chip select, startup MMIO
plan, and RX-on-EOT policy in its `scenario_manifest_identity.v2` service
identity. The published runtime manifest schema and class/kind verifier reject
an SPI session paired with another artifact kind. The source plan is part of
the manifest before a real RTL process starts; the driver and peer implementation bytes
are part of the generated build identity. The bounded replay cache returns an
identical receipt for a repeated transaction key without an additional tick or
FIFO effect. A fresh-process `save_evidence_bundle` /
`replay_evidence_bundle` comparison passed with the full pin trace and RXFIFO
word; changing the literal source from `A5C396F0` to `A5C396F1` changed the
observed word and semantic trace.

After integration, the formal scenario also passed with a `ResourceBudget`
and fresh replay. Its per-step tick reservation covers the declarative APB
startup writes and the optional RXFIFO read; a first budgeted run exposed an
underdeclared one-tick limit and was rejected before this bound was corrected.
Explicit reset discards pre-reset tick samples and rearms the startup plan.

## Accepted real run

At CLKDIV=1, STATUS `0x102` transmitted `A5C396F0` on 32 actual selected MOSI
rising edges. STATUS `0x101` received a literal external `A5 C3 96 F0` stream:
the real RXFIFO returned `0xA5C396F0`, the peer counted 32 selected rises, and
the real EOT bit 1 pulsed. Both transfers used SPILEN `0x00200000`. A
register-only roundtrip is not the acceptance evidence.

## Limit

CLKDIV=0 RX is not accepted by this peer contract. The actual output pins show
33 selected SCK rises by EOT while the controller's internal RX enable samples
32 bits. The current strict peer exhausts a 32-bit source at that extra rise;
with a padding bit, the RXFIFO is shifted. This needs separate pin timing
resolution before CLKDIV=0 can be claimed. Quad line-width modes, header/dummy
framing, threshold IRQ rearm, repeated transfers in one reset epoch, software
reset scope, and CPU-to-SPI-to-CPU composition remain outside this acceptance.

Commands used:

```bash
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src python3 -m unittest tests.integration.test_local_pulp_spi_generated_real -v
PYTHONPATH=src python3 -m unittest tests.local_harness.test_pulp_spi_contract tests.local_harness.test_source_lock tests.local_harness.test_driver_renderer tests.local_harness.test_runtime_renderer -q
```
