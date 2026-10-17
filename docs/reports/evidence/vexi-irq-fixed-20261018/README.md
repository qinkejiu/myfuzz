# VexiiRiscv + PULP GPIO fixed-instance IRQ evidence (2026-10-18)

Produced from a detached worktree snapshot at source commit
`ad4eb9e6ff6d1bcd6c91e70a71bfb56c8a2b4674` (implementation `f454962` plus the
gate-test key fix) under
`flock -w 14400 /home/qinkejiu/myfuzz/.superpowers/heavy-worker.lock`.
Other agents' uncommitted changes in the main worktree were not part of the
snapshot. The PULP GPIO submodule in that snapshot was checked out at the pinned
commit `f82caeb7f7d89427f05e9af5ed31e0675efe0d83`; the derived source contract
re-hashed its `rtl/apb_gpio.sv` bytes before the run, and the GPIO artifact
digest in `summary.json` binds the exact file set used.

## Files

| File | Bytes | SHA-256 |
| --- | --- | --- |
| `first.json.gz` | 170,177 | `05363adb0260d68de452e6ef0917937441f6ecdc5a559d80c5f46d713b6b78a7` |
| `fresh.json.gz` | 170,172 | `71aca53ab76ae51c3adcc93c1722b1bc99f04f72dd700b1cbe7e89f7e32ef53f` |
| `summary.json` | 22,059 | `83ec540efee075f9b2278c81bc5986b1002f4ea41f8092300133c8ad3f787948` |
| `gate.log` | 922 | `ea8539be6cde745aa17b726d9ca5ffbeee7e444d863e94a8060463814312d34f` |

`first.json.gz` and `fresh.json.gz` are the complete evidence documents of the
two independent operating-system processes. `summary.json` pins their
uncompressed SHA-256 (`first`: `ff6b49ce…`, 6,598,806 bytes; `fresh`:
`0eaffe7c…`, 6,598,805 bytes), the row checks of both runs, the replay
comparison, the implementation source hashes and the child logs. `gate.log` is
the combined pytest real-gate and evidence-publication output.

```sh
gunzip -c first.json.gz | sha256sum   # ff6b49ce4bed3d0572bed3f84931d4780ae510b834f50459e53894fc308edcac
gunzip -c fresh.json.gz | sha256sum   # 0eaffe7c51f52d5141cb23f609b9a2a79b73482013a8f13c8961eaf6185a3433
```

## Row identity

* Cases (preloaded table): `[17, 34, 51, 90, 165, 291, 1023, 127]`; driven
  `PADOUTSET` words: `[17, 35, 51, 91, 165, 291, 1023, 127]`.
* Program image: 4,384 bytes, sha256
  `e4fb014dbfcae1920261bec4ffb078b4340c8a33d3d0cc6274fc784632a69c86`;
  `mtvec = 0x80000200`, 52 main words, 21 ISR words.
* CPU: generated `VexiiRiscv.v`, source revision
  `sha256:5e73d0523bbe106f4d489971315b7320c1e2e9eccbee60bc679a5bad7d5ce977`;
  runtime artifact digest
  `ee91caefef7c253ff7d733c8cfa31705670b4eea5ab336337fd829a0c7acc778`;
  harness binary sha256
  `d9a986e6a3e134e3937ed66f0443182f9af86220285b6008082a0d2fce267aa8`.
* GPIO: PULP `apb_gpio` git
  `f82caeb7f7d89427f05e9af5ed31e0675efe0d83`; runtime artifact digest
  `ac5c4224c6d88ac1777de81515eea022bbb1de019d33036bf1ccaf9fa0afeb8f`;
  harness binary sha256
  `1fb4696cb2b5849cda3eb53b6be2bb373f22626c8b220d22f8156222a781c5ff`.
* Native executions: first CPU `5b849cb6e286400a84d1c03fdd42f2a2`, GPIO
  `75464baff3454cfc8b542a5a488af26e`; fresh CPU
  `1be5e0d79b88435da565547c66620763`, GPIO
  `e095531be3324d2384bb378995ea7457`. Both runs have the same artifact/build
  identities and equal raw CPU/GPIO samples; only these native run identities
  differ.
* Implementation hashes (from `summary.json`): scenario module
  `04621b7415b485b15b4c50ae2f6be9ed276ce292f2deae2fe8163230dd5e3244`, gate
  script `122556d1e42373d4dbe3f1a48792ca9cbc127224405d0744acdc6688732572e8`,
  derived profile `eb7aecd17393f45cc5371f2fd0c26c748393e9c778ca68c29d7343886c4ea920`,
  derived contract `7277c0267c74dabfb53f54c91e029f30f64aad11087c50c3760a8bab48299ae6`,
  driver header `1e72a2d2a8fce550c87e37cdf28bb3bb23a9954d150a89392fe75375fe9bbb8e`.

## Counts and results

| Quantity | Both runs |
| --- | --- |
| CPU ticks | 1,567 |
| GPIO ticks | 1,711 |
| IRQ rises / falls | 8 / 8 |
| `mtvec` vector fetches | 8 |
| APB deliveries | 36 (4 configuration + 8 × 4) |
| `result` | `[17, 35, 51, 91, 165, 291, 1023, 127]` |
| `status` | `[1, 1, 1, 1, 1, 1, 1, 1]` (GPIO latched status bit observed by the ISR) |
| `check` | `[0, 0, 0, 0, 0, 0, 0, 0]` (main: ISR result XOR written value) |
| `done` | `0x600d` |
| Row checks | 77/77 `ok` in each run |
| Fresh replay | `matches: true` |

## Boundaries

The chain is one fixed CPU+GPIO instance with real RTL on both sides: real CPU
fetches/stores, real APB3 register accesses, the GPIO's real synchronized input
and real `interrupt` pulse, the core's real `int_m_external` entry, a real trap
and vector fetch, a real ISR with real reads/writes and `mret`, and real CPU
stores to RAM.

It is **not** a P6 campaign row and does not claim P6. The program image is
fixed per row with a preloaded case table; there is no online genome mutation,
coverage feedback, arbitrary program-image replay, saved-failure reproduction or
authenticated prefix-replay certificate. The host's pulse-to-level wire and
GPIO `gpio_out → gpio_in` loopback are declared composition wires, not RTL; no
interrupt controller, masking/priority/claim, multi-source arbitration, second
IP, DMA or single combined clock-accurate SoC top exists here. See
[the report](../../vexiiriscv-cpu-ip-irq-20261018.md) for the full boundary list
and the exact remaining P6 pieces.

## Reproduce

```sh
PYTHONPATH=src python3 scripts/run_vexiiriscv_irq_fixed_row.py \
  --output docs/reports/evidence/vexi-irq-fixed-20261018
MYFUZZ_VEXII_IRQ_REAL=1 PYTHONPATH=src python3 -m pytest -q \
  tests/scenario/test_vexii_pulp_gpio_fixed.py
```
