# BOOM adaptation status (2026-10-18)

This note corrects older inventory entries that describe BOOM as having no
profile, no generated RTL, or no CPU/IP path. Those statements applied to an
earlier snapshot. The evidence below remains tied to its recorded derived
source and run snapshots; it does not imply generic TileLink support or full
P6 acceptance.

## Confirmed assets and runs

- `configs/cpus/boom/component_profile.json` describes the generated 47-port
  `BoomTile`, including a shared coherent TileLink endpoint with 39 physical
  fields. `generated/rtl.tar.gz`, the source manifests, and the two declared
  compatibility patches pin a derived Chipyard/BOOM build; it is not an
  unmodified upstream generation.
- The direct generated CPU/RAM gate records real A/C/D/E coherent traffic and
  dirty writeback. Its current persistent supplement records two fresh runs,
  599 edges each, A21/C80/D164/E14, and CPU plus backing RAM result `0x123`:
  [persistent coherent evidence](../../configs/cpus/boom/evidence/persistent-coherent-20261017/README.md).
- A separate persistent BOOM→PULP GPIO run uses the standard ScenarioRunner,
  DataflowRouter, and real APB samples. Two fresh 20,597-event prefixes match;
  changing the delivered GPIO read from 53 to 52 changes the CPU result and
  failure branch, while suppressing D leaves the CPU waiting:
  [GPIO evidence](../../configs/cpus/boom/evidence/persistent-runtime-20261017/README.md).
  This GPIO program covers A/D. It must not be combined with the separate
  cached-RAM supplement to claim one run exercised A/C/D/E through an IP.
- A separate bounded IRQ gate also passed on its pinned snapshot:
  [BOOM IRQ result](boom-irq-native-attempt3-20261017.md).

## Remaining adapter and event boundaries

The GPIO route is a profile-specific uncached MMIO path. It accepts a narrow
subset of aligned 32-bit Get/Put requests in the declared external window,
routes those requests to PULP GPIO, and supplies the measured target result as
a matched D response. The native RAM manager continues to handle coherent
cache traffic. This path is not a general TileLink coherent interconnect or a
full Chipyard SoC.

The TileLink-coherent plugin inventories A/B/C/D/E fields but has no channel
relations or temporal rules and currently declares no legal generic adapters.
The dedicated coherent observer projects accepted A/C/D/E beats only. Saved
drivers tie B.valid low and do not retain full per-edge valid/ready samples;
they also do not expose D denied/corrupt as measured values. The accepted-beat
rows cannot be re-labelled as TL-UL events or used as a complete handshake
checker. C's synthetic `mask=255` in the old direct trace is manager metadata,
not a physical C-channel field.

Still open are generic TileLink-coherent admission, complete per-edge channel
checking and coverage, B-probe behavior, arbitrary MMIO bursts/concurrency,
generic source/consumption authority, and a single same-run CPU/IP gate that
also exercises coherent C/E traffic. BOOM has no DMA CPU/IP path in these
records. The P6/P7/P8 gates remain independently governed by their own plans.

The remote `myfuzz/project` snapshot named by the user is based on `42a9ce9`;
these BOOM additions and saved gates are not evidence that the entire newer
local worktree has already been reproduced or jointly re-run there.
