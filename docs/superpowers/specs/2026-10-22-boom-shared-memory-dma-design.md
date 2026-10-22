# BOOM uncached shared-memory CPU-programmed DMA

Root-reviewed bounded design for the existing six-CPU DMA objective. Independent
RTL/adapter review is in `.superpowers/sdd/boom-dma-design-review-20261022.md`;
implementation is underway under the companion plan. It remains a design
contract until native evidence passes.

## Choice and boundary

Three approaches are possible: mirror native backing RAM to host RAM; add a
fully coherent external DMA client; or share an explicitly uncached data
aperture through the existing native accepted A/D face. A mirror cannot keep
CPU dirty lines and DMA writes coherent and cannot establish common writer
provenance. A coherent client requires missing B probes/cache ownership and
larger protocol work. Choose the uncached aperture: native instruction/cache
backing stays in the existing manager, while actual uncached CPU data and DMA
master requests use one host memory object.

No host copy propagates CPU data between memories. This design does not alter
the pinned CPU RTL/profile or claim coherent DMA, physical SRAM/interconnect,
global timing, IRQ/ISR, retirement, generic TileLink/F6/D4 or system completion.

## Exact address and source contract

Use current derived `configs/cpus/boom/component_profile.json`, its archived
generated RTL/source/physical-port manifests and existing
`GeneratedBoomScenarioSession` / `GeneratedBoomCpuSession` native lineage.
Boot trampoline remains native0x10040 and program starts0x80000000. Native
`TlRam` continues to service instruction-cache and ordinary coherent traffic.
Static code is installed before the first edge through existing LOAD only.

Use external selection page [0x4000,0x5000), subdivided as:

| Purpose | Exact span |
| --- | --- |
| SOURCE | 0x4100..0x410f |
| DESTINATION | 0x4200..0x420f |
| RESULT | 0x4300..0x4317 (status, four observed words, marker) |
| DMA control | 0x4400..0x440f |

Shared `PersistentMemory` declares precisely source16, destination16 and
result24 regions; no code or MMIO belongs to this memory. Host preloads only
zero destination and result. Source is initially unmaterialized and supplied
by four actual CPU stores:135,246,357,468. DMA uses the exact same memory
object through its existing RAM-only `MemoryService`; no master IP targets.

Pinned generated source facts (line numbers refer to current
`configs/cpus/boom/generated/chipyard.TestHarness.SmallBoomConfig.top.v`):

- LSU `mpu_physaddr_0` legal predicates at286960–286968 include
  `((paddr ^ 0x4000) & ~0xfff)==0`; legal_address_0 includes that predicate.
- LSU cacheable_0 near287015 is legal AND either
  `((paddr ^ 0x10000000) & 0x94010000)==0` or
  `((paddr ^ 0x80000000) & 0x90000000)==0`. Neither matches0x4xxx.
- prot_r_0 is legal AND actual PMP read permission. The first prot_w
  predicate `(paddr & 0x8a130000)==0` covers0x4xxx; write permission also
  requires actual PMP. This is a PMA/source basis, not a fabricated PMP grant.
- The cache request classifier near186405–186417 also excludes0x4xxx.
  Prior GPIO/results runs establish actual uncached accesses in this page;
  the new run must still show its selected source/destination spans as size2
  Get/Put, with no unexpected Acquire/Release used as shared-data substitutes.

Freeze these actual source bytes with the new execution. Refuse source drift
or a layout not satisfying all selected predicates. Do not broaden the native
page bounds or silently fall back to native TlRam for a rejected data address.

## Accepted A/D memory binding

Bind `GeneratedBoomCpuSession(..., external_range=(0x4000, 0x5000))`
explicitly for this mode, independently of Router's sole
`DeviceWindow('dma', 0x4400, 16, dma)`. Current register-only mode derives
external_range from its Router window and must retain that default. Merely
attaching a memory object without changing the native selection would leave
CPU data in TlRam and does not implement this design.

Retain native source/size matching in RESPOND. Extend the Runner adapter's declared external-data contract to carry
the shared memory/service and exact permitted spans, separately from Router's
DMA16-byte window. Existing GPIO/register mode remains unchanged by default.
All new entry points are opt-in, source-bound and identity-recorded; no CPU
name branch is added to Runner or generic Router.

On each actual native external A acceptance, validate opcode0/1/4, param0,
size2, word alignment, mask exactly `0xf << (address & 7)`, page/spans and
request sequence/epoch. Retain its entire physical64-bit data/mask. A complete
`TransactionKey` uses native execution UUID, testcase, CPU instance, reset
epoch, external uncached channel and monotonically increasing accepted
external sequence. The sequence covers memory and control, never a separate
synthetic success counter. Preserve physical TL source as a separate field.

For a permitted shared-data A request, select actual four enabled bytes from
the64-bit lane. Execute `MemoryService.read/write` exactly once using that key
and address (width4,be15), retaining original physical lane facts separately.
Read snapshots and writes retain issued service receipts, byte versions and
writer keys. Offer measured Get data or Put acknowledgement as matched native
D via existing `respond_external`; high-lane Get data is shifted32 bits for
the CPU. The returned response is frozen, stable across D backpressure, and
does not clock CPU/DMA itself. Actual native D consumption completes the CPU
transaction, not the host service effect or RESPOND call alone.

For a control request inside0x4400..0x440f, enqueue existing Router delivery
to the registered DMA session, keeping64-bit beat metadata and lane selection.
Only its scheduled DMA target step performs real Wishbone control edges; the
callback supplies actual response through matched D. No direct host DMA
register access or unrecorded router drain is permitted.

Any external-page request outside declared spans, unsupported opcode/size/
mask, duplicate/stale response or changed binding refuses before shared memory
or provider effects. Do not turn refusal into invented denied/corrupt or bus
success. Existing native driver currently drives denied/corrupt0; preserve
that limitation explicitly and retain failed-attempt diagnostics.

## Firmware and lifecycle

Use RV64-compatible word instructions: LUI with immediate `0x4` forms the
small positive base address `0x4000`; bounded ADDI immediates `0x100`,
`0x200`, `0x300`, and `0x400` form the selected subpage addresses. the current page-only shared builder
cannot accept these four distinct subpage addresses unchanged. Add explicit
bounded address encoding or a narrowly parameterized extension after review;
do not weaken overlap/range guards just to reuse a signature. Retain existing
CVW/Vexii/CVA6 bytes by default.

CPU writes all four source words, then DMA source+8,dest+12,count+4=4,
start+0=0x0fed0004. Use real FENCE iorw,iorw ordering before reading status/
data and between required stores as needed for distinct observed word beats;
native evidence must prove this ordering. Poll actual busy31 until0, test
error30 independently, read destination and source, compare and save actual
destination words. Write marker1 only after equality; failure writesFFFFFFFF.
Do not require observing busy1. Wrong key03db0004 follows identical flow and
must reach first actual mismatch without accepted DMA master traffic.

Run deterministic `dma,cpu` pairs, at most4000rounds. Record every scheduled
edge and any explicit no-edge quiesce action. After actual final marker store
and its matched D completion, require the retained native prefix to show
**no partially accepted multibeat A transfer** before quiescing. The existing
native QUIESCE gates all A.ready, including continuations; it is not a
root-aware partial-A drain implementation. This fixture's external words are
single-beat and instruction Acquire requests are single A beats. Prove this
precondition from opcode/size/beat accounting, not an inferred boolean.
On the marker external-D boundary pending_external also holds A.ready low,
so no new A is simultaneously accepted. If the precondition fails, refuse
quiesce and preserve a failed attempt within the original bound; supporting
arbitrary partial A requires a separately source-bound root-aware policy.
After the checked boundary, quiesce CPU and continue scheduled drain of
existing native D/E/C and DMA responses. Native manager
drained() covers queued D, grant sinks and partial A/C; adapter additionally
counts active external/queued control and pending offered D. Shared memory
effect does not clear those counters prematurely.

Reset cancels or explicitly accounts every pending external/control request
before a new epoch. No old callback/token may cross epoch. Native reset
recreates CPU/TlRam/code, while shared data reset policy must be explicit:
this first fixture restarts both sessions with fresh shared memory and the
same permitted initial images. It does not claim in-place warm DMA recovery.
All failure paths unconditionally reap both native processes and preserve
primary/capture/cleanup failures plus actual exit codes.

## Acceptance evidence

1. Exact profile/source/driver/manager/binary/input identities, canonical
   heavy lock, unique immutable attempt directory and preserved failures.
2. Four real CPU source A stores→service commits→matched consumed D, and
   four CPU control A→Router key→scheduled DMA control STB/ACK→consumed D.
   Retain original lane/mask/size/source/data and actual DMA indirect ticks.
3. Exactly four native DMA RAM reads and four destination writes, each with
   full typed key, accepted Wishbone beat and actual CYC/ACK/noERR response.
   Four-byte read versions/writers equal corresponding actual CPU commits;
   CPU destination snapshots equal corresponding DMA commits. CPU source
   rereads and status/data observations join consumed D values. No CPU
   destination writes, host source/config writes or copied data authority.
4. Unique actual CPU status/result/marker writes and completed responses,
   all pending states drained. Native cached instruction A/C/D/E events stay
   visible and must not be attributed to shared-data memory receipts.
5. Wrong-key first/fresh: CPU writes stale key, actual destination0 vs
   source135 mismatch, markerFFFFFFFF, no DMA accepted master/response/effect.
   A separate pre-effect layout refusal checks undeclared subpage address
   without fabricating a native environment error.
6. Independent fresh native sessions replay complete saved actions for both
   branches, exact identity documents first, explicit declared UUID-only
   normalization for runtime records/writer strings, full prefix equality,
   distinct PIDs/executions and both real process exits0. No ignored event,
   timing, address or receipt field to obtain a pass.

Implementation and native proof remain open under
`docs/superpowers/plans/2026-10-22-boom-shared-memory-dma.md`. This document
is a narrow memory-service design; it does not relabel existing BOOM coherent
traces as shared-memory or DMA execution evidence.
