# ZipCPU wbdmac: static source/profile slice

The actual checkout is `third_party/soc-zipcpu`, commit
`42606d2d6ef55df313772232977621b2d72f0159`. The proposed
`third_party/zipcpu_wbdmac_upstream_reference` directory does not exist.

The unmodified `rtl/peripherals/wbdmac.v` is self-contained with `FORMAL`
undefined. Actual Verilator lint and JSON elaboration at ADDRESS_WIDTH=30,
BUS_WIDTH=32, SLV_WIDTH=32, LGMEMLEN=10 produced 21 physical ports, zero warnings
and zero errors. Compact logs/ports are in `evidence/`; the authenticated
source/parameter closure is `configs/soc/closures/zipcpu_wbdmac.json` and its
hash is registered in `configs/soc/sources.lock.json`.

## Slice B edge transport

The profile now admits the explicit `wishbone_dma_edge_v1` dual-role shape and
can generate a `wishbone_dma` runtime top and C++ driver. Both interfaces retain
`wishbone/pipelined`; no classic adapter or CPU service is reused. The 32-bit
trigger port has one constant-zero owner in port_actions, so it is not also
mapped as a functional input endpoint. The reference interface description keeps
its semantic trigger declaration. Native IRQ remains a sampled DUT output.

`STEP_WB_DMA` drives exactly one edge with nine ordered input fields: control
CYC/STB/WE/word-index/data, then master STALL/ACK/read-data/ERR. Every edge carries
actual pre/post backend pin samples and post-edge physical IRQ observation.
There is no ACCESS convenience command and no hidden wait loop. Header/parser,
Python registry and artifact metadata carry the same widths/maxima. The plugin,
policy, field schema and guard header participate in the captured build identity.

The conservative environment permits one accepted outstanding master request:
accept at pre-edge CYC && STB && !STALL, complete at CYC && (ACK || ERR). It
allows STALL while delivering an older response, rejects ACK+ERR, unsolicited
completion and new acceptance on a completion edge before ticking. Held STB with
STALL low represents another acceptance, never a replay. Generic command-cache
replay returns the original receipt without advancing another edge.

Generation and host C++ guard/stub transport tests establish this infrastructure,
not DMA RTL execution. No autonomous DMA session, RAM service, CPU configuration,
real transfer, IRQ delivery or fresh RTL transfer replay has been tested. The
source-lock runtime status remains runtime_unverified. Slice C must connect the
real sampled master requests to ledger-backed frozen memory effects and responses.

Control address is a two-bit word index. CPU byte offsets 0/4/8/12 correspond
to control/total-word-count/source-byte-address/destination-byte-address.
No slave SEL exists: partial control writes must be rejected before effects.
The master emits 30-bit word addresses: the environment must zero-extend then
shift left two bits. No master SEL exists; initial full-word accesses use 0xf.
Host ownership of every response/control input is listed in
`ram_to_ram_config.json`; DUT request outputs and native IRQ are never sources.

Executable RTL at lines 258–263 requires start key **0xfed**, despite stale
header prose saying 0x3db. Initial start is `0x0fed0004` after setting total
length **4 words**, source and destination byte addresses. Bits29/28 stay zero
to increment both addresses; bit15 stays zero for immediate start, and all
`i_dev_ints` bits are fixed zero. Control accesses while busy are acknowledged
but may be ignored. An interrupt can mean final acknowledged write OR bus error;
it is an observed native output, not automatically successful completion.

Next steps are actual transport validation, a persistent DMA
session and ledger-backed memory service, then genuine CPU configuration and
four-word DMA transfer with stalls, native IRQ, error/old-key/reset controls,
and fresh replay. No DMA transfer or IRQ has been simulated in this slice.
