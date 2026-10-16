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

This is a structurally loaded physical profile and source declaration. It is
**not admitted/generated/executable** by existing local harness templates.
Both Wishbone interfaces are pipelined; `wishbone/pipelined` is deliberately
not relabeled `wishbone/classic` to match an existing adapter. No composite DMA
template, one-edge driver, autonomous master session or CPU integration exists.
A standard local-harness request must fail closed until those are implemented.

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

Next steps are the dedicated dual-role template/transport, persistent DMA
session and ledger-backed memory service, then genuine CPU configuration and
four-word DMA transfer with stalls, native IRQ, error/old-key/reset controls,
and fresh replay. No DMA transfer or IRQ has been simulated in this slice.
