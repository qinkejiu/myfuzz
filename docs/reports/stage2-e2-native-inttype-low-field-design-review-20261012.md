# Native INTTYPE_LOW selected-field design review — 2026-10-12

This is an independent read-only pre-execution review. No native process or large artifact audit was started. The proposed first chunk covers four selected fields, not the entire register bank or complete L2/functional certification.

The current actual profile declares `INTTYPE_LOW` at offset0x1c, width32, plain rw. The v3 source-bound sidecar declares sixteen nonoverlapping two-bit fields covering the full word; each has relative read/write mask3 and side_effect none. The pinned RTL writes PWDATA[2*i +:2] to pin i and reads the same packing. Actual rendered PAD_NUM must include pin15; a sidecar declaration alone cannot make a truncated instance support that field.

| Selected field | lsb | width | bus mask |
|---|---:|---:|---:|
| pin0 | 0 | 2 | 0x00000003 |
| pin1 | 2 | 2 | 0x0000000c |
| pin14 | 28 | 2 | 0x30000000 |
| pin15 | 30 | 2 | 0xc0000000 |

Explicit RMW compiles36bytes/nine RV32I instructions: actual LW, load ~busmask, AND, load shifted field value, OR, SW. No byte strobe exists in this APB peripheral, so a field write must preserve all unselected bits in the actual loaded full word. The relevant assertion is actual SW data==(actual LW data & ~mask)|(relative_value<<lsb), including high-bit masks after uint32 truncation. Direct partial-field SW must not replace this path. The compiler requires all32bits to have declared plain rw/full masks and actual profile read/write permissions; selected-field support alone is insufficient.

The following READ compiles actual LW, optional SRLI by field lsb, ANDI3, then actual RAM SW. Results are field-relative zero-extended values0..3, not full register words. The audit must bind the private issued commit to the selected CPU read's actual transaction and compare four little-endian bytes, while preserving full original APB PRDATA in the access proof. Exact current recompilation must check machine bytes,36byte RMW length, read extraction and original request identities.

INTTYPE changes affect IRQ edge detection: RTL codes00 falling,01 rising,10 both, while11 matches none of these detection expressions. Interrupt generation is additionally gated by actual GPIOEN and INTEN. The experiment must not infer IRQ quietness or functional edge behavior from a programmed type value, a sidecar reset value, or a host assumption. The production bootstrap writes targetB INTTYPE_LOW/INTEN and can enable CPU interrupts. All actual CPU input commands, CPU/B raw physical IRQ samples and IRQ policy events must therefore remain in the trace and be reconstructed exactly; any unexpected interrupt path is evidence to investigate, not permission to suppress or erase events. Writing targetA type does not itself isolate targetB IRQ routing.

The planned eight requests are four RMW+four READ. Expected selected accesses are twelve MMIO deliveries/twelve completed ordinary associations,36 selected APB projections and four selected issued RAM commits, with four RMW/write-readback and four read-result certificates. Startup or other unselected actual accesses stay in the complete journal and must be accounted separately; these counts are selected expectations, not substitute evidence. The worker must observe actual RMW old/new words and verify untouched bits for each pair rather than assume reset contents or replace readback with host arithmetic.

Independent audit requirements are authenticated nine-artifact identity and current trusted selector; eight original-request recompiles; complete plan/trace semantic and journal identity; exact completed receipt/delivery/raw/base/sample seals; actual private RAM commit hashes/bytes/CPU lineage; selected and full-stream snapshots/certificate projections; source closure and each current cache's own frozen inputs/binary digest; complete actual IRQ projection; separate180-second single-worker generation/fresh resource receipts and full fresh-state comparison. Saved context is used for comparison only, never restored live authority. Fresh fulltrace availability must be described accurately.

Source review references: `register_program.py` RMW permission and complete-word checks, RMW sequence and field-relative READ extraction; `configs/peripherals/pulp_gpio/component_profile.json`; v3 `test_capability.json`; pinned `third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv` write packing335–353/read packing610–618 and IRQ expressions131–138. No concrete compiler defect was found in this scoped source review. Native execution and complete artifact acceptance remain pending Root-controlled workers and audit GO.
