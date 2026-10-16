# Source-owned storage producers behind the generic APB template

This follows the existing new-IP design and actual generic APB identity/trace changes. It preserves the whole system acceptance scope. It is a next implementation boundary, not a claim that timer storage/version authority exists.

## Objective and selected route

Keep APB transport, router and F4 execution selected by admitted protocol/template, with no component-name branch. Add a closed, source-reviewed storage producer contract for an exact source/parameter/register tuple. Source registration must be separate from the generic bus adapter. Arbitrary JSON evidence_ref, readback values, caller-selected hierarchy strings and saved raw events must never issue live authority.

Alternatives considered: readback-only prerequisites cannot establish internal prestate; arbitrary hierarchy declarations lack writer proof; a code-owned source-pinned producer descriptor with complete writer review can support the genuine timer source while preserving unknown-source refusal. This is the selected implementation path. It does not establish arbitrary-RTL semantic inference, and a timer-only registration cannot by itself complete P7 universal onboarding.

## Concrete timer source findings

Pinned top apb_timer SHA22dce4e3ff8328bdd6e1621c20e2877e7f44cfecccc07203d09e994632cc1778; child timer SHAd352fc4476da83658d361e8f500b5a73f857f0a11e9436ab47d5bf0ba0bc7fce. Parameters APB_ADDR_WIDTH12/TIMER_CNT2. TIMER0_CTRL is regs_q[REG_TIMER_CTRL], REG_TIMER_CTRL=1. Child default regs_n=regs_q, sole CTRL write is selected APB PWDATA, reset clears the packed bank, and sequential state takes regs_n. COUNT autonomously changes and CMP writes clear COUNT; these are not the selected stable field.

A critical alias detail must survive the producer implementation: top slave_address_int takes PADDR[4] for TIMER_CNT2; the child's2-bit register_adr truncates PADDR[4:2] to PADDR[3:2]. Therefore CTRL0 is selected by PADDR[4:2]==1, not only PADDR==4. Upper APB address bits alias the storage. The full-word adapter separately rejects misaligned host requests. Every accepted alias write must count as a real CTRL writer, revoke stale tokens and retain its actual address/context; ignoring aliases would falsely certify continuity.

The prospective real SV path inside generated runtime is u_component.u_dut.TIMER_GEN[0].timer_i.regs_q[1]. Its complete generated hierarchy and elaboration still require actual verification. A contract must not silently substitute PWDATA, PRDATA, host expected data or an unrelated state expression.

## Implementation boundaries

1. Source admission: exact source closure/revision/top/parameters and complete source SHA map, selected register/width/reset and reviewed reset/write/hold equation. Match source identity, not component name. Unknown source shapes/writers/parameters refuse. Descriptor is code-owned; JSON can only select a registered contract.
2. Generation: expose read-only pre/post actual storage, actual harness reset and APB address/control/data probes. Derive bus wires from structural ABI, with no input or DUT/adapter timing changes. Bind all probe expressions and descriptor source into runtime/driver/build identities. Canonical whole-wrapper/runtime projection must reject rewired or expected-value taps.
3. Producer eligibility: factor actual build/process/reset/command admission into a closed shared producer interface. Retain source/code pins, actual subprocess/nonce/epoch, built binary manifest, exact command frame/receipt, continuous sample coverage and uncertain-effect revocation. Do not simply add a Python type to GPIO's observer list.
4. Version authority: consume each actual tick, check physical storage continuity and the source-owned reset/write/hold equation, count all accepted aliases, and issue process-local single-use register/version tokens. Every actual command or scope/process/reset/source change revokes stale issuances; lost or malformed receipts poison the producer. Serialized reports never rehydrate authority.
5. F4: select the registered field contract from D3; choose target/session by protocol template and producer contract. Preserve exact instruction→CPU→Router→APB→storage commit→readback/RAM joins and all required assertions. Candidate layout remains4bytes for the timer declaration, with no dummy pins or setup producer. Preserve old GPIO and both CPU ABI boundaries.

## Verification sequence

- Pure RED first for wrong source/hierarchy/parameter/register/decode/alias, fake or discontinuous samples, serialized/stale/foreign tokens, missing actual reset/build/command eligibility and changed ownership/layout. Actual common admission must run; only tool/frontend identity may be explicitly represented by software fixtures.
- Review source writer/reset/alias analysis and canonical probe generation; no runtime component-name branches or semantic fallback.
- New independent remote native storage gate: measured reset, actual accepted CTRL/alias writes and read, actual storage pre/post, process/binary/source identity and controlled refusal. Preserve every attempt.
- Genuine CPU→timer continuous3 candidates plus2 complete fresh prefixes under the same compiled public entry, with actual per-run PID/nonce/close/source receipts. Keep current GPIO/Ibex/CV32 regressions. Stage completion still requires the remaining six-CPU/four-family/DMA/event/search gates; this one chain is not whole acceptance.
