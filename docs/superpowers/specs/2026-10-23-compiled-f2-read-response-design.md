# Compiled F2 CPU load and native IP read response

Status,2026-10-24: approved by user continuation on2026-10-23 and implemented.
The bounded file-entry F2/F4 slice has its own accepted2098-input gate cohort:
[report](../../reports/f2-f4-current-acceptance-20261023.md). The unified F2
RFuzz supplement completed its final21916-input freeze3 cohort:all ten
software/native/positive/rename/refusal/F4-compatibility gates independently
accepted,with final Spec/source and Quality PASS:
[unified-entry report](../../reports/compiled-f2-rfuzz-entry-20261023.md).
These results do not grant unrestricted same-protocol or system acceptance.

## Goal and bounded scope

Execute the selected D3 F2 path using its actual instruction-image source,
CPU-owned load address, real APB3 IP response and declared assertions. The first
supported shape is RV32I OBI1 CPU plus one source-registered, side-effect-free,
32-bit APB3 storage register. Target selection uses protocol/template/source
contracts and exact declared access, with no CPU/IP name dispatch. Timer and
SPI are two existing source-registered acceptance instances, not an unrestricted
claim about every APB3 IP.

The CPU issues a real LW, receives real IP PRDATA through its native OBI response,
and computes/stores a dependent result in declared persistent RAM. This is
bounded value-flow consumption evidence for the exact generated program. It is
not authenticated architectural retirement or a general CPU semantic observer.

## Findings that require a new contract

Direct inspection of both frozen Timer/SPI D3 documents and current source found:

1. `_evaluate_f2` emits `ram_byte_version` with only an IP register name as
   `memory_id`. Actual RAM witnesses require an installed memory cell, generation,
   byte offset and writer/version evidence. An IP register is not that resource.
2. F2's request and consumed nodes are both on the CPU, but their `mmio_route`
   declaration names CPU and peripheral. Existing live topology admission rejects
   those endpoints.
3. Generic MMIO edge provenance currently matches accepted writes only. Making
   topology bindable does not supply a read-response producer/consumer witness.
4. The installed candidate layout and executor are F4/write specific; their
   stable source/build/process joins do not themselves implement F2.

Research: `.superpowers/sdd/compiled-f2/contract-research.md` and
`.superpowers/sdd/compiled-f2/runtime-research.md`. Historical D3 documents and
reports remain immutable evidence. New compiler output has new identities.

## Approaches

### A. Versioned F2 contract and an installed read-response handler — recommended

Correct F2's prerequisite/topology, install the actual handler and typed
assertion outcomes, and validate both registered instances plus refusal cases.
This closes a real D3-to-D4 execution gap and gives each change an executable
acceptance boundary. It touches compiler, runtime and report integration.

### B. Correct the D3 declaration only

Smaller software change; useful for truthful admission. F2 still has no native
executor or measured CPU response chain, so the central functionality remains
open. It may be an implementation checkpoint inside A, not final acceptance.

### C. Reuse F4 by inserting a setup write and relabel its readback

Rejected for this slice: the extra write is not an F2-owned source and would
change state/setup semantics. Relabeling an F4 certificate does not execute the
original F2 prerequisites or its declared read-response edges.

## 1. Versioned static execution contract

Keep the outer `compiled_paths.v1` container and add an F2-only
`execution_contract` with schema `compiled_F2_read_contract.v1`. Its exact
fields identify:

- instruction source and CPU load source IDs;
- source and target components/endpoints, device/window, exact address, register,
  field, read mask and full-word access;
- version selector: kind `ip_register_version`, target component/register and
  epoch policy `current_live_epoch`;
- request, IP-response and CPU-consumption node IDs;
- consumption mode `native_read_then_dependent_ram_store`;
- the complete admitted expectation-ID list.

The selector is a compile-time requirement, not an issued runtime prerequisite.
Before the candidate runs, the installed native authority must resolve it to an
actual `ip_register_prerequisite` with live epoch, observation event/version and
evidence identity. Never invent an epoch, RAM byte version, reset observation
or commit. An observed initial current register value does not claim that a
prior CPU write occurred or grant a reset prerequisite.

F2 sources and their mirrored constraints retain `operation=read`,
`value_origin=bound_target_rdata`, full-word BE=15 and exact source ownership.
The candidate supplies address, never PRDATA or target storage. The existing
singleton address range remains singleton; no payload/value entropy is added.
Compile address dimensions as unsigned32 address/alignment constraints; a
register response-field mask is not an address mask or permission to fuzz PRDATA.
The F2 execution contract stores response-field metadata separately. The first
handler requires full32-bit readable storage; partial-field cases remain unsupported.
No seed, extra source, side-effecting read, autonomous selected-state writer,
partial mask/lane, unsupported constraint or assertion is silently discarded.

The runtime graph becomes program-image → CPU-read-request → IP-read-response
→ CPU-data-read-consumed. Its request and return edges have real CPU/IP endpoint
pairs and the exact Router/window declaration. Both route edges must use the
same transaction identity. A matching route aperture alone is insufficient.
Each edge has separately defined producer/delivery/consumer evidence below.
The two route declarations are matched with distinct read-request and
read-return roles from the F2 contract. The reverse route is not certified by
reusing the outbound request as its consumer. The full compiled document, marker, path, source, artifact and binding identities
are pinned. A graph path hash is insufficient: the saved Timer/SPI path hashes
are equal despite different target registers and CPU artifacts.

Missing marker, legacy RAM-shaped F2 prerequisite or old CPU→CPU route shape
refuses F2 admission before native startup. There is no load-time upgrade or
F2-to-F4 rewriting. Normal recompilation reconstructs the whole D3 document;
old whole-document compiler equality checks are expected to reject stale data.

## 2. Native version and response proof

Use the existing reviewed APB register session, source registration, physical
samples, startup capture and native register authority. Add a code-owned F2
selector/consumer for the read shape, rather than passing an edited path to the
F4 write selector. No hidden setup writes, diagnostic register accesses or
arbitrary source pins are added.

After genuine startup capture, the regular Runner schedules the IP's normal
idle step with empty inputs. That measured command must establish the current
source-verified storage state and contiguous startup handoff. Only then may
existing native authority issue/consume a current version token and resolve the
pre-read prerequisite. If state/handoff is unavailable, fail before submitting
the CPU load; startup pages or JSON alone do not grant the version. This uses
existing authority checks; no widened issuance eligibility is proposed.

The candidate then runs its admitted RV32I fragment: construct address, LW,
apply a fixed XOR immediate to the loaded register, and SW the dependent value
to a separate declared writable RAM result word. The XOR constant is a code-owned
nonzero immediate, pinned in the generated-program declaration, not extra fuzz
input. Result storage cannot overlap instruction slots or MMIO.

A pure exact-hop verifier consumes actual recorded events together with live
native authority and immutable memory snapshots. It requires:

1. The actual instruction-source bytes/version/writer and each functional fetch
   joined to native OBI accepted request and completed response.
2. Exact native CPU load address/BE/channel/sequence, request producer and Router
   acceptance/delivery for the admitted window/target.
3. APB PRE accepted read with PSEL/PENABLE/PREADY, PWRITE=0, correct decode,
   PRDATA equal to the source-verified current register value, and no PSLVERR.
4. Continuity from the pre-read version witness through the read samples, with
   no intervening reset, unexplained state change or aliased write. Any intervening
   idle commands must have contiguous authenticated samples; a gap refuses. Resolve and
   compare the post-command current witness; diagnostic data is not authority.
5. The same transaction's return delivery and native OBI RVALID/RDATA, with the
   admitted CPU error policy. An IP read response is not yet CPU consumption.
6. A later native CPU store of `loaded_rdata XOR constant` to the result RAM,
   exact store transaction, installed memory version/writer and snapshot, plus
   functional instruction-fetch ordering. Value equality alone does not certify.

New read provenance matching is explicitly operation-scoped and binds producer
references, transaction, address, direction, data and ordering. Existing write
matching retains its original behavior. Until all required hops are available,
that edge remains incomplete/unknown; a topology match grants no certificate.
No unsupported CPU error behavior is normalized to success.

## 3. Runtime organization and identity

Add focused modules for F2 admission/layout, generated reader and exact-hop
verification. Reuse the existing builder/session receipt APIs and pure saved
build-join validation. Extract a shared protocol helper only for an exact common
OBI operation already covered by both handlers; do not make F2 inherit the large
F4 runtime or parameterize away F4-only assertions and write semantics.

Register an explicit compiled F2 executor/projection; installed support is
selected by flow, protocol, template, ABI and registered source contract. Actual
startup still validates physical identity and live evidence. The CLI reports
selected F2 support and per-path reasons for every other unsupported flow.

As with F4, prepare admitted components before binding/manifest capture, verify
live executable before READY, preserve original/fresh process diagnostics and
write a schema-checked run-level build join. A new F2 execution binding has schema
`compiled_F2_execution_binding.v1`; it must never be accepted as an F4 binding.
Extract/extend pure build-join primitives through explicit supported binding
schemas while retaining strict legacy F4 validation and complete saved-material
checks. No caller-supplied factory or capability claim grants execution.

## 4. Typed assertion outcomes and fresh replay

A new `compiled_assertion_results.v1` document records full compiled/binding/run
identity and one row per case/path/expectation, with status passed/failed/missing,
reason and exact evidence references. The two D3 expectations are
`protocol_checker.receipt_violations` and `cross_component.declared_edge_hops`.
Additional dependent-RAM checks are named executor checks, not invented D3
expectations. Actual checker violations force finding; missing provenance cannot
be passed. Once D3/path admission succeeds, emit exactly one row for every
expected assertion for each admitted case, including explicit `missing` rows
when execution, construction or timeout prevents evidence collection. Never
omit expected rows or replace unavailable evidence with passed. `failed` means
an observed checker violation or contradictory/mismatched required hop;
`missing` means the required observation was not obtained. Refusal/error status
is recorded separately from these assertion outcomes. Before D3/path admission,
record `admission_refused` with available diagnostics and no assertion authority;
there is no admitted case/path assertion inventory to fabricate. Strict saved
validation rejects duplicated, unknown or omitted admitted expectations.

Keep checker findings as bug classifications. Give capability-report construction
an explicit validated assertion-result input, crosschecked against the selected
D3 expectations and saved execution evidence. It must not derive assertion
success from an empty findings list. Report-file byte hashes are checked/pinned
at CLI finalization, including assertions, prefix, replay and build join.

Fresh independently recompiles/adopts the same static contract, prepares both
components, resolves live prerequisites and executes the same cases in new
processes. Compare the full normalized semantic prefix and assertion outcomes;
retain raw distinct PID/nonces and all stable binary/source/build/version facts.
Only the established process-local identity projection is allowed. Neither a
changed binary nor response/value/version evidence is normalized away.

## 5. Acceptance and refusal matrix

Implementation checkpoints: (1) corrected D3 contract and fail-closed admission;
(2) read-specific layout/program and native version/response consumer;
(3) runtime, CLI, assertion/report and saved-file validation; (4) frozen gates
and independent source/evidence audits. Each checkpoint has a scoped review.

Required software controls include stale legacy contract, wrong owner/source,
read/write confusion, candidate PRDATA injection, wrong address/BE/endpoint/window,
renamed same-contract instances, similar-name wrong shape, unregistered or changed
source, side effects/autonomous writers, missing live version, wrong epoch,
startup/sample gaps, cross-case/process transaction reuse, borrowed read response,
wrong native data/error, missing dependent store, missing/duplicated assertions,
coherently rehashed saved-material swaps and fresh divergence. Preserve original
primary errors and available cleanup evidence.

Freeze production and test inputs before final acceptance. Run the scoped F2 and
F4/CLI/builder/session/provenance regressions with exact archived inputs, commands,
counts, skip reasons and exit/reap receipts. Native Timer and SPI positive gates
must execute real CPU reads in original/fresh processes, record exact-hop and
typed assertion joins and complete prefix equality. Rename component instances
without changing protocol/source semantics and verify selection is independent
of names. Real negative gates must refuse before forbidden side effects or
retain the observed partial failure without granting certification.

The selected registers reset to zero and have a singleton candidate address.
That bounded positive demonstrates the chain; it establishes neither useful
mutation diversity nor stable throughput. Any later nonzero priming phase needs
its own declared, authenticated state source and is outside this slice.

## 6. Boundaries and document maintenance

Do not award F1 retirement, general F3, F5 IRQ, F6 DMA, arbitrary OBI/APB3 register
semantics, AXI/AHB/TileLink execution, new protocol adapters, coverage-guided
search quality, clean-room tool provenance, cold-build performance, P6/P7-E/P8 or
six-CPU/four-IP system completion. Other D3 flows retain explicit runtime refusal.

Update CURRENT_PROGRESS, runtime boundaries, component/code references, P7 plan
and report indexes only with actual implemented and measured results. New F2
source changes also invalidate current-byte attribution of historical whole-D3
F4 runs; preserve those frozen runs and perform the required current-source F4
regression rather than borrowing their old acceptance.

No source changes, tests, builds or remote commands were performed for this
specification. Remote execution, if needed later, follows `agent.md` and stays
under `/root/fanzehui/` on the target server.
