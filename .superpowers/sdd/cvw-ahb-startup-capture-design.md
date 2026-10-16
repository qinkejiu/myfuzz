# AHB actual startup capture: proposed next source increment

2026-10-17. Read-only design after steady-state freeze da4605f; independent review93a7bda closed the scope-only event budget finding, no remaining high/medium. No implementation, model, build, elaboration or native execution in this design.

## Actual gap

In driver_renderer, `tick` already snapshots immediately before the rising edge and after eval, increments local_ticks once, then returns the clock to0. Startup calls `tick(dut, nullptr)` in the exact assert/release loops, then sets local_ticks=0 and emits the existing five-token READY. An AHB address can be accepted during release ticks, before command sample1. The current observer honestly emits ahb_prefix_unknown. Saved old CPU sample1 already shows backend req_valid1, which cannot reconstruct the missing address edge.

Capture must occur alongside those actual existing ticks. Do not add reset edges, wait cycles, backend responses, initialization or CPU/adapter behavior. First raw data is whatever RTL actually presents under asserted reset; an initially empty pipeline is known only after a physically measured reset edge and the admitted adapter's actual reset contract.

## Alternatives

1. Recommended: AHB-only bounded startup buffer, fetched after unchanged READY through a new zero-clock command. It reuses canonical RESULT parsing and issued execution/sequence replay protection without widening READY or generic startup readers.
2. A versioned unsolicited startup record preceding READY requires a protocol reader change and line/version coordination for every startup path. It is feasible but larger than needed.
3. Treat backend request1 as a synthesized address or reset after READY to regain visibility changes facts/timing; reject.

## Driver and transport

Only AHB generated drivers allocate the startup vector. Replace only their two startup loop call arguments from nullptr to the vector pointer; retain every reset assignment/eval/tick/order/count and local_ticks reset byte for byte. Keep native sample pre/post snapshots intact, including all13 actual taps and actual backend/ordinary physical groups. Attach actual harness reset pre/post and startup edge index/stage in a separate startup record envelope, reading the actual model reset value, not inferring a CPU pin name. The existing exported HRESETn is separate raw evidence, not substituted for harness reset.

Artifact contract `cpu_ahb_startup_capture.v1` declares actual assert/release counts, total bound,13role mapping, reset normalized polarity, raw namespace and zero-clock page retrieval. Request already caps assert/release each<=1024, total<=2048. Proposed page size32 samples,<=64 pages, total serialized buffer<=8MiB; derive exact conservative worst-case sample/page sizes from generated snapshot maxima at source generation and reject generation if any existing1MiB RESULT JSON bound would be exceeded. Never silently truncate. Startup execution does not depend on host retrieval success.

Add only AHB operation `READ_AHB_STARTUP(page_index)` with bounded integer index. It returns standard local_driver_result.v1 with samples=[], before=after=0,new_ticks0 and the page envelope under observations; generic wire payload shape/READY remain unchanged. Envelope contains version, page index/count, total ticks, assert/release counts and exact startup records. It never calls tick or assigns protocol inputs. Existing command execution nonce/sequence/cached replay binds delivery to the issued native session. Preserve all original receipts, including cached retries if admitted. No native checksum is invented; host archives original canonical bytes and SHA separately.

The generated AHB command dispatcher rejects STEP_MEMORY until the startup pages have been completely fetched in order. This affects host command admission only, with no RTL edge while fetching. Out-of-order or repeated distinct-sequence retrieval is explicitly rejected; exact cached command replay keeps normal idempotency. All other runtime kinds retain exact original operations/driver bytes.

## Session and observer continuity

AHB begin_case obtains unchanged READY, opens the actual issued execution/case/reset scope and retrieves every page before returning the session to Runner. It validates total count==assert+release, page coverage/order, exact startup index1..N, actual reset envelope, complete13role widths, issued receipt scope/tick0 and exact generated artifact startup contract. Preserve raw pages/receipts before projection; any malformed/missing page aborts/poisons and cannot clock a STEP. No existing three-pin historical raw is upgraded.

Observer v2 has an explicit startup ingestion path. Raw startup indices and command local_tick values retain separate namespaces; internal monotonic measured-edge order continues N+command_tick. Reset-asserted physical edges are preserved and cancel pending state in the same issued scope; address/data acceptance is disabled under actual asserted harness reset. A measured asserted-reset edge establishes the adapter's empty state from its source-authenticated reset logic, rather than a guessed initial state. Release edges follow the same AHB pre-only state machine through the first command. Do not normalize or erase the original local_tick reset to0 at READY.

Only after complete contiguous startup ingestion can the observer mark measured_reset_to_command_prefix=true. This is a narrower claim than CPU retirement, full burst semantics or initial power-on correctness. Missing startup still remains explicitly partial, but a newly declared startup-capable generated artifact cannot silently fall back after failed retrieval. Oldscope reset cancellation and global byte/edge/record/scope budgets include startup records; page retrieval is bounded overhead, not a scope-budget renewal. Runtime event stream and global raw reference IDs survive Runner EventJournal clearing.

## Required software RED before implementation

- AHB source-generation comparison proves all original assignments/edge calls/order and all other runtime branches unchanged except buffer argument/copies and page command admission. No native tool execution in these controls.
- Real wire RESULT parser fixtures with zero ticks; wrong nonce/sequence/tick, duplicate/noncanonical JSON, missing/extra/out-of-order pages, width/reset/count mismatches, byte/page bounds and cache replay controls.
- Reset/release software traces include address accepted on final release edge, following write data on first CMD, read old completion/new address overlap, stalls/errors, reset cancellation, zero release ticks and maximum2048 startup edges. No post double acceptance and no guessed pending context.
- Actual AHB session begin uses source-only transport fixture; page failure preserves current receipt, closes process and refuses every command retry. Runner imports startup plus command stream exactly once across EventJournal drains.

After software/review, prepare a new source snapshot and separately schedule an actual generated native gate. Full archived startup pages, command raw, observer replay, fresh whole prefix, Runner once-only, PID/close and new complete source/build identities are necessary. Current steady-state51/52 software controls and old native chain are insufficient substitutes. CVA6 frozen remote preparation is untouched.
