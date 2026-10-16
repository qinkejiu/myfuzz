# Measured AHB startup capture software increment

2026-10-17. Software freeze for independent review. **96 passed in3.40s**:30 startup controls,52 steady AHB controls and14 preexisting Standard mini-driver controls. No DUT build, model, elaboration or native execution; remote frozen copies untouched. Only the explicitly authorized standalone C++ parser and protocol mini-driver were compiled/executed, without DUT/simulator dependencies.

## Actual generated capture

AHB generated drivers replace only each startup-loop `tick(dut,nullptr)` call with a passive wrapper that reads actual model reset before/after exactly one unchanged tick, retains its original full pre/post sample, and appends index/reset metadata. All reset assignments/evals, assert/release loop order/count, actual tick body, final tick0 reset and five-token READY remain byte-identical. The existing13 `_shape` ABI-derived taps carry all raw AHB roles. No response, initialization, clock edge or DUT/adapter connection was added.

A generated AHB-only contract pins assert/release counts, page/count/serialized bounds and namespaces. Total ticks<=2048,32 records/page,<=64 pages. Native serialized record buffer and conservative all-receipt storage bound each<=8MiB; each page RESULT JSON bound<=existing1MiB. Bounds use exact declared snapshot maxima, decimal maximum widths and raw string encoding, plus conservative record/envelope overhead. Generation rejects excessive bounds; native guards reject oversized records/buffer/page rather than truncating. These are serialized storage bounds, not a C++ allocator heap cap.

`READ_AHB_STARTUP(page)` retrieves the actual buffer with no tick or protocol input assignment. It uses canonical existing RESULT with samples=[], tick_before=tick_after0/new_ticks0, page under observations. Every page is ordered and the generated driver rejects STEP before all pages complete. Page progression occurs only after successful replay.finish of RESULT; cached command replay neither clocks nor advances page order twice.

## Shared ABI opt-in decision

Root explicitly selected a minimal shared-header extension instead of an inline parser copy. `CommandSet::Standard` remains the default for parse_command and BoundedReplay; only `AhbStartup` permits READ_AHB_STARTUP page0..63. Replay's independent request revalidation uses the same selected command set. AHB generated CPP opts in at both sites. Standard rejects the operation and all other runtime registries retain their closed operations. The shared header's SHA changes build identities honestly; other runtime CPP bytes and READY wire remain unchanged. Old native artifacts are not relabeled as this source version.

Controls compare complete generic template defaults against pinned old template bytes and native-memory/AXI-Lite synthetic template outputs byte for byte. Actual CVW generation uses saved elaborated ports/frontend manifest software fixtures; it compares the old/new full startup main prefix and tick body exactly after reversing only the passive call name. Root's d117b0a pure renderer extraction is reversed structurally in the existing full AST control, preserving the admission prefix and complete generation body.

## Session, raw and observation state

AHB constructor and strict Runner identity reconstruction recompute the startup contract from generated ABI widths and exact code-owned bounds, require the new AHB driver generation version, and pin it in observer v2 identity. Unknown/mutated contract, boot, mapping, version or build fields refuse admission.

After unchanged READY, begin_case retrieves/validates every actual issued RESULT page before returning a usable session. It preserves each original parsed receipt in a lifetime list and emits it into the stable runtime event stream before projection. Those receipt bytes and all startup raw edges consume the same global byte/event budgets; actual startup edges consume global edge budget. The session refuses an impossible known startup edge budget before starting transport. First overrun/failure remains retained with uncertainty; counters cannot renew across scopes. Page loss clears the current receipt first, so diagnostics never borrow a previous page. Any ordinary Exception aborts/poisons and subsequent STEP/reset/begin cannot clock. Raw parse failures without a returned receipt remain unknown.

The observer validates contiguous startup index1..N, actual reset metadata, exact native sample tick and13 role shapes. Actual asserted-reset edges establish the adapter's source-declared empty pipeline; release edges continue the same AHB state machine. A late-release accepted address can complete on a later command; write data remains the following phase. Startup raw local_tick stays1..N, command raw local_tick restarts1, and a separate measurement_tick is N+command_tick. Command ticks must be contiguous after complete startup. Only after the first fully measured command does measured_reset_to_command_prefix become true. Missing/invalid startup cannot silently fall back to prefix_unknown on a newly declared capable session.

Global observer_record_index remains independent of Runner list clearing. Actual Runner/EventJournal controls drain startup and command rows once, preserve cross-boundary references, then add0 on a repeated drain. Two independent Python session constructors with constructed parsed-wire transport compare the whole observer/Runner prefix, normalizing only issued typed execution paths. This is explicitly a software fresh control, without PID/native evidence. All events retain observation_only/runtime_accepted=false/semantic_accepted=false/native_transaction_key=null; capture grants no source, retirement, register or native-reset authority.

## Remaining gate

Independent source review, a new immutable source snapshot, and root's exact authorization for a new generated native CVW/Caliptra or RAM gate remain required. Historical first/fresh has only3 ordinary physical bits and cannot substitute for new13-role startup evidence. The future gate must archive startup pages/receipts, command raw, full observer/Runner stream, replay/fresh equality and actual source/binary/PID/reaped exit. No new native pass or complete CPU protocol acceptance follows from these software controls.

Receipts/source pins: `evidence/cvw-ahb-startup-20261017/`. Prior steady-state source/review: da4605f/93a7bda. Design080280d is amended by root's shared CommandSet opt-in interface decision described above; the READY-altering and duplicated-parser alternatives were not implemented.
