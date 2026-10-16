# CPU AHB observation software increment

2026-10-17. Source-only implementation, independent review pending. Software controls: **51 passed in 1.30s**. No build, model, lint, elaboration or native execution occurred. Test subprocess guard permits only git; it blocked an initial attempted frontend before execution.

## Implemented boundary

The renderer's AHB branch adds 13 read-only tap assignments from `_shape`'s exact ABI-derived wires. Every original DUT/adapter connection remains unchanged. An AST control removes exactly the new helper and its AHB call and compares the entire remaining renderer against the pinned original. The existing driver already emits optional protocol_taps in each pre/post sample; no READY/wire protocol change was made.

GeneratedNativeMemorySession has one default no-op hook after result/control/sample-pre binding and last_samples capture, before response mutation and backend effects. Only GeneratedAhbMemorySession overrides it. The AHB session captures the current actual receipt, clears the previous receipt before each step, catches all ordinary Exception failures, records uncertainty, aborts transport and refuses subsequent steps/resets before commands. Invalid external inputs before command carry possible_effects=false. Missing receipt after lost reply remains explicitly unknown, not a previous edge.

Independent AhbCpuObserver has a code-owned versioned 34-bit-address/32-bit-data/4-bit-strobe shape. It completes the old data phase before accepting a new address on the same measured pre edge; a write captures actual data/strobes on the following pre phase. Wait continuity checks are the declared AHB subset, with response-error address release allowed. Read data and HRESP are retained at completion. HRESP1 is a bus error observation, not automatically a protocol bug. Post is evidence/limited continuity only, never a second transfer. HSIZE/HBURST/HPROT/lock remain raw values without execution claims; zero strobes remain zero.

Events remain observation_only/runtime_accepted=false/semantic_accepted=false. Observational correlation IDs are distinct from nonexistent native transaction IDs (native_transaction_key=null). Stable runtime_events list feeds actual Runner once-only import. EventJournal may clear that list in place; raw references use monotonic observer_record_index and global event budgets, preserving cross-drain address/write-data/completion links. Reset cancels old-scope pending records before transport and keeps historical scope data.

Global defaults: 100000 edges, 64MiB serialized raw stopping threshold, 1000000 event threshold, 256 scopes. First offending raw edge and terminal diagnostic are retained; budgets are stopping thresholds with diagnostic slack, not strict allocation caps. Exhaustion/poison cannot be renewed by a new scope or reset. Aggregate accepted/completed/read/write/stall/error counters persist across scopes.

## Actual Runner identity gap closed

The preexisting strict generated-session identity sets had no AHB service identity, so the historical direct-step Caliptra chain did not prove standard Runner admission. The new AHB-only closed set authenticates exact service schema/component/memory policy, actual code-owned observer defaults plus trace binding, boot constraints, fully regenerated artifact and build identity. AHB JSON comparisons preserve bool/int distinctions; unknown fields and altered mappings/budgets/boot/build fail. Existing class resolution already identifies the real GeneratedAhbMemorySession factory; no broad class or authority allowlist was added.

Software controls use real profile binding, source-byte contract verification, renderer, driver generation, constructor and identity regeneration. Saved elaborated ports and saved frontend manifest replace fresh frontend execution; build tool identity is explicitly a software fixture. These are software integration controls, not a fresh elaboration/source acceptance or native result. The actual Runner import and EventJournal drain paths execute with those software fixtures.

## Evidence and remaining gates

`evidence/cvw-ahb-implementation-20261017` contains RED/GREEN logs, original renderer bytes and freeze SHA. Source audit/design: `.superpowers/sdd/cvw-ahb-cpu-event-design.md` and commit198ba7d. Historical first/fresh raw retains only HCLK/HREADY/HRESETn; its three bits cannot be transformed into 13 physical roles. Tests reject that historical artifact's missing taps and preserve its original sample.

Every scope begins with `ahb_prefix_unknown`: CPU/adapter reset-release ticks can accept an address before READY, which existing command samples cannot recover. This increment deliberately provides a partial measured prefix. Complete CPU protocol-prefix evidence requires a later bounded, versioned startup tap record sampled at the actual unchanged reset/release tick boundary and continuing to the first CMD. That design is the next gate, not implemented here. It must not alter CPU/adapter timing or invent an initially empty pipeline.

Independent review, startup capture, and a separately scheduled new generated native/Runner fresh-prefix gate remain open. No retirement, source authority, native-reset authority, register authority, burst conformance or full CPU protocol completion follows from this software result. CVA6 remote frozen preparation was not modified.
