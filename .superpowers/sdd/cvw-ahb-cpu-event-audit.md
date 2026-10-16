# CVW AHB CPU events: source audit before implementation

Read-only root audit, 2026-10-17. No new event implementation, test, build or native execution in this audit. Candidate later work follows the user's CPU/IP event expansion requirement; current Ibex/CVA6/BOOM gates retain priority.

## Actual seam

- GeneratedAhbMemorySession subclasses GeneratedNativeMemorySession. Native completion service verifies pre_backend control echo, sets last_samples, and only then commits/routes the accepted beat. It currently has no live runtime_events stream for AHB physical pipeline projection.
- runtime_renderer._AHB_LITE is exact address34/data32, 13 roles: htrans/haddr/hwrite/hwdata/hwstrb/hsize/hburst/hprot/hmastlock/hsel output; hready/hrdata/hresp input. Real subordinate inputs are HREADYEXT/HRDATAEXT/HRESPEXT; the separately exported CPU HREADY is not that declared input role. Match actual ABI bindings rather than deriving pin names.
- Renderer AHB branch currently exports the actual physical ABI through ordinary samples; it does not append cpu_protocol_traces. OBI's explicit protocol_taps scheme cannot be assumed present on this branch.
- ahb_lite_memory_target accepts address/control in IDLE, latches write data/strobes in ADDRESS on the following edge, exposes the backend request in WAIT_DATA/WAIT_SERVICE, and finishes in COMPLETE. COMPLETE with actual rsp_valid simultaneously captures the next selected NONSEQ/SEQ address. Post-edge observations must never be counted as a second edge acceptance.
- Target uses HWSTRB for write lanes and transports HSIZE/HBURST/HPROT/HMASTLOCK without implementing their full semantics. An observer can preserve these actual fields; it cannot silently claim burst/cacheability/lock execution support from observing them.

## Reuse that would be incorrect

IpProtocolEventNormalizer._consume_ahb_lite is for the generated single-transaction register manager. While its active data phase exists, any new offered address is reported single_outstanding_address_overlap, then it returns after completion without accepting that new address. CVW's real pipeline supports exactly that overlap at a completion edge. Reusing this target-side normalizer for the CPU would create false protocol errors and lose real addresses. Do not change its existing target contract merely to accommodate CPU traffic.

## Required implementation properties

Use a separate, receipt-bound CPU AHB observation contract with exact admitted ABI shape and real pre/post physical mapping; derive role binding from declaration facts. Preserve 34-bit address independently of 32-bit data and all physical response/control values. Track accepted address versus following data phase, stalls and same-edge old completion/new address. Raw unknown/service failure must be retained and terminally poison before any further command; classify possible effects explicitly. Bound raw bytes/edges/scopes/records globally, preserve stream identity and integrate ScenarioRunner's once-only runtime_events drain. Reset cancels pending observations in their old scope. Events remain observation_only with no source/runtime/semantic authority.

Software controls must cover old-complete+new-address, delayed write data, wait holds, HRESP data completion, reset, malformed sample/receipt, all Exception paths, diagnostic budgets, and retry before clock. Native evidence should first replay saved CVW/Caliptra full physical samples to prove field bindings, then use a new frozen generated CVW session/Runner and fresh full prefix; offline history is not a new native result. A target's tied-low HRESP does not prove CPU error handling.

No claim of completion follows from this audit; actual live AHB event implementation and native gate remain open.
