# AHB manager sampling-domain correction (source-only design)

Attempt1 is immutable failure evidence (bc9d4fe), not a protocol pass. The saved original startup receipt has sixteen measured edges; source and raw observations establish that HREADYEXT is an external subordinate input, HREADY is the manager's aggregate ready output, and HRESETn is the actual synchronized bus reset output. External reset metadata remains literal driver command-domain evidence.

## Proposed declaration and binding

Add one non-protocol `observation` endpoint with exactly two explicit one-bit output roles, `manager_ready` and `bus_reset_n`, bound by the CVW profile to the already observed HREADY and HRESETn ports. Retain the thirteen external AHB roles, including hready=HREADYEXT. Do not modify DUT/adapter wiring, resets, ticks, or driver commands. Runtime metadata carries a versioned domain contract; authenticate it against the profile endpoint, structural ABI, physical export, clock/reset provenance and exact role widths/directions. No CPU-name branch, port-name inference, EXT fallback or reset inversion fallback is permitted. Constructor and identity reconstruction must reproduce the same contract.

Observer input preserves external rows separately from explicit measured-domain PRE/POST rows. Raw native samples and external reset metadata are retained unchanged. Observer version and identity declare the domain correction. Transport startup/page ABI need not change if serialization is byte-identical; an explicit domain metadata schema distinguishes interpretation from transport version.

## Phase and reset semantics

Only PRE is a measured edge. Use measured manager_ready to accept external selected addresses and progress an owned external data phase. Use actual bus_reset_n PRE for cancellation and reset observation. Startup before the first actually observed bus-reset assertion remains raw and unknown; a measured assertion then release establishes the bus-domain prefix. Do not infer synchronizer latency from external reset scheduling.

The top currently does not export aggregate HRESP/HRDATA. External response/data validation is therefore qualified to an owned selected-external data phase; do not claim other internal slave response semantics. A pending external completion must be consistent with external ready. Enforce hold/error release where the external data phase supplies the relevant response context; mark other-slave context as unvalidated rather than inventing aggregate HRESP. This qualification must be explicit in contract and events, not silently treated as a full CPU-bus protocol pass.

## Source-only RED/GREEN and negatives

Replay the exact SHA-pinned original sixteen-edge receipt with the old interpretation to retain `ahb_address_hold` RED. Separately project the same native bytes through the new declared domain binding and verify legal edge11 address progression, no false acceptance while HRESETn=0, all sixteen raw edges retained, actual-reset provenance, pending phase and counts. This is saved-data software replay, not a new native pass.

Negative controls: true global stall with an owned external phase and changed address; inconsistent external/global completion; absent/duplicated/swapped roles; wrong widths/directions/source wires; mismatched domain clock/reset provenance; missing actual reset assertion; tampered actual reset sample; constructor/identity domain substitution; raw retention and poison before another command; global budgets and Runner drain references. Existing external-role/raw and unrelated runtime rendering controls remain in force.

No new build, elaboration, model, remote operation or native attempt is authorized. A reviewed source freeze and independent new snapshot precede a separate exact native GO.
