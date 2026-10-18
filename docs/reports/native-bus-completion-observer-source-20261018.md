# Native bus completion observer: stage④ source increment

Status: implementation and author source review only. No tests, project imports,
frontend, build, model or remote execution were performed. The old directed gate
does not validate this source or its newly enabled observation path.

## Actual source path

Four production files change: new `scenario/native_cpu_events.py`,
`local_harness/native_session.py`, the actual deferred session in
`scenario/picorv32_native_cpu_example.py`, and a small native dispatch/raw-journal
branch in `scenario/runner.py`.

Only an artifact carrying the verified opt-in
`native_completion_observation.v1` installs the code-owned observer. Both base
and deferred STEP_MEMORY paths pass their already parsed and handshake-checked
DriverReceipt, before actual service. No request, response, input ownership,
clock, instruction acceptance or queued target service policy changes.

The observer retains one actual request key and checks native tuple/marker
stability, actual backend acceptance, response consumption, command execution
nonce/sequence, tick continuity, epoch and memory sequence. The real RAM service
binds its returned immutable ReadSnapshot to that accepted key. Routed MMIO
remains the actual target path; its backend response is joined using the real
pending response sequence, not a fabricated RAM snapshot.

The adapter RTL and driver tick ordering require three separate observations:

1. PRE backend request acceptance enters RESPONSE at that edge.
2. A later PRE backend response consumption enters COMPLETE; that tick's POST
   native ready/rdata is an offer, not CPU completion.
3. The next actual PRE native valid/ready handshake emits
   `native_bus_completed`. Its native returned value must equal the consumed
   response. Its POST may already carry a different CPU tuple.

Marker1 identifies an instruction bus transfer, while marker0 identifies a data
transfer. Instruction-marked writes, changed markers/requests, wrong pending
sequence, response errors, duplicate/out-of-order completions, tick gaps and
bounded missing completion refuse observation. Observer failure poisons it and
aborts the owned process while preserving the primary exception. A reset clears
incomplete observer state; it never converts cancellation into completion.

## Raw stream and limits

The complete real PRE/POST sample frames drain through Runner's existing tick
sample journal, with actual driver scope and any clock-edge counters retained.
Dedicated diagnostic/completion events point to that real raw producer event.
Native dispatch does not instantiate the OBI trace-set observer or claim generic
peripheral checker support. Default artifacts have no observer and expose no
callable tick drain, preserving Runner's legacy output routing. The bounded
pending raw queue refuses at4096 undrained frames. Source changes legitimately
change artifact identities; no byte-identical identity claim is made.

All new events use `native_bus_observation.v1`, transfer-only proof scope,
source-authority=false and retirement=false. Actual RAM read snapshot references
are retained, but stage⑤ exact admitted source-byte/writer matching is absent.
No source_consumed event, feedback energy, IRQ, retirement or closed-loop
certificate is granted.

The new scopes intentionally retain actual process nonces. Existing typed fresh
normalization has no rules for these newly introduced scope fields. A future
opt-in gate needs explicit narrowly typed normalization and guarded fresh
reconstruction before claiming semantic fresh equality. This increment does not
rewrite nonces, extend replay schemas or claim a runtime pass.

Author source review checked default dispatch, base/deferred service order,
offered-request stability through completion PRE, completion POST switching,
real snapshot binding, failure cleanup and single-outstanding sequencing. This
is source reasoning, not execution evidence; independent review and an actual
new source-frozen gate remain required.

## Lifecycle source correction (`34f01e3`)

Independent source review found that backend response consumption cleared the
old pending counter one tick before the actual native CPU completion PRE. The
source now counts the same outstanding transfer until the observer completes it;
Deferred MMIO uses the combined parent counter without double counting. Both
reset paths explicitly cancel observation state, while abort poisons it and a
failed observer cannot launch another case. Direct close with an incomplete
transfer closes the owned process first and then raises the original protocol
error, retaining any cleanup exception as a note.

The reviewer re-read these changes and closed the Important finding at source
level. No tests, imports, builds or DUT runs were executed for this correction;
the previous frozen directed gate does not validate this new source.
