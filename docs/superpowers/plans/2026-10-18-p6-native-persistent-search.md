# P6 native persistent search and feedback implementation plan

Status: **proposed source interfaces and acceptance gates; no implementation or
execution in this change**. Implements Stage C of
[the next-step record](../../reports/p6-next-implementation-20261018.md).
The bounded three-case real gate is accepted at its frozen scope; it is not
persistent RFuzz search, four-feedback acceptance, or P6 completion.

## 1. Evidence baseline and concrete integration gaps

Use [the actual directed gate](../../reports/p6-native-persistent-directed-20261018.md)
and its archived `run-attempt3/positive/first.json.gz`, not a guessed CPU model.
The retained archive SHA is
`dc399360c1b72d5754effad7ba0563b823ce2cffa396bef85b93cbb81937d784`.

The first selected source word has these actual references:

| Observation | Exact saved evidence |
|---|---|
| Accepted native request | CPU event 357, local tick 47; PRE `m_req_valid=m_req_ready=1`, read at `0x200`, BE15; artifact-declared physical instruction marker is 1 |
| Memory producer | event 359, `producer_event_id=357`, transaction channel `memory`, epoch0/sequence9; four writer IDs equal the admitted instruction action; `data_hex=1305e003` |
| Actual response consumption | CPU event 371, local tick48; PRE `m_rsp_valid=m_rsp_ready=1`; `data_rsp_source_sequence=9`, epoch0, actual rdata65013011 |

This joins a real instruction-marked request, authenticated memory writer
snapshot, and actual response consumption. It establishes a bounded fetch
response consumption witness, **not retirement**. The native service uses
channel `memory`; ordinary data reads use the same channel.

Three source gaps must be resolved explicitly:

1. `ScenarioRfuzzExecutor` calls `session.submit_case(case)` directly. Supplying
   the current plain session bypasses the guards in `PicoNativeOnlineRuntime.submit`.
2. `_InstructionEvidence` and `_online_consumed` recognize channel `instr`.
   Widening their condition to arbitrary `memory_read` would count data reads,
   offered-but-unaccepted requests, and responses the CPU never consumed.
3. `_GpioPinIrqEvidence` is a gpio_b/single-bit/IRQ pilot. Its implicit source
   selection cannot certify gpio0's eight-bit sample, PADIN read and CPU return
   path. The native profile has no accepted IRQ contract.

## 2. Lifecycle alternatives and chosen first increment

| Alternative | Benefit | Required scope / risk |
|---|---|---|
| Guarded `ScenarioSession` subclass, reused by current executor | Existing executor's actual submit call necessarily enters the guard; keeps its session type admission, event journal, timings, source ownership and replay path | Guards must be owned by the session, with one decoder commit owned by the executor; constructor/finish/replay and failure paths need review |
| Generic explicit lifecycle contract (`before_submit`, `after_submit`, `after_commit`, abort) in executor | Suitable for several protocol runtimes with explicit producer capabilities | Larger shared executor API, exception-order and replay changes; arbitrary injected callbacks must not acquire evidence authority |

**Choose the guarded session for the first working increment.** Add a
code-owned `NativePacketSession(ScenarioSession)` near native online assembly;
factor the existing packet guard into one implementation used by directed and
RFuzz entries. No duplicate guard implementations or CPU-name switch in the
executor. Keep the generic lifecycle contract as a later generalization after
one real search gate establishes the actual consumption requirements.

### C1: guarded execution interface

- `submit_case(case)` validates one four-byte source/support fragment at the
  declared packet cursor, actual waiting instruction address and all four
  existing pending/queue conditions **before any instruction/pin injection**.
- Call the inherited real `submit_case` exactly once, with the existing 128 CPU
  operations and existing GPIO schedule. Check actual next waiting address is
  previous cursor+32, response/target/event queues empty and no uncertain status
  before returning the real result. Add no clocks to make the guard pass.
- Session records completed packet position independently of the decoder;
  `ScenarioRfuzzExecutor` remains the sole `commit_candidate` owner in its path.
  Directed runtime remains sole decoder commit owner in its path. Never call
  `runtime.submit(raw)` from an executor that already decoded/commits a case.
- Any pre/post physical guard, actual-submit, or post-submit decoder-commit
  failure makes the operation terminal and finalizes the original runner once;
  preserve the first exception, actual attempted case and complete prefix.
  An executor commit failure must propagate terminal state to this guarded
  session, rather than allow a later direct submission. Review the actual
  existing executor failure branch before selecting that narrow notification
  seam; do not add a callback that can assert success.
- Pure candidate rejection before physical effects can be retried; it does not
  consume a packet. No session reset/factory call/RAM replacement per candidate.
  Bound begin/warmup and finish exactly as in the real directed entry.

## 3. C2: native fetch receipt and capability-based consumption

Add `scenario/native_instruction_fetch.py` as a bounded reducer over the actual
runner journal and the source-pinned native service identity. Proposed schema:
`native_instruction_fetch_receipt.v1`. Input capability descriptor:
`instruction_fetch_consumption.native_memory.v1`.

Eligibility requires the registered native service schema, actual artifact kind
and instruction-marker declaration, process/nonce/epoch identity, real event
continuity, and selected runtime path/source ownership. Bind descriptors to
code-owned producer implementations and actual source/build identity; an
arbitrary dict, injected factory or renamed CPU is not producer admission.

Receipt fields must carry:

- source admission ID, action ID, component/path/source IDs and packet address;
- actual process scope and reset epoch, full transaction key including channel
  and source sequence; producer version/source/artifact binding;
- accepted CPU event ID and raw PRE sample reference, marker identity/value,
  aligned address/read/BE, actual request handshake;
- memory_read event ID, producer-event join, four bytes, four writer IDs and
  generations; every admitted byte must match, not merely one matching lane;
- consumed CPU event ID, actual PRE response valid/ready/value, exact pending
  request epoch/sequence and once-only consumption;
- explicit `proof_scope=native_instruction_response_consumed`, with
  `retirement_observed=false` and no execution/IRQ authority.

Reconstruct per-process single-outstanding sequences from the actual accepted
events. The accept event's current `data_rsp_source_sequence=0` is **not** its
new request sequence: derive that accepted sequence from the actual journal,
then join the memory transaction and consumed pending sequence. Reject gaps,
duplicate/reused identities, reset/uncertain frames, wrong marker, data/MMIO
requests, writer/value mismatches, and any missing response. A waiting offered
fetch or service-side memory read alone emits no consumed receipt.

Add a narrow versioned consumer registry for fetch-consumption semantics in
the executor; preserve the current `instr` consumer unchanged as its existing
capability. Native instruction consumption and reporting must use the new
receipt; do not edit `_InstructionEvidence` to accept all `memory` traffic.
The one-word ADDI source does not encode a complete MMIO access, so its tail
association must use the fixed packet contract and actual observations; do
not make `_mmio_access` infer the immutable tail from candidate bytes.

## 4. C3: GPIO byte and four feedback classes

Add a separate, code-owned non-IRQ GPIO-byte consumption capability. Require
the admitted byte/action, actual injected port sample and full selected mask,
actual synchronizer/target PADIN response, Router delivery key and CPU response
consume. Do not reuse the gpio_b/single-bit IRQ witness or count any sampled
input as completed propagation. Current artifact lacks separate APB phase taps;
claim backend transaction and physical GPIO evidence only.

Keep stage, edge, state-transition and loop feedback separate:

| Feedback | Minimum real witness / attribution |
|---|---|
| Stage | Actual named native fetch consumption or GPIO-byte sample for the admitted source; explicit event/action/path reference |
| Edge | Actual matched request/target response/Router delivery/CPU consumption, with full transaction identity and endpoint binding |
| State transition | Actual before/after GPIO register/output or RAM writer-version transition, tied to actual source/case and consumed events; repeated equal evidence gives no novelty |
| Closed loop | Ordered full source→target→return consumption chain for that source admission, with all declared non-retirement terminal hops and no omitted downstream join |

Introduce a separately versioned native transport-chain producer and explicit
hop contract if C2/C3 provide all required joins. Current
`runtime_chain_certificate.v1`, `ChainCertificates` and the existing
ClosedLoopFeedback frozen hop/scope validator include Ibex retirement/IRQ
requirements; **do not weaken them, borrow their schema, or inject an apparent
Ibex producer**. The new consumer must select the registered schema/capability,
preserve old behavior, deduplicate full certificate/feature IDs and reject
same-ID/different-evidence reuse. No generic caller callback grants authority.

Initially enable stage/edge/state only when their actual witness exists;
closed-loop-required admission must refuse until the separate native chain
producer and independent validation are complete. Label missing hops explicitly,
without counting them as a successful loop. Then connect accepted native
feedback to existing energy allocation through explicit source/path attribution
and preserve allocation before/after, deltas and deduplication evidence.

CPU and IP sources must both receive actual selections/consumption and their
own next-case weights. The known packet computes `A XOR B`; this arithmetic
check alone is not a source certificate or a terminal provenance proof.
Equal/same-value candidates cannot be used to invent a state transition.

## 5. C4: packet-aware documents and full replay

Keep `native_online_packet.v1`: source word4 bytes, immutable tail28 bytes,
stride32, 96 source packets at `0x200..0xe00`, plus one unfilled end guard.
Manifest binds all 97 reservations, tail/bootstrap bytes, RV32 source grammar,
both source masks, schedule, producer contracts and source/tool/build identities.
Current generic document reconstruction explicitly lacks native packet support;
add a closed version dispatcher or continue refusing that reconstruction. Never
silently use contiguous four-byte slots for a recorded 32-byte packet decoder.

Cap live accepted cases at96 and at the configured max_cases, and validate
RFuzz budget/max_tests before launching. Rejected candidates spend no slot;
attempted/uncertain physical cases cannot be relabeled as harmless rejection.
Record reservation exhaustion as a typed bounded terminal outcome, not a DUT
finding or automatic new session. Keep IRQ requests unsupported before begin.

Save initial warmup→all cases→single finish in one complete prefix. Full cold
fresh uses a new factory/process pair and explicit packet reconstruction;
warm fresh may reuse verified build caches but still requires new processes,
new nonce, pristine declared RAM/Router and replay from initialization. It is
not replay of only the final packet or reuse of live session state.
Compare whole plans/trace, typed receipts, allocation/feedback identities and
terminal queues under declared identity normalization only. Distinguish source
candidate replay from a new feedback-driven search; replay must not redraw
source choices or replace the saved weighted decisions.

## 6. Owned implementation increments and verification plan

1. **Guarded session:** native assembly/runtime and session tests only; review
   direct executor call, once-only commits, pure refusal vs terminal physical
   failure, unchanged128 budget and no per-case reset. Preserve directed gate.
2. **Native receipt:** native reducer/capability consumer and tests. Saved raw
   archive controls must reproduce357→359→371/sequence9. Mutate each marker,
   handshake, producer ID, writer lane, sequence, consume value and scope;
   each mutation must remove/refuse consumption. Data reads must never count.
3. **RFuzz adapter/documents:** dedicated native entry, explicit targets,
   capability registry and packet-aware replay dispatch. Test96/97 boundary,
   one-word stride, immutable tails, decoder commit failure and unsupported IRQ.
4. **Native feedback producer:** separate schema/consumer and attribution;
   negative controls remove each downstream hop, replay duplicate certificates,
   reuse IDs with changed evidence and attempt an Ibex-schema substitution.
5. **Actual real gate:** new independently frozen remote operation, exact
   source/tool/host closure and directory maps, canonical nonblocking lock,
   original process/nonce/epoch and queues logged. Run an actual persistent
   RFuzz session; demonstrate both source directions and all four valid feedback
   classes affecting subsequent source/path weights. Require cold/warm full
   fresh plus actual controlled-response negative and independent audits.
6. Only then consider row5 campaign matrix/uniform-independent baselines;
   protocol rows2–4, throughput and complete P6 remain separate.

All tests and real gates above are **future verification tasks**, not results
of this planning change. No model, remote command, tool query or test was run
to write this plan; archived JSON/raw samples were read using standard-library
file, gzip, tar and JSON handling only.
