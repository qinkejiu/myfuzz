# Bounded memory record grammar v2

The generic mixed runtime opts into `bounded_memory_record.v2` when
`memory_flows=True`. All records remain exactly four bytes. The existing F3
little-endian uint32 record stores a word at the reserved scratch address
`runtime.result - 4`. Existing non-memory F1 instructions retain their meaning.

`F1:03200000` is a newly admitted **typed RAM-read token**. Although these bytes
encode `LW x0,0(x0)`, the runtime does not execute that instruction verbatim.
The lowerer generates `LUI + LW x2,...(x1)` for the same reserved scratch word
used by F3, checking the address and permissions against the compiled
`InstructionImageSourceBinding` RAM range. Trailing NOPs preserve the existing
persistent-session schedule. Other F1 loads and stores remain rejected.
The token gives no arbitrary address or register access. It never reads RAM
through a host shortcut to stand in for DUT execution.

For example, the public record catalog may contain `F3:55000000` and
`F1:03200000`. A two-case run can establish the RAM word through a real CPU store
and subsequently read it through the real CPU data port. The shared constructor
opts into CPU commit/readback receipts, installs the exact CPU service's commit
journal and Runner memory dependency consumer before begin, and repeats the
same installation in fresh construction. Runs with `memory_flows=False` retain
the previous receipt configuration.

The memory case's `memory_read` is `observed` only when all four historical
byte-version certificates match the issuance transaction, resource, generation,
versions, writer references and values, and the same data-port OBI transaction
has a complete case-local acceptance/response with matching address and read
value. A successful submit, matching values alone, an incomplete response or
missing writer/version evidence leaves this observation `unknown`.

Evidence scope remains modeled host persistent RAM consumed over the DUT OBI
port. CPU retirement and instruction-to-store causality remain `unknown`.
The documentary read projection grants no live prerequisites, source-origin
credit, execution authority or policy reward. The installed-provider audit
bridge also keeps current-state observation and cross-testcase attribution
`unknown`; it cannot replace a live RAM state provider. Native original/fresh
execution is required before claiming this configured path has run successfully.

Cost limitation: the current physical-beat reconstruction reads the session
prefix, matching the existing F3 observer. The installed historical classifier
validates a bounded ledger, not an incremental certificate stream. This path is
a mechanism gate, not an efficiency result; a bounded incremental OBI/certificate
reader is needed before measuring large campaigns.

## Live typed-catalog strategy adapter

An explicit mixed catalog consisting only of F3 word stores and
`F1:03200000`, with at least one of each, selects `live-ram` search through the
normal descriptor CLI. Other mixed catalogs retain their prior selection path.
`ram_case_adapter.py` attaches to the same admitted runtime and uses the same
public record catalog for state, uniform and legacy policies.

The opaque `ram.py` installation accepts only the actual compiled mixed runtime,
its installed Runner consumer and its actual ScenarioSession. Queries validate
the running native CPU process and runtime identity, then use the production
`LiveMemoryEffectTracker.retained_ram_witnesses` reader to inspect the exact four
current STORE byte resources without creating a host read transaction. Missing,
expired, overwritten, reset or replaced authority resources are unknown. Writer
case ownership is read from completed actual session receipts and checked
against the same Runner journal; CPU TransactionKey.testcase_id is not used as
search case ownership.

The policy frontier changes from `ram:written` to `ram:consumed` only after
attributed current store resources are available. Completion and rewards require
the actual read issuance's four version certificates, a complete matching DUT
OBI read, exact equality to the current four-byte resource identity, and actual
writer/read receipt boundaries in different cases. Relation novelty uses only
the declared resource and finite value class. Delayed reward is split
conservatively between the attributed writer decisions and the actual consumer;
overwritten or reset pending writers are censored. Repeat consumption cannot
create novelty from different event IDs or versions. Retirement and upstream
instruction/source causality remain unknown throughout.

Strict fresh reconstructs the runtime, current state, case ownership and native
read join. Original measured policy costs are replay inputs for deterministic
policy scoring; fresh measured costs are separate observations. Neither saved
state nor saved ownership restores execution authorization. The search manifest
records compiled source bindings, state transitions, costs, terminal censored
credit, and credited semantic relations. Source-code snapshots bind the added
provider and selector modules in the existing descriptor source manifest.

## Measured interaction metrics

`live-ram` exports `certified-ram-dut-read.v1` through the common search metrics.
The campaign passes its actual execution clock and start instant into the
selector after native initialization. After a live relation is authenticated,
its first semantic observation is timestamped on that same clock. Terminal
pending-contribution handling completes before the clock stops; finalization,
within-invocation replay and fresh replay are outside this search interval.
Decision durations and search elapsed time are measured directly. Neither the
sum of policy costs nor original replay cost inputs supply event timestamps.

Each invocation saves `ram-measurements.json` with actual certified relation
keys/times, useful consumer cases, decision durations, measured action costs and
search duration. Its digest is bound into the search manifest. Fresh validates
the original measurement binding, reruns the native proof and checks the same
certified semantic set, while recording its own independently measured times.
Consequently wall times may differ without weakening semantic fresh checks.

With a finite seconds budget, the existing comparator computes timed unique
interaction coverage, AUC and useful-case rates using these actual events.
Without that budget, observed counts and first-hit times remain available;
AUC and budget-normalized rates are unavailable, and primary fixed-budget
comparability is refused. RTL coverage remains unavailable unless separately
measured; the interaction metric retains its host RAM plus DUT OBI scope.
