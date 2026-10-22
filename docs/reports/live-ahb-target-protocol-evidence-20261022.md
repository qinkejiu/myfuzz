# AHB-Lite target protocol reporting: software and native gates

## Scope

The generated target's singular `base_protocol_trace` can now be attached to
the existing Runner protocol evidence and L1 base-coverage report. The Runner
remains the only producer of target raw samples, protocol projections, and
checker findings. The report uses the existing
`runner_protocol_trace_set_report.v1` schema and keeps
`proof_scope=protocol_boundary_only`.

Plural CPU `base_protocol_traces` retain their existing authenticated OBI
observer and projection ownership. The singular path is attached only after
the Runner has admitted a protocol normalizer and checker and the target has a
callable `drain_tick_samples` method. Both paths consume the same complete
ordered Runner journal and retain its event IDs. The coverage consumer clears
pending request/response joins when it consumes the existing global
`reset_barrier`, while keeping accumulated counters and diagnostics.

This report includes software replay of genuine archived target edge samples
and a new native Runner first/fresh gate. The saved DMA provider descriptor
alone remains insufficient; the software gate uses complete archived
direct-access samples, and the native gate captures new direct-access samples.

## Files and checks

- [Protocol observer](../../src/myfuzz/scenario/protocol_trace_sets.py)
  adds evidence-only singular mode; it does not construct a second projector.
- [Runner](../../src/myfuzz/scenario/runner.py) attaches that mode after
  admission and leaves its existing singular target projection loop as the
  sole event producer.
- [Base coverage consumer](../../src/myfuzz/scenario/ip_base_coverage.py)
  drops only pending correlations at a newly consumed reset barrier.
- [Design](../superpowers/specs/2026-10-22-live-ahb-target-protocol-evidence-design.md)
  and [implementation plan](../superpowers/plans/2026-10-22-live-ahb-target-protocol-evidence.md)
  define the intended boundary.

Static checks run on 2026-10-22:

- `python3 -m py_compile` on the three changed production modules: exit 0.
- `git diff --check` on the scoped source and documentation files: exit 0.
- Independent source-only review found no actionable findings in the three
  AHB implementation hunks.
- The initial source slice ran no tests. The software follow-up is recorded
  below; that software follow-up performed no native build/run or remote operation.
  A later local native gate is recorded separately below.

## Archived target software gate

The new [Runner regression](../../tests/scenario/test_runner_ahb_trace_set.py)
reconstructs the current generated artifact and checks its trace, physical pin
maps and clock observation contract against the historical artifact. It then
uses two SHA-pinned historical documents, each with 91 real AHB accesses and
364 pre/post tick samples. Original bytes are retained as deterministic gzip
in [the input manifest](evidence/live-ahb-target-protocol-evidence-20261022/archived-inputs/manifest.json),
so the regression does not depend on ignored `/runs/` files.

Each replay uses an actual file-backed `EventJournal` and the singular Runner
projection path. It retains 728 raw pre/post rows, exactly 91 request/accept/
response triples, and 91 unique boundary certificates with no diagnostics or
pending chains. Coverage records 57 reads and 34 writes. The complete journal
IDs, evidence-integrity cursor, certificate raw links and idempotent repeated
reports are checked. First/fresh historical inputs and their complete current
software replay prefixes agree; normalization affects only the known
top-level Runner execution ID.

Response-value tampering and a response reference changed to the actual POST
sample at the same tick both yield zero certificates and projection-mismatch
diagnostics. A separate synthetic coverage-barrier test proves pending-clear
and counter retention; it does not execute a hardware reset.

The focused file has four cases. The final five-module integration gate is
**77 passed, 67 subtests passed**, exit 0, including Reduced AXI journal
lifecycle, AHB singular reporting, OBI plural reporting, AHB evidence and base
coverage. Its [raw log](evidence/live-ahb-target-protocol-evidence-20261022/software-attempt2/pytest.log)
and [verification receipt](evidence/live-ahb-target-protocol-evidence-20261022/software-attempt2/verification.json)
retain the command, PID, exit status and unchanged before/after hashes of the
selected inputs. This is not a complete source closure freeze. Independent
[AHB source review](evidence/live-ahb-target-protocol-evidence-20261022/software-attempt1/independent-ahb-review.md)
found no remaining blocker.

The first combined attempt is retained as a failure: 70 passed and four old
OBI fixture admission errors. Its [exact differences](evidence/live-ahb-target-protocol-evidence-20261022/software-attempt1/obi-fixture-diff.json)
were four provenance hash leaves and two derived digests. The corrected
retrospective OBI fixture verifies historical source bytes separately from
current bytes, recomputes both identities, and preserves every other field
and generated SV/C++ bytes. Rehashed false-provenance and altered-mapping
controls reject. [Historical source-byte provenance](evidence/ibex-raw-obi-20261017/historical-provenance-bytes/README.md)
and [independent review](evidence/live-ahb-target-protocol-evidence-20261022/software-attempt2/obi-fixture-review.md)
are saved. Historical driver bytes are not represented as current native
execution evidence.

## New native Runner gate

The opt-in [native regression](../../tests/integration/test_runner_ahb_protocol_reporting_real.py)
executes the real generated Caliptra target through ScenarioRunner and a
file-backed EventJournal. Its schedule is step, idle step, warm_all, step.
Each process performs one full-word write to block offset 0x80 and reads
NAME0, NAME1 and STATUS; setup/probes run again after restart. This checks
register bus transfers and ready status, without starting a SHA digest.

[Attempt2 verification](evidence/live-ahb-target-protocol-evidence-20261022/native-attempt2/verification.json)
records actual exit0, **1 passed in 13.47s**, supervised elapsed13.69s and peak
process-tree RSS126,816,256 bytes. First/fresh each have 242 journal events,
35 PRE plus35 POST raw samples and eight unique certificates (six reads,
two writes). Each request/accept/response links to actual PRE pin samples;
AHB transaction keys remain absent with the explicit native-ID gap. Both
reports have zero pending. Full actions, journals, reports, Runner identity
and session identity compare equal without normalizing journal records.

The reset barrier is unique and retains accumulated certificate/coverage
counts. It reports zero pending/cancelled responses. `warm_all` reaps the
old generated process, increments epoch and starts another generated process;
command ticks remain cumulative across epochs. Startup reset is repeated on
each launch. This is a completed-transfer restart check, not an in-flight
hardware-reset or cancellation check. The four first/fresh epoch processes
have distinct execution identities/PIDs and all exit0.

The attempt freezes and archives 361 declared build inputs and three verifier
files, generated SV/C++, artifact, cache manifest and compressed native binary.
Build key is `d5413d45bd9d259218d0cd65c0806406026ca86d0593235f1615d5d4bc013d95`;
binary SHA-256 is `9ff78e38c214ad6b2da4a2f33711a2424387cf4edf001590af4c585ef83ffc1d`.
Declared inputs match before/after execution. Executable observations cover
Python, Verilator and g++; complete transitive toolchain closure is not claimed.

[Attempt1](evidence/live-ahb-target-protocol-evidence-20261022/native-attempt1/verification.json)
is retained as failed: the first native instance finished both epochs with
exit0, then the verifier indexed `kind` on another valid journal schema before
fresh ran. The one-line fix uses `row.get('kind')` for barrier selection and
retains every barrier assertion. [Saved-input reproduction](evidence/live-ahb-target-protocol-evidence-20261022/native-attempt2/verifier-correction.json)
reproduces the original KeyError and finds the unique real warm_all barrier
with the corrected predicate. Independent source review confirmed no
barrier assertion was weakened.

Independent [raw-evidence audit](evidence/live-ahb-target-protocol-evidence-20261022/native-attempt2/native-evidence-audit.md)
recomputed all raw PRE pin links, certificate uniqueness, counts, complete
first/fresh equality and recorded process terminals. The separate
[input archive audit](evidence/live-ahb-target-protocol-evidence-20261022/native-attempt2/input-archive-audit.md)
verified all364 members, current declared inputs, artifact, cache and binary
hashes with zero mismatches. These reviews grant only the boundary stated above.

## Still open

Positive native wait/error/cancel branches remain unproven: this Caliptra
wrapper ties hold and bus error low, so its successful accesses cannot
establish those branches. A capable genuine target or real stimulus is
required. In-flight Runner/hardware reset cancellation also remains open.
AHB's no-native-transaction-ID gap remains visible. This slice does not prove
CPU origin, DMA effect, architectural consumption, retirement, or a bug.
P6/P7/P8, generic same-protocol onboarding, and the six-CPU/four-IP goal
remain open.
