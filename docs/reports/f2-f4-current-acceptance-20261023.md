# F2/F4 current-source acceptance reconciliation, 2026-10-23

Status: all eight final frozen gates are terminal and independently audited PASS.
Bounded F2 directed/file-entry and F4 compatibility acceptance is complete.
Unified F2 RFuzz (original Task5) and system acceptance remain open.

## Current candidate gate ledger

Base HEAD: 4186ff565280d7d6729b010981f2741cea1d3b4c plus frozen working-tree changes.
The common 2098-entry source-map file SHA256 is
acef7a2cb7aece5b8b74a4f3af48fad8ee9693c071c2588c3671d801119a1da4.
Root compared software5, F4Timer3/SPI3 and F2Timer2/CVE2Timer2/SPI2 initial maps;
all are equal. Native RTL/build/tool identity is verified separately per run.

| Gate | Actual state | Evidence qualification |
| --- | --- | --- |
| software attempt5,53modules | accepted focused software gate | independent audit PASS;1001passed,31skipped,53subtests |
| F4Timer/CV32E20 attempt3 | accepted bounded2cases | independent original/fresh538-event audit PASS |
| F4SPI/CV32E40P attempt3 | accepted bounded2cases | independent original/fresh2806-event audit PASS; no CPU error-pin observation |
| F2Timer/Ibex attempt2 | accepted bounded1case | independent original/fresh631-event and typed-report audit PASS |
| F2Timer/CV32E20 attempt2 | accepted bounded1case | independent full raw/version/typed-report audit PASS; actual error pin observed |
| F2SPI/CV32E40P attempt2 | accepted bounded1case | independent full4355-event/typed-report audit PASS; no CPU error pin |
| F2 renamed Timer attempt2 | accepted bounded1case | compute_unit7/target_unit9; fullfresh/31hashes and independent audit PASS; no inherited hierarchy proof |
| F2 wrong address attempt2 | accepted refusal control, actual/expected exit2 | independent audit PASS; after D2/D3, before runtime construction |

Bounded file-entry/F4 compatibility acceptance only; unified F2 RFuzz and system acceptance remain open. Earlier attempts below keep their own
source/terminal boundaries; they are not upgraded by later fixes.

## Why this run is required

Current committed source had the focused shared-audit test but no corresponding
module. Reproduced the missing-module assertion before editing; retained log:
`.superpowers/sdd/compiled-f2/task5/process-audit-current-red.log`.
F2/F4 duplicated receipt/process/diagnostic code while F2 also imported the
construction diagnostic helpers from F4. Extracted the exact common operations
into `compiled_process_audit.py` and made each flow inherit the focused
`BuiltProcessAudit` mixin. Each retains its own executor, checker, binding,
error prefix and execution-audit schema. No native storage/source authority,
receipt validation or saved-output check is relaxed.

The focused development command passed31tests in35.08s. Independent source
review: Spec PASS / Quality PASS; evidence and pre-edit baselines are in
`.superpowers/sdd/compiled-f2/task5/shared-audit-current/`. These checks do not
replace final frozen software/native evidence.

## Frozen gate scope

Supervisor: `.superpowers/sdd/f2-f4-current-gates-20261023/run_gate.py`.
[Evidence root](evidence/f2-f4-current-gates-20261023/). The initial attempts archived
2093 exact project Python/config/declared-control/wrapper files, actual command,
before/after maps, stdout/stderr and terminal PID/exit/reap/timeout/RSS. External
RTL/tool/native output identity remains joined separately in native receipts.

- Initial software scope:46explicit modules, including new F2 contract/layout/reader/decoder/
  live consumer/assertion/provenance/file-entry and affected F4/CLI/build/session
  controls. This is a focused acceptance group, not the whole repository suite.
- F4: Timer and CV32E40P/SPI current-source RFuzz CLI, max-tests2, budget30s,
  rounds32, full first/fresh prefixes and run-level build/output/process joins.
- F2: Timer and SPI original/fresh file-entry gates, plus renamed Timer component
  instances without source/protocol change, and wrong-address pre-start refusal.

Gate statuses and terminal audits will be added from actual outputs. No source,
test, config or wrapper edits are allowed while the frozen gates execute.
Historical F2 final bundles retain their own committed source and verified saved
hashes; they do not accept these edited current runtime bytes.

## System boundaries

The two F2 register cases still have singleton address domains and zero PRDATA;
there is no added mutation diversity, nonzero priming or stable throughput.
No general F1/F3/F5/F6, unrestricted same-protocol onboarding, P6/P7-E/P8 or
six-CPU/four-IP system acceptance is awarded. Remote Stage2 controller/tool/source
closure remains separate from local native results.

## First frozen attempt and review follow-up

Both initial attempts used2093 identical inputs, archiveSHA256
`593723df94dc09c5242b441ee823afa6252fecf5847c95abf72e273b0be71f2b`.
F4Timer exit0/reaped/no-timeout,169.513606s, inputsunchanged; this is pre-fix
evidence. Software was intentionally interrupted with SIGINT to verified pytest
PID589244 after independent review found proof/accounting gaps; terminalexit2,
reaped/no-timeout,123.772689s,inputsunchanged. It is not a passing software gate.

Independent current F2 proof review found three P2 defects: omitted assertion
rows for submitted failed cases, missing functional fetch ordering allowing a
late XOR fetch, and replay discarding secondary audit/export failures. Report:
`.superpowers/sdd/compiled-f2/current-proof-review-20261023.md`. Fixes and
meaningful regression controls are now implemented and independently rereviewed.
Typed assertion input to the capability report and other-flow unsupported-path
reporting are also integrated; see the scoped evidence below.
All initial evidence remains immutable; final acceptance will use new attempts
after the source fixes and reviews.

## Reviewed fixes after the first freeze

These commands are separate development checks, not an aggregate final gate:

| Scope | Observed result | Independent review / evidence |
| --- | --- | --- |
| Shared process/build audit | 31 passed | Spec/Quality PASS; `.superpowers/sdd/compiled-f2/task5/shared-audit-current/` |
| Failed attempts, fetch order, replay errors, exact selected-read absence | 45 passed, 36.85s | Spec/Quality PASS; `.superpowers/sdd/compiled-f2/current-proof-fix-20261023/` |
| Typed capability report, source/type identity, unsupported paths | 90 passed, 48.61s | PASS; `.superpowers/sdd/compiled-f2/capability-integration-20261023/` |
| Runtime report and CLI saved outputs / constructor failure | 41 passed, 89.60s | Spec/Quality PASS; `.superpowers/sdd/compiled-f2/runtime-report-integration-20261023/` |
| Isolated primary-error preservation on report export failure | Old implementation: 1 failed; current: 1 passed, 0.34s | `primary-export-baseline-red.log` / `primary-export-current-green.log` in the runtime-report directory |

The runtime exposes each admitted attempt independently from certified records;
missing and contradicted selected-read observations remain distinct. Capability
projection validates typed assertions against independently collected case
inventory and exact binding identity. The CLI saves both documents and the
projected capability report, retaining constructor diagnostics and original
exceptions on failure. These changes do not grant native authority or higher
generic capability tiers.

Next: whole-slice review, update the explicit software scope to include the new
capability tests, freeze all executable inputs, then rerun software and serial
native gates. No final frozen gate is currently running. The final wrapper must
record its actual file/module counts, rather than reuse the initial counts.


## Final whole-slice review and software attempt2

Independent whole-slice review initially rejected fresh saved-output binding and
then a residual formatting-only byte-pin issue. Both have meaningful RED/GREEN
controls; final Spec PASS / Quality PASS, no remaining P1/P2. Full chronology and
reviewed source hashes: `.superpowers/sdd/compiled-f2/whole-slice-review-20261023.md`.
Final 24 controls cover unmodified two-replay output as well as immediate/later
semantic substitutions and later formatting-only changes. Source changes retain
initial byte pins through final verification; fresh hash indexes are validated
against each saved file. Related 84-test development run was not frozen during
edits and is not final acceptance.

`software-attempt2` is running with actual argv of 50 modules and 2098 archived
inputs, PID772238. No terminal acceptance yet. Supervisor review found the old
wrapper used to generate the module list is not included in the archive; the
actual resulting argv is saved. This dependency-archive boundary must be resolved
without modifying an in-flight freeze. Native scope now also includes a distinct
CV32E20 Timer gate required by the plan; the Ibex Timer gate is retained.


Software attempt2 terminal: intentionally SIGINT after supervisor review,
exit2/reaped/no-timeout, 96.030556s, 2098 inputs unchanged. Pytest reported
66 passed / 30 skipped before interruption; not a passing gate. The full archive
SHA is `bf957a10bbbe14557bb891f7432881f1028694832cd8d99b406e9df801763e07`.
Supervisor review independently verified 2098/2098 archive member hashes. The
module-list generator now uses an embedded literal, removing the unarchived
runtime dependency; all direct F2/F4 integration modules are included for the
next attempt, adding three affected F4 compatibility modules. No production or
test source changed between these supervisor revisions.


Revised supervisor preflight PASS: 53 unique existing modules; embedded list
removes the old-wrapper runtime dependency. SHA256
`4f97227c48bd8cfe63cbb242ef2fc9ee9d85fd3d0d5c10f666f12190482e7788`.
Independent review: `.superpowers/sdd/compiled-f2/final-supervisor-review-20261023.md`.
Software attempt3 started; executable inputs frozen, no terminal acceptance yet.


## Software attempt3 terminal: failed, retained

Actual pytest: **974 passed, 31 skipped, 4 failed, 53 subtests passed in 1187.59s**.
Supervisor: exit1/reaped/no-timeout,1188.099216s,maxRSS401896KiB,
2098inputs unchanged; archiveSHA
`8c1d7c7d84c9ec3efc9cdaa8c568f8a34b0557ef256f999f35a57b2f1e7d7aa7`.
Thirty skips are the documented timer-only registered-source boundaries; the
additional skip is `test_compiled_f4.py:58` requiring the isolated actual RTL gate.
No skip counts as execution capability evidence.

All four failures occur in `test_compiled_f4_layout_replay_audit.py`: two pin
slice tests construct a runtime without `register_name`, and two process/replay
audit tests lack `_build_sessions`. Investigation is comparing current HEAD
behavior with the extracted runtime; no production weakening or removed tests
is authorized. This is not passing software or native acceptance. The existing
whole-slice source review does not override these real failures.


Isolated HEAD baseline reproduced the exact same four fixture failures:
`red-head-runtime.log` reports4failed/8passed17.42s; current runtime baseline
`red-current.log` reports4failed/8passed18.09s. Logs and isolated loader are in
`.superpowers/sdd/compiled-f2/f4-layout-fixture-20261023/`.
HEAD already requires the source-selected register and complete build/process
join. Only the test fixtures are being updated; real receipt/process validation
must remain exercised, with an intentionally wrong identity refusal control.
This diagnosis does not turn the failed attempt into a passing one.


## Fixture correction reviewed; native compatibility started

Only `test_compiled_f4_layout_replay_audit.py` changed: two pin-decoder fixtures
use their D3 register; audit/replay fixtures provide schema-valid software
receipts and launch observations while executing real validation methods.
Two intentional receipt/launch drift controls refuse. Focused14passed34.03s;
relatedaudit9passed0.35s; independentSpec/QualityPASS in
`.superpowers/sdd/compiled-f2/f4-layout-fixture-20261023/independent-review.md`.
TestSHA `9178a8740975d5cfe0adea97539ee92f09ef5b57d91085752f00129d5528290f`.
The later isolated HEAD recheck named green-head-runtime.log actually has10pass
and4setup errors from relocated source closure; it is **not passing evidence**.

Candidate source/tests/configs/wrapper frozen again. `f4-timer-attempt2` started;
final full software rerun remains pending. Native and software must ultimately
refer to the same unchanged candidate input map; test-only repair does not
retroactively accept the failed software attempt.


Final full software attempt4 also started (PID961285/session71669) concurrently
with F4 Timer attempt2 (PID958406/session34791). Both initial maps have2098
identical entries; no source/test/config/wrapper writes are permitted. Native
gates remain serial. Each attempt must finish with its own unchanged-input and
terminal evidence; concurrency is not evidence of passing. Available memory at
launch was4979MiB, swapunused. Early process.json observation preceded child
creation while the supervisor archived inputs; the same handle was repolled,
not restarted, and the actual child PID subsequently appeared.

Fixture HEAD diagnostic follow-up: the first moved-source recheck remains the
reported10pass/4setup-errors. A separately saved package-relative-path repeat
reports14passed33.57s; this is isolated runtime compatibility evidence only,
not a whole-HEAD gate. Neither result replaces current candidate acceptance.


## Current-candidate F4 Timer native terminal

`f4-timer-attempt2`: actualCLIexit0/reaped/no-timeout170.510239s,
maxRSS628508KiB,2098inputs unchanged; archiveSHA
`f33f8ede428813611b70888471d3c5101930fc7c939619b10d2efa5fcd9bc7d8`.
Run summary complete,2/2certified; fresh matches/full with538events/2records,
compiled_F4_build_join complete. Root inspected actual summary/fresh/buildjoin;
independent raw-event/process/archive audit is pending at
`.superpowers/sdd/compiled-f2/f4-timer-current-native-audit-20261023.md`.
This is the post-fixture-correction candidate, not the pre-proof-fix attempt1.

F4 SPI attempt2 started next (unifiedexec65391); fullsoftwareattempt4 remains
live (71669/PID961285). Inputs stay frozen. No final whole-slice acceptance yet.


## Independent Timer raw audit found a persistence gap

F4 RFuzz `save_replay` discarded actual_events rather than persisting them.
The538-event live comparison, fresh prefix certificates, process/build joins
and complete original raw trace are available, but fresh full raw events are
not. Independent audit cannot recompute that fresh event chain from the
saved bundle; therefore complete raw native acceptance is **not awarded**.
This qualifies the positive Timer terminal above rather than rewriting it.

Before production repair, running software4 and SPI2 were intentionally
interrupted and reaped, with inputs unchanged:

| Attempt | Actual terminal | Wall seconds | Qualification |
| --- | --- | --- | --- |
| software-attempt4 | exit2 / no-timeout / reaped |308.219625| SIGINT due newly found raw-save defect; not passing |
| f4-spi-attempt2 | exit-2 / no-timeout / reaped |139.704511| SIGINT during fresh; not passing |

SPI original CPU/target exits are both0. Fresh CPU is0; fresh target was reaped
with-9 during controlled interruption cleanup, retained as refused buildjoin.
Do not call that a naturally discovered RTL fault or passing fresh replay.
Only F4 RFuzz output persistence/verification and its focused tests are being
repaired; protocol execution and runtime authority stay unchanged. Expected
new evidence directory: `.superpowers/sdd/compiled-f2/f4-fresh-raw-20261023/`.
No final gate currently runs; previous source/input archives remain immutable.


## Raw-output closure fix, scoped development checks

The actual F4 replay callback now saves available fresh raw events first,
independently retains other available diagnostics, and keeps primary errors.
Same-call output validation covers seven original/fresh documents and their
initial byte pins; final driver guard checks those pins again. The final
summary records all four fresh file paths/SHAs, enabling offline references.
No protocol/authority/ownership/coverage/feedback behavior is changed.

Focused runtime RED19failed/5passed; GREEN24passed0.41s. Related orchestration
and failure-audit33passed51.17s. Driver summary RED2failed23.02s and
GREEN2passed23.50s; runtime agent's selected driver/wrapper run3passed23.90s.
These are separate scoped commands, not an aggregate gate. Combined four-file
review pending; evidence index:
`.superpowers/sdd/compiled-f2/f4-fresh-raw-20261023/`.
Runtime logs were originally written to `.sdd/` due a parent path abbreviation;
the original remains, and runtime/ in the canonical index is a byte-preserving
copy. The execution commands/paths in those logs are not rewritten.


## Joint source review PASS; new frozen attempt5 / Timer3

Four-file raw-output correction: independentSpec/QualityPASS, no openP1/P2;
`.superpowers/sdd/compiled-f2/f4-fresh-raw-20261023/independent-review.md` pins
all four source hashes. This does not retroactively fill the missing Timer2 raw.

Fresh freeze started: software-attempt5 (53 modules, execsession85214) and
f4-timer-attempt3 (execsession92150). Both initial maps contain2098 identical
project/control/wrapper inputs. No source/test/config/wrapper edits while these
run. Independent raw audit must use the newly saved fresh events from Timer3.


## Timer3 corrected-source native terminal / fresh raw retained

Actualsupervisor exit0/reaped/no-timeout153.544096s,maxRSS627804KiB,
2098inputs unchanged, archiveSHA
`82d219fdb0dda59cfbe6e6420fa1352ea35fca9dc2ae0256352a12a3a9577de1`.
Root inspected runcomplete2/2certified, fullfresh538events, buildjoincomplete,
and all four real child exits0/reaped. `compiled_f4_fresh_events.json` actually
contains538events and has its summary SHA descriptor. All18summary document
hashes match current bytes, including four fresh documents.

Independent raw audit is pending separately at
`.superpowers/sdd/compiled-f2/f4-timer-current-native-attempt3-audit-20261023.md`.
It must recompute fresh semantic/native-hop evidence, not inherit Timer2's
runtime claim. F4SPIattempt3 started next (execsession2903); softwareattempt5
stilllive(execsession85214/PID1020689). Source/tests/config/wrapper remain frozen.


Timer3 independent full raw audit **PASS**, noP1/P2:
`.superpowers/sdd/compiled-f2/f4-timer-current-native-attempt3-audit-20261023.md`.
Auditor independently rehashed original/fresh538-event semantics, reconstructed
16fetch/4APB/2RAM hops in each, checked full prefix,2098archive/map bytes and
18summary descriptors, buildinputs/hostsources/tool/backend/runtime/cachebinary,
and all four PID/nonce/READY/exe/exits. Both original/fresh were cache hits,
not cold compilations. Only this bounded Timer/CV32E20 two-case F4 item is
accepted. Timer2 missing-raw evidence remains unaccepted and other gates open.

## SPI3 corrected-source terminal and F2 Timer start

F4SPIattempt3 actualterminal0/reaped/no-timeout176.064340s,
maxRSS644008KiB,2098inputs unchanged; archiveSHA
77e4f6451eae48bf47943f74781a1c2b32f668559321524e1182039b7f5434e6.
Root inspected complete2/2certified, fullfresh2806events with2806retained raw
rows, completebuildjoin, fourchildexit0/reaped and matching summaryfilehashes.
Independent raw/build/process/archive audit pending separately in
.superpowers/sdd/compiled-f2/f4-spi-current-native-attempt3-audit-20261023.md.

F2Timer/Ibex attempt2 started (execsession80822). Extra F2Timer/CV32E20,
SPI/CV32E40P, renamed-instance and wrong-address modes follow serially;
softwareattempt5 continues inparallel. All candidate inputs remain frozen.


SPI3 independent full raw audit **PASS**, noP1/P2:
.superpowers/sdd/compiled-f2/f4-spi-current-native-attempt3-audit-20261023.md.
Original/fresh2806-event semantic hashes were independently recomputed; each
16fetch/4APBoffset8/2RAM chain, source/archive/document hashes,375/399buildinputs,
host/tool/runtime/cache and all four actual process records were checked.
Both executions were cachehits. CPU shape is fail_stop_no_error_pin with
native_error_observationFalse; absent error pin is not an observed zero error.
Only bounded SPI/CV32E40P two-case F4 compatibility is accepted.


## Current F2 Timer/Ibex attempt2 terminal

Actualexit0/reaped/no-timeout233.659203s,maxRSS302420KiB,
2098inputs unchanged; archiveSHA
643cebf76234a70e02fab70167861cdb05752581d0ecd3db6a8081a87b1f18b1.
Root inspected completed1case/1certified, fullfreshmatches/firstdifferenceNone,
completeF2buildjoin and all4nativechildexit0/reaped. Two typed expected assertion
rows are passed with one independently exported case inventory; capability
report contains those two validated rows without promoting higher tiers.
All31saved_file_hashes match actual bytes. Independent raw/source/build/process/
assertion/report audit is pending separately:
.superpowers/sdd/compiled-f2/f2-timer-current-native-attempt2-audit-20261023.md.

Next F2Timer/CV32E20 attempt2 is live (execsession71768). Softwareattempt5 remains
live85214. No source/test/config/wrapper edits; remaining F2SPI/renamed/refusal
and complete software/system gates are not accepted yet.


F2Timer/Ibex2 independent raw/source/build/process/assertion/report audit **PASS**:
.superpowers/sdd/compiled-f2/f2-timer-current-native-attempt2-audit-20261023.md.
Original/fresh631-event semantics independently recomputed; seven functional
fetches, LW/PRDATA0/rawXORI0x5a5/RAM1445/[0,2], same-key request/return, startup
idle version0/writecount0 and continuous target ticks1–133 checked. This is
current-version continuity, not reset proof or retirement.31savedhashes and
2098archive members match; typed inventory validates and capability exact
reprojection matches with no tier increase. Only one bounded case accepted.


F2Timer/CV32E20 attempt2 terminal0/reaped/no-timeout219.443715s,
maxRSS300484KiB,2098inputs unchanged; archiveSHA
9331efec221d1d83e3ea5ff12bbacec64a08e84caaf25b129d4eb5e71b7e4c8e.
Root inspected completed1/1certified,fullfreshmatch,2typedassertionspassed,
completebuildjoin/fournativeexit0/reaped and31savedhashesmatch. Independent
auditor is reviewing this CPU's actual ABI/error-observation shape separately.
F2SPIattempt2 started next(execsession38010); software5 remainslive85214.


## Final software attempt5 real terminal

Actualpytest **1001 passed,31 skipped,53 subtests passed in1263.22s**.
Supervisor exit0/reaped/no-timeout1263.874187s,maxRSS400284KiB,
2098inputs unchanged; archiveSHA
82d219fdb0dda59cfbe6e6420fa1352ea35fca9dc2ae0256352a12a3a9577de1.
The31skips are30timer-only registered-source controls and1isolated actualRTL
opt-in. They are not native passes. This is the explicit53module group, not
all repository tests. Independent terminal/archive/current-byte review pending:
.superpowers/sdd/compiled-f2/final-software-attempt5-audit-20261023.md.

F2Timer/CV32E20 independent audit **PASS**, noP1/P2, separate from Ibex:
.superpowers/sdd/compiled-f2/f2-cve2-timer-current-native-attempt2-audit-20261023.md.
Actual profile/upstream_cve2/firstfetch0x10000 and native_error_roleTrue checked;
error0 was actually observed. Both631raw semantics, sevenfetches/readPRDATA0/
XORI5a5/RAM1445, initialidle/version0 and continuoustick133, exact typed/capability
reprojection and31savedhashes/source/build/process joins passed. No resetproof,
retirement or tier increase is awarded. F2SPI/rename/refusal remain open.


Software5 independent terminal/archive/current-source audit **PASS**, noP1/P2:
.superpowers/sdd/compiled-f2/final-software-attempt5-audit-20261023.md.
Ordered actual53module argv independently rebuilt; all2098unique regular/pathsafe
archive members match32,113,361bytes and before/after/current/re-enumerated
scope;17latest source-review pins match. RealPID absent, terminal0/reaped,
stdout1001passed31skipped53subtests,stderr empty;31skipreasons individually
counted. No native runs were counted as software passes.

F2SPI/CV32E40P independent audit **PASS**:
.superpowers/sdd/compiled-f2/f2-spi-current-native-attempt2-audit-20261023.md.
Both4355raw semantics and actual7fetch/LW/offset8PRDATA0/XORI5a5/RAM1445 chains,
startupidle/version continuity, exact typed inventory/capability reprojection,
source/build/process/prefix/savedhashes verified. CPU errorNone means unobserved,
not observedzero. No tier increase, resetproof or retirement grant.

RenamedTimer2 terminal0/reaped/no-timeout227.926888s/2098unchanged, archiveSHA
d920f4346d4e61d2382670bf7e70042b57809aa4681519521222f7881531393a.
Root inspected compute_unit7/target_unit9 actual binding and process identities,
completed1certified/2passedassertions/fullfresh/completejoin/31hashesmatch.
Independent audit pending. Wrongaddress2 started(execsession89422); no source
edits before its terminal and final evidence audit.
