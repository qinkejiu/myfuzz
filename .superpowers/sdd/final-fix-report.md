# Final review fix wave

Worktree: `/home/qinkejiu/myfuzz/.worktrees/ibex-protocol-longrun`.
Baseline: `915b221`. Implementation: `6d4ef8a`; reviewed follow-up: `dba09b1`
(no push).
The requested findings file was absent when work started; the controller's six
Important findings and three Minor items were the complete fix requirements.
One implementer owns all changes; a read-only helper audited evidence locations
and the identity/source closure boundaries.
The systematic-debugging and test-driven-development skills guided the separate
RED reproductions before minimal fixes; verification-before-completion required
fresh final regression and real artifact checks, not inherited pass claims.

## Root causes and RED/GREEN evidence

1. **C.ANDI**: the legality provider tested only bit 11, misclassifying the
   `bits[11:10]=10` immediate form as register arithmetic. The transducer then
   cleared RV32 bit 12 or RV64 bit 6 to satisfy that faulty provider. Independent
   opcode-mask cases `0x9805`, `0x9855`, `0x987d`, `0x8801`, `0x887d` exposed the
   rejection/bit loss without filtering through the provider. Correct two-bit
   classification removes both compensations and preserves all six immediate
   bits. [RISC-V opcode source](https://github.com/riscv/riscv-opcodes/blob/master/extensions/rv_c)
   independently identifies the form.
2. **CSR capability**: `_i_templates` and the I legality set incorrectly contained
   six Zicsr operations. They are removed without expanding the public I/M/C
   contract. Every eight-bit I-only selector and each CSR funct3 now checks
   against an independent opcode oracle. The example has 50 32-bit and 26 16-bit
   templates; selector 220 still selects MUL, and 207 still selects C.MV.
   The [ratified Zicsr specification](https://docs.riscv.org/reference/isa/v20260120/unpriv/zicsr.html)
   places CSR instructions outside base I. Findings 1/2 initially produced
   **9 failed, 3 passed**, then `tests/isa`: **63 passed, 32 subtests passed**.
3. **Include precedence**: crawler filelist roots preceded locator roots, whereas
   published compilation used the reverse. Both now use locator roots first,
   then filelist declaration order, with first-occurrence de-duplication. A real
   Verilator fixture with duplicate `width.svh` files initially annotated 16 bits
   where compilation selected 8; annotation and final compilation now agree.
4. **Cross-file packed evidence**: reset verification demanded a CPU module in
   every member declaration file. After restricting that check to clock/reset
   source evidence and the selected module body, the real package/header fixture
   reached the second RED: `KeyError: include/response.svh`. Every verified source
   closure file now receives a provenance ID, while `compilation_unit_ids` and
   emitted `sources.f` preserve the independent compilation order. A package and
   included header jointly define the packed response members and publish/lint
   successfully; headers are not emitted as standalone units. Related suite:
   **109 passed, 53 subtests passed**. A follow-up audit also exposed headers
   changed during lint/final compilation being published with stale provenance.
   Both mutation regressions failed first, then passed after rechecking the full
   source evidence hash at both boundaries.
5. **Implementation identity**: the previous contract bound declarative fields
   but omitted actual generated rules. `implementation_hash` now hashes the
   generated RTL body after comment/whitespace normalization, with a fixed module
   identifier and without a self-referential hash banner. It binds emitted ISA
   templates, minimal repairs, protocol and coherent-memory behavior, is path
   independent, and participates in `contract_hash`. A real compiled ADDI-to-SLTI
   rule change originally left the contract unchanged; it now changes identity
   and rejects the old header. An independent normalization of the public emitted
   RTL reproduces its implementation hash. Explicit identity propagates through
   contract, artifact provenance, manifest, execution proof and replay summaries.
   Missing/changed bindings reject before executing saved inputs. The API also
   checks the actual sibling corpus manifest used by unannotated upstream entry
   files, including required stable fields, exact filename/count set, raw input,
   retained trace and coverage. Initially unbound capture requires completed live
   feedback receipts. Sidecar/partial-inline omissions were reproduced RED and
   corrected; binary hashes and replay keys remain build-specific.
6. **Address ceiling**: backend planning permits a half-open region ending at
   `2**address_width`, but all three render sites attempted to emit that endpoint
   in W bits. Both legacy and constrained rendering failed RED. Decode now uses
   `addr <= end - 1`. Icarus evaluates both route decoders, the shared backend
   decoder and target selection at `0xfffffffb`, `0xfffffffc`, `0xffffffff`; all
   agree with the valid highest four-byte interval. Constrained rendering also
   passes and continues to map normalized requests to the transducer.

## Minor items

- Fixed the schema/runtime policy mismatch. The actual property is
  `warning_policy` (the initial task called it `error_behavior`): explicit `fatal`
  and `recorded-nonfatal` are now accepted by both validators. JSON Schema failed
  the `fatal` case before the enum fix and passes afterward.
- Fixed CycleField revalidation through forced mutation and a recomputed layout
  hash: invalid field IDs, boolean/float widths and non-integer offsets originally
  bypassed validation. Six RED cases now fail closed. Combined ceiling/Minor
  targeted suite: **8 passed, 2 subtests passed**.
- **Not changed:** AXI WSTRB/AWSIZE lane validation remains a defensive
  enhancement. This fix wave does not extend the adapter's supported protocol
  scope or advertise that enhancement as implemented.

## Verification and acceptance

- Task 8 focused: **259 passed, 9 subtests passed** (53.75 s). Its old example
  diagnostic fixture also failed after removing CSR; it now explicitly enables
  the supported illegal class in its test header, with selector 255.
- Initial Task 9 focused: **665 passed, 3 skipped, 442 subtests passed** (67.49 s).
- First full regression: **1437 passed, 3 skipped, 1163 subtests passed** (177.60 s).
- Pre-follow-up live/replay identity suite: **21 passed, 3 skipped, 9 subtests passed**.
- `git diff --check` and exact staged diff checks passed before implementation commit.

### Fresh real native-client acceptance

All following commands exited zero, with one low-priority build/run worker and
the full bounded client drain allowed to finish:

```bash
bash examples/real_ibex_rfuzz/commands.sh check
bash examples/real_ibex_rfuzz/commands.sh compose runs/examples/contract-rfuzz-final-compose
bash examples/real_ibex_rfuzz/commands.sh test runs/examples/contract-rfuzz-final-5s 5
bash examples/real_ibex_rfuzz/commands.sh inspect runs/examples/contract-rfuzz-final-5s
bash examples/real_ibex_rfuzz/commands.sh replay runs/examples/contract-rfuzz-final-5s runs/examples/contract-rfuzz-final-replay
```

The executable was the unchanged native
`runs/rfuzz_client_native_build/target/debug/kfuzz`, version `kfuzz 0.1.0`,
SHA-256 `bbb72e52e60b1380cccd3b8c25febf0b6ccde51b17802d457ffadef43f87747b`.
The actual toolchain reported Verilator 5.051 devel. Each of the separate
compose/live/rebuild probes executed 80 cycles with two instruction
requests/responses/initializations and zero errors.

| Final live measurement | Value |
| --- | --- |
| RTL tests / completed feedback receipts | 124153 / 98557 |
| Corpus / same-build replays / independent rebuilt replays | 23 / 23 / 23 |
| Execution cycles | 9932240 |
| Backend requests / completions | 249246 / 248306 |
| Instruction requests / responses / initializations | 249246 / 248306 / 248306 |
| Protocol / transducer / total errors | 0 / 0 / 0 |
| Ordinary diagnostics / return code | 0 / 0 |
| Remaining / forcibly removed owned shared-memory segments | 0 / 0 |
| Stop request / actual interrupt elapsed | 5 s / 5.000071473001299 s |
| Drain / total wall time | 23.32143781099876 s / 28.32273579500179 s |
| Drain limit / sampled peak process-group RSS | 60 s / 108556288 bytes |

Five seconds denotes the stop request, not total wall time. Completed receipts
are deduplicated input/coverage pairs, not the RTL test count. Tail requests need
not complete before a short input ends, so request and completion totals differ.

All three builds reproduce byte-identical generated RTL. Independent replay
requires stable semantic identities and identical feedback, but deliberately
records a different native simulator binary hash. Current SHA-256 identities
(without the `sha256:` prefix):

```text
composition     de949da80a67b0fc92c50412c5ff07874b6c26e2d304513e3c67f7a6ee2a3a6c
layout          d23dd16f9cd98973407167d90bd3431d82c7736bf2519eef8c47934fad111d8a
contract        99bc895ab8c8f94ac66e8af4043b96e275dae5ec90a683d1df4cdf0640d5e6b1
implementation  cc5cf3c20d76c82acfb526e4f04b0566d35131b767ebf6491d7b75d7f997a880
header          0ce915e60d573aaf57501e98b0ead6f976cdd21466c393d6bc1bd39a9af32495
live binary     8f5bdbc13296cdafa82a16dac0f95470e462d9c75fc400b317514ed42cc74e11
rebuilt binary  823854e5eb909afdd9e5f0d1799eea4e032b352093e8594aa8fedef4c0b5dc32
transducer RTL  72a13f6b85c7531af6a91dc17811db829dbfa59b11e6b1e0f2bacee6d871702d
```

`examples/real_ibex_rfuzz/expected/bounded-result.json` records the exact file
hashes for summary, live report, corpus manifest, replay and independent rebuild,
the source-evidence identity, the configuration, and representative
`entry_0000.json`. Both the implementer and a separate read-only helper recomputed
the actual full 23-entry filename set, raw/input/trace/coverage/control/simulator
hashes and canonical replay keys against those on-disk artifacts. The helper also
recompiled the current contract in memory and reproduced the exact saved contract
and generated RTL, without rebuilding or rerunning RTL. All checks passed.

README, system explanation, handoff and the expected reference now describe these
new results and the corrected 50/26 ISA template counts. Append-only notes in the
Task 8/9 reports supersede their historical identities and saved-corpus
compatibility claims. The old `contract-rfuzz-review-5s` and `contract-rfuzz-5s`
artifacts remain untouched: their missing implementation identity and old ISA
contract are rejected by current replay, not silently rebound to this build.

### Final post-documentation verification

The final focused and full commands are run after the implementation commit and
the refreshed documents. Their complete results are recorded here before the
evidence commit.

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 nice -n15 python3 -m pytest tests/composition tests/isa tests/examples/test_real_ibex_rfuzz_example.py tests/integration/test_rfuzz_simulator.py tests/integration/test_rfuzz_live.py -q
PYTHONPATH=src python3 -m pytest tests -q
bash -n examples/real_ibex_rfuzz/commands.sh
git diff --check
```

Pre-follow-up Task 9 focused result: **667 passed, 3 skipped, 442 subtests passed in
73.51 s**. The two extra passing cases relative to the earlier focused run cover
partial inline replay identity and source freshness after final compilation.
Pre-follow-up full regression: **1437 passed, 3 skipped, 1163 subtests passed in 177.46 s
(0:02:57)**. The three default opt-in skips remain separate from the explicit
real native-client acceptance above. Shell syntax and whitespace checks passed.

The read-only evidence reviewer independently checked all 52 expected-reference
result fields, representative `entry_0000.json`, template counts and guide/report
consistency. No mismatch was found. Historical Task 8/9 reports have exactly 17
added lines each, with no deletion or rewrite of their prior evidence.

### Commit-level review and compatible follow-up

The requesting-code-review skill triggered a separate read-only review of
`915b221..6d4ef8a`. It found no additional ISA, include-order, packed-source or
ceiling-decoder gap, but identified two concrete follow-ups. The
receiving-code-review skill required reproducing them before making changes:

1. **Important, sidecar plus inline replay identity:** stable sidecar validation
   already permitted a different independently rebuilt binary, but a later inline
   check still compared the original binary/key to that new artifact. A new test
   initially produced two failing subtests for `replay_corpus` and
   `build_corpus_manifest`. Correcting the replay comparison exposed the second
   RED at manifest's duplicated check. Inline binary/key now match the validated
   original sidecar, while all stable keys still match the new artifact; the
   manifest builder relies on that already-verified build-specific binding.
   GREEN: **1 passed, 2 subtests passed**. Tampered inline binary identity still
   rejects before execution; inline-only and legacy checks retain prior behavior.
2. **Minor, binary include collateral:** source closure can contain non-HDL
   files, but assigning IDs to the full closure tried to decode every file as
   UTF-8. A real packed package/header fixture plus a non-UTF-8 include attachment
   failed with `UnicodeDecodeError`. Non-UTF-8 content now receives a raw-byte
   (hex-encoded canonical input) content ID, retaining existing normalized text
   IDs. The fixture publishes/lints successfully and excludes the binary from
   `sources.f`: **1 passed**.

The combined affected suites returned **35 passed, 3 skipped, 16 subtests passed
in 11.21 s**. The same reviewer inspected both fixes and their tests, reporting
both resolved and **Ready: Yes**, with no further issue in their scope. Exact
four-file implementation/test staging produced `dba09b1`. This follow-up does
not change ISA rules, emitted RTL or this Ibex source's normalized text identities;
the measured live/rebuild artifacts above remain the `6d4ef8a` run. The expected
reference records `dba09b1` separately as a compatible follow-up, not a new run.

After `dba09b1`, the independent evidence reviewer again regenerated the contract
and RTL entirely in memory and compared all three saved `final-*` directories:
canonical contract bytes, implementation hash and complete RTL bytes all remain
identical. No build, elaboration, RTL run or file mutation was needed for this
check. Final Task 9 focused regression returned **668 passed, 3 skipped, 444
subtests passed in 69.15 s**. The final full command
`PYTHONPATH=src python3 -m pytest tests -q` returned **1439 passed, 3 skipped,
1165 subtests passed in 176.56 s (0:02:56)**. A fresh read-only `inspect` using the
final code returned the same passed real-live summary. `bash -n` and
`git diff --check` passed again; exact staged-path and staged whitespace checks
precede the evidence commit.

Existing `.superpowers/sdd/task-2-report.md` edits and every `third_party/` path
remain outside staging. No CPU-name or hierarchy-based rule was introduced.
The task-2 report retains SHA-256
`5a2bf56f8f1fa3104b6ef7752022c574086a581fdd4e66c715f4cbeece08671f`;
the separate main-workspace handoff retains SHA-256
`b668109cf859af1d6a59f0e0e48a255ccc5b728c21b44a7cde6393b9b61bab4c`.
Task 14 formal closure, three 300-second runs and BOOM processor acceptance remain
deferred; this bounded Ibex acceptance does not complete them.

## Delivery scope

All six original Important findings and the commit-review Important are resolved.
The two requested simple Minors and the new binary-collateral Minor are fixed;
only the explicitly deferred AXI WSTRB/AWSIZE lane-defense Minor remains open.
Implementation/test commits are `6d4ef8a` and `dba09b1`. This report, the refreshed
expected reference, README, system explanation, handoff and the two append-only
historical report notes are the exact seven paths in the final evidence commit.
No push, merge, third-party edit, client patch or unrelated cleanup was performed.
