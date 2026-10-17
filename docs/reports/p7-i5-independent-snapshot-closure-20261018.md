# P7 I5 independent snapshot: static selected closure audit

Status: **source facts only; no native execution or admission grant**.

Audited snapshot: `/tmp/myfuzz-p7-i5-source-6b40ef4`.
The name identifies the preparation lineage, not an assertion that every byte
equals commit 6b40ef4: it includes separately recorded runner/native and
independent Git metadata overlays.

The externally supplied `ready-freeze.json` hashes to
`b6372fcdb7ca1e93c289f850b0d53bc421c571204a65b86bd828815eb1f13dd2`.
It describes **15,333 files / 798,103,129 bytes**. This audit checked a selected
478-file source/include/lock/proof read set against its hash, size and mode,
plus the actual files defining all eight negative selectors. No missing
declared source, include directory, selected lock artifact or timer proof was
found in this scope. This is not an independent rehash of every snapshot file.

## Actual selected profiles

N1/N5/N7 share the real parametrized `loaded` fixture: both Ibex and CV32E40P
are needed. N4 generates the Ibex+timer declaration. N3 uses real GPIO;
the independent native rerun requests CV32E20+timer. N8 has six declaration
mutations, including switching the CPU profile to CV32E40P. All eight selector
definitions occur exactly once in their frozen test modules.

| Profile | Declared files / expanded filelist | Include roots | Selected lock artifacts |
|---|---:|---:|---:|
| Ibex OBI local | 43 | 4 | 71 |
| CV32E40P | 31 | 4 | 33 |
| CV32E20 | 28 | 3 | 29 |
| PULP GPIO | 1 | 0 | 3 |
| PULP timer | 2 | 0 | 4 |

The CV32E40P manifest was read directly, expanding only its declared
`DESIGN_RTL_DIR=rtl`; its source lines and four include directories exist.
All selected lock entries were matched by exact `id`, rather than using all
records sharing a source root. Every artifact SHA matches, including GPIO
LICENSE/Bender.yml and timer LICENSE/src_files.yml. Ibex's selected license
also matches. No project verifier was imported or substituted.

## Conditional textual includes

A conservative literal-include scan found seven unresolved textual occurrences:
five `formal_tb_frag.svh` occurrences in Ibex/CVE2 are inside nested
`FORMAL` and `YOSYS` guards; CV32E40P's `uvm_macros.svh` is guarded by
`CV32E40P_TRACE_EXECUTION`; CVE2's `cve2_pmp_reset.svh` is guarded by
`CVE2_CUSTOM_PMP_RESET_VALUES` and has a present default alternative.
The selected profiles do not request those macros; CVE2 requests only
`RVFI=1`. These are not established missing dependencies of the declared
Verilator path. This manual guard inspection is not a general preprocessor
or elaboration proof; enabling those other modes needs a new closure audit.

## Timer proof and operational files

The exact `PROOF_RELATIVE` file is present:
`docs/reports/evidence/verilog-probe-pulp-apb-timer/proof.json`, SHA
`85c1bec713b7012d42dd12565ca11706aba485a35036f8d88ec063558571aa2c`.
Its declared source hashes match actual timer RTL and the freeze:

- `src/apb_timer.sv`: `22dce4e3ff8328bdd6e1621c20e2877e7f44cfecccc07203d09e994632cc1778`
- `src/timer.sv`: `d352fc4476da83658d361e8f500b5a73f857f0a11e9436ab47d5bf0ba0bc7fce`

The proof's schema is `apb_storage_probe_hierarchy_proof.v1`; its recorded
proof digest is `a889c6eb699ecdbd2ad4959f3ca14a5762608edb5a8ce93523343e02fffbef85`.
This audit reads the saved proof and pins its bytes; it does not rerun its
commands or certify newly generated runtime/wrapper bytes against it.

The APB adapter RTL, runner, CLI implementation, source lock, N3 fixture and
existing empty private heavy-worker lock were also checked against the freeze.
No source, Git metadata or frozen file was modified by this audit.

## Limits and retained machine record

Read operations used only standard-library JSON, file/hash/stat and AST parsing;
there were no project imports, compiler/frontend/version commands, tests,
Git commands, native processes or remote operations. The machine record is
`/tmp/myfuzz-independent-preparation-20261018/independent-static-closure-audit.json`.
Remote extraction must still restore modes and independently verify the full
map. Python dependency/tool/wrapper closure, actual source immutability across
execution, N1–N8 results and native full fresh replay remain separate gates.
P7 I5 is not completed by this static audit.
