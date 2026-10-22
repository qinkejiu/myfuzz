# Independent audit — compiled F2 native Timer/SPI first/fresh gates (2026-10-23)

Repository `/home/qinkejiu/myfuzz`. Audited commits: `a54289b` (compiled evidence
bundle + report) and `91a8037` (compiler/decoder/layout integration). Current
`HEAD` is `eca42ab`, three commits later, with a dirty working tree; the audited
evidence directory and report are tracked, clean and unmodified.

- Evidence: `docs/reports/evidence/compiled-f2-native-gate-20261023/`
  (44 files on disk; 36 tracked at `a54289b`).
- Report under audit: `docs/reports/compiled-f2-native-gate-20261023.md`
  (tracked at `a54289b`, clean, sha256
  `efdffa4b247cdcbd8715effb6a84991f22bb25914f2ca140e3db0cc6bdb17cde`).

Read-only audit. No source, test, config or evidence file was modified; the only
deliberate file written is this report. Recomputation used `hashlib`/`json`, the
shipped `normalized_semantic_sha256`, `verify_compiled_f2_build_join`,
`validate_built_receipts`, `built_receipt_sha256` and
`load_generated_artifacts`, all imported with `PYTHONPATH=src:.`; those imports
may have refreshed ordinary `__pycache__/*.pyc` bytecode caches (build artifacts,
not tracked source). I also extracted `git archive 91a8037` / `a54289b` into
`/tmp` to test whether the audited commits can import the gate, then deleted the
extraction. No RTL run, rebuild or pytest run was performed.

## Verdict

The two native packages are **internally consistent and re-derivable from the
bytes that exist today**. Every reported Timer/SPI fact checked here recomputes:
`status=completed` with no error, `executor=compiled_f2_obi_apb`, one certified
case, the exact semantic hashes, the three-edge certificates, the
`PRDATA XOR 0x5a5` store, distinct reaped original/fresh processes, byte-stable
build/binary/artifact identities, all 28 `saved_file_hashes.json` entries, and
the complete `compiled_F2_build_join.v1` document (re-verified with the shipped
verifier against the external generated artifacts).

Two material problems remain, both in **framing/reproducibility**, not in the
observed chain:

1. **F-1 — the executed source is largely uncommitted.** The report says the SPI
   961-file pin "equal[s] the current committed tree exactly" and that only one
   Timer file differs. That is true against the **working tree** (961/961 and
   1153/1154) but false against the audited commits: 38 pinned `src/` files are
   absent from the commits and 40 (SPI) / 41 (Timer) tracked files differ. The
   committed tree cannot even import the gate (`ModuleNotFoundError:
   myfuzz.integration.compiled_build_join`, `myfuzz.scenario.instruction_image_binding`;
   and tracked `compiled_f2.py` imports `_diagnostic_build_snapshot` /
   `_artifact_execution_identity`, absent from the committed `compiled_f4.py`).
2. **F-3/F-4 — report-text inaccuracies.** The declared dependent result word is
   `262140 = 0x0003fffc`, not the report's `0x0004003c` (which is outside the
   declared RAM range). The failed-attempt **logs are not committed** (they match
   `.gitignore:13 *.log`), although the report says they are. The Timer CPU is
   lowRISC `ibex_top`, not "CV32E20/CVE2".

None of F-1/F-3/F-4 changes the certified chain: the PRDATA=0 read, the
`0x5a5` store at `0x3fffc`, the three certified edges and the fresh equality are
all present in the pinned bytes and the committed certificates. But the package
should be cited as "working-tree reproducible, commits incomplete", not as
source-closed.

## Verdict table

| # | Requirement / claim | Verdict | Evidence (exact path) | Recomputed value / observation |
|---|---|---|---|---|
| 1.1 | `report.json` status / error / executor / one case | **PASS** | `.../timer/report.json` (sha256 `9ff34755…`), `.../spi/report.json` (`c3f3cb81…`) | `status=completed`; no `error`/`error_type` key at all (success writer only adds them on failure — equivalent to null); `executor=compiled_f2_obi_apb`; `flow=F2`; `cases=1`; `certified_cases=1`; `replays=1`; `runtime_admitted=true` |
| 1.2 | Prefix / fresh / replays | **PASS** | `.../timer/prefix.json` (`59845b98…`), `.../timer/replays.json` (`f036a0e6…`), `.../timer/fresh-1/comparison.json` (`9c08a221…`); same shape SPI (`1023f8a6…`, `28c84c08…`, `3c6d05c6…`) | `records.length=1`; `replays.length=1`; `matches=true`; `first_difference=null`; `verification_scope=full`; fresh prefix hash equals original prefix hash; `case_timings[0].certified=true` |
| 1.3 | Semantic hash (expected = actual) | **PASS** | `prefix.semantic_hash`, `replays[0].{expected,actual}_semantic_hash`, `fresh-1/comparison.{expected,actual}_semantic_hash`, external `events.json` | Independently recomputed with `normalized_semantic_sha256('complete', events, {'peripheral':133,'processor':129})`: Timer `255a637c…5a29c5`, SPI `7daccad3…cafab21`; identical for original and fresh event journals |
| 1.4 | Build join `compiled_F2_build_join.v1` complete | **PASS** | `.../timer/compiled_f2_build_join.v1.json` (`70ed848b…7c692f`), `.../spi/compiled_f2_build_join.v1.json` (`68aa273e…7338df`) | `status=complete`, `error=None`; shipped `verify_compiled_f2_build_join(...)` returns PASS for both against the external generated artifacts; receipt/binding/artifact sub-hashes recompute |
| 2.1 | Prerequisite kind `ip_register_version`, no RAM-version masquerade | **PASS** | certificate `prerequisite` + `version_witness` in `prefix.json`; `execution_binding.prerequisites` | `kind=ip_register_version`; `subject={component:peripheral, register:TIMER0_CTRL|SPICMD, reset_epoch:0}`; `evidence_ref=gpio_register_commit.v1:peripheral:0:78/399:…:0`; witness schema `apb_storage_register_version.v1`, `field_version=0`, `value=0`, `write_count=0`; producer `allowed_kinds=['ip_register_version']` only |
| 2.2 | Edge provenance (CPU→CPU persistent, CPU→IP read_request, IP→CPU read_return; no CPU→CPU MMIO) | **PASS** | certificate `exact_hops.edges[0..2]` | edge 0 `relation=persistent_state`, `processor→processor`, resource `(processor,ram)`, `rule_index=1`; edge 1 `relation=mmio_route`, `role=read_request`, `processor→peripheral`, `rule_index=2`; edge 2 `relation=mmio_route`, `role=read_return`, `peripheral→processor`, `rule_index=3`; all `status=certified` |
| 2.3 | Dependent `PRDATA XOR 0x5a5` store joined to native OBI accept/response + RAM snapshot | **PASS** | certificate `exact_hops.ram_write_hop`; `assertions[1].evidence`; external `events.json` `memory_write` event | native read PRDATA `0`; store value `1445 = 0x5a5`; RAM address `262140 = 0x0003fffc`, byte offset `196604`; `native_acceptance_event=148`, `native_obi.response_event=166`, `memory_write_event=149` (Timer); `712/786/722` (SPI); `memory_write` event `{address:262140, value:1445}` |
| 2.4 | Typed assertions passed and bound | **PASS** | `prefix.assertions` (`compiled_assertion_results.v1`), certificate `assertions` | `protocol_checker.receipt_violations` passed (`violations: []`), `cross_component.declared_edge_hops` passed (`edge_ids [[1,0],[2,0],[3,0]]`, endpoints `[[processor,processor],[processor,peripheral],[peripheral,processor]]`); `binding_sha256` = certificate `execution_binding_sha256`; `compiled_document_sha256` = producer `compiled_sha256`; `path_id`/`path_sha256`/`run_id` present |
| 3.1 | Original/fresh CPU+IP PIDs distinct, exit 0, reaped | **PASS** | `.../timer/execution_audit.json` (`143898ac…`), `.../timer/fresh-1/execution_audit.json` (`30769f68…`); SPI (`25c839e0…`, `c48d220f…`) | Timer CPU `261178`→`265753`, IP `261124`→`265699`; SPI CPU `272339`→`276464`, IP `272285`→`276410`; all `returncode=0`, `reaped=true`, `closed=true` |
| 3.2 | Fresh comparison matches true / first_difference null / full | **PASS** | `fresh-1/comparison.json`, `replays.json` | `matches=true`, `first_difference=null`, `verification_scope=full`, `scope=full_fresh_prefix_real_RTL_and_live_read_versions` |
| 3.3 | Build/binary/artifact identities stable | **PASS** | `fresh-1/comparison.json` `original_build`/`fresh_build`; build join `original`/`fresh` | identical `artifact_digest`, `binary_sha256`, `build_digest`, `built_receipt_sha256`, `observed_executable_sha256`, `ready_artifact_digest`; only `pid` and `execution_nonce` differ |
| 4.1 | `saved_file_hashes.json` recovery | **PASS** | `.../timer/saved_file_hashes.json` (`6df83949…`), SPI (`9d86c0c6…`) | 28/28 entries match the external outputs; the 12 committed pinned documents match their committed bytes; committed `report.json`/`saved_file_hashes.json` are byte-identical to the external copies |
| 4.2 | `source_input_hashes.json` vs **current working tree** | **PASS** | `.../timer/source_input_hashes.json` (`cf51b571…`, 1154 entries), SPI (`9d5e729d…`, 961 entries) | Timer 1153/1154 match; SPI 961/961 match |
| 4.3 | Timer caveat: one later fixed-ownership file differs | **PASS** | `timer/source_input_hashes.json` row `/home/qinkejiu/myfuzz/src/myfuzz/integration/compiled_execution_files.py` | only mismatch: pinned `3e6aa33991a42372…` vs current `1f5b4fe7439dfe62…`; Timer generated peripheral artifact `fixed_physical_inputs=[]`, so the later ownership derivation is a functional no-op for Timer |
| 4.4 | SPI 961 equal "current **committed** tree" | **PASS WITH GAPS** | `spi/source_input_hashes.json`; `git archive 91a8037`/`a54289b`/`HEAD` | true for the working tree (961/961) but **not** for any commit: 834 match, 40 differ, 38 absent, 49 submodule; committed tree cannot import the gate (F-1) |
| 5.1 | Failed-attempt evidence preserved | **PASS WITH GAPS** | `failed-attempts/*-report.json`, `failed-attempts/*.log` | 6 reports committed and byte-identical to external failed dirs; error strings match the report exactly; the 6 logs + 2 `gate.log` are **untracked** (`.gitignore:13 *.log`) though byte-identical to the external controller logs |
| 5.2 | Boundary claims honest (one candidate, reset-zero, no throughput, no F4/F1/F3/F5/F6/P6/P7/P8) | **PASS WITH GAPS** | report lines 158–172; `prefix.feedback`; artifacts | one record, `distinct_addresses=1`, `dependent_result_stores=1`, `register_versions=1`; PRDATA 0, store `0x5a5`; `coverage_guided=false`, `general_instruction_search=false`, `full_D4_accepted=false`; disclaimers accurate, except F-3/F-4/F-2 below |
| 5.3 | "No renamed-instance native control" | **UNVERIFIABLE** | report line 166 | negative claim; no renamed-instance native evidence anywhere in the bundle; only a pure renamed-component test exists (`tests/local_harness/test_harness_set.py::test_v2_route_uses_declared_endpoint_ids_with_renamed_instances`), not committed evidence |
| 5.4 | "No F4 native re-run after these F2 changes" | **PASS** | `docs/reports/evidence/compiled-f4-*` mtimes | mtime support only: newest F4 native evidence is `2026-10-22 23:39 +0800`, F2 Timer gate starts `2026-10-23 05:04 +0800`; no F4 native output is newer; the claim is not otherwise logged |
| 5.5 | "187 passed, 0 failed" / "7 passed" test claims | **UNVERIFIABLE** | report lines 141–156 | no committed pytest log or exit record; not re-run here because the working tree differs from the audited commits |

## 1. Report documents

### 1.1 `report.json` (both instances)

Both report documents are `compiled_execution_files_report.v1` and agree with
the per-gate evidence:

| Field | Timer | SPI |
|---|---|---|
| `status` | `completed` | `completed` |
| `error` / `error_type` | absent (no key) | absent (no key) |
| `executor` / `flow` | `compiled_f2_obi_apb` / `F2` | same |
| `runtime_admitted` | `true` | `true` |
| `cases` / `certified_cases` / `replays` | `1` / `1` / `1` | same |
| `case_wall_seconds` | `66.443075…` | `84.368524…` |
| `startup_seconds` | `12.862212…` | `24.118488…` |
| `total_wall_seconds` | `192.225059…` | `232.149637…` |
| `capability_report_sha256` | `9ad8279d59a6ee3a1331c5d6332ec2af62f1d541750ff0ccdb689330b4bc48e8` | `205b85cfd0d17278989cb8c8e6fad794a62791aafb85e60a039aec0c7f20dc57` |
| `build_join.status` / `.sha256` | `complete` / `70ed848b…7c692f` | `complete` / `68aa273e…7338df` |
| `semantic_hash` | `255a637c…5a29c5` | `7daccad3…cafab21` |
| `heavy_lock` | `/home/qinkejiu/.native-gate/f2-heavy.lock` | same |

The `capability_report_sha256` equals the file's sha256 and the
`saved_file_hashes.json` entry; the build-join sha256 equals the file's sha256
and the saved entry. The report's success path never writes an `error` field
(`src/myfuzz/integration/compiled_execution_files.py:460-466`); the failure path
does (`:481-504`), which is why the six failed reports carry `error_type`/`error`
and the two successful ones do not. Reading "error null" as "no error field" is
correct; there is no explicit `error: null`.

The support document (`capability_report.json`) is the pre-startup
`compiled_F2_support.v1`: `execution_supported=1`, `runtime_admitted=false`,
`status=supported_requires_actual_startup`, `startup_requires` lists the five
requirements. That is consistent with the report's statement that support
"starts no process"; the run-level `report.json` `runtime_admitted=true` is the
post-gate value.

### 1.2 Prefix, replays and fresh comparison

- `prefix.json` has `run_id` `compiled-f2-timer-read` / `compiled-f2-spi-read`,
  `max_cases=1`, `rounds_per_case=128`, one `record`, one certificate.
- `replays.json` is a one-element list. `fresh-1/comparison.json` is the same
  comparison without `wall_seconds`/`artifact_directory`.
- The saved `prefix.json` and external `fresh-1/prefix.json` have the **same**
  sha256 (`59845b984…` Timer, `1023f8a602…` SPI), i.e. the process-stable
  projection is byte-identical between original and fresh. Process identity is
  validated live and projected out (`certificate_projection:
  stable_fields_only_process_fields_validated_live`).
- `case_timings.json` has one row, `certified=true`.

### 1.3 Semantic hash — independent recomputation

The committed semantic hash is not merely copied between documents; it
recomputes from the external event journal. Using the repository's
`normalized_semantic_sha256` from `src/myfuzz/integration/compiled_f4.py`
(the function body is identical at `HEAD`, `a54289b` and the working tree):

```
normalized_semantic_sha256('complete', events, {'peripheral':133,'processor':129})
```

gives `255a637c1126887a8aa3dfe496d9f121b79a70aea4862f3e93811b42515a29c5`
(Timer) and `7daccad37e5c171093f50e68af01bea3d3892b95e88b15725a710a2ddcafab21`
(SPI) — exactly the committed `report`, `prefix`, `replays` and `comparison`
values. The **fresh** event journals (`fresh-1/events.json`) also recompute to
the same two hashes, while the raw fresh journals differ from the originals in
process-local fields. This is the strongest independent check in the package.

### 1.4 Build join

Both `compiled_f2_build_join.v1.json` documents are `status=complete` with
`error=None`, `logical_path_id=F2:ram.image`, `runtime_path_id=ba230cff…`,
two artifact digests and two receipts. I re-ran the shipped verifier:

```
load_generated_artifacts(generated_root=/home/qinkejiu/.native-gate/f2-<name>/generated,
                         base_dir=/home/qinkejiu/myfuzz)
verify_compiled_f2_build_join(document, flow='F2', artifacts=…,
    execution_binding=prefix['execution_binding'],
    original=document['original'], fresh=document['fresh'])
```

→ **PASS** for both. `validate_built_receipts` passes; each receipt's
`build_digest` recomputes as `sha256(canonical(build_identity minus build_digest))`;
`built_executable_receipts_sha256` equals the canonical receipt map. This
independently confirms the reported build-join sha256s `70ed848b…7c692f` /
`68aa273e…7338df`. Caveat: the verifier module
(`src/myfuzz/integration/compiled_build_join.py`) is itself untracked (F-1), so
this is an independent *reconstruction* of the saved document, not an
independently implemented verifier; the individual receipt, binding and
artifact digests were also recomputed directly as canonical-JSON sha256.

## 2. Certificates

### 2.1 Prerequisite — `ip_register_version`, not a RAM version

Both certificates (`prefix.json → records[0].certificate`) carry:

```json
"prerequisite": {
  "kind": "ip_register_version",
  "subject": {"component": "peripheral", "register": "TIMER0_CTRL" | "SPICMD",
              "reset_epoch": 0},
  "evidence_ref": "gpio_register_commit.v1:peripheral:0:78:TIMER0_CTRL:0"
                | "gpio_register_commit.v1:peripheral:0:399:SPICMD:0",
  "schema_version": "source_prerequisite.v1"
}
```

The `gpio_register_commit.v1:…` string is the legacy **event-kind name for an
APB register commit**, produced by `ip_register_evidence_ref(component,
register, reset_epoch, observation_event_id, version)` in
`src/myfuzz/scenario/source_actions.py:176-183`; it is not a RAM reference. The
observation event is the live native APB transaction on the target bus (event
raw ref `78` / `399`; the corresponding journal event is
`transaction_accept`, `endpoint_id=timer.bus|spi.bus`, `component_id=pulp_timer|
pulp_spi`). The companion version documents are
`apb_storage_register_version.v1` with `field_version=0`, `value=0`,
`write_count=0`, `reset_epoch=0`, `artifact_digest` equal to the target artifact,
`probe_digest` and `source_contract_digest` equal to the storage probe/contract —
no RAM byte offset, memory id or `ram_byte_version` appears. The producer
declares `allowed_kinds=['ip_register_version']`
(`src/myfuzz/integration/compiled_storage_producer.py:329-330,461-462`) and the
consumer enforces the same (`src/myfuzz/integration/generated_storage_consumer.py:784-786`).
**No RAM-version masquerade.**

### 2.2 Edges

| Edge | relation | role | source → target | rule |
|---|---|---|---|---|
| 0 | `persistent_state` | `read_request` | `processor` → `processor` (resource `processor/ram`) | 1 |
| 1 | `mmio_route` | `read_request` | `processor` → `peripheral` (base `1073745920`, size `4096`, `device_id=peripheral`) | 2 |
| 2 | `mmio_route` | `read_return` | `peripheral` → `processor` | 3 |

All three are `status=certified` in both gates. The first edge is a persistent
instruction/state relation, not an MMIO route; the only `mmio_route` edges are
CPU→IP (`read_request`) and IP→CPU (`read_return`). **No CPU→CPU MMIO
fabrication.** The assertion evidence records the same endpoint sequence
`[[processor,processor],[processor,peripheral],[peripheral,processor]]` and
`edge_ids [[1,0],[2,0],[3,0]]`.

Native hop numbers are consistent between certificate and events:

| Gate | APB sample | OBI acceptance | OBI response | dependent store |
|---|---|---|---|---|
| Timer | `78` | `67` | `97` | write `149`, OBI accept `148`, OBI resp `166` |
| SPI | `399` | `295` | `493` | write `722`, OBI accept `712`, OBI resp `786` |

### 2.3 Dependent store — value right, address in the report wrong

`ram_write_hop` (both gates):

```json
{"address": 262140, "byte_offset": 196604, "value": 1445, "width_bytes": 4,
 "native_acceptance_event": 148|712, "native_obi": {"address": 262140,
 "value": 1445, "write": 1, "response_event": 166|786, ...}}
```

The native read PRDATA is `0` (`native_obi.rdata=0` on both MMIO edges), so
`0 XOR 0x5a5 = 0x5a5 = 1445`. The consumer check is exactly
`e['value'] == (pre['value'] ^ 0x5a5)` and `e['address'] ==
declaration['result_address']` (`src/myfuzz/integration/compiled_f2_consumer.py:220-226`);
the result word is `image.range[1]-3 = 262143-3 = 262140` in
`src/myfuzz/integration/compiled_f4.py:761,850`. The external `events.json`
contains one `memory_write` event `{address: 262140, value: 1445}`.

**Report defect (F-3):** report line 96 says the store is at
`0x0004003c`. `262140` is `0x0003fffc`; `0x0004003c` is `262204`, which is
outside the declared RAM range `0x10000–0x3ffff`. The byte offset `196604`
(`262140 - 65536`) is correct, so only the absolute-address hex is wrong.

### 2.4 Typed assertions

The certificate `assertions` and the `prefix.assertions` document
(`compiled_assertion_results.v1`) both show:

- `protocol_checker.receipt_violations`: `passed`, `violations: []`;
- `cross_component.declared_edge_hops`: `passed`, with
  `native_read_APB_event`, `native_read_OBI_events`, `dependent_RAM_write_event`
  and the three edge joins.

The document's `binding_sha256` equals the certificate's
`execution_binding_sha256` (which recomputes from the binding document),
`compiled_document_sha256` equals the producer binding's `compiled_sha256`,
and `path_id` / `path_sha256` / `run_id` all match the prefix. The declared
`execution_contract.expectation_ids` is exactly those two ids. **Both typed
expectations passed and are bound.**

## 3. Process records

`execution_audit.json` (`compiled_F2_execution_audit.v1`) and the fresh copies:

| Gate | Run | CPU pid | IP pid | exit | reaped | closed |
|---|---|---|---|---|---|---|
| Timer | original | `261178` | `261124` | 0 / 0 | true | true |
| Timer | fresh | `265753` | `265699` | 0 / 0 | true | true |
| SPI | original | `272339` | `272285` | 0 / 0 | true | true |
| SPI | fresh | `276464` | `276410` | 0 / 0 | true | true |

All four PIDs per gate are distinct; CPU and IP nonces are distinct. Between
original and fresh, every identity field is identical (`artifact_digest`,
`binary_sha256`, `build_digest`, `built_receipt_sha256`,
`observed_executable_sha256`, `ready_artifact_digest`, `role`, `argv`, `reaped`,
`returncode`, `aborted`, `failure_stage`) and only `pid` and `execution_nonce`
change. The fresh comparison is `matches: true`, `first_difference: null`,
`verification_scope: full`.

The report's binary prefixes are exact:
`a2af5a1c…62460f` / `3ef38b1d…144044` (Timer CPU/IP) and
`03f255ae…d42c68` / `839b7cc7…299ff67` (SPI CPU/IP).

## 4. Independent recovery

### 4.1 `saved_file_hashes.json`

28 entries per gate. Every entry verifies against
`/home/qinkejiu/.native-gate/f2-<name>/<relative>` (external full outputs,
present and retained). Of the 28, 12 are also committed under the evidence
directory and match their `saved_file_hashes` bytes; the other 16
(`events.json`, `fresh-1/{events,prefix,artifact_hashes}.json`,
`capability_selection.json`, `path_compile_request.json`, `generated/**`) are
external-only. The committed `report.json` and `saved_file_hashes.json` are
byte-identical to the external copies. The report discloses that the full
outputs are not committed and are pinned by these hashes; that disclosure is
accurate.

### 4.2 `source_input_hashes.json` against the current tree

| Gate | Entries | Match current working tree | Mismatch |
|---|---|---|---|
| Timer | 1154 | 1153 | `src/myfuzz/integration/compiled_execution_files.py` |
| SPI | 961 | 961 | none |

The Timer mismatch is exactly the pinned `3e6aa33991a42372…` versus current
`1f5b4fe7439dfe62…`. The SPI pin equals the committed
`compiled_execution_files.py` (`1f5b4fe7…`) that contains
`_artifact_fixed_input_ownership`. The generated peripheral artifact for Timer
declares `fixed_physical_inputs: []`, while SPI declares the four
`spi.pins.sdi*` sidebands, which supports the report's claim that the later
ownership derivation does not change Timer's already-passed run. The pinned
Timer bytes themselves are not recoverable from git (no commit or dangling blob
has sha256 `3e6aa339…`), so the "only this change" diff cannot be proven
byte-for-byte; the no-op argument rests on the empty Timer fixed-input list and
the 1153 matching files.

Submodule files (49 SPI / 242 Timer, under `external_designs/` and
`third_party/`) match the current checked-out submodule trees; they are
gitlinks in the superproject and were not compared to superproject blobs.

### 4.3 The "current committed tree" problem (F-1)

Comparing the 961/1154 pinned entries with the audited commits:

| Gate | Match HEAD | Differ from HEAD | Absent from HEAD | Submodule (not comparable) |
|---|---|---|---|---|
| SPI | 834 | 40 | 38 | 49 |
| Timer | 833 | 41 | 38 | 242 |

So `78` SPI / `79` Timer `src/` files are not at their pinned bytes in the
audited commits (`HEAD`/`91a8037` show 40/41 tracked-file differences; `a54289b`
differs by one more). Of the 38 absent files, 37 are Python modules and 1 is an
incidental CMake artifact
(`src/myfuzz/frontend/build/CMakeFiles/3.28.3/CompilerIdCXX/CMakeCXXCompilerId.cpp`);
16 of the absent modules are in the entry's static import closure, including
`integration/compiled_build_join.py`, `integration/compiled_f4_build_join.py`,
`integration/compiled_f4_runtime_path.py`, `integration/native_obi_hops.py`,
`scenario/compiled_assertion_results.py`, `scenario/instruction_image_binding.py`.
The 40/41 differing files include `integration/compiled_f4.py`,
`integration/compiled_rfuzz.py`, `scenario/runtime_path_contract.py`,
`scenario/apb_storage_register_version.py`, and the Timer-only
`compiled_execution_files.py`.

This is not cosmetic. The tracked `compiled_f2.py` imports
`_diagnostic_build_snapshot` and `_artifact_execution_identity` from
`.compiled_f4`, but the committed `compiled_f4.py` defines neither; and tracked
`compiled_execution_files.py:27` imports `_diagnostic_build_snapshot` at module
level. A `git archive 91a8037` import test fails:

```
import myfuzz.integration.compiled_f2_build_join
  → ModuleNotFoundError: No module named 'myfuzz.integration.compiled_build_join'
import myfuzz.integration.compiled_f2
  → ModuleNotFoundError: No module named 'myfuzz.scenario.instruction_image_binding'
```

(`a54289b` fails the same way.) Therefore the report's sentence "its 961 pinned
source files equal the current committed tree exactly" (line 65) is **false as
written**. The correct statement is: the pins equal the **current working tree**
(961/961, 1153/1154); excluding the 49/242 submodule entries, the audited
commits reproduce only 834 of 912 (SPI) and 833 of 912 (Timer) executed source
files — the other 78/79 are untracked or modified — and the committed tree
cannot import the gate. Submodule contents remain reconstructible from their
own checked-out commits; the gap is confined to the superproject source. The run
is recoverable today only because the uncommitted working-tree files still
exist. This is the main residual gap in "independent recovery".

### 4.4 Build join re-verification

Already covered in §1.4: both joins pass the shipped verifier against the
external generated artifacts and the binding embedded in `prefix.json`.

## 5. Failed attempts and boundaries

### 5.1 Preserved failed attempts

Six failed attempts are present:

| Attempt | `status` | `error_type` | `error` | external dir |
|---|---|---|---|---|
| Timer 1 | `refused` | `ValueError` | `compiled-files-candidate-address-range` | `f2-timer-failed-attempt1` |
| Timer 2 | `refused` | `ValueError` | `compiled-F2-producer-binding-changed` | `f2-timer-failed-attempt2` |
| Timer 3 | `incomplete` | `ValueError` | `compiled-F2-protocol-checker-failed:('storage-version-token-invalid',)` | `f2-timer-failed-attempt3` |
| Timer 4 | `incomplete` | `KeyError` | `'postcondition'` | `f2-timer-failed-attempt4` |
| Timer 5 | `incomplete` | `NameError` | `name 'compiled_document_sha256' is not defined` | `f2-timer-failed-attempt5` |
| SPI 1 | `refused` | `ValueError` | `generic APB3 scenario ownership fields mismatch physical inputs` | `f2-spi-failed-attempt1` |

The committed reports are byte-identical to the external `report.json`s, and
the error strings match the report's narrative. The six external directories
exist and were not overwritten.

**Gap (F-4):** the report says "Every failed attempt's `report.json` and log are
committed". The six `.log` files (and the two `gate.log` files) are **not**
committed: they match `.gitignore:13 *.log` and are absent from `a54289b`/
`91a8037`/`HEAD`; only the working-tree copies exist. They are byte-identical to
the external controller logs, so they are preserved locally, but a clean
checkout does not contain them. The bundle has 44 files, 36 tracked, 8
untracked logs.

### 5.2 Boundary claims

The report's boundary section is mostly accurate and conservative:

- **One candidate per instance / reset-zero:** `records` has one entry
  (`04100040` → `0x40001004`; `08100040` → `0x40001008`); `feedback` is
  `{cases:1, certified:1, dependent_result_stores:1, distinct_addresses:1,
  register_versions:1}`; PRDATA is `0`; the store is `0x5a5`. Correct.
- **No mutation diversity / throughput / search quality:** `coverage_guided=false`,
  `general_instruction_search=false`, one case, `useful_cases_per_second
  ≈0.015`. Correct and explicitly disclaimed.
- **No seed / extra source / hidden setup write / diagnostic access / PRDATA
  entropy:** `producer.session_construction` is
  `{bound_inputs:[], dynamic_inputs:[], probe_offsets:[], setup_writes:[]}`;
  `seed=null`; the consumer requires exactly one `ACCESS_APB3_REG` and no
  unexpected commands. Consistent.
- **No F1 retirement / F3/F5/F6 / P6/P7-E/P8 / system completion:** the
  certificate edges stop at `F2.data_read_consumed`; the report and the
  capability docs disclaim the rest; `full_D4_accepted=false`.
- **No F4 native re-run:** no F4 native evidence is newer than the F2 gate
  (newest F4 native file `2026-10-22 23:39 +0800` vs F2 start
  `2026-10-23 05:04 +0800`). Weak but consistent.
- **No renamed-instance native control:** negative claim, not independently
  evidenced; only the pure edge/admission test exists.

### 5.3 Other report-text defects

- **F-2 (CPU label).** Report line 4 calls the Timer CPU "CV32E20/CVE2". The
  executed artifact is `ibex_obi_local` / `ibex_top` from
  `third_party/rfuzz/upstream/ibex` (`generated/processor/source_verification.json`:
  `closure_roots=["third_party/rfuzz/upstream/ibex"]`, `top_module="ibex_top"`).
  The repo has a separate `cv32e20` source
  (`third_party/cv32e20_upstream_reference`, `cve2_*`). The harness class is
  generically named `GeneratedCve2Session`, which may explain the slip, but the
  RTL is Ibex, not CV32E20/CVE2.
- **F-5 (wording).** The report calls the fresh comparison scope `full`; the
  document field is `verification_scope: "full"` while `scope` is
  `"full_fresh_prefix_real_RTL_and_live_read_versions"`. Harmless ambiguity.
- **F-5 (error null).** No explicit `error: null` field exists on success
  (`report.json`); absence is the representation. If the audit rubric expects a
  literal `null`, that is a schema-presentation gap, not a false success.

## 6. Residual gaps

1. **Source closure is not committed (F-1, material).** 78 SPI / 79 Timer `src/`
   files are not at their pinned bytes in the audited commits; the committed
   tree cannot import the gate. Reproducibility depends on the dirty working
   tree and on the external `/home/qinkejiu/.native-gate` outputs. The report
   should say "current working tree", not "current committed tree".2. **Result-word address typo (F-3, material to citation).** Report line 96:
   `0x0004003c` → correct `0x0003fffc` (`262140`); `0x4003c` is outside the
   declared RAM range.
3. **Failed-attempt logs not committed (F-4, minor).** The report's "log are
   committed" is false; 8 `.log` files are gitignored and only exist in the
   working tree / external outputs.
4. **Timer caveat's "only this change" not byte-provable (minor).** The pinned
   Timer `compiled_execution_files.py` (`3e6aa339…`) is not in any commit or
   dangling blob; the no-op conclusion rests on the empty Timer fixed-input list
   and the other 1153 matches.
5. **External-only pinned documents (disclosed).** 16 of the 28 pinned documents
   (events, fresh prefix/events, generated/*, capability_selection,
   path_compile_request) are not committed. All 28 match the retained external
   outputs today.
6. **Test counts and negative claims (unverifiable).** "187 passed" / "7 passed"
   have no committed log; "no renamed-instance native" and "no other agent's
   lock/output was touched" are negative claims with no artifact.
7. **CPU label (F-2, minor).** "CV32E20/CVE2" should read "lowRISC Ibex
   (`ibex_obi_local`/`ibex_top`)".

## Appendix — recomputation details

- Semantic hash: `normalized_semantic_sha256('complete', events,
  {'peripheral':133,'processor':129})`; ticks inferred as the maximum
  `local_tick` per component in the event journal, and confirmed by the
  certificate `version_witness.local_tick=133`/`command_sequence=130`.
- Build join: `verify_compiled_f2_build_join` + `validate_built_receipts` from
  `src/myfuzz/integration/compiled_build_join.py` (working-tree module; the
  function bodies used here are not part of the committed tree — see F-1).
- Hex/decimal: `262140 = 0x3fffc`; `196604 = 0x2fffc`; `262204 = 0x4003c`;
  `1445 = 0x5a5`; Timer record `04100040` → `0x40001004`; SPI `08100040` →
  `0x40001008`.
- Evidence bundle: 44 files, 36 tracked; 8 `.log` files untracked
  (`.gitignore:13 *.log`). Report sha256
  `efdffa4b247cdcbd8715effb6a84991f22bb25914f2ca140e3db0cc6bdb17cde`.

No file outside this audit was created or modified; the `/tmp` archive
extractions used for the import test were removed.
