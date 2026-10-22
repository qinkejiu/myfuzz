# Compiled F2 native Timer/SPI read-response first/fresh gates

Status: **both registered F2 instances pass real first/fresh native gates**.
Timer (lowRISC Ibex `ibex_obi_local` OBI + PULP APB timer `TIMER0_CTRL`) and SPI
(CV32E40P OBI + PULP APB SPI `SPICMD`) each executed one declared read
candidate, consumed the real IP PRDATA through native OBI, stored
`PRDATA XOR 0x5a5` in the declared result RAM word, and replayed the complete
prefix in fresh processes with full equality. No F1 retirement, F3/F5/F6,
F4 re-acceptance, P6/P7-E/P8 or system completion is claimed.

Design: [approved specification](../superpowers/specs/2026-10-23-compiled-f2-read-response-design.md).
Previous slice: [F2 read-response runtime](compiled-f2-read-response-runtime-20261023.md).
Evidence: [evidence bundle](evidence/compiled-f2-native-gate-20261023/).
External full outputs: `/home/qinkejiu/.native-gate/f2-timer`, `f2-spi`
(not committed; every saved byte is pinned by the committed
`saved_file_hashes.json` and `source_input_hashes.json` remains in the output).

## Public entry

`CompiledF2Runtime` is now selected and executed through the existing file
entry `scripts/run_compiled_dataflow.py`:

- `src/myfuzz/local_harness/compiled_execution_projection.py` adds
  `assess_compiled_f2_support` (`compiled_F2_support.v1`): source-backed
  producer binding, `execution_supported=1`, `runtime_admitted=false`,
  `flow_id=F2`, startup requirements. It starts no process.
- `src/myfuzz/local_harness/generated_execution_admission.py` dispatches
  `executor=compiled_f2_obi_apb` to `CompiledF2Runtime` (unknown executors still
  refuse).
- `src/myfuzz/integration/compiled_execution_files.py` is flow-aware (F4/F2):
  four-byte F2 address records, F2 layout classification, typed capability
  report, `compiled_f2_build_join.v1` run-level join
  (`build_compiled_f2_build_join` + `verify_compiled_f2_build_join`),
  capability-report re-derivation, same-call saved-file pinning
  (`_pin_saved_document`, `saved_file_hashes.json`) and exact preserved
  original/fresh build/execution snapshots. It also derives profile-constant
  fixed physical input ownership from the validated D2 artifacts (needed by the
  SPI sideband pins) instead of accepting an unowned physical input.
- F2 address records are pinned in the configs:
  `configs/scenarios/compiled-f4-obi-apb-timer/f2_read_records.json`
  (`04100040` = `0x40001004`, `TIMER0_CTRL`) and
  `configs/scenarios/compiled-f4-obi-apb-spi-cv32e40p/f2_read_records.json`
  (`08100040` = `0x40001008`, `SPICMD`), with the SPI file supplement
  `f2_execution_supplement.json`.

Command (identical shape for both gates; outputs must be new):

```
PYTHONPATH=src:. python3 scripts/run_compiled_dataflow.py \
  --compose configs/scenarios/<config>/compose.json \
  --ip-capability configs/scenarios/<config>/test_capability.json \
  --supplement configs/scenarios/<config>/<supplement>.json \
  --records configs/scenarios/<config>/f2_read_records.json \
  --executor compiled_f2_obi_apb \
  --output /home/qinkejiu/.native-gate/f2-<name> \
  --cache-dir /home/qinkejiu/.native-gate/cache \
  --heavy-lock /home/qinkejiu/.native-gate/f2-heavy.lock \
  --run-id compiled-f2-<name>-read --max-cases 1 --rounds-per-case 128 --replays 1
```

The canonical `/home/qinkejiu/.native-gate/cache` build cache was reused
(Timer startup 12.9 s; SPI startup 24.1 s). The lock is the external
`f2-heavy.lock`; no other agent's lock/output was touched.

The SPI gate ran after the fixed-input-ownership addition; its 961 pinned source
files equal the source tree committed at `5634abb`. The Timer gate ran immediately
before that addition and its own 1154-file `source_input_hashes.json` pins the
exact bytes it executed: the only file differing from the committed tree is
`src/myfuzz/integration/compiled_execution_files.py`, whose later change only
derives profile-constant fixed-input ownership (the Timer target declares no
fixed inputs, so its already-passed run is unaffected).

## Real gate results

| Fact | Timer | SPI |
|---|---|---|
| Executor / flow | `compiled_f2_obi_apb` / F2 | `compiled_f2_obi_apb` / F2 |
| Register / exact address | `TIMER0_CTRL` / `0x40001004` | `SPICMD` / `0x40001008` |
| Gate CLI PID / exit | `257096` / **0** | `270387` / **0** |
| Started → finished (UTC) | `2026-10-22T21:04:38Z` → `21:08:09Z` | `2026-10-22T21:10:34Z` → `21:14:49Z` |
| Original CPU / IP PID | `261178` / `261124`, both exit 0, reaped | `272339` / `272285`, both exit 0, reaped |
| Fresh CPU / IP PID | `265753` / `265699`, both exit 0, reaped | `276464` / `276410`, both exit 0, reaped |
| Original CPU binary sha256 | `a2af5a1c…62460f` | `03f255ae…d42c68` |
| Original IP binary sha256 | `3ef38b1d…144044` | `839b7cc7…299ff67` |
| Case wall / startup / total | `66.44 s` / `12.86 s` / `192.23 s` | `84.37 s` / `24.12 s` / `232.15 s` |
| Fresh replay wall | `89.10 s` | `104.67 s` |
| Fresh comparison | `matches: true`, `first_difference: null`, scope `full` | same |
| Semantic hash (expected = actual) | `255a637c…5a29c5` | `7daccad3…cafab21` |
| `compiled_F2_build_join.v1` | `complete`, sha256 `70ed848b…7c692f` | `complete`, sha256 `68aa273e…7338df` |
| Capability report sha256 | `9ad8279d…4bc48e8` | `205b85cf…20dc57` |

Per-gate native chain (from the committed `prefix.json` certificates):

- Timer: APB read sample event `78`, native OBI data acceptance `67`, OBI
  response `97`; PRDATA `0`, dependent store `0x000005a5` (`1445`) at
  `0x0003fffc`/byte offset `196604`; edges `[processor→processor
  persistent_state, processor→peripheral read_request, peripheral→processor
  read_return]`, all certified.
- SPI: APB read sample event `399`, OBI acceptance `295`, response `493`;
  PRDATA `0`, dependent store `0x000005a5` at the same declared result word;
  the same three certified edges.
- Both certificates carry `kind=ip_register_version` prerequisites
  (`subject {component: peripheral, register: TIMER0_CTRL|SPICMD,
  reset_epoch: 0}`, live native APB observation event, field version 0) and the
  two typed expectations `protocol_checker.receipt_violations` and
  `cross_component.declared_edge_hops`, both `passed`, in a
  `compiled_assertion_results.v1` document bound to compiled/binding/path/run
  identity.
- Fresh processes re-admitted the private source documents and re-executed the
  same candidate; process identities differ, stable build/binary/artifact
  receipts are identical, and the full normalized prefix equaled the original.

## Development RED and preserved failures

The native gate was iterated openly. Every failed attempt's `report.json` and
log are committed under `evidence/.../failed-attempts/`; the external failed
output directories were retained (`f2-timer-failed-attempt1..5`,
`f2-spi-failed-attempt1`) and were not overwritten.

1. Timer attempt 1 — `compiled-files-candidate-address-range`: my first record
   used the wrong byte order for `0x40001004`. Fixed the pinned record.
2. Timer attempt 2 — `compiled-F2-producer-binding-changed`: the sealed F2
   producer binding has `eq=False`, so `_stable` compared identities instead of
   its canonical document. Fixed to compare type + `document_json`.
3. Timer attempt 3 — `compiled-F2-protocol-checker-failed:
   ('storage-version-token-invalid',)`: the post-read token was issued before
   the CPU case, but a new APB command clears earlier tokens. Native evidence in
   the failed output already showed the real case; the token is now issued after
   the command receipt, exactly as F4's consumer does.
4. Timer attempt 4 — `'postcondition'`: the fresh-prefix comparator expects a
   certificate `postcondition`; the F2 certificate now records the stable post
   read witness there. The original timer case had certified in this attempt.
5. Timer attempt 5 — `NameError: compiled_document_sha256`: missing import in
   the build-join path; the fresh comparison had already matched. Fixed.
6. SPI attempt 1 — `generic APB3 scenario ownership fields mismatch physical
   inputs`: SPI's profile-constant `spi.pins.sdi*` sidebands needed explicit
   Scenario ownership. The file entry now derives fixed-input fields/owners and
   physical ports from the validated artifact `fixed_physical_inputs` and
   physical exports.

## Focused software gates

```
PYTHONPATH=src:. python3 -m pytest -q -ra tests/integration/test_compiled_f2_execution_files.py \
  tests/integration/test_compiled_f2_read_response.py tests/integration/test_compiled_f2.py \
  tests/integration/test_compiled_f2_layout.py tests/integration/test_compiled_f2_consumer.py \
  tests/integration/test_compiled_f2_decoder.py tests/integration/test_compiled_f2_build_join.py \
  tests/integration/test_compiled_f2_runtime_path.py tests/integration/test_compiled_execution_files.py \
  tests/scenario/test_f2_read_contract.py tests/scenario/test_edge_provenance_f2_read.py \
  tests/scenario/test_edge_provenance.py tests/integration/test_compiled_f4_runtime_path.py
```

Result: **187 passed, 0 failed** (193.81 s), exit 0. New public-entry controls:
7 passed in 15.27 s (support report, flow mapping, four-byte record shape,
unknown-executor refusal, typed pre-generation refusal, saved-file swap
refusal).

## Boundaries

- The selected registers reset to zero, so PRDATA was `0x00000000` and the
  dependent store was `0x000005a5`. This proves the bounded chain, not mutation
  diversity, nonzero priming, stable throughput or search quality.
- One candidate per instance; the singleton address remains singleton. No seed,
  extra source, hidden setup write, diagnostic access or PRDATA entropy exists.
- No renamed-instance *native* control was run in this slice; the renamed-
  component pure edge/admission test is green and F2 selection is by
  contract/ownership, not names.
- No F4 native re-run was performed after these F2 changes. The F4 runtime-path
  software regression is green; current-source F4 native acceptance remains the
  main session's separate obligation.
- No F1 retirement, F3/F5/F6, arbitrary APB3 register semantics, AXI/AHB/TileLink
  execution, P6/P7-E/P8 or six-CPU/four-IP completion is claimed.


## Post-audit source closure

The independent audit (`docs/reports/f2-native-independent-audit-20261023.md`)
found that the exact executed source was still a dirty working tree at the time
of the gates. The complete source/test/config tree used by both gates is now
committed as `5634abb` (`chore: checkpoint current Codex system source and
tests`); the 38 previously untracked modules and the modified entry/build files
are included, so the committed tree can import and select the F2 executor. The
SPI 961-file pin therefore equals `5634abb`; the Timer run's single differing
file is the later fixed-input-ownership change described above (a functional
no-op for the Timer target). The failed-attempt logs are force-added despite the
repository `*.log` ignore rule. The audit's F-1 is resolved by source
integration; F-2/F-3/F-4 report-text issues are corrected here.


## Final clean-HEAD rerun (source-closed)

After `5634abb` committed the exact source used by the gates, both F2 instances
were rerun from the clean tree. Evidence:
`docs/reports/evidence/compiled-f2-native-gate-final-20261023/{timer,spi}/`.

- Timer: `status=completed`, 1 certified, semantic
  `9e90366a2194501ad14ad46516f566e21720366afdc9863c2e53a1841a36c9df`,
  build join `complete` `8ef6a67e…`, fresh `matches=true/full`.
- SPI: `status=completed`, 1 certified, semantic
  `da0e5e46034ba27b9cbd8ca734a16fb7d9b76d3feb8f4184925761838cc92323`,
  build join `complete` `4d22e476…`, fresh `matches=true/full`.
- Both ran with the same external cache/lock and produced new
  `saved_file_hashes.json`/`source_input_hashes.json`; the committed archive is
  the final source-closed evidence. The earlier a54289b bundle remains as the
  audited working-tree package and its failed attempts.
