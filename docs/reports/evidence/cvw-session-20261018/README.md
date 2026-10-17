# CVW directed D4 session evidence (2026-10-18)

This directory preserves the evidence for the CVW/CORE-V Wally session-assembly
gap closure.  It was produced on the repository's single heavy-worker lock
(`flock -w 14400 /home/qinkejiu/myfuzz/.superpowers/heavy-worker.lock`) with real
Verilator RTL, from `/home/qinkejiu/myfuzz`.

## Main gate

`command.txt` is the exact command.  `run/` is the CLI's complete output
directory:

| file | meaning |
|---|---|
| `run/run-summary.json` | the driver's verdict: `status: complete`, `exit_code: 0`, every requested stage `ok` |
| `run/declaration-review.json` | D1 |
| `run/generated/harness_set.json` | D2 (one CVW + one PULP GPIO harness) |
| `run/compiled_paths.v1.json` | D3 (`{executable: 4, unsupported: 2}`) |
| `run/execution_projection.v1.json` | explicitly `directed_fixed_image`, `runtime_admitted: false` |
| `run/session/report.json` | the real directed case: 1 test, 43 accepted AHB beats, 7 CPU→GPIO APB deliveries, `[0x35,0x6a,1,0xa5]`, final GPIO state |
| `run/session/receipts.jsonl` | the one F4 receipt: `rtl_case_committed`, CPU 172 / GPIO 201 local ticks, five `cpu:gpio:apb…` features |
| `run/session/directed-session.json` | the complete first/fresh evidence and comparison |
| `run/bundle/bundle-manifest.json` | second view of the directed documents (not an RFuzz authenticated prefix) |
| `run/fresh-verification.json` | `matches: true`, `first_difference: null`, `verification_scope: full` |
| `run/capability-report.json` | F4: `RTL operational` + `Cross-component accepted`; coverage/bug not claimed |
| `run/.incomplete` | **absent**: the run completed |

`stdout.log` is the CLI's JSON summary line; `stderr.log` is empty;
`gate-exit.txt` records the exit code and wall time.

## Negative control

`client-binary-refusal/` is a real CLI run of the same family with
`--client-binary third_party/rfuzz/…/kfuzz`.  It completes D1–D3 and refuses the
session stage with `directed-session-does-not-consume-client-binary`; no
session is started.  See `client-binary-refusal.stdout.log`.

## Tests

- `pytest-gate.log` — the gated real test
  `test_the_family_cli_starts_a_real_directed_session_and_grades_f4`
  (`1 passed`).
- `ahb-session-tests.log` — `tests/local_harness/test_ahb_lite_session.py`
  (`8 passed`), including the boot-hold and boot-from-service tests.
- `static-chain-tests.log` — the existing
  `tests/integration/test_cvw_cpu_pulp_gpio_chain_real.py` (`2 passed`);
  `static-chain/{first,fresh}.json` are its complete raw observations.
- `ahb-runtime-generation-tests.log` — `tests/integration/test_cvw_ahb_runtime_generation.py`
  (`4 passed`, including the real-CVW elaboration).
- `run-tests.sh` / `run-rtl-regressions.sh` — the reproduction scripts for the
  tests above.
- `source-identity.json` — HEAD, the worktree status, the audited file hashes,
  and the gate verdict.

## Boundaries

This is a **directed fixed-image session**, not an RFuzz online campaign: no
`OnlineCaseDecoder`, no per-case reserved instruction window, no RFuzz client,
no coverage feedback.  It does not claim F5 interrupt consumption, F6 DMA,
retirement observation, or native IRQ receipts.  See
`../../cvw-directed-session-20261018.md` for the full report.
