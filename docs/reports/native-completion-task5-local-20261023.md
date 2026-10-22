# Native exact-source completion Task 5 local three-branch gate (2026-10-23)

Commit: `d8d88c7` (fix: leave the truthful terminal cleanup state after a
source refusal), parent `06ee952`. This is a **local** real-RTL gate; it is not
the remote r11 Stage 2 package/independent-auditor acceptance.

## Command

```sh
PYTHONPATH=src python3 scripts/verify_picorv32_native_online.py \
  --output /home/qinkejiu/.native-gate/agent-refusal-1/run2 \
  --cache-dir /home/qinkejiu/.native-gate/agent-refusal-1/cache \
  --heavy-lock /home/qinkejiu/.native-gate/agent-refusal-1/heavy.lock \
  --gate-run-id fdeab0ce868540f0d429df29ec71f2fce7c2ee4eaffcde416065f5d53d7285ca \
  --native-completion-observation --native-source-binding \
  --native-source-completion
```

Archived evidence: `docs/reports/evidence/native-completion-task5-local-20261023/`.

## Result

`summary.json.gz` (SHA-256 `15a089d7c1efb8c353ae9fce175a79701a094ca7463865834ba60085debd3543`):

- `positive_status=bounded_directed_gate_passed`
- `controlled_status=bounded_directed_gate_passed`
- `native_source_refusal_status=native_source_completion_refusal_gate_passed`
- `coverage_guided_search=false`, `formal_p6_complete=false`,
  `retirement_authority=false`, `source_authority=false`
- `script_sha256=1422dc3f595eb97f181a6a875d271af238031d7fbd7d5f9a2914c54ab4cc7124`

Branch evidence:

| Branch | result SHA-256 | Process terminal |
|---|---|---|
| positive | `e48e69c5ea731d3fd8eb3f8e5d6024050f3e9ab393139eccafaa94ff788c3528` | cpu 0, gpio0 0, cpu 0, gpio0 0 |
| controlled-response | `cd352010fd84b593283bcd231181880d468eeee48f6e8f637ccad091907ef136` | cpu 0, gpio0 0, cpu 0, gpio0 0 |
| native-source-refusal | `4ee8c3b128034644dad251708cdaecdc860687a9b9f62413f3a0dd7192e58a99` | cpu 0, gpio0 0, cpu 0, gpio0 0 |

The refusal branch retains the exact selected-source contradiction, one
retained pending response, the refused PRE sample, the poisoned write journal
and a full fresh replay; it is no longer SIGKILLed (`-9`) and no longer fails
the impossible `_pending`/`_case_id` assertions that were diagnosed from the
real state.

## Fix boundary

The source fix is narrow:

- The refusal path now performs the graceful terminal close instead of treating
  the declared candidate refusal as an environment kill.
- `_validate_native_source_completion_terminal_cleanup` checks the retained
  response in `observer.pending` and the immutable
  `reference.template.testcase_id`, not host fields that are legitimately
  cleared at the response edge.

Every retained-response, transaction, writer, PRE/POST, journal and process
check remains; no positive/controlled behavior was weakened.

## What this does not prove

- It is a local real-RTL run. It does not prove the remote `/root/fanzehui/myfuzz`
  Stage 2 upload, claim, controller lifecycle, independent post-gate auditor,
  source-tree/tool closure or gate executable identity. The r11 Task 5 plan
  remains open.
- Proof scope is `native_instruction_bus_transfer_completed`; it does not prove
  decode, architectural retirement, CPU semantic consumption, peripheral payload
  consumption or feedback.
- It does not close P6/P7/P8 or the six-CPU/four-IP objective.
- The remote r11 controller/package and independent audit are still required
  before calling Task 5 complete.


## Source closure (post-audit)

The gate executed the shared working tree; its exact source is now committed as
`9573e7c` (`feat(native): integrate exact-source completion Task5 source and
evidence`). This includes the seven modified modules and the previously
untracked `native_instruction_bus_completion.py` identified by the independent
audit, plus the verifier and gate script. The audit's F-1 finding (run not
reproducible from `d8d88c7` alone) is therefore resolved by source integration;
the module hashes were not archived in the gate bundle, so reproducibility is
by committed source bytes and the archived script SHA, not a per-module receipt.

Independent audit: `docs/reports/native-task5-local-independent-audit-20261023.md`
(verdict: branch results supported; no remote Stage2/independent r11 auditor).
