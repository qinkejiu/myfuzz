# F6 saved limited-RVFI projection for CV32E40P (2026-10-30)

**Verdict: the archived (saved-semantics) projection now revalidates a CV32E40P
`pc_insn_order_only` F6 IRQ/ISR archive honestly from raw events, and refuses
fabricated full-RVFI claims. No native pass is claimed here:** no RTL campaign,
Verilator build or new simulation was started by this change, and every archive
in the tests is explicitly synthetic.

Scope of this change: `src/myfuzz/integration/compiled_f6_saved_semantics.py`
(one new authority-aware branch plus helpers), two new test files, and this
report. The registered contract side (`cv32e40p_irq_receipt_contract.py`,
`native_irq_receipt_contract.py`) and the live issuer
(`native_f6_isr_return.py`) are owned by another change and are already
visible in the tree; this projection consumes them and does not reimplement
them.

## 1. Authority split in the archived projection

The archived contract already carries `cpu.native_irq_provider`. The projection
selects the retirement authority from that registered provider only:

| `retirement_authority` in the archived provider | Archived branch | CPUs today |
| --- | --- | --- |
| absent (legacy) or `full_rvfi` | unchanged full-RVFI branch (same statements as before this change) | `ibex_rvfi_local`, `cv32e20` |
| `pc_insn_order_only` | new limited branch | `cv32e40p_rvfi_local` |
| any other declared value | refused: `unregistered-retirement-authority` | — |

Evidence for the split is `myfuzz.scenario.irq_return_successor.retirement_authority`
(the shared vocabulary the live issuer also uses), the registered
`validate_native_irq_receipt_contract`, and `native_irq_receipt_contract(cpu_artifact)`
when a CPU artifact is supplied. A limited provider is additionally pinned by
`_saved_retirement_scope` and refuses drift:

- observed retirement fields exactly `{valid, order, insn, pc_rdata}`;
- `unobserved_retirement_fields` declared, duplicate-free, disjoint from the
  observed set and a superset of `intr, pc_wdata, trap, mode, halt, mem_addr,
  mem_rdata, mem_wdata, mem_rmask, mem_wmask`;
- `native_irq_serial_observable(provider) is False` (no exact serial token);
- `native_irq_notification_observed(provider, ...) is False` (no post-edge
  notification, because `rvfi_intr` is not driven);
- `native_irq_retirement_diversion_scope(provider) == 'unobservable'`;
- `decision_acceptance` and the decision/redirect probe names and widths come
  from the contract (`ack_probe`, `id_probe`, `source_id`, `id_width`,
  `entry_pc_probe`; `irq_taken_pre`, `irq_masked_pre`, redirect probes).

The `physical_widths` table, required physical exports and probe widths for the
limited branch are all derived from that contract, so the projection never
assumes a field the CPU does not drive. The full-RVFI branch keeps its previous
width table and its previous statements verbatim.

## 2. Evidence schema of the limited rebuild

New/added `details` keys (additive; every pre-existing detail field is kept for
both authorities):

| key | value |
| --- | --- |
| `retirement_authority` | `full_rvfi` or `pc_insn_order_only` |
| `unobserved_fields` | normalized `rvfi_*` names this authority cannot observe (`[]` for full) |
| `retirement_diversion_scope` | `unobservable` for limited only |
| `take_probes` | the raw pre-edge take values actually read (taken/ack/id/entry PC/redirect) |
| `entry_pc`, `mret_pc`, `mret_rvfi_order`, `successor_rvfi_order` | recomputed retirement facts |
| `return_target` | successor PC |
| `return_target_source` | `first_subsequent_valid_retirement_pc` (limited) |
| `return_target_authority` | `inferred_architectural_successor_after_MRET` |

`pc_wdata` is never read and never recorded for limited authority. The limited
rebuild reads only these raw documents: the `cpu_external_irq_taken` event, the
`cpu_external_irq_sample` receipts, the PRE/POST `local_tick_sample` physical
observations, the `instr_response` rows, `cpu_native_exception_redirect` events
(refusal only), the `native_f6_isr_return.v1` saved detail (comparison only),
and the unchanged DMA/word/commit/memory rows. Physical field names come from
the provider (`input_port`, probes, notification widths); runtime `probe_*`
names are resolved through the bound CPU artifact when one is supplied.

## 3. Exact checks

Take (raw `cpu_external_irq_taken`, inside the fixed 16-tick delivery window,
plus the unchanged DMA-output/delivery/sample joins):

- take key `[cpu, epoch, sequence>0]`, receipt identity, `command_scope`,
  `observation_contract == provider`, `actual_pre_input == actual_post_input == 1`;
- `irq_taken_pre == 1`; `ack_probe == 1`; `id_probe == source_id` and within
  `id_width`; optional `accepted_source_id == source_id`;
- `entry_pc_probe` present, aligned, and `== program_contract.isr_address`
  (`limited take entry PC is not the declared ISR address`);
- every probe read from the take event and from the same parsed step's PRE
  sample must agree, otherwise `conflicting limited pre-edge probe observations`;
- `redirect_probes.taken == 0` at the take;
- for every later tick up to the successor, the PRE `irq_taken_pre` must be 0
  (`limited ISR intervening native take`).

Entry / fixed path:

- the first `rvfi_valid` retirement after the take whose `rvfi_pc_rdata` equals
  the probe entry PC must be unique; its `rvfi_insn` must equal the first word
  of the actual fixed ISR image (`fw.initial_images[isr_address][:4]`);
- the entry receipt/order/PC must equal the saved `handler_entry_*` fields;
- the archived valid retirements from the entry onward must match the compiled
  dispatch stage and DMA stage PC/word path
  (`validate_dma_dispatch_retirements`); if the saved `dispatcher_retirements`,
  `dispatcher_stage_sha256` or `dma_stage_address` are present they must equal
  the rebuilt values;
- valid retirements must have consecutive `rvfi_order` and consecutive parsed
  receipt sequences in the same execution, no intervening reset, and each must
  carry typed `rvfi_valid/order/insn/pc_rdata` (absent → `missing`).

MRET:

- exactly one retired `0x30200073`, at the declared success/error MRET site of
  the fixed ISR image, in the branch selected by the actual status word, after
  the entry, with the saved receipt/tick/order;
- `return_receipt_ticks` must match the raw MRET step receipt (when the saved
  detail is a production issuer summary);
- `pc_wdata` is not consulted; a saved `return_target_source` that mentions
  `pc_wdata` is refused.

Successor:

- exactly one `rvfi_valid` retirement after the MRET; it must be `order+1`, in
  the current dynamic slot window `[slot, slot+136)` from the saved slot map,
  with a later receipt sequence and later tick (`validate_return_successor`,
  authority `pc_insn_order_only`);
- its PC/instruction must equal the saved `successor_*` claims and the
  canonical prefix/preload bytes at that address;
- the actual `instr_response` row (transaction, address, `rdata == insn`,
  `error == 0`, acceptance/response tick, native handshake, producer
  consumption) and its receipt must join; the saved
  `successor_instruction_response` must equal the raw row exactly;
- the existing status/terminal/MRET chronology and readback/result joins
  (including the destination **source-byte version** join
  `ISR readback destination writer/version join`) are unchanged.

Diversion:

- any raw `cpu_native_exception_redirect` between the take and the successor
  refuses (`limited ISR intervening native exception redirect`);
- `retirement_diversion_scope='unobservable'` is recorded, and the projection
  never claims that per-retirement trap/debug/NMI/halt absence was inspected.

## 4. Refused fabrication shapes

Every refusal names the claiming document and field. The mode is `failed` for a
contradiction and `missing` for absent evidence.

| Archived shape | Refusal reason |
| --- | --- |
| `pc_wdata` / `intr` / `trap` / `mode` / `halt` / `mem_*` in a POST physical sample or CPU event | `claims unobservable retirement field <name> in archived CPU event <id> ...` |
| any other `rvfi_*` field (e.g. `rvfi_shadow_field`) | `claims undeclared RVFI retirement field ...` |
| `pc_wdata` or a serial observation in the saved ISR return detail | `claims unobservable retirement field pc_wdata in saved ISR return document` / `claims unobservable IRQ serial token ...` |
| `internal_version` other than `unknown` in a saved detail or anywhere in the archived attempt | `claims unobservable internal_version in ...` |
| a saved detail declaring a different authority/diversion scope/acceptance/unobserved set | `limited saved retirement authority mismatch`, `... diversion scope mismatch`, `... decision acceptance differs from the contract`, `... unobserved field declaration mismatch` |
| a mutated provider (e.g. source id 12) | `invalid evidence: unregistered-native-IRQ-receipt-contract` |
| missing take probes | `limited pre-edge probe unavailable: <name>` (`missing`) |
| entry PC ≠ declared ISR | `limited take entry PC is not the declared ISR address` |
| probe disagreement between event and PRE sample | `conflicting limited pre-edge probe observations: <name>` |
| wrong entry word | `limited ISR entry instruction differs from the declared handler word` |
| missing/wrong MRET | `limited duplicate/missing raw MRET`, `limited raw MRET site/branch/order mismatch` |
| successor order gap / outside window | `limited ISR retirement order discontinuity`, `limited first post-MRET successor is not the current dynamic return` |
| missing successor instruction response | `limited successor instruction response transaction unavailable` (`missing`) |
| altered saved successor response | `limited successor instruction response differs from raw Runner row` |
| altered saved entry/MRET/pre-edge restatement | `limited saved handler entry evidence differs from raw retirements`, `limited saved MRET evidence differs from raw retirements`, `limited saved take pre-edge observation differs from the raw take` |
| intervening raw exception redirect | `limited ISR intervening native exception redirect` |
| wrong source-byte version | `ISR readback destination writer/version join` (existing join) |

A full-RVFI archive is *not* scanned by these rules: the tests assert that an
Ibex archive still passes with `rvfi_intr`/`rvfi_pc_wdata` present and is
reported as `full_rvfi`.

## 5. Sibling archived projections

`project_saved_cpu_configuration`, `project_saved_word_transfer` and
`project_saved_cross_component_edges` do not read `mem_*`, `intr` or
`pc_wdata`: they use CPU data transactions, commits and declared edge hops. No
adaptation was needed; a test asserts exact parity on the same journal before
and after the authority rewrite (configuration outcome/issue list identical,
four-word transfer `passed` and equal). Cross-component edges still require the
bound CPU OBI artifact on both authorities, which is a native/artifact concern.

## 6. What remains unknown

- Per-retirement `trap`, `intr`, `mode`, `mem_*`, debug/NMI/halt are not driven:
  the projection cannot and does not claim their absence. Only an actual
  redirect event or redirect probe is diversion evidence.
- `pc_wdata` has no return-target authority; the target is inferred from the
  immediately following retirement.
- The CPU internal version is unknown (`internal_version` only allowed as
  `'unknown'`); no serial token or IRQ-source lineage exists for this adapter.
- The post-edge value of `irq_ack_o`/`irq_id_o` and the meaning of other
  `irq_i` bits are not asserted (the profile binds only `irq_i[11]`).
- Intervening retirements may be 2-byte aligned (RV32C in the profile's
  extension list); only the entry/MRET/successor sites are asserted 4-byte
  aligned, as the fixed firmware and slot map require.
- Whether a live campaign will produce this evidence at all is a native
  question; nothing here proves it.

## 7. Commands and results

All runs used `PYTHONPATH=src` (the package is not installed in this
environment, so the plain `python3 -m pytest` form cannot import `myfuzz`).

```sh
# Required archived saved-semantics set (slot map file added by this change)
PYTHONPATH=src python3 -m pytest \
  tests/integration/test_compiled_f6_saved_semantics.py \
  tests/integration/test_compiled_f6_saved_outputs.py \
  tests/integration/test_f6_saved_slot_mapping.py \
  tests/integration/test_compiled_f6_saved_outputs.py -q
# 423 passed

# Every other in-repo caller of project_saved_irq_isr / saved_slot_mapping
PYTHONPATH=src python3 -m pytest \
  tests/integration/test_verify_compiled_f6.py \
  tests/integration/test_compiled_f6_live_projection.py \
  tests/integration/test_f6_mixed_archived_indices.py \
  tests/integration/test_saved_irq_cpu_provider.py \
  tests/integration/test_f6_saved_limited_rvfi.py -q
# 158 passed  (106 + 3 + 49)

# One combined run covering both sets
PYTHONPATH=src python3 -m pytest \
  tests/integration/test_compiled_f6_saved_semantics.py \
  tests/integration/test_compiled_f6_saved_outputs.py \
  tests/integration/test_f6_saved_slot_mapping.py \
  tests/integration/test_verify_compiled_f6.py \
  tests/integration/test_compiled_f6_live_projection.py \
  tests/integration/test_f6_mixed_archived_indices.py \
  tests/integration/test_saved_irq_cpu_provider.py \
  tests/integration/test_f6_saved_limited_rvfi.py -q
# 581 passed
```

Per-file baselines before/after this change (same working tree, other agents'
changes included): `test_compiled_f6_saved_semantics.py` +
`test_compiled_f6_saved_outputs.py` = 419 passed; `test_verify_compiled_f6.py`
+ `test_compiled_f6_live_projection.py` + `test_f6_mixed_archived_indices.py` =
106 passed; `test_saved_irq_cpu_provider.py` = 3 passed (7 together with
`tests/local_harness/test_native_irq_profile_provider.py`). New:
`test_f6_saved_limited_rvfi.py` = 49 passed (positives, the
expected-ERR branch, the production-summary shape, the sibling-projection
parity, the full-RVFI non-routing proof and 37 refusal mutations);
`test_f6_saved_slot_mapping.py` = 4 passed.

## 8. What the lead must run natively

This change proves only the offline revalidation of an archive. To close a
native obligation the lead must, in the frozen window:

1. Run one real CV32E40P (`cv32e40p_rvfi_local`) local F6 campaign — original
   plus same-call fresh — that actually takes the external IRQ, enters the fixed
   ISR, returns by MRET and resumes in the current slot. Keep the archived
   `prefix` (attempts, `actual_events`, assertion material, `local_by_id`) from
   that run.
2. Re-run the archived projection on that prefix **with the actual CPU artifact
   bound** (the same way `scripts/verify_compiled_f6.py` passes
   `artifacts[cpu]`): only that path also checks the artifact's physical exports
   (`irq_i` input, the four RVFI outputs, the `irq_ack_o`/`irq_id_o`
   notifications and the seven probe outputs) and the OBI protocol traces.
3. Confirm the saved outcome equals the reprojected outcome for
   `dma.irq_isr_completion` (the script already refuses a mismatch), and that
   the rebuild reports `retirement_authority=pc_insn_order_only`,
   `retirement_diversion_scope=unobservable`, no `pc_wdata` and no serial token.

No native result is reported here; a successful native run must supply its own
raw archive and must be judged on that archive, not on this document.

Required changes outside this file's ownership (reporting only):

- `src/myfuzz/scenario/native_f6_isr_return.py` (already being extended in the
  same window) must keep the limited event shape this projection compares:
  `entry`/`mret`/`take_pre_edge_observation` restating only observable values,
  `retirement_authority`, `unobserved_fields`, `retirement_diversion_scope`,
  `successor_instruction_response` and its receipt, `handler_entry_*`,
  `return_receipt_ticks`, and no `pc_wdata` / `*_irq_serial_observation`.
  In the version reviewed here its limited arm accepts the entry/handler MRET
  through the pre-edge probes and `validate_return_successor(...,
  authority='pc_insn_order_only')`, and keeps `pc_wdata`/serial observations in
  the full-RVFI event only. If that regresses, the archived projection refuses
  the resulting archive instead of accepting it.
- The registered contract must keep the exact field/probe names used by
  `_saved_retirement_scope`; a rename is a loud refusal, not silent drift.
