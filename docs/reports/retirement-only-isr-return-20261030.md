# Retirement-only ISR chain and F6 ISR return (CV32E40P)

Date: 2026-10-30
Scope: F5 shared ISR chain and F6 ISR-return chain for a CPU whose retirement
stream is `valid/order/insn/pc_rdata` only. No native RTL was run for this
report; every claim below is a code/evidence-schema claim or a pure/synthetic
test result.

## 1. Retirement authority split

The authority is read from the registered native-IRQ receipt contract of the
CPU artifact (`native_irq_receipt_contract(artifact)`), through the new pure
rule `src/myfuzz/scenario/irq_return_successor.py::retirement_authority`:

| `retirement_authority` | CPUs | Meaning |
|---|---|---|
| absent / `full_rvfi` | `ibex_rvfi_local`, `cv32e20` | Full RVFI retirement; `rvfi_intr`/`rvfi_trap`/`rvfi_mode`/`rvfi_pc_wdata`/`mem_*`/`halt` and the exact serial token exist. Today's behaviour is byte-identical. |
| `pc_insn_order_only` | `cv32e40p_rvfi_local` | Only `rvfi_valid/rvfi_order/rvfi_insn/rvfi_pc_rdata` are driven. IRQ acceptance is the real pre-edge `irq_ack_o`/`irq_id_o` decision and the real `if_stage_i.exc_pc`; there is no serial token and no per-retirement memory/trap/privilege observation. |

A missing `retirement_authority` key keeps the legacy full-RVFI rule. An
unknown authority string refuses.

## 2. Exact checks

### 2.1 Pure successor rule (`irq_return_successor.py`)

`validate_return_successor(mret, successor, *, start, end, authority='full_rvfi')`

Common to both authorities (unchanged):

* `successor.order == mret.order + 1` (no skipped first successor),
* aligned `pc_rdata` inside `[start, end)`,
* `successor.receipt_id.sequence > mret.receipt_id.sequence`, same non-empty
  `execution`,
* `successor.local_tick > mret.local_tick`.

Full-RVFI only (unchanged): `successor.intr == 0` and an observed, observed-zero
`irq_serial_observation.retirement`.

Limited only (added):

* `intr` must be **absent** from the successor; a zero is refused as fabricated,
* any `irq_serial_observation` must be absent or explicitly
  `{'status': 'unobservable', 'value': None}`; an observed token (including
  zero) is refused,
* trap/intr/retirement-serial are recorded as unobservable, never asserted 0.

### 2.2 F6 issuer (`native_f6_isr_return.py`)

Install (limited):

* the contract binds the exact registered provider (`native_irq_provider`,
  `native_take_provider`) and the execution binding as before,
* `decision_acceptance` must be typed (`ack_probe`, `id_probe`, `source_id`,
  `entry_pc_probe`, optional `id_width`),
* `retirement_fields` normalized to `rvfi_*` must contain
  `rvfi_valid/rvfi_order/rvfi_insn/rvfi_pc_rdata` and must be a subset of the
  artifact's actually declared RVFI observation fields,
* `unobserved_retirement_fields` must be non-empty and disjoint from the
  declared fields,
* `retirement_diversion_fields == []` and
  `retirement_diversion_scope == 'unobservable'`,
* the ack/id/entry-PC probe names must exist as real one-bit/vector physical
  output exports,
* the `irq_decision_serial`/`irq_retirement_serial` export requirement is
  skipped (no such token exists).

Take (limited): still the current native take key, from the original
`_step_local`/`_retire` frames, with a real `producer_event_id`; requires the
real pre-edge `irq_ack_pre == 1`, `irq_id_pre == decision_acceptance.source_id`
inside `id_width`, `irq_taken_pre == 1`, real aligned `irq_entry_pc` equal to
the program's declared ISR address, and refuses any
`cpu_native_exception_redirect` at/after the take.

Handler entry (limited): the first `rvfi_valid` retirement whose
`pc_rdata == irq_entry_pc` (retirements before it are recorded as
`pre_entry_retirements`, orders must stay consecutive); its `insn` must equal
the first fixed ISR word; no `rvfi_intr`/`rvfi_mode` is read.

Diversion (limited): per-retirement trap/debug/NMI absence is not claimed
(`retirement_diversion_scope='unobservable'`). The only diversion observation
is the absence of a `cpu_native_exception_redirect` event between the take and
the MRET, and between the take and the MRET successor; such an event refuses.

MRET (limited): the actual retired word `0x30200073` at a declared handler
`mret_addresses` site, strictly increasing order, an earlier source-joined
entry, and no redirect since the take. `pc_wdata` is not used.

Successor (limited): the extended validator plus the existing actual consumed
instruction response (`rdata`, `error == 0`, response tick, full transaction
key, pinned-response/original handshake checks).

### 2.3 F5 ISR observer (`observe_irq_isr`)

Full-RVFI path: unchanged (serial-certificate anchor, fixed handler path, the
four selected memory operations with `mem_*` retirement joins, OBI/source
version joins, successor proof). The existing observable difference for all
CPUs is the new top-level `retirement_authority` key on the result wrapper.

Limited path (`_observe_limited_irq_isr`):

1. Anchor: a provider certificate with `proof_scope == 'irq_acceptance'` whose
   `native_take_event_id` is in the current receipt. The F5 source-admission
   conditions are identical to the full path (admission role/case/path/
   component, `trigger.origin_status == 'known'`, certificate
   `source_origin_status`, exactly one `pin_causes` entry whose
   `current_sample.origin_refs == [admission.document()]` and
   `value == source_case.source.value`).
2. Take: real `cpu_external_irq_taken` event, matching `take_key`, real
   `producer_event_id` that is the actual CPU step event (component + local
   tick), real `receipt_id`, `irq_ack_pre == 1`, `irq_id_pre == source_id`
   within `id_width`, `irq_taken_pre == 1`, `irq_redirect_pre` absent/0 and a
   real aligned `irq_entry_pc`.
3. Entry: first `cpu_retire` at the real `irq_entry_pc`; retirements before it
   are recorded. The entry is the fixed ISR entry declared by the firmware
   document (`retirement_path[0]` for the shared GPIO view, otherwise the
   vector/vector+44 trampoline word whose JAL target must be the handler, or
   the handler itself).
4. Path: the actual `(pc_rdata, insn)` sequence from the entry to the MRET must
   equal the declared fixed path exactly (same mechanism as the full
   `retirement_path` branch); retire scope (`cpu_retire.v2`, observation
   contract, `valid == 1`) and consecutive orders are required; exactly one
   MRET, at the last fixed address.
5. Fabricated-field refusal: any non-`None` `intr`, `trap`, `halt`, `mode`,
   `pc_wdata`, `mem_addr`, `mem_rdata`, `mem_wdata`, `mem_rmask`, `mem_wmask`
   on a retirement (or on the MRET/successor) refuses; a zero is not accepted.
6. Ordered data join (replaces the unobservable per-retirement join): the
   expected data operations are derived from the admitted fixed instruction
   words plus the firmware document seeds (`scratch` mscratch value,
   `gpio.base`, `result`). A declared `memory_operations` list is honoured when
   a document provides one. The actual ordered `memory_read`/`memory_write`/
   `mmio_delivery` events of the CPU data channel inside
   `[entry retirement, MRET]` must equal them: same count, same
   execution/testcase/component/epoch/channel scope, strictly increasing
   `source_sequence`, same address, read/write kind, derived value (read
   values feed the result stores; `result+8` is `old+1`; saved/restored
   registers are value-unknown but address/order exact), and a native OBI beat
   with `write`, `address`, `value`/`rdata`, `byte_enable == 15` and
   `acceptance_event < event_id < response_event`. MMIO reads additionally join
   the real `mmio_acceptance` row; RAM events must be the beat's own producer.
   `register_reads` are the MMIO deliveries (with their declared offsets),
   `result_RAM` the ordered writes inside the declared result span.
7. Successor: `verify_irq_successor` in limited scope (see 2.4), then the
   absence of a `cpu_native_exception_redirect` between take and successor.
8. Any missing link returns `status='unknown'` with a precise `reason`;
   `reward_eligible`/`grants_prerequisites` stay `False`.

### 2.4 `verify_irq_successor`

Both authorities keep the full native source-byte/version/OBI response checks
unchanged. Limited additionally requires the successor's `trap`, `halt` and
`intr` fields to be **absent** (not zero; `None` is tolerated only for
`trap`/`halt`) and the retirement serial to be unobservable, refuses any
`mem_*`/`pc_wdata` claim on the MRET or successor, returns
`raw_mret_pc_wdata=None`, `return_target_source='first_subsequent_valid_retirement_pc'`,
`retirement_authority` and `unobserved_fields`.

### 2.5 Port-local host IRQ coordinates

`prepare_shared_f5` now derives the host-facing CPU IRQ bit from the artifact's
unique one-bit input export (`host_offset = node.bit_offset - export.bit_lo`;
CV32E40P 11 -> 0, Ibex/CV32E20 0 -> 0), uses it for the ownership check and the
`Binding` target offset, and rewrites the owner with
`shared_f5_ownership_document`. `compiled_f5_crosswalk._validate_f5_topology`
uses the same helper for the binding and compiled-ownership comparisons while
keeping the `_physical` DUT-bit check unchanged.

## 3. Emitted evidence schema (limited authority)

### F5 `irq_isr` certificate (each `certificates` entry)

```
status='verified', case_id,
retirement_authority='pc_insn_order_only',
unobserved_fields=[contract.unobserved_retirement_fields],
native_take_event_id, native_IRQ (the irq_acceptance certificate),
source_admission,
entry_retirement={event_id, pc, insn, order, local_tick},
pre_entry_retirements=[{event_id, pc, insn, order}],
handler_retire_events=[event_id...],
register_reads=[{offset, value, delivery_event, transaction, native_OBI}],
result_RAM=[{event_id, address, value, native_OBI, transaction}],
mret_event,
raw_mret_pc_wdata=None,
return_PC, return_proof,
per_retirement_join='unobservable',
join_scope='ordered_retirement_to_actual_data_transaction',
retirement_diversion_scope='unobservable',
ordered_data_transactions=[{kind, address, value, event_id, event_kind,
    transaction, native_OBI}]
```

`return_proof` keeps today's keys (successor event/order, response event,
backend/physical response steps, memory read, versions, native OBI,
`source_action_id`) plus `return_target_source`,
`retirement_authority`, `unobserved_fields`; its `raw_mret_pc_wdata` is `None`.
Full-RVFI certificates keep exactly today's key set.

### F6 issuer event (`native_f6_isr_return.v1`)

Unchanged keys (component/execution/epoch/case/slot, take key and receipt,
handler-entry receipt/order/PC, return receipt/ticks, local tick, phase,
`rvfi_order`, `instruction`, `pc_rdata`, `isr_sha256`, dispatcher fields,
`execution_binding_sha256`) plus, for limited only:

```
retirement_authority, unobserved_fields,
retirement_diversion_scope='unobservable',
entry={event_id: None, pc, insn, order, local_tick, receipt_id},
mret_pc, mret={event_id: None, pc, insn, order, local_tick, receipt_id},
take_pre_edge_observation={irq_ack_pre, irq_id_pre, irq_entry_pc,
    accepted_source_id[, irq_taken_pre]},
pre_entry_retirements,
successor_receipt_id, successor_rvfi_order, successor_local_tick,
successor_pc_rdata, successor_instruction,
successor_instruction_response, successor_instruction_response_receipt_id,
return_target, return_target_source='first_subsequent_valid_retirement_pc',
return_target_authority='inferred_architectural_successor_after_MRET'
```

`entry.event_id`/`mret.event_id` are `None` because the issuer runs inside the
original retirement callback, before the Runner journals that event; the
receipt id plus local tick locate it. The issuer document
(`native_f6_isr_return_issuer.v1`) gains `retirement_authority`,
`unobserved_fields`, `retirement_diversion_scope` and `decision_acceptance` for
limited, and does not gain `pc_wdata`/`intr`/`mem_*`.

## 4. Files changed

* `src/myfuzz/scenario/irq_return_successor.py` — authority-aware successor rule
  and `retirement_authority` reader.
* `src/myfuzz/scenario/native_f6_isr_return.py` — limited install, take
  acceptance, entry-by-real-PC, redirect window, MRET, successor and evidence.
* `src/myfuzz/integration/shared_irq_firmware.py` — authority dispatch, ordered
  data-operation derivation/join, fabricated-field refusal, limited
  `verify_irq_successor`, limited certificates.
* `src/myfuzz/integration/shared_gpio_irq_isr.py` — shared firmware view now
  carries the declared `scratch` seed (for the ordered join).
* `src/myfuzz/integration/shared_f5_runtime.py` — port-local host IRQ offset and
  ownership rewrite for `prepare_shared_f5`.
* `src/myfuzz/integration/compiled_f5_crosswalk.py` — port-local binding and
  ownership comparison in `_validate_f5_topology` (granted by the lead for
  exactly this alignment).
* `tests/integration/test_retirement_only_isr.py` — new 44-test suite.
* `docs/reports/retirement-only-isr-return-20261030.md` — this report.

Not touched: `src/myfuzz/local_harness/*`,
`shared_slot_consumers.py`, `shared_f5_slots.py`, `shared_f6_slots.py`,
`compiled_f6.py`, `gpio_irq_dependency_evidence.py`, `shared_f6_assembly.py`,
`research/`, `runs/`.

## 5. Tests actually run (commands and counts)

All with `PYTHONPATH=src:.`.

1. `python3 -m pytest tests/integration/test_cv32e20_f6_isr_return.py tests/integration/test_compiled_f6_isr_return.py tests/integration/test_f6_gpio_companion.py tests/integration/test_shared_irq_firmware.py tests/integration/test_shared_gpio_irq_isr.py tests/scenario/test_irq_return_successor.py tests/integration/test_retirement_only_isr.py tests/local_harness/test_cv32e40p_irq_contract.py -q`
   -> **230 passed** (358 s). Full-RVFI Ibex/E20 and the new limited suite all pass.
2. `python3 -m pytest tests/integration/test_retirement_only_isr.py -q`
   -> **44 passed** (90 s).
3. `python3 -m pytest tests/integration/test_shared_f5_runtime.py -q`
   -> **12 passed** (46 s).
4. `python3 -m pytest tests/integration/test_live_f5_crosswalk.py tests/integration/test_compiled_f5_crosswalk.py tests/integration/test_shared_f5_replay.py tests/integration/test_shared_f5_support_binding.py -q`
   -> **28 passed, 4 failed** (311 s). The four failures are
   `test_shared_f5_support_binding.py` `LocalHarnessBuildError:
   build-admission-failed:runtime-physical-facts-mismatch` raised by
   `local_harness/build.py` against the concurrently changed
   `configs/peripherals/pulp_gpio_causal_local/component_profile.json`; none of
   them reaches the limited-authority code.
5. `python3 -m pytest tests/integration/test_shared_f6_slots.py tests/integration/test_shared_f6_memory_slots.py tests/integration/test_shared_f6_storage_script.py tests/integration/test_compiled_f6_contract.py -q`
   -> **81 passed** (258 s).
6. A combined run that included `tests/integration/test_compiled_f6_consumer.py`
   exceeded the 10-minute tool cap and was killed; no result is claimed for it.

### What the new suite proves

* the limited authority is accepted for a correct ordered
  retirement+data+OBI join, with the real take probes and firmware-derived
  operations;
* it refuses: entry-PC mismatch, wrong entry instruction, missing MRET,
  successor outside the slot, successor order gap, an intervening
  `cpu_native_exception_redirect`, a missing/extra/out-of-order data
  transaction, a wrong derived store value, a fabricated `mem_*` or `intr`
  value, a take without ack/id, and a limited contract without
  `unobserved_retirement_fields`;
* the emitted limited documents claim no `intr`/`pc_wdata`/`trap`/`halt`/
  `mem_*` key anywhere (recursive assertion) and list them as unobserved;
* the full-RVFI observer certificate keeps exactly today's key set;
* the real CV32E40P artifact/contract drive the F6 issuer through take ->
  entry (real `irq_entry_pc`) -> MRET -> successor and emit the limited
  evidence above, and refuse mismatched entry PC/instruction, missing take,
  missing MRET, out-of-range/gapped successor and an intervening redirect;
* the port-local host IRQ coordinate maps the real E40 DUT bit 11 to host bit
  0, maps the real Ibex `irq_external_i` bit 0 to 0, and refuses ambiguous
  exports and mismatched ownership offsets.

## 6. What stays unknown (never zero-filled)

* `rvfi_intr`, `rvfi_pc_wdata`, `rvfi_trap`, `rvfi_mode`, `halt` — not driven;
  `unobserved_fields` lists `intr, pc_wdata, trap, halt, mode`.
* `mem_addr`, `mem_rdata`, `mem_wdata`, `mem_rmask`, `mem_wmask` — not driven;
  association is ordered-window only
  (`per_retirement_join='unobservable'`,
  `join_scope='ordered_retirement_to_actual_data_transaction'`).
* retirement serial lineage (`irq_decision_serial`/`irq_retirement_serial`) —
  no exact token exists; absent rather than 0.
* debug/NMI/halt diversion after the take — the only real observation is the
  absence of `cpu_native_exception_redirect`
  (`retirement_diversion_scope='unobservable'`).
* F6 `entry`/`mret` journal event ids — not assigned at issuance time
  (`None`; located by receipt id + local tick).
* `memory_operations` was not added to `build_irq_firmware`: its document digest
  is pinned by `tests/integration/test_shared_irq_firmware.py`
  (`370d158d...`) and `compiled_f4` re-derives the document byte-for-byte, so
  adding a key would change the Ibex firmware identity. The ordered operations
  are derived from the admitted instruction words plus `scratch`/`gpio.base`/
  `result` instead, and a declared `memory_operations` list is honoured when a
  document provides one.
* The saved-evidence projection `compiled_f6_saved_semantics.py`
  (`retirement_chain`) still requires raw `rvfi_pc_wdata`, `rvfi_intr`,
  `rvfi_trap`, `rvfi_mode` and `irq_retirement_serial`, and
  `compiled_f6_consumer.py` reviews the live event; both need the limited
  branch (they were outside this file ownership). They are the consumers that
  would otherwise need `pc_wdata`; the limited issuer keeps the field absent
  and emits `return_target_source` instead.

## 7. Remaining native acceptance work (lead runs in the frozen window)

1. CV32E40P standalone F5: real `cpu_external_irq_taken` with ack/id/entry-PC,
   real ordered data transactions and OBI beats inside the ISR window; confirm
   the derived fixed operations match the real sequence and that
   `status='verified'` is granted only with the full join.
2. CV32E40P shared F1-F6: the shared GPIO dispatcher view (`retirement_path`,
   scratch seed) against the real take/entry/MRET.
3. Declared-IRQ F5: `declared_irq_consumption.py` intentionally keeps its
   `unsupported`/refusal for CV32E40P (no
   `observe_pc_insn_order_retirement_path` /
   `validate_pc_insn_order_retirements` name is exposed by this work).
4. F6 return: confirm the real `irq_entry_pc` equals the declared ISR address,
   no `cpu_native_exception_redirect` occurs in the return window, the MRET
   word `0x30200073` retires at a declared site, and the actual successor
   retirement order/PC/receipt satisfy the extended rule.
5. Port-local IRQ: confirm the runner drives `irq_i` bit 0 on the host side
   while the DUT artifact bit is 11.
6. Re-run the saved-evidence projection after its limited branch is added.

No native pass is claimed by this report.
