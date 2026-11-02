# Declared-IRQ F5 consumption on a pc/insn/order-only CPU — 2026-10-30

Scope: make the config-driven declared-output IRQ **F5 consumption** chain work
for `cv32e40p_rvfi_local`, whose registered retirement authority is
`pc_insn_order_only`. The CPU panel really drives only `rvfi_valid`,
`rvfi_order`, `rvfi_insn` and `rvfi_pc_rdata`: there is no serial token and no
`intr`/`pc_wdata`/`trap`/`mode`/`mem_*` field. The limited chain therefore joins
the *documented* handler path by order and keeps every undriven field absent
instead of zero-filled.

**This report contains no native result for the two new configurations.** No
native RTL was executed for this work (no `--native`, no Verilator build, no DUT
simulation); only pure Python/pytest was run. The native evidence that the
reused limited path works on this CPU is the earlier
`research/input-strategy-audit-20261027/runs/cv32e40p-irq-20261030/shared-six-v6`
campaign (audit `status=verified`, both F5 certificates
`authority=pc_insn_order_only`), which is the *shared GPIO* chain, not these
declared-output targets. `reward_eligible`/`grants_F5`/`grants_F6`/
`grants_prerequisites` stay `false` everywhere in the produced documents.

## 1. What the CPU contract really declares

`configs/cpus/cv32e40p_rvfi_local/component_profile.json` +
`cv32e40p_irq_receipt_contract()`:

| Fact | Value |
|---|---|
| retirement authority | `retirement_authority='pc_insn_order_only'` |
| observed retirement fields | `['valid', 'order', 'insn', 'pc_rdata']` |
| unobserved retirement fields | `['intr', 'pc_wdata', 'trap', 'halt', 'mode', 'mem_addr', 'mem_rdata', 'mem_wdata', 'mem_rmask', 'mem_wmask']` |
| serial observation | none (`serial_observation` absent) |
| real pre-edge acceptance | `irq_ack_pre`, `irq_id_pre` (5 bit), `irq_entry_pc` (32 bit), `source_id=11` |
| real redirect probes | `irq_redirect_pre`, `irq_redirect_cause` |
| IRQ input | `irq_i[11]`, machine external (`SOURCE_ID=11`) |

So a limited join may use: the actual parsed input pre/post, the native take and
its real ack/id/entry-PC acceptance, the exact `(pc, insn, order)` retirement
stream, the target's native pre/post samples, the CPU-side OBI beats, the ISR's
actual MMIO delivery and RAM write values, and the real successor
`(pc, insn, order, receipt_id, local_tick)`. It may **not** use any serial,
`intr`, `pc_wdata`, `trap`, `halt`, `mode` or `mem_*` value.

## 2. Implementation

### 2.1 `retirement_only_provider()` resolves the real limited path

The previous probe looked for three functions that do not exist
(`shared_irq_retirement.validate_pc_insn_order_retirements`,
`shared_irq_dispatcher.validate_pc_insn_order_retirements`,
`shared_irq_firmware.observe_pc_insn_order_retirement_path`), so it always
returned `None`. It now probes the entry points `shared_irq_firmware` really
defines (all required to be callable; otherwise `None`, never a partial claim):

| Role | Real module attribute |
|---|---|
| dispatcher | `observe_irq_isr` |
| limited branch | `_observe_limited_irq_isr` |
| take scope | `_limited_take_scope` |
| retirement window | `_limited_retirement_window` |
| ordered data join | `_join_limited_memory_operations` |
| fixed ISR path | `fixed_isr_path` |
| redirect rows | `_redirect_rows` |
| unobserved fields | `_unobserved_fields` |
| reject fabricated fields | `_reject_unobserved_fields` |
| successor | `myfuzz.scenario.irq_return_successor.validate_return_successor` |

The provider document names the module, each entry point, the successor entry
point, `retirement_authority='pc_insn_order_only'` and the real join scope
`ordered_retirement_to_actual_data_transaction`. The declared-F5 observation
imports the helpers it needs (`_limited_retirement_window`, `fixed_isr_path`,
`_redirect_rows`, `_unobserved_fields`, `_reject_unobserved_fields`) plus the
shared successor functions. Two probed entry points are deliberately not called:
`_limited_take_scope` requires the graph's IRQ acceptance *certificate*, which is
not part of this journal contract (the equivalent real evidence here is the
take's own ack/id/entry-PC acceptance), and
`_join_limited_memory_operations` would re-derive the same ordered data
transactions that `_verify_consumption` already joins more strictly (it adds the
target's native pre/post samples). They stay in the probe because they are part
of the path the probe certifies as importable.

Nothing in `shared_irq_firmware.py`, `local_harness/*`,
`irq_return_successor.py` or `native_f6_isr_return.py` was modified; everything
is consumed by import.

### 2.2 Admission for `pc_insn_order_only`

`admit_declared_irq_consumption(...)` now returns `status='admitted'` for
CV32E40P, with:

* `cpu.retirement_authority='pc_insn_order_only'`;
* `cpu.observation_contract` = the registered contract (it *is* declared, so it
  is no longer blanked to `None`);
* `cpu.retirement_joins='by_documented_order'` and
  `consumption.retirement_joins='by_documented_order'`;
* `cpu.unobserved_retirement_fields` = the ten contract-declared fields;
* `consumption.value_joins='delivery_read_value==OBI_rdata==RAM_write_value'`
  (no `retirement_mem_value`, which this CPU cannot observe);
* `cpu.retirement_only_provider` = the resolved provider document;
* `layers.consumption='order_only'`.

Admission additionally validates the limited contract (`_admit_limited_cpu`):
the declared authority, that the four observed fields are declared, that no
declared-unobserved name is also declared observed, that
`unobserved_retirement_fields` is a non-empty string list, and that the real
pre-edge entry-PC acceptance probe exists. A malformed limited contract raises
`ValueError` instead of being silently admitted.

An optional `cpu_contract=` argument binds the **realized** artifact contract to
the admission: it must be a registered contract and digest-equal to the one
resolved from the profile (`declared-F5-admission-CPU-contract-mismatch`
otherwise). This is what the native script uses before it takes a step.

If a real helper disappears, `retirement_only_provider()` returns `None` and
admission falls back to `status='unsupported'` with
`reason='declared-F5-pc-insn-order-only-retirement-work-unavailable'` (tested by
deleting `_limited_retirement_window` at runtime).

### 2.3 Observation limited branch

`observe_declared_irq_consumption(...)` derives the authority from the passed
CPU contract with `irq_return_successor.retirement_authority(...)`. For
`pc_insn_order_only`:

1. **No serial anywhere.** A take whose serial observation *claims* an observed
   decision token is refused (`…-limited-CPU-fabricated-decision-serial`), as is
   one that claims an observed retirement token
   (`…-limited-CPU-fabricated-retirement-serial`). `transport.decision_serial`
   stays `None`, `decision_serial_status='unavailable'`, and
   `transport.native_take` carries **no** `irq_serial_observation` key.
2. **Real acceptance.** `transport.native_take` records the contract's real
   `irq_ack_pre==1`, `irq_id_pre==source_id` and the 4-byte-aligned
   `irq_entry_pc`; a take that fails them is refused
   (`…-limited-CPU-native-acceptance`).
3. **Documented entry.** The entry PC comes from that real pre-edge probe, never
   from a scenario constant. `_limited_entry_path` composes the documented path
   from the fixed images: the handler path itself when the entry is the handler,
   or the real trampoline word (`vector` / `vector_external`) followed by the
   handler path. An entry outside the fixed vector is refused.
4. **Window by the shared helper.** `_limited_retirement_window` (imported from
   `shared_irq_firmware`, given a thin `SimpleNamespace(cpu_id=…, events=…)`
   facade) validates the exact `(pc, insn)` sequence from that entry to exactly
   one MRET, requires `valid==1`, `schema_version='cpu_retire.v2'` and the
   contract identity on every row, requires contiguous `order`, rejects every
   fabricated unobserved field (including a zero `intr`/`trap`/`halt`/`mode`/
   `pc_wdata`/`mem_*`), and reports retirements between the take and the entry
   as `pre_entry_retirements` instead of guessing them away.
5. **No trap/halt authority.** `trap`/`halt` are unobservable here, so a real
   `cpu_native_exception_redirect` between the take and the MRET (or between the
   take and the successor) is refused via `_redirect_rows`.
6. **Labels.** `transport.first_handler_retirement.scope` is
   `first_retirement_after_native_take` and additionally carries
   `retirement_joins='by_documented_order'`; `consumption` records
   `retirement_authority`, `unobserved_retirement_fields`,
   `per_retirement_join='unobservable'`, `join_scope` and
   `pre_entry_retirements`.
7. **Value joins keep their teeth.** `_verify_consumption` still requires, per
   declared status read: the actual MMIO delivery with the real read value, the
   target's own native pre/post/data samples with the same value, the CPU-side
   OBI data beat (acceptance < delivery < response < retirement), and the
   dependent RAM `SW` with the same value plus its OBI beat; the clear/ack
   writes keep their joins too. Only the per-retirement `mem_*` equalities are
   dropped (`full_fields=False`).
8. **Successor by the shared authority.**
   `validate_return_successor(mret, successor, start, end,
   authority='pc_insn_order_only')` requires order+1, a same-execution strictly
   later receipt sequence, a strictly later tick, an aligned in-range PC, **no**
   `intr` field and no observed serial. The successor is additionally rejected
   if it carries a fabricated unobserved field or a non-`cpu_retire.v2` scope.
   Its evidence omits `raw_mret_pc_wdata` and instead records
   `return_target_source='first_subsequent_valid_retirement_pc'`,
   `retirement_authority` and the unobserved field list.
9. **No fabricated MRET data.** For a limited CPU `consumption.mret` has no
   `raw_pc_wdata` key and `consumption.successor` has no `raw_mret_pc_wdata`
   key; neither is required anywhere.

### 2.4 Full-RVFI CPUs stay byte-identical

For Ibex and CV32E20 nothing changed: the authority resolves to `full_rvfi`
(the `validate_return_successor` default), the serial/`intr`/`mem_*` joins and
every emitted key stay exactly as before. The new limited-only keys are never
added on the full path. A regression test pins the canonical SHA-256 of the four
pre-change observation documents (see §4).

### 2.5 Script support

`scripts/run_declared_irq_f5.py`:

* `cpu_authority(contract)` and `check_cpu_authority(admission, contract)` bind
  the realized CPU authority to the admitted join rules (limited ⇒ admitted with
  a real provider and `by_documented_order`; full ⇒ `exact_fields`) and refuse a
  cross-authority pairing;
* after the CPU artifact is realized, `main` calls
  `admit_declared_irq_consumption(config, base_dir=…, cpu_contract=cpu_contract)`
  and requires its digest to equal the pre-artifact admission, so the native run
  can only proceed on the contract it admitted;
* the same contract object is passed into
  `observe_declared_irq_consumption(..., cpu_contract=cpu_contract)`;
* `prefix.json` and `summary.json` record `retirement_authority`;
* the exit-code rule is unchanged: the run still fails unless the summary is
  `status='verified'` **and** `irq_consumption='verified'`;
* nothing in the script reads or requires `raw_pc_wdata` (or any other field the
  limited CPU cannot drive).

### 2.6 New configurations

| Config | Target / protocol | Status register | Trigger writes | CPU |
|---|---|---|---|---|
| `configs/scenarios/declared-irq-f5-wb-timer-cv32e40p/config.json` | `zipcpu_timer`, wishbone | `COUNT` @ 0 | `(0, 8)` | `cv32e40p_rvfi_local` |
| `configs/scenarios/declared-irq-f5-apb-spi-cv32e40p/config.json` | `pulp_spi`, apb3 | `INTSTA` @ 40 | `(36, 0x80000000)` | `cv32e40p_rvfi_local` |

Identical targets/triggers/status offsets/ranges to the working Ibex configs
(`target_window`, `image_start=0x10000`, `image_end=0x30000`,
`result_address=0x10c40`); only `cpu_profile` (and the documentation strings)
differ. Pure-Python admission of both returns `admitted`.

## 3. Tests and exact results

Command (exactly the prescribed one, with the new test file appended):

```
PYTHONPATH=src:. python3 -m pytest \
  tests/integration/test_declared_irq_f5_firmware.py \
  tests/integration/test_declared_irq_f5_consumption.py \
  tests/integration/test_declared_irq_f5_script.py \
  tests/integration/test_declared_irq_f5_limited_cpu.py -q
```

Result: **106 passed** (`0 failed`, 0 skipped), 0.59 s. Per file:

| File | Tests | Result |
|---|---|---|
| `tests/integration/test_declared_irq_f5_firmware.py` | 33 | passed |
| `tests/integration/test_declared_irq_f5_consumption.py` | 30 | passed |
| `tests/integration/test_declared_irq_f5_script.py` | 18 | passed |
| `tests/integration/test_declared_irq_f5_limited_cpu.py` (new) | 25 | passed |

Before this change the first three files held 66 tests, all green.

Additional regression runs (unchanged code, proving no collateral damage):

```
PYTHONPATH=src:. python3 -m pytest tests/test_doc_link_check.py \
  tests/test_repository_audit.py tests/test_capabilities.py -q
# 85 passed, 17 subtests passed

PYTHONPATH=src:. python3 -m pytest \
  tests/local_harness/test_cpu_native_irq_receipt.py \
  tests/local_harness/test_cv32e40p_irq_contract.py \
  tests/local_harness/test_cv32e20_irq_contract.py \
  tests/integration/test_saved_irq_cpu_provider.py \
  tests/integration/test_cv32e20_shared_config.py -q
# 46 passed, 15 subtests passed
```

### 3.1 What the new tests cover (`test_declared_irq_f5_limited_cpu.py`)

* **Positive chain** over a realistic synthetic `cv32e40p_rvfi_local` journal
  (no serial, no `intr`/`mem_*`, contiguous documented path, MRET, real
  successor), parametrised over the two target protocols/offsets
  (`apb3`/40, `wishbone`/0) and over the three documented entries
  (`vector`, `vector_external`, `handler`): 6 cases. Asserts the real value
  joins, the entry/handler/MRET path, the join labels, the absence of
  `raw_pc_wdata`/`raw_mret_pc_wdata` and of every unobserved field in the
  retirement records, and false grants.
* A retirement between the take and the entry is reported as
  `pre_entry_retirements` and still verifies.
* Refusals: fabricated zero `intr` on a handler retirement; fabricated
  `pc_wdata` on the MRET; fabricated `mem_addr` on the load retirement;
  fabricated `pc_wdata` on the successor; observed decision serial on the take;
  observed retirement serial on the take; observed serial on a handler
  retirement; non-contiguous retirement order; successor order skip;
  fabricated `intr` on the successor; missing MRET; entry PC outside the fixed
  vector; missing retirement observation contract; unverified take acceptance;
  real exception redirect before the MRET; and the observation refusing when
  the real shared helper is absent.
* An explicitly *unobservable* serial document is not a claim and still
  verifies.

### 3.2 Full-RVFI byte-identical regression

Captured from the pre-change implementation and asserted as canonical
`sha256(json.dumps(document, sort_keys=True, separators=(',', ':')))`:

| Journal | Digest |
|---|---|
| Ibex default | `cef98817e3b8718a67e03ddbc80c1e48ac4aa86bc312b073374e991c08048578` |
| Ibex with contract | `950946ff92283d3eb0c321679cc6a4a8e4382664950b342fb6fdf8c0c5cfe01b` |
| CV32E20 with contract | `950946ff92283d3eb0c321679cc6a4a8e4382664950b342fb6fdf8c0c5cfe01b` |
| Field-light retirements, full authority | `51f18ad44415ff113a6121166664ccfea39ed2e745e4bcfc303ef1fc0d5ea107` |

The same test also asserts the full path still has `retirement_joins='exact_fields'`
(except the deliberately field-light case), `raw_pc_wdata` in `mret`,
`raw_mret_pc_wdata` in `successor`, and none of the limited-only keys.

### 3.3 Admission tests

* E40 admission is `admitted` with the real provider, `by_documented_order`,
  the four observed fields, the ten unobserved fields and
  `layers.consumption='order_only'`.
* With `_limited_retirement_window` removed the probe returns `None` and
  admission falls back to `unsupported` with the documented reason.
* A mismatched/unregistered `cpu_contract` binding raises.
* Full-RVFI admission keeps `exact_fields` and an empty unobserved list.
* Both new configs are admitted and pass the script's case-image/firmware
  checks (added to the script test's config matrix).

## 4. Evidence scope (honest limits)

The verified observation document for a limited CPU claims exactly:

* one actual target output sample (real wire + bit) and one OR frame with unique
  attribution;
* the actual parsed CPU input pre/post, the actual native take, and the real
  pre-edge ack/id/entry-PC acceptance;
* one actual ISR read of every declared status register, joined to the target's
  own native samples and the CPU-side OBI beat, with the real read value;
* the dependent RAM write(s) carrying that value, with their OBI beat;
* the documented `(pc, insn)` handler path **by order** from the real entry PC
  to exactly one MRET, with contiguous `order` and no fabricated field, plus
  the real successor retirement/response/source-byte version;
* no serial lineage, no `intr`, no `pc_wdata`, no `trap`/`halt`/`mode`, no
  per-retirement `mem_*` value, no trap-cause attribution.

It claims nothing about: internal IP cause/version, case origin, cross-case
writer attribution, live authority, strategy superiority, or any F5/F6 grant.
`cause_source` can only become `read_status_bit` when the configuration's
declared cause bit is actually set in the real read value — the new E40 configs
declare no cause bits (`status_cause_bits: null`).

## 5. Exact native commands for the lead (frozen window)

Nothing below was executed here. Each config is run twice, as two separate
invocations of the same configuration. `--output` must not exist. Use a cache
the lead already owns (the E40 artifact must be elaborated/compiled once); the
example uses the same warm cache as the working F5 runs — a cache miss simply
rebuilds the artifact. Run from the repository root.

```
PYTHONPATH=src:. python3 scripts/run_declared_irq_f5.py --native \
  --config configs/scenarios/declared-irq-f5-wb-timer-cv32e40p/config.json \
  --output runs/declared-irq-f5-cv32e40p-20261030/wb-timer/original --mode original \
  --cache runs/config-driven-20261028/cache

PYTHONPATH=src:. python3 scripts/run_declared_irq_f5.py --native \
  --config configs/scenarios/declared-irq-f5-wb-timer-cv32e40p/config.json \
  --output runs/declared-irq-f5-cv32e40p-20261030/wb-timer/fresh --mode fresh \
  --cache runs/config-driven-20261028/cache \
  --original runs/declared-irq-f5-cv32e40p-20261030/wb-timer/original

PYTHONPATH=src:. python3 scripts/run_declared_irq_f5.py --native \
  --config configs/scenarios/declared-irq-f5-apb-spi-cv32e40p/config.json \
  --output runs/declared-irq-f5-cv32e40p-20261030/apb-spi/original --mode original \
  --cache runs/config-driven-20261028/cache

PYTHONPATH=src:. python3 scripts/run_declared_irq_f5.py --native \
  --config configs/scenarios/declared-irq-f5-apb-spi-cv32e40p/config.json \
  --output runs/declared-irq-f5-cv32e40p-20261030/apb-spi/fresh --mode fresh \
  --cache runs/config-driven-20261028/cache \
  --original runs/declared-irq-f5-cv32e40p-20261030/apb-spi/original
```

`--original` on the fresh invocation is optional and only compares the original
summary digest after the fresh evidence has been written; the canonical
cross-invocation comparison is `summary.json.semantic_sha256` of the two runs.

Expected shape of a successful observation (from the pure-Python chain, to be
confirmed or refused by the real journal):

* `admission.json`: `status='admitted'`, `cpu.retirement_authority='pc_insn_order_only'`,
  `cpu.retirement_joins='by_documented_order'`,
  `cpu.retirement_only_provider.module='myfuzz.integration.shared_irq_firmware'`,
  `layers.consumption='order_only'`;
* `first_fetch = 0x10000` (E40 `PC_BOOT = {boot_addr_i[31:2], 2'b0}`);
* `mtvec = 0x10201` (vectored), so the external cause-11 entry is
  `vector_external = 0x1022c`; the handler is at `0x10400` and the MRET at
  `0x10440` (17 handler words);
* `observation.json`: `status='verified'`, `irq_consumption='verified'`,
  `transport.decision_serial=null`,
  `transport.native_take.irq_entry_pc=0x1022c`,
  `transport.first_handler_retirement.pc=0x1022c` (the JAL trampoline word
  `0x1d40006f`), `consumption.mret.pc=0x10440` and `insn=0x30200073`,
  `consumption.return_target=PARK` (`0x11040`),
  `consumption.pre_entry_retirements=[]` (a non-empty list is allowed and
  reported, not a failure).

A refusal is a result too: `summary.status` stays `refused`/`ambiguous`, the
script exits non-zero, and `observation.refusals` names the exact missing or
contradictory join.

## 6. What remains

1. **Native original/fresh runs** for the two new configs (the commands in §5).
   No native RTL was run for this work; the E40 declared-output chain is proven
   only at the pure-Python level and by reuse of the previously verified shared
   limited path.
2. **Real E40 journal assumptions to watch.** The chain assumes the first
   retired instruction after the take is at the vector/trampoline (or reports
   earlier ones as `pre_entry_retirements`), that the handler retires strictly
   in program order, that no `cpu_native_exception_redirect` appears between the
   take and the successor, and — as on the full-RVFI path — that the case
   journal holds exactly one native take (`one-actual-native-CPU-take-required`
   otherwise; the 16-tick pulse and the ISR length are unchanged from the
   working Ibex configs). Each condition is checked, not assumed silently; a
   mismatch refuses with the exact reason.
3. **CV32E20 declared-target coverage.** The AHB Caliptra SHA and the existing
   Ibex configs remain full-RVFI and unchanged; no limited variant of them was
   added (E40 is the only registered `pc_insn_order_only` CPU).
4. **Per-retirement `mem_*` and interrupt-cause attribution** stay unobservable
   for E40 by contract. They are not worked around, zero-filled or inferred.
5. **No grants.** `reward_eligible`, `grants_F5`, `grants_F6` and
   `grants_prerequisites` are `false` in every admission/observation/summary
   document produced here.

## 7. Files changed

| File | Change |
|---|---|
| `src/myfuzz/integration/declared_irq_consumption.py` | real limited-path provider probe; limited admission (`_admit_limited_cpu`, contract binding); limited observation branch (`_limited_entry_path`, `_limited_helpers`, authority-aware transport/successor, fabricated-field/serial/redirect refusals, documented-order labels); full-RVFI path untouched |
| `scripts/run_declared_irq_f5.py` | `cpu_authority`/`check_cpu_authority`; artifact contract bound into admission and passed into observation; `retirement_authority` recorded; exit rule unchanged |
| `configs/scenarios/declared-irq-f5-wb-timer-cv32e40p/config.json` | new Wishbone ZipTimer variant on `cv32e40p_rvfi_local` |
| `configs/scenarios/declared-irq-f5-apb-spi-cv32e40p/config.json` | new APB PULP SPI variant on `cv32e40p_rvfi_local` |
| `tests/integration/test_declared_irq_f5_limited_cpu.py` | new: 25 limited-chain positive/refusal tests |
| `tests/integration/test_declared_irq_f5_consumption.py` | extended: full-RVFI byte-identical digest regression (+4) |
| `tests/integration/test_declared_irq_f5_firmware.py` | extended: E40 admitted/failed-probe/contract-binding/full-RVFI admission tests (+3) |
| `tests/integration/test_declared_irq_f5_script.py` | extended: new configs in the case matrix, authority-binding tests (+8) |
| `docs/reports/declared-irq-f5-limited-cpu-20261030.md` | this report |

`shared_irq_firmware.py`, `local_harness/*`, `irq_return_successor.py` and
`native_f6_isr_return.py` were not modified; they are imported and reused.
