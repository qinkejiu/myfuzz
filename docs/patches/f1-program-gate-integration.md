# F1 program-space gate integration

Date: 2026-11-02. Status: **patch plan, not applied**. This document is the
integration contract for `src/myfuzz/fuzz/f1_program_gate.py`. It edits no
entry, C++ host, existing test or scenario config, and it reports no RTL run.

## 1. What the isolated module provides

`src/myfuzz/fuzz/f1_program_gate.py` is the future single Python gate and the
Python authority for the host's per-case F1 criteria.

| API | Contract |
|---|---|
| `F1GateFlags` | Immutable scenario flags: `program_words`, `subword`, `allow_branches`, `allow_address_forms`, `allow_compressed`; rejects impossible combinations. |
| `f1_gate_flags_from_scenario(config)` | Maps `f1_program_words`, `f1_subword`, `f1_allow_branches`, `f1_allow_address_forms`, `f1_allow_compressed`; missing keys keep the historical defaults. |
| `normalize_f1_gate_flags(flags)` | Accepts `F1GateFlags`, a scenario/field mapping, or `None`. |
| `validate_f1_program_record(record, *, isa, window_bytes, flags)` | Dispatches to the one validator below and returns `None`. |
| `f1_reference_expectation(record, *, isa, window_bytes, flags, ...)` | Calls `reference_run`/`reference_run_compressed`; returns retired count, PC order, trace, final state and `trace_hash`. |
| `trace_hash(trace)` / `canonical_trace(trace)` | FNV-1a 32 over `(pc, insn_word, rd, wdata)` per retirement. |
| `host_mirror_spec()` | JSON-ready table of the C++ changes in §4. |

Dispatch by flag mode (all opt-ins require `f1_program_words > 1`):

| `mode` | Selected validator |
|---|---|
| `single` | fixed one-word gate (`f1_program_words == 1`): the f1f4 `validate_instruction_bytes` subset, ALU opcodes only, mailbox x8 untouched |
| `legacy` | `rv32_program.validate_program_words` |
| `address` | same, `allow_address_forms=True` |
| `branch` | same, `allow_branches=True` |
| `extended` | same, both flags |
| `subword` | `rv32_subword.validate_subword_program` |
| `compressed` | `rv32_compressed.validate_compressed_program` (plus branches when declared) |

The `legacy` adapter preserves the historical `_validate_f1_program` ordering
and text (`F1 program memory word <i> is not LW or SW`, `... must use x18 as
its base`, `... leaves the declared data window (offset <n>)`, the three
reserved-write messages, and the control-flow sentence). The opt-in modes
prefix the shared validator's message with `F1 program` and otherwise leave it
intact.

## 2. Entry changes (`scripts/run_inprocess_f1f6.py`)

Anchors are current-tree line ranges; match the quoted snippet, not only the
number.

1. **Read flags once (≈3054-3069).** After the existing `f1_words`/
   `f1_subword` reads, add:

   ```python
   from myfuzz.fuzz.f1_program_gate import f1_gate_flags_from_scenario
   f1_flags = f1_gate_flags_from_scenario(config)
   ```

   `f1_gate_flags_from_scenario` now owns the type and combination checks
   (program length 1..16, boolean flags, opt-ins need program mode,
   compressed+address and subword+shape are refused). Keep the existing
   `f1_words` local for arity/firmware generation.

2. **`validate_record` (≈950-973).** Replace the `f1_subword`/else branch and
   the private `_validate_f1_program` call with one gate:

   ```python
   if len(record['fields']) == 1 and f1_words == 1:
       return validate_f1(record, isa=isa, windows=windows)
   validate_f1_program_record(
       record, isa=isa, window_bytes=PROGRAM_DATA_WORDS * 4, flags=f1_flags)
   return record
   ```

   The `len == 1 and f1_words == 1` branch must stay first: that is the fixed
   single-word contract, not the program-space gate. Pass `f1_flags` into
   `validate_record` (add the keyword) from every call site: the fuzz gate at
   ≈2828, seed records at ≈2841, and any replay/candidate path that calls it.

3. **Delete `_validate_f1_program` (≈976-1038).** No other code may call it
   after change 2; keeping it would create a second authority. The new module
   reproduces its refusal text, including the AUIPC admission.

4. **Header (≈1758-1761).** Next to `F1_ALLOW_SUBWORD`, emit the three new
   compile-time facts:

   ```python
   f'#define F1_ALLOW_BRANCHES {int(config.get("f1_allow_branches", False))}',
   f'#define F1_ALLOW_ADDRESS_FORMS {int(config.get("f1_allow_address_forms", False))}',
   f'#define F1_ALLOW_COMPRESSED {int(config.get("f1_allow_compressed", False))}',
   ```

5. **Fuzz strategy (≈2824-2854, `src/myfuzz/fuzz/strategy.py:49-52`).** The
   strategy currently takes only `f1_subword`. Add the four flags (or pass
   `f1_flags`) and select the matching generator call:
   `generate_program(..., style="address"/"branch"/"extended",
   allow_address_forms=..., allow_branches=...)` and
   `generate_compressed_program(...)`; also pass the flags to
   `mutate_program`. No new rule belongs in the strategy.

6. **Case correspondence (≈2401-2425).** `prog_retires == words`,
   `prog_pc_ordered` and `prog_insns_match` describe a straight-line
   32-bit image. For `branch`, `extended` and `compressed` modes, compare the
   case line with `f1_reference_expectation` instead: `prog_retires ==
   retired_count`, `prog_pc_order == pc_order`, and `prog_trace_hash ==
   trace_hash`. Keep the legacy checks for `legacy`/`address` (address forms
   are still straight-line). `successor_pc` stays
   `slot + 4 * len(record['fields'])` in every mode, including compressed.

7. **Expectation state.** Call `f1_reference_expectation` with the host's
   absolute state: `data_base=layout['slot']`, `registers={18:
   layout['data_base']}` plus any declared initial registers, and
   `memory={layout['data_base']: value, ...}`. This makes the trace PCs and
   `memory_changes` directly comparable with the host case line.

8. **Observation keys (`case_observation_keys`, ≈304).** Add
   `prog_trace_hash`, `prog_trace_count`, `prog_pc_order` to the F1 tuple, and
   extend the case parser/report accordingly.

## 3. Trace hash (the comparison value)

Python:

```text
for each retirement, in order:
    for value in (pc, insn_word, rd, wdata):
        for byte in value as little-endian uint32:
            digest ^= byte
            digest = (digest * 16777619) & 0xffffffff
initial digest = 2166136261
result = "fnv1a32:" + hex(digest)
```

`insn_word` is the 32-bit installed word, or the 16-bit parcel for a
compressed instruction. The mnemonic is not hashed, because the host has the
encoded word, not the Python name. This is the same FNV-1a pair the host
already uses in `window_hash` (`scripts/inprocess_obi_apb_f1f4_spike.cpp:737-750`).

## 4. C++ host changes (`scripts/inprocess_obi_apb_f1f4_spike.cpp`)

`host_mirror_spec()` returns this same table as JSON. The host file must not be
edited by the isolated-module patch; these are the required follow-up changes.

| ID | Anchor | Required change |
|---|---|---|
| `record_flags` | `275-288` macros | Add `F1_ALLOW_BRANCHES`, `F1_ALLOW_ADDRESS_FORMS`, `F1_ALLOW_COMPRESSED`, default `0`. `F1_MAX_WORDS` stays the record-word count; a compressed record word holds two parcels. |
| `branch_targets` | `755-831` `make_record` kF1 | With branches enabled, admit opcode `0x63` for funct3 `{0,1,4,5,6,7}`; decode the B-type displacement; require 4-byte alignment, strictly positive offset, and target index `<= count` (the record's actual word count; the appended return jump sits at index `count`). Refuse JAL/JALR/CSR and every backward/zero target. Do not use a `+4` PC-order test. |
| `address_provenance` | `791-824` memory branch | With address forms enabled, a memory word whose `rs1 != 18` must carry immediate `0` and a base statically proven `data_base + d`. Mirror the forward may-dataflow in `rv32_program._provenance_states`: `x18` = `window[0,0]`; `LUI`/`ADDI`/`ADD` propagate constants and window ranges; `ANDI` folds only constants; other writes are unknown; a merge unions two window ranges; proven `[low, high]` plus the word's immediate must be 4-byte aligned and inside `[0, PROGRAM_DATA_WORDS*4-4]`. Keep the existing `x18` fast path. |
| `compressed_fetch` | `768-831`, slot install `1252-1265` | With compression enabled, a record word with `bits[1:0] != 3` is two 16-bit parcels: low at `pc`, high at `pc+2`. A 32-bit word still occupies a whole record word and may not straddle one. Decode both halves with the admitted ALU subset (destination `x12..x15`, nonzero imm/shamt, no control/memory parcels). Install the same 4-byte record words; `program_end` remains `kSlot + 4*record.words`. Expected retirement count is the image instruction count (2 per packed record), not `record.words`; `prog_insns_match` must compare the parcel (16-bit) or full word (32-bit) per PC. |
| `pc_step` | `1780-1792`, pass `2461-2482` | Never derive the next PC as `last + 4`. A compressed parcel steps 2, a 32-bit word steps 4, and a taken branch jumps forward. Compare the observed retirement PC sequence with `pc_order` (or its hash) instead of `prog_pc_ordered`. |
| `trace_hash` | RVFI block `1774-1845`, case line `2679-2700` | For every RVFI-valid retirement with `kSlot <= pc < program_end`, feed `(pc, insn, rd_addr, rd_wdata)` as four little-endian uint32 values to the FNV loop in §3. Emit `prog_trace_hash` and `prog_trace_count`; compare them with `f1_reference_expectation` in Python correspondence. Do not re-simulate in the host to guess a branch trace. |

The host cannot know a branch program's taken path before it runs. Choose one:

- **(recommended) Python correspondence:** the host emits the trace hash and
  PC order, and the entry compares them with the expectation after the case.
  This needs no protocol extension.
- **in-host pass/fail:** extend the `NEED_RECORD` reply with one
  `EXPECT_F1 <retired_count> <trace_hash> <pc_csv>` line, store it per case,
  and compare at case end. The Python expectation remains the authority.

## 5. Test evidence

```text
PYTHONPATH=src:. python3 -m pytest \
  tests/fuzz/test_f1_program_gate.py \
  tests/fuzz/test_rv32_program.py \
  tests/fuzz/test_rv32_program_branches.py \
  tests/fuzz/test_rv32_compressed.py -q
219 passed in 0.50s
```

70 of those are new gate tests; the 149 existing program/branch/compressed
tests are unchanged. A separate check of the untouched entry suites
(`test_entry_f1_program.py`, `test_entry_f1_subword.py`) is 84 passed. No
Verilator/RTL run was performed, so none of these numbers are hardware
evidence.

Differential checks against the untouched entry gates (not part of pytest):

- single-word mode vs `scripts.run_inprocess_f1f4.validate_record`: 0
  acceptance differences and 0 message differences over 6,000 generated ALU,
  memory, control and random words;
- legacy program mode vs `scripts.run_inprocess_f1f6._validate_f1_program`:
  0 acceptance differences over 7,000 generated and random words, with the
  small decoder-wording caveat in §6.

## 6. Non-goals / caveats

- No existing file, config or C++ host is modified by this patch.
- `f1_reference_expectation` raises by name for `f1_subword` records:
  `rv32_subword.reference_run_subword` has final state but no retirement trace,
  and the gate does not invent one. Subword validation is still dispatched.
- The single-word mode is byte-for-byte compatible with the fixed f1f4 gate
  (including the AUIPC refusal and the raw `validate_instruction_bytes` text).
  The program-mode legacy adapter matches the entry's *acceptance* exactly.
  For a malformed encoding that passes the opcode/reserved prechecks, the inner
  decoder wording is the shared validator's (`OP funct7 ... is not emittable`)
  instead of the old `validate_instruction_bytes` wording; the entry-facing
  `F1 instruction <i> is not legal for this profile:` prefix is identical.
- Branch/address/compressed generation and mutation in `FuzzStrategy` are
  follow-up entry work (§2.5), not part of this isolated patch.
