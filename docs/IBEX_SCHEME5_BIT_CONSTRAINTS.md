# Ibex Scheme5 Bit-Only Constraints

This is the current Ibex scheme5 implementation aligned with the original RFuzz intent: keep the 395-bit `rfuzz_input_bits` interface unchanged and only project illegal or low-value input combinations into more useful legal combinations.

Implementation:

```text
configs/designs/ibex_scheme5_bit_constraints/config.json
configs/designs/ibex_scheme5_bit_constraints/harness/ibex_core_scheme5_bit_constraints_harness.sv
scripts/runs/run_ibex_baseline_vs_scheme5_bit_constraints_1000s.py
```

It intentionally does not include instruction templates, scenario selection, protocol state machines, memory models, RF models, or DUT-output feedback.

## Constraints

| Constraint | Original illegal/unhelpful combinations | Transformation | Why randomness is preserved | Controlling input bits |
|---|---|---|---|---|
| Boot mtvec-style alignment | `boot_addr_i[7:0] != 0` gives reset/trap vectors with noisy low-byte offsets. | `boot_addr_i = {raw_boot_addr_i[31:8], 8'h00}` | Upper 24 address bits remain fully fuzz-controlled. | `rfuzz_input_bits[222:199]` |
| 32-bit instruction encoding bias | Completely random `instr_rdata_i[1:0]` often selects compressed/illegal encodings, which can stall normal decode/execute exploration. | `instr_rdata_i[1:0] = (&raw_instr_rdata_i[5:2]) ? raw_instr_rdata_i[1:0] : 2'b11` | The upper 30 instruction bits stay raw; low bits are still allowed to be raw when bits `[5:2]` are all one. This is not an instruction template. | `rfuzz_input_bits[126:95]` |
| Fetch enable projection | Half of raw samples have `fetch_enable_i[0] == 0`, so the core may not fetch. | `fetch_enable_i = {raw_fetch_enable_i[3:1], \|raw_fetch_enable_i}` | All 4 raw bits still control the result; only all-zero disables fetch. | `rfuzz_input_bits[15:12]` |
| Instruction valid requires grant, progress-biased | `instr_rvalid_i=1` while `instr_gnt_i=0` is inconsistent; suppressing valid with grant makes response probability too low. | `instr_rvalid_i = raw_instr_rvalid_i`; `instr_gnt_i = raw_instr_gnt_i \| instr_rvalid_i` | `raw_instr_rvalid_i` keeps direct 1/2 control over response valid; `raw_instr_gnt_i` still controls extra grant-only cycles. | `rfuzz_input_bits[5]`, `rfuzz_input_bits[4]` |
| Data valid requires grant, progress-biased | `data_rvalid_i=1` while `data_gnt_i=0` is inconsistent; suppressing valid with grant makes LSU response probability too low. | `data_rvalid_i = raw_data_rvalid_i`; `data_gnt_i = raw_data_gnt_i \| data_rvalid_i` | `raw_data_rvalid_i` keeps direct 1/2 control over response valid; `raw_data_gnt_i` still controls extra grant-only cycles. | `rfuzz_input_bits[10]`, `rfuzz_input_bits[9]` |
| Instruction error only on valid response, low-frequency | `instr_err_i=1` without a valid response is invalid; frequent errors over-focus trap paths. | `instr_err_i = instr_rvalid_i & raw_instr_err_i & (&raw_rf_rdata_a_ecc_i[3:0])` | Error remains fuzz-controlled, but only fires when five independent raw bits select it during a valid response. | `rfuzz_input_bits[6]`, `[5]`, `[4]`, `[94:91]` |
| Data error only on valid response, low-frequency | `data_err_i=1` without a valid response is invalid; frequent errors over-focus trap paths. | `data_err_i = data_rvalid_i & raw_data_err_i & (&raw_rf_rdata_b_ecc_i[3:0])` | Error remains fuzz-controlled, but only fires when five independent raw bits select it during a valid response. | `rfuzz_input_bits[11]`, `[10]`, `[9]`, `[62:59]` |
| NMI low-frequency and priority over regular IRQ | High-rate NMI and regular IRQs together can dominate execution with asynchronous trap entries. | `irq_nm_i = raw_irq_nm_i & (&raw_instr_rdata_i[13:10])`; regular IRQs are gated by `irq_gate` and cleared when NMI is active. | NMI and regular IRQs are still raw-bit controlled; extra raw bits only lower event frequency. | `rfuzz_input_bits[2]`, `[126:113]`, `[3]`, `[1]`, `[0]`, `[30:16]` |
| Regular IRQ low-frequency | Level-sensitive IRQs asserted too often keep interrupt paths hot and reduce normal instruction progress. | `irq_* = raw_irq_* & (&raw_instr_rdata_i[9:6]) & ~irq_nm_i` for software/timer/external IRQs. | Each interrupt source keeps its own raw bit; the shared gate comes from independent instruction bits. | `rfuzz_input_bits[3]`, `[1]`, `[0]`, `[120:117]`, `[2]` |
| Fast IRQ onehot projection | Dense `irq_fast_i` values assert many fast interrupts together; Ibex prioritizes them, so most asserted bits are redundant noise. | `irq_fast_i` keeps only the lowest-numbered asserted raw fast IRQ, then applies the same low-frequency IRQ gate and NMI exclusion. | The selected fast IRQ is still determined by raw `irq_fast_i`; the projection removes redundant simultaneous fast IRQs. | `rfuzz_input_bits[30:16]`, `[120:117]`, `[2]` |
| Debug low-frequency and excluded during NMI | Frequent `debug_req_i` can dominate normal execution; simultaneous debug and NMI mixes two asynchronous entry classes. | `debug_req_i = raw_debug_req_i & (&raw_data_rdata_i[3:0]) & ~irq_nm_i` | Debug remains fuzz-controlled, but only fires when five independent raw bits select it and NMI is absent. | `rfuzz_input_bits[8]`, `[190:187]`, `[2]`, `[126:113]` |

## Deliberate Non-Constraints

`grant requires request` is not enforced in scheme5 because `instr_req_o` and `data_req_o` are DUT outputs in Ibex. Gating grant with those outputs would create a DUT-output-driven environment model, which this implementation explicitly avoids.

RF read-data is also left as raw fuzz input. Enforcing x0 reads as zero would require inspecting `dut.rf_raddr_a_o`/`dut.rf_raddr_b_o`, which is also DUT-output feedback.
