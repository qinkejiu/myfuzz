# CV32E40P partial RVFI / I2C MMIO

Configuration-only CPU substitution using `cv32e40p_rvfi_local`; the I2C request, capability, supplement and acceptance records remain shared with the original generic MMIO scenario. The public executor remains `compiled_mmio_obi_apb` (the existing compatibility alias).

Observed retirement fields are only valid/order/insn/pc_rdata. No intr/pc_wdata values or IRQ/F5/F6 authority are supplied. Use the original I2C `acceptance_sequence.json` with `run_generic_scenario.py`, then independently audit original/fresh using `verify_cpu_retirement.py --cpu processor` and the existing MMIO audit. Native acceptance is separate from preparation.
