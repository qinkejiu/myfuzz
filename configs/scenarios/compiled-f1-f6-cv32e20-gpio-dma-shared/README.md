# CV32E20 shared six-flow configuration

Uses the main CV32E20 RV32I (32 GPR) profile and source-backed first fetch `0x10000`. DMA/GPIO requests, capabilities, flow records and all other reserved addresses match the existing Ibex shared scenario. The supplement format has no include/override, so its only semantic difference is `program.boot_address`; no new executor is introduced.

Preparation is separate from native acceptance: F5/F6 require the source-verified CPU evidence provider and actual original/fresh proofs.
