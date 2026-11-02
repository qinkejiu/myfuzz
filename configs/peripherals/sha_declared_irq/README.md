# Caliptra SHA256 declared IRQ transport smoke

Uses the existing `caliptra_sha256` profile and AHB `full-word-single` target request. No upstream RTL or IP-specific source contract is added.

CPU full-word writes at byte offsets `0x800=1` (global error enable), `0x804=1` (error0 enable), `0x81c=1` (software error0 trigger) select the scalar `error_intr` observed output. Decode offsets are in `sha256_reg.sv:118-125`; bit0 enables at 744-801, sticky software error status at 928-946, enabled aggregation at 1032-1036 and 904-905; `sha256.sv:440` exports the resulting global error IRQ. The software-trigger bit self-clears (1065-1085), but its error status/output remains sticky. The smoke explicitly maps the first observed rise to a bounded CPU pulse; it does not claim the source is a native one-cycle pulse.

This is software-triggered IRQ output transport, not SHA digest execution or an AHB error. `sha256_ctrl.sv:110-111` ties target hold/error low. Internal version/cause authority, ISR MMIO, F5/F6 and rewards stay unknown/disabled. Both reset_n and cptra_pwrgood remain controlled by the existing reset schedule.
