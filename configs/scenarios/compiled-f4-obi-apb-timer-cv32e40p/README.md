# CV32E40P OBI / PULP Timer generic F2/F4 configuration

This configuration reuses the Timer compose, peripheral request, capability,
execution supplement and read records from `compiled-f4-obi-apb-timer` without
changing their bytes. The processor request is the existing CV32E40P request
from `compiled-f4-obi-apb-spi-cv32e40p`, with instance `processor` and reset
assert/release 8/8 ticks. No CPU/IP-specific Python executor is added.

The admitted APB storage word is TIMER0_CTRL at offset 4 (`0x40001004`);
`F2:04100040` reads it. F4 uses the same three full-word values as the source
configuration. The capability covers that control word, not an autonomous
counter or IRQ consumption.

On 2026-10-28 the actual generated preparation, component verification,
registered adapter selection and generic F2/F4 execution-plan compilation
passed. CPU binding is `cpu.obi/1/read-write-no-error-pins`; target binding is
`target.apb3/1/full-word`, `storage.rw.v1`. No DUT/native run was performed for
this configuration on the current source tree. Older Timer/CV32E40P results
are not acceptance evidence for this source tree; native original/fresh remains
pending.

The shared search entry is `configs/search/timer-cv32e40p.json`.
