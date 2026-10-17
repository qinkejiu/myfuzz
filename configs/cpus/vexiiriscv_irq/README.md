# Derived VexiiRiscv profile with a real external IRQ entry

`component_profile.json` is the authenticated baseline
`configs/cpus/vexiiriscv/component_profile.json` plus exactly one declared
delta; it selects the *same* generated RTL bytes
(`configs/cpus/vexiiriscv/generated/VexiiRiscv.v`) and the same reduced
single-beat AXI4 contract.

The delta:

* removes the baseline `constant 0` port action for the core's real
  `PrivilegedPlugin_logic_harts_0_int_m_external` input;
* declares that physical input as the `processor.interrupts` /
  `machine_external` (`active_high`) interrupt entry of this CPU;
* records the unchanged `rdtime`, machine-timer and machine-software inputs,
  which stay `constant 0` exactly as the baseline declares them.

`vexii_irq_contract.py` re-authenticates the baseline closure (including the
generated-RTL revision and lint/generation evidence) and then refuses anything
except this exact document, byte-for-byte. There is no second source selector:
the derived profile cannot outlive or diverge from its baseline pin.

The runtime kind is `reduced_dual_axi_irq_cpu`: the generated driver's step
operation is `STEP_REDUCED_AXI_IRQ`, whose first field is the real interrupt pin
and whose remaining 17 fields are the identical reduced AXI response inputs. The
session drives the caller's level and records its transitions; it does not
decide that an interrupt is pending and does not claim one was taken. Trap
entry, vector fetch, ISR execution, `mret` return and IRQ deassertion are
measured by the fixed-instance scenario, not by this declaration.

The baseline profile and its historical CPU/RAM and CPU→GPIO evidence keep
their original identity; this derived profile adds no claim about them.

See:

* `src/myfuzz/scenario/vexii_pulp_gpio_fixed.py` — fixed instance and row;
* `docs/reports/vexiiriscv-cpu-ip-irq-20261018.md` — measured acceptance and
  boundaries;
* `docs/reports/evidence/vexi-irq-fixed-20261018/` — two fresh runs.
