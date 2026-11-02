# pulp_timer_10mhz_timed

Declared composition variant of `configs/peripherals/pulp_timer_irq`
(the pinned PULP apb_timer plus its declared `irq_o[0]` pulse endpoint).

* RTL, source revision, file list, reset and APB3 pin contract are the
  pinned upstream ones (`third_party/soc-pulp-apb-timer` revision
  `git:03eba2e6965f5363df12621882bc70498c551a73`); only the declared
  composition rate and the Verilator timing mode differs.
* This is a harness **composition declaration**, not an upstream
  synthesis configuration: the pinned profile keeps its own 50 MHz rate
  and is not edited.
* `capabilities.verilator_timing_mode` is `timing` so the model is
  built with `--timing`; the pinned RTL schedules no delayed events,
  so this variant proves the timed build/link and phase path, not an
  event ordering.
