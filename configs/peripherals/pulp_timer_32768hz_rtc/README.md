# pulp_timer_32768hz_rtc

Declared composition variant of `configs/peripherals/pulp_timer_irq` at
**32.768 kHz** - the rate of an independent RTC crystal, i.e. a second clock
domain rather than a divided reference.

* The exact common grid with the 50 MHz reference CPU is 12.8 GHz, so this
  model's half period is 390 625 grid steps and the CPU's is 256.  The model
  side is far above the planner's 1024-step phase-grid bound, which is what
  "no usable common phase grid" means numerically: there is no rounding of a
  declared rate, only a named refusal.
* Used by
  `configs/scenarios/inprocess-obi-apb-timer-async-grid-refusal.json` to
  record that refusal.  It is **never** a runnable session: the entry refuses
  before any host tick, and `runs/p2-timing-20261103/refusals/` keeps the
  exact stderr.
* The RTL, source revision, reset and APB3 pin contract are the pinned
  upstream ones; only the declared `clocks[0].frequency_hz` differs, and the
  pinned profile is not edited.
