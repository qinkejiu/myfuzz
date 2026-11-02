# pulp_timer_30mhz

Declared composition variant of `configs/peripherals/pulp_timer_irq` at
30 MHz: a rate with **no whole half-period divider** against the 50 MHz
reference CPU (50/30 = 5/3).

* Before the P2 exact rational grid this profile existed only as the phase
  planner's named-refusal fixture; the recorded refusal is historical
  (`runs/p1-timing/refusals/nondivisor-ratio.log`).
* Since P2 the planner places the pair on the exact common grid of
  150 MHz: the reference CPU's half period is 3 grid steps and this model's
  is 5, one host tick advances 6 grid steps, and a session with it really
  runs (`runs/p2-timing-20261103`, scenario
  `configs/scenarios/inprocess-obi-apb-rational-rate-timers-f1f4.json`).
* The RTL, source revision, reset and APB3 pin contract are the pinned
  upstream ones; only the declared `clocks[0].frequency_hz` differs, and the
  pinned profile is not edited.
