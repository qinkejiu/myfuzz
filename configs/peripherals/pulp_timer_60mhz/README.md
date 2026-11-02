# pulp_timer_60mhz

Declared composition variant of `configs/peripherals/pulp_timer_irq` at
60 MHz: **faster than the 50 MHz reference CPU** (half period 5/6 of the
CPU's).

* Before the P2 sub-stepped exact grid the phase planner refused this rate by
  name; the recorded refusal is historical
  (`runs/p1-timing/refusals/faster-than-reference-cpu.log`).
* Since P2 the exact common grid is 300 MHz: the reference CPU's half period
  is 6 grid steps and this model's is 5, so one host tick advances 12 grid
  steps and the model takes five of its own rising edges inside a tick - the
  sub-stepping.  The measured per-case rising-edge count is the evidence
  (`runs/p2-timing-20261103`, scenario
  `configs/scenarios/inprocess-obi-apb-rational-rate-timers-f1f4.json`).
* **Bus traffic to this model is refused by name**: this host reads a model's
  protocol outputs once per host tick, and this model's whole APB access window
  - `PSEL`/`PENABLE` for two of its own cycles, plus a `PREADY` response the
  bridge clears on its next edge - is 10 grid steps of the 12-step tick, so it
  can fall between two samples.  A record routed here fails with
  `unsupported-target-traffic:timer60:faster-than-reference-cpu:...`
  (`runs/p2-timing-20261103/refusals/faster-target-traffic.log`); the clock is
  still sub-stepped and measured.
* The RTL, source revision, reset and APB3 pin contract are the pinned
  upstream ones; only the declared `clocks[0].frequency_hz` differs, and the
  pinned profile is not edited.
