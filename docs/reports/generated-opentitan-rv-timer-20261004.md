# Generated OpenTitan RV Timer local RTL acceptance

The pinned `opentitan_rv_timer` source at `fca045df919a26c47e71616b9dac917b1ea4fd07` now has a generated independent local TL-UL harness. The local scalar boundary retains all 25 physical ports: 20 TL-UL signals, clock/reset, one native timer interrupt, and alert/RACL diagnostic outputs. Its alert receiver and RACL policy inputs use package defaults; RACL is disabled in the pinned local wrapper. The original `rv_timer` RTL and register block execute in one persistent Verilator process per testcase.

The source gate checks the original lock record and exact closure, plus the local profile, scalar wrapper, and union of all pinned source and include bytes. The generated runtime uses `beat_to_tlul` with integrity generation, a 4096-byte target window, and a bounded local request/response handshake. `GeneratedOpentitanRvTimerSession` exposes only real register responses and the observed RTL IRQ. It does not synthesize a successful compare or interrupt.

Acceptance run, 2026-10-04:

- `MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src python3 -m unittest tests.integration.test_local_opentitan_rv_timer_generated_real -v`: 2/2 passed. A register test saw the actual counter increase, actual compare IRQ become high, and the native sticky interrupt clear after stopping the counter and writing INTR_STATE0. A second test saved formal scenario evidence and matched a fresh process replay.
- `MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src python3 -m unittest tests.integration.test_scenario_cve2_opentitan_rv_timer_generated_real -v`: 1/1 passed. A CV32E20 program produced four actual TL-UL writes, then read the real timer interrupt state and counter through the router, stored both values in persistent RAM, and matched a fresh replay.
- `PYTHONPATH=src python3 -m unittest tests.local_harness.test_runtime_renderer tests.local_harness.test_generation_cli -q`: 12/12 passed.
- Final source gate and generator check: full 25-port selection, `tlul_timer` artifact, `source_verified`.

The CPU chain checks interrupt state through a real MMIO read. Its CPU external IRQ input is fixed to zero; it does not claim CPU trap entry. The timer-only scenario has no independent fuzzable pin, so cross-component mutation in this example comes from the CPU program and the timer's real register state. This is an independent harness pair with transaction routing, not a reconstructed SoC bus topology.
