# Ibex and OpenTitan pattgen real dataflow integration

### Task 1: Ibex and OpenTitan pattgen real dataflow integration

**Files:**
- Create: `tests/integration/test_scenario_ibex_opentitan_pattgen_generated_real.py`
- Create: `docs/reports/generated-ibex-opentitan-pattgen-chain-20261005.md`

**Verification:**
- Real two-variant CPU-to-pattgen-to-CPU generated RTL scenario and fresh replay
- Nearby scenario and generated TL-UL tests
- `git diff --check`

#### Goal

Prove a real Ibex OBI program can configure a pinned OpenTitan pattgen through
the abstract MMIO router, observe pattgen's actual two-channel serial outputs,
read its actual completion status back into the CPU, and replay the complete
scenario with fresh RTL processes.

This is not a generated SoC. Ibex and pattgen remain in independent harnesses;
the router transfers only accepted register transactions and real read values.

#### Scope

- Add one gated real integration test using the already authenticated Ibex OBI
  profile and OpenTitan pattgen TL-UL profile.
- The CPU program performs all pattgen setup writes, polls the real completion
  register, and stores the returned completion mask in persistent RAM.
- Parameterize a CPU program source value and run at least two legal variants;
  each value must change the pattern produced by actual pattgen RTL.
- Check register transaction order/value, both completion bits returned to the
  CPU, LSB-first output bits and local-clock periods, persistent RAM result,
  absence of reset between setup and completion, and fresh replay equivalence.
- Add a concise result report. Update the central capability table separately
  after review so unrelated documentation remains untouched during the task.

#### Constraints

- Preserve the current `Fuzzable Source`/`Bound Input` ownership model.
- CPU-generated register writes must originate from real CPU OBI transactions.
- Pattgen pattern data, output clock, and completion state must come from real
  pattgen RTL, never from the CPU program oracle or the test driver.
- Do not route completion IRQs through a fabricated interrupt controller.
- Do not change the pattgen RTL, source lock, generic harness generator, or
  claim CPU interrupt-handler coverage.

#### Acceptance

`MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest
tests.integration.test_scenario_ibex_opentitan_pattgen_generated_real -v`

must pass on two CPU-program variants and fresh replay, with assertions showing
the changed CPU source reaches pattgen output and both real completion bits
reach CPU memory. Focused scenario/local-harness regressions and
`git diff --check` must also pass.
