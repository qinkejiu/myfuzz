# P2/P5 pin8 native IRQ to CPU acceptance identity (2026-10-07)

## Scope

The producer now carries an exact GPIO B trigger reference through the local
`source_start`, `pulse_start`, `cpu_irq_input`, and observed `cpu_irq_taken`
events. The reference identifies the authenticated GPIO tick observation, the
derived `gpio_irq_trigger`, and the exact `local_tick_sample` phase. CPU input
and acceptance events identify the actual CPU step event. A missing,
conflicting, or reset reference remains absent.

`Pin8CpuIrqCertificates` independently joins the existing pin8 source-to-native
IRQ certificate with those delivery records. It verifies one GPIO B pin8
trigger, source event ID, declared four-tick pulse, one actual CPU step whose
input IRQ is one, and the same step's `irq_taken_pre=1`. It bounds cached
identity state and drops reset, overrun, expiry, and aged candidates.

The certificate ends at CPU IRQ acceptance. It does not establish ISR
execution, MMIO status/data reads, stores, or final GPIO A output.

## Evidence

- Existing probed trace:
  `runs/current-dataflow-p4-xori-certified-20261007-online/online_final_trace.json`
  contains five authenticated pin8 native IRQ certificates but has no new
  trigger-reference and CPU input fields. The new CPU certificate consumer
  correctly emits **zero** certificates from that trace unchanged.
- An in-memory compatibility test adds the new receipt shape to one existing
  source/pulse/CPU-take sequence in that trace, preserving its measured native
  tick, trigger, local sample, CPU step, and CPU acceptance. It emits **one**
  exact CPU IRQ certificate. This is a software compatibility check, not a new
  real RTL run or replay.
- Negative mutations of trigger event identity, local sample identity, CPU
  step identity, actual CPU IRQ input, Boolean field aliases, local sample,
  pulse start, and overrun all emit zero certificates. A reused source event
  ID is rejected, and one native certificate cannot issue twice.
- Focused verification:
  `PYTHONPATH=src:. python3 -m pytest -q tests/scenario/test_pin8_cpu_irq_certificates.py tests/scenario/test_pin8_irq_certificates.py tests/scenario/test_irq_delivery.py tests/scenario/test_generated_gpio_tick_delivery.py`
  → **37 passed**. `git diff --check` and `compileall` passed for the edited
  modules.

## Frozen-source real RTL gate

The changed source was frozen at
`/tmp/myfuzz-pin8-irq-snapshot-20261007`. Its 2,742 `src/`, `configs/`,
`scripts/`, `schemas/`, and `tests/` files are listed in
`runs/current-dataflow-p2-pin8-cpu-irq-identity-snapshot-20261007.sha256`
(manifest SHA-256
`0942fc29aae7d57b38fddffe60bff782dcff9e4bf88c123c046425cfbd6fe196`).
The pinned Ibex and PULP GPIO third-party source directories were copied into
the snapshot as hard-linked files; the frozen source manifest was checked again
after the run and replay: **2,742 checked, zero failures**. This is an
isolated source snapshot result, not proof about later changes in the shared
worktree.

The real online command ran from that snapshot:

```bash
python3 scripts/run_ibex_pulp_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir /home/qinkejiu/myfuzz/runs/current-dataflow-p5-timing-20261007-cache \
  --output /home/qinkejiu/myfuzz/runs/current-dataflow-p2-pin8-cpu-irq-identity-snapshot-20261007-online \
  --seconds 30 --max-tests 25 --seed 20261007 \
  --run-id current-dataflow-p2-pin8-cpu-irq-identity-snapshot-20261007 \
  --cpu-retirement --gpio-consumption
```

It exited 0 with **25/25 complete**, 36.336 seconds effective search and
31,679 trace events. An independent read-only audit found **5** authenticated
pin8 native IRQ certificates and **5** corresponding
`pin8_admission_to_cpu_irq_taken` certificates. Their source cases are 4, 10,
16, 20 and 22; their trigger IDs are `gpio_b:0:trigger:1`, `:3`, `:5`, `:6`
and `:7`. Each new CPU certificate binds a GPIO B trigger event and native
observation, `source_start`, four-tick `pulse_start`, real CPU step with
`inputs.irq=1`, same-step `cpu_irq_input`, and `cpu_irq_taken` with
`outputs.irq_taken_pre=1`. The two other native GPIO B trigger records were
pin0 rather than authenticated pin8 admissions and received no pin8
certificate.

The certificate counts were reproduced from the saved trace with:

```bash
PYTHONPATH=src:. python3 - <<'PY'
import json
from myfuzz.scenario.pin8_irq_certificates import Pin8IrqCertificates
from myfuzz.scenario.pin8_cpu_irq_certificates import Pin8CpuIrqCertificates
p = '/home/qinkejiu/myfuzz/runs/current-dataflow-p2-pin8-cpu-irq-identity-snapshot-20261007-online/online_final_trace.json'
events = json.load(open(p))['events']
print(len(events), len(Pin8IrqCertificates().ingest(events)),
      len(Pin8CpuIrqCertificates().ingest(events)))
PY
```

Output: `31679 5 5`.

Fresh replay used the same frozen source and a separate replay cache against
that run's saved `online_plan.json` and `online_final_trace.json`:

```bash
python3 scripts/run_ibex_pulp_online.py replay \
  --cache-dir /home/qinkejiu/myfuzz/runs/current-dataflow-p2-pin8-cpu-irq-identity-snapshot-20261007-replay-cache \
  --plan /home/qinkejiu/myfuzz/runs/current-dataflow-p2-pin8-cpu-irq-identity-snapshot-20261007-online/online_plan.json \
  --trace /home/qinkejiu/myfuzz/runs/current-dataflow-p2-pin8-cpu-irq-identity-snapshot-20261007-online/online_final_trace.json
```

It exited 0 with `matches=true`, `first_difference=null`, and
`difference_context=null`. The complete event and local-tick comparison is
therefore a real RTL replay check for this bounded run.

This closes the **pin8 admission → native GPIO B trigger → CPU IRQ acceptance**
identity gap for five measured examples. It still ends at IRQ acceptance;
neither ISR execution nor status/data read, RAM store, final GPIO A output,
or full P5 chain throughput is certified. The 25-case short run cannot be
used as a ten-minute efficiency gate.
