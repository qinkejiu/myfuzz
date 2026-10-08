# P2/P5 pin8 source to native GPIO B IRQ certificate

## Claim boundary

`Pin8IrqCertificates` reads an ordered event journal and issues
`pin8_admission_to_gpio_b_native_irq_observation` certificates. The chain is
an authenticated pin8 `SourceAdmission` and injection, actual GPIO B input
receipt, versioned `input → sync0 → sync1` resources with exact dependency and
origin, one native GPIO B pin8 rising trigger, and the following native high
observation with the same `trigger_id` and exact prior/current cause resources.
The authenticated PULP GPIO tick validates physical pre/post probe values and
native IRQ mask. A certificate includes source and consumer case, admission ID,
action ID, trigger ID, witness event IDs, resource versions, prior latch
version, and reset epoch. State is limited to 128 sources, ticks and triggers
and a 4,096-event age. Reset, missing or unknown origin, wrong cause, missing
observation, or bounded eviction removes credit.

The trigger's `causes.prior_sample` is a **previous value 0** on
`padin_latch`; its `causes.current_sample` is the **new value 1** on `sync1`.
The earlier PADIN-latch certificate for the previous low admission is not
mistaken for the rising admission. The trigger's native IRQ observation is a
GPIO-side high signal, not proof that Ibex accepted the interrupt.

## Existing real RTL trace audit

The 25-case probed trace
`runs/current-dataflow-p4-xori-certified-20261007-online/online_final_trace.json`
has 31,651 journal events. The bounded auditor issues **5 certificates**,
for source cases 4, 10, 16, 20 and 22. Their native trigger IDs are
`gpio_b:0:trigger:1`, `:3`, `:5`, `:6`, and `:7` respectively. The first
certificate witnesses event IDs `[6349, 6350, 6390, 6391, 6392, 6434, 6435,
6474]`, resource versions `[6245, 6258, 6292]`, and previous latch version
6293. The separate 100-case probed JSONL trace
`runs/current-dataflow-p4-xori-retire-20261007-online/online_events.jsonl`
has 143,675 events and independently yields the same 5 native IRQ
certificates. These are bounded real trace checks, not a 600-second chain
throughput claim.

In the 25-case trace, 7 GPIO B native trigger reports exist; 5 have pin8 mask
`0x100` and two have pin0 mask `0x1`. There are 5 `cpu_irq_taken` events, but
they carry `source_event_id` values without a GPIO `trigger_id`, resource
version or origin-admission ID. Those events cannot be joined to these five
certificates by equality of event identity. Their temporal proximity, pin
value, or equal count is insufficient. The producer should expose the exact
GPIO B trigger ID on the IRQ delivery and CPU take edge, including reset epoch
and source/target endpoint identity, then the auditor can extend the chain.
The downstream ISR PADIN read, CPU response and GPIO A output also need
versioned origin joins before a full P5 propagation chain can be counted.

## Verification

```bash
PYTHONPATH=src:. python3 -m pytest \
  tests/scenario/test_pin8_irq_certificates.py \
  tests/scenario/test_pin8_consumption_certificates.py -q
```

Result: `10 passed`. The tests include the real 25-case trace, unknown sync1
origin, wrong observation trigger ID, reset between trigger and observation,
and strict event-age eviction. The 100-case check was streamed with:

```bash
PYTHONPATH=src:. python3 - <<'PY'
import json
from myfuzz.scenario.pin8_irq_certificates import Pin8IrqCertificates
auditor = Pin8IrqCertificates()
count = 0
with open('runs/current-dataflow-p4-xori-retire-20261007-online/online_events.jsonl') as source:
    for line in source:
        count += len(auditor.ingest((json.loads(line),)))
print(count)
PY
```

Result: `5`.
