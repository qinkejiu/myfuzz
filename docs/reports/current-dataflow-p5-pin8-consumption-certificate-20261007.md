# Pin-8 source-to-GPIO consumption certificate, bounded pilot

## Scope and evidence

`Pin8ConsumptionCertificates` is a read-only, incremental journal consumer. It emits **only** `pin8_admission_to_gpio_b_padin_latch` certificates. It requires a valid `SourceAdmission` digest and exact pin-8 source ID/action; a `source_injection` with the same admission ID; an authenticated PULP GPIO tick and exact actual-input receipt; the tracker's `gpio_input_applied_resource`; and known source-admission origin in each versioned `input → sync0 → sync1 → padin_latch` dependency. The certificate records source and consumer case identities separately, witness event IDs, four resource versions, reset epoch and endpoint observation ID. An unknown origin, missing dependency or tick, wrong value, superseding drive, reset, or bounded-state eviction produces no certificate. Held same-action receipts are accepted only when their actual tick and value still match. It keeps at most 128 pending sources and 128 recent ticks and segments, with a 4,096-event candidate age bound by default; these bounds can reject an otherwise valid long-latency path.

This is a **physical GPIO input consumption subchain**, not a complete Ibex + two GPIO propagation chain. It says nothing about GPIO B IRQ trigger-to-CPU routing or take, ISR PADIN read and CPU response/store, or final GPIO A output. The older 600-second P5 snapshot did not enable the authenticated GPIO probe profile, so this module cannot issue a certificate from that run. `observed_path` labels and four coarse target bits still cannot supply its missing resource versions.

## Real trace check

The existing probed Ibex + dual GPIO 25-case trace at `runs/current-dataflow-p4-xori-certified-20261007-online/online_final_trace.json` contains 31,651 events. The bounded consumer emits **13** distinct pin-8-to-PADIN-latch certificates. The first has admission `9c8e41bdfc3ab30a15cd5e7147c86da8569d0987fc3694dc03c63db4063739dc`, source case 3, endpoint case 3, witness event IDs `[5241,5242,5264,5282,5283,5284,5326,5362]`, resource versions `[5189,5202,5236,5270]`, and final physical observation event 5342. A separate 100-case, 143,675-event diagnostic JSONL yields **14** subchain certificates. Neither result is divided by the P5 600-second denominator or presented as full-chain throughput. In these samples all certified endpoints happen within their source case, though the schema and state machine preserve and permit later-case endpoints.

The default `IbexPulpOnlineChecker` still reports contradictions rather than complete chains. `InteractionFeedback`'s IRQ/read/write paths remain local witnesses. Strict complete real propagation chains/s for P5 remains undetermined until an additional certificate connects this sourced GPIO B resource/trigger to a specific CPU IRQ take and then follows accepted ISR transactions, matched CPU response and final GPIO A output under the same origin/version identity. A source admission, matching value, or temporal proximity alone is insufficient for those joins.

## Reproduction

```bash
PYTHONPATH=src:. python3 -m pytest tests/scenario/test_pin8_consumption_certificates.py -q
PYTHONPATH=src:. python3 - <<'PY'
import json
from myfuzz.scenario.pin8_consumption_certificates import Pin8ConsumptionCertificates
path = 'runs/current-dataflow-p4-xori-certified-20261007-online/online_final_trace.json'
events = json.load(open(path))['events']
certificates = Pin8ConsumptionCertificates().ingest(events)
print(len(events), len(certificates), certificates[0])
PY
PYTHONPATH=src:. python3 - <<'PY'
import json
from myfuzz.scenario.pin8_consumption_certificates import Pin8ConsumptionCertificates
path = 'runs/current-dataflow-p4-xori-retire-20261007-online/online_events.jsonl'
auditor = Pin8ConsumptionCertificates()
count = events = 0
with open(path) as source:
    for line in source:
        events += 1
        count += len(auditor.ingest((json.loads(line),)))
print(events, count)
PY
```
