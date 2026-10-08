"""Real journal regression for an exact pin-8 input-to-native-IRQ join."""

import json
from pathlib import Path

from myfuzz.scenario.pin8_irq_certificates import Pin8IrqCertificates


TRACE = (Path(__file__).resolve().parents[2] / "runs" /
         "current-dataflow-p4-xori-certified-20261007-online" /
         "online_final_trace.json")


def test_real_probed_trace_certifies_five_pin8_native_irq_rises():
    events = json.loads(TRACE.read_text())["events"]
    certificates = Pin8IrqCertificates().ingest(events)
    assert len(certificates) == 5
    assert all(c["scope"] == "pin8_admission_to_gpio_b_native_irq_observation"
               for c in certificates)
    assert all(c["trigger_event_id"] < c["observation_event_id"]
               for c in certificates)
    assert len({c["trigger_id"] for c in certificates}) == 5
    assert all(isinstance(c["trigger_tick_event_id"], int)
               and c["trigger_tick_event_id"] < c["trigger_event_id"]
               for c in certificates)


def test_unknown_sync1_origin_or_wrong_trigger_cause_fails_closed():
    events = json.loads(TRACE.read_text())["events"]
    trigger = next(e for e in events if e.get("kind") == "gpio_irq_trigger"
                   and e.get("component") == "gpio_b" and e.get("mask") == 256)
    trigger["causes"][0]["current_sample"]["origin_status"] = "unknown"
    certificates = Pin8IrqCertificates().ingest(events)
    assert trigger["trigger_id"] not in {c["trigger_id"] for c in certificates}


def test_missing_native_observation_does_not_certify_delivery():
    events = json.loads(TRACE.read_text())["events"]
    observation = next(e for e in events if e.get("kind") == "gpio_irq_observation"
                       and e.get("component") == "gpio_b" and e.get("mask") == 256)
    observation["trigger_id"] = "different-trigger"
    certificates = Pin8IrqCertificates().ingest(events)
    assert len(certificates) == 4


def test_reset_between_trigger_and_observation_drops_credit():
    events = json.loads(TRACE.read_text())["events"]
    events[6450] = {"event_id": 6451, "kind": "reset_barrier"}
    certificates = Pin8IrqCertificates().ingest(events)
    assert len(certificates) == 4


def test_event_age_bound_fails_closed():
    events = json.loads(TRACE.read_text())["events"]
    assert Pin8IrqCertificates(max_event_gap=64).ingest(events) == ()
