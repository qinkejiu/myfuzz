"""Exact pin8 native IRQ to CPU input/take joins over a real trace prefix."""

import json
from functools import lru_cache
from pathlib import Path

from myfuzz.scenario.pin8_cpu_irq_certificates import Pin8CpuIrqCertificates
from myfuzz.scenario.pin8_irq_certificates import Pin8IrqCertificates


TRACE = (Path(__file__).resolve().parents[2] / "runs" /
         "current-dataflow-p4-xori-certified-20261007-online" /
         "online_final_trace.json")


@lru_cache(maxsize=1)
def _trace_and_native():
    events = json.loads(TRACE.read_text())["events"]
    native = Pin8IrqCertificates().ingest(events)
    return events, native


def _with_first_cpu_receipt():
    original, native = _trace_and_native()
    events = list(original)
    certificate = native[0]
    trigger_id = certificate["trigger_id"]
    start = next(e for e in events[certificate["trigger_event_id"]:]
                 if e.get("kind") == "source_start"
                 and e.get("source") == ["gpio_b", "irq"])
    source_id = start["source_event_id"]
    pulse = next(e for e in events[start["event_id"]:]
                 if e.get("kind") == "pulse_start"
                 and e.get("source_event_id") == source_id)
    taken = next(e for e in events[pulse["event_id"]:]
                 if e.get("kind") == "cpu_irq_taken"
                 and e.get("source_event_id") == source_id)
    step = events[taken["event_id"] - 3]
    assert step["event_id"] == taken["event_id"] - 2
    assert step["inputs"]["irq"] == step["outputs"]["irq_taken_pre"] == 1
    ref = {"trigger_id": trigger_id,
           "trigger_event_id": certificate["trigger_event_id"],
           "observation_event_id": certificate["trigger_tick_event_id"],
           "sample_event_id": start["event_id"] - 1}
    for event in (start, pulse, taken):
        events[event["event_id"] - 1] = {**event, "source_trigger": ref}
    events[taken["event_id"] - 2] = {
        "event_id": taken["event_id"] - 1, "kind": "cpu_irq_input",
        "source": ["gpio_b", "irq"], "target": ["cpu", "irq"],
        "source_event_id": source_id, "source_trigger": ref,
        "cpu_tick": taken["cpu_tick"], "cpu_step_event_id": step["event_id"],
        "value": 1, "source_bit_offset": 0, "target_bit_offset": 0,
        "width": 1}
    events[taken["event_id"] - 1] = {
        **events[taken["event_id"] - 1],
        "cpu_step_event_id": step["event_id"]}
    return events, certificate, start, taken


def test_original_real_trace_has_no_invented_cpu_certificate():
    original, _ = _trace_and_native()
    assert Pin8CpuIrqCertificates().ingest(original) == ()


def test_exact_source_pulse_cpu_input_and_take_certify_one_existing_real_chain():
    events, native, start, taken = _with_first_cpu_receipt()
    certificates = Pin8CpuIrqCertificates().ingest(events)
    assert len(certificates) == 1
    proof = certificates[0]
    assert proof["trigger_id"] == native["trigger_id"]
    assert proof["source_start_event_id"] == start["event_id"]
    assert proof["cpu_irq_taken_event_id"] == taken["event_id"]
    assert proof["cpu_step_event_id"] == taken["event_id"] - 2


def test_wrong_trigger_or_cpu_step_or_overrun_never_certifies():
    events, _, start, taken = _with_first_cpu_receipt()
    for fault in ("wrong_trigger", "wrong_step", "wrong_input", "bool_input",
                  "bool_binding", "overrun", "wrong_sample",
                  "wrong_pulse_start"):
        damaged = list(events)
        if fault == "wrong_trigger":
            record = dict(damaged[taken["event_id"] - 1])
            record["source_trigger"] = {**record["source_trigger"],
                                        "trigger_event_id": 1}
            damaged[taken["event_id"] - 1] = record
        elif fault == "wrong_step":
            record = dict(damaged[taken["event_id"] - 2])
            record["cpu_step_event_id"] = start["event_id"]
            damaged[taken["event_id"] - 2] = record
        elif fault == "wrong_input":
            step = dict(damaged[taken["event_id"] - 3])
            step["inputs"] = {**step["inputs"], "irq": 0}
            damaged[taken["event_id"] - 3] = step
        elif fault == "bool_input":
            step = dict(damaged[taken["event_id"] - 3])
            step["inputs"] = {**step["inputs"], "irq": True}
            damaged[taken["event_id"] - 3] = step
        elif fault == "bool_binding":
            record = dict(damaged[start["event_id"] - 1])
            record["source_bit_offset"] = False
            damaged[start["event_id"] - 1] = record
        elif fault == "wrong_sample":
            record = dict(damaged[start["event_id"] - 1])
            record["source_trigger"] = {**record["source_trigger"],
                                        "sample_event_id": 1}
            damaged[start["event_id"] - 1] = record
        elif fault == "wrong_pulse_start":
            pulse_id = start["event_id"] + 1
            record = dict(damaged[pulse_id - 1])
            record["start_cpu_tick"] += 1
            damaged[pulse_id - 1] = record
        else:
            event_id = next(
                e["event_id"] for e in damaged[start["event_id"]:taken["event_id"] - 1]
                if e.get("kind") == "source_end" and
                e.get("source_event_id") == start["source_event_id"])
            damaged[event_id - 1] = {"event_id": event_id,
                                     "kind": "irq_overrun",
                                     "active_source_event_id": start["source_event_id"]}
        assert Pin8CpuIrqCertificates().ingest(damaged) == (), fault


def test_source_event_ids_must_advance_without_reuse():
    events, _, start, _ = _with_first_cpu_receipt()
    ref = events[start["event_id"] - 1]["source_trigger"]
    consumer = Pin8CpuIrqCertificates()
    consumer._raw[ref["observation_event_id"]] = events[ref["observation_event_id"] - 1]
    consumer._samples[ref["sample_event_id"]] = events[ref["sample_event_id"] - 1]
    later = {**events[start["event_id"] - 1], "source_event_id": 2}
    consumer._source(later)
    reused = {**later, "source_event_id": 1, "event_id": later["event_id"] + 1}
    consumer._source(reused)
    assert set(consumer._sources) == {2}
