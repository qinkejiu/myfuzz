"""A source admission earns credit only after the authenticated GPIO stages consume it."""

from copy import deepcopy

from myfuzz.scenario.source_provenance import SourceAdmission
from myfuzz.scenario.pin8_consumption_certificates import Pin8ConsumptionCertificates
from tests.scenario.test_gpio_consumption_versions import tick, probes


def _admission(index=3):
    return SourceAdmission.create(
        case_id=f"case-{index}", case_index=index,
        source_id="gpio_b.external_pin8", path_id="pin-path",
        direction="IP_TO_CPU_TO_IP", component="gpio_b",
        action_id=f"pin-{index}", role="fuzz_source",
        input_kind="source_event", input_sha256="a" * 64)


def _case(index):
    return {"schema_version": "event_source_provenance.v1",
            "observed_case": {"case_id": f"case-{index}", "case_index": index}}


def _resource(register, version, observed_id, origin, predecessor=None):
    return {"component": "gpio_b", "reset_epoch": 0, "register": register,
            "bit": 8, "version": version, "value": 0,
            "observation_event_id": observed_id, "local_tick": version,
            "origin_status": "known", "origin_refs": [origin],
            "dependencies": [] if predecessor is None else [{key: predecessor[key]
                for key in ("component", "reset_epoch", "register", "bit", "version",
                            "value", "observation_event_id", "local_tick")}],}


def _events(admission):
    origin = admission.document()
    input_resource = _resource("input", 1, 4, origin)
    input_resource["actual_receipt_event_id"] = 3
    sync0 = _resource("sync0", 2, 6, origin, input_resource)
    sync1 = _resource("sync1", 3, 8, origin, sync0)
    latch = _resource("padin_latch", 4, 10, origin, sync1)
    ticks = [dict(tick(local_tick, probes(gpioen=256, input_clock_enable=4),
                       probes(gpioen=256, input_clock_enable=4), component="gpio_b"),
                  event_id=event_id, provenance=_case(4))
             for event_id, local_tick in ((3, 1), (6, 2), (8, 3), (10, 4))]
    return [
        {"event_id": 1, "kind": "source_admission", "admission": origin,
         "provenance": dict(_case(3), origin_status="known",
                            origin_admission_ids=[admission.admission_id])},
        {"event_id": 2, "kind": "source_injection", "action_id": admission.action_id,
         "component": "gpio_b", "port": "gpio_in", "bit_offset": 8,
         "width": 1, "value": 0, "provenance": dict(_case(3),
             origin_status="known", origin_admission_ids=[admission.admission_id])},
        ticks[0],
        {"event_id": 4, "kind": "gpio_input_segment_applied", "component": "gpio_b",
         "port": "gpio_in", "bit_lo": 8, "width": 1, "value": 0,
         "reset_epoch": 0, "local_tick": 1, "actual_receipt_event_id": 3,
         "actual_input_value": 0,
         "origin": {"kind": "source_admission", "action_id": admission.action_id},
         "provenance": _case(4)},
        {"event_id": 5, "kind": "gpio_input_applied_resource", "component": "gpio_b",
         "status": "observed", "origin_status": "known", "reset_epoch": 0,
         "local_tick": 1, "observation_event_id": 4, "producer_event_id": 4,
         "schema_version": "gpio_input_applied_resource.v1",
         "proof_scope": "gpio_native_resource_observation",
         "bit_resources": [input_resource], "provenance": _case(4)},
        ticks[1],
        {"event_id": 7, "kind": "gpio_input_sample", "component": "gpio_b",
         "status": "observed", "reset_epoch": 0, "local_tick": 2,
         "observation_event_id": 6, "producer_event_id": 6,
         "schema_version": "gpio_input_sample.v1",
         "proof_scope": "gpio_native_resource_observation",
         "enabled_mask": 256, "stages": {"sync0": [sync0]},
         "provenance": _case(4)},
        ticks[2],
        {"event_id": 9, "kind": "gpio_input_sample", "component": "gpio_b",
         "status": "observed", "reset_epoch": 0, "local_tick": 3,
         "observation_event_id": 8, "producer_event_id": 8,
         "schema_version": "gpio_input_sample.v1",
         "proof_scope": "gpio_native_resource_observation",
         "enabled_mask": 256, "stages": {"sync1": [sync1]},
         "provenance": _case(4)},
        ticks[3],
        {"event_id": 11, "kind": "gpio_input_sample", "component": "gpio_b",
         "status": "observed", "reset_epoch": 0, "local_tick": 4,
         "observation_event_id": 10, "producer_event_id": 10,
         "schema_version": "gpio_input_sample.v1",
         "proof_scope": "gpio_native_resource_observation",
         "enabled_mask": 256, "stages": {"padin_latch": [latch]},
         "provenance": _case(4)},
    ]


def test_pin8_certificate_keeps_source_and_later_consumer_case():
    admission = _admission()
    auditor = Pin8ConsumptionCertificates()
    certificates = []
    for event in _events(admission):
        certificates.extend(auditor.ingest((event,)))
    assert len(certificates) == 1
    certificate = certificates[0]
    assert certificate["scope"] == "pin8_admission_to_gpio_b_padin_latch"
    assert certificate["admission_id"] == admission.admission_id
    assert certificate["source_case"] == {"case_id": "case-3", "case_index": 3}
    assert certificate["consumer_case"] == {"case_id": "case-4", "case_index": 4}
    assert certificate["event_ids"] == [1, 2, 3, 4, 5, 7, 9, 11]
    assert certificate["resource_versions"] == [1, 2, 3, 4]


def test_unknown_origin_and_missing_dependency_do_not_certify():
    admission = _admission()
    for mutation in ("unknown", "missing_dependency", "wrong_admission"):
        events = _events(admission)
        if mutation == "unknown":
            events[6]["stages"]["sync0"][0]["origin_status"] = "unknown"
        elif mutation == "missing_dependency":
            events[10]["stages"]["padin_latch"][0]["dependencies"] = []
        else:
            events[6]["stages"]["sync0"][0]["origin_refs"] = [
                _admission(99).document()]
        assert Pin8ConsumptionCertificates().ingest(events) == ()


def test_superseded_drive_and_reset_drop_pending_chain():
    admission = _admission()
    for interruption in (
        {"kind": "gpio_input_applied_resource", "component": "gpio_b",
         "status": "observed", "reset_epoch": 0, "bit_resources": [
             _resource("input", 99, 10, _admission(99).document())]},
        {"kind": "reset_barrier"},
    ):
        events = _events(admission)
        event = deepcopy(interruption)
        event["event_id"] = 6
        for item in events[5:]:
            item["event_id"] += 1
        events.insert(5, event)
        assert Pin8ConsumptionCertificates().ingest(events) == ()


def test_same_action_held_drive_across_ticks_keeps_original_resource_chain():
    admission = _admission()
    events = _events(admission)
    held = deepcopy(events[3])
    held.update(event_id=9, local_tick=3, actual_receipt_event_id=8)
    for item in events[8:]:
        item["event_id"] += 1
    events.insert(8, held)
    events[-1]["producer_event_id"] = 11
    events[-1]["observation_event_id"] = 11
    events[-1]["stages"]["padin_latch"][0]["observation_event_id"] = 11
    assert len(Pin8ConsumptionCertificates().ingest(events)) == 1


def test_held_drive_with_wrong_actual_receipt_drops_prior_credit():
    admission = _admission()
    events = _events(admission)
    held = deepcopy(events[3])
    held.update(event_id=9, local_tick=3, actual_receipt_event_id=8,
                actual_input_value=256)
    for item in events[8:]:
        item["event_id"] += 1
    events.insert(8, held)
    events[-1]["producer_event_id"] = 11
    events[-1]["observation_event_id"] = 11
    events[-1]["stages"]["padin_latch"][0]["observation_event_id"] = 11
    assert Pin8ConsumptionCertificates().ingest(events) == ()
