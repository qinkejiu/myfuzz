"""Bounded, read-only pin-8 source-to-native-GPIO-IRQ certificates.

The terminal observation is the GPIO B native IRQ high report. CPU interrupt
delivery is deliberately outside this certificate: its journal has no exact
trigger identity linking it to the native GPIO event.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable, Mapping

from .gpio_consumption import is_authenticated_gpio_tick
from .pin8_consumption_certificates import _case, _depends_on, _resource, _bit8
from .source_provenance import SourceAdmission


def _same_resource(left: Mapping, right: Mapping) -> bool:
    keys = ("component", "reset_epoch", "register", "bit", "version",
            "value", "observation_event_id", "local_tick", "origin_status",
            "origin_refs", "dependencies")
    return all(left.get(key) == right.get(key) for key in keys)


class Pin8IrqCertificates:
    """Consume a contiguous journal, failing closed on missing or aged edges."""

    def __init__(self, *, max_pending: int = 128, max_event_gap: int = 4096):
        if (type(max_pending) is not int or max_pending < 1 or
                type(max_event_gap) is not int or max_event_gap < 1):
            raise ValueError("certificate bounds must be positive integers")
        self.max_pending = max_pending
        self.max_event_gap = max_event_gap
        self._last_event_id = 0
        self._last_case = -1
        self._sources: OrderedDict[str, dict] = OrderedDict()
        self._ticks: OrderedDict[int, Mapping] = OrderedDict()
        self._triggers: OrderedDict[str, dict] = OrderedDict()

    def ingest(self, events: Iterable[Mapping]) -> tuple[dict, ...]:
        result = []
        for event in events:
            if (not isinstance(event, Mapping) or
                    type(event.get("event_id")) is not int or
                    event["event_id"] != self._last_event_id + 1):
                raise ValueError("certificate journal must be contiguous")
            self._last_event_id = event["event_id"]
            self._expire(event["event_id"])
            kind = event.get("kind")
            if kind in ("reset_barrier", "gpio_reset_resource"):
                self._sources.clear(); self._ticks.clear(); self._triggers.clear()
            elif kind == "source_admission":
                self._admission(event)
            elif kind == "source_injection":
                self._injection(event)
            elif kind == "gpio_tick_observation":
                if event.get("component") == "gpio_b" and is_authenticated_gpio_tick(dict(event)):
                    self._ticks[event["event_id"]] = event
                    self._limit(self._ticks)
            elif kind == "gpio_input_segment_applied":
                self._segment(event)
            elif kind == "gpio_input_applied_resource":
                self._applied(event)
            elif kind == "gpio_input_sample":
                self._sample(event)
            elif kind == "gpio_irq_trigger":
                self._trigger(event)
            elif kind == "gpio_irq_observation":
                certificate = self._observation(event)
                if certificate is not None:
                    result.append(certificate)
        return tuple(result)

    def _limit(self, cache: OrderedDict) -> None:
        while len(cache) > self.max_pending:
            cache.popitem(last=False)

    def _expire(self, event_id: int) -> None:
        for key, state in tuple(self._sources.items()):
            if event_id - state["admission_event_id"] > self.max_event_gap:
                del self._sources[key]
        for cache in (self._ticks, self._triggers):
            for key, value in tuple(cache.items()):
                age_id = key if cache is self._ticks else value["trigger_event_id"]
                if event_id - age_id > self.max_event_gap:
                    del cache[key]

    def _admission(self, event: Mapping) -> None:
        try:
            admission = SourceAdmission.from_document(event.get("admission"))
        except (TypeError, ValueError):
            return
        provenance = event.get("provenance")
        if (admission.source_id != "gpio_b.external_pin8" or
                admission.component != "gpio_b" or admission.role != "fuzz_source" or
                admission.input_kind != "source_event" or
                admission.direction != "IP_TO_CPU_TO_IP" or
                admission.case_index <= self._last_case or
                _case(event) != {"case_id": admission.case_id,
                                 "case_index": admission.case_index} or
                not isinstance(provenance, Mapping) or
                provenance.get("origin_status") != "known" or
                provenance.get("origin_admission_ids") != [admission.admission_id]):
            return
        self._last_case = admission.case_index
        self._sources[admission.admission_id] = dict(
            admission=admission, admission_event_id=event["event_id"],
            injection=None, segment=None, input=None, sync0=None, sync1=None)
        self._limit(self._sources)

    def _injection(self, event: Mapping) -> None:
        provenance = event.get("provenance")
        ids = provenance.get("origin_admission_ids") if isinstance(provenance, Mapping) else None
        if not isinstance(ids, list) or len(ids) != 1 or ids[0] not in self._sources:
            return
        state = self._sources[ids[0]]
        admission = state["admission"]
        if (state["injection"] is not None or
                event.get("action_id") != admission.action_id or
                event.get("component") != "gpio_b" or event.get("port") != "gpio_in" or
                event.get("bit_offset") != 8 or event.get("width") != 1 or
                type(event.get("value")) is not int or event["value"] not in (0, 1) or
                _case(event) != {"case_id": admission.case_id,
                                 "case_index": admission.case_index}):
            del self._sources[ids[0]]
            return
        state["injection"] = event["event_id"]
        state["value"] = event["value"]

    def _segment(self, event: Mapping) -> None:
        if event.get("component") != "gpio_b" or event.get("bit_lo") != 8:
            return
        origin = event.get("origin")
        action = origin.get("action_id") if isinstance(origin, Mapping) else None
        state = next((s for s in self._sources.values() if s["admission"].action_id == action), None)
        tick = self._ticks.get(event.get("actual_receipt_event_id"))
        valid = (tick is not None and event.get("local_tick") == tick.get("local_tick") and
                 event.get("reset_epoch") == tick.get("reset_epoch") and
                 event.get("port") == "gpio_in" and event.get("width") == 1 and
                 isinstance(origin, Mapping) and origin.get("kind") == "source_admission" and
                 type(event.get("actual_input_value")) is int and
                 event["actual_input_value"] == tick["pre"]["gpio_in"] == tick["post"]["gpio_in"] and
                 event.get("value") == ((event["actual_input_value"] >> 8) & 1))
        for key, previous in tuple(self._sources.items()):
            if previous["segment"] is not None and previous is not state:
                del self._sources[key]
        if state is None or state["injection"] is None:
            return
        if state["segment"] is not None:
            if not valid or event.get("value") != state["value"] or event.get("reset_epoch") != state["epoch"]:
                del self._sources[state["admission"].admission_id]
            return
        if not valid or event.get("value") != state["value"]:
            del self._sources[state["admission"].admission_id]
            return
        state["segment"] = event["event_id"]
        state["tick"] = tick["event_id"]
        state["epoch"] = event["reset_epoch"]

    def _applied(self, event: Mapping) -> None:
        if event.get("component") != "gpio_b":
            return
        for key, state in tuple(self._sources.items()):
            if state["segment"] != event.get("producer_event_id"):
                continue
            item = _bit8(event.get("bit_resources"))
            resource = (_resource(item, register="input", admission=state["admission"],
                                  epoch=state["epoch"], value=state["value"])
                        if item is not None else None)
            if (event.get("schema_version") != "gpio_input_applied_resource.v1" or
                    event.get("proof_scope") != "gpio_native_resource_observation" or
                    event.get("status") != "observed" or
                    event.get("origin_status") != "known" or
                    event.get("observation_event_id") != state["segment"] or
                    resource is None or resource.get("actual_receipt_event_id") != state["tick"]):
                del self._sources[key]
            else:
                state["input"] = resource
                state["applied_event_id"] = event["event_id"]

    def _sample(self, event: Mapping) -> None:
        if event.get("component") != "gpio_b":
            return
        tick = self._ticks.get(event.get("producer_event_id"))
        if (tick is None or event.get("schema_version") != "gpio_input_sample.v1" or
                event.get("proof_scope") != "gpio_native_resource_observation" or
                event.get("status") != "observed" or
                event.get("observation_event_id") != tick["event_id"] or
                event.get("local_tick") != tick.get("local_tick") or
                event.get("reset_epoch") != tick.get("reset_epoch") or
                type(event.get("enabled_mask")) is not int or
                not event["enabled_mask"] & (1 << 8) or
                not isinstance(event.get("stages"), Mapping)):
            return
        for state in self._sources.values():
            if state["input"] is None or state["epoch"] != event["reset_epoch"]:
                continue
            for register, predecessor in (("sync0", "input"), ("sync1", "sync0")):
                item = _bit8(event["stages"].get(register))
                resource = (_resource(item, register=register, admission=state["admission"],
                                      epoch=state["epoch"], value=state["value"])
                            if item is not None else None)
                if (state[predecessor] is not None and resource is not None and
                        resource["observation_event_id"] == tick["event_id"] and
                        _depends_on(resource, state[predecessor])):
                    state[register] = resource
                    state[register + "_event_id"] = event["event_id"]

    def _trigger(self, event: Mapping) -> None:
        if event.get("component") != "gpio_b" or event.get("mask") != 1 << 8:
            return
        tick = self._ticks.get(event.get("producer_event_id"))
        causes = event.get("causes")
        if (tick is None or event.get("schema_version") != "gpio_irq_trigger.v1" or
                event.get("proof_scope") != "gpio_native_resource_observation" or
                event.get("status") != "observed" or event.get("origin_status") != "known" or
                event.get("phase") != "post" or
                event.get("observation_event_id") != tick["event_id"] or
                event.get("local_tick") != tick.get("local_tick") or
                event.get("reset_epoch") != tick.get("reset_epoch") or
                tick["pre"].get("gpio_probe_native_irq") != 0 or
                tick["post"].get("gpio_probe_native_irq") != 1 or
                tick["post"].get("gpio_probe_irq_trigger_mask") != 1 << 8 or
                not isinstance(causes, list) or len(causes) != 1 or
                not isinstance(causes[0], Mapping) or causes[0].get("pin") != 8 or
                type(event.get("trigger_id")) is not str):
            return
        cause = causes[0]
        prior, current = cause.get("prior_sample"), cause.get("current_sample")
        if (not isinstance(prior, Mapping) or not isinstance(current, Mapping) or
                prior.get("component") != "gpio_b" or prior.get("register") != "padin_latch" or
                prior.get("bit") != 8 or prior.get("value") != 0 or
                prior.get("reset_epoch") != event["reset_epoch"] or
                current.get("value") != 1 or
                prior.get("observation_event_id") != tick["event_id"]):
            return
        for state in self._sources.values():
            sample = state["sync1"]
            if (sample is None or state["value"] != 1 or
                    state["epoch"] != event["reset_epoch"] or
                    not _same_resource(sample, current) or
                    sample["observation_event_id"] != tick["event_id"]):
                continue
            case = _case(event)
            if case is None or case["case_index"] < state["admission"].case_index:
                return
            self._triggers[event["trigger_id"]] = dict(
                trigger_id=event["trigger_id"], trigger_event_id=event["event_id"],
                trigger_tick_id=tick["event_id"], case=case,
                admission=state["admission"], admission_event_id=state["admission_event_id"],
                injection_event_id=state["injection"], segment_event_id=state["segment"],
                input_event_id=state["applied_event_id"],
                sync0_event_id=state["sync0_event_id"],
                sync1_event_id=state["sync1_event_id"],
                versions=[state[r]["version"] for r in ("input", "sync0", "sync1")],
                prior_version=prior.get("version"), epoch=state["epoch"],
                cause=dict(cause))
            self._limit(self._triggers)
            return

    def _observation(self, event: Mapping) -> dict | None:
        if event.get("component") != "gpio_b" or event.get("mask") != 1 << 8:
            return None
        state = self._triggers.get(event.get("trigger_id"))
        tick = self._ticks.get(event.get("producer_event_id"))
        if state is None or tick is None:
            return None
        causes = event.get("causes")
        if (event.get("schema_version") != "gpio_irq_observation.v1" or
                event.get("proof_scope") != "gpio_native_resource_observation" or
                event.get("status") != "observed" or event.get("phase") != "pre" or
                event.get("observation_event_id") != tick["event_id"] or
                event.get("reset_epoch") != state["epoch"] or
                event.get("local_tick") != tick.get("local_tick") or
                tick["pre"].get("gpio_probe_native_irq") != 1 or
                tick["pre"].get("gpio_probe_irq_trigger_mask") != 1 << 8 or
                not isinstance(causes, list) or len(causes) != 1 or
                not isinstance(causes[0], Mapping) or causes[0].get("pin") != 8 or
                causes[0].get("prior_sample") != state["cause"]["prior_sample"] or
                causes[0].get("current_sample") != state["cause"]["current_sample"] or
                _case(event) != state["case"]):
            del self._triggers[state["trigger_id"]]
            return None
        del self._triggers[state["trigger_id"]]
        admission = state["admission"]
        return dict(schema_version="pin8_irq_certificate.v1",
                    scope="pin8_admission_to_gpio_b_native_irq_observation",
                    proof_scope="authenticated_gpio_resource_versions_only",
                    admission_id=admission.admission_id, action_id=admission.action_id,
                    source_case={"case_id": admission.case_id,
                                 "case_index": admission.case_index},
                    consumer_case=state["case"], component="gpio_b", pin=8,
                    trigger_id=state["trigger_id"], reset_epoch=state["epoch"],
                    trigger_event_id=state["trigger_event_id"],
                    trigger_tick_event_id=state["trigger_tick_id"],
                    observation_event_id=event["event_id"],
                    event_ids=[state[k] for k in ("admission_event_id", "injection_event_id",
                                                   "segment_event_id", "input_event_id",
                                                   "sync0_event_id", "sync1_event_id",
                                                   "trigger_event_id")]+[event["event_id"]],
                    resource_versions=state["versions"],
                    prior_padin_latch_version=state["prior_version"])
