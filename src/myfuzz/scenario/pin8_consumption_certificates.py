"""Bounded certificates for admitted pin-8 input consumed by real GPIO B RTL.

This does not certify an IRQ, CPU interrupt, MMIO read, or full feedback path.
The GPIO resource reports are trusted only when joined to an authenticated
actual tick and to the exact admission/action identities in the event journal.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable, Mapping

from .gpio_consumption import is_authenticated_gpio_tick
from .source_provenance import SourceAdmission


_REF_FIELDS = ("component", "reset_epoch", "register", "bit", "version",
               "value", "observation_event_id", "local_tick")


def _integer(value: object) -> bool:
    return type(value) is int and value >= 0


def _case(event: Mapping) -> dict | None:
    metadata = event.get("provenance")
    observed = metadata.get("observed_case") if isinstance(metadata, Mapping) else None
    if (not isinstance(observed, Mapping)
            or type(observed.get("case_id")) is not str
            or not observed["case_id"] or not _integer(observed.get("case_index"))):
        return None
    return {"case_id": observed["case_id"], "case_index": observed["case_index"]}


def _resource(event: Mapping, *, register: str, admission: SourceAdmission,
              epoch: int, value: int) -> dict | None:
    if (event.get("component") != "gpio_b" or event.get("reset_epoch") != epoch
            or event.get("register") != register or event.get("bit") != 8
            or event.get("value") != value or event.get("origin_status") != "known"
            or event.get("origin_refs") != [admission.document()]
            or not _integer(event.get("version"))
            or not _integer(event.get("observation_event_id"))
            or not _integer(event.get("local_tick"))):
        return None
    return dict(event)


def _depends_on(resource: Mapping, predecessor: Mapping) -> bool:
    dependencies = resource.get("dependencies")
    return (isinstance(dependencies, list) and len(dependencies) == 1
            and isinstance(dependencies[0], Mapping)
            and all(dependencies[0].get(key) == predecessor.get(key)
                    for key in _REF_FIELDS))


def _bit8(resources: object) -> Mapping | None:
    if not isinstance(resources, list):
        return None
    candidates = [item for item in resources
                  if isinstance(item, Mapping) and item.get("bit") == 8]
    return candidates[0] if len(candidates) == 1 else None


class Pin8ConsumptionCertificates:
    """Consume one ordered journal suffix and emit at most one certificate per pin admission.

    State is bounded by ``max_pending`` and ``max_event_gap``. Eviction,
    malformed identity, unknown origin, superseding drive, or reset drops the
    candidate; no later event may restore that candidate's credit.
    """

    def __init__(self, *, max_pending: int = 128, max_event_gap: int = 4096):
        if (type(max_pending) is not int or max_pending < 1
                or type(max_event_gap) is not int or max_event_gap < 1):
            raise ValueError("certificate bounds must be positive integers")
        self.max_pending = max_pending
        self.max_event_gap = max_event_gap
        self._last_event_id = 0
        self._last_pin_case = -1
        self._pending: OrderedDict[str, dict] = OrderedDict()
        self._ticks: OrderedDict[int, Mapping] = OrderedDict()
        self._segments: OrderedDict[int, Mapping] = OrderedDict()

    def ingest(self, events: Iterable[Mapping]) -> tuple[dict, ...]:
        certificates = []
        for event in events:
            if not isinstance(event, Mapping) or type(event.get("event_id")) is not int:
                raise ValueError("journal event needs an integer event_id")
            event_id = event["event_id"]
            if event_id != self._last_event_id + 1:
                raise ValueError("certificate journal must be contiguous")
            self._last_event_id = event_id
            for key, state in tuple(self._pending.items()):
                if event_id - state["admission_event_id"] > self.max_event_gap:
                    del self._pending[key]
            for cache in (self._ticks, self._segments):
                while cache and event_id - next(iter(cache)) > self.max_event_gap:
                    cache.popitem(last=False)
            kind = event.get("kind")
            if kind in {"reset_barrier", "gpio_reset_resource"}:
                self._pending.clear()
                self._ticks.clear()
                self._segments.clear()
                continue
            if kind == "source_admission":
                self._admission(event)
            elif kind == "source_injection":
                self._injection(event)
            elif kind == "gpio_tick_observation":
                if is_authenticated_gpio_tick(dict(event)) and event.get("component") == "gpio_b":
                    self._ticks[event_id] = event
                    while len(self._ticks) > self.max_pending:
                        self._ticks.popitem(last=False)
            elif kind == "gpio_input_segment_applied":
                self._segment(event)
            elif kind == "gpio_input_applied_resource":
                self._applied(event)
            elif kind == "gpio_input_sample":
                certificate = self._sample(event)
                if certificate is not None:
                    certificates.append(certificate)
        return tuple(certificates)

    def _admission(self, event: Mapping) -> None:
        try:
            admission = SourceAdmission.from_document(event.get("admission"))
        except (TypeError, ValueError):
            return
        if (admission.source_id != "gpio_b.external_pin8"
                or admission.component != "gpio_b" or admission.role != "fuzz_source"
                or admission.input_kind != "source_event"
                or admission.direction != "IP_TO_CPU_TO_IP"
                or admission.case_index <= self._last_pin_case
                or _case(event) != {"case_id": admission.case_id,
                                    "case_index": admission.case_index}):
            return
        provenance = event.get("provenance", {})
        if (provenance.get("origin_status") != "known"
                or provenance.get("origin_admission_ids") != [admission.admission_id]):
            return
        self._last_pin_case = admission.case_index
        self._pending[admission.admission_id] = {
            "admission": admission, "admission_event_id": event["event_id"],
            "injection": None, "segment": None, "applied": None,
            "sync0": None, "sync1": None, "padin_latch": None}
        while len(self._pending) > self.max_pending:
            self._pending.popitem(last=False)

    def _injection(self, event: Mapping) -> None:
        provenance = event.get("provenance", {})
        ids = provenance.get("origin_admission_ids") if isinstance(provenance, Mapping) else None
        if not isinstance(ids, list) or len(ids) != 1:
            return
        state = self._pending.get(ids[0])
        if state is None:
            return
        admission = state["admission"]
        if (state["injection"] is not None or event.get("action_id") != admission.action_id
                or event.get("component") != "gpio_b" or event.get("port") != "gpio_in"
                or event.get("bit_offset") != 8 or event.get("width") != 1
                or event.get("value") not in (0, 1)
                or type(event.get("value")) is not int
                or _case(event) != {"case_id": admission.case_id,
                                    "case_index": admission.case_index}):
            del self._pending[ids[0]]
            return
        state["injection"] = event["event_id"]
        state["value"] = event["value"]

    def _segment(self, event: Mapping) -> None:
        if event.get("component") != "gpio_b" or event.get("bit_lo") != 8:
            return
        origin = event.get("origin")
        action = origin.get("action_id") if isinstance(origin, Mapping) else None
        state = next((s for s in self._pending.values()
                      if s["admission"].action_id == action), None)
        tick = self._ticks.get(event.get("actual_receipt_event_id"))
        valid_tick = (tick is not None and tick.get("local_tick") == event.get("local_tick")
                      and tick.get("reset_epoch") == event.get("reset_epoch")
                      and event.get("width") == 1 and event.get("port") == "gpio_in"
                      and isinstance(origin, Mapping)
                      and origin.get("kind") == "source_admission"
                      and event.get("actual_input_value") == tick["pre"]["gpio_in"]
                      and event.get("actual_input_value") == tick["post"]["gpio_in"]
                      and type(event.get("actual_input_value")) is int
                      and (event["actual_input_value"] >> 8) & 1 == event.get("value"))
        # The local harness repeats a held source segment at every tick. A
        # different action or value supersedes it; an identical held receipt
        # leaves the first exact resource-to-stage chain intact.
        if state is not None and state["segment"] is not None:
            if (event.get("value") == state["value"]
                    and event.get("reset_epoch") == state["epoch"]
                    and valid_tick):
                return
            del self._pending[state["admission"].admission_id]
            return
        for key, previous in tuple(self._pending.items()):
            if previous["segment"] is not None:
                del self._pending[key]
        if state is None or state["injection"] is None or event.get("value") != state["value"]:
            return
        if not valid_tick:
            return
        state["segment"] = event["event_id"]
        state["tick"] = tick["event_id"]
        state["epoch"] = event["reset_epoch"]
        self._segments[event["event_id"]] = event
        while len(self._segments) > self.max_pending:
            self._segments.popitem(last=False)

    def _applied(self, event: Mapping) -> None:
        if event.get("component") != "gpio_b":
            return
        item = _bit8(event.get("bit_resources"))
        if item is None:
            return
        for key, state in tuple(self._pending.items()):
            if state["segment"] is None or state["segment"] != event.get("producer_event_id"):
                continue
            resource = _resource(item, register="input", admission=state["admission"],
                                 epoch=state["epoch"], value=state["value"])
            if (event.get("schema_version") != "gpio_input_applied_resource.v1"
                    or event.get("proof_scope") != "gpio_native_resource_observation"
                    or event.get("status") != "observed"
                    or event.get("origin_status") != "known"
                    or event.get("observation_event_id") != state["segment"]
                    or event.get("reset_epoch") != state["epoch"]
                    or resource is None or resource["observation_event_id"] != state["segment"]
                    or resource.get("actual_receipt_event_id") != state["tick"]):
                del self._pending[key]
                return
            state["applied"] = event["event_id"]
            state["input"] = resource
            return

    def _sample(self, event: Mapping) -> dict | None:
        if event.get("component") != "gpio_b":
            return None
        tick = self._ticks.get(event.get("producer_event_id"))
        if (tick is None or event.get("schema_version") != "gpio_input_sample.v1"
                or event.get("proof_scope") != "gpio_native_resource_observation"
                or event.get("status") != "observed"
                or event.get("observation_event_id") != tick["event_id"]
                or event.get("local_tick") != tick.get("local_tick")
                or event.get("reset_epoch") != tick.get("reset_epoch")
                or type(event.get("enabled_mask")) is not int
                or not event["enabled_mask"] & (1 << 8)):
            return None
        stages = event.get("stages")
        if not isinstance(stages, Mapping):
            return None
        for key, state in tuple(self._pending.items()):
            if state["applied"] is None or state["epoch"] != event["reset_epoch"]:
                continue
            admission = state["admission"]
            for register, previous in (("sync0", "input"),
                                       ("sync1", "sync0"),
                                       ("padin_latch", "sync1")):
                predecessor = state.get(previous)
                item = _bit8(stages.get(register))
                resource = (_resource(item, register=register, admission=admission,
                                      epoch=state["epoch"], value=state["value"])
                            if item is not None else None)
                if (predecessor is not None and resource is not None
                        and resource["observation_event_id"] == tick["event_id"]
                        and _depends_on(resource, predecessor)):
                    state[register] = resource
                    state[register + "_event"] = event["event_id"]
            if state["padin_latch"] is None:
                continue
            consumer = _case(event)
            if consumer is None or consumer["case_index"] < admission.case_index:
                del self._pending[key]
                return None
            certificate = {
                "schema_version": "pin8_consumption_certificate.v1",
                "scope": "pin8_admission_to_gpio_b_padin_latch",
                "admission_id": admission.admission_id,
                "action_id": admission.action_id,
                "source_case": {"case_id": admission.case_id,
                                "case_index": admission.case_index},
                "consumer_case": consumer,
                "component": "gpio_b", "pin": 8, "value": state["value"],
                "reset_epoch": state["epoch"],
                "event_ids": [state["admission_event_id"], state["injection"],
                              state["tick"], state["segment"], state["applied"],
                              state["sync0_event"], state["sync1_event"],
                              state["padin_latch_event"]],
                "resource_versions": [state["input"]["version"],
                                      state["sync0"]["version"],
                                      state["sync1"]["version"],
                                      state["padin_latch"]["version"]],
                "endpoint_observation_event_id": state["padin_latch"]["observation_event_id"],
                "proof_scope": "authenticated_gpio_resource_versions_only",
            }
            del self._pending[key]
            return certificate
        return None
