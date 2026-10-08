"""Conservative interaction feedback derived from recorded RTL observations.

The collector does not predict DUT outputs or infer a causal edge merely from
two components appearing in the same testcase. A reported edge has a concrete
delivery/transaction witness; a closed loop additionally requires observed
input consumption at every hop.

``closed_loops`` here keeps its legacy bound-input meaning: a chain of
``bound_input_consumed`` edges returning to its first component. Certified
end-to-end runtime chains are consumed separately, and read-only, by
:mod:`myfuzz.scenario.closed_loop_feedback`, which reports ``closed_loop``,
``partial_propagation`` and ``stage_reached`` hits from
``runtime_chain_certificate.v1`` documents.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from copy import deepcopy
from bisect import bisect_right
import json
from typing import Callable


def _identity(value: object) -> str | None:
    if not isinstance(value, Mapping):
        return None
    try:
        return json.dumps(dict(value), sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError):
        return None


def _pair(value: object) -> tuple[str, str] | None:
    if (not isinstance(value, (tuple, list)) or len(value) != 2
            or not all(isinstance(item, str) and item for item in value)):
        return None
    return value[0], value[1]


def _event_id(event: Mapping) -> int | None:
    value = event.get("event_id")
    return value if type(value) is int and value > 0 else None


def _real_output(event: Mapping, component: str, port: str) -> bool:
    outputs = event.get("outputs")
    return (event.get("component") == component
            and isinstance(outputs, Mapping)
            and type(outputs.get(port)) is int)


def _delivery_matches_output(delivery: Mapping, producer: Mapping,
                             source: tuple[str, str]) -> bool:
    if not _real_output(producer, *source):
        return False
    value = delivery.get("value")
    if type(value) is not int:
        return False
    slicing = ("source_bit_offset", "target_bit_offset", "width", "target_value")
    if not any(name in delivery for name in slicing):
        return producer["outputs"][source[1]] == value
    if any(type(delivery.get(name)) is not int for name in slicing):
        return False
    offset, target_offset, width = (delivery["source_bit_offset"],
                                   delivery["target_bit_offset"], delivery["width"])
    if offset < 0 or target_offset < 0 or not 1 <= width <= 8192:
        return False
    mask = (1 << width) - 1
    return (value == (producer["outputs"][source[1]] >> offset) & mask
            and value == (delivery["target_value"] >> target_offset) & mask)


def _delivery_matches_input(delivery: Mapping, value: object) -> bool:
    if type(value) is not int:
        return False
    if "width" not in delivery:
        return value == delivery["value"]
    # The corresponding output witness already validated the slice fields.
    mask = (1 << delivery["width"]) - 1
    return (value >> delivery["target_bit_offset"]) & mask == delivery["value"]


class _JournalEventLookup:
    """Small Mapping-like facade over Runner's authoritative event journal."""

    def __init__(self, lookup: Callable[[int], Mapping | None],
                 owner: InteractionFeedback) -> None:
        self._lookup = lookup
        self._owner = owner

    def get(self, event_id: int, default=None):
        if (type(event_id) is not int
                or not self._owner._starting_event_id < event_id <= self._owner._last_event_id):
            return default
        found = self._lookup(event_id)
        return found if found is not None else default

    def __getitem__(self, event_id: int):
        found = self.get(event_id)
        if found is None:
            raise KeyError(event_id)
        return found

    def __len__(self) -> int:
        return self._owner._ingested_count


class InteractionFeedback:
    """Accumulate an event prefix and return deterministic JSON-ready feedback.

    ``ingest`` accepts either a new suffix or a repeated cumulative prefix.
    Reusing an event ID with different content is rejected. Reset barriers
    invalidate outstanding bound-delivery witnesses, but prior feedback remains
    in the historical summary.
    """

    def __init__(self, *, event_lookup: Callable[[int], Mapping | None] | None = None,
                 starting_event_id: int = 0
                 ) -> None:
        if event_lookup is not None and not callable(event_lookup):
            raise ValueError("online event lookup must be callable")
        if type(starting_event_id) is not int or starting_event_id < 0:
            raise ValueError("starting event ID must be nonnegative")
        if event_lookup is None and starting_event_id:
            raise ValueError("offline feedback starts at event zero")
        self._event_lookup = event_lookup
        self._starting_event_id = starting_event_id
        self._events: dict[int, dict] | _JournalEventLookup = (
            _JournalEventLookup(event_lookup, self) if event_lookup is not None else {})
        self._last_event_id = starting_event_id
        self._ingested_count = 0
        self._epoch = 0
        self._epoch_by_event_id: dict[int, int] = {}
        self._reset_event_ids: list[int] = []
        self._reported_counts: dict[str, int] = {}
        self._stages: Counter[str] = Counter()
        self._transitions: Counter[str] = Counter()
        self._edges: list[dict] = []
        self._pending_bound: dict[tuple[str, str], dict] = {}
        self._acceptances: dict[str, dict] = {}
        self._irq_starts: dict[tuple[tuple[str, str], tuple[str, str], int], dict] = {}
        self._irq_pulses: dict[tuple[tuple[str, str], tuple[str, str], int], dict] = {}
        self._read_deliveries: dict[tuple[str, int, int], dict] = {}
        self._edge_counts: Counter[str] = Counter()
        self._loop_counts: Counter[str] = Counter()
        self._path_counts: Counter[str] = Counter()
        self._loops: dict[tuple[int, ...], dict] = {}
        self._open_chains: dict[tuple[str, int | None], list[tuple[dict, ...]]] = defaultdict(list)
        self._consumed_by_step: dict[int | None, dict] = {}
        self._verified_writes: list[dict] = []
        self._irq_path_slots: list[dict | None] = []
        self._irq_taken_path_slots: list[dict | None] = []
        self._read_path_slots: list[dict | None] = []
        self._active_irq: dict | None = None
        self._taken_by_start: dict[int, dict] = {}
        self._reported_edge_count = 0
        self._reported_loop_keys: set[tuple[int, ...]] = set()
        self._changed_path_slots: set[tuple[str, int]] = set()
        self._reported_paths: dict[tuple[str, int], dict] = {}

    def ingest(self, events: Iterable[Mapping]) -> None:
        for event in events:
            if not isinstance(event, Mapping):
                raise ValueError("interaction event must be a mapping")
            event_id = _event_id(event)
            if event_id is None:
                raise ValueError("interaction event needs a positive event_id")
            record = (dict(event) if self._event_lookup is not None
                      else deepcopy(dict(event)))
            if self._event_lookup is not None and event_id <= self._starting_event_id:
                if self._event_lookup(event_id) != record:
                    raise ValueError("event_id was reused with different evidence")
                continue
            previous = self._events.get(event_id)
            if previous is not None:
                if previous != record:
                    raise ValueError("event_id was reused with different evidence")
                continue
            if event_id <= self._last_event_id:
                raise ValueError("interaction events must arrive in event order")
            if self._event_lookup is not None:
                if event_id != self._last_event_id + 1:
                    raise ValueError("online interaction events must be contiguous")
                if self._event_lookup(event_id) != record:
                    raise ValueError("online event differs from journal evidence")
            else:
                self._events[event_id] = record
            self._last_event_id = event_id
            self._ingested_count += 1
            if record.get("kind") == "reset_barrier":
                self._epoch += 1
                self._reset_event_ids.append(event_id)
            if self._event_lookup is None:
                self._epoch_by_event_id[event_id] = self._epoch
            self._consume_event(event_id, record)

    def _consume_event(self, event_id: int, event: Mapping) -> None:
        # Process each unique event once. Cumulative prefixes are deduplicated
        # by ingest(), so this preserves the original event-order semantics.
        events = self._events
        stages = self._stages
        transitions = self._transitions
        edges = self._edges
        pending_bound = self._pending_bound
        acceptances = self._acceptances
        irq_starts = self._irq_starts
        irq_pulses = self._irq_pulses
        read_deliveries = self._read_deliveries
        prior_edge_count = len(edges)

        def add_edge(kind: str, source: str, target: str, witness: tuple[int, ...],
                     *, producer_step: int | None = None,
                     consumer_step: int | None = None) -> None:
            edge = {"kind": kind, "source": source, "target": target,
                    "witness_event_ids": list(witness),
                    "producer_step_event_id": producer_step,
                    "consumer_step_event_id": consumer_step}
            metadata = self._witness_provenance(witness, producer_step, consumer_step)
            if metadata is not None:
                edge["provenance"] = metadata
            edges.append(edge)

        kind = event.get("kind")
        if kind == "reset_barrier":
            pending_bound.clear()
            acceptances.clear()
            irq_starts.clear()
            irq_pulses.clear()
            read_deliveries.clear()
            self._active_irq = None
            self._taken_by_start.clear()
            transitions["reset_barrier"] += 1
        elif kind == "source_injection":
            component, port = event.get("component"), event.get("port")
            if isinstance(component, str) and isinstance(port, str):
                stages[f"source_injected:{component}.{port}"] += 1
        elif kind == "dataflow_delivery":
            source, target = _pair(event.get("source")), _pair(event.get("target"))
            producer_id = event.get("producer_event_id")
            producer = events.get(producer_id) if type(producer_id) is int else None
            if (source is not None and target is not None
                    and type(event.get("value")) is int
                    and producer_id is not None and producer_id < event_id
                    and producer is not None
                    and _delivery_matches_output(event, producer, source)):
                pending_bound[target] = event
                stages[f"bound_delivered:{source[0]}:{target[0]}"] += 1
        elif kind == "mmio_acceptance":
            transaction = _identity(event.get("source_transaction"))
            if transaction is not None:
                acceptances[transaction] = event
                stages["mmio_accepted"] += 1
        elif kind == "mmio_delivery":
            transaction = _identity(event.get("source_transaction"))
            accepted = acceptances.get(transaction) if transaction is not None else None
            source_transaction = event.get("source_transaction")
            source = (source_transaction.get("source_component")
                      if isinstance(source_transaction, Mapping) else None)
            target = event.get("device_id")
            if (accepted is not None and accepted["event_id"] < event_id
                    and accepted.get("device_id") == target
                    and accepted.get("write") == event.get("write")
                    and all(accepted.get(field) == event.get(field)
                            for field in ("address", "offset", "beat_bytes",
                                          "byte_enable", "write_value"))
                    and isinstance(source, str) and source
                    and isinstance(target, str) and target):
                if event.get("write") is True:
                    add_edge("mmio_write_delivered", source, target,
                             (accepted["event_id"], event_id),
                             producer_step=accepted.get("producer_event_id"),
                             consumer_step=event.get("producer_event_id"))
                    stages[f"mmio_write_delivered:{source}:{target}"] += 1
                elif event.get("write") is False and type(event.get("read_value")) is int:
                    add_edge("mmio_read_returned", target, source,
                             (accepted["event_id"], event_id),
                             producer_step=event.get("producer_event_id"),
                             consumer_step=accepted.get("producer_event_id"))
                    stages[f"mmio_read_returned:{target}:{source}"] += 1
                    tx = event["source_transaction"]
                    epoch, sequence = tx.get("source_epoch"), tx.get("source_sequence")
                    if type(epoch) is int and type(sequence) is int:
                        read_deliveries[(source, epoch, sequence)] = event
            # One delivery consumes one acceptance. A malformed delivery is
            # evidence of a mismatch, not a retry token for a later event.
            if accepted is not None:
                del acceptances[transaction]
        elif kind == "source_start":
            source, target = _pair(event.get("source")), _pair(event.get("target"))
            occurrence = event.get("source_event_id")
            if source is not None and target is not None and type(occurrence) is int:
                irq_starts[(source, target, occurrence)] = event
                stages[f"irq_started:{source[0]}:{target[0]}"] += 1
        elif kind == "cpu_irq_taken":
            source, target = _pair(event.get("source")), _pair(event.get("target"))
            occurrence = event.get("source_event_id")
            key = (source, target, occurrence)
            start = irq_starts.get(key) if type(occurrence) is int else None
            if start is not None and start["event_id"] < event_id:
                add_edge("irq_taken", source[0], target[0],
                         (start["event_id"], event_id))
                stages[f"irq_taken:{source[0]}:{target[0]}"] += 1
        elif kind == "pulse_start":
            source, target = _pair(event.get("source")), _pair(event.get("target"))
            occurrence = event.get("source_event_id")
            key = (source, target, occurrence)
            start = irq_starts.get(key) if type(occurrence) is int else None
            if (start is not None and start["event_id"] < event_id
                    and type(event.get("start_cpu_tick")) is int
                    and type(event.get("end_cpu_tick_exclusive")) is int
                    and event["start_cpu_tick"] < event["end_cpu_tick_exclusive"]):
                irq_pulses[key] = event
        elif kind == "state_dependency":
            edge_kind = event.get("edge_kind")
            memory_id = event.get("memory_id")
            if (edge_kind in ("RAW", "WAW", "WAR", "PERSIST", "INVALIDATE")
                    and isinstance(memory_id, str) and memory_id
                    and isinstance(event.get("source"), str)
                    and isinstance(event.get("target"), str)):
                transitions[f"memory:{edge_kind}:{memory_id}"] += 1

        # A local step proves delivery consumption. Sliced bindings need
        # explicit source/target offsets and width from the runner; legacy
        # deliveries can establish only an equal complete port value.
        inputs = event.get("inputs")
        component = event.get("component")
        if kind is None and isinstance(component, str) and isinstance(inputs, Mapping):
            tick = event.get("local_tick")
            for key, pulse in tuple(irq_pulses.items()):
                source, target, _ = key
                if (target != (component, "irq") or inputs.get("irq") != 1
                        or type(tick) is not int):
                    continue
                if pulse["start_cpu_tick"] <= tick < pulse["end_cpu_tick_exclusive"]:
                    add_edge("irq_input_sampled", source[0], component,
                             (irq_starts[key]["event_id"], pulse["event_id"], event_id),
                             consumer_step=event_id)
                    stages[f"irq_input_sampled:{source[0]}:{component}"] += 1
                    del irq_pulses[key]
            outputs = event.get("outputs")
            if isinstance(outputs, Mapping) and outputs.get("data_rsp_consumed") == 1:
                epoch, sequence = (outputs.get("data_rsp_source_epoch"),
                                   outputs.get("data_rsp_source_sequence"))
                if type(epoch) is int and type(sequence) is int:
                    delivery = read_deliveries.pop((component, epoch, sequence), None)
                    if (delivery is not None and delivery["event_id"] < event_id
                            and type(outputs.get("data_rsp_rdata")) is int
                            and outputs["data_rsp_rdata"] == delivery["read_value"]):
                        source = delivery["device_id"]
                        add_edge("mmio_read_consumed", source, component,
                                 (delivery["event_id"], event_id),
                                 producer_step=delivery.get("producer_event_id"),
                                 consumer_step=event_id)
                        stages[f"mmio_read_consumed:{source}:{component}"] += 1
            for (target_component, port), delivery in tuple(pending_bound.items()):
                if target_component != component or port not in inputs:
                    continue
                del pending_bound[(target_component, port)]
                if not _delivery_matches_input(delivery, inputs[port]):
                    continue
                source = _pair(delivery["source"])
                producer_id = delivery["producer_event_id"]
                producer = events[producer_id]
                source_step = (producer.get("producer_event_id")
                               if producer.get("kind") == "local_tick_sample"
                               else producer_id)
                if type(source_step) is not int or source_step >= event_id:
                    continue
                add_edge("bound_input_consumed", source[0], component,
                         (producer_id, delivery["event_id"], event_id),
                         producer_step=source_step, consumer_step=event_id)
                stages[f"bound_consumed:{source[0]}:{component}"] += 1

        for edge in edges[prior_edge_count:]:
            self._record_edge(edge)

    def _witness_provenance(self, witness: tuple[int, ...],
                            producer_step: int | None,
                            consumer_step: int | None) -> dict | None:
        """Copy explicit metadata after the existing edge checks succeed.

        Only explicit witness and step IDs are consulted. Consumer metadata
        supplies context/resources, never a producer origin. Transport
        declarations remain candidates, and case never supplies an origin.
        """
        records = {event_id: self._events.get(event_id) for event_id in witness}
        consumer_id = consumer_step if type(consumer_step) is int else witness[-1]
        for context_id in (producer_step, consumer_id):
            if type(context_id) is int and context_id not in records:
                records[context_id] = self._events.get(context_id)
        metadata = {}
        for event_id, record in records.items():
            value = record.get("provenance") if isinstance(record, Mapping) else None
            if (isinstance(value, Mapping)
                    and value.get("schema_version") == "event_source_provenance.v1"):
                metadata[event_id] = value
        if not metadata:
            return None
        origins, candidates, resources = set(), {}, []
        transports = {"dataflow_delivery", "mmio_delivery", "source_start",
                      "pulse_start", "cpu_irq_taken"}
        for event_id in records:
            value = metadata.get(event_id)
            if value is None:
                continue
            refs = value.get("origin_admission_ids")
            if event_id != consumer_step and isinstance(refs, (list, tuple)):
                origins.update(ref for ref in refs if type(ref) is str and ref)
            raw_candidates = value.get("edge_candidates")
            if (event_id in witness and event_id != consumer_step
                    and records[event_id].get("kind") in transports
                    and isinstance(raw_candidates, (list, tuple))):
                for candidate in raw_candidates:
                    identity = _identity(candidate)
                    if identity is not None:
                        candidates.setdefault(identity, deepcopy(dict(candidate)))
            resource = value.get("resource")
            if isinstance(resource, Mapping):
                resources.append({"event_id": event_id, "resource": deepcopy(dict(resource))})
        consumer = metadata.get(consumer_id)
        return {"schema_version": "interaction_edge_provenance.v1",
                "observed_case": deepcopy(consumer.get("observed_case")) if consumer else None,
                "origin_admission_ids": sorted(origins),
                "edge_candidates": list(candidates.values()),
                "resource_snapshots": resources,
                "proof_scope": "witness_metadata_only"}

    def _same_epoch(self, *chain: dict) -> bool:
        epochs = {self._epoch_for_event(event_id)
                  for edge in chain for event_id in edge["witness_event_ids"]}
        return len(epochs) == 1

    def _epoch_for_event(self, event_id: int) -> int:
        if self._event_lookup is not None:
            if type(event_id) is not int or not 1 <= event_id <= self._last_event_id:
                raise KeyError(event_id)
            return bisect_right(self._reset_event_ids, event_id)
        return self._epoch_by_event_id[event_id]

    def _verified_write(self, edge: dict) -> bool:
        accepted_id, delivered_id = edge["witness_event_ids"]
        accepted, delivered = self._events[accepted_id], self._events[delivered_id]
        producer_id, consumer_id = (edge["producer_step_event_id"],
                                    edge["consumer_step_event_id"])
        if type(producer_id) is not int or type(consumer_id) is not int:
            return False
        producer = self._events.get(producer_id)
        consumer = self._events.get(consumer_id)
        outputs = producer.get("outputs") if producer is not None else None
        return (producer is not None and producer.get("kind") is None
                and producer.get("component") == edge["source"]
                and isinstance(outputs, Mapping)
                and outputs.get("data_req_accepted") == 1
                and outputs.get("data_write") == 1
                and outputs.get("data_addr") == accepted.get("address")
                and outputs.get("data_wdata") == accepted.get("write_value")
                and consumer is not None and consumer.get("kind") is None
                and consumer.get("component") == edge["target"]
                and delivered.get("producer_event_id") == consumer.get("event_id"))

    @staticmethod
    def _path(kind: str, components: list[str], chain: tuple[dict, ...]) -> dict:
        witness = list(dict.fromkeys(event_id for edge in chain
                                      for event_id in edge["witness_event_ids"]))
        return {"kind": kind, "components": components,
                "witness_event_ids": witness}

    @staticmethod
    def _path_feature(path: dict) -> str:
        return "observed_path:" + path["kind"] + ":" + ":".join(path["components"])

    def _set_irq_path(self, state: dict) -> None:
        boundary = state.get("end_event_id", self._last_event_id + 1)
        irq = state["edge"]
        result = None
        for read, write in state["reads"]:
            if (read["consumer_step_event_id"] >= boundary or write is None
                    or write["witness_event_ids"][-1] >= boundary):
                continue
            result = self._path("irq_sample_read_then_write",
                                [irq["source"], irq["target"], write["target"]],
                                (irq, read, write))
            break
        slot = state["slot"]
        previous = self._irq_path_slots[slot]
        if result != previous:
            if previous is not None:
                self._path_counts[self._path_feature(previous)] -= 1
            self._irq_path_slots[slot] = result
            if result is not None:
                self._path_counts[self._path_feature(result)] += 1
            self._changed_path_slots.add(("irq", slot))

        # An IRQ input sample proves delivery to the CPU pin, while the
        # controller's taken pulse separately proves architectural acceptance.
        # Keep both path names distinct so callers cannot silently promote a
        # merely sampled IRQ into a taken interrupt.
        taken = self._taken_by_start.get(irq["witness_event_ids"][0])
        accepted = None
        if taken is not None:
            sample_id = irq["witness_event_ids"][-1]
            taken_id = taken["witness_event_ids"][-1]
            for read, write in state["reads"]:
                if (write is None
                        or read["consumer_step_event_id"] >= boundary
                        or write["witness_event_ids"][-1] >= boundary
                        or not sample_id < taken_id < read["witness_event_ids"][0]
                        or not self._same_epoch(irq, taken, read, write)):
                    continue
                accepted = self._path("irq_taken_read_then_write",
                                      [irq["source"], irq["target"], write["target"]],
                                      (irq, taken, read, write))
                break
        previous = self._irq_taken_path_slots[slot]
        if accepted == previous:
            return
        if previous is not None:
            self._path_counts[self._path_feature(previous)] -= 1
        self._irq_taken_path_slots[slot] = accepted
        if accepted is not None:
            self._path_counts[self._path_feature(accepted)] += 1
        self._changed_path_slots.add(("irq_taken", slot))

    def _record_edge(self, edge: dict) -> None:
        kind = edge["kind"]
        self._edge_counts[f"{kind}:{edge['source']}:{edge['target']}"] += 1
        if kind == "bound_input_consumed":
            self._consumed_by_step[edge["consumer_step_event_id"]] = edge
            predecessors = tuple(self._open_chains.get(
                (edge["source"], edge["producer_step_event_id"]), ()))
            chains = [(edge,)]
            chains.extend((*chain, edge) for chain in predecessors
                          if (len(chain) < 4
                              and edge["witness_event_ids"][1]
                              > chain[-1]["consumer_step_event_id"]))
            for chain in chains:
                tail = chain[-1]
                if len(chain) >= 2 and tail["target"] == chain[0]["source"]:
                    witness = tuple(item["witness_event_ids"][1] for item in chain)
                    if witness not in self._loops:
                        loop = {"components": [chain[0]["source"]]
                                + [item["target"] for item in chain],
                                "delivery_event_ids": list(witness)}
                        self._loops[witness] = loop
                        self._loop_counts["closed_loop:" + ":".join(loop["components"])] += 1
                elif len(chain) < 4:
                    self._open_chains[(tail["target"], tail["consumer_step_event_id"])].append(chain)
        elif kind == "irq_input_sampled":
            if self._active_irq is not None:
                self._active_irq["end_event_id"] = edge["witness_event_ids"][0]
                self._set_irq_path(self._active_irq)
            slot = len(self._irq_path_slots)
            self._irq_path_slots.append(None)
            self._irq_taken_path_slots.append(None)
            self._active_irq = {"edge": edge, "reads": [], "slot": slot}
        elif kind == "irq_taken":
            start_id = edge["witness_event_ids"][0]
            self._taken_by_start[start_id] = edge
            state = self._active_irq
            if (state is not None
                    and state["edge"]["witness_event_ids"][0] == start_id):
                self._set_irq_path(state)
        elif kind == "mmio_write_delivered":
            if not self._verified_write(edge):
                return
            self._verified_writes.append(edge)
            state = self._active_irq
            if state is None:
                return
            irq = state["edge"]
            delivered = self._events[edge["witness_event_ids"][-1]]
            for candidate in state["reads"]:
                read, matched = candidate
                if matched is not None or not self._same_epoch(irq, read, edge):
                    continue
                read_delivery = self._events[read["witness_event_ids"][0]]
                if (edge["source"] == irq["target"]
                        and read["consumer_step_event_id"] < edge["producer_step_event_id"]
                        and delivered.get("offset") == 0x0c
                        and delivered.get("write_value")
                        == read_delivery.get("read_value", -1) >> 8):
                    candidate[1] = edge
            self._set_irq_path(state)
        elif kind == "mmio_read_consumed":
            read_delivery = self._events[edge["witness_event_ids"][0]]
            state = self._active_irq
            if state is not None:
                irq = state["edge"]
                if (edge["source"] == irq["source"]
                        and edge["target"] == irq["target"]
                        and irq["consumer_step_event_id"] < edge["consumer_step_event_id"]
                        and read_delivery.get("offset") == 8
                        and self._same_epoch(irq, edge)):
                    state["reads"].append([edge, None])
            bound = self._consumed_by_step.get(edge["producer_step_event_id"])
            if (bound is None or bound["target"] != edge["source"]
                    or not self._same_epoch(bound, edge)
                    or bound["consumer_step_event_id"] >= edge["witness_event_ids"][0]):
                return
            bound_delivery = self._events[bound["witness_event_ids"][1]]
            if (read_delivery.get("offset") != 8
                    or type(read_delivery.get("read_value")) is not int
                    or read_delivery["read_value"] & 0xff != bound_delivery.get("value")):
                return
            for write in reversed(self._verified_writes):
                delivered = self._events[write["witness_event_ids"][-1]]
                if (write["target"] == bound["source"]
                        and self._same_epoch(write, bound, edge)
                        and write["consumer_step_event_id"] is not None
                        and write["consumer_step_event_id"] <= bound["producer_step_event_id"]
                        and write["witness_event_ids"][-1] < bound["witness_event_ids"][1]
                        and delivered.get("offset") == 0x0c
                        and (delivered.get("write_value", -1) & 0xff)
                        == bound_delivery.get("value")):
                    path = self._path("write_bound_then_read",
                                      [write["source"], write["target"],
                                       bound["target"], edge["target"]],
                                      (write, bound, edge))
                    slot = len(self._read_path_slots)
                    self._read_path_slots.append(path)
                    self._path_counts[self._path_feature(path)] += 1
                    self._changed_path_slots.add(("read", slot))
                    break


    def _feature_counts(self) -> dict[str, int]:
        return dict(sorted((self._stages + self._transitions + self._edge_counts
                            + self._loop_counts + self._path_counts).items()))

    def summary(self) -> dict:
        """Return the complete historical report from incrementally kept indexes."""
        paths = [path for path in (*self._irq_path_slots,
                                  *self._irq_taken_path_slots,
                                  *self._read_path_slots)
                 if path is not None]
        return {"schema_version": "interaction_feedback.v1",
                "event_count": len(self._events),
                "stages": dict(sorted(self._stages.items())),
                "edges": deepcopy(self._edges),
                "edge_counts": dict(sorted(self._edge_counts.items())),
                "state_transitions": dict(sorted(self._transitions.items())),
                "closed_loops": deepcopy([self._loops[key] for key in sorted(self._loops)]),
                "observed_paths": deepcopy(paths),
                "path_counts": dict(sorted((key, value)
                                           for key, value in self._path_counts.items()
                                           if value > 0)),
                "feature_counts": self._feature_counts()}

    def incremental_summary(self) -> dict:
        """Return new witnesses and accumulated feature counts without history scans.

        ``edges`` and ``observed_paths`` are the suffix since the previous
        call. ``summary()`` remains the complete historical report. A path
        withdrawn by a later reset/IRQ boundary appears in
        ``removed_observed_paths``.
        """
        counts = self._feature_counts()
        feature_deltas = {
            name: count - self._reported_counts.get(name, 0)
            for name, count in counts.items()
            if count > self._reported_counts.get(name, 0)}
        new_features = sorted(set(counts) - set(self._reported_counts))
        delta_edges = deepcopy(self._edges[self._reported_edge_count:])
        self._reported_edge_count = len(self._edges)
        new_loop_keys = sorted(set(self._loops) - self._reported_loop_keys)
        delta_loops = deepcopy([self._loops[key] for key in new_loop_keys])
        self._reported_loop_keys.update(new_loop_keys)
        delta_paths: list[dict] = []
        removed_paths: list[dict] = []
        for key in sorted(self._changed_path_slots):
            kind, index = key
            path = (self._irq_path_slots[index] if kind == "irq" else
                    self._irq_taken_path_slots[index] if kind == "irq_taken" else
                    self._read_path_slots[index])
            previous = self._reported_paths.get(key)
            if previous == path:
                continue
            if previous is not None:
                removed_paths.append(deepcopy(previous))
            if path is not None:
                delta_paths.append(deepcopy(path))
                self._reported_paths[key] = deepcopy(path)
            else:
                self._reported_paths.pop(key, None)
        self._changed_path_slots.clear()
        self._reported_counts = dict(counts)
        return {"schema_version": "interaction_feedback.v1",
                "event_count": len(self._events),
                "stages": dict(sorted(self._stages.items())),
                "edges": delta_edges,
                "delta_edges": delta_edges,
                "edge_counts": dict(sorted(self._edge_counts.items())),
                "state_transitions": dict(sorted(self._transitions.items())),
                "closed_loops": delta_loops,
                "delta_closed_loops": delta_loops,
                "observed_paths": delta_paths,
                "delta_observed_paths": delta_paths,
                "removed_observed_paths": removed_paths,
                "path_counts": dict(sorted((key, value)
                                           for key, value in self._path_counts.items()
                                           if value > 0)),
                "feature_counts": counts,
                "feature_deltas": feature_deltas,
                "new_features": new_features}

    def novelty_weights(self, desired: Mapping[str, Iterable[str]], *,
                        unseen: int = 64, seen: int = 8) -> dict[str, int]:
        """Score caller-supplied target/path/source IDs by observed features.

        The caller owns the mapping from a candidate ID to required stage,
        edge, state, or loop feature IDs. Unknown features receive more energy.
        """
        if (type(unseen) is not int or type(seen) is not int
                or unseen < 0 or seen < 0):
            raise ValueError("novelty weights must be nonnegative integers")
        counts = self._feature_counts()
        result: dict[str, int] = {}
        for candidate, features in desired.items():
            if not isinstance(candidate, str) or not candidate:
                raise ValueError("candidate ID must be a nonempty string")
            names = tuple(features)
            if any(not isinstance(name, str) or not name for name in names):
                raise ValueError("feature IDs must be nonempty strings")
            result[candidate] = sum(seen if counts.get(name, 0) else unseen
                                    for name in names)
        return dict(sorted(result.items()))


def summarize_interactions(events: Iterable[Mapping]) -> dict:
    """Return a stable, JSON-ready summary for one complete event prefix."""
    feedback = InteractionFeedback()
    feedback.ingest(events)
    return feedback.summary()
