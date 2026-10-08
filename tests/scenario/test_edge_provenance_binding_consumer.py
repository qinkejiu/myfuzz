"""Target-side data-binding consumption: the hop must cite the exact delivery.

``direct_binding`` only used to accept interrupt/source consumer shapes
(``cpu_irq_input``/``cpu_irq_taken``/``source_start``/...), so a wide *data*
binding such as ``gpio_a.gpio_out -> gpio_b.gpio_in`` could never certify its
consumer hop: the target's own input observation is not an interrupt record.

This module pins the data consumer path: the target side's own recorded input
observation -- an authenticated ``gpio_tick_observation`` or an applied-input
record (``gpio_input_applied``/``gpio_input_segment_applied``) -- cites the
delivered transport by its exact ``delivery_event_id`` plus the declared source
endpoint/bit offset, and its per-bit rows reconstruct the declared target
window exactly. The cited delivery must itself be a ``dataflow_delivery`` of
this declared edge whose own ``producer_event_id`` names the driver record the
consumer's value came from, so the certificate names the one chain the target
actually cited (producer, delivery and consumer move onto it together).

Negative rules pinned here, each on its own journal:

* a differing consumed value (and a target input whose measured window differs)
  leaves the consumer hop missing;
* a window at the wrong bit offset/width, an inconsistent per-bit source offset,
  and a row value wider than its own width are all refused;
* an observation that merely *follows* the delivery in time -- adjacent, with no
  citation -- is never joined;
* a citation of another declared edge's delivery, of a non-resolving event id,
  and of a record that is not a delivery at all are all refused;
* a tick whose pre/post probe contract is not authenticated (wrong contract, or
  a derived signal that contradicts the measured transition) is not evidence;
* a cited delivery whose own driver record observed a different value is not a
  chain, so neither the delivery nor the consumer hop is credited.

The same journals also pin that the MMIO route, the IRQ binding and the
persistent resource version keep their existing hop semantics, that the row
scan stays bounded, and -- on the frozen real traces -- that every conclusion
already reported for the nine declared edges is unchanged while the data
binding's consumer hop moves onto the exact chain the target cited.
"""

from __future__ import annotations

import functools
import json
from pathlib import Path

import pytest

from myfuzz.local_harness.pulp_gpio_probe_contract import (
    PULP_GPIO_PROBES,
    pulp_gpio_observation_contract,
)
from myfuzz.scenario.acceptance_metrics import TraceEventStream
from myfuzz.scenario.edge_provenance import (
    CERTIFIED,
    CONSUMER,
    DELIVERY,
    EDGE_PROVENANCE_SCHEMA,
    PRODUCER,
    EdgeEndpoints,
    EdgeProvenanceConsumer,
    edge_provenance_report,
    edge_provenance_session,
)
from myfuzz.scenario.runtime_path_contract import (
    RuntimeEdgeContract,
    RuntimeNode,
    RuntimePathContract,
)

ROOT = Path(__file__).resolve().parents[2]
STREAMED_RUN = ROOT / "runs/current-dataflow-p5-streamed-short-20261007-online"
PAIRED_RUN = ROOT / "runs/current-dataflow-p5-paired-20261007-online"
P3_RUN = ROOT / "runs/p3-slot-policy-20261007-online"

GRAPH_SHA256 = "58471d1e3c55652b4570cbdc2a782c060c9ac21427830be22a9ec4a9ce8a48ac"

BINDING_KEY = (2, 0)
IRQ_KEY = (4, 0)
MMIO_KEY = (5, 0)
OTHER_KEY = (6, 0)
RESOURCE_KEY = (9, 0)

#: First record of every journal; later records name it so a driver's
#: ``producer_event_id`` always resolves inside the stream.
BOOTSTRAP = 1

SOURCE = ("dev_a", "out")
TARGET = ("dev_b", "in")
IRQ_SOURCE = ("irq_src", "irq")
IRQ_TARGET = ("irq_target", "irq")
OTHER_SOURCE = ("dev_c", "out")
OTHER_TARGET = ("dev_d", "in")

DELIVERED = 0x5A


# --------------------------------------------------------------------- fixture


def _resolve(value, ids):
    if isinstance(value, str) and value.startswith("@"):
        name, _, delta = value[1:].partition("+")
        assert name in ids, name
        return ids[name] + (int(delta) if delta else 0)
    if isinstance(value, dict):
        return {key: _resolve(item, ids) for key, item in value.items()}
    if isinstance(value, list):
        return [_resolve(item, ids) for item in value]
    return value


class _Journal:
    """Ordered synthetic journal with contiguously assigned event ids."""

    def __init__(self):
        self._rows = []
        self._built = None

    def add(self, name, event):
        self._rows.append([name, dict(event)])
        self._built = None
        return self

    def ref(self, name):
        return "@" + name

    def index(self, name):
        for position, row in enumerate(self._rows):
            if row[0] == name:
                return position
        raise KeyError(name)

    def _build(self):
        if self._built is None:
            ids = {}
            for position, row in enumerate(self._rows):
                assert row[0] not in ids, row[0]
                ids[row[0]] = position + 1
            events = [_resolve({**row[1], "event_id": position + 1}, ids)
                      for position, row in enumerate(self._rows)]
            self._built = (events, ids)
        return self._built

    @property
    def events(self):
        return self._build()[0]

    @property
    def ids(self):
        return self._build()[1]


def _transaction(sequence, *, component="dev_b"):
    return {"channel_id": "data", "execution_id": "local-execution",
            "source_component": component, "source_epoch": 0,
            "source_sequence": sequence, "testcase_id": "synthetic"}


def _provenance(*candidates):
    return {"schema_version": "event_source_provenance.v1",
            "observed_case": {"case_id": "case-1", "case_index": 1},
            "origin_status": "unknown", "origin_admission_ids": [],
            "invalid_origin_references": 0, "unknown_writer_ids": [],
            "edge_candidates": [{"rule_index": key[0], "prerequisite_index": key[1]}
                                for key in candidates],
            "resource": None, "proof_scope": "observation_only"}


def _endpoint_node(name, component, port, bit_offset, width):
    return RuntimeNode(name, component, "physical", port=port,
                       bit_offset=bit_offset, width=width)


def _contract():
    nodes = (
        _endpoint_node("dev_a.out", "dev_a", "out", 0, 8),
        _endpoint_node("dev_b.in", "dev_b", "in", 0, 8),
        _endpoint_node("dev_c.out", "dev_c", "out", 0, 8),
        _endpoint_node("dev_d.in", "dev_d", "in", 0, 8),
        _endpoint_node("irq_src.irq", "irq_src", "irq", 0, 1),
        _endpoint_node("irq_target.irq", "irq_target", "irq", 0, 1),
        RuntimeNode("cpu.mmio", "cpu", "logical"),
        RuntimeNode("dev_b.ram", "dev_b", "state"),
        RuntimeNode("ram.bytes", "ram", "state"),
    )
    edges = (
        RuntimeEdgeContract(*BINDING_KEY, relation="direct_binding"),
        RuntimeEdgeContract(*IRQ_KEY, relation="direct_binding"),
        RuntimeEdgeContract(*MMIO_KEY, relation="mmio_route", initiator_component="cpu",
                            device_id="dev_b", base=0x40000000, size=0x1000),
        RuntimeEdgeContract(*OTHER_KEY, relation="direct_binding"),
        RuntimeEdgeContract(*RESOURCE_KEY, relation="persistent_state",
                            resource_component="ram", resource_id="buffer"),
    )
    return RuntimePathContract(GRAPH_SHA256, nodes, edges)


def _endpoints():
    return {
        BINDING_KEY: EdgeEndpoints(_endpoint_node("dev_a.out", "dev_a", "out", 0, 8),
                                   _endpoint_node("dev_b.in", "dev_b", "in", 0, 8)),
        IRQ_KEY: EdgeEndpoints(_endpoint_node("irq_src.irq", "irq_src", "irq", 0, 1),
                               _endpoint_node("irq_target.irq", "irq_target", "irq", 0, 1)),
        MMIO_KEY: EdgeEndpoints(_endpoint_node("cpu.mmio", "cpu", "mmio", 0, 0x1000),
                                _endpoint_node("dev_b.mmio", "dev_b", "mmio", 0, 0x1000)),
        OTHER_KEY: EdgeEndpoints(_endpoint_node("dev_c.out", "dev_c", "out", 0, 8),
                                 _endpoint_node("dev_d.in", "dev_d", "in", 0, 8)),
        RESOURCE_KEY: EdgeEndpoints(
            _endpoint_node("ram.bytes", "ram", "buffer", 0, 1),
            _endpoint_node("ram.bytes", "ram", "buffer", 0, 1)),
    }


# --------------------------------------------------------- target observation


def _probe_document(*, gpio_in=0):
    """All-zero authenticated probe pair with the measured ``gpio_in``.

    Every derived signal of an all-zero probe document is zero: no rise, no
    fall, no trigger mask, no bank write, no synchronizer enable, so the static
    pre/post document satisfies the same contract a measured idle tick does.
    """
    document = {"gpio_in": gpio_in, "gpio_out": 0, "gpio_dir": 0, "gpio_in_sync": 0,
                "gpio_padcfg": "0" * 32}
    for name in PULP_GPIO_PROBES:
        document["gpio_probe_" + name] = 0
    document["gpio_probe_pready"] = 1
    return document


def _rows(*, delivery="@delivery", value=DELIVERED, width=8, bit=0, source=SOURCE,
          kind="binding", origin_extra=None):
    """One per-bit input-context row set citing ``delivery`` exactly."""
    rows = []
    for index in range(width):
        origin = {"kind": kind, "source_component": source[0], "source_port": source[1],
                  "source_bit_lo": bit + index, "producer_local_tick": 3,
                  "producer_phase": "post", "producer_reset_epoch": 0,
                  "producer_resource_refs": []}
        if delivery is not None:
            origin["delivery_event_id"] = delivery
        if origin_extra is not None:
            origin.update(origin_extra)
        rows.append({"bit_lo": bit + index, "width": 1,
                     "value": (value >> index) & 1, "origin": origin})
    return rows


def _sample_tick(journal, name, *, component, port, value, tick, candidates=()):
    return journal.add(name, {
        "kind": "local_tick_sample", "component": component, "local_tick": tick,
        "phase": "post", "producer_event_id": BOOTSTRAP,
        "outputs": {port: value, "physical": value, "irq": value},
        "provenance": _provenance(*candidates)})


def _binding_tick(journal, name, *, component, rows, measured, tick=3,
                  authenticated=True, probe_mutation=None, producer="@tick_b"):
    post = _probe_document(gpio_in=measured)
    if probe_mutation is not None:
        probe_mutation(post)
    event = {
        "kind": "gpio_tick_observation", "component": component, "local_tick": tick,
        "reset_epoch": 0, "source_epoch": 0,
        "observation_contract": (pulp_gpio_observation_contract() if authenticated
                                 else {"schema_version": "unauthenticated.v1"}),
        "pre": _probe_document(gpio_in=0), "post": post,
        "active_input_context": {"segments": rows},
        "provenance": _provenance()}
    if producer is not None:
        event["producer_event_id"] = producer
    return journal.add(name, event)


def _build_journal(*, driver_value=DELIVERED, delivery_value=None, consumer_rows=None,
                   measured=None, authenticated=True, consumer_kind="tick",
                   consumer_component="dev_b", probe_mutation=None):
    """Bootstrap + driver + delivery + one target-side observation.

    The driver record carries **no** edge candidate of its own (the real trace's
    sampled ticks do not), so the delivery's own candidate and its
    ``producer_event_id`` are what attribute the driver record to the declared
    edge.
    """
    journal = _Journal()
    journal.add("bootstrap", {
        "kind": "local_tick_sample", "component": "cpu", "local_tick": 1,
        "phase": "post", "producer_event_id": BOOTSTRAP, "outputs": {},
        "provenance": _provenance()})
    delivered = driver_value if delivery_value is None else delivery_value
    _sample_tick(journal, "driver", component="dev_a", port="out",
                 value=driver_value, tick=3)
    journal.add("delivery", {
        "kind": "dataflow_delivery", "producer_event_id": journal.ref("driver"),
        "source": list(SOURCE), "source_bit_offset": 0,
        "target": list(TARGET), "target_bit_offset": 0, "width": 8,
        "value": delivered, "target_value": delivered,
        "provenance": _provenance(BINDING_KEY)})
    journal.add("tick_b", {
        "kind": "local_tick_sample", "component": "dev_b", "local_tick": 3,
        "phase": "post", "producer_event_id": BOOTSTRAP, "outputs": {},
        "provenance": _provenance()})
    rows = _rows(value=delivered) if consumer_rows is None else consumer_rows
    observed = delivered if measured is None else measured
    if consumer_kind is None:
        return journal
    if consumer_kind == "tick":
        _binding_tick(journal, "consumer", component=consumer_component, rows=rows,
                      measured=observed, authenticated=authenticated,
                      probe_mutation=probe_mutation, producer=journal.ref("tick_b"))
    else:
        journal.add("consumer", {
            "kind": consumer_kind, "component": consumer_component, "status": "observed",
            "port": TARGET[1], "local_tick": 3,
            "producer_event_id": journal.ref("tick_b"),
            "requested_input_value": observed, "actual_input_value": observed,
            "segments": rows, "provenance": _provenance()})
    return journal


def _by_key(report):
    return {(row["rule_index"], row["prerequisite_index"]): row for row in report["edges"]}


def _hop(row, hop_id):
    for hop in row["hops"]:
        if hop["hop_id"] == hop_id:
            return hop
    return None


def _hops(row):
    return [hop["hop_id"] for hop in row["hops"]]


def _consume(events, *, contract=None, endpoints=None, **kwargs):
    consumer = EdgeProvenanceConsumer(contract or _contract(),
                                      endpoints=endpoints if endpoints is not None
                                      else _endpoints(), **kwargs)
    certificates = consumer.ingest(list(events))
    return consumer, certificates, consumer.report()


# ------------------------------------------------------------------ positives


def test_target_input_citation_certifies_the_data_binding():
    """driver -> delivery -> target observation citing that exact delivery."""
    journal = _build_journal()
    ids = journal.ids
    consumer, certificates, report = _consume(journal.events)
    row = _by_key(report)[BINDING_KEY]
    assert row["status"] == "certified"
    assert row["missing"] == []
    assert row["reason"] is None
    assert _hops(row) == [PRODUCER, DELIVERY, CONSUMER]
    assert [hop["event_id"] for hop in row["hops"]] == [
        ids["driver"], ids["delivery"], ids["consumer"]]
    assert _hop(row, PRODUCER)["value"] == DELIVERED
    assert _hop(row, PRODUCER)["key"] == "endpoint_output"
    assert _hop(row, DELIVERY)["value"] == DELIVERED
    assert _hop(row, DELIVERY)["chain"] == {"producer_event_id": ids["driver"]}
    consumer_hop = _hop(row, CONSUMER)
    assert consumer_hop["value"] == DELIVERED
    assert consumer_hop["delivery_event_id"] == ids["delivery"]
    assert consumer_hop["driver_event_id"] == ids["driver"]
    assert consumer_hop["delivery_value"] == DELIVERED
    assert consumer_hop["explicit_delivery_reference"] is True
    assert consumer_hop["segments"] == 8
    assert row["references"]["delivery_event_id"] == ids["delivery"]
    assert row["references"]["producer_event_id"] == ids["driver"]
    assert report["counts"]["rejected"] == 0
    assert report["counts"]["certified"] == 1
    assert json.loads(json.dumps(report))["edges"] == report["edges"]
    assert any(certificate["schema_version"] == EDGE_PROVENANCE_SCHEMA and
               certificate["status"] == CERTIFIED and certificate["missing"] == []
               for certificate in certificates)


def test_applied_input_record_certifies_the_data_binding():
    """The applied-input record shape carries the same exact citation."""
    for kind in ("gpio_input_applied", "gpio_input_segment_applied"):
        journal = _build_journal(consumer_kind=kind)
        ids = journal.ids
        _consumer, _certificates, report = _consume(journal.events)
        row = _by_key(report)[BINDING_KEY]
        assert row["status"] == "certified", kind
        assert _hop(row, CONSUMER)["delivery_event_id"] == ids["delivery"]
        assert _hop(row, CONSUMER)["value"] == DELIVERED
        assert _hop(row, CONSUMER)["observation"] == kind


def test_certificate_names_the_chain_the_target_cited():
    """A later delivery of the same tick is the chain the target joined.

    The consumer cites the *second* delivery; the certificate must move the
    producer and delivery hops onto that cited chain instead of keeping the
    first delivery the journal happened to observe.
    """
    journal = _Journal()
    journal.add("bootstrap", {
        "kind": "local_tick_sample", "component": "cpu", "local_tick": 1,
        "phase": "post", "producer_event_id": BOOTSTRAP, "outputs": {},
        "provenance": _provenance()})
    for index, value in enumerate((0x01, DELIVERED)):
        _sample_tick(journal, f"driver_{index}", component="dev_a", port="out",
                     value=value, tick=3)
        journal.add(f"delivery_{index}", {
            "kind": "dataflow_delivery",
            "producer_event_id": journal.ref(f"driver_{index}"),
            "source": list(SOURCE), "source_bit_offset": 0,
            "target": list(TARGET), "target_bit_offset": 0, "width": 8,
            "value": value, "target_value": value,
            "provenance": _provenance(BINDING_KEY)})
    journal.add("tick_b", {
        "kind": "local_tick_sample", "component": "dev_b", "local_tick": 3,
        "phase": "post", "producer_event_id": BOOTSTRAP, "outputs": {},
        "provenance": _provenance()})
    _binding_tick(journal, "consumer", component="dev_b",
                  rows=_rows(delivery=journal.ref("delivery_1"), value=DELIVERED),
                  measured=DELIVERED, producer=journal.ref("tick_b"))
    ids = journal.ids
    _consumer, _certificates, report = _consume(journal.events)
    row = _by_key(report)[BINDING_KEY]
    assert row["status"] == "certified"
    assert [hop["event_id"] for hop in row["hops"]] == [
        ids["driver_1"], ids["delivery_1"], ids["consumer"]]
    assert _hop(row, DELIVERY)["value"] == DELIVERED
    assert _hop(row, PRODUCER)["value"] == DELIVERED
    assert _hop(row, CONSUMER)["delivery_event_id"] == ids["delivery_1"]


# ------------------------------------------------------------------ negatives


def test_adjacent_observation_without_a_citation_is_never_joined():
    """Time adjacency is not evidence: no ``delivery_event_id``, no hop."""
    journal = _build_journal(consumer_rows=_rows(delivery=None, kind="source_admission"))
    _consumer, _certificates, report = _consume(journal.events)
    row = _by_key(report)[BINDING_KEY]
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]
    assert _hops(row) == [PRODUCER, DELIVERY]
    assert row["proof_scope"] == "partial_journal_observation"


def test_consumed_value_must_equal_the_delivery_value():
    rows = _rows(value=DELIVERED)
    rows[0]["value"] ^= 1
    journal = _build_journal(consumer_rows=rows, measured=DELIVERED)
    _consumer, _certificates, report = _consume(journal.events)
    row = _by_key(report)[BINDING_KEY]
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]
    assert CONSUMER not in _hops(row)


def test_measured_target_window_must_agree_with_the_cited_rows():
    """The target's own measured input is part of the value join."""
    journal = _build_journal(measured=DELIVERED ^ 0x01)
    _consumer, _certificates, report = _consume(journal.events)
    row = _by_key(report)[BINDING_KEY]
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]


def test_consumed_window_must_match_the_declared_bit_offset_and_width():
    """A window shifted out of the declared target range is not the edge."""
    rows = _rows(value=DELIVERED, width=8, bit=1)
    journal = _build_journal(consumer_rows=rows, measured=DELIVERED << 1)
    _consumer, _certificates, report = _consume(journal.events)
    row = _by_key(report)[BINDING_KEY]
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]


def test_inconsistent_per_bit_source_offset_is_refused():
    """``source_bit_lo`` must keep the declared source/target bit relation."""
    rows = _rows(value=DELIVERED)
    for row in rows:
        row["origin"]["source_bit_lo"] += 1
    journal = _build_journal(consumer_rows=rows)
    _consumer, _certificates, report = _consume(journal.events)
    row = _by_key(report)[BINDING_KEY]
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]


def test_row_value_wider_than_its_own_width_is_refused():
    rows = _rows(value=DELIVERED)
    rows[3]["width"] = 1
    rows[3]["value"] = 0b11
    journal = _build_journal(consumer_rows=rows)
    _consumer, _certificates, report = _consume(journal.events)
    row = _by_key(report)[BINDING_KEY]
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]


def test_overlapping_rows_cannot_cover_the_declared_window_twice():
    rows = _rows(value=DELIVERED)
    rows.append(dict(rows[0]))
    journal = _build_journal(consumer_rows=rows)
    _consumer, _certificates, report = _consume(journal.events)
    row = _by_key(report)[BINDING_KEY]
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]


def test_citation_of_another_declared_edges_delivery_is_refused():
    """A delivery of the other declared binding is not this edge's transport."""
    journal = _build_journal(consumer_kind=None)
    journal.add("other_driver", {
        "kind": "local_tick_sample", "component": "dev_c", "local_tick": 4,
        "phase": "post", "producer_event_id": BOOTSTRAP,
        "outputs": {"out": 0x11}, "provenance": _provenance(OTHER_KEY)})
    journal.add("other_delivery", {
        "kind": "dataflow_delivery", "producer_event_id": journal.ref("other_driver"),
        "source": list(OTHER_SOURCE), "source_bit_offset": 0,
        "target": list(OTHER_TARGET), "target_bit_offset": 0, "width": 8,
        "value": 0x11, "target_value": 0x11,
        "provenance": _provenance(OTHER_KEY)})
    journal.add("stray_tick", {
        "kind": "gpio_tick_observation", "component": "dev_b", "local_tick": 5,
        "reset_epoch": 0, "source_epoch": 0,
        "observation_contract": pulp_gpio_observation_contract(),
        "pre": _probe_document(gpio_in=0), "post": _probe_document(gpio_in=0x11),
        "active_input_context": {
            "segments": _rows(delivery=journal.ref("other_delivery"), value=0x11)},
        "provenance": _provenance()})
    _consumer, _certificates, report = _consume(journal.events)
    rows = _by_key(report)
    assert rows[BINDING_KEY]["status"] == "incomplete"
    assert rows[BINDING_KEY]["missing"] == [CONSUMER]
    assert rows[OTHER_KEY]["status"] == "incomplete"


def test_citation_of_a_non_resolving_id_is_refused():
    forged = 4096
    journal = _build_journal(consumer_rows=_rows(delivery=forged))
    _consumer, _certificates, report = _consume(journal.events)
    row = _by_key(report)[BINDING_KEY]
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]


def test_citation_of_a_non_delivery_record_is_refused():
    """The driver record is a real event id, but it is not a delivery."""
    journal = _build_journal(consumer_rows=_rows(delivery="@driver"))
    _consumer, _certificates, report = _consume(journal.events)
    row = _by_key(report)[BINDING_KEY]
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]


def test_unauthenticated_tick_observation_is_not_evidence():
    """A tick whose pre/post contract is not authenticated cannot certify."""
    journal = _build_journal(authenticated=False)
    _consumer, _certificates, report = _consume(journal.events)
    row = _by_key(report)[BINDING_KEY]
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]


def test_tick_with_contradicting_derived_probe_is_not_evidence():
    """A measured rise that the recorded sync/padin state denies is refused."""
    journal = _build_journal(probe_mutation=lambda post: post.update(
        {"gpio_probe_rise": 1, "gpio_probe_irq_trigger_mask": 1}))
    _consumer, _certificates, report = _consume(journal.events)
    row = _by_key(report)[BINDING_KEY]
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]


def test_cited_delivery_whose_driver_value_disagrees_never_certifies():
    """The cited chain must be internally exact, not just endpoint-correct."""
    journal = _build_journal(driver_value=DELIVERED ^ 1, delivery_value=DELIVERED)
    _consumer, _certificates, report = _consume(journal.events)
    row = _by_key(report)[BINDING_KEY]
    assert row["status"] == "incomplete"
    assert row["missing"] == [DELIVERY, CONSUMER]


def test_applied_input_value_must_agree_with_the_cited_rows():
    journal = _build_journal(consumer_kind="gpio_input_applied", measured=DELIVERED ^ 1)
    _consumer, _certificates, report = _consume(journal.events)
    row = _by_key(report)[BINDING_KEY]
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]


def test_consumer_from_the_wrong_component_cannot_join():
    journal = _build_journal(consumer_component="dev_d")
    _consumer, _certificates, report = _consume(journal.events)
    row = _by_key(report)[BINDING_KEY]
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]


# ------------------------------------------------- preserved edge semantics


def _full_journal():
    """The data binding plus one certified route, IRQ binding and RAM version."""
    journal = _build_journal()
    journal.add("mmio_acceptance", {
        "kind": "mmio_acceptance", "component": "cpu", "device_id": "dev_b",
        "address": 0x40000004, "offset": 4, "beat_bytes": 4, "byte_enable": 15,
        "write": True, "write_value": DELIVERED, "acceptance_order": 1,
        "source_sequence": 1, "source_transaction": _transaction(1, component="cpu"),
        "producer_event_id": BOOTSTRAP, "provenance": _provenance(MMIO_KEY)})
    journal.add("mmio_delivery", {
        "kind": "mmio_delivery", "component": "cpu", "device_id": "dev_b",
        "address": 0x40000004, "offset": 4, "beat_bytes": 4, "byte_enable": 15,
        "write": True, "write_value": DELIVERED, "delivery_order": 1,
        "target_delivery_order": 1, "read_value": None,
        "source_sequence": 1, "source_transaction": _transaction(1, component="cpu"),
        "producer_event_id": BOOTSTRAP, "provenance": _provenance(MMIO_KEY)})
    _sample_tick(journal, "irq_driver", component="irq_src", port="irq",
                 value=1, tick=4, candidates=(IRQ_KEY,))
    journal.add("irq_delivery", {
        "kind": "dataflow_delivery", "producer_event_id": journal.ref("irq_driver"),
        "source": list(IRQ_SOURCE), "source_bit_offset": 0,
        "target": list(IRQ_TARGET), "target_bit_offset": 0, "width": 1,
        "value": 1, "target_value": 1, "provenance": _provenance(IRQ_KEY)})
    journal.add("irq_consumer", {
        "kind": "cpu_irq_input", "cpu_step_event_id": BOOTSTRAP, "cpu_tick": 4,
        "source": list(IRQ_SOURCE), "source_bit_offset": 0,
        "target": list(IRQ_TARGET), "target_bit_offset": 0, "width": 1,
        "value": 1, "source_event_id": journal.ref("irq_delivery"),
        "provenance": _provenance(IRQ_KEY)})
    journal.add("ram_write", {
        "kind": "memory_write", "component": "ram", "memory_id": "buffer",
        "address": 0x2000, "byte_offset": 32, "width_bytes": 4, "byte_enable": 15,
        "generation": 0, "version": [0, 4], "value": 0x11,
        "transaction": _transaction(4), "producer_event_id": BOOTSTRAP,
        "provenance": _provenance(RESOURCE_KEY)})
    journal.add("ram_read", {
        "kind": "memory_read", "component": "ram", "memory_id": "buffer",
        "address": 0x2000, "byte_offset": 32, "width_bytes": 4,
        "generation": 0, "versions": [[0, 4]] * 4,
        "writer_event_ids": [journal.ref("ram_write")] * 4,
        "writer_kinds": ["RAM"] * 4, "value": 0x11,
        "transaction": _transaction(5), "producer_event_id": BOOTSTRAP,
        "provenance": _provenance(RESOURCE_KEY)})
    return journal


def test_mmio_route_and_irq_binding_keep_their_hop_semantics():
    journal = _full_journal()
    ids = journal.ids
    _consumer, _certificates, report = _consume(journal.events)
    rows = _by_key(report)
    assert rows[BINDING_KEY]["status"] == "certified"
    mmio = rows[MMIO_KEY]
    assert mmio["status"] == "certified"
    assert _hops(mmio) == [PRODUCER, DELIVERY]
    assert [hop["event_id"] for hop in mmio["hops"]] == [
        ids["mmio_acceptance"], ids["mmio_delivery"]]
    assert _hop(mmio, PRODUCER)["transaction"] == _hop(mmio, DELIVERY)["transaction"]
    irq = rows[IRQ_KEY]
    assert irq["status"] == "certified"
    assert _hops(irq) == [PRODUCER, DELIVERY, CONSUMER]
    assert [hop["event_id"] for hop in irq["hops"]] == [
        ids["irq_driver"], ids["irq_delivery"], ids["irq_consumer"]]
    assert _hop(irq, CONSUMER)["key"] == "source_event_id+endpoint+value"
    assert _hop(irq, CONSUMER)["value"] == 1
    assert report["counts"] == {"total": 5, "certified": 4, "incomplete": 0,
                                "unknown": 1, "rejected": 0, "evicted": 0}


def test_persistent_resource_evidence_is_unchanged():
    journal = _full_journal()
    ids = journal.ids
    _consumer, _certificates, report = _consume(journal.events)
    row = _by_key(report)[RESOURCE_KEY]
    assert row["status"] == "certified"
    assert _hops(row) == [PRODUCER, DELIVERY, CONSUMER]
    assert _hop(row, PRODUCER)["event_id"] == ids["ram_write"]
    assert _hop(row, DELIVERY)["shared_event"] is True
    assert _hop(row, CONSUMER)["event_id"] == ids["ram_read"]
    assert _hop(row, CONSUMER)["writer_reference_forms"] == ["event_id"]
    assert row["persistent_state"]["reader_reference_forms"]["event_id"] == 4
    assert row["persistent_state"]["reader_reference_forms"]["placeholder"] == 0
    assert row["persistent_state"]["missing_fields"] == []


# ---------------------------------------------------------------- boundedness


def test_oversized_segment_list_is_bounded_and_cannot_certify():
    """A hostile row list is scanned under a bound and never guessed into a join."""
    rows = _rows(value=DELIVERED) * 500
    journal = _build_journal(consumer_rows=rows)
    consumer, _certificates, report = _consume(journal.events, max_pending=4)
    row = _by_key(report)[BINDING_KEY]
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]
    assert report["counts"]["rejected"] == 0
    assert consumer.pending_count <= 4
    assert consumer.pending_hint_count <= report["bounds"]["max_record_references"]


def test_repeated_target_observations_keep_pending_and_hints_bounded():
    journal = _build_journal()
    for index in range(3000):
        journal.add(f"tick_{index}", {
            "kind": "gpio_tick_observation", "component": "dev_b",
            "local_tick": 10 + index, "reset_epoch": 0, "source_epoch": 0,
            "observation_contract": pulp_gpio_observation_contract(),
            "pre": _probe_document(gpio_in=0), "post": _probe_document(gpio_in=DELIVERED),
            "active_input_context": {
                "segments": _rows(delivery=journal.ref("delivery"), value=DELIVERED)},
            "provenance": _provenance()})
    consumer, _certificates, report = _consume(journal.events, max_pending=2,
                                               max_event_gap=1_000_000)
    assert report["counts"]["certified"] == 1
    assert consumer.pending_count <= 2
    assert consumer.pending_hint_count <= report["bounds"]["max_record_references"]
    assert report["bounds"]["max_record_references"] == max(1024, 2 * 64)
    assert consumer.events_observed == len(journal.events)


# ---------------------------------------------------------------- real trace


@functools.lru_cache(maxsize=None)
def _real_report(run_dir):
    contract, endpoints = edge_provenance_session(run_dir)
    return edge_provenance_report(contract, TraceEventStream(run_dir).events(),
                                  endpoints=endpoints)


def _real_rows(report):
    return {(row["rule_index"], row["prerequisite_index"]): row
            for row in report["edges"]}


def test_real_streamed_run_still_reports_the_data_binding_incomplete():
    """That frozen prefix has no target-side observation record at all.

    Its own report is pinned unchanged: the eight other edges still certify and
    the data binding still names its missing consumer hop, so the new path
    never credits a journal that carries no target observation.
    """
    if not STREAMED_RUN.is_dir():  # pragma: no cover - frozen artifact absent
        pytest.skip(f"frozen trace missing: {STREAMED_RUN}")
    report = _real_report(str(STREAMED_RUN))
    assert report["events_observed"] == 10418
    assert report["counts"] == {"total": 9, "certified": 8, "incomplete": 1,
                                "unknown": 0, "rejected": 0, "evicted": 0}
    row = _real_rows(report)[BINDING_KEY]
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]
    assert [hop["event_id"] for hop in row["hops"]] == [17, 18]


@pytest.mark.parametrize("run_dir,driver,delivery,consumer", [
    (PAIRED_RUN, 24, 25, 27),
    (P3_RUN, 22, 23, 25),
])
def test_real_run_certifies_the_data_binding_on_the_cited_target_chain(
        run_dir, driver, delivery, consumer):
    if not run_dir.is_dir():  # pragma: no cover - frozen artifact absent
        pytest.skip(f"frozen trace missing: {run_dir}")
    report = _real_report(str(run_dir))
    assert report["events_rejected"] == 0
    assert report["counts"] == {"total": 9, "certified": 9, "incomplete": 0,
                                "unknown": 0, "rejected": 0, "evicted": 0}
    row = _real_rows(report)[BINDING_KEY]
    assert row["status"] == "certified"
    assert row["missing"] == []
    assert [hop["event_id"] for hop in row["hops"]] == [driver, delivery, consumer]
    assert _hop(row, PRODUCER)["key"] == "endpoint_output"
    assert _hop(row, PRODUCER)["value"] == 0
    assert _hop(row, DELIVERY)["chain"] == {"producer_event_id": driver}
    cited = _hop(row, CONSUMER)
    assert cited["delivery_event_id"] == delivery
    assert cited["driver_event_id"] == driver
    assert cited["value"] == 0
    assert cited["observation"] == "gpio_tick_observation"
    assert cited["segments"] == 8
    assert row["references"]["delivery_event_id"] == delivery


@pytest.mark.parametrize("run_dir", [PAIRED_RUN, P3_RUN])
def test_real_run_keeps_every_other_edge_conclusion(run_dir):
    """Six MMIO routes and both IRQ bindings keep their existing verdicts."""
    if not run_dir.is_dir():  # pragma: no cover - frozen artifact absent
        pytest.skip(f"frozen trace missing: {run_dir}")
    report = _real_report(str(run_dir))
    rows = _real_rows(report)
    routes = [row for row in rows.values() if row["relation"] == "mmio_route"]
    assert len(routes) == 6
    assert all(row["status"] == "certified" for row in routes)
    for row in routes:
        assert _hops(row) == [PRODUCER, DELIVERY]
        assert (_hop(row, PRODUCER)["transaction"]
                == _hop(row, DELIVERY)["transaction"])
        assert _hop(row, PRODUCER)["device_id"] == _hop(row, DELIVERY)["device_id"]
    irq = rows[IRQ_KEY]
    other_irq = rows[(10, 0)]
    assert irq["status"] == other_irq["status"] == "certified"
    for row in (irq, other_irq):
        assert _hops(row) == [PRODUCER, DELIVERY, CONSUMER]
        assert _hop(row, CONSUMER)["key"] == "source_event_id+endpoint+value"
        assert _hop(row, CONSUMER)["value"] == 1
        assert (_hop(row, PRODUCER)["producer_event_id"]
                == _hop(row, DELIVERY)["chain"]["source_event_id"])
    assert [hop["event_id"] for hop in irq["hops"]] \
        == [hop["event_id"] for hop in other_irq["hops"]]
