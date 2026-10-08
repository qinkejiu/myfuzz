"""Generic per-declared-edge provenance: producer, delivery and consumer hops.

The consumer under test is fed one contiguous journal slice at a time and
settles each declared :class:`RuntimeEdgeContract` edge from exact event keys:

* ``direct_binding`` -- the *source-side* endpoint record (whose
  ``producer_event_id`` the delivery names) and the *target-side* endpoint
  record (a distinct interrupt/source event naming the same target endpoint and
  the delivered value) surround one ``dataflow_delivery``;
* ``mmio_route`` -- ``mmio_acceptance`` and ``mmio_delivery`` carry *equal*
  transaction keys plus one ``device_id`` inside the declared aperture, and the
  optional consumer hop is a distinct event naming the same transaction key;
* ``persistent_state`` -- the read's ``writer_event_ids`` row, its version and
  the ``state_dependency`` ``observation_event_id`` all name the declared write
  event.

Negative rules under test: a hop that is only half-observable is
``incomplete`` with ``missing`` naming the first absent hop; an edge with no
observable shape at all is ``unknown`` (never zero, never certified); a forged
producer id, a mismatched transaction key, a non-contiguous or repeated event
id and a conflicting repeat of one id are rejected and counted; eviction and
an event-gap reset never restore credit.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from myfuzz.scenario.acceptance_metrics import TraceEventStream
from myfuzz.scenario.edge_provenance import (
    CONSUMER,
    DELIVERY,
    EDGE_PROVENANCE_REPORT_SCHEMA,
    EDGE_PROVENANCE_SCHEMA,
    PRODUCER,
    EdgeEndpoints,
    EdgeProvenanceConsumer,
    edge_endpoints_from_compiled,
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

GRAPH_SHA256 = "58471d1e3c55652b4570cbdc2a782c060c9ac21427830be22a9ec4a9ce8a48ac"
PROOF_SCOPE = "declared_edge_ids_only"
PARTIAL_SCOPE = "partial_journal_observation"

BINDING_KEY = (2, 0)
MMIO_KEY = (5, 0)
RESOURCE_KEY = (9, 0)
PIN8_KEY = (4, 0)

#: First record of the synthetic journal; every sampled record names it so a
#: delivery's ``producer_event_id`` always resolves inside the stream.
BOOTSTRAP = 1

PIN8_SOURCE = ("gpio_b", "irq", 0, 1)
PIN8_TARGET = ("cpu", "irq", 0)


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

    def __init__(self, tag=""):
        self._rows = []
        self._tag = tag
        self._built = None

    def add(self, name, event):
        self._rows.append([None if name is None else self._tag + name, dict(event)])
        self._built = None
        return self

    def ref(self, name):
        return "@" + self._tag + name

    def index(self, name):
        for index, row in enumerate(self._rows):
            if row[0] == self._tag + name:
                return index
        raise KeyError(f"{self._tag}{name}")

    def without(self, name):
        self._rows.pop(self.index(name))
        self._built = None
        return self

    def mutate(self, name, **changes):
        index = self.index(name)
        self._rows[index][1] = {**self._rows[index][1], **changes}
        self._built = None
        return self

    def insert_before(self, name, event):
        self._rows.insert(self.index(name), [None, dict(event)])
        self._built = None
        return self

    def _build(self):
        if self._built is None:
            ids = {}
            for position, row in enumerate(self._rows):
                if row[0] is not None:
                    assert row[0] not in ids, row[0]
                    ids[row[0]] = position + 1
            events = [_resolve({**row[1], "event_id": position + 1}, ids)
                      for position, row in enumerate(self._rows)]
            self._built = (events, {key[len(self._tag):]: value
                                    for key, value in ids.items()})
        return self._built

    @property
    def events(self):
        return self._build()[0]

    @property
    def ids(self):
        return self._build()[1]


def _transaction(sequence, *, channel="data", component="cpu"):
    return {"channel_id": channel, "execution_id": "local-execution",
            "source_component": component, "source_epoch": 0,
            "source_sequence": sequence, "testcase_id": "synthetic"}


def _provenance(case_index=1, *candidates):
    """Event provenance carrying the declared edge identities of a real trace."""
    return {"schema_version": "event_source_provenance.v1",
            "observed_case": {"case_id": f"case-{case_index}",
                              "case_index": case_index},
            "origin_status": "unknown", "origin_admission_ids": [],
            "invalid_origin_references": 0, "unknown_writer_ids": [],
            "edge_candidates": [{"rule_index": key[0], "prerequisite_index": key[1]}
                                for key in candidates],
            "resource": None, "proof_scope": "observation_only"}


def _endpoint_node(name, component, port, bit_offset, width):
    return RuntimeNode(name, component, "physical", port=port,
                       bit_offset=bit_offset, width=width)


def _contract(*, pin8=False):
    nodes = (
        _endpoint_node("dev_a.out", "dev_a", "out", 0, 8),
        _endpoint_node("dev_b.in", "dev_b", "in", 0, 8),
        RuntimeNode("cpu.mmio", "cpu", "logical"),
        RuntimeNode("dev_b.ram", "dev_b", "state"),
        RuntimeNode("ram.bytes", "ram", "state"),
    )
    edges = [
        RuntimeEdgeContract(*BINDING_KEY, relation="direct_binding"),
        RuntimeEdgeContract(*MMIO_KEY, relation="mmio_route", initiator_component="cpu",
                            device_id="dev_b", base=0x40000000, size=0x1000),
        RuntimeEdgeContract(*RESOURCE_KEY, relation="persistent_state",
                            resource_component="ram", resource_id="buffer"),
    ]
    if pin8:
        nodes = nodes + (_endpoint_node("irq_src.irq", "irq_src", "irq", 0, 1),
                         _endpoint_node("irq_target.irq", "irq_target", "irq", 0, 1))
        edges.append(RuntimeEdgeContract(*PIN8_KEY, relation="direct_binding"))
    return RuntimePathContract(GRAPH_SHA256, nodes, tuple(edges))


def _endpoints(*, pin8=False):
    """Resolved physical endpoints of the synthetic topology."""
    mapping = {
        BINDING_KEY: EdgeEndpoints(_endpoint_node("dev_a.out", "dev_a", "out", 0, 8),
                                   _endpoint_node("dev_b.in", "dev_b", "in", 0, 8)),
        MMIO_KEY: EdgeEndpoints(_endpoint_node("cpu.mmio", "cpu", "mmio", 0, 0x1000),
                                _endpoint_node("dev_b.mmio", "dev_b", "mmio", 0, 0x1000)),
        RESOURCE_KEY: EdgeEndpoints(
            _endpoint_node("ram.bytes", "ram", "buffer", 0, 1),
            _endpoint_node("ram.bytes", "ram", "buffer", 0, 1)),
    }
    if pin8:
        mapping[PIN8_KEY] = EdgeEndpoints(
            _endpoint_node("irq_src.irq", "irq_src", "irq", 0, 1),
            _endpoint_node("irq_target.irq", "irq_target", "irq", 0, 1))
    return mapping


def _tick(journal, name, *, component, value, tick=1, candidates=()):
    return journal.add(name, {
        "kind": "local_tick_sample", "component": component, "local_tick": tick,
        "phase": "post", "producer_event_id": BOOTSTRAP,
        "outputs": {"out": value, "irq": value, "physical": value},
        "provenance": _provenance(1, *candidates)})


def _binding_journal():
    """Certified binding, MMIO route and RAM version chains in one journal."""
    journal = _Journal()
    _tick(journal, "tick_a", component="dev_a", value=0x5A, tick=3,
          candidates=(BINDING_KEY,))
    journal.add("binding_delivery", {
        "kind": "dataflow_delivery", "producer_event_id": journal.ref("tick_a"),
        "source": ["dev_a", "out"], "source_bit_offset": 0,
        "target": ["dev_b", "in"], "target_bit_offset": 0, "width": 8,
        "value": 0x5A, "target_value": 0x5A,
        "provenance": _provenance(1, BINDING_KEY)})
    journal.add("binding_consumer", {
        "kind": "dataflow_consumption", "producer_event_id": journal.ref("tick_b"),
        "source": ["dev_a", "out"], "source_bit_offset": 0,
        "target": ["dev_b", "in"], "target_bit_offset": 0, "width": 8,
        "value": 0x5A, "source_event_id": journal.ref("binding_delivery"),
        "provenance": _provenance(1, BINDING_KEY)})
    _tick(journal, "tick_b", component="dev_b", value=0x5A, tick=3)
    _tick(journal, "irq_driver", component="irq_src", value=1, tick=4,
          candidates=(PIN8_KEY,))
    journal.add("irq_delivery", {
        "kind": "dataflow_delivery", "producer_event_id": journal.ref("irq_driver"),
        "source": ["irq_src", "irq"], "source_bit_offset": 0,
        "target": ["irq_target", "irq"], "target_bit_offset": 0, "width": 1,
        "value": 1, "target_value": 1, "provenance": _provenance(1, PIN8_KEY)})
    journal.add("irq_consumer", {
        "kind": "cpu_irq_input", "cpu_step_event_id": journal.ref("tick_b"),
        "cpu_tick": 4, "source": ["irq_src", "irq"], "source_bit_offset": 0,
        "target": ["irq_target", "irq"], "target_bit_offset": 0, "width": 1,
        "value": 1, "source_event_id": journal.ref("irq_delivery"),
        "provenance": _provenance(1, PIN8_KEY)})
    _tick(journal, "cpu_tick", component="cpu", value=0, tick=5,
          candidates=(MMIO_KEY,))
    journal.add("mmio_acceptance", {
        "kind": "mmio_acceptance", "component": "cpu", "device_id": "dev_b",
        "address": 0x40000004, "offset": 4, "beat_bytes": 4, "byte_enable": 15,
        "write": True, "write_value": 0x5A, "acceptance_order": 1,
        "source_sequence": 1, "source_transaction": _transaction(1),
        "producer_event_id": journal.ref("cpu_tick"),
        "provenance": _provenance(1, MMIO_KEY)})
    journal.add("mmio_delivery", {
        "kind": "mmio_delivery", "component": "cpu", "device_id": "dev_b",
        "address": 0x40000004, "offset": 4, "beat_bytes": 4, "byte_enable": 15,
        "write": True, "write_value": 0x5A, "delivery_order": 1,
        "target_delivery_order": 1, "read_value": None,
        "source_sequence": 1, "source_transaction": _transaction(1),
        "producer_event_id": journal.ref("cpu_tick"),
        "provenance": _provenance(1, MMIO_KEY)})
    journal.add("ram_write", {
        "kind": "memory_write", "component": "ram", "memory_id": "buffer",
        "address": 0x2000, "byte_offset": 32, "width_bytes": 4, "byte_enable": 15,
        "generation": 0, "version": [0, 4], "value": 0x11,
        "transaction": _transaction(4), "producer_event_id": journal.ref("tick_b"),
        "provenance": _provenance(1, RESOURCE_KEY)})
    journal.add("ram_read", {
        "kind": "memory_read", "component": "ram", "memory_id": "buffer",
        "address": 0x2000, "byte_offset": 32, "width_bytes": 4,
        "generation": 0, "versions": [[0, 4], [0, 4], [0, 4], [0, 4]],
        "writer_event_ids": [journal.ref("ram_write")] * 4,
        "writer_kinds": ["RAM"] * 4, "value": 0x11,
        "transaction": _transaction(2), "producer_event_id": journal.ref("tick_b"),
        "provenance": _provenance(1, RESOURCE_KEY)})
    journal.add("ram_version", {
        "kind": "state_dependency", "edge_kind": "RAW", "memory_id": "buffer",
        "byte_offset": 32, "generation": 0, "version": [0, 4],
        "source": "init:buffer:32",
        "target": "TransactionKey(execution_id='local-execution', testcase_id='synthetic', "
                  "source_component='cpu', source_epoch=0, channel_id='data', source_sequence=1)",
        "source_transaction": _transaction(1),
        "producer_event_id": journal.ref("ram_read"),
        "provenance": _provenance(1, MMIO_KEY)})
    journal.add("ram_readback", {
        "kind": "memory_read", "component": "ram", "memory_id": "buffer",
        "address": 0x2000, "byte_offset": 32, "width_bytes": 4,
        "generation": 0, "versions": [[0, 4], [0, 4], [0, 4], [0, 4]],
        "writer_event_ids": [journal.ref("ram_write")] * 4,
        "writer_kinds": ["RAM"] * 4, "value": 0x11,
        "transaction": _transaction(5), "producer_event_id": journal.ref("tick_b"),
        "provenance": _provenance(1, RESOURCE_KEY)})
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


def _consume(events, contract=None, endpoints=None, **kwargs):
    """One consumer, one pass: ingest the slice, then render the report.

    The synthetic journal has four declared edges, so every helper defaults to
    the pin8 contract and its resolved endpoints.
    """
    events = list(events)
    consumer = EdgeProvenanceConsumer(contract or _contract(pin8=True),
                                      endpoints=endpoints or _endpoints(pin8=True),
                                      **kwargs)
    certificates = consumer.ingest(events)
    return consumer, certificates, consumer.report()


# ------------------------------------------------------------------ positives


def test_binding_delivery_edge_is_certified_by_exact_ids():
    journal = _binding_journal()
    ids = journal.ids
    consumer, certificates, report = _consume(journal.events)
    row = _by_key(report)[BINDING_KEY]
    assert report["schema_version"] == EDGE_PROVENANCE_REPORT_SCHEMA
    assert all(certificate["schema_version"] == EDGE_PROVENANCE_SCHEMA
               for certificate in certificates)
    assert row["status"] == "certified"
    assert row["relation"] == "direct_binding"
    assert row["direction"] == "forward"
    assert row["components"] == ["dev_a", "dev_b"]
    assert row["scope"] == "binding"
    assert row["proof_scope"] == PROOF_SCOPE
    assert row["missing"] == []
    assert row["unsupported_shape"] is False
    assert row["declared_shape"] is True
    assert _hops(row) == [PRODUCER, DELIVERY, CONSUMER]
    assert _hop(row, PRODUCER)["event_id"] == ids["tick_a"]
    assert _hop(row, DELIVERY)["event_id"] == ids["binding_delivery"]
    assert _hop(row, CONSUMER)["event_id"] == ids["binding_consumer"]
    assert _hop(row, PRODUCER)["producer_event_id"] == ids["tick_a"]
    assert _hop(row, PRODUCER)["value"] == 0x5A
    assert _hop(row, PRODUCER)["key"] == "endpoint_output"
    assert _hop(row, DELIVERY)["key"] == "producer_event_id"
    assert _hop(row, DELIVERY)["chain"] == {"producer_event_id": ids["tick_a"]}
    assert _hop(row, CONSUMER)["key"] == "source_event_id+endpoint+value"
    assert report["counts"] == {"total": 4, "certified": 4, "incomplete": 0,
                                "unknown": 0, "rejected": 0, "evicted": 0}
    assert report["events_observed"] == len(journal.events)
    assert report["events_rejected"] == 0
    assert len(certificates) == 4
    assert all(certificate["status"] == "certified" for certificate in certificates)


def test_pin8_style_irq_binding_certifies_driver_and_target_records():
    journal = _binding_journal()
    ids = journal.ids
    _consumer, _certificates, report = _consume(journal.events, _contract(pin8=True), _endpoints(pin8=True))
    row = _by_key(report)[PIN8_KEY]
    assert row["status"] == "certified"
    assert row["components"] == ["irq_src", "irq_target"]
    assert _hop(row, PRODUCER)["event_id"] == ids["irq_driver"]
    assert _hop(row, DELIVERY)["event_id"] == ids["irq_delivery"]
    assert _hop(row, CONSUMER)["event_id"] == ids["irq_consumer"]
    assert _hop(row, CONSUMER)["value"] == 1
    assert _hop(row, PRODUCER)["value"] == 1


def test_mmio_route_edge_is_certified_by_equal_transaction_key():
    journal = _binding_journal()
    ids = journal.ids
    _consumer, _certificates, report = _consume(journal.events, endpoints=_endpoints())
    row = _by_key(report)[MMIO_KEY]
    assert row["status"] == "certified"
    assert row["relation"] == "mmio_route"
    assert row["scope"] == "route_window"
    assert row["components"] == ["cpu", "dev_b"]
    assert row["missing"] == []
    assert _hops(row) == [PRODUCER, DELIVERY]
    assert row["observed_shape"]["consumer"] is False
    assert _hop(row, PRODUCER)["event_id"] == ids["mmio_acceptance"]
    assert _hop(row, DELIVERY)["event_id"] == ids["mmio_delivery"]
    transaction = {"channel_id": "data", "execution_id": "local-execution",
                   "source_component": "cpu", "source_epoch": 0,
                   "source_sequence": 1, "testcase_id": "synthetic"}
    assert _hop(row, PRODUCER)["transaction"] == transaction
    assert _hop(row, DELIVERY)["transaction"] == transaction
    assert _hop(row, PRODUCER)["key"] == "transaction_key+aperture"
    assert _hop(row, DELIVERY)["key"] == "transaction_key+aperture"
    assert row["proof_scope"] == PROOF_SCOPE
    assert row["references"]["transaction"]["source_sequence"] == 1
    assert "observation_event_id" not in row["references"]


def test_mmio_route_certifies_without_a_consumer_hop_but_records_it():
    journal = _binding_journal().without("ram_version")
    report = _consume(journal.events, endpoints=_endpoints())[2]
    row = _by_key(report)[MMIO_KEY]
    assert row["status"] == "certified"
    assert _hops(row) == [PRODUCER, DELIVERY]
    assert row["observed_shape"]["consumer"] is False
    assert row["missing"] == []
    assert row["references"]["transaction"]["source_sequence"] == 1


def test_persistent_state_edge_is_certified_by_resource_version_chain():
    journal = _binding_journal()
    ids = journal.ids
    _consumer, _certificates, report = _consume(journal.events)
    row = _by_key(report)[RESOURCE_KEY]
    assert row["status"] == "certified"
    assert row["relation"] == "persistent_state"
    assert row["scope"] == "resource_version"
    assert row["components"] == ["ram"]
    assert row["missing"] == []
    assert row["resource"] == {"component": "ram", "resource_id": "buffer"}
    assert _hops(row) == [PRODUCER, DELIVERY, CONSUMER]
    assert _hop(row, PRODUCER)["event_id"] == ids["ram_write"]
    assert _hop(row, PRODUCER)["key"] == "resource_write"
    assert _hop(row, PRODUCER)["version"] == [0, 4]
    assert _hop(row, DELIVERY)["event_id"] == ids["ram_write"]
    assert _hop(row, DELIVERY)["key"] == "resource_version"
    assert _hop(row, DELIVERY)["shared_event"] is True
    assert _hop(row, CONSUMER)["event_id"] == ids["ram_read"]
    assert _hop(row, CONSUMER)["key"] == "writer_event_id+version"
    assert _hop(row, CONSUMER)["version"] == [0, 4]
    assert _hop(row, CONSUMER)["writer_event_id"] == ids["ram_write"]
    assert _hop(row, CONSUMER)["explicit_writer_refs"] is True
    assert row["references"]["version"] == [0, 4]
    assert row["references"]["observation_event_id"] == ids["ram_read"]
    assert row["references"]["writer_event_id"] == ids["ram_write"]


def test_missing_consumer_hop_is_incomplete_with_missing_named():
    journal = _binding_journal().without("binding_consumer")
    journal.mutate("irq_driver", provenance=_provenance(1, PIN8_KEY))
    consumer, certificates, report = _consume(journal.events, endpoints=_endpoints(pin8=True))
    row = _by_key(report)[BINDING_KEY]
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]
    assert _hops(row) == [PRODUCER, DELIVERY]
    assert row["proof_scope"] == PARTIAL_SCOPE
    assert row["reason"] == "end_of_journal"
    assert report["counts"] == {"total": 4, "certified": 3, "incomplete": 1,
                                "unknown": 0, "rejected": 0, "evicted": 0}
    assert _hops(_by_key(report)[PIN8_KEY]) == [PRODUCER, DELIVERY, CONSUMER]
    settled = {certificate["status"] for certificate in consumer.certificates}
    assert settled == {"certified", "incomplete"}
    assert [certificate["status"] for certificate in certificates].count("certified") == 3


def test_declared_edge_without_any_observable_shape_is_unknown():
    """No slice shape at all -> ``unknown``, never ``incomplete`` and never zero."""
    journal = _binding_journal()
    consumer = EdgeProvenanceConsumer(_contract(pin8=True), endpoints=_endpoints(pin8=True))
    certificates = consumer.ingest(journal.events[:1])
    assert certificates == ()
    report = consumer.report()
    row = _by_key(report)[4, 0] if False else None
    rows = _by_key(report)
    assert rows[PIN8_KEY]["status"] == "unknown"
    assert rows[PIN8_KEY]["hops"] == []
    assert rows[PIN8_KEY]["missing"] == []
    assert rows[PIN8_KEY]["proof_scope"] == "no_observable_shape"
    assert rows[PIN8_KEY]["declared_shape"] is True
    assert rows[PIN8_KEY]["observed_shape"] == {"producer": False, "delivery": False,
                                                "consumer": False}
    assert report["counts"]["unknown"] >= 1
    assert report["counts"]["certified"] == 0
    # The binding edge did observe its producer shape in the same slice, so it
    # is ``incomplete`` instead of ``unknown``.
    assert rows[BINDING_KEY]["status"] == "incomplete"
    assert _hops(rows[BINDING_KEY]) == [PRODUCER]


def test_empty_journal_reports_unknown_for_every_declared_edge():
    consumer = EdgeProvenanceConsumer(_contract(pin8=True), endpoints=_endpoints(pin8=True))
    consumer.ingest([])
    report = consumer.report()
    assert report["counts"] == {"total": 4, "certified": 0, "incomplete": 0,
                                "unknown": 4, "rejected": 0, "evicted": 0}
    assert report["events_observed"] == 0
    for row in report["edges"]:
        assert row["status"] == "unknown"
        assert row["reason"] == "no_observable_hop"
        assert row["hops"] == []
        assert row["missing"] == []


def test_declared_edge_without_hop_evidence_is_unknown_with_reason():
    row = _by_key(_consume([], endpoints=_endpoints())[2])[BINDING_KEY]
    assert row["status"] == "unknown"
    assert row["reason"] == "no_observable_hop"
    assert row["unsupported_shape"] is False
    assert row["declared_shape"] is True
    assert row["observed_shape"] == {"producer": False, "delivery": False,
                                     "consumer": False}
    assert row["proof_scope"] == "no_observable_shape"


def test_forged_producer_reference_is_rejected():
    journal = _binding_journal()
    journal.mutate("binding_delivery", producer_event_id=10 ** 6)
    consumer, _certificates, report = _consume(journal.events, endpoints=_endpoints())
    assert report["events_rejected"] == 1
    assert report["counts"]["rejected"] == 1
    assert report["rejections"][0]["reason"] == "unknown_producer_reference"
    assert report["rejections"][0]["event_id"] == journal.ids["binding_delivery"]
    binding = _by_key(report)[BINDING_KEY]
    assert binding["status"] == "incomplete"
    assert binding["missing"] == [DELIVERY, CONSUMER]
    assert _hops(binding) == [PRODUCER]
    assert binding["reason"] == "end_of_journal"
    assert consumer.rejections[0]["kind"] == "dataflow_delivery"


def test_forged_producer_endpoint_record_does_not_attach_producer_hop():
    """A delivery whose producer record names no declared output stays incomplete."""
    journal = _binding_journal()
    journal.mutate("tick_a", component="dev_b", outputs={"out": 0x5A})
    report = _consume(journal.events, endpoints=_endpoints())[2]
    row = _by_key(report)[BINDING_KEY]
    assert row["status"] == "incomplete"
    assert row["missing"] == [PRODUCER, DELIVERY, CONSUMER]
    assert _hops(row) == []
    # The forged snapshot keeps its producer hint, so the delivery that names it
    # is refused rather than attached to a hop the record cannot support.
    assert report["events_rejected"] == 1
    assert report["rejections"][0]["reason"] == "unknown_producer_reference"
    assert report["counts"] == {"total": 4, "certified": 2, "incomplete": 1,
                                "unknown": 1, "rejected": 1, "evicted": 0}


def test_transaction_key_mismatch_keeps_route_incomplete():
    journal = _binding_journal()
    journal.mutate("mmio_delivery", source_transaction=_transaction(7))
    report = _consume(journal.events, _contract(), _endpoints())[2]
    row = _by_key(report)[MMIO_KEY]
    assert row["status"] == "incomplete"
    assert row["missing"] == [DELIVERY]
    assert _hops(row) == [PRODUCER]
    assert report["counts"]["certified"] == 2
    assert report["events_rejected"] == 0


def test_conflicting_transaction_key_shape_is_rejected():
    journal = _binding_journal()
    journal.mutate("mmio_delivery", source_transaction={"channel_id": "data"})
    report = _consume(journal.events, endpoints=_endpoints())[2]
    assert report["events_rejected"] == 1
    assert report["rejections"][0]["reason"] == "invalid_identity_field"
    assert report["rejections"][0]["kind"] == "mmio_delivery"
    row = _by_key(report)[MMIO_KEY]
    assert row["status"] == "incomplete"
    assert row["missing"] == [DELIVERY]
    assert _hops(row) == [PRODUCER]


def test_out_of_aperture_acceptance_does_not_attach_route_hop():
    journal = _binding_journal()
    journal.mutate("mmio_acceptance", address=0x50000004)
    journal.mutate("mmio_delivery", address=0x50000004)
    report = _consume(journal.events, endpoints=_endpoints())[2]
    row = _by_key(report)[MMIO_KEY]
    assert row["status"] == "incomplete"
    assert row["missing"] == [PRODUCER, DELIVERY]
    assert _hops(row) == []
    assert row["reason"] == "end_of_journal"


def test_non_contiguous_event_ids_are_rejected_and_counted():
    events = _binding_journal().events
    broken = [event for event in events if event["event_id"] != 5]
    consumer = EdgeProvenanceConsumer(_contract(), endpoints=_endpoints())
    consumer.ingest(broken)
    assert consumer.events_rejected == 1
    assert consumer.rejections[0]["reason"] == "non_contiguous_event_id"
    assert consumer.rejections[0]["event_id"] == 6
    assert consumer.last_event_id == len(broken) + 1
    assert consumer.ingest([{"kind": "local_tick_sample", "event_id": len(broken) + 1,
                             "component": "cpu", "local_tick": 1, "outputs": {},
                             "producer_event_id": 1, "provenance": _provenance()}]) == ()


def test_non_integer_and_repeated_event_ids_are_rejected():
    events = _binding_journal().events
    consumer = EdgeProvenanceConsumer(_contract(), endpoints=_endpoints())
    consumer.ingest([{**events[0], "event_id": True}])
    consumer.ingest([events[1]])
    consumer.ingest([dict(events[1])])
    assert [row["reason"] for row in consumer.rejections] == [
        "non_integer_event_id", "non_contiguous_event_id", "repeated_event_id"]
    assert consumer.events_rejected == 3
    assert consumer.last_event_id == 2
    forged = EdgeProvenanceConsumer(_contract(), endpoints=_endpoints())
    forged.ingest([{**events[0], "event_id": "1"}])
    assert forged.rejections[0]["reason"] == "non_integer_event_id"
    assert forged.last_event_id == 0


def test_same_event_id_with_conflicting_content_is_rejected():
    """A later record that conflicts with a consumed id is refused, not merged."""
    journal = _binding_journal()
    events = journal.events
    consumer = EdgeProvenanceConsumer(_contract(), endpoints=_endpoints())
    consumer.ingest(events[:1])
    consumer.ingest([dict(events[1])])
    # Flush first, so the replay below starts from a fully settled journal.
    report = consumer.report()
    assert consumer.ingest([dict(events[1])]) == ()
    assert consumer.ingest([{**events[1], "value": 0x77}]) == ()
    assert [row["reason"] for row in consumer.rejections] == [
        "repeated_event_id", "repeated_event_id"]
    assert consumer.events_rejected == 2
    after = consumer.report()
    assert [[(hop["hop_id"], hop["event_id"]) for hop in row["hops"]]
            for row in after["edges"]] == [[(hop["hop_id"], hop["event_id"])
                                            for hop in row["hops"]]
                                           for row in report["edges"]]
    assert after["counts"]["rejected"] == report["counts"]["rejected"] + 2
    assert {(row["rule_index"], row["status"]) for row in report["edges"]} == \
        {(row["rule_index"], row["status"]) for row in after["edges"]}


def test_persistent_state_without_byte_link_is_incomplete():
    """No read names the writer event id: versions alone never certify."""
    journal = _binding_journal()
    journal.mutate("ram_read", writer_event_ids=["init:buffer:32"] * 4,
                   writer_kinds=["INITIAL_IMAGE"] * 4,
                   versions=[[0, 9], [0, 9], [0, 9], [0, 9]])
    journal.mutate("ram_version", version=[0, 9])
    journal.mutate("ram_readback", writer_event_ids=["init:buffer:32"] * 4,
                   versions=[[0, 9], [0, 9], [0, 9], [0, 9]])
    report = _consume(journal.events, _contract(), _endpoints())[2]
    row = _by_key(report)[RESOURCE_KEY]
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]
    assert _hops(row) == [PRODUCER, DELIVERY]
    assert report["counts"]["certified"] == 2
    assert report["counts"]["incomplete"] == 1


def test_persistent_state_version_mismatch_is_incomplete():
    journal = _binding_journal()
    journal.mutate("ram_read", versions=[[0, 7], [0, 7], [0, 7], [0, 7]])
    journal.mutate("ram_version", version=[0, 7])
    journal.mutate("ram_readback", versions=[[0, 7], [0, 7], [0, 7], [0, 7]])
    row = _by_key(_consume(journal.events, _contract(), _endpoints())[2])[RESOURCE_KEY]
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]
    assert _hops(row) == [PRODUCER, DELIVERY]


def test_binding_value_mismatch_is_incomplete_not_certified():
    journal = _binding_journal()
    journal.mutate("binding_consumer", value=0x11)
    report = _consume(journal.events, endpoints=_endpoints())[2]
    row = _by_key(report)[BINDING_KEY]
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]
    assert report["counts"]["incomplete"] == 1
    assert report["counts"]["certified"] == 2


def test_binding_without_any_driver_record_is_incomplete():
    """A delivery alone has no source-side record, so no producer hop exists."""
    journal = _binding_journal()
    journal.mutate("binding_consumer", kind="local_tick_sample")
    report = _consume(journal.events, endpoints=_endpoints())[2]
    row = _by_key(report)[BINDING_KEY]
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]
    assert _hops(row) == [PRODUCER, DELIVERY]
    assert report["counts"]["certified"] == 2


def test_constructed_contract_rejects_unknown_relation_shape():
    nodes = (_endpoint_node("dev_a.out", "dev_a", "out", 0, 8),
             _endpoint_node("dev_b.in", "dev_b", "in", 0, 8))
    contract = RuntimePathContract(
        GRAPH_SHA256, nodes, (RuntimeEdgeContract(1, 0, "causal_order"),))
    report = EdgeProvenanceConsumer(contract, endpoints={}).report([])
    row = report["edges"][0]
    assert row["status"] == "unknown"
    assert row["declared_shape"] is False
    assert row["unsupported_shape"] is True
    assert row["reason"] == "declared_shape_unsupported"
    assert row["unsupported_shape_reason"] == (
        "causal_order has no runtime join shape in this consumer")
    assert row["observed_shape"] is None


def test_constructor_requires_contract_and_positive_bounds():
    with pytest.raises(ValueError):
        EdgeProvenanceConsumer("not-a-contract")
    with pytest.raises(ValueError):
        EdgeProvenanceConsumer(_contract(), endpoints=_endpoints(), max_pending=0)
    with pytest.raises(ValueError):
        EdgeProvenanceConsumer(_contract(), endpoints=_endpoints(), max_event_gap=0)
    with pytest.raises(ValueError):
        edge_provenance_report("not-a-contract", [])


def test_malformed_edge_candidate_identity_is_rejected():
    """A declared-edge candidate with an ill-typed identity never opens an edge."""
    journal = _binding_journal()
    first = dict(journal.events[0])
    first["provenance"] = {**first["provenance"],
                           "edge_candidates": [{"rule_index": "2",
                                                "prerequisite_index": 0}]}
    consumer = EdgeProvenanceConsumer(_contract(), endpoints=_endpoints())
    consumer.ingest([first])
    assert consumer.events_rejected == 1
    assert consumer.rejections[0] == {"reason": "invalid_identity_field",
                                      "event_id": 1, "kind": "local_tick_sample"}
    report = consumer.report()
    assert report["counts"] == {"total": 3, "certified": 0, "incomplete": 0,
                                "unknown": 3, "rejected": 1, "evicted": 0}


def test_report_does_not_mutate_consumer_state_and_is_json_serializable():
    events = _binding_journal().events
    consumer = EdgeProvenanceConsumer(_contract(), endpoints=_endpoints())
    consumer.ingest(events)
    first = consumer.report()
    second = consumer.report()
    assert json.loads(json.dumps(first, sort_keys=True)) == first
    assert first["edges"] == second["edges"]
    assert first["counts"] == second["counts"]
    assert len(first["contract_identity"]) == 64


# -------------------------------------------------------------------- bounds


def test_pending_never_exceeds_max_pending_over_fifty_thousand_events():
    """Fifty thousand events keep every bound: pending, hints, decisions."""
    events = _binding_journal().events
    consumer = EdgeProvenanceConsumer(_contract(pin8=True), endpoints=_endpoints(pin8=True),
                                      max_pending=2, max_event_gap=64)
    peak = 0
    for index in range(50000):
        event = dict(events[index % len(events)])
        event["event_id"] = index + 1
        consumer.ingest((event,))
        peak = max(peak, consumer.pending_count)
        assert consumer.pending_count <= 2
        assert consumer.pending_hint_count <= 1024
    report = consumer.report()
    assert peak <= 2
    assert consumer.pending_count <= 2
    assert report["bounds"] == {"max_pending": 2, "max_event_gap": 64,
                                "max_record_references": 1024}
    assert report["events_observed"] == 50000
    assert report["events_rejected"] == len(report["rejections"])
    assert report["counts"]["rejected"] == report["events_rejected"]
    assert len(report["rejections"]) <= 64
    assert report["counts"]["total"] == 4
    assert report["counts"]["evicted"] <= report["counts"]["total"]
    assert {row["status"] for row in report["edges"]} <= {
        "certified", "incomplete", "unknown"}


def test_evicted_edge_never_recovers_credit():
    """A pending-capacity eviction is final: later events never add hops."""
    journal = _Journal()
    journal.add("seed", {"kind": "local_tick_sample", "component": "cpu",
                         "local_tick": 0, "phase": "post", "producer_event_id": 1,
                         "outputs": {"out": 0}, "provenance": _provenance()})
    journal.add("tick_a", {"kind": "local_tick_sample", "component": "dev_a",
                           "local_tick": 1, "phase": "post",
                           "producer_event_id": journal.ref("seed"),
                           "outputs": {"out": 1},
                           "provenance": _provenance(1, BINDING_KEY)})
    journal.add("mmio_tick", {"kind": "local_tick_sample", "component": "cpu",
                              "local_tick": 2, "phase": "post",
                              "producer_event_id": journal.ref("tick_a"),
                              "outputs": {"out": 0},
                              "provenance": _provenance(1, MMIO_KEY)})
    journal.add("binding_delivery", {"kind": "dataflow_delivery",
                                     "producer_event_id": journal.ref("tick_a"),
                                     "source": ["dev_a", "out"], "source_bit_offset": 0,
                                     "target": ["dev_b", "in"], "target_bit_offset": 0,
                                     "width": 8, "value": 1, "target_value": 1,
                                     "provenance": _provenance(1, BINDING_KEY)})
    journal.add("binding_consumer", {"kind": "dataflow_consumption",
                                     "producer_event_id": journal.ref("binding_delivery"),
                                     "source": ["dev_a", "out"], "source_bit_offset": 0,
                                     "target": ["dev_b", "in"], "target_bit_offset": 0,
                                     "width": 8, "value": 1, "provenance": _provenance(1)})
    events = journal.events
    consumer = EdgeProvenanceConsumer(_contract(), endpoints=_endpoints(),
                                      max_pending=1, max_event_gap=4096)
    # The binding edge opens on its driver record, then the MMIO edge needs the
    # single pending slot and evicts it before its own delivery arrives.
    consumer.ingest(events)
    assert consumer.evictions == 1
    report = consumer.report()
    rows = _by_key(report)
    assert rows[BINDING_KEY]["status"] == "incomplete"
    assert rows[BINDING_KEY]["reason"] == "pending_capacity"
    # The producer hop seen before the eviction stays visible; the delivery and
    # consumer records that arrive later are refused.
    assert _hops(rows[BINDING_KEY]) == [PRODUCER]
    assert rows[BINDING_KEY]["missing"] == [DELIVERY, CONSUMER]
    assert report["evictions"] == [{"rule_index": BINDING_KEY[0],
                                    "prerequisite_index": BINDING_KEY[1],
                                    "reason": "pending_capacity"}]
    assert report["counts"]["evicted"] == 1
    assert consumer.pending_count <= 1


def test_gap_bound_resets_pending_and_credit_is_not_restored():
    """An event-gap reset drops partial hops; late events never restore them."""
    journal = _binding_journal()
    events = journal.events
    consumer = EdgeProvenanceConsumer(_contract(), endpoints=_endpoints(),
                                      max_pending=8, max_event_gap=2)
    consumer.ingest(events[:1])
    assert consumer.pending_count == 1
    # Reading the partial state must not settle it; ``report`` would flush it.
    assert [hop["hop_id"] for hop in
            consumer._active[BINDING_KEY]["hops"].values()] == [PRODUCER]
    consumer.ingest([{"kind": "local_tick_sample", "event_id": 500, "component": "cpu",
                      "local_tick": 9, "outputs": {}, "producer_event_id": 1,
                      "provenance": _provenance()}])
    assert consumer.resets == 1
    assert consumer.pending_count == 0
    rest = [{**event, "event_id": event["event_id"] + 500} for event in events[1:]]
    consumer.ingest(rest)
    report = consumer.report()
    row = _by_key(report)[BINDING_KEY]
    assert row["status"] == "incomplete"
    assert row["reason"] == "event_gap_reset"
    # Hops seen before the reset stay visible; the later attempts to add more
    # are refused and never restore credit for this edge.
    assert _hops(row) == [PRODUCER]
    assert row["missing"] == [DELIVERY, CONSUMER]
    assert report["resets"] == 1
    assert consumer.dropped_late_hops >= 1


def test_single_event_ingest_attributes_referenced_records():
    """One-event slices resolve the same hops as one batch ingest."""
    events = _binding_journal().events
    expected = {BINDING_KEY: [PRODUCER, DELIVERY, CONSUMER],
                PIN8_KEY: [PRODUCER, DELIVERY, CONSUMER],
                MMIO_KEY: [PRODUCER, DELIVERY],
                RESOURCE_KEY: [PRODUCER, DELIVERY, CONSUMER]}
    streamed = EdgeProvenanceConsumer(_contract(pin8=True), endpoints=_endpoints(pin8=True))
    for event in events:
        streamed.ingest((event,))
    report = streamed.report()
    assert report["counts"]["certified"] == 4
    assert report["events_rejected"] == 0
    for key, hops in expected.items():
        row = _by_key(report)[key]
        assert row["status"] == "certified", key
        assert _hops(row) == hops, key
    # And a deleted consumer hop is still named in the streamed report.
    journal = _binding_journal().without("binding_consumer")
    streamed = EdgeProvenanceConsumer(_contract(pin8=True), endpoints=_endpoints(pin8=True))
    for event in journal.events:
        streamed.ingest((event,))
    row = _by_key(streamed.report())[BINDING_KEY]
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]


def test_reset_clears_credit_and_continuity():
    events = _binding_journal().events
    consumer = EdgeProvenanceConsumer(_contract(), endpoints=_endpoints())
    consumer.ingest(events[:2])
    assert consumer.pending_count == 1
    consumer.reset()
    assert consumer.pending_count == 0
    assert consumer.last_event_id == 0
    consumer.ingest([{"kind": "local_tick_sample", "event_id": 1, "component": "cpu",
                      "local_tick": 1, "outputs": {}, "producer_event_id": 1,
                      "provenance": _provenance()}])
    assert consumer.events_rejected == 0
    report = consumer.report()
    assert report["events_observed"] == 1


# --------------------------------------------------------------- real trace


def _stream(run_dir):
    return TraceEventStream(run_dir).events()


@pytest.fixture(scope="module")
def real_run():
    """The frozen streamed run's own compiled declaration and event stream."""
    if not STREAMED_RUN.is_dir():  # pragma: no cover - frozen artifact absent
        pytest.skip(f"frozen trace missing: {STREAMED_RUN}")
    manifest = json.loads(
        (STREAMED_RUN / "online_session_manifest.json").read_text(encoding="utf-8"))
    compiled = manifest["runtime_paths"]
    contract = RuntimePathContract.from_document(compiled["declaration"]["contract"])
    assert contract.identity_sha256 == compiled["contract_sha256"]
    assert contract.graph_sha256 == compiled["graph_sha256"]
    events = [first for first in _stream(STREAMED_RUN)]
    return contract, compiled, events


def _real_endpoints(contract, compiled):
    endpoints = edge_endpoints_from_compiled(contract, compiled)
    missing = [edge.key for edge in contract.edges if edge.key not in endpoints]
    assert not missing, missing
    return endpoints


def test_real_contract_is_the_runs_own_declaration(real_run):
    contract, compiled, _events = real_run
    assert contract.graph_sha256 == GRAPH_SHA256
    assert len(contract.edges) == 9
    relations = {(edge.key, edge.relation) for edge in contract.edges}
    assert (BINDING_KEY, "direct_binding") in relations
    assert (PIN8_KEY, "direct_binding") in relations
    assert (MMIO_KEY, "mmio_route") in relations
    endpoints = _real_endpoints(contract, compiled)
    assert endpoints[BINDING_KEY].source.component == "gpio_a"
    assert endpoints[BINDING_KEY].target.component == "gpio_b"
    assert endpoints[PIN8_KEY].source.component == "gpio_b"
    assert endpoints[PIN8_KEY].target.component == "cpu"
    assert endpoints[MMIO_KEY].source.component == "cpu"
    assert endpoints[MMIO_KEY].target.component == "gpio_b"


def test_real_streamed_trace_coverage_report_is_honest(real_run):
    """Real streamed trace: 8 of 9 declared edges certify, 1 stays open.

    Certified here means the *identity* join of the declared edge, not RTL
    causality: the MMIO routes join acceptance to delivery by an equal exact
    transaction key inside the declared aperture, and the two IRQ bindings join
    a source pulse record, its pulse transport record and the CPU interrupt
    record by the one ``source_event_id`` they share.
    """
    contract, compiled, observed = real_run
    report = edge_provenance_report(contract, observed,
                                    endpoints=_real_endpoints(contract, compiled))
    assert report["schema_version"] == EDGE_PROVENANCE_REPORT_SCHEMA
    assert report["events_observed"] == len(observed) == 10418
    assert report["events_rejected"] == 0
    assert report["counts"] == {"total": 9, "certified": 8, "incomplete": 1,
                                "unknown": 0, "rejected": 0, "evicted": 0}
    rows = _by_key(report)
    # gpio_a -> gpio_b data binding: the source tick record and its delivery
    # exist; no record of the bound target input ever being consumed does.
    binding = rows[BINDING_KEY]
    assert binding["status"] == "incomplete"
    assert binding["missing"] == [CONSUMER]
    assert binding["proof_scope"] == PARTIAL_SCOPE
    assert [hop["hop_id"] for hop in binding["hops"]] == [PRODUCER, DELIVERY]
    assert [hop["event_id"] for hop in binding["hops"]] == [17, 18]
    assert binding["hops"][0]["key"] == "endpoint_output"
    assert binding["hops"][0]["value"] == 0
    assert binding["hops"][1]["value"] == 0
    assert binding["hops"][1]["chain"] == {"producer_event_id": 17}
    assert binding["references"]["producer_event_id"] == 17
    # pin8 IP->CPU IRQ binding: source_start(2119) -> pulse_start(2120) ->
    # cpu_irq_input(2122), all naming the one source_event_id 1.
    pin8 = rows[PIN8_KEY]
    assert pin8["status"] == "certified"
    assert pin8["missing"] == []
    assert pin8["proof_scope"] == PROOF_SCOPE
    assert [hop["hop_id"] for hop in pin8["hops"]] == [PRODUCER, DELIVERY, CONSUMER]
    assert [hop["event_id"] for hop in pin8["hops"]] == [2119, 2120, 2122]
    assert pin8["hops"][0]["key"] == "source_event_id"
    assert pin8["hops"][0]["producer_event_id"] == 1
    assert pin8["hops"][1]["key"] == "source_event_id"
    assert pin8["hops"][2]["key"] == "source_event_id+endpoint+value"
    assert pin8["hops"][2]["value"] == 1
    assert [hop["event_id"] for hop in rows[(10, 0)]["hops"]] == [2119, 2120, 2122]
    # CPU MMIO write route: acceptance and delivery share one transaction key
    # and one declared aperture. This proves transport identity, not that the
    # delivered value equals the resource write.
    mmio = rows[MMIO_KEY]
    assert mmio["status"] == "certified"
    assert [hop["event_id"] for hop in mmio["hops"]] == [106, 115]
    assert mmio["hops"][0]["transaction"] == mmio["hops"][1]["transaction"]
    assert mmio["hops"][0]["transaction"]["source_sequence"] == 1
    assert mmio["hops"][0]["device_id"] == "gpio_b"
    assert mmio["hops"][0]["base"] == 0x40000000
    assert mmio["hops"][0]["size"] == 4096
    assert mmio["hops"][0]["address"] == 0x40000004
    # Four declared MMIO routes share the two router windows, and this trace
    # only ever accepts and delivers the data-window write: every route that
    # observes that window reports the same exact event pair, none invents one.
    for key, row in rows.items():
        if row["relation"] != "mmio_route":
            continue
        if row["status"] == "certified":
            assert [hop["event_id"] for hop in row["hops"]] in ([106, 115], [325, 331])
        else:
            assert row["status"] == "unknown"
            assert row["hops"] == []
            assert row["reason"] == "no_observable_hop"


def test_real_trace_declares_no_persistent_edge_so_none_is_claimed(real_run):
    """The run's own contract declares no persistent_state relation at all.

    So no RAM version chain can be certified *for this contract*, even though
    the trace carries Stores and RAM reads. The consumer is still able to
    certify a declared persistent edge when a read names the exact writer event
    id (covered by the synthetic resource-version test).
    """
    contract, compiled, observed = real_run
    report = edge_provenance_report(contract, observed,
                                    endpoints=_real_endpoints(contract, compiled))
    rows = _by_key(report)
    assert [row for row in rows.values() if row["relation"] == "persistent_state"] == []
    assert all(row["relation"] in ("direct_binding", "mmio_route")
               for row in report["edges"])
    # Stores and RAM reads exist in this very trace and still do not certify a
    # persistent edge: every read writer_event_id is a string such as
    # ``initial-image``, so no read names the exact write event id.
    reads = [event for event in observed if event.get("kind") == "memory_read"]
    writes = [event for event in observed if event.get("kind") == "memory_write"]
    assert reads and writes
    numeric = [writer for event in reads for writer in (event.get("writer_event_ids") or [])
               if type(writer) is int]
    assert numeric == []
    string_writers = {writer for event in reads
                      for writer in (event.get("writer_event_ids") or [])
                      if type(writer) is str}
    assert string_writers


def test_real_trace_unknown_origin_events_are_not_certified_by_origin_status(real_run):
    """``origin_status="unknown"`` MMIO/Store events stay non-certified."""
    contract, compiled, observed = real_run
    endpoints = _real_endpoints(contract, compiled)
    consumer = EdgeProvenanceConsumer(contract, endpoints=endpoints, max_pending=32)
    unknown_origin = 0
    origins = {}
    for event in observed:
        provenance = event.get("provenance")
        if isinstance(provenance, dict) and provenance.get("origin_status") == "unknown":
            unknown_origin += 1
            origins[event["event_id"]] = provenance.get("proof_scope")
        consumer.ingest((event,))
    report = consumer.report()
    assert unknown_origin > 0
    assert origins[2122] == "observation_only"
    assert origins[115] == "transport_candidates_only"
    assert consumer.pending_count == 0
    assert consumer.events_rejected == 0
    rows = _by_key(report)
    assert report["counts"] == {"total": 9, "certified": 8, "incomplete": 1,
                                "unknown": 0, "rejected": 0, "evicted": 0}
    # A certified hop never claims a source admission the events do not carry:
    # the MMIO/IRQ hops are joined by transaction/source-event ids only.
    assert all("source_admission_id" not in hop for row in rows.values()
               for hop in row["hops"])
    assert rows[PIN8_KEY]["status"] == "certified"
    assert rows[BINDING_KEY]["status"] == "incomplete"


def test_real_trace_streamed_one_event_at_a_time_is_attributed(real_run):
    """Streaming the generator event by event is the documented usage.

    A single-event slice cannot pre-scan references, so the consumer must still
    attribute a sampled tick record to the edge named later by its delivery.
    """
    contract, compiled, observed = real_run
    endpoints = _real_endpoints(contract, compiled)
    consumer = EdgeProvenanceConsumer(contract, endpoints=endpoints)
    newly = []
    for event in _stream(STREAMED_RUN):
        newly.extend(consumer.ingest((event,)))
    report = consumer.report()
    streamed = {(row["rule_index"], row["prerequisite_index"]): row
                for row in report["edges"]}
    batch = _by_key(edge_provenance_report(contract, observed, endpoints=endpoints))
    assert report["events_observed"] == 10418
    assert report["counts"] == {"total": 9, "certified": 8, "incomplete": 1,
                                "unknown": 0, "rejected": 0, "evicted": 0}
    for key, row in streamed.items():
        assert row["status"] == batch[key]["status"], key
        assert row["missing"] == batch[key]["missing"], key
        assert [(hop["hop_id"], hop["event_id"]) for hop in row["hops"]] == \
            [(hop["hop_id"], hop["event_id"]) for hop in batch[key]["hops"]], key
    pin8 = streamed[PIN8_KEY]
    assert pin8["status"] == "certified"
    assert [hop["event_id"] for hop in pin8["hops"]] == [2119, 2120, 2122]
    assert consumer.pending_count == 0
    assert len(newly) >= 8


def test_edge_provenance_session_resolves_the_runs_own_declaration():
    if not STREAMED_RUN.is_dir():  # pragma: no cover - frozen artifact absent
        pytest.skip(f"frozen trace missing: {STREAMED_RUN}")
    contract, endpoints = edge_provenance_session(STREAMED_RUN)
    assert contract.graph_sha256 == GRAPH_SHA256
    assert contract.identity_sha256 == json.loads(
        (STREAMED_RUN / "online_session_manifest.json").read_text(
            encoding="utf-8"))["runtime_paths"]["contract_sha256"]
    assert set(endpoints) == {edge.key for edge in contract.edges}
    assert endpoints[PIN8_KEY].source.component == "gpio_b"
    assert endpoints[MMIO_KEY].target.component == "gpio_b"


def test_real_trace_without_resolved_endpoints_is_pinned_unknown(real_run):
    """Capability boundary: without resolved endpoints nothing can be claimed.

    The event identities still agree with the contract (same ``graph_sha256``,
    same declared rules), but this consumer never guesses a physical endpoint
    from an event, so every edge is ``unknown`` with the resolution reason --
    which says "not observable here", not "the chain did not happen".
    """
    contract, compiled, observed = real_run
    report = edge_provenance_report(contract, _stream(STREAMED_RUN))
    assert report["counts"] == {"total": 9, "certified": 0, "incomplete": 0,
                                "unknown": 9, "rejected": 0, "evicted": 0}
    for row in report["edges"]:
        assert row["status"] == "unknown"
        assert row["reason"] == "no_observable_hop"
        assert row["proof_scope"] == "no_observable_shape"
        assert row["unsupported_shape"] is False
        assert row["unsupported_shape_reason"] == (
            "no resolved physical endpoints for this declared edge")
        assert row["hops"] == []
    # The premise holds: the trace's own candidates carry this contract's graph
    # digest and declared rule indices, so the gap is endpoint resolution only.
    candidates = {event["event_id"]: event["provenance"]["edge_candidates"]
                  for event in observed
                  if isinstance(event.get("provenance"), dict)
                  and event["provenance"].get("edge_candidates")}
    assert candidates
    declared = {(edge.rule_index, edge.prerequisite_index) for edge in contract.edges}
    for rows in candidates.values():
        for candidate in rows:
            assert candidate["graph_sha256"] == contract.graph_sha256
            assert (candidate["rule_index"], candidate["prerequisite_index"]) in declared
            assert candidate["relation"] in ("direct_binding", "mmio_route")
            assert candidate["scope"] in ("binding", "route_window")
            assert candidate["path_ids"]


def test_real_trace_stream_reports_every_declared_edge(real_run):
    contract, compiled, observed = real_run
    report = edge_provenance_report(contract, observed,
                                    endpoints=_real_endpoints(contract, compiled))
    assert len(report["edges"]) == len(contract.edges) == 9
    assert report["contract_identity"] == contract.identity_sha256
    assert report["graph_sha256"] == GRAPH_SHA256
    assert report["bounds"]["max_pending"] == 4096
    assert report["bounds"]["max_record_references"] == 262144
    assert report["events_rejected"] == 0
    for row in report["edges"]:
        assert row["status"] in ("certified", "incomplete", "unknown")
        assert row["proof_scope"] in (PROOF_SCOPE, PARTIAL_SCOPE, "no_observable_shape")
        assert (row["status"] == "unknown") == (row["hops"] == [])
