"""Appended ``persistent_state`` edges: declaration, judgement, real trace.

The Ibex + dual PULP GPIO online contract declares two *appended* persistent
resource relations -- CPU store to host RAM byte version to a later load, and
GPIO A PADOUT register commit to a later read of that same bit version.  This
module pins, with negative cases, exactly what those edges may and may not
certify:

* an exact writer identity (integer write event id, the writer's own canonical
  ``TransactionKey(...)``, or the writer's own declared ``writer_event_id``)
  together with an exact version, a covered byte window and a matching
  generation certifies;
* a placeholder writer name such as ``initial-image``, a version mismatch, a
  generation mismatch, a byte window the write's ``byte_enable`` does not cover,
  a register read without ``observation_event_id`` or with a different version,
  and an edge whose endpoints were never resolved never certify;
* the nine pre-existing declared edges keep their exact identities and their
  real-trace counts while the appended rows are declared.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from myfuzz.scenario.acceptance_metrics import TraceEventStream
from myfuzz.scenario.edge_provenance import (
    CONSUMER,
    DELIVERY,
    PRODUCER,
    EdgeEndpoints,
    EdgeProvenanceConsumer,
    _ANCHOR_LIMIT,
    edge_provenance_report,
)
from myfuzz.scenario.ibex_pulp_dual_source import (
    ONLINE_GPIO_REGISTER_RESOURCE_COMPONENT,
    ONLINE_GPIO_REGISTER_RESOURCE_ID,
    ONLINE_GPIO_REGISTER_VERSION_NODE,
    ONLINE_RAM_RESOURCE_COMPONENT,
    ONLINE_RAM_RESOURCE_ID,
    ONLINE_RAM_VERSION_NODE,
    make_ibex_pulp_dual_source_online_decoder,
)
from myfuzz.scenario.persistent_state_provenance import (
    legacy_prefix_join,
    persistent_state_report,
    resource_candidate_resolver,
)
from myfuzz.scenario.runtime_path_contract import (
    RuntimeEdgeContract,
    RuntimeNode,
    RuntimePathContract,
)

ROOT = Path(__file__).resolve().parents[2]
LEGACY_RUN = ROOT / "runs/current-dataflow-p5-streamed-short-20261007-online"
PAIRED_RUN = ROOT / "runs/current-dataflow-p5-paired-20261007-online"
P4_RUN = ROOT / "runs/p4-shift-fuzz-20261007-online"

RAM_KEY = (15, 0)
REGISTER_KEY = (16, 0)
LEGACY_KEYS = ((0, 0), (2, 0), (4, 0), (5, 0), (6, 0), (10, 0), (11, 0),
               (12, 0), (13, 0))
SYNTHETIC_GRAPH_SHA256 = "a" * 64
BOOTSTRAP = 1
OBSERVATION = 2

TRANSACTION = {"channel_id": "data", "execution_id": "local-execution",
               "source_component": "cpu", "source_epoch": 0,
               "source_sequence": 7, "testcase_id": "ibex-dual-source-stream"}
TRANSACTION_REPR = ("TransactionKey(execution_id='local-execution', "
                    "testcase_id='ibex-dual-source-stream', "
                    "source_component='cpu', source_epoch=0, channel_id='data', "
                    "source_sequence=7)")


# ------------------------------------------------------------------- helpers


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
        for index, row in enumerate(self._rows):
            if row[0] == name:
                return index
        raise KeyError(name)

    def remove(self, name):
        self._rows.pop(self.index(name))
        self._built = None
        return self

    def mutate(self, name, **changes):
        self._rows[self.index(name)][1] = {**self._rows[self.index(name)][1], **changes}
        self._built = None
        return self

    @property
    def ids(self):
        return {row[0]: index + 1 for index, row in enumerate(self._rows)}

    @property
    def events(self):
        if self._built is None:
            ids = self.ids
            self._built = [self._resolve({**row[1], "event_id": position + 1}, ids)
                           for position, row in enumerate(self._rows)]
        return [dict(event) for event in self._built]

    def _resolve(self, value, ids):
        if isinstance(value, str) and value.startswith("@"):
            return ids[value[1:]]
        if isinstance(value, dict):
            return {key: self._resolve(item, ids) for key, item in value.items()}
        if isinstance(value, list):
            return [self._resolve(item, ids) for item in value]
        return value


def _provenance(*candidates):
    return {"schema_version": "event_source_provenance.v1",
            "observed_case": None, "origin_status": "unknown",
            "origin_admission_ids": [], "invalid_origin_references": 0,
            "unknown_writer_ids": [],
            "edge_candidates": [{"rule_index": key[0], "prerequisite_index": key[1]}
                                for key in candidates],
            "resource": None, "proof_scope": "observation_only"}


def _node(node_id, component, port):
    return RuntimeNode(node_id, component, "physical", port=port,
                       bit_offset=0, width=1)


def _contract():
    nodes = (RuntimeNode("cpu.online_instruction", "cpu", "logical"),
             RuntimeNode(ONLINE_RAM_VERSION_NODE, "cpu", "logical"),
             RuntimeNode(ONLINE_GPIO_REGISTER_VERSION_NODE, "gpio_a", "logical"))
    edges = (RuntimeEdgeContract(*RAM_KEY, relation="persistent_state",
                                 resource_component="cpu", resource_id="ram"),
             RuntimeEdgeContract(*REGISTER_KEY, relation="persistent_state",
                                 resource_component="gpio_a", resource_id="out"))
    return RuntimePathContract(SYNTHETIC_GRAPH_SHA256, nodes, edges)


def _endpoints():
    return {
        RAM_KEY: EdgeEndpoints(_node("cpu.online_instruction", "cpu", "ram"),
                               _node(ONLINE_RAM_VERSION_NODE, "cpu", "ram")),
        REGISTER_KEY: EdgeEndpoints(
            _node(ONLINE_GPIO_REGISTER_VERSION_NODE, "gpio_a", "out"),
            _node(ONLINE_GPIO_REGISTER_VERSION_NODE, "gpio_a", "out")),
    }


def _bootstrap(journal):
    journal.add("bootstrap", {
        "kind": "local_tick_sample", "component": "cpu", "local_tick": 1,
        "outputs": {"ram": 0}, "producer_event_id": BOOTSTRAP,
        "provenance": _provenance()})
    journal.add("write_access", {
        "kind": "gpio_apb_access", "component": "gpio_a", "local_tick": 2,
        "access_id": "gpio-access:gpio_a:0:7", "producer_event_id": BOOTSTRAP,
        "provenance": _provenance()})
    return journal


def _ram_write(journal, *, version=(0, 7), generation=0, byte_offset=128,
               width_bytes=4, byte_enable=15, name="ram_write"):
    return journal.add(name, {
        "kind": "memory_write", "component": ONLINE_RAM_RESOURCE_COMPONENT,
        "memory_id": ONLINE_RAM_RESOURCE_ID, "address": 0x20000,
        "byte_offset": byte_offset, "width_bytes": width_bytes,
        "byte_enable": byte_enable, "generation": generation, "version": list(version),
        "value": 0x11223344, "transaction": dict(TRANSACTION),
        "producer_event_id": journal.ref("bootstrap"),
        "provenance": _provenance(RAM_KEY)})


def _ram_read(journal, *, writer_event_ids, versions, generation=0,
              byte_offset=128, width_bytes=4, name="ram_read",
              writer_kinds=("STORE",) * 4, candidates=(RAM_KEY,)):
    return journal.add(name, {
        "kind": "memory_read", "component": ONLINE_RAM_RESOURCE_COMPONENT,
        "memory_id": ONLINE_RAM_RESOURCE_ID, "address": 0x20000,
        "byte_offset": byte_offset, "width_bytes": width_bytes,
        "generation": generation, "versions": [list(item) for item in versions],
        "writer_event_ids": list(writer_event_ids),
        "writer_kinds": list(writer_kinds), "value": 0x11223344,
        "transaction": dict(TRANSACTION),
        "producer_event_id": journal.ref("bootstrap"),
        "provenance": _provenance(*candidates)})


def _register_commit(journal, *, version=41, name="register_commit"):
    return journal.add(name, {
        "kind": "gpio_register_commit",
        "component": ONLINE_GPIO_REGISTER_RESOURCE_COMPONENT,
        "register": ONLINE_GPIO_REGISTER_RESOURCE_ID, "status": "observed",
        "access_id": "gpio-access:gpio_a:0:7", "operation": "overwrite",
        "producer_event_id": journal.ref("write_access"),
        "bit_resources": [{
            "component": ONLINE_GPIO_REGISTER_RESOURCE_COMPONENT,
            "register": ONLINE_GPIO_REGISTER_RESOURCE_ID, "bit": 0,
            "version": version, "value": 1, "observation_event_id": OBSERVATION,
            "local_tick": 2, "reset_epoch": 0}],
        "provenance": _provenance(REGISTER_KEY)})


def _register_read(journal, *, version=41, observation=OBSERVATION, name="register_read"):
    row = {"component": ONLINE_GPIO_REGISTER_RESOURCE_COMPONENT,
           "register": ONLINE_GPIO_REGISTER_RESOURCE_ID, "bit": 0,
           "version": version, "value": 1}
    if observation is not None:
        row["observation_event_id"] = observation
    return journal.add(name, {
        "kind": "gpio_register_read",
        "component": ONLINE_GPIO_REGISTER_RESOURCE_COMPONENT,
        "register": ONLINE_GPIO_REGISTER_RESOURCE_ID, "status": "observed",
        "access_id": "gpio-access:gpio_a:0:8", "read_value": 1,
        "producer_event_id": journal.ref("write_access"),
        "bit_resources": [row], "provenance": _provenance(REGISTER_KEY)})


def _ram_journal():
    journal = _bootstrap(_Journal())
    _ram_write(journal)
    _ram_read(journal, writer_event_ids=[journal.ref("ram_write")] * 4,
              versions=[[0, 7]] * 4)
    return journal


def _register_journal():
    journal = _bootstrap(_Journal())
    _register_commit(journal)
    _register_read(journal)
    return journal


def _consume(events, *, contract=None, endpoints=None, resolver=None, **kwargs):
    consumer = EdgeProvenanceConsumer(contract or _contract(),
                                      endpoints=_endpoints() if endpoints is None
                                      else endpoints,
                                      candidate_resolver=resolver, **kwargs)
    consumer.ingest(events)
    return consumer.report()


def _row(report, key):
    rows = {(row["rule_index"], row["prerequisite_index"]): row
            for row in report["edges"]}
    return rows[key]


def _hop(row, hop_id):
    for hop in row["hops"]:
        if hop["hop_id"] == hop_id:
            return hop
    return None


# --------------------------------------------------------------- declaration


def test_online_contract_appends_exactly_two_persistent_state_edges():
    contract = make_ibex_pulp_dual_source_online_decoder().runtime_contract
    declarations = {edge.key: edge for edge in contract.edges}
    assert sorted(declarations) == sorted([*LEGACY_KEYS, RAM_KEY, REGISTER_KEY])
    ram, register = declarations[RAM_KEY], declarations[REGISTER_KEY]
    assert (ram.relation, ram.resource_component, ram.resource_id) == (
        "persistent_state", ONLINE_RAM_RESOURCE_COMPONENT, ONLINE_RAM_RESOURCE_ID)
    assert (register.relation, register.resource_component, register.resource_id) == (
        "persistent_state", ONLINE_GPIO_REGISTER_RESOURCE_COMPONENT,
        ONLINE_GPIO_REGISTER_RESOURCE_ID)
    node_ids = {node.node_id for node in contract.nodes}
    assert {ONLINE_RAM_VERSION_NODE, ONLINE_GPIO_REGISTER_VERSION_NODE} <= node_ids


def test_appended_rows_leave_every_legacy_rule_and_edge_byte_identical():
    """The appended rows extend the declaration; they never rewrite a legacy row."""
    decoder = make_ibex_pulp_dual_source_online_decoder()
    contract = decoder.runtime_contract
    recorded = json.loads(
        (LEGACY_RUN / "online_session_manifest.json").read_text(encoding="utf-8")
    )["runtime_paths"]
    graph = recorded["declaration"]["graph"]
    current = decoder.graph.edge_document()
    assert current["sources"] == graph["sources"]
    assert current["rules"][:len(graph["rules"])] == graph["rules"]
    assert current["edges"][:len(graph["edges"])] == graph["edges"]
    legacy = {edge.key: edge for edge in contract.edges if edge.key in LEGACY_KEYS}
    assert len(legacy) == 9
    for row in recorded["declaration"]["contract"]["edges"]:
        key = (row["rule_index"], row["prerequisite_index"])
        assert legacy[key] == RuntimeEdgeContract(**row)


def test_appended_edges_are_off_every_declared_path():
    """No enumerated declared path selects an appended rule, so no path moves."""
    decoder = make_ibex_pulp_dual_source_online_decoder()
    selected = set()
    for _direction, path in decoder.runtime_paths:
        selected.update((edge.rule_index, edge.prerequisite_index) for edge in path.edges)
    assert selected and not (selected & {RAM_KEY, REGISTER_KEY})
    assert selected == {(index, 0) for index in range(15)}
    assert len(decoder.runtime_paths) == 2


def test_legacy_prefix_join_accepts_the_frozen_run(tmp_path):
    if not LEGACY_RUN.is_dir():  # pragma: no cover - frozen artifact absent
        pytest.skip(f"frozen trace missing: {LEGACY_RUN}")
    join, endpoints = legacy_prefix_join(LEGACY_RUN)
    assert join.appended_edge_keys == (RAM_KEY, REGISTER_KEY)
    assert join.legacy_edge_keys == LEGACY_KEYS
    assert set(join.checks) == {
        "recorded_graph_is_exact_prefix_of_wiring_graph",
        "legacy_contract_edges_unchanged",
        "appended_rule_indices_beyond_recorded_rules",
        "declared_resource_component_registered_in_run_topology"}
    assert set(endpoints) == {RAM_KEY, REGISTER_KEY}
    assert endpoints[RAM_KEY].source.port == ONLINE_RAM_RESOURCE_ID
    assert endpoints[REGISTER_KEY].source.port == ONLINE_GPIO_REGISTER_RESOURCE_ID
    assert [row["resolution"] for row in join.endpoint_evidence] == \
        ["declaration_endpoints"] * 2


def test_legacy_prefix_join_rejects_a_tampered_recorded_graph(tmp_path):
    if not LEGACY_RUN.is_dir():  # pragma: no cover - frozen artifact absent
        pytest.skip(f"frozen trace missing: {LEGACY_RUN}")
    manifest = json.loads(
        (LEGACY_RUN / "online_session_manifest.json").read_text(encoding="utf-8"))
    manifest["runtime_paths"]["declaration"]["graph"]["rules"][4]["target"] = \
        "online.tampered.target"
    run = tmp_path / "tampered-run"
    run.mkdir()
    (run / "online_session_manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError):
        legacy_prefix_join(run)


def test_legacy_prefix_join_rejects_a_declared_edge_swap(tmp_path):
    if not LEGACY_RUN.is_dir():  # pragma: no cover - frozen artifact absent
        pytest.skip(f"frozen trace missing: {LEGACY_RUN}")
    manifest = json.loads(
        (LEGACY_RUN / "online_session_manifest.json").read_text(encoding="utf-8"))
    compiled = manifest["runtime_paths"]
    edges = compiled["declaration"]["contract"]["edges"]
    for row in edges:
        if row["relation"] == "direct_binding":
            row["relation"] = "mmio_route"
            row.update(initiator_component="cpu", device_id="gpio_b",
                       base=0x40000000, size=0x1000)
            break
    run = tmp_path / "swapped-run"
    run.mkdir()
    (run / "online_session_manifest.json").write_text(json.dumps(manifest),
                                                      encoding="utf-8")
    with pytest.raises((ValueError, KeyError)):
        legacy_prefix_join(run)


# ------------------------------------------------- RAM judgement (synthetic)


def test_ram_write_then_read_naming_the_write_event_id_is_certified():
    journal = _ram_journal()
    ids = journal.ids
    row = _row(_consume(journal.events), RAM_KEY)
    assert row["status"] == "certified"
    assert row["missing"] == []
    assert [hop["hop_id"] for hop in row["hops"]] == [PRODUCER, DELIVERY, CONSUMER]
    assert _hop(row, PRODUCER)["event_id"] == ids["ram_write"] == _hop(row, DELIVERY)["event_id"]
    assert _hop(row, PRODUCER)["key"] == "resource_write"
    assert _hop(row, PRODUCER)["byte_enable"] == 15
    assert _hop(row, PRODUCER)["write_event_id"] == ids["ram_write"]
    assert _hop(row, DELIVERY)["key"] == "resource_version"
    assert _hop(row, DELIVERY)["shared_event"] is True
    assert _hop(row, CONSUMER)["key"] == "writer_event_id+version"
    assert _hop(row, CONSUMER)["write_event_id"] == ids["ram_write"]
    assert _hop(row, CONSUMER)["writer_reference_forms"] == ["event_id"]
    assert row["persistent_state"]["reader_reference_forms"]["event_id"] == 4
    assert row["persistent_state"]["missing_fields"] == []
    assert row["persistent_state"]["rejected_candidates"] == []


def test_ram_read_naming_the_writers_transaction_key_is_certified():
    journal = _ram_journal()
    journal.mutate("ram_read", writer_event_ids=[TRANSACTION_REPR] * 4)
    row = _row(_consume(journal.events), RAM_KEY)
    assert row["status"] == "certified"
    assert _hop(row, CONSUMER)["key"] == "writer_version+transaction_key"
    assert _hop(row, CONSUMER)["writer_reference_forms"] == ["transaction_key"]
    assert row["persistent_state"]["reader_reference_forms"]["transaction_key"] == 4


def test_ram_read_naming_only_the_boot_image_placeholder_is_incomplete():
    """A string placeholder names no write record, so it never certifies."""
    journal = _ram_journal()
    journal.mutate("ram_read", writer_event_ids=["initial-image"] * 4,
                   writer_kinds=["INITIAL_IMAGE"] * 4)
    row = _row(_consume(journal.events), RAM_KEY)
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]
    assert [hop["hop_id"] for hop in row["hops"]] == [PRODUCER, DELIVERY]
    block = row["persistent_state"]
    assert block["reader_reference_forms"]["placeholder"] == 1
    assert any("placeholder" in note for note in block["missing_fields"])


def test_ram_read_with_a_different_version_is_incomplete():
    journal = _ram_journal()
    journal.mutate("ram_read", versions=[[0, 9]] * 4)
    row = _row(_consume(journal.events), RAM_KEY)
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]
    assert any("version" in note for note in row["persistent_state"]["missing_fields"])


def test_ram_read_outside_the_enabled_bytes_is_incomplete():
    journal = _bootstrap(_Journal())
    _ram_write(journal, byte_enable=0b0011)
    _ram_read(journal, writer_event_ids=[journal.ref("ram_write")] * 4,
              versions=[[0, 7]] * 4)
    row = _row(_consume(journal.events), RAM_KEY)
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]
    assert any("byte_enable" in note
               for note in row["persistent_state"]["missing_fields"])


def test_ram_read_with_a_different_generation_is_incomplete():
    journal = _ram_journal()
    journal.mutate("ram_read", generation=1)
    row = _row(_consume(journal.events), RAM_KEY)
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]
    assert "memory_read.generation" in row["persistent_state"]["missing_fields"]


def test_ram_write_without_an_exact_version_never_becomes_a_producer():
    journal = _ram_journal()
    journal.mutate("ram_write", version=None)
    row = _row(_consume(journal.events), RAM_KEY)
    assert row["status"] == "incomplete"
    assert row["missing"] == [PRODUCER, DELIVERY, CONSUMER]
    assert "memory_write.version[generation, commit_sequence]" in \
        row["persistent_state"]["missing_fields"]


def test_ram_read_joining_a_retained_earlier_write_is_certified():
    """A read may name any retained write of the resource, not only the first."""
    journal = _bootstrap(_Journal())
    _ram_write(journal, version=(0, 7), byte_offset=128)
    _ram_write(journal, version=(0, 8), byte_offset=512, name="second_write")
    _ram_read(journal, writer_event_ids=[journal.ref("ram_write")] * 4,
              versions=[[0, 7]] * 4)
    row = _row(_consume(journal.events), RAM_KEY)
    assert row["status"] == "certified"
    assert _hop(row, PRODUCER)["event_id"] == journal.ids["ram_write"]
    assert _hop(row, DELIVERY)["event_id"] == journal.ids["ram_write"]
    assert _hop(row, CONSUMER)["version"] == [0, 7]


# -------------------------------------------- register judgement (synthetic)


def test_register_commit_then_read_of_the_same_version_is_certified():
    journal = _register_journal()
    ids = journal.ids
    row = _row(_consume(journal.events), REGISTER_KEY)
    assert row["status"] == "certified"
    assert row["missing"] == []
    assert [hop["hop_id"] for hop in row["hops"]] == [PRODUCER, DELIVERY, CONSUMER]
    assert _hop(row, PRODUCER)["key"] == "register_commit"
    assert _hop(row, PRODUCER)["event_id"] == ids["register_commit"]
    assert _hop(row, DELIVERY)["key"] == "register_version"
    assert _hop(row, DELIVERY)["bits"][0]["version"] == 41
    assert _hop(row, CONSUMER)["key"] == "register_version_reference"
    reference = _hop(row, CONSUMER)["references"][0]
    assert (reference["field"], reference["bit"], reference["version"],
            reference["observation_event_id"]) == ("bit_resources", 0, 41, OBSERVATION)
    assert row["persistent_state"]["writer_records"] == 1
    assert row["persistent_state"]["reader_records"] == 1


def test_register_read_without_observation_event_id_is_incomplete():
    journal = _register_journal()
    journal.mutate("register_read", bit_resources=[
        {"component": ONLINE_GPIO_REGISTER_RESOURCE_COMPONENT,
         "register": ONLINE_GPIO_REGISTER_RESOURCE_ID, "bit": 0,
         "version": 41, "value": 1}])
    row = _row(_consume(journal.events), REGISTER_KEY)
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]
    assert "gpio_register_read.bit_resources[].version+observation_event_id" in \
        row["persistent_state"]["missing_fields"]


def test_register_read_with_a_different_version_is_incomplete():
    journal = _register_journal()
    journal.mutate("register_read", bit_resources=[
        {"component": ONLINE_GPIO_REGISTER_RESOURCE_COMPONENT,
         "register": ONLINE_GPIO_REGISTER_RESOURCE_ID, "bit": 0,
         "version": 42, "value": 1, "observation_event_id": OBSERVATION}])
    row = _row(_consume(journal.events), REGISTER_KEY)
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]


def test_register_read_of_a_different_observation_is_incomplete():
    journal = _register_journal()
    journal.mutate("register_read", bit_resources=[
        {"component": ONLINE_GPIO_REGISTER_RESOURCE_COMPONENT,
         "register": ONLINE_GPIO_REGISTER_RESOURCE_ID, "bit": 0,
         "version": 41, "value": 1, "observation_event_id": BOOTSTRAP}])
    row = _row(_consume(journal.events), REGISTER_KEY)
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]


def test_register_commit_without_bit_versions_is_not_a_producer():
    journal = _register_journal()
    journal.mutate("register_commit", bit_resources=[
        {"component": ONLINE_GPIO_REGISTER_RESOURCE_COMPONENT,
         "register": ONLINE_GPIO_REGISTER_RESOURCE_ID, "bit": 0, "value": 1}])
    row = _row(_consume(journal.events), REGISTER_KEY)
    assert row["status"] == "incomplete"
    assert row["missing"] == [PRODUCER, DELIVERY, CONSUMER]


def test_register_edge_without_any_register_record_is_unknown():
    journal = _bootstrap(_Journal())
    _ram_write(journal)
    _ram_read(journal, writer_event_ids=[journal.ref("ram_write")] * 4,
              versions=[[0, 7]] * 4)
    report = _consume(journal.events)
    row = _row(report, REGISTER_KEY)
    assert row["status"] == "unknown"
    assert row["reason"] == "no_observable_hop"
    assert row["persistent_state"]["writer_records"] == 0
    assert row["persistent_state"]["reader_records"] == 0
    assert "(gpio_a, out)" in row["persistent_state"]["unsupported_shape_reason"]
    assert _row(report, RAM_KEY)["status"] == "certified"


# ------------------------------------------------- fail-closed and attribution


def test_appended_edge_without_resolved_endpoints_is_unknown():
    """Declaring an edge is not evidence: no endpoints means no claim."""
    row = _row(_consume(_ram_journal().events, endpoints={}), RAM_KEY)
    assert row["status"] == "unknown"
    assert row["hops"] == []
    assert row["unsupported_shape_reason"] == \
        "no resolved physical endpoints for this declared edge"
    assert row["proof_scope"] == "no_observable_shape"


def test_candidate_resolver_adds_candidates_without_dropping_journal_ones():
    journal = _bootstrap(_Journal())
    _ram_write(journal)
    _ram_read(journal, writer_event_ids=[journal.ref("ram_write")] * 4,
              versions=[[0, 7]] * 4, candidates=())
    calls = []

    def resolver(event):
        calls.append(event.get("event_id"))
        if event.get("kind") in ("memory_write", "memory_read"):
            return ({"rule_index": RAM_KEY[0], "prerequisite_index": RAM_KEY[1]},)
        return ()

    row = _row(_consume(journal.events, resolver=resolver), RAM_KEY)
    assert row["status"] == "certified"
    # The resolver is consulted once while registering hints and once while
    # observing the same event; it must stay pure and cheap.
    assert len(calls) == 2 * len(journal.events)
    # The resolver only adds declared identities; it can never create one.
    unknown = {"rule_index": 99, "prerequisite_index": 0}
    assert resource_candidate_resolver(_contract(), (RAM_KEY,))(unknown) == ()


def test_candidate_resolver_never_attributes_an_undeclared_resource():
    resolver = resource_candidate_resolver(_contract(), (RAM_KEY, REGISTER_KEY))
    assert resolver({"kind": "memory_read", "component": "cpu", "memory_id": "other"}) == ()
    assert resolver({"kind": "memory_read", "component": "gpio_b",
                     "memory_id": "ram"}) == ()
    assert resolver({"kind": "gpio_register_read", "component": "gpio_b",
                     "register": "out"}) == ()
    assert resolver({"kind": "local_tick_sample", "component": "cpu"}) == ()
    assert resolver({"kind": "memory_read", "component": "cpu",
                     "memory_id": "ram"}) == (
        {"rule_index": RAM_KEY[0], "prerequisite_index": RAM_KEY[1]},)


def test_register_read_citing_the_commit_as_a_dependency_is_certified():
    journal = _register_journal()
    journal.mutate("register_read", bit_resources=[
        {"component": ONLINE_GPIO_REGISTER_RESOURCE_COMPONENT,
         "register": ONLINE_GPIO_REGISTER_RESOURCE_ID, "bit": 0,
         "version": 41, "value": 1, "observation_event_id": OBSERVATION,
         "dependencies": [
             {"component": ONLINE_GPIO_REGISTER_RESOURCE_COMPONENT,
              "register": ONLINE_GPIO_REGISTER_RESOURCE_ID, "bit": 0,
              "version": 41, "observation_event_id": OBSERVATION}]}])
    row = _row(_consume(journal.events), REGISTER_KEY)
    assert row["status"] == "certified"
    assert [item["field"] for item in _hop(row, CONSUMER)["references"]] == \
        ["bit_resources", "bit_resources[].dependencies"]


def test_register_read_that_precedes_its_commit_never_certifies():
    journal = _bootstrap(_Journal())
    _register_read(journal)
    _register_commit(journal)
    row = _row(_consume(journal.events), REGISTER_KEY)
    assert row["status"] == "incomplete"
    assert row["missing"] == [CONSUMER]


# -------------------------------------------------------------- boundedness


def test_retained_write_history_and_notes_stay_bounded():
    journal = _bootstrap(_Journal())
    for index in range(_ANCHOR_LIMIT + 40):
        _ram_write(journal, version=(0, index + 1), byte_offset=128 + 4 * index,
                   name=f"write-{index}")
    consumer = EdgeProvenanceConsumer(_contract(), endpoints=_endpoints())
    consumer.ingest(journal.events)
    report = consumer.report()
    row = _row(report, RAM_KEY)
    assert row["status"] == "incomplete"
    block = row["persistent_state"]
    assert block["writer_records"] == _ANCHOR_LIMIT + 40
    assert block["dropped_anchors"] == 40
    assert len(block["missing_fields"]) <= 8
    assert any("retained writer records" in note for note in block["missing_fields"])
    assert consumer.pending_count <= 4096
    assert consumer.pending_hint_count <= max(1024, 4096 * 64)


def test_evicted_persistent_edge_never_recovers_credit():
    journal = _bootstrap(_Journal())
    _ram_write(journal, name="ram_write")
    _register_commit(journal)
    _register_read(journal)
    _ram_read(journal, writer_event_ids=[journal.ref("ram_write")] * 4,
              versions=[[0, 7]] * 4)
    consumer = EdgeProvenanceConsumer(_contract(), endpoints=_endpoints(),
                                      max_pending=1)
    consumer.ingest(journal.events)
    report = consumer.report()
    assert consumer.evictions == 1
    evicted = _row(report, RAM_KEY)
    assert evicted["status"] == "incomplete"
    assert evicted["reason"] == "pending_capacity"
    assert _row(report, REGISTER_KEY)["status"] == "certified"
    assert [row["rule_index"] for row in report["evictions"]] == [RAM_KEY[0]]


def test_event_gap_reset_never_restores_credit():
    journal = _bootstrap(_Journal())
    _ram_write(journal)
    for index in range(6):
        journal.add(f"tick-{index}", {
            "kind": "local_tick_sample", "component": "cpu", "local_tick": 10 + index,
            "outputs": {"ram": 0}, "producer_event_id": journal.ref("bootstrap"),
            "provenance": _provenance()})
    _ram_read(journal, writer_event_ids=[journal.ref("ram_write")] * 4,
              versions=[[0, 7]] * 4)
    consumer = EdgeProvenanceConsumer(_contract(), endpoints=_endpoints(),
                                      max_event_gap=4)
    consumer.ingest(journal.events)
    row = _row(consumer.report(), RAM_KEY)
    assert consumer.resets >= 1
    assert row["status"] == "incomplete"
    assert row["reason"] == "event_gap_reset"


# ---------------------------------------------------------------- real trace


@pytest.fixture(scope="module")
def legacy_run():
    if not LEGACY_RUN.is_dir():  # pragma: no cover - frozen artifact absent
        pytest.skip(f"frozen trace missing: {LEGACY_RUN}")
    return LEGACY_RUN


def test_real_streamed_run_keeps_nine_legacy_edges_and_certifies_the_ram_edge(
        legacy_run):
    report = persistent_state_report(legacy_run)
    assert report["legacy"]["counts"] == {"total": 9, "certified": 8,
                                          "incomplete": 1, "unknown": 0,
                                          "rejected": 0, "evicted": 0}
    assert report["extended"]["counts"] == {"total": 11, "certified": 9,
                                            "incomplete": 1, "unknown": 1,
                                            "rejected": 0, "evicted": 0}
    assert report["legacy_edges_unchanged"] is True
    legacy_rows = {(row["rule_index"], row["prerequisite_index"]): row
                   for row in report["legacy"]["edges"]}
    extended_rows = {(row["rule_index"], row["prerequisite_index"]): row
                     for row in report["extended"]["edges"]}
    for key, row in legacy_rows.items():
        assert extended_rows[key] == row
    ram = extended_rows[RAM_KEY]
    assert ram["status"] == "certified"
    assert _hop(ram, PRODUCER)["version"] == _hop(ram, CONSUMER)["version"]
    assert _hop(ram, CONSUMER)["writer_reference_forms"] == ["transaction_key"]
    assert ram["persistent_state"]["reader_reference_forms"]["event_id"] == 0
    assert ram["persistent_state"]["reader_reference_forms"]["transaction_key"] > 0
    register = extended_rows[REGISTER_KEY]
    assert register["status"] == "unknown"
    assert register["persistent_state"]["writer_records"] == 0
    assert "(gpio_a, out)" in register["persistent_state"]["unsupported_shape_reason"]


def test_real_streamed_run_never_names_a_write_event_id(legacy_run):
    """The real read snapshot carries writer *names*, never an event id."""
    numeric = string = 0
    for event in TraceEventStream(legacy_run).events():
        if event.get("kind") != "memory_read":
            continue
        for reference in event.get("writer_event_ids") or ():
            if type(reference) is int:
                numeric += 1
            elif type(reference) is str:
                string += 1
    assert numeric == 0
    assert string > 0


def test_real_paired_run_is_a_legacy_prefix_without_reading_its_trace():
    if not PAIRED_RUN.is_dir():  # pragma: no cover - frozen artifact absent
        pytest.skip(f"frozen trace missing: {PAIRED_RUN}")
    join, endpoints = legacy_prefix_join(PAIRED_RUN)
    assert join.appended_edge_keys == (RAM_KEY, REGISTER_KEY)
    assert endpoints[RAM_KEY].target.component == ONLINE_RAM_RESOURCE_COMPONENT
    assert endpoints[REGISTER_KEY].source.component == \
        ONLINE_GPIO_REGISTER_RESOURCE_COMPONENT


def test_real_p4_run_is_a_legacy_prefix_without_reading_its_trace():
    if not P4_RUN.is_dir():  # pragma: no cover - frozen artifact absent
        pytest.skip(f"frozen trace missing: {P4_RUN}")
    join, endpoints = legacy_prefix_join(P4_RUN)
    assert join.appended_edge_keys == (RAM_KEY, REGISTER_KEY)
    assert join.legacy_graph_sha256 == \
        "58471d1e3c55652b4570cbdc2a782c060c9ac21427830be22a9ec4a9ce8a48ac"
