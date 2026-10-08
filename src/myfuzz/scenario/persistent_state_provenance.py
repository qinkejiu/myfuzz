"""Per-declared-edge provenance for the appended ``persistent_state`` edges.

The two RAM/register version edges appended to the Ibex + dual PULP GPIO online
declaration
(:data:`myfuzz.scenario.ibex_pulp_dual_source.ONLINE_RAM_VERSION_NODE` and
:data:`~myfuzz.scenario.ibex_pulp_dual_source.ONLINE_GPIO_REGISTER_VERSION_NODE`)
are *new* declarations. Every saved run predates them: its manifest carries the
legacy declaration only, and no event of its journal names the appended edge
identity. Measuring those edges on such a run therefore needs three explicit,
checkable joins -- and this module performs exactly those, without ever
inventing a fact:

1. **declaration join** -- the run's recorded ``declaration.graph`` must be an
   *exact prefix* of the current wiring graph (same ``schema_version``, same
   sources, same rule and edge rows in the same order) and every edge of the
   run's recorded contract must equal the current contract's edge of the same
   key. The appended keys must lie beyond the run's recorded rule count, so the
   append can never have redefined a rule the run already used.
2. **resource join** -- each appended ``persistent_state`` declaration names a
   component and a resource; the run's own recorded topology must list that
   component, and the endpoint pair is taken from the *current* wiring graph
   rule (prerequisite, target) plus that component, mirroring
   :func:`myfuzz.scenario.edge_provenance.edge_endpoints_from_compiled`'s
   persistent branch. The run's compiled ``paths`` cannot select the appended
   edges (they did not exist), so this is the only honest resolution available,
   and it is reported as ``declaration_endpoints`` with its evidence.
3. **event join** -- one event of the run's trace is attributed to an appended
   edge only when the event itself names that edge's declared resource
   (``memory_write``/``memory_read`` with the declared ``memory_id``,
   ``gpio_register_commit``/``gpio_register_read`` with the declared
   ``register``). The attribution is the only thing added; every hop is then
   judged by the same fail-closed consumer, which still requires an exact
   version reference and rejects placeholders.

The module renders both the run's *own* legacy report and the extended report
from one streaming pass over the same events, so the unchanged legacy edges are
compared inside a single pass rather than across two reads.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import json
from pathlib import Path

from .acceptance_metrics import TraceEventStream
from .edge_provenance import (EdgeEndpoints, EdgeProvenanceConsumer,
                              edge_provenance_session)
from .runtime_path_contract import RuntimeNode

PERSISTENT_STATE_REPORT_SCHEMA = "persistent_state_provenance_report.v1"

#: Observed writer/reader record kinds of the two declared resource families.
_MEMORY_SHAPE_KINDS = frozenset(("memory_write", "memory_write_commit",
                                 "memory_initialization", "memory_read"))
_REGISTER_SHAPE_KINDS = frozenset(("gpio_register_commit", "gpio_register_read",
                                   "gpio_target_receipt"))


@dataclass(frozen=True)
class PersistentStateJoin:
    """The exact declaration/resource join that admits one run's measurement."""

    run_dir: str
    legacy_contract_sha256: str
    legacy_graph_sha256: str
    contract_sha256: str
    graph_sha256: str
    legacy_edge_keys: tuple
    appended_edge_keys: tuple
    endpoint_evidence: tuple
    checks: tuple

    def document(self) -> dict:
        return {"run_dir": self.run_dir,
                "legacy_contract_sha256": self.legacy_contract_sha256,
                "legacy_graph_sha256": self.legacy_graph_sha256,
                "contract_sha256": self.contract_sha256,
                "graph_sha256": self.graph_sha256,
                "legacy_edge_keys": [list(key) for key in self.legacy_edge_keys],
                "appended_edge_keys": [list(key) for key in self.appended_edge_keys],
                "endpoint_evidence": [dict(row) for row in self.endpoint_evidence],
                "checks": list(self.checks)}


def _wiring_declaration():
    """The current online wiring contract and its frozen declared graph."""
    from .ibex_pulp_dual_source import make_ibex_pulp_dual_source_online_decoder
    decoder = make_ibex_pulp_dual_source_online_decoder()
    contract = decoder.runtime_contract
    graph = decoder.graph
    return contract, graph


def _recorded_declaration(run_dir) -> dict:
    manifest_path = Path(run_dir) / "online_session_manifest.json"
    if not manifest_path.is_file():
        raise ValueError(f"run directory has no session manifest: {run_dir}")
    return json.loads(manifest_path.read_text(encoding="utf-8"))["runtime_paths"]


def legacy_prefix_join(run_dir) -> tuple[PersistentStateJoin, dict]:
    """Verify the run predates *only* the appended rows of this same wiring.

    Returns ``(join, appended_endpoints)``. Every claim behind the join is an
    equality check on the run's own recorded declaration; a run compiled from
    any other wiring raises instead of being measured.
    """
    legacy_contract, _legacy_endpoints = edge_provenance_session(run_dir)
    contract, graph = _wiring_declaration()
    compiled = _recorded_declaration(run_dir)
    recorded = compiled["declaration"]["graph"]
    current = graph.edge_document()
    if recorded.get("schema_version") != current["schema_version"]:
        raise ValueError("recorded dependency graph schema differs from this wiring")
    if recorded.get("sources") != current["sources"]:
        raise ValueError("recorded dependency graph sources differ from this wiring")
    recorded_rules = recorded.get("rules")
    recorded_edges = recorded.get("edges")
    if (not isinstance(recorded_rules, list) or not isinstance(recorded_edges, list)
            or current["rules"][:len(recorded_rules)] != recorded_rules
            or current["edges"][:len(recorded_edges)] != recorded_edges):
        raise ValueError("recorded dependency graph is not a prefix of this wiring graph")
    current_by_key = {edge.key: edge for edge in contract.edges}
    legacy_keys = tuple(sorted(edge.key for edge in legacy_contract.edges))
    for key in legacy_keys:
        if key not in current_by_key or current_by_key[key] != next(
                edge for edge in legacy_contract.edges if edge.key == key):
            raise ValueError(f"declared edge {key} changed since this run")
    appended_keys = tuple(sorted(key for key in current_by_key if key not in legacy_keys))
    if not appended_keys:
        raise ValueError("this wiring declares no appended edge to measure")
    recorded_rule_count = len(recorded_rules)
    if any(key[0] < recorded_rule_count for key in appended_keys):
        raise ValueError("an appended edge reuses a rule index the run already declared")
    topology = compiled["topology"]
    components = set(topology["components"])
    endpoints, evidence = {}, []
    nodes = {node.node_id: node.component for node in contract.nodes}
    rules = graph.ordered_rules
    for key in appended_keys:
        declaration = current_by_key[key]
        rule = rules[key[0]]
        if declaration.relation != "persistent_state":
            raise ValueError(f"appended edge {key} is not a persistent_state relation")
        prerequisite = rule.prerequisites[key[1]]
        target = rule.target
        if declaration.resource_component not in (nodes.get(prerequisite),
                                                 nodes.get(target)):
            raise ValueError(f"appended edge {key} resource is outside its declared edge")
        if declaration.resource_component not in components:
            raise ValueError(f"run topology does not register {declaration.resource_component}")
        endpoints[key] = EdgeEndpoints(
            RuntimeNode(prerequisite, declaration.resource_component, "physical",
                        port=declaration.resource_id, bit_offset=0, width=1),
            RuntimeNode(target, declaration.resource_component, "physical",
                        port=declaration.resource_id, bit_offset=0, width=1))
        evidence.append({"rule_index": key[0], "prerequisite_index": key[1],
                         "relation": declaration.relation,
                         "component": declaration.resource_component,
                         "resource_id": declaration.resource_id,
                         "prerequisite": prerequisite, "target": target,
                         "resolution": "declaration_endpoints"})
    return PersistentStateJoin(
        run_dir=str(run_dir), legacy_contract_sha256=legacy_contract.identity_sha256,
        legacy_graph_sha256=legacy_contract.graph_sha256,
        contract_sha256=contract.identity_sha256, graph_sha256=contract.graph_sha256,
        legacy_edge_keys=legacy_keys, appended_edge_keys=appended_keys,
        endpoint_evidence=tuple(evidence),
        checks=("recorded_graph_is_exact_prefix_of_wiring_graph",
                "legacy_contract_edges_unchanged",
                "appended_rule_indices_beyond_recorded_rules",
                "declared_resource_component_registered_in_run_topology")), endpoints


def _candidate(key) -> dict:
    return {"rule_index": key[0], "prerequisite_index": key[1]}


def resource_candidate_resolver(contract, keys):
    """Pure attribution of the observed resource shapes to appended edges.

    An event is attributed only when the event *itself* names the declared
    resource of that edge: its ``(component, memory_id)`` for the memory family
    or its ``(component, register)`` for the register family. Nothing else is
    inferred, and an event naming an undeclared resource is never attributed.
    """
    by_resource = {}
    for key in keys:
        declaration = next(edge for edge in contract.edges if edge.key == key)
        by_resource[(declaration.resource_component, declaration.resource_id)] = key

    def resolve(event):
        if not isinstance(event, Mapping):
            return ()
        kind = event.get("kind")
        component = event.get("component")
        if kind in _MEMORY_SHAPE_KINDS:
            key = by_resource.get((component, event.get("memory_id")))
            return () if key is None else (_candidate(key),)
        if kind in _REGISTER_SHAPE_KINDS:
            key = by_resource.get((component, event.get("register")))
            if key is None:
                rows = event.get("bit_resources")
                if isinstance(rows, list):
                    for row in rows:
                        if not isinstance(row, Mapping):
                            continue
                        key = by_resource.get((row.get("component"), row.get("register")))
                        if key is not None:
                            break
            return () if key is None else (_candidate(key),)
        return ()

    return resolve


def persistent_state_report(run_dir, *, max_pending: int = 4096,
                            max_event_gap: int = 65536,
                            chunk_chars: int | None = None) -> dict:
    """One streaming pass: the run's own report and the extended one.

    Returns ``{"schema_version", "join", "legacy", "extended", "legacy_edges_unchanged"}``
    where ``legacy`` is rendered from the run's *own* contract and endpoints
    (exactly what :func:`edge_provenance_report` would print) and ``extended``
    is rendered from the current wiring contract with the appended edges
    resolved and attributed as documented above.
    """
    join, appended_endpoints = legacy_prefix_join(run_dir)
    legacy_contract, legacy_endpoints = edge_provenance_session(run_dir)
    contract, _graph = _wiring_declaration()
    endpoints = dict(legacy_endpoints)
    endpoints.update(appended_endpoints)
    resolver = resource_candidate_resolver(contract, join.appended_edge_keys)
    kwargs = {"max_pending": max_pending, "max_event_gap": max_event_gap}
    legacy = EdgeProvenanceConsumer(legacy_contract, endpoints=legacy_endpoints, **kwargs)
    extended = EdgeProvenanceConsumer(contract, endpoints=endpoints,
                                      candidate_resolver=resolver, **kwargs)
    stream = (TraceEventStream(run_dir) if chunk_chars is None
              else TraceEventStream(run_dir, chunk_chars=chunk_chars))
    for event in stream.events():
        legacy.ingest((event,))
        extended.ingest((event,))
    legacy_report, extended_report = legacy.report(), extended.report()
    legacy_rows = {(row["rule_index"], row["prerequisite_index"]): row
                   for row in legacy_report["edges"]}
    extended_rows = {(row["rule_index"], row["prerequisite_index"]): row
                     for row in extended_report["edges"]}
    unchanged = all(extended_rows.get(key) == row for key, row in legacy_rows.items())
    return {"schema_version": PERSISTENT_STATE_REPORT_SCHEMA,
            "join": join.document(),
            "legacy": legacy_report, "extended": extended_report,
            "legacy_edges_unchanged": unchanged,
            "bounds": {"max_pending": max_pending, "max_event_gap": max_event_gap}}


__all__ = ["PERSISTENT_STATE_REPORT_SCHEMA", "PersistentStateJoin",
           "legacy_prefix_join", "resource_candidate_resolver",
           "persistent_state_report"]
