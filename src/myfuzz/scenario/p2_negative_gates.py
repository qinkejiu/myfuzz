"""P2 negative gates: declared path breaks that must fail before any RTL.

A fresh dual-source run declares its topology twice: the runtime path contract
(which edges the selected paths must use) and the wiring declaration (which
bindings, MMIO windows, ownership producers and IRQ pulses really exist).  This
module turns "cut A->B", "delete the IRQ binding", "wrong MMIO base", "wrong
MMIO target", "different edge identity" and "wrong declared producer" into
*trusted, declarative* variants of those two documents, and provides a
preflight executor that must reject them **before a harness is rendered or a
process exists**.

Evidence, not assertion:

* :class:`LaunchProbe` patches every render entry point, the harness build, the
  session constructors, ``subprocess`` and the filesystem writers for the scope
  of one preflight call, then reports how many times each effect was attempted.
  A rejected gate therefore carries "0 renders, 0 builds, 0 processes, 0
  factory calls" as data instead of a claim.
* The declaration-only topology (:func:`declared_topology`) is a runner-shaped
  object with no artifact, binary or process, so the *real*
  ``compile_runtime_path_contract`` checker runs against the declared topology
  and produces its own messages (``direct edge (2, 0) Binding matches=0`` and
  friends).
* :func:`assert_replay_identity_not_mutually_recognized` uses the same
  declaration and the real replay identity gate
  (``ScenarioRfuzzExecutor._install_runtime_replay_identity``, the check
  ``replay_scenario_rfuzz_corpus`` performs) to show that one graph declared
  under two edge identities cannot be recognized across runs.

Scope: this is a software gate.  It proves a *declaration* is broken before
RTL; it does not, and cannot, prove anything about a running real IP.

Ownership: this module is self-contained.  It reads only the pre-existing
public declarations of ``ibex_pulp_dual_source`` (the online decoder, the
genome templates and ``dual_source_ownership``) and derives its wiring
declaration from them in :func:`_wiring_from_declaration`; it adds nothing to
that module and shares no mutable state with it.
"""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import asdict, dataclass, replace
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Callable, Iterator
from unittest.mock import patch

from .dependency import SourceBinding, SourceBindings
from .feedback import CoverageTarget
from .ibex_pulp_dual_source import (
    dual_source_ownership, make_ibex_pulp_dual_source_online_decoder,
    make_ibex_pulp_dual_source_templates)
from .memory import MemoryRegion, PersistentMemory
from .ownership import InputField, InputOwner, OwnershipMap, compile_ownership
from .rfuzz_decoder import GenomeRecordDecoder
from .router import DataflowRouter, DeviceWindow
from .runner import Binding, ScenarioRunner
from .runtime_path_contract import (
    CompiledRuntimePathContract, PreparedRuntimePathContract,
    compile_runtime_path_contract)


#: Versioned schema of a complete, RTL-free path declaration.
DECLARATION_SCHEMA = "p2_path_declaration.v1"
#: Versioned schema of the declared wiring inside a path declaration.
WIRING_SCHEMA = "p2_wiring_declaration.v1"
#: Versioned schema of one trusted path-breaking variant.
GATE_SCHEMA = "p2_negative_gate.v1"
#: Versioned schema of one preflight result.
RESULT_SCHEMA = "p2_preflight_result.v1"
#: Versioned schema of one replay mutual-recognition report.
REPLAY_SCHEMA = "p2_replay_identity_report.v1"

#: Declarations may come from the online instruction decoder or the genome
#: decoder; both share this wiring and this contract.
AUTHORITIES = ("online", "genome")

#: The six trusted P2 gates.
GATE_IDS = ("cut_binding", "drop_irq_binding", "wrong_mmio_base",
            "wrong_target_window", "edge_identity_swap", "producer_drift")

#: The swapped edge identity is an existing graph edge of this topology that no
#: trusted declaration uses, so the graph and every selected path stay intact
#: while the declaration changes which edge identity carries the route.  The
#: registry verifies both facts against the live graph before it is used.
EDGE_IDENTITY_SWAP_RULE = 7

#: Counted effects.  A preflight rejection must leave every one of them at 0.
PROBE_COUNTERS = ("rtl_process_launches", "rtl_begin_attempts",
                  "tool_process_invocations", "harness_renders",
                  "harness_builds", "harness_session_constructions",
                  "filesystem_writes", "factory_calls")

#: Rejection stages that must never have touched a harness.
DECLARATION_STAGES = ("declaration_admission", "contract_compile",
                      "declaration_coherence")

#: The coverage targets a fresh RFuzz run needs; only their identities matter
#: to the replay identity gate, which never executes a case.
_REPLAY_TARGETS = (
    CoverageTarget("gpio_a_output_bit0", "gpio_a", "gpio_out", 1, 1),
    CoverageTarget("gpio_b_irq", "gpio_b", "irq", 1, 1),
    CoverageTarget("cpu_external_irq_vector_fetch", "cpu", "instr_addr",
                   0xffffffff, 0x1012c),
    CoverageTarget("cpu_data_write", "cpu", "data_write", 1, 1))

_MESSAGE_EDGE = re.compile(r"edge \((\d+), (\d+)\)")


class NegativeGateError(ValueError):
    """A variant, declaration or probe misuse; never a path rejection."""


class ProbeViolation(RuntimeError):
    """A preflight attempted a harness effect while it had to stay pure."""


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _render(value: Any) -> str:
    if isinstance(value, bool) or value is None:
        return json.dumps(value)
    if isinstance(value, int):
        return f"{value} (0x{value:x})"
    if isinstance(value, str):
        return repr(value)
    return _canonical(value)


def binding_label(row: dict) -> str:
    return (f"{row['source_component']}.{row['source_port']}"
            f"->{row['target_component']}.{row['target_port']}"
            f"@{row['source_bit_offset']}:{row['width']}")


def owner_label(row: dict) -> str:
    return (f"{row['component_id']}.{row['port']}"
            f"@{row['bit_offset']}:{row['width']}")


def edge_label(rule_index: int, prerequisite_index: int) -> str:
    return f"({rule_index}, {prerequisite_index})"


# ---------------------------------------------------------------------------
# Declaration: graph + contract + selected paths + trusted wiring.
# ---------------------------------------------------------------------------

#: IRQ pulse delivery policy of this integration (CPU ticks of one pulse).
#: Not derivable from the contract; the real-runner equivalence test fails
#: loudly if the factory's policy ever differs.
IRQ_PULSE_WIDTH_CPU_TICKS = 4
#: RAM carve-out the factory gives the CPU program and its fixed result slot.
#: Also not derivable from the contract; verified by the same test.
TRUSTED_MEMORY_REGIONS = (MemoryRegion("ram", 0x10000, 0x30000),)
TRUSTED_MEMORY_INITIALIZATION_SEED = 37
TRUSTED_MAX_INITIALIZED_BYTES = 0x20000


@dataclass(frozen=True)
class P2WiringDeclaration:
    """The declared endpoints of this fixed wiring: no session, artifact or RTL.

    Everything here is *derived from the existing public declarations* of
    ``ibex_pulp_dual_source`` and ``runtime_path_contract``: each ``mmio_route``
    contract edge fixes one device window's base, size and (non-initiator)
    component; each ``direct_binding`` contract edge fixes one binding's
    endpoints and width; ``dual_source_ownership()`` fixes every owned input
    bit.  Only the IRQ pulse policy and the CPU memory carve-out are trusted
    constants of the integration.

    This is deliberately a *declaration* transform target: the constructor
    rejects malformed records (unknown components, invalid types and ranges),
    while route semantics (a window's target, an aperture against the runtime
    contract, a declared producer against its binding) stay preflight rules so
    that a broken declaration remains representable and can be rejected with a
    located reason instead of failing to exist.
    """

    sessions: tuple[str, ...]
    router_initiator: str
    windows: tuple[tuple[str, int, int, str], ...]
    bindings: tuple[Binding, ...]
    ownership_fields: tuple[InputField, ...]
    ownership_owners: tuple[InputOwner, ...]
    irq_pulse_widths: tuple[tuple[Binding, int], ...]
    memory_component: str
    memory_regions: tuple[MemoryRegion, ...]
    memory_initialization_seed: int
    max_initialized_bytes: int
    profile_aperture: int

    def __post_init__(self) -> None:
        if (not self.router_initiator or not isinstance(self.sessions, tuple)
                or not self.sessions
                or any(not isinstance(name, str) or not name for name in self.sessions)
                or len(set(self.sessions)) != len(self.sessions)):
            raise ValueError('invalid P2 wiring component declaration')
        if (not isinstance(self.windows, tuple)
                or any(type(window) is not tuple or len(window) != 4
                       or not isinstance(window[0], str) or not window[0]
                       or type(window[1]) is not int or window[1] < 0
                       or type(window[2]) is not int or window[2] < 4
                       or not isinstance(window[3], str) or not window[3]
                       for window in self.windows)
                or len({window[0] for window in self.windows}) != len(self.windows)):
            raise ValueError('invalid P2 wiring MMIO window declaration')
        if (not isinstance(self.bindings, tuple)
                or any(not isinstance(binding, Binding) for binding in self.bindings)
                or len(set(self.bindings)) != len(self.bindings)):
            raise ValueError('invalid P2 wiring binding declaration')
        if (not isinstance(self.ownership_fields, tuple)
                or not isinstance(self.ownership_owners, tuple)
                or any(not isinstance(field, InputField) for field in self.ownership_fields)
                or any(not isinstance(owner, InputOwner) for owner in self.ownership_owners)):
            raise ValueError('invalid P2 wiring ownership declaration')
        if (not isinstance(self.irq_pulse_widths, tuple)
                or any(type(item) is not tuple or len(item) != 2
                       or not isinstance(item[0], Binding)
                       or type(item[1]) is not int or item[1] < 1
                       for item in self.irq_pulse_widths)):
            raise ValueError('invalid P2 wiring IRQ pulse declaration')
        if (not isinstance(self.memory_regions, tuple) or not self.memory_regions
                or any(not isinstance(region, MemoryRegion) for region in self.memory_regions)
                or type(self.memory_initialization_seed) is not int
                or type(self.max_initialized_bytes) is not int
                or self.max_initialized_bytes < 0
                or type(self.profile_aperture) is not int or self.profile_aperture < 4):
            raise ValueError('invalid P2 wiring memory or aperture declaration')
        named = set(self.sessions)
        if any(component not in named for _, _, _, component in self.windows):
            raise ValueError('declared MMIO window names an unregistered component')
        if any(component not in named for component in (
                self.router_initiator, self.memory_component,
                *(endpoint for binding in self.bindings
                  for endpoint in (binding.source_component, binding.target_component)))):
            raise ValueError('declared wiring endpoint names an unregistered component')
        compile_ownership(self.ownership_fields, self.ownership_owners)

    def document(self) -> dict:
        return {'schema_version': WIRING_SCHEMA,
                'sessions': list(self.sessions),
                'router_initiator': self.router_initiator,
                'windows': [{'device_id': device_id, 'base': base, 'size': size,
                             'component': component}
                            for device_id, base, size, component in self.windows],
                'bindings': [asdict(binding) for binding in self.bindings],
                'ownership': {'fields': [asdict(field) for field in self.ownership_fields],
                              'owners': [asdict(owner) for owner in self.ownership_owners]},
                'irq_pulse_widths': [{'binding': asdict(binding), 'width_cpu_ticks': width}
                                     for binding, width in self.irq_pulse_widths],
                'memory': {'component': self.memory_component,
                           'regions': [asdict(region) for region in self.memory_regions],
                           'initialization_seed': self.memory_initialization_seed,
                           'max_initialized_bytes': self.max_initialized_bytes},
                'profile_aperture': self.profile_aperture}

    @classmethod
    def from_document(cls, document: dict) -> P2WiringDeclaration:
        try:
            if (type(document) is not dict
                    or set(document) != {'schema_version', 'sessions', 'router_initiator',
                                         'windows', 'bindings', 'ownership',
                                         'irq_pulse_widths', 'memory', 'profile_aperture'}
                    or document['schema_version'] != WIRING_SCHEMA
                    or type(document['sessions']) is not list
                    or type(document['windows']) is not list
                    or type(document['bindings']) is not list
                    or type(document['irq_pulse_widths']) is not list):
                raise ValueError('invalid P2 wiring schema')
            ownership = document['ownership']
            memory = document['memory']
            if (type(ownership) is not dict
                    or set(ownership) != {'fields', 'owners'}
                    or type(ownership['fields']) is not list
                    or type(ownership['owners']) is not list
                    or type(memory) is not dict
                    or set(memory) != {'component', 'regions', 'initialization_seed',
                                       'max_initialized_bytes'}
                    or type(memory['regions']) is not list):
                raise ValueError('invalid P2 wiring record')
            wiring = cls(
                sessions=tuple(document['sessions']),
                router_initiator=document['router_initiator'],
                windows=tuple((row['device_id'], row['base'], row['size'], row['component'])
                              for row in document['windows']),
                bindings=tuple(Binding(**row) for row in document['bindings']),
                ownership_fields=tuple(InputField(**row) for row in ownership['fields']),
                ownership_owners=tuple(InputOwner(**row) for row in ownership['owners']),
                irq_pulse_widths=tuple((Binding(**row['binding']), row['width_cpu_ticks'])
                                       for row in document['irq_pulse_widths']),
                memory_component=memory['component'],
                memory_regions=tuple(MemoryRegion(**row) for row in memory['regions']),
                memory_initialization_seed=memory['initialization_seed'],
                max_initialized_bytes=memory['max_initialized_bytes'],
                profile_aperture=document['profile_aperture'])
            if _canonical(wiring.document()) != _canonical(document):
                raise ValueError('P2 wiring document is not canonical')
            return wiring
        except (KeyError, TypeError) as error:
            raise ValueError('invalid P2 wiring document') from error


def _wiring_from_declaration(prepared: PreparedRuntimePathContract,
                             ownership: OwnershipMap) -> P2WiringDeclaration:
    """Derive the declared wiring from the trusted contract, graph and ownership."""
    document = prepared.document()
    nodes = {node['node_id']: node for node in document['contract']['nodes']}
    windows: dict[str, tuple[str, int, int, str]] = {}
    initiators: set[str] = set()
    bindings: list[Binding] = []
    for edge in prepared.contract.edges:
        source, target = _endpoints_of(document, edge.key)
        if source is None or target is None:
            raise NegativeGateError(
                f"trusted contract edge {edge.key} has no declared graph endpoints")
        if edge.relation == 'mmio_route':
            initiators.add(edge.initiator_component)
            others = [node for node in (source, target)
                      if node['component'] != edge.initiator_component]
            if len(others) != 1:
                raise NegativeGateError(
                    f"trusted MMIO edge {edge.key} does not name exactly one device component")
            row = (edge.device_id, edge.base, edge.size, others[0]['component'])
            previous = windows.setdefault(edge.device_id, row)
            if previous != row:
                raise NegativeGateError(
                    f"trusted MMIO device {edge.device_id!r} is declared inconsistently")
        elif edge.relation == 'direct_binding':
            if (source['kind'] != 'physical' or target['kind'] != 'physical'
                    or source['width'] != target['width']):
                raise NegativeGateError(
                    f"trusted direct edge {edge.key} is not a whole-field physical binding")
            binding = Binding(source['component'], source['port'],
                              target['component'], target['port'], source['width'],
                              source['bit_offset'], target['bit_offset'])
            if binding not in bindings:
                bindings.append(binding)
    if len(initiators) != 1:
        raise NegativeGateError("trusted MMIO routes do not share one initiator component")
    if not windows:
        raise NegativeGateError("trusted declaration has no MMIO window")
    apertures = {size for _, _, size, _ in windows.values()}
    if len(apertures) != 1:
        raise NegativeGateError("trusted MMIO windows do not share one profile aperture")
    initiator = next(iter(initiators))
    interrupt = next((binding for binding in bindings
                      if binding.target_component == initiator), None)
    if interrupt is None:
        raise NegativeGateError("trusted wiring declares no CPU interrupt binding")
    ownership_document = ownership.document()
    return P2WiringDeclaration(
        sessions=tuple(sorted({node['component'] for node in nodes.values()})),
        router_initiator=initiator,
        windows=tuple((device_id, *row[1:]) for device_id, row in sorted(windows.items())),
        bindings=tuple(bindings),
        ownership_fields=tuple(InputField(**row) for row in ownership_document['fields']),
        ownership_owners=tuple(InputOwner(**row) for row in ownership_document['owners']),
        irq_pulse_widths=((interrupt, IRQ_PULSE_WIDTH_CPU_TICKS),),
        memory_component=initiator,
        memory_regions=TRUSTED_MEMORY_REGIONS,
        memory_initialization_seed=TRUSTED_MEMORY_INITIALIZATION_SEED,
        max_initialized_bytes=TRUSTED_MAX_INITIALIZED_BYTES,
        profile_aperture=next(iter(apertures)))


def _endpoints_of(document: dict, key: tuple[int, int]):
    graph_edge = next((edge for edge in document["graph"]["edges"]
                       if (edge["rule_index"], edge["prerequisite_index"]) == key), None)
    if graph_edge is None:
        return None, None
    nodes = {node["node_id"]: node for node in document["contract"]["nodes"]}
    return nodes.get(graph_edge["prerequisite"]), nodes.get(graph_edge["target"])


@dataclass(frozen=True, eq=False)
class PathDeclaration:
    """One complete, RTL-free declaration of a fresh run's declared topology.

    Equality is canonical-document equality, because the underlying prepared
    path contract is an opaque sealed object.
    """

    authority: str
    prepared: PreparedRuntimePathContract
    wiring: P2WiringDeclaration
    source_bindings: tuple[SourceBinding, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.authority, str) or not self.authority:
            raise ValueError("path declaration requires an authority")
        if not isinstance(self.prepared, PreparedRuntimePathContract):
            raise ValueError("path declaration requires prepared runtime paths")
        if not isinstance(self.wiring, P2WiringDeclaration):
            raise ValueError("path declaration requires a wiring declaration")
        if (not isinstance(self.source_bindings, tuple)
                or any(not isinstance(item, SourceBinding) for item in self.source_bindings)):
            raise ValueError("path declaration source bindings must be immutable records")

    @property
    def graph(self):
        return self.prepared.graph

    @property
    def contract(self):
        return self.prepared.contract

    @property
    def runtime_paths(self) -> tuple:
        return self.prepared.runtime_paths

    @property
    def path_ids(self) -> tuple[str, ...]:
        return self.prepared.path_ids

    @property
    def identity_sha256(self) -> str:
        return _digest(self.document())

    def document(self) -> dict:
        return {"schema_version": DECLARATION_SCHEMA,
                "authority": self.authority,
                "paths": self.prepared.document(),
                "wiring": self.wiring.document(),
                "source_bindings": [asdict(item) for item in self.source_bindings]}

    def __eq__(self, other: object) -> bool:
        return (isinstance(other, PathDeclaration)
                and self.document() == other.document())

    def __hash__(self) -> int:
        return hash((self.authority, self.identity_sha256))

    @classmethod
    def from_document(cls, document: dict) -> PathDeclaration:
        try:
            if (type(document) is not dict
                    or set(document) != {"schema_version", "authority", "paths",
                                         "wiring", "source_bindings"}
                    or document["schema_version"] != DECLARATION_SCHEMA
                    or not isinstance(document["authority"], str)
                    or not document["authority"]
                    or document["authority"] not in AUTHORITIES
                    or type(document["paths"]) is not dict
                    or type(document["wiring"]) is not dict
                    or type(document["source_bindings"]) is not list):
                raise ValueError("invalid path declaration schema")
            declaration = cls(
                authority=document["authority"],
                prepared=PreparedRuntimePathContract.from_document(document["paths"]),
                wiring=P2WiringDeclaration.from_document(document["wiring"]),
                source_bindings=tuple(SourceBinding(**row)
                                      for row in document["source_bindings"]))
            if _canonical(declaration.document()) != _canonical(document):
                raise ValueError("path declaration document is not canonical")
            return declaration
        except (KeyError, TypeError, AttributeError) as error:
            raise ValueError("invalid path declaration document") from error


_TRUSTED_DECLARATIONS: dict[str, PathDeclaration] = {}


def trusted_path_declaration(authority: str = "online") -> PathDeclaration:
    """The trusted declaration: real graph, real contract, derived wiring.

    Nothing here renders a harness, reads an RTL source or starts a process;
    the online decoder, the genome templates, the ownership map and the runtime
    path contract are pure declarations of the existing trusted modules.  The
    wiring is derived from those declarations (see
    :func:`_wiring_from_declaration`), so this module adds no declaration of its
    own to the shared wiring module.
    """
    if authority not in AUTHORITIES:
        raise NegativeGateError(f"unknown path declaration authority {authority!r}")
    if authority in _TRUSTED_DECLARATIONS:
        return _TRUSTED_DECLARATIONS[authority]
    if authority == "online":
        decoder = make_ibex_pulp_dual_source_online_decoder()
        source_bindings: tuple[SourceBinding, ...] = ()
    else:
        decoder = make_ibex_pulp_dual_source_templates().decoder
        source_bindings = tuple(decoder.source_bindings.entries)
    prepared = PreparedRuntimePathContract(decoder.graph, decoder.runtime_contract,
                                            decoder.runtime_paths)
    if decoder.ownership.document() != dual_source_ownership().document():
        raise NegativeGateError("decoder ownership differs from the trusted ownership declaration")
    declaration = PathDeclaration(
        authority=authority,
        prepared=prepared,
        wiring=_wiring_from_declaration(prepared, decoder.ownership),
        source_bindings=source_bindings)
    _TRUSTED_DECLARATIONS[authority] = declaration
    return declaration


def _selections_for_edge(declaration: PathDeclaration,
                         key: tuple[int, int]) -> str | None:
    for row in declaration.prepared.document()["selections"]:
        if any((edge["rule_index"], edge["prerequisite_index"]) == key
               for edge in row["edges"]):
            return row["path_id"]
    return None


def _endpoints(declaration: PathDeclaration, key: tuple[int, int]):
    prepared = declaration.prepared.document()
    graph_edge = next((edge for edge in prepared["graph"]["edges"]
                       if (edge["rule_index"], edge["prerequisite_index"]) == key), None)
    if graph_edge is None:
        return None, None
    nodes = {node["node_id"]: node for node in prepared["contract"]["nodes"]}
    return nodes.get(graph_edge["prerequisite"]), nodes.get(graph_edge["target"])


def _binding_edge(declaration: PathDeclaration, row: dict) -> tuple[int, int] | None:
    """Locate the declared direct edge whose endpoints are this binding."""
    for edge in declaration.contract.edges:
        if edge.relation != "direct_binding":
            continue
        source, target = _endpoints(declaration, edge.key)
        if source is None or target is None:
            continue
        if ((source["component"], source["port"]) == (row["source_component"], row["source_port"])
                and (target["component"], target["port"]) == (row["target_component"], row["target_port"])):
            return edge.key
    return None


def _window_edge(declaration: PathDeclaration, device_id: str) -> tuple[int, int] | None:
    for edge in declaration.contract.edges:
        if edge.relation == "mmio_route" and edge.device_id == device_id:
            return edge.key
    return None


def _owner_edge(declaration: PathDeclaration, row: dict) -> tuple[int, int] | None:
    """Locate the declared direct edge that drives this owned input range."""
    for edge in declaration.contract.edges:
        if edge.relation != "direct_binding":
            continue
        _, target = _endpoints(declaration, edge.key)
        if target is None or target.get("kind") != "physical":
            continue
        if ((target["component"], target["port"]) == (row["component_id"], row["port"])
                and target["bit_offset"] <= row["bit_offset"]
                and row["bit_offset"] + row["width"] <= target["bit_offset"] + target["width"]):
            return edge.key
    return None


def _delta_entry(*, kind: str, operation: str, field_name: str,
                 record_field: str | None, trusted: Any, declared: Any,
                 edge: tuple[int, int] | None,
                 path_id: str | None) -> dict:
    return {"kind": kind, "operation": operation, "field": field_name,
            "record_field": record_field, "trusted": trusted, "declared": declared,
            "edge": (None if edge is None else
                     {"rule_index": edge[0], "prerequisite_index": edge[1]}),
            "path_id": path_id}


def declaration_delta(trusted: PathDeclaration,
                      declared: PathDeclaration) -> list[dict]:
    """Every locatable difference between the trusted and a candidate declaration.

    The order is canonical: authority, graph, contract edge identities, bindings,
    windows, ownership records, wiring metadata and declared sources.
    """
    if not isinstance(trusted, PathDeclaration) or not isinstance(declared, PathDeclaration):
        raise NegativeGateError("declaration delta requires two path declarations")
    deltas: list[dict] = []
    if trusted.authority != declared.authority:
        deltas.append(_delta_entry(kind="authority", operation="replace",
            field_name="authority", record_field=None, trusted=trusted.authority,
            declared=declared.authority, edge=None, path_id=None))
    if trusted.prepared.document()["graph"] != declared.prepared.document()["graph"]:
        deltas.append(_delta_entry(kind="graph", operation="replace",
            field_name="paths.graph", record_field=None, trusted="trusted graph",
            declared="declared graph", edge=None, path_id=None))
    deltas.extend(_contract_edge_deltas(trusted, declared))
    deltas.extend(_binding_deltas(trusted, declared))
    deltas.extend(_window_deltas(trusted, declared))
    deltas.extend(_ownership_deltas(trusted, declared))
    deltas.extend(_metadata_deltas(trusted, declared))
    deltas.extend(_source_binding_deltas(trusted, declared))
    return deltas


def _contract_edge_deltas(trusted: PathDeclaration,
                          declared: PathDeclaration) -> list[dict]:
    trusted_edges = {edge.key: edge for edge in trusted.contract.edges}
    declared_edges = {edge.key: edge for edge in declared.contract.edges}
    deltas: list[dict] = []
    moved: set[tuple[int, int]] = set()
    for key in sorted(set(trusted_edges) - set(declared_edges)):
        source = asdict(trusted_edges[key])
        # A declaration that kept its fields but changed its edge identity is a
        # move of one identity, not an unrelated delete plus insert.
        content = {name: value for name, value in source.items()
                   if name not in ("rule_index", "prerequisite_index")}
        target_key = next((other for other in sorted(set(declared_edges) - set(trusted_edges))
                           if other not in moved
                           and {name: value
                                for name, value in asdict(declared_edges[other]).items()
                                if name not in ("rule_index", "prerequisite_index")} == content
                           and _endpoints(declared, other)[0] is not None), None)
        if target_key is not None:
            moved.add(target_key)
            deltas.append(_delta_entry(kind="contract_edge", operation="replace",
                field_name=f"paths.contract.edges[{edge_label(*key)}].rule_index",
                record_field="rule_index", trusted=key[0], declared=target_key[0],
                edge=key, path_id=_selections_for_edge(declared, key)
                or _selections_for_edge(trusted, key)))
        else:
            deltas.append(_delta_entry(kind="contract_edge", operation="delete",
                field_name=f"paths.contract.edges[{edge_label(*key)}]",
                record_field=None, trusted=source, declared=None, edge=key,
                path_id=_selections_for_edge(trusted, key)))
    for key in sorted(set(declared_edges) - set(trusted_edges) - moved):
        deltas.append(_delta_entry(kind="contract_edge", operation="insert",
            field_name=f"paths.contract.edges[{edge_label(*key)}]",
            record_field=None, trusted=None, declared=asdict(declared_edges[key]),
            edge=key, path_id=_selections_for_edge(declared, key)))
    for key in sorted(set(trusted_edges) & set(declared_edges)):
        source, target = asdict(trusted_edges[key]), asdict(declared_edges[key])
        for name in sorted(set(source) | set(target)):
            if source.get(name) != target.get(name):
                deltas.append(_delta_entry(kind="contract_edge", operation="replace",
                    field_name=f"paths.contract.edges[{edge_label(*key)}].{name}",
                    record_field=name, trusted=source.get(name),
                    declared=target.get(name), edge=key,
                    path_id=_selections_for_edge(declared, key)))
    return deltas


def _binding_deltas(trusted: PathDeclaration, declared: PathDeclaration) -> list[dict]:
    trusted_rows = {_canonical(row): row for row in trusted.wiring.document()["bindings"]}
    declared_rows = {_canonical(row): row for row in declared.wiring.document()["bindings"]}
    deltas: list[dict] = []
    for key in sorted(set(trusted_rows) - set(declared_rows)):
        row = trusted_rows[key]
        edge = _binding_edge(trusted, row)
        deltas.append(_delta_entry(kind="binding", operation="delete",
            field_name=f"wiring.bindings[{binding_label(row)}]", record_field=None,
            trusted=row, declared=None, edge=edge,
            path_id=None if edge is None else _selections_for_edge(trusted, edge)))
    for key in sorted(set(declared_rows) - set(trusted_rows)):
        row = declared_rows[key]
        edge = _binding_edge(declared, row)
        deltas.append(_delta_entry(kind="binding", operation="insert",
            field_name=f"wiring.bindings[{binding_label(row)}]", record_field=None,
            trusted=None, declared=row, edge=edge,
            path_id=None if edge is None else _selections_for_edge(declared, edge)))
    for key in sorted(set(trusted_rows) & set(declared_rows)):
        source, target = trusted_rows[key], declared_rows[key]
        for name in sorted(set(source) | set(target)):
            if source.get(name) != target.get(name):
                edge = _binding_edge(declared, target)
                deltas.append(_delta_entry(kind="binding", operation="replace",
                    field_name=f"wiring.bindings[{binding_label(target)}].{name}",
                    record_field=name, trusted=source.get(name),
                    declared=target.get(name), edge=edge,
                    path_id=None if edge is None else _selections_for_edge(declared, edge)))
    return deltas


def _window_deltas(trusted: PathDeclaration, declared: PathDeclaration) -> list[dict]:
    trusted_rows = {row["device_id"]: row for row in trusted.wiring.document()["windows"]}
    declared_rows = {row["device_id"]: row for row in declared.wiring.document()["windows"]}
    deltas: list[dict] = []
    for device_id in sorted(set(trusted_rows) - set(declared_rows)):
        row = trusted_rows[device_id]
        edge = _window_edge(trusted, device_id)
        deltas.append(_delta_entry(kind="window", operation="delete",
            field_name=f"wiring.windows[{device_id}]", record_field=None,
            trusted=row, declared=None, edge=edge,
            path_id=None if edge is None else _selections_for_edge(trusted, edge)))
    for device_id in sorted(set(declared_rows) - set(trusted_rows)):
        row = declared_rows[device_id]
        edge = _window_edge(declared, device_id)
        deltas.append(_delta_entry(kind="window", operation="insert",
            field_name=f"wiring.windows[{device_id}]", record_field=None,
            trusted=None, declared=row, edge=edge,
            path_id=None if edge is None else _selections_for_edge(declared, edge)))
    for device_id in sorted(set(trusted_rows) & set(declared_rows)):
        source, target = trusted_rows[device_id], declared_rows[device_id]
        for name in sorted(set(source) | set(target)):
            if source.get(name) != target.get(name):
                edge = _window_edge(declared, device_id)
                deltas.append(_delta_entry(kind="window", operation="replace",
                    field_name=f"wiring.windows[{device_id}].{name}", record_field=name,
                    trusted=source.get(name), declared=target.get(name), edge=edge,
                    path_id=None if edge is None else _selections_for_edge(declared, edge)))
    return deltas


def _ownership_deltas(trusted: PathDeclaration, declared: PathDeclaration) -> list[dict]:
    trusted_ownership = trusted.wiring.document()["ownership"]
    declared_ownership = declared.wiring.document()["ownership"]
    deltas: list[dict] = []
    trusted_fields = {_canonical(row): row for row in trusted_ownership["fields"]}
    declared_fields = {_canonical(row): row for row in declared_ownership["fields"]}
    for key in sorted(set(trusted_fields) ^ set(declared_fields)):
        row = trusted_fields.get(key) or declared_fields[key]
        deltas.append(_delta_entry(kind="ownership_field",
            operation="delete" if key in trusted_fields else "insert",
            field_name=f"wiring.ownership.fields[{owner_label(row)}]",
            record_field=None, trusted=trusted_fields.get(key),
            declared=declared_fields.get(key), edge=None, path_id=None))

    def keyed(ownership):
        return {_canonical({name: row[name] for name in
                            ("component_id", "port", "bit_offset", "width")}): row
                for row in ownership["owners"]}
    trusted_owners, declared_owners = keyed(trusted_ownership), keyed(declared_ownership)
    for key in sorted(set(trusted_owners) - set(declared_owners)):
        row = trusted_owners[key]
        edge = _owner_edge(trusted, row)
        deltas.append(_delta_entry(kind="ownership_owner", operation="delete",
            field_name=f"wiring.ownership.owners[{owner_label(row)}]",
            record_field=None, trusted=row, declared=None, edge=edge,
            path_id=None if edge is None else _selections_for_edge(trusted, edge)))
    for key in sorted(set(declared_owners) - set(trusted_owners)):
        row = declared_owners[key]
        edge = _owner_edge(declared, row)
        deltas.append(_delta_entry(kind="ownership_owner", operation="insert",
            field_name=f"wiring.ownership.owners[{owner_label(row)}]",
            record_field=None, trusted=None, declared=row, edge=edge,
            path_id=None if edge is None else _selections_for_edge(declared, edge)))
    for key in sorted(set(trusted_owners) & set(declared_owners)):
        source, target = trusted_owners[key], declared_owners[key]
        for name in ("kind", "producer_ref"):
            if source[name] != target[name]:
                edge = _owner_edge(declared, target)
                deltas.append(_delta_entry(kind="ownership_owner", operation="replace",
                    field_name=f"wiring.ownership.owners[{owner_label(target)}].{name}",
                    record_field=name, trusted=source[name], declared=target[name],
                    edge=edge,
                    path_id=None if edge is None else _selections_for_edge(declared, edge)))
    return deltas


def _metadata_deltas(trusted: PathDeclaration, declared: PathDeclaration) -> list[dict]:
    trusted_wiring = trusted.wiring.document()
    declared_wiring = declared.wiring.document()
    deltas: list[dict] = []
    for name in ("router_initiator", "sessions", "profile_aperture", "memory",
                 "irq_pulse_widths"):
        if trusted_wiring.get(name) != declared_wiring.get(name):
            deltas.append(_delta_entry(kind="wiring", operation="replace",
                field_name=f"wiring.{name}", record_field=name,
                trusted=trusted_wiring.get(name), declared=declared_wiring.get(name),
                edge=None, path_id=None))
    return deltas


def _source_binding_deltas(trusted: PathDeclaration,
                           declared: PathDeclaration) -> list[dict]:
    if [asdict(item) for item in trusted.source_bindings] == \
            [asdict(item) for item in declared.source_bindings]:
        return []
    return [_delta_entry(kind="source_bindings", operation="replace",
                         field_name="source_bindings", record_field=None,
                         trusted=[asdict(item) for item in trusted.source_bindings],
                         declared=[asdict(item) for item in declared.source_bindings],
                         edge=None, path_id=None)]


def self_findings(declaration: PathDeclaration) -> list[dict]:
    """Candidate-internal coherence findings; no trusted baseline needed.

    These are checks the trusted wiring must also satisfy, so they are reported
    for any candidate declaration instead of being folded into the trusted
    comparison.  They never replace the real checker's own reason.
    """
    wiring = declaration.wiring
    findings: list[dict] = []
    declared = set(wiring.bindings)
    for binding, width in wiring.irq_pulse_widths:
        if binding not in declared:
            findings.append({
                "kind": "orphan_irq_pulse", "field": "wiring.irq_pulse_widths",
                "detail": ("declared IRQ pulse policy references the undeclared "
                           f"binding {binding}")})
    for device_id, base, size, component in wiring.windows:
        if component != device_id:
            findings.append({
                "kind": "window_target", "field": f"wiring.windows[{device_id}].component",
                "detail": (f"declared MMIO window {device_id!r} routes to component "
                           f"{component!r}")})
        if size != wiring.profile_aperture:
            findings.append({
                "kind": "window_aperture", "field": f"wiring.windows[{device_id}].size",
                "detail": (f"declared MMIO window {device_id!r} size {size} differs from "
                           f"the profile aperture {wiring.profile_aperture}")})
    return findings


def located_reason(delta: list[dict]) -> str | None:
    """One sentence naming the field and both values of the first difference."""
    if not delta:
        return None
    entry = delta[0]
    suffix = "" if len(delta) == 1 else f" (+{len(delta) - 1} more declaration changes)"
    if entry["operation"] == "delete":
        return (f"declared {entry['field']} is absent from the trusted "
                f"declaration{suffix}")
    if entry["operation"] == "insert":
        return (f"declared {entry['field']} is not part of the trusted "
                f"declaration{suffix}")
    return (f"declared {entry['field']}={_render(entry['declared'])} differs from "
            f"trusted {_render(entry['trusted'])}{suffix}")


# ---------------------------------------------------------------------------
# Variants: trusted, declarative transformations of one declaration document.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NegativeGateVariant:
    """One controlled, declared break of the trusted path declaration."""

    variant_id: str
    kind: str
    operation: str
    identity: dict
    record_field: str | None
    field: str
    baseline_value: Any
    mutated_value: Any
    expected_reason: str
    edge: tuple[int, int]

    def document(self) -> dict:
        return {"schema_version": GATE_SCHEMA,
                "variant_id": self.variant_id,
                "kind": self.kind,
                "operation": self.operation,
                "target": {"identity": dict(self.identity),
                           "record_field": self.record_field,
                           "field": self.field,
                           "edge": {"rule_index": self.edge[0],
                                    "prerequisite_index": self.edge[1]}},
                "baseline_value": self.baseline_value,
                "mutated_value": self.mutated_value,
                "expected_reason": self.expected_reason}

    @classmethod
    def from_document(cls, document: dict) -> NegativeGateVariant:
        if (type(document) is not dict
                or set(document) != {"schema_version", "variant_id", "kind", "operation",
                                     "target", "baseline_value", "mutated_value",
                                     "expected_reason"}
                or document["schema_version"] != GATE_SCHEMA
                or type(document["variant_id"]) is not str
                or type(document["kind"]) is not str
                or document["operation"] not in ("delete", "replace")
                or type(document["target"]) is not dict
                or set(document["target"]) != {"identity", "record_field", "field", "edge"}
                or type(document["target"]["identity"]) is not dict
                or type(document["target"]["field"]) is not str
                or type(document["target"]["edge"]) is not dict
                or set(document["target"]["edge"]) != {"rule_index", "prerequisite_index"}
                or type(document["expected_reason"]) is not str):
            raise ValueError("invalid P2 negative gate document")
        if document["operation"] == "delete" and document["mutated_value"] is not None:
            raise ValueError("delete variant cannot carry a mutated value")
        if document["operation"] == "replace" and document["mutated_value"] is None:
            raise ValueError("replace variant requires a mutated value")
        edge = document["target"]["edge"]
        variant = cls(
            variant_id=document["variant_id"], kind=document["kind"],
            operation=document["operation"],
            identity=dict(document["target"]["identity"]),
            record_field=document["target"]["record_field"],
            field=document["target"]["field"],
            baseline_value=document["baseline_value"],
            mutated_value=document["mutated_value"],
            expected_reason=document["expected_reason"],
            edge=(edge["rule_index"], edge["prerequisite_index"]))
        # A gate document is trusted input: it must be exactly one of the
        # registry variants derived from the live trusted declaration.
        if variant.document() != trusted_gate(variant.variant_id).document():
            raise ValueError("P2 negative gate document does not match the trusted variant")
        return variant

    def apply(self, declaration: PathDeclaration) -> PathDeclaration:
        """Return a copy of the declaration document with exactly this break.

        The transform is pure declaration editing: ``document()`` builds fresh
        dictionaries, so the trusted declaration object is never mutated and the
        same gate always produces the same broken copy.
        """
        if not isinstance(declaration, PathDeclaration):
            raise NegativeGateError("a P2 negative gate applies to a path declaration")
        trusted = trusted_path_declaration(declaration.authority)
        if declaration.identity_sha256 != trusted.identity_sha256:
            raise NegativeGateError(
                "a P2 negative gate applies only to the trusted declaration of its authority")
        document = declaration.document()
        self._mutate(document)
        return PathDeclaration.from_document(document)

    def _rows(self, document: dict) -> tuple[list[dict], str]:
        if self.kind == "binding":
            return document["wiring"]["bindings"], "wiring.bindings"
        if self.kind == "window":
            return document["wiring"]["windows"], "wiring.windows"
        if self.kind == "owner":
            return document["wiring"]["ownership"]["owners"], "wiring.ownership.owners"
        if self.kind == "contract_edge":
            return document["paths"]["contract"]["edges"], "paths.contract.edges"
        raise NegativeGateError(f"unknown P2 gate target kind {self.kind!r}")

    def _mutate(self, document: dict) -> None:
        rows, label = self._rows(document)
        matches = [index for index, row in enumerate(rows)
                   if all(row.get(name) == value
                          for name, value in self.identity.items())]
        if len(matches) != 1:
            raise NegativeGateError(
                f"gate {self.variant_id} target {label} matches={len(matches)}")
        index = matches[0]
        if self.operation == "delete":
            del rows[index]
        elif self.record_field is None:
            raise NegativeGateError("replace variant requires a target record field")
        elif rows[index].get(self.record_field) != self.baseline_value:
            raise NegativeGateError(
                f"gate {self.variant_id} target field {self.record_field} does not "
                "carry the trusted value")
        else:
            rows[index][self.record_field] = self.mutated_value
        if self.kind == "contract_edge":
            # The contract document is canonical only in edge-key order.
            rows.sort(key=lambda row: (row["rule_index"], row["prerequisite_index"]))


def _variants_from(declaration: PathDeclaration) -> tuple[NegativeGateVariant, ...]:
    cached = _VARIANT_CACHE.get(declaration.authority)
    if cached is not None:
        return cached
    wiring = declaration.wiring
    bindings = [asdict(binding) for binding in wiring.bindings]
    a_binding = next(row for row in bindings if row["target_component"] == "gpio_b")
    irq_binding = next(row for row in bindings if row["target_component"] == "cpu")
    window_a = next({"device_id": device_id, "base": base, "size": size,
                     "component": component}
                    for device_id, base, size, component in wiring.windows
                    if device_id == "gpio_a")
    owner_low = next(asdict(owner) for owner in wiring.ownership_owners
                     if owner.component_id == "gpio_b" and owner.kind == "bound")
    route = next(edge for edge in declaration.contract.edges
                 if edge.relation == "mmio_route" and edge.device_id == "gpio_a")
    contract_keys = {edge.key for edge in declaration.contract.edges}
    graph_keys = {(edge["rule_index"], edge["prerequisite_index"])
                  for edge in declaration.prepared.document()["graph"]["edges"]}
    if ((EDGE_IDENTITY_SWAP_RULE, 0) not in graph_keys
            or (EDGE_IDENTITY_SWAP_RULE, 0) in contract_keys):
        raise NegativeGateError("declared edge identity swap target is not a free graph edge")
    binding_edge = _binding_edge(declaration, a_binding)
    irq_edge = _binding_edge(declaration, irq_binding)
    window_edge = _window_edge(declaration, window_a["device_id"])
    owner_edge = _owner_edge(declaration, owner_low)
    if None in (binding_edge, irq_edge, window_edge, owner_edge, route.key):
        raise NegativeGateError("trusted declaration does not locate every gate edge")
    variants = (
        NegativeGateVariant(
            variant_id="cut_binding", kind="binding", operation="delete",
            identity={name: a_binding[name] for name in (
                "source_component", "source_port", "target_component", "target_port",
                "source_bit_offset", "target_bit_offset")},
            record_field=None,
            field=f"wiring.bindings[{binding_label(a_binding)}]",
            baseline_value=a_binding, mutated_value=None,
            expected_reason="", edge=binding_edge),
        NegativeGateVariant(
            variant_id="drop_irq_binding", kind="binding", operation="delete",
            identity={name: irq_binding[name] for name in (
                "source_component", "source_port", "target_component", "target_port",
                "source_bit_offset", "target_bit_offset")},
            record_field=None,
            field=f"wiring.bindings[{binding_label(irq_binding)}]",
            baseline_value=irq_binding, mutated_value=None,
            expected_reason="", edge=irq_edge),
        NegativeGateVariant(
            variant_id="wrong_mmio_base", kind="window", operation="replace",
            identity={"device_id": window_a["device_id"]},
            record_field="base", field=f"wiring.windows[{window_a['device_id']}].base",
            baseline_value=window_a["base"], mutated_value=window_a["base"] + 0x1000,
            expected_reason="", edge=window_edge),
        NegativeGateVariant(
            variant_id="wrong_target_window", kind="window", operation="replace",
            identity={"device_id": window_a["device_id"]},
            record_field="component",
            field=f"wiring.windows[{window_a['device_id']}].component",
            baseline_value=window_a["component"],
            mutated_value=next(component for _, _, _, component in wiring.windows
                               if component != window_a["component"]),
            expected_reason="", edge=window_edge),
        NegativeGateVariant(
            variant_id="edge_identity_swap", kind="contract_edge", operation="replace",
            identity={"rule_index": route.key[0], "prerequisite_index": route.key[1]},
            record_field="rule_index",
            field=f"paths.contract.edges[{edge_label(*route.key)}].rule_index",
            baseline_value=route.key[0], mutated_value=EDGE_IDENTITY_SWAP_RULE,
            expected_reason="", edge=route.key),
        NegativeGateVariant(
            variant_id="producer_drift", kind="owner", operation="replace",
            identity={name: owner_low[name] for name in (
                "component_id", "port", "bit_offset", "width")},
            record_field="producer_ref",
            field=f"wiring.ownership.owners[{owner_label(owner_low)}].producer_ref",
            baseline_value=owner_low["producer_ref"],
            mutated_value=f"{owner_low['producer_ref']}_drift",
            expected_reason="", edge=owner_edge),
    )
    # The registry documents an exact break; verify every documented fact
    # against the live checker before the variants are handed out.
    verified = []
    for variant in variants:
        mutated = variant.apply(declaration)
        if mutated.prepared.document()["graph"] != declaration.prepared.document()["graph"]:
            raise NegativeGateError(f"gate {variant.variant_id} changed the declared graph")
        delta = declaration_delta(declaration, mutated)
        if len(delta) != 1 or delta[0]["field"] != variant.field:
            raise NegativeGateError(
                f"gate {variant.variant_id} is not a single located declaration change")
        result = preflight_path_declaration(mutated, trusted=declaration)
        if not result["rejected"] or result["stage"] not in DECLARATION_STAGES:
            raise NegativeGateError(
                f"gate {variant.variant_id} is not rejected by the trusted preflight")
        edge = result["first_failing_edge"]
        if (edge is None or (edge["rule_index"], edge["prerequisite_index"]) != variant.edge):
            raise NegativeGateError(
                f"gate {variant.variant_id} does not fail at its declared edge")
        if not (result["framework_reason"] or ""):
            raise NegativeGateError(
                f"gate {variant.variant_id} needs the real checker's own reason")
        verified.append(replace(variant, expected_reason=result["framework_reason"]))
    _VARIANT_CACHE[declaration.authority] = tuple(verified)
    return _VARIANT_CACHE[declaration.authority]


_VARIANT_CACHE: dict[str, tuple[NegativeGateVariant, ...]] = {}


def p2_negative_gate_variants(*, declaration: PathDeclaration | None = None
                              ) -> tuple[NegativeGateVariant, ...]:
    """The six trusted P2 gates, derived from the trusted declaration."""
    base = trusted_path_declaration() if declaration is None else declaration
    if not isinstance(base, PathDeclaration):
        raise NegativeGateError("P2 negative gates require a path declaration")
    trusted = trusted_path_declaration(base.authority)
    if base.identity_sha256 != trusted.identity_sha256:
        raise NegativeGateError("P2 negative gates require the trusted declaration")
    return _variants_from(base)


def trusted_gate(variant_id: str, *,
                 declaration: PathDeclaration | None = None) -> NegativeGateVariant:
    if variant_id not in GATE_IDS:
        raise NegativeGateError(f"unknown P2 negative gate {variant_id!r}")
    return next(variant for variant in p2_negative_gate_variants(declaration=declaration)
                if variant.variant_id == variant_id)


# ---------------------------------------------------------------------------
# Launch probe: injectable evidence that no harness effect happened.
# ---------------------------------------------------------------------------

_RENDER_ENTRY_POINTS = (
    ("myfuzz.local_harness", "load_local_harness_request", "harness_renders"),
    ("myfuzz.local_harness", "plan_local_harness", "harness_renders"),
    ("myfuzz.local_harness", "render_local_harness", "harness_renders"),
    ("myfuzz.local_harness", "verify_local_source_lock", "harness_renders"),
    ("myfuzz.local_harness", "render_local_runtime", "harness_renders"),
    ("myfuzz.local_harness", "render_local_driver", "harness_renders"),
    ("myfuzz.local_harness", "build_local_harness", "harness_builds"),
    ("myfuzz.local_harness.plan", "plan_local_harness", "harness_renders"),
    ("myfuzz.local_harness.renderer", "render_local_harness", "harness_renders"),
    ("myfuzz.local_harness.runtime_renderer", "render_local_runtime", "harness_renders"),
    ("myfuzz.local_harness.driver_renderer", "render_local_driver", "harness_renders"),
    ("myfuzz.local_harness.build", "build_local_harness", "harness_builds"),
    ("myfuzz.local_harness.session", "GeneratedLocalSession.__init__",
     "harness_session_constructions"),
    ("myfuzz.local_harness.session", "GeneratedLocalSession.prepare_local",
     "harness_builds"),
    ("myfuzz.local_harness.session", "GeneratedLocalSession.begin_case",
     "rtl_begin_attempts"),
    ("myfuzz.scenario.ibex_pulp_dual_source", "_artifact", "harness_renders"),
    ("myfuzz.scenario.ibex_pulp_dual_source", "render_local_harness", "harness_renders"),
    ("myfuzz.scenario.ibex_pulp_dual_source", "render_local_runtime", "harness_renders"),
    ("myfuzz.scenario.ibex_pulp_dual_source", "render_local_driver", "harness_renders"),
    ("myfuzz.scenario.runner", "ScenarioRunner.begin_test", "rtl_begin_attempts"),
)


class LaunchProbe:
    """Count every effect that could render, build or start a harness.

    The probe is armed for one preflight call.  The first attempt *raises*
    :class:`ProbeViolation` after being counted, so a broken gate fails loudly
    instead of silently continuing into a render.
    """

    def __init__(self) -> None:
        self.counts: dict[str, int] = {name: 0 for name in PROBE_COUNTERS}
        self.calls: list[dict] = []
        self.scopes: list[str] = []
        self._armed = False
        self._permitted: set[str] = set()

    def record(self, counter: str, *, target: str, detail: dict | None = None) -> None:
        if counter not in self.counts:
            raise NegativeGateError(f"unknown probe counter {counter!r}")
        self.counts[counter] += 1
        self.calls.append({"counter": counter, "target": target, "detail": detail or {}})

    def _recorder(self, counter: str, target: str, original: Callable):
        def recorded(*args, **kwargs):
            self.record(counter, target=target)
            if counter not in self._permitted:
                raise ProbeViolation(
                    f"preflight attempted {counter} at {target}; a rejected declaration "
                    "must fail before any harness or process exists")
            return original(*args, **kwargs)
        return recorded

    @contextmanager
    def permit(self, *counters: str) -> Iterator[LaunchProbe]:
        """Allow (but still count) the named effects for one explicit stage.

        Only the runner stage, which by definition builds a runner object, may
        permit ``harness_session_constructions``; every declaration-stage
        rejection stays strictly forbidden from any harness effect.
        """
        unknown = set(counters) - set(self.counts)
        if unknown:
            raise NegativeGateError(f"unknown probe counter(s) {sorted(unknown)}")
        self._permitted.update(counters)
        try:
            yield self
        finally:
            self._permitted.difference_update(counters)

    def _bind(self, stack: ExitStack, owner: object, attribute: str,
              module_name: str, counter: str) -> None:
        target = f"{module_name}.{attribute}"
        self.calls.append({"counter": counter, "target": target,
                           "detail": {"armed": True}})
        stack.enter_context(patch.object(owner, attribute,
                                         self._recorder(counter, target,
                                                        getattr(owner, attribute))))

    @contextmanager
    def arm(self, scope: str = "preflight") -> Iterator[LaunchProbe]:
        if self._armed:
            raise NegativeGateError("launch probe is already armed")
        self._armed = True
        self.scopes.append(scope)
        with ExitStack() as stack:
            self._bind(stack, subprocess, "Popen", "subprocess", "rtl_process_launches")
            self._bind(stack, subprocess, "run", "subprocess", "tool_process_invocations")
            for module_name, attribute, counter in _RENDER_ENTRY_POINTS:
                try:
                    module = __import__(module_name, fromlist=["__name__"])
                except ImportError:  # pragma: no cover - module topology change
                    continue
                parts = attribute.split(".")
                owner: object = module
                try:
                    for part in parts[:-1]:
                        owner = getattr(owner, part)
                    if not hasattr(owner, parts[-1]):
                        continue
                except AttributeError:  # pragma: no cover - module topology change
                    continue
                self._bind(stack, owner, parts[-1], module_name, counter)
            for name in ("write_text", "write_bytes", "mkdir"):
                self._bind(stack, Path, name, "pathlib.Path", "filesystem_writes")
            try:
                yield self
            finally:
                self._armed = False

    def evidence(self) -> dict:
        return {"armed": self._armed, "scopes": list(self.scopes),
                **{name: self.counts[name] for name in PROBE_COUNTERS}}

    @property
    def effects(self) -> int:
        return sum(self.counts[name] for name in PROBE_COUNTERS)


def _counted_factory(factory: Callable[[], ScenarioRunner],
                     probe: LaunchProbe) -> Callable[[], ScenarioRunner]:
    if not callable(factory):
        raise NegativeGateError("runner factory must be callable")

    def counted():
        probe.record("factory_calls", target="runner_factory")
        return factory()
    return counted


# ---------------------------------------------------------------------------
# Declaration-only topology and the preflight executor.
# ---------------------------------------------------------------------------


class DeclaredSession:
    """A declared component endpoint: no artifact, no binary, no process."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.router = None
        self.memory = None

    @property
    def process(self):
        return None

    def _refuse(self, action: str) -> None:
        raise RuntimeError(f"declaration topology cannot {action} a harness")

    def prepare_local(self) -> None:
        self._refuse("build")

    def begin_case(self, testcase_id: str) -> None:
        self._refuse("start")

    def end_case(self) -> None:
        self._refuse("stop")


class DeclaredTopology:
    """Runner-shaped object over a declaration; structurally unable to run RTL."""

    def __init__(self, declaration: PathDeclaration) -> None:
        wiring = declaration.wiring
        self.sessions = {name: DeclaredSession(name) for name in wiring.sessions}
        windows = tuple(DeviceWindow(device_id, base, size, self.sessions[component])
                        for device_id, base, size, component in wiring.windows)
        if windows:
            self.sessions[wiring.router_initiator].router = DataflowRouter(windows)
        self.sessions[wiring.memory_component].memory = PersistentMemory(
            regions=wiring.memory_regions,
            initialization_seed=wiring.memory_initialization_seed,
            max_initialized_bytes=wiring.max_initialized_bytes)
        self.ownership = compile_ownership(wiring.ownership_fields,
                                           wiring.ownership_owners)
        self.bindings = wiring.bindings

    def begin_test(self, testcase_id: str) -> None:
        raise RuntimeError("declaration topology cannot start a harness")


def declared_topology(declaration: PathDeclaration) -> DeclaredTopology:
    if not isinstance(declaration, PathDeclaration):
        raise NegativeGateError("declared topology requires a path declaration")
    return DeclaredTopology(declaration)


def compile_declared_paths(declaration: PathDeclaration
                           ) -> CompiledRuntimePathContract:
    """Run the real runtime path checker against the declared topology."""
    topology = declared_topology(declaration)
    return compile_runtime_path_contract(declaration.graph, declaration.contract,
                                         topology, paths=declaration.runtime_paths)


def _edge_from_message(message: str) -> tuple[int, int] | None:
    match = _MESSAGE_EDGE.search(message)
    return None if match is None else (int(match.group(1)), int(match.group(2)))


def _result(declaration: PathDeclaration, trusted: PathDeclaration, probe: LaunchProbe,
            *, rejected: bool, stage: str, delta: list[dict],
            reason: str | None = None, error_type: str | None = None,
            framework_reason: str | None = None,
            extra: dict | None = None) -> dict:
    edge = _edge_from_message(framework_reason or reason or "")
    located_by = "framework_message"
    if edge is None and delta and delta[0].get("edge"):
        edge = (delta[0]["edge"]["rule_index"], delta[0]["edge"]["prerequisite_index"])
        located_by = "declaration_delta"
    first_failing_edge = None
    if edge is not None:
        key = {"rule_index": edge[0], "prerequisite_index": edge[1]}
        path_id = next((entry.get("path_id") for entry in delta
                        if entry.get("edge") == key and entry.get("path_id")), None)
        if path_id is None:
            path_id = (_selections_for_edge(declaration, edge)
                       or _selections_for_edge(trusted, edge))
        field = next((entry["field"] for entry in delta if entry.get("edge") == key), None)
        first_failing_edge = {"rule_index": edge[0], "prerequisite_index": edge[1],
                              "path_id": path_id, "field": field,
                              "located_by": located_by}
    result = {"schema_version": RESULT_SCHEMA,
              "authority": declaration.authority,
              "rejected": rejected,
              "stage": stage,
              "reason": reason,
              "error_type": error_type,
              "framework_reason": framework_reason,
              "located_reason": located_reason(delta),
              "coherence_findings": self_findings(declaration),
              "first_failing_edge": first_failing_edge,
              "declaration_delta": delta,
              "declaration_sha256": declaration.identity_sha256,
              "trusted_sha256": trusted.identity_sha256,
              "changed": declaration.identity_sha256 != trusted.identity_sha256,
              "path_ids": list(declaration.path_ids),
              "probe": probe.evidence(),
              "no_harness_effects": probe.effects == 0,
              "rejected_before_harness": bool(rejected and probe.effects == 0)}
    if extra:
        result.update(extra)
    return result


def _refuse_harness_effects(result: dict, probe: LaunchProbe) -> None:
    if result["stage"] in DECLARATION_STAGES and probe.effects:
        raise ProbeViolation(
            f"declaration rejection at {result['stage']} recorded harness effects: "
            f"{probe.evidence()}")


def preflight_path_declaration(declaration: PathDeclaration, *,
                               trusted: PathDeclaration | None = None,
                               factory: Callable[[], ScenarioRunner] | None = None,
                               probe: LaunchProbe | None = None,
                               runner_stage: bool = False) -> dict:
    """Reject a declared path break before any harness render or RTL process.

    Stages: canonical admission, the real runtime path contract compile against
    the declaration-only topology, a trusted-declaration coherence check, and
    optionally the same compile against a real factory-built runner.
    """
    if not isinstance(declaration, PathDeclaration):
        raise NegativeGateError("preflight requires a path declaration")
    if type(runner_stage) is not bool:
        raise NegativeGateError("runner_stage must be boolean")
    if probe is None:
        probe = LaunchProbe()
    if not isinstance(probe, LaunchProbe):
        raise NegativeGateError("probe must be a LaunchProbe")
    if trusted is None:
        trusted = trusted_path_declaration(declaration.authority)
    elif not isinstance(trusted, PathDeclaration):
        raise NegativeGateError("trusted declaration must be a path declaration")
    if factory is not None and runner_stage:
        factory = _counted_factory(factory, probe)
    with probe.arm("preflight_path_declaration"):
        try:
            admitted = PathDeclaration.from_document(declaration.document())
        except ValueError as error:
            result = _result(declaration, trusted, probe, rejected=True,
                             stage="declaration_admission", delta=[],
                             reason=str(error), error_type=type(error).__name__)
            _refuse_harness_effects(result, probe)
            return result
        delta = declaration_delta(trusted, admitted)
        try:
            compiled = compile_declared_paths(admitted)
        except ValueError as error:
            result = _result(admitted, trusted, probe, rejected=True,
                             stage="contract_compile", delta=delta,
                             reason=str(error), error_type=type(error).__name__,
                             framework_reason=str(error))
            _refuse_harness_effects(result, probe)
            return result
        if delta:
            result = _result(admitted, trusted, probe, rejected=True,
                             stage="declaration_coherence", delta=delta,
                             reason=located_reason(delta), error_type="ValueError")
            _refuse_harness_effects(result, probe)
            return result
        if runner_stage and factory is not None:
            try:
                # The runner stage builds a runner object by definition; that
                # one effect is permitted and still counted. Every other effect
                # stays forbidden even here.
                with probe.permit("harness_session_constructions"):
                    runner = factory()
                real = compile_runtime_path_contract(
                    admitted.graph, admitted.contract, runner,
                    paths=admitted.runtime_paths)
                real.validate_topology()
            except ValueError as error:
                return _result(admitted, trusted, probe, rejected=True,
                               stage="runner_topology", delta=[],
                               reason=str(error), error_type=type(error).__name__,
                               framework_reason=str(error))
            return _result(admitted, trusted, probe, rejected=False, stage="accepted",
                           delta=[], extra={"runner_topology": real.document()})
        return _result(admitted, trusted, probe, rejected=False, stage="accepted",
                       delta=[], extra={"compiled": compiled.document()})


def expect_preflight_rejection(variant: NegativeGateVariant,
                               factory: Callable[[], ScenarioRunner] | None = None, *,
                               declaration: PathDeclaration | None = None,
                               probe: LaunchProbe | None = None,
                               runner_stage: bool = True) -> dict:
    """Apply one trusted gate variant, then demand a located pre-RTL rejection."""
    if not isinstance(variant, NegativeGateVariant):
        raise NegativeGateError("expect_preflight_rejection requires a gate variant")
    base = trusted_path_declaration() if declaration is None else declaration
    if not isinstance(base, PathDeclaration):
        raise NegativeGateError("gate variant requires a path declaration")
    if probe is None:
        probe = LaunchProbe()
    try:
        # The probe also covers the declaration transform: building a variant
        # document must not touch a harness either.
        with probe.arm("variant_application"):
            mutated = variant.apply(base)
    except ValueError as error:
        result = _result(base, base, probe, rejected=True,
                         stage="declaration_admission", delta=[],
                         reason=str(error), error_type=type(error).__name__)
        return {**result, "variant_id": variant.variant_id,
                "variant": variant.document()}
    result = preflight_path_declaration(mutated, trusted=base, factory=factory,
                                        probe=probe, runner_stage=runner_stage)
    return {**result, "variant_id": variant.variant_id,
            "variant": variant.document()}


# ---------------------------------------------------------------------------
# Replay mutual recognition: same graph, different edge identity.
# ---------------------------------------------------------------------------


def replay_identity_record(declaration: PathDeclaration) -> dict:
    """The saved-declaration record shape the corpus replay gate consumes."""
    if not isinstance(declaration, PathDeclaration):
        raise NegativeGateError("replay identity record requires a path declaration")
    return {"status": "contract_preflight",
            "declaration": declaration.prepared.document(),
            "compiled": {}}


def assert_replay_identity_not_mutually_recognized(
        trusted: PathDeclaration, swapped: PathDeclaration, *,
        probe: LaunchProbe | None = None) -> dict:
    """Two declarations of one graph under different edge identities.

    Uses the real replay identity gate
    (``ScenarioRfuzzExecutor._install_runtime_replay_identity``: exactly what
    ``replay_scenario_rfuzz_corpus`` runs before it touches a factory) against
    real ``GenomeRecordDecoder`` instances built from each declaration.  This is
    an API-level verification of identity, not an RTL replay.
    """
    for declaration in (trusted, swapped):
        if not isinstance(declaration, PathDeclaration):
            raise NegativeGateError("replay identity gate requires path declarations")
        if not declaration.source_bindings:
            raise NegativeGateError(
                "replay identity gate requires a declaration with trusted source bindings")
    if probe is None:
        probe = LaunchProbe()
    # ``myfuzz.integration`` builds on ``myfuzz.scenario``; importing it inside
    # the function keeps that direction one-way at module import time.
    from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor

    templates = make_ibex_pulp_dual_source_templates().decoder.templates
    with probe.arm("replay_identity"):
        def executor_for(declaration: PathDeclaration, run_id: str):
            decoder = GenomeRecordDecoder(
                graph=declaration.graph,
                ownership=compile_ownership(declaration.wiring.ownership_fields,
                                            declaration.wiring.ownership_owners),
                source_bindings=SourceBindings(declaration.source_bindings),
                runtime_contract=declaration.contract,
                templates=templates)
            return ScenarioRfuzzExecutor(run_id=run_id, decoder=decoder,
                                         factory=_refusing_factory,
                                         targets=_REPLAY_TARGETS, replay_only=True)

        executor_trusted = executor_for(trusted, "p2-replay-trusted")
        executor_swapped = executor_for(swapped, "p2-replay-swapped")
        record_trusted = replay_identity_record(trusted)
        record_swapped = replay_identity_record(swapped)

        def install(executor, record: dict) -> str | None:
            try:
                executor._install_runtime_replay_identity(record)
            except ValueError as error:
                return str(error)
            return None

        trusted_by_trusted = install(executor_trusted, record_trusted)
        swapped_by_swapped = install(executor_swapped, record_swapped)
        trusted_by_swapped = install(executor_swapped, record_trusted)
        swapped_by_trusted = install(executor_trusted, record_swapped)
    report = {
        "schema_version": REPLAY_SCHEMA,
        "same_graph": (trusted.graph.edge_document() == swapped.graph.edge_document()),
        "path_ids": list(trusted.path_ids),
        "swapped_path_ids": list(swapped.path_ids),
        "contract_sha256": trusted.contract.identity_sha256,
        "swapped_contract_sha256": swapped.contract.identity_sha256,
        "declaration_sha256": trusted.identity_sha256,
        "swapped_declaration_sha256": swapped.identity_sha256,
        "trusted_recognized_by_trusted": trusted_by_trusted is None,
        "swapped_recognized_by_swapped": swapped_by_swapped is None,
        "trusted_recognized_by_swapped": trusted_by_swapped is None,
        "swapped_recognized_by_trusted": swapped_by_trusted is None,
        "trusted_rejected_by_swapped": trusted_by_swapped,
        "swapped_rejected_by_trusted": swapped_by_trusted,
        "probe": probe.evidence(),
        "no_harness_effects": probe.effects == 0,
        "rejected_before_harness": probe.effects == 0,
    }
    if report["same_graph"] and not report["trusted_recognized_by_trusted"]:
        raise NegativeGateError("the trusted replay identity must recognize itself")
    return report


def _refusing_factory():
    raise AssertionError("replay identity verification must not construct a runner")
