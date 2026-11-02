"""Process-local binding of an issued static plan to real sessions.

A ``BoundExecutionPlan`` is not serializable and has no ``from_json``.  It is
created only by :func:`bind_execution_plan`, privately stores the actual runner,
sessions, prepared runtime-path objects and bound adapters, and refuses any
object that this preparation did not issue or attach.  Every effect boundary
re-checks object identity and the pinned implementation/ABI facts.
"""
from __future__ import annotations

from hashlib import sha256
import json
from types import MappingProxyType
from typing import Mapping

from myfuzz.scenario.runner import ScenarioRunner

from .contracts import (
    AdapterSelection,
    GenericExecutionPlan,
    GenericRuntimeRefused,
    ProcessLocalIssuance,
    canonical_json_bytes,
    parse_closed_json,
)
from .preparation import PreparationContext
from .registry import (
    AHB_CPU_ADAPTER_ID,
    AXI4LITE_CPU_ADAPTER_ID,
    AXI4_CPU_ADAPTER_ID,
    CPU_ADAPTER_ID,
    TL_COHERENT_CPU_ADAPTER_ID,
    GPIO_STORAGE_ADAPTER_ID,
    STORAGE_ADAPTER_ID,
    WISHBONE_CPU_ADAPTER_ID,
    WISHBONE_STORAGE_ADAPTER_ID,
    registrations,
)

_TOKEN = object()
_LIVE = ProcessLocalIssuance("bound-execution-plans")

_COMPONENT_KEYS = ("instance_id", "source_sha256", "profile_sha256",
                   "artifact_sha256", "semantic_contract_sha256",
                   "descriptor_sha256")
_SELECTION_KEYS = ("adapter_id", "adapter_version", "implementation_sha256",
                   "component_artifact_sha256", "semantic_contract_sha256",
                   "instance_id", "endpoint_id", "role")


def _refuse(code: str, pointer: str = "", detail=None) -> None:
    raise GenericRuntimeRefused(code, pointer, detail)


def _bind_storage_adapter(*, component, session, selection, preparation,
                          endpoint_id):
    from .adapters.apb3_storage import (
        bind_storage_adapter,
        declare_target_route,
    )
    route = declare_target_route(preparation=preparation,
                                 component=component, endpoint_id=endpoint_id)
    return bind_storage_adapter(component=component, session=session,
                                selection=selection, route=route,
                                preparation=preparation)


def _bind_cpu_adapter(*, component, session, selection, preparation,
                      endpoint_id):
    from .adapters.obi_cpu import bind_cpu_adapter
    return bind_cpu_adapter(component=component, session=session,
                            selection=selection)


def _bind_wishbone_storage_adapter(*, component, session, selection,
                                     preparation, endpoint_id):
    from .adapters.wishbone_storage import (
        bind_wishbone_storage_adapter,
        declare_target_route,
    )
    route = declare_target_route(preparation=preparation,
                                 component=component, endpoint_id=endpoint_id)
    return bind_wishbone_storage_adapter(
        component=component, session=session, selection=selection,
        route=route, preparation=preparation, endpoint_id=endpoint_id)


def _bind_wishbone_cpu_adapter(*, component, session, selection,
                                preparation, endpoint_id):
    from .adapters.wishbone_cpu import bind_wishbone_cpu_adapter
    return bind_wishbone_cpu_adapter(
        component=component, session=session, selection=selection,
        preparation=preparation, endpoint_id=endpoint_id)


def _bind_gpio_storage_adapter(**kwargs):
    from .adapters.gpio_storage import bind_gpio_storage_adapter
    return bind_gpio_storage_adapter(**kwargs)


def _bind_ahb_cpu_adapter(**kwargs):
    from .adapters.ahb_cpu import bind_ahb_cpu_adapter
    return bind_ahb_cpu_adapter(**kwargs)


def _bind_axi4lite_cpu_adapter(**kwargs):
    from .adapters.axi4lite_cpu import bind_axi4lite_cpu_adapter
    return bind_axi4lite_cpu_adapter(**kwargs)


def _bind_axi4_cpu_adapter(**kwargs):
    from .adapters.axi4_cpu import bind_reduced_axi_cpu_adapter
    return bind_reduced_axi_cpu_adapter(**kwargs)


def _bind_tl_coherent_cpu_adapter(**kwargs):
    from .adapters.tilelink_cpu import bind_tl_coherent_cpu_adapter
    return bind_tl_coherent_cpu_adapter(**kwargs)


def _bind_cva6_axi4_cpu_adapter(**kwargs):
    from .adapters.cva6_axi4_cpu import bind_cva6_axi4_cpu_adapter
    return bind_cva6_axi4_cpu_adapter(**kwargs)


def _bind_mmio_adapter(**kwargs):
    from .adapters.apb3_mmio import bind_mmio_adapter
    return bind_mmio_adapter(**kwargs)


def _bind_wishbone_mmio_adapter(**kwargs):
    from .adapters.wishbone_mmio import bind_wishbone_mmio_adapter
    return bind_wishbone_mmio_adapter(**kwargs)


def _bind_tlul_mmio_adapter(**kwargs):
    from .adapters.extended_mmio import bind_tlul_adapter
    return bind_tlul_adapter(**kwargs)


def _bind_axi4lite_mmio_adapter(**kwargs):
    from .adapters.extended_mmio import bind_axi4lite_adapter
    return bind_axi4lite_adapter(**kwargs)


def _bind_ahb_lite_mmio_adapter(**kwargs):
    from .adapters.extended_mmio import bind_ahb_lite_adapter
    return bind_ahb_lite_adapter(**kwargs)


# Code-owned factories; there is no caller-supplied factory/import-string path.
_FACTORIES = MappingProxyType({
    AHB_CPU_ADAPTER_ID: _bind_ahb_cpu_adapter,
    TL_COHERENT_CPU_ADAPTER_ID: _bind_tl_coherent_cpu_adapter,
    AXI4LITE_CPU_ADAPTER_ID: _bind_axi4lite_cpu_adapter,
    AXI4_CPU_ADAPTER_ID: _bind_axi4_cpu_adapter,
    'cva6.axi4.cpu.v1': _bind_cva6_axi4_cpu_adapter,
    'apb3.mmio.v1': _bind_mmio_adapter,
    'wishbone.mmio.v1': _bind_wishbone_mmio_adapter,
    'tlul.mmio.v1': _bind_tlul_mmio_adapter,
    'axi4lite.mmio.v1': _bind_axi4lite_mmio_adapter,
    'ahb-lite.mmio.v1': _bind_ahb_lite_mmio_adapter,
    GPIO_STORAGE_ADAPTER_ID: _bind_gpio_storage_adapter,
    STORAGE_ADAPTER_ID: _bind_storage_adapter,
    WISHBONE_STORAGE_ADAPTER_ID: _bind_wishbone_storage_adapter,
    WISHBONE_CPU_ADAPTER_ID: _bind_wishbone_cpu_adapter,
    CPU_ADAPTER_ID: _bind_cpu_adapter,
})


def _plan_document(plan: GenericExecutionPlan) -> dict:
    if type(plan) is not GenericExecutionPlan:
        _refuse("generic-plan-mismatch", "/plan",
                {"reason": "GenericExecutionPlan-required"})
    return plan.document()


def _plan_components(document: dict, preparation: PreparationContext) -> dict:
    rows = document.get("components")
    if type(rows) is not list or not rows:
        _refuse("generic-plan-mismatch", "/plan/components",
                {"reason": "nonempty-components-required"})
    issued = {component.instance_id: component
              for component in preparation.components()}
    if not issued:
        _refuse("generic-plan-mismatch", "/plan/components",
                {"reason": "no-component-issued-by-this-preparation"})
    components = {}
    for index, row in enumerate(rows):
        pointer = f"/plan/components/{index}"
        parsed = parse_closed_json(row, _COMPONENT_KEYS,
                                   optional=("descriptor",), pointer=pointer)
        instance_id = parsed["instance_id"]
        component = issued.get(instance_id)
        if component is None:
            _refuse("generic-plan-mismatch", pointer + "/instance_id",
                    {"reason": "component-not-issued-here",
                     "instance_id": instance_id})
        for name in ("source_sha256", "profile_sha256", "artifact_sha256",
                     "semantic_contract_sha256"):
            if parsed[name] != getattr(component, name):
                _refuse("generic-plan-mismatch", pointer + "/" + name,
                        {"reason": "component-identity-mismatch"})
        if parsed["descriptor_sha256"] != component.descriptor_sha256():
            _refuse("generic-plan-mismatch", pointer + "/descriptor_sha256",
                    {"reason": "descriptor-digest-mismatch"})
        if "descriptor" in parsed and parsed["descriptor"] != component.document():
            _refuse("generic-plan-mismatch", pointer + "/descriptor",
                    {"reason": "descriptor-document-mismatch"})
        if instance_id in components:
            _refuse("generic-plan-mismatch", pointer + "/instance_id",
                    {"reason": "duplicate-component"})
        components[instance_id] = component
    missing = sorted(set(issued) - set(components))
    if missing:
        _refuse("generic-plan-mismatch", "/plan/components",
                {"reason": "admitted-components-not-in-plan",
                 "instances": missing})
    return components


def _issued_selection(preparation: PreparationContext,
                      selection: AdapterSelection) -> AdapterSelection:
    wanted = selection.canonical_bytes()
    for issued in preparation.selections():
        if issued.canonical_bytes() == wanted:
            return preparation.require_selection(issued)
    _refuse("generic-plan-mismatch", "/plan/selections",
            {"reason": "selection-not-issued-by-this-preparation",
             "adapter_id": selection.adapter_id})


def _plan_selections(document: dict, preparation: PreparationContext,
                     components: dict) -> list:
    rows = document.get("selections")
    if type(rows) is not list or not rows:
        _refuse("generic-plan-mismatch", "/plan/selections",
                {"reason": "nonempty-selections-required"})
    selections = []
    seen_endpoints = set()
    for index, row in enumerate(rows):
        pointer = f"/plan/selections/{index}"
        parsed = parse_closed_json(row, _SELECTION_KEYS,
                                   optional=("selection_sha256",),
                                   pointer=pointer)
        instance_id = parsed["instance_id"]
        component = components.get(instance_id)
        if component is None:
            _refuse("generic-plan-mismatch", pointer + "/instance_id",
                    {"reason": "selection-component-not-in-plan"})
        selection = AdapterSelection(
            parsed["adapter_id"], parsed["adapter_version"],
            parsed["implementation_sha256"],
            parsed["component_artifact_sha256"],
            parsed["semantic_contract_sha256"])
        selection = _issued_selection(preparation, selection)
        if "selection_sha256" in parsed \
                and parsed["selection_sha256"] != selection.sha256():
            _refuse("generic-plan-mismatch", pointer + "/selection_sha256",
                    {"reason": "selection-digest-mismatch"})
        if selection.component_artifact_sha256 != component.artifact_sha256:
            _refuse("generic-plan-mismatch",
                    pointer + "/component_artifact_sha256",
                    {"reason": "selection-artifact-mismatch"})
        if selection.semantic_contract_sha256 != component.semantic_contract_sha256:
            _refuse("generic-plan-mismatch",
                    pointer + "/semantic_contract_sha256",
                    {"reason": "selection-semantic-mismatch"})
        endpoints = {endpoint["endpoint_id"]: endpoint
                     for endpoint in component.endpoints()}
        endpoint = endpoints.get(parsed["endpoint_id"])
        if endpoint is None:
            _refuse("generic-plan-mismatch", pointer + "/endpoint_id",
                    {"reason": "endpoint-not-in-component"})
        if endpoint["role"] != parsed["role"]:
            _refuse("generic-plan-mismatch", pointer + "/role",
                    {"role": parsed["role"], "endpoint_role": endpoint["role"]})
        registration = {reg.adapter_id: reg for reg in registrations()}.get(
            selection.adapter_id)
        if registration is None:
            _refuse("generic-adapter-missing", pointer + "/adapter_id",
                    {"adapter_id": selection.adapter_id})
        if registration.adapter_version != selection.adapter_version:
            _refuse("generic-adapter-missing", pointer + "/adapter_version",
                    {"expected": registration.adapter_version,
                     "declared": selection.adapter_version})
        if registration.implementation_sha256() != selection.implementation_sha256:
            _refuse("generic-binding-drift", pointer + "/implementation_sha256",
                    {"adapter_id": selection.adapter_id,
                     "reason": "implementation-changed"})
        key = (instance_id, parsed["endpoint_id"])
        if key in seen_endpoints:
            _refuse("generic-adapter-ambiguous", pointer + "/endpoint_id",
                    {"reason": "duplicate-selection-for-endpoint"})
        seen_endpoints.add(key)
        selections.append(dict(instance_id=instance_id,
                               endpoint_id=parsed["endpoint_id"],
                               role=parsed["role"], selection=selection,
                               endpoint=endpoint, registration=registration))
    return selections


def _validate_sessions(sessions: Mapping[str, object], components: dict,
                       selections: list) -> dict:
    if not isinstance(sessions, Mapping):
        _refuse("generic-binding-drift", "/sessions",
                {"reason": "mapping-required"})
    required = {row["instance_id"] for row in selections}
    if set(sessions) != required:
        _refuse("generic-binding-drift", "/sessions",
                {"reason": "session-set-mismatch",
                 "required": sorted(required),
                 "supplied": sorted(sessions)})
    for name in sorted(sessions):
        if sessions[name] is None:
            _refuse("generic-binding-drift", "/sessions/" + name,
                    {"reason": "session-required"})
    return dict(sessions)


def _validate_runner(runner, sessions: dict) -> ScenarioRunner:
    if not isinstance(runner, ScenarioRunner):
        _refuse("generic-binding-drift", "/runner",
                {"reason": "ScenarioRunner-required"})
    runner_sessions = getattr(runner, "sessions", None)
    if not isinstance(runner_sessions, Mapping):
        _refuse("generic-binding-drift", "/runner/sessions")
    if set(runner_sessions) != set(sessions):
        _refuse("generic-binding-drift", "/runner/sessions",
                {"reason": "runner-session-set-mismatch",
                 "runner": sorted(runner_sessions),
                 "supplied": sorted(sessions)})
    for name, session in sessions.items():
        if runner_sessions[name] is not session:
            _refuse("generic-binding-drift", "/runner/sessions/" + name,
                    {"reason": "runner-session-identity-mismatch"})
    return runner


def _validate_runtime_attachment(preparation: PreparationContext, *,
                                 runner, sessions: dict) -> None:
    registered = preparation.runtime_objects()
    if registered.get("runner") is not runner:
        _refuse("generic-binding-drift", "/runner",
                {"reason": "runner-not-attached-by-this-preparation"})
    registered_sessions = registered.get("sessions") or {}
    if set(registered_sessions) != set(sessions):
        _refuse("generic-binding-drift", "/sessions",
                {"reason": "attached-session-set-mismatch"})
    for name, session in sessions.items():
        if registered_sessions[name] is not session:
            _refuse("generic-binding-drift", "/sessions/" + name,
                    {"reason": "session-not-attached-by-this-preparation"})


def _validate_prepared_paths(preparation: PreparationContext,
                             prepared_paths) -> None:
    registered = preparation.prepared_paths()
    if registered.get("prepared") is not prepared_paths:
        _refuse("generic-plan-mismatch", "/prepared_paths",
                {"reason": "prepared-graph-not-issued-by-this-preparation"})


def _bind_adapters(preparation: PreparationContext, *,
                   components: dict, selections: list,
                   sessions: dict) -> dict:
    adapters = {}
    for row in selections:
        instance_id = row["instance_id"]
        if instance_id in adapters:
            _refuse("generic-adapter-ambiguous", "/selections",
                    {"reason": "multiple-adapters-for-instance",
                     "instance_id": instance_id})
        factory = _FACTORIES.get(row["registration"].adapter_id)
        if factory is None:
            _refuse("generic-adapter-missing", "/selections",
                    {"adapter_id": row["registration"].adapter_id})
        try:
            bound = factory(component=components[instance_id],
                            session=sessions[instance_id],
                            selection=row["selection"],
                            preparation=preparation,
                            endpoint_id=row["endpoint_id"])
        except GenericRuntimeRefused:
            raise
        except (TypeError, ValueError) as error:
            _refuse("generic-binding-drift", "/adapters/" + instance_id,
                    {"reason": "adapter-bind-refused",
                     "adapter_id": row["registration"].adapter_id,
                     "detail": str(error)[:160]})
        for name, expected in (
                ("component_instance_id", instance_id),
                ("adapter_id", row["selection"].adapter_id),
                ("adapter_version", row["selection"].adapter_version)):
            if getattr(bound, name, None) != expected:
                _refuse("generic-binding-drift",
                        "/adapters/" + instance_id + "/" + name,
                        {"expected": expected})
        for method in ("assert_current", "close"):
            if not callable(getattr(bound, method, None)):
                _refuse("generic-binding-drift",
                        "/adapters/" + instance_id + "/" + method,
                        {"reason": "adapter-surface-required"})
        bound.assert_current()
        adapters[instance_id] = bound
    return adapters


class BoundExecutionPlan:
    """Process-local live handle; construction outside this module is refused."""

    __slots__ = ("_plan", "_preparation", "_sessions", "_runner",
                 "_prepared_paths", "_adapters", "_plan_sha256",
                 "_documentary", "_closed")

    def __init__(self, *, _token):
        if _token is not _TOKEN:
            _refuse("generic-binding-drift", "/bound_plan",
                    {"reason": "bind_execution_plan-required"})

    @classmethod
    def _build(cls, *, plan, preparation, sessions, runner, prepared_paths,
               adapters) -> "BoundExecutionPlan":
        handle = cls(_token=_TOKEN)
        handle._plan = plan
        handle._preparation = preparation
        handle._sessions = MappingProxyType(dict(sessions))
        handle._runner = runner
        handle._prepared_paths = prepared_paths
        handle._adapters = MappingProxyType(dict(adapters))
        handle._plan_sha256 = plan.identity_sha256
        handle._documentary = None
        handle._closed = False
        return handle

    @property
    def plan(self) -> GenericExecutionPlan:
        return self._plan

    @property
    def plan_sha256(self) -> str:
        return self._plan_sha256

    @property
    def sessions(self) -> Mapping[str, object]:
        return self._sessions

    @property
    def runner(self) -> ScenarioRunner:
        return self._runner

    @property
    def prepared_paths(self):
        return self._prepared_paths

    @property
    def adapters(self) -> Mapping[str, object]:
        return self._adapters

    @property
    def closed(self) -> bool:
        return self._closed

    def require_live(self) -> "BoundExecutionPlan":
        if self._closed:
            _refuse("generic-binding-drift", "/bound_plan",
                    {"reason": "binding-closed"})
        if not _LIVE.holds(self):
            _refuse("generic-binding-drift", "/bound_plan",
                    {"reason": "not-issued-by-this-process"})
        return self

    def assert_current(self) -> None:
        self.require_live()
        self._preparation.assert_current()
        if self._plan.identity_sha256 != self._plan_sha256:
            _refuse("generic-plan-mismatch", "/plan/identity_sha256")
        if sha256(self._plan.document_bytes).hexdigest() != self._plan_sha256:
            _refuse("generic-plan-mismatch", "/plan/document_bytes")
        self._preparation.require_plan(self._plan)
        registered = self._preparation.runtime_objects()
        if registered.get("runner") is not self._runner:
            _refuse("generic-binding-drift", "/runner",
                    {"reason": "runner-replaced"})
        runner_sessions = getattr(self._runner, "sessions", None)
        if not isinstance(runner_sessions, Mapping) or set(runner_sessions) != set(self._sessions):
            _refuse("generic-binding-drift", "/runner/sessions")
        for name, session in self._sessions.items():
            if runner_sessions[name] is not session:
                _refuse("generic-binding-drift", "/runner/sessions/" + name,
                        {"reason": "session-replaced"})
        self._validate_prepared_identity()
        for name, adapter in self._adapters.items():
            adapter.assert_current()

    def _validate_prepared_identity(self) -> None:
        registered = self._preparation.prepared_paths()
        if registered.get("prepared") is not self._prepared_paths:
            _refuse("generic-plan-mismatch", "/prepared_paths",
                    {"reason": "prepared-graph-replaced"})

    def documentary(self) -> dict:
        if self._closed:
            _refuse("generic-binding-drift", "/bound_plan",
                    {"reason": "binding-closed"})
        if self._documentary is None:
            self._documentary = {
                "schema_version": "bound_execution_plan.v1",
                "scope": "process_local_documentary_no_native_authority",
                "plan_sha256": self._plan_sha256,
                "preparation_id": self._preparation.preparation_id,
                "sessions": sorted(self._sessions),
                "components": sorted(self._sessions),
                "adapters": [
                    {"instance_id": name,
                     "adapter_id": adapter.adapter_id,
                     "adapter_version": adapter.adapter_version,
                     "binding_sha256": getattr(adapter, "binding_sha256", None)}
                    for name, adapter in sorted(self._adapters.items())
                ],
            }
        return json.loads(json.dumps(self._documentary))

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        _LIVE.revoke(self)
        errors = []
        for name, adapter in self._adapters.items():
            try:
                adapter.close()
            except Exception as error:  # noqa: BLE001 - cleanup must drain all
                errors.append((name, repr(error)))
        self._adapters = MappingProxyType({})
        self._sessions = MappingProxyType({})
        self._runner = None
        self._prepared_paths = None
        self._plan = None
        self._preparation = None
        self._documentary = None
        if errors:
            _refuse("generic-binding-drift", "/adapters/close",
                    {"errors": errors[:4]})


def require_bound_plan(handle, *, pointer: str = "/bound_plan") -> BoundExecutionPlan:
    """Accept only a handle issued by :func:`bind_execution_plan` in this process."""
    if type(handle) is not BoundExecutionPlan:
        _refuse("generic-binding-drift", pointer,
                {"reason": "BoundExecutionPlan-required"})
    _LIVE.require(handle, pointer=pointer)
    return handle


def bind_execution_plan(plan: GenericExecutionPlan, *,
                        preparation: PreparationContext,
                        sessions: Mapping[str, object],
                        prepared_paths,
                        runner: ScenarioRunner) -> BoundExecutionPlan:
    """Bind one issued plan to this preparation's attached live objects."""
    if type(preparation) is not PreparationContext:
        _refuse("generic-contract-type", "/preparation")
    preparation.require_open()
    document = _plan_document(plan)
    prepared = preparation.require_plan(plan)
    preparation.assert_current()
    components = _plan_components(document, preparation)
    selections = _plan_selections(document, preparation, components)
    supplied_sessions = _validate_sessions(sessions, components, selections)
    validated_runner = _validate_runner(runner, supplied_sessions)
    _validate_runtime_attachment(preparation, runner=validated_runner,
                                 sessions=supplied_sessions)
    _validate_prepared_paths(preparation, prepared_paths)
    adapters = _bind_adapters(preparation, components=components,
                              selections=selections,
                              sessions=supplied_sessions)
    handle = BoundExecutionPlan._build(
        plan=prepared, preparation=preparation, sessions=supplied_sessions,
        runner=validated_runner, prepared_paths=prepared_paths,
        adapters=adapters)
    _LIVE.issue(handle, snapshot=canonical_json_bytes(handle.documentary()))
    return handle
