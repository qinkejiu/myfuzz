"""One same-preparation D2/D3 context and its process-local object membership.

``create_preparation`` is the only issuer: it performs exactly one D2 generation,
one request/ownership build and one ``compile_paths`` call, then assesses every
requested flow on the *same* artifact mapping and compiled inputs.  The context
privately owns the real ``LocalRuntimeArtifact`` objects, the sealed input pins
and the issued component/selection/plan handles.  A JSON document, an equal
dataclass value or another preparation's objects never become members.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import uuid

from myfuzz.integration.compiled_execution_files import (
    PreparedCompiledInputs,
    _hashes,
    _no_symlinks,
    _source_paths,
    prepare_compiled_execution_inputs,
)
from myfuzz.local_harness.generated_artifact_admission import (
    GeneratedArtifactRefused,
    _artifact_files,
)
from myfuzz.local_harness.runtime_artifact import LocalRuntimeArtifact
from myfuzz.scenario.compiled_paths import compiled_document_sha256

from .contracts import (
    AdapterSelection,
    CapabilityRequirement,
    GenericExecutionPlan,
    GenericRuntimeRefused,
    ProcessLocalIssuance,
    VerifiedComponent,
    canonical_json_bytes,
    require_digest,
    require_identifier,
)

_TOKEN = object()
_GENERIC_FLOWS = ("F1", "F2", "F3", "F4", "F5", "F6")


def _refuse(code: str, pointer: str = "", detail=None) -> None:
    raise GenericRuntimeRefused(code, pointer, detail)


def _digest(value: bytes) -> str:
    return sha256(value).hexdigest()


def _json_sha(value) -> str:
    return _digest(canonical_json_bytes(value))


def _input_file(path: Path) -> Path:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        _refuse("generic-source-unverified", str(path),
                {"reason": "regular-input-file-required"})
    return path


@dataclass(frozen=True, slots=True)
class PreparationInputs:
    """Canonical documentary view of the files one preparation consumed."""

    base_dir: Path
    compose_path: Path
    capability_paths: tuple[Path, ...]
    supplement_path: Path
    generated_dir: Path
    flow_ids: tuple[str, ...]


class PreparationContext:
    """Private live owner of one same-pass preparation.  Not JSON-restorable."""

    __slots__ = (
        "_inputs", "_artifacts", "_compiled_inputs", "_supports",
        "_request_document", "_capability_selection", "_stamp",
        "_source_pins", "_generated_pins", "_input_digests",
        "_components", "_selections", "_plans", "_closed", "_test_only",
        "_prepared_paths", "_runtime_objects", "_documentary", "_f6_provider_artifacts",
    )

    def __init__(self, *, _token):
        if _token is not _TOKEN:
            _refuse("generic-binding-drift", "/preparation",
                    {"reason": "create_preparation-required"})

    # -- construction -----------------------------------------------------
    @classmethod
    def _build(cls, *, inputs: PreparationInputs,
               prepared: PreparedCompiledInputs,
               source_pins: dict[str, str],
               generated_pins: dict[str, str],
               input_digests: dict[str, str]) -> "PreparationContext":
        context = cls(_token=_TOKEN)
        context._inputs = inputs
        context._artifacts = dict(prepared.artifacts)
        context._f6_provider_artifacts = prepared.artifacts if "F6" in inputs.flow_ids else None
        context._compiled_inputs = prepared.inputs
        context._supports = dict(prepared.supports)
        context._request_document = prepared.request_document
        context._capability_selection = prepared.capability_selection
        context._stamp = (f"prep-{uuid.uuid4().hex[:16]}")
        context._source_pins = dict(source_pins)
        context._generated_pins = dict(generated_pins)
        context._input_digests = dict(input_digests)
        context._components = ProcessLocalIssuance("verified-components")
        context._selections = ProcessLocalIssuance("adapter-selections")
        context._plans = ProcessLocalIssuance("execution-plans")
        context._closed = False
        context._test_only = False
        context._prepared_paths = None
        context._runtime_objects = None
        context._documentary = None
        return context

    @classmethod
    def _for_tests(cls) -> "PreparationContext":
        """Software-test fixture with no artifacts; production never calls it."""
        context = cls(_token=_TOKEN)
        context._inputs = None
        context._artifacts = {}
        context._f6_provider_artifacts = None
        context._compiled_inputs = {}
        context._supports = {}
        context._request_document = {}
        context._capability_selection = {}
        context._stamp = "prep-test-fixture"
        context._source_pins = {}
        context._generated_pins = {}
        context._input_digests = {}
        context._components = ProcessLocalIssuance("verified-components")
        context._selections = ProcessLocalIssuance("adapter-selections")
        context._plans = ProcessLocalIssuance("execution-plans")
        context._closed = False
        context._test_only = True
        context._prepared_paths = None
        context._runtime_objects = None
        context._documentary = None
        return context

    # -- basic state ------------------------------------------------------
    def require_open(self) -> "PreparationContext":
        if self._closed:
            _refuse("generic-binding-drift", "/preparation",
                    {"reason": "preparation-closed"})
        return self

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def preparation_id(self) -> str:
        return self._stamp

    @property
    def inputs(self) -> PreparationInputs:
        return self._inputs

    @property
    def base_dir(self) -> Path:
        return Path(self._inputs.base_dir)

    @property
    def generated_dir(self) -> Path:
        return Path(self._inputs.generated_dir)

    @property
    def flow_ids(self) -> tuple[str, ...]:
        return tuple(self._inputs.flow_ids)

    @property
    def artifacts(self):
        from types import MappingProxyType
        return MappingProxyType(self._artifacts)

    @property
    def input_digests(self) -> dict:
        return dict(self._input_digests)

    def artifact(self, instance_id: str) -> LocalRuntimeArtifact:
        self.require_open()
        artifact = self._artifacts.get(instance_id)
        if artifact is None:
            _refuse("generic-source-unverified", "/instance_id",
                    {"reason": "not-in-this-preparation",
                     "instances": sorted(self._artifacts)})
        return artifact

    def flow_support(self, flow_id: str) -> dict:
        self.require_open()
        support = self._supports.get(flow_id)
        if support is None:
            _refuse("generic-flow-unsupported", "/flow_id",
                    {"requested": flow_id, "prepared": sorted(self._supports)})
        return json.loads(json.dumps(support))

    # -- same-pass D3 facts ----------------------------------------------
    def compiled_inputs(self) -> dict:
        """Private API for compiler/binding in this package; the same objects."""
        self.require_open()
        return self._compiled_inputs

    def d3_document(self) -> dict:
        self.require_open()
        return json.loads(json.dumps(self._compiled_inputs["compiled"]))

    def declared_endpoint_template(self, instance_id: str,
                                   endpoint_id: str) -> tuple[str, str, str]:
        """Wiring-declared template triple for one endpoint (explicit, unique)."""
        self.require_open()
        wiring = None
        try:
            wiring = self._compiled_inputs["request"].wiring.document
        except (AttributeError, KeyError):
            _refuse("generic-template-mismatch", "/wiring",
                    {"reason": "wiring-document-required"})
        cpu = wiring.get("cpu") if isinstance(wiring, dict) else None
        if isinstance(cpu, dict) and cpu.get("instance_id") == instance_id:
            triple = (cpu.get("template"), "1", cpu.get("variant_id"))
        else:
            rows = [row for row in (wiring.get("windows") or ())
                    if isinstance(row, dict)
                    and row.get("target_instance") == instance_id
                    and row.get("endpoint_id") in (None, endpoint_id)]
            if len(rows) != 1:
                _refuse("generic-template-mismatch", "/wiring/windows",
                        {"instance_id": instance_id, "endpoint_id": endpoint_id,
                         "matches": len(rows)})
            triple = (rows[0].get("template"), "1", rows[0].get("variant_id"))
        if any(type(item) is not str or not item for item in triple):
            _refuse("generic-template-mismatch", "/wiring/template",
                    {"instance_id": instance_id, "endpoint_id": endpoint_id})
        return triple

    def declared_cpu_data_endpoint(self, instance_id: str) -> str:
        """The wiring-declared CPU data endpoint; never inferred from order."""
        self.require_open()
        try:
            wiring = self._compiled_inputs["request"].wiring.document
        except (AttributeError, KeyError):
            _refuse("generic-template-mismatch", "/wiring",
                    {"reason": "wiring-document-required"})
        cpu = wiring.get("cpu") if isinstance(wiring, dict) else None
        if not isinstance(cpu, dict) or cpu.get("instance_id") != instance_id:
            _refuse("generic-template-mismatch", "/wiring/cpu",
                    {"reason": "cpu-instance-mismatch",
                     "instance_id": instance_id})
        endpoint_id = cpu.get("endpoint_id")
        if type(endpoint_id) is not str or not endpoint_id:
            _refuse("generic-template-mismatch", "/wiring/cpu/endpoint_id")
        return endpoint_id

    def canonical_endpoint(self, instance_id: str, endpoint_id: str) -> dict:
        """The D3 endpoint row for this instance/endpoint, if declared once."""
        self.require_open()
        document = self._compiled_inputs["compiled"]
        rows = [row for row in document.get("endpoints", ())
                if row.get("instance_id") == instance_id
                and row.get("endpoint_id") == endpoint_id]
        if len(rows) > 1:
            _refuse("generic-template-mismatch", "/endpoints",
                    {"reason": "duplicate-endpoint", "endpoint_id": endpoint_id})
        return json.loads(json.dumps(rows[0])) if rows else None

    # -- issuance ---------------------------------------------------------
    def issue_component(self, component: VerifiedComponent) -> VerifiedComponent:
        self.require_open()
        if type(component) is not VerifiedComponent:
            _refuse("generic-contract-type", "/component")
        existing = [row for row in self.components()
                    if row.instance_id == component.instance_id]
        if existing:
            if existing[0].descriptor_bytes == component.descriptor_bytes:
                return existing[0]
            _refuse("generic-binding-drift", "/component",
                    {"reason": "component-already-issued", "instance_id":
                     component.instance_id})
        self._components.issue(component, snapshot=component.descriptor_bytes)
        self._documentary = None
        return component

    def _components_records(self):
        return self._components.records()

    def require_component(self, component: VerifiedComponent) -> VerifiedComponent:
        self.require_open()
        self._components.require(component, pointer="/component")
        if self._components.snapshot(component) != component.descriptor_bytes:
            _refuse("generic-binding-drift", "/component",
                    {"reason": "descriptor-changed-since-issuance"})
        return component

    def components(self) -> tuple[VerifiedComponent, ...]:
        return tuple(self._components_records())

    def issue_selection(self, selection: AdapterSelection) -> AdapterSelection:
        self.require_open()
        if type(selection) is not AdapterSelection:
            _refuse("generic-contract-type", "/selection")
        existing = [object_ for object_ in self._selections_records()
                    if object_.canonical_bytes() == selection.canonical_bytes()]
        if existing:
            # The recorded object is the issued one; equal bytes are idempotent.
            return existing[0]
        self._selections.issue(selection, snapshot=selection.canonical_bytes())
        self._documentary = None
        return selection

    def _selections_records(self):
        return self._selections.records()

    def require_selection(self, selection: AdapterSelection) -> AdapterSelection:
        self.require_open()
        self._selections.require(selection, pointer="/selection")
        if self._selections.snapshot(selection) != selection.canonical_bytes():
            _refuse("generic-binding-drift", "/selection",
                    {"reason": "selection-changed-since-issuance"})
        return selection

    def selections(self) -> tuple[AdapterSelection, ...]:
        return tuple(self._selections_records())

    def issue_plan(self, plan: GenericExecutionPlan) -> GenericExecutionPlan:
        self.require_open()
        if type(plan) is not GenericExecutionPlan:
            _refuse("generic-contract-type", "/plan")
        issued = self._plans_records()
        if issued:
            if issued[0] is plan:
                return plan
            _refuse("generic-plan-mismatch", "/plan",
                    {"reason": "one-plan-per-preparation",
                     "issued": issued[0].identity_sha256,
                     "requested": plan.identity_sha256})
        self._plans.issue(plan, snapshot=plan.document_bytes)
        self._documentary = None
        return plan

    def _plans_records(self):
        return self._plans.records()

    def require_plan(self, plan: GenericExecutionPlan) -> GenericExecutionPlan:
        self.require_open()
        self._plans.require(plan, pointer="/plan")
        if self._plans.snapshot(plan) != plan.document_bytes:
            _refuse("generic-binding-drift", "/plan",
                    {"reason": "plan-bytes-changed-since-issuance"})
        return plan

    def plans(self) -> tuple[GenericExecutionPlan, ...]:
        return tuple(self._plans_records())

    # -- G4: prepared graph and live runtime attachments -------------------
    def register_prepared_paths(self, *, prepared, runtime_paths, graph) -> None:
        self.require_open()
        if self._prepared_paths is not None:
            _refuse("generic-plan-mismatch", "/prepared_paths",
                    {"reason": "graph-already-materialized"})
        compiled = (self._compiled_inputs.get("compiled")
                    if isinstance(self._compiled_inputs, dict) else None)
        contract = (compiled_document_sha256(compiled)
                    if compiled is not None else None)
        if contract is None and not self._test_only:
            _refuse("generic-plan-mismatch", "/prepared_paths",
                    {"reason": "same-pass-inputs-required"})
        self._prepared_paths = dict(prepared=prepared, runtime_paths=runtime_paths,
                                    graph=graph, contract=contract)

    def prepared_paths(self):
        self.require_open()
        if self._prepared_paths is None:
            _refuse("generic-plan-mismatch", "/prepared_paths",
                    {"reason": "graph-not-materialized"})
        return self._prepared_paths

    def attach_runtime(self, *, runner, sessions) -> None:
        self.require_open()
        if self._runtime_objects is not None:
            _refuse("generic-binding-drift", "/runner",
                    {"reason": "runtime-already-attached"})
        self._runtime_objects = dict(runner=runner, sessions=dict(sessions))

    def runtime_objects(self):
        self.require_open()
        if self._runtime_objects is None:
            _refuse("generic-binding-drift", "/runner",
                    {"reason": "runtime-not-attached"})
        return self._runtime_objects

    # -- evidence boundary -------------------------------------------------
    def assert_artifact_current(self, artifact: LocalRuntimeArtifact) -> None:
        self.require_open()
        instance_id = artifact.plan.request.instance_id
        if self._artifacts.get(instance_id) is not artifact:
            _refuse("generic-source-unverified", "/artifact",
                    {"reason": "not-the-preparation-object"})
        for filename, payload in _artifact_files(artifact).items():
            path = self.generated_dir / instance_id / filename
            try:
                current = path.read_bytes()
            except OSError as error:
                _refuse("generic-source-unverified", "/artifact",
                        {"reason": "generated-file-unreadable",
                         "file": str(path)})
            if current != payload:
                _refuse("generic-binding-drift", "/artifact",
                        {"reason": "generated-file-changed", "file": filename})

    def assert_current(self) -> None:
        """Recheck sealed input and generated-file pins at a boundary only."""
        self.require_open()
        if not self._source_pins and not self._test_only:
            _refuse("generic-source-unverified", "/inputs",
                    {"reason": "no-source-pins"})
        if self._test_only:
            return
        if self._f6_provider_artifacts is not None:
            try:
                from myfuzz.local_harness.generated_artifact_admission import validated_f6_provider_credentials
                validated_f6_provider_credentials(self._f6_provider_artifacts)
                if (set(self._f6_provider_artifacts) != set(self._artifacts)
                        or any(self._f6_provider_artifacts[name] is not artifact
                               for name, artifact in self._artifacts.items())):
                    raise ValueError("f6-provider-artifact-replaced")
            except ValueError as error:
                _refuse("generic-binding-drift", "/artifacts",
                        {"reason": str(error)[:160]})
        source_arguments = self._source_arguments()
        try:
            paths = _source_paths(*source_arguments)
            hashes = _hashes(paths)
        except (OSError, ValueError) as error:
            _refuse("generic-source-unverified", "/inputs",
                    {"reason": type(error).__name__})
        if hashes != self._source_pins:
            changed = sorted(set(hashes) ^ set(self._source_pins))
            _refuse("generic-binding-drift", "/inputs",
                    {"reason": "source-input-changed",
                     "files": changed[:8]})
        self._assert_generated_current()

    def _source_arguments(self):
        inputs = self._inputs
        return (inputs.base_dir, inputs.compose_path, inputs.capability_paths,
                inputs.supplement_path, None)

    def _assert_generated_current(self) -> None:
        pins = dict(self._generated_pins)
        try:
            for path in self.generated_dir.rglob("*"):
                if path.is_symlink():
                    _refuse("generic-binding-drift", "/generated",
                            {"reason": "generated-symlink"})
                if not path.is_file():
                    continue
                current = _digest(path.read_bytes())
                expected = pins.pop(str(path), None)
                if expected is None or current != expected:
                    _refuse("generic-binding-drift", "/generated",
                            {"reason": "generated-file-changed",
                             "file": str(path)})
        except OSError as error:
            _refuse("generic-binding-drift", "/generated",
                    {"reason": "generated-file-unreadable"})
        if pins:
            _refuse("generic-binding-drift", "/generated",
                    {"reason": "generated-file-missing",
                     "file": sorted(pins)[0]})

    # -- snapshot/close ----------------------------------------------------
    def snapshot(self) -> dict:
        """Documentary snapshot: no live handle, no execution authority."""
        self.require_open()
        if self._documentary is not None:
            return json.loads(json.dumps(self._documentary))
        document = {
            "schema_version": "preparation_snapshot.v1",
            "preparation_id": self._stamp,
            "scope": "process_local_documentary_no_runtime_authority",
            "test_fixture": self._test_only,
            "flows": list(self.flow_ids) if self._inputs else [],
            "input_digests": dict(self._input_digests),
            "artifacts": [
                {"instance_id": instance_id,
                 "kind": artifact.runtime_document.get("kind"),
                 "artifact_digest": artifact.runtime_document.get(
                     "artifact_digest"),
                 "profile_sha256": artifact.plan.profile_sha256}
                for instance_id, artifact in sorted(self._artifacts.items())
            ],
            "input_files": [
                {"path": path, "sha256": digest}
                for path, digest in sorted(self._source_pins.items())
            ],
            "components": [row.document() for row in self.components()],
            "selections": [row.document() for row in self.selections()],
            "plans": [{"schema_version": plan.schema_version,
                       "identity_sha256": plan.identity_sha256}
                      for plan in self.plans()],
        }
        self._documentary = json.loads(json.dumps(document))
        return document

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._components.close()
        self._selections.close()
        self._plans.close()
        if self._f6_provider_artifacts is not None:
            from myfuzz.local_harness.generated_artifact_admission import release_f6_provider_credentials
            release_f6_provider_credentials(self._f6_provider_artifacts)
            self._f6_provider_artifacts = None
        self._artifacts.clear()
        self._compiled_inputs = {}
        self._prepared_paths = None
        self._runtime_objects = None
        self._source_pins = {}
        self._generated_pins = {}
        self._documentary = None

    # -- software-test fixture --------------------------------------------
    def _issue_test_fixture(self, component: VerifiedComponent) -> VerifiedComponent:
        """Issue a synthetic component for negative software tests only."""
        if not self._test_only:
            _refuse("generic-binding-drift", "/component",
                    {"reason": "test-fixture-issuance-refused"})
        return self.issue_component(component)


def _generated_pins(generated: Path,
                    artifacts: dict[str, LocalRuntimeArtifact]) -> dict[str, str]:
    pins: dict[str, str] = {}
    for path in generated.rglob("*"):
        if path.is_symlink():
            _refuse("generic-source-unverified", "/generated",
                    {"reason": "generated-symlink"})
        if path.is_file():
            pins[str(path)] = _digest(path.read_bytes())
    for instance_id, artifact in artifacts.items():
        for filename, payload in _artifact_files(artifact).items():
            expected = _digest(payload)
            if pins.get(str(generated / instance_id / filename)) != expected:
                _refuse("generic-source-unverified", "/generated",
                        {"reason": "artifact-file-mismatch",
                         "instance_id": instance_id, "file": filename})
    return pins


def _d2_document(generated: Path, artifacts: dict[str, LocalRuntimeArtifact]) -> dict:
    return {
        "schema_version": "generic_preparation_d2.v1",
        "components": [
            {"instance_id": instance_id,
             "kind": artifact.runtime_document.get("kind"),
             "artifact_digest": artifact.runtime_document.get("artifact_digest"),
             "profile_sha256": artifact.plan.profile_sha256}
            for instance_id, artifact in sorted(artifacts.items())
        ],
        "wiring_sha256": _digest((generated / "wiring_contract.json").read_bytes()),
        "harness_set_sha256": _digest((generated / "harness_set.json").read_bytes()),
    }


def create_preparation(*, base_dir: Path, compose_path: Path,
                       capability_paths: tuple[Path, ...],
                       supplement_path: Path, generated_dir: Path,
                       flow_ids: tuple[str, ...]) -> PreparationContext:
    """One D2 generation and one D3 build; owns every produced live object."""
    base = Path(_no_symlinks(base_dir)).resolve()
    compose = Path(_no_symlinks(compose_path)).resolve()
    capabilities = tuple(Path(_no_symlinks(path)).resolve()
                         for path in capability_paths)
    supplement = Path(_no_symlinks(supplement_path)).resolve()
    generated = Path(generated_dir)
    flow_ids = tuple(flow_ids)
    if not flow_ids or len(set(flow_ids)) != len(flow_ids):
        _refuse("generic-flow-unsupported", "/flow_ids",
                {"reason": "nonempty-unique-required"})
    unsupported = [flow for flow in flow_ids if flow not in _GENERIC_FLOWS]
    if unsupported:
        _refuse("generic-flow-unsupported", "/flow_ids",
                {"unsupported": unsupported, "supported": list(_GENERIC_FLOWS)})
    for path in (compose, supplement, *capabilities):
        if not path.is_relative_to(base):
            _refuse("generic-source-unverified", "/inputs",
                    {"reason": "outside-base-dir", "path": str(path)})
    for path in (*capabilities, compose, supplement):
        _input_file(path)
    if not capabilities:
        _refuse("generic-source-unverified", "/capabilities",
                {"reason": "explicit-capability-required"})
    try:
        prepared = prepare_compiled_execution_inputs(
            base_dir=base, compose_path=compose,
            capability_paths=capabilities, supplement_path=supplement,
            generated_dir=generated, flow_ids=flow_ids)
    except GeneratedArtifactRefused as error:
        _refuse("generic-source-unverified", "/generated", error.document()
                if hasattr(error, "document") else
                {"code": getattr(error, "code", "generated-artifact"),
                 "pointer": getattr(error, "pointer", "")})
    except ValueError as error:
        _refuse("generic-source-unverified", "/preparation",
                {"reason": str(error)[:200]})
    try:
        if not prepared.artifacts:
            _refuse("generic-source-unverified", "/generated",
                    {"reason": "no-artifacts"})
        source_paths = _source_paths(base, compose, capabilities, supplement, None)
        source_pins = _hashes(source_paths)
        generated_root = Path(prepared.generated_dir)
        pins = _generated_pins(generated_root, prepared.artifacts)
        d2 = _json_sha(_d2_document(generated_root, prepared.artifacts))
        d3 = compiled_document_sha256(prepared.inputs["compiled"])
        if not isinstance(d3, str):
            _refuse("generic-source-unverified", "/d3",
                    {"reason": "compiled-digest-unavailable"})
        inputs = PreparationInputs(
            base_dir=base, compose_path=compose,
            capability_paths=capabilities, supplement_path=supplement,
            generated_dir=generated_root, flow_ids=flow_ids)
        return PreparationContext._build(
            inputs=inputs, prepared=prepared, source_pins=source_pins,
            generated_pins=pins,
            input_digests={"d2": d2, "d3": require_digest(d3, "/d3")})
    except BaseException:
        if "F6" in flow_ids:
            from myfuzz.local_harness.generated_artifact_admission import release_f6_provider_credentials
            release_f6_provider_credentials(prepared.artifacts)
        raise


def load_preparation_snapshot(document) -> dict:
    """Parse a documentary snapshot; it never restores a live context."""
    if type(document) is not dict or document.get("schema_version") != "preparation_snapshot.v1":
        _refuse("generic-plan-mismatch", "/preparation",
                {"reason": "documentary-snapshot-required"})
    return json.loads(json.dumps(document))
