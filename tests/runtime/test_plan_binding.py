"""G4: process-local binding of an issued plan to attached live objects.

Software only.  The positive native binding is exercised by the G5/G6
integration, because the trusted adapters refuse a software session double by
design; here every refusal path is checked against a real same-pass preparation.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from myfuzz.runtime.admission import verify_component
from myfuzz.runtime.binding import (
    BoundExecutionPlan,
    bind_execution_plan,
    require_bound_plan,
)
from myfuzz.runtime.compiler import (
    compile_execution_plan,
    load_execution_plan_document,
    plan_bindings,
)
from myfuzz.runtime.contracts import (
    CapabilityRequirement,
    GenericExecutionPlan,
    GenericRuntimeRefused,
)
from myfuzz.runtime.preparation import PreparationContext, create_preparation
from myfuzz.runtime.registry import select_adapter
from myfuzz.scenario.runner import ScenarioRunner

ROOT = Path(__file__).resolve().parents[2]
TIMER = ROOT / "configs/scenarios/compiled-f4-obi-apb-timer"


@pytest.fixture(scope="module")
def prepared(tmp_path_factory):
    output = tmp_path_factory.mktemp("binding-preparation")
    context = create_preparation(
        base_dir=ROOT,
        compose_path=TIMER / "compose.json",
        capability_paths=(TIMER / "test_capability.json",),
        supplement_path=TIMER / "execution_supplement.json",
        generated_dir=output / "generated",
        flow_ids=("F2", "F4"),
    )
    bindings = plan_bindings(context)
    components = []
    selections = []
    requirements = []
    for binding in bindings:
        component = verify_component(context.artifact(binding.instance_id),
                                     preparation=context, base_dir=ROOT)
        endpoint = next(row for row in component.endpoints()
                        if row["endpoint_id"] == binding.endpoint_id)
        requirement = CapabilityRequirement(
            role=binding.role,
            endpoint_id=binding.endpoint_id,
            protocol=tuple(binding.protocol),
            template=tuple(binding.template),
            semantic_kind=binding.semantic_kind,
            operations=tuple(sorted(set(binding.required_operations))),
            data_width=endpoint["data_width"],
            address_width=endpoint["address_width"],
            max_outstanding=endpoint["max_outstanding"],
            completion_kind=endpoint["completion_kind"],
            byte_enable_required=endpoint["byte_enable"],
            address_units=endpoint["address_units"],
            evidence_obligations=tuple(binding.evidence_obligations),
        )
        selection = select_adapter(component, requirement, preparation=context)
        components.append(component)
        selections.append(selection)
        requirements.append(requirement)
    plan = compile_execution_plan(context, components=tuple(components),
                                  selections=tuple(selections),
                                  requirements=tuple(requirements))
    sessions = {row.instance_id: object() for row in components}
    runner = ScenarioRunner(sessions=sessions,
                            ownership=context.compiled_inputs()["ownership"],
                            bindings=())
    context.attach_runtime(runner=runner, sessions=sessions)
    marker = object()
    context.register_prepared_paths(prepared=marker, runtime_paths=object(),
                                    graph=object())
    yield dict(context=context, plan=plan, bindings=bindings,
               components=tuple(components), selections=tuple(selections),
               requirements=tuple(requirements),
               attached=dict(sessions=sessions, runner=runner,
                             prepared_paths=marker))
    context.close()


def _attached(prepared):
    return prepared["attached"]


def test_plan_is_bound_only_to_this_preparation(prepared):
    context = prepared["context"]
    plan = prepared["plan"]
    equal_value = GenericExecutionPlan(plan.schema_version, plan.document_bytes,
                                       plan.identity_sha256)
    with pytest.raises(GenericRuntimeRefused) as caught:
        bind_execution_plan(equal_value, preparation=context,
                            sessions={}, prepared_paths=object(), runner=None)
    assert caught.value.code == "generic-binding-drift"
    assert caught.value.detail["issuance"] == "execution-plans"


def test_binding_constructor_is_private_and_unissued_handle_refused():
    with pytest.raises(GenericRuntimeRefused) as caught:
        BoundExecutionPlan(_token=object())
    assert caught.value.code == "generic-binding-drift"
    with pytest.raises(GenericRuntimeRefused):
        require_bound_plan(object())
    # An equal-looking object cannot become a live handle either.
    with pytest.raises(GenericRuntimeRefused):
        require_bound_plan(BoundExecutionPlan.__new__(BoundExecutionPlan))


def test_binding_refuses_detached_or_tampered_plan(prepared):
    context = prepared["context"]
    plan = prepared["plan"]
    pretty = json.dumps(plan.document(), sort_keys=True, indent=2).encode()
    with pytest.raises(GenericRuntimeRefused) as caught:
        load_execution_plan_document(pretty)
    assert caught.value.code == "generic-plan-mismatch"
    assert caught.value.pointer == "/plan"
    tampered = json.loads(plan.document_bytes)
    tampered["memory"]["resources"] = []
    forged = GenericExecutionPlan.freeze(tampered)
    with pytest.raises(GenericRuntimeRefused) as caught:
        bind_execution_plan(forged, preparation=context, sessions={},
                            prepared_paths=object(), runner=None)
    assert caught.value.code == "generic-binding-drift"


def test_binding_refuses_unattached_runner_and_sessions(prepared):
    context = prepared["context"]
    attached = _attached(prepared)
    other_runner = ScenarioRunner(
        sessions=attached["sessions"],
        ownership=context.compiled_inputs()["ownership"], bindings=())
    with pytest.raises(GenericRuntimeRefused) as caught:
        bind_execution_plan(prepared["plan"], preparation=context,
                            sessions=attached["sessions"],
                            prepared_paths=attached["prepared_paths"],
                            runner=other_runner)
    assert caught.value.code == "generic-binding-drift"
    assert caught.value.detail["reason"] == "runner-not-attached-by-this-preparation"


def test_binding_refuses_missing_extra_and_swapped_sessions(prepared):
    context = prepared["context"]
    attached = _attached(prepared)
    missing = dict(attached["sessions"])
    missing.pop(sorted(missing)[0])
    with pytest.raises(GenericRuntimeRefused) as caught:
        bind_execution_plan(prepared["plan"], preparation=context, sessions=missing,
                            prepared_paths=attached["prepared_paths"],
                            runner=attached["runner"])
    assert caught.value.detail["reason"] == "session-set-mismatch"
    swapped = dict(attached["sessions"])
    name = sorted(swapped)[0]
    swapped[name] = object()
    with pytest.raises(GenericRuntimeRefused) as caught:
        bind_execution_plan(prepared["plan"], preparation=context, sessions=swapped,
                            prepared_paths=attached["prepared_paths"],
                            runner=attached["runner"])
    assert caught.value.detail["reason"] == "runner-session-identity-mismatch"


def test_binding_refuses_foreign_prepared_graph(prepared):
    context = prepared["context"]
    attached = _attached(prepared)
    foreign = PreparationContext._for_tests()
    marker = object()
    foreign.register_prepared_paths(prepared=marker, runtime_paths=object(),
                                    graph=object())
    with pytest.raises(GenericRuntimeRefused) as caught:
        bind_execution_plan(prepared["plan"], preparation=context,
                            sessions=attached["sessions"],
                            prepared_paths=marker, runner=attached["runner"])
    assert caught.value.code == "generic-plan-mismatch"
    assert caught.value.detail["reason"] == \
        "prepared-graph-not-issued-by-this-preparation"
    foreign.close()


def test_binding_refuses_untrusted_adapter_factory(prepared, monkeypatch):
    import myfuzz.runtime.binding as binding_module
    context = prepared["context"]
    attached = _attached(prepared)

    class CallerProvided:
        component_instance_id = "peripheral"
        adapter_id = "apb3.storage.v1"
        adapter_version = "1"

        def assert_current(self):
            return None

        def close(self):
            return None

    monkeypatch.setattr(binding_module, "_FACTORIES",
                        {"apb3.storage.v1": lambda **kwargs: CallerProvided(),
                         "obi.cpu.v1": lambda **kwargs: CallerProvided()})
    with pytest.raises(GenericRuntimeRefused) as caught:
        bind_execution_plan(prepared["plan"], preparation=context,
                            sessions=attached["sessions"],
                            prepared_paths=attached["prepared_paths"],
                            runner=attached["runner"])
    # A factory that ignores the real session produces a surface mismatch, a
    # refusal -- never an accepted live binding.
    assert caught.value.code in ("generic-binding-drift", "generic-adapter-missing")


def test_binding_refuses_caller_factory_argument(prepared):
    context = prepared["context"]
    with pytest.raises(TypeError):
        bind_execution_plan(prepared["plan"], preparation=context, sessions={},
                            prepared_paths=object(), runner=None,
                            factory=lambda **kwargs: object())


def test_missing_adapter_module_is_a_dependency_not_a_skip(prepared):
    """Until the G3 adapters exist the bind path must refuse, not fabricate."""
    context = prepared["context"]
    attached = _attached(prepared)
    try:
        bind_execution_plan(prepared["plan"], preparation=context,
                            sessions=attached["sessions"],
                            prepared_paths=attached["prepared_paths"],
                            runner=attached["runner"])
    except GenericRuntimeRefused as error:
        assert error.code in ("generic-adapter-missing", "generic-binding-drift")
    except ImportError as error:
        pytest.fail("trusted adapter module missing; G4 binding cannot be "
                    f"evaluated: {error}")
    else:  # pragma: no cover - only after real adapters accept real sessions
        raise AssertionError("software session doubles must never bind")
