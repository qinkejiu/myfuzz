#!/usr/bin/env python3
"""Explicit generic-runtime preparation entry point (G4: ``--mode prepare``).

This is the only supported top-level invocation of the generic runtime.  It is
deliberately *not* a factory/loader: the composition, the ip-capability sidecars
and the execution supplement are explicit file arguments, the flows are explicit
and the output directory must be new.

One invocation performs exactly one preparation:

``create_preparation`` -> one D2 generation, one request/ownership build and one
``compile_paths`` call for *all* requested flows -> ``verify_component`` for
every generated artifact -> ``select_adapter`` for every derived endpoint
binding -> one ``compile_execution_plan``.

Writing this command's outputs is static documentation only.  It starts no RTL,
no native child process and no runner; ``--mode run`` is refused here and is
owned by G5.

Exit codes: 0 prepared, 2 refused (a structured ``refusals.json`` is written
with the code/pointer/detail, and no process was started), 1 unexpected error.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from myfuzz.runtime.admission import verify_component
from myfuzz.runtime.compiler import (
    compile_execution_plan,
    plan_bindings,
    requirement_for_binding,
)
from myfuzz.runtime.contracts import GenericRuntimeRefused
from myfuzz.runtime.preparation import create_preparation
from myfuzz.runtime.registry import select_adapter

SUPPORTED_FLOWS = ("F2", "F4")
TASK_ID = "G4-partial"
REFUSAL_SCHEMA = "generic_runtime_refusal.v1"
INPUTS_SCHEMA = "generic_runtime_inputs.v1"
CAPABILITIES_SCHEMA = "generic_runtime_capabilities.v1"
DIGESTS_SCHEMA = "generic_runtime_digests.v1"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--compose", type=Path, required=True,
        help="composition file (harness_compose.v1); relative to the repo root")
    parser.add_argument(
        "--ip-capability", type=Path, action="append", required=True,
        help="explicit ip_test_capability sidecar; repeatable, relative to the "
             "repo root")
    parser.add_argument(
        "--supplement", type=Path, required=True,
        help="compiled_execution_file_supplement.v1 file; relative to the "
             "repo root")
    parser.add_argument(
        "--flow", action="append", required=True,
        help="requested flow (F2 or F4); repeatable and combined into ONE "
             "preparation")
    parser.add_argument(
        "--mode", required=True,
        help="prepare (implemented) or run (refused; owned by G5)")
    parser.add_argument(
        "--output", type=Path, required=True,
        help="new output directory; relative to the repo root")
    return parser


def _refuse(code: str, pointer: str = "", detail=None) -> None:
    raise GenericRuntimeRefused(code, pointer, detail)


def _resolve(path: Path, base: Path) -> Path:
    path = Path(path)
    return path if path.is_absolute() else base / path


def _relative(path: Path, base: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(Path(base).resolve()))
    except ValueError:
        return str(Path(path).resolve())


def _validate_request(args) -> tuple[str, ...]:
    if args.mode not in ("prepare", "run"):
        _refuse("generic-mode-unsupported", "/mode",
                {"requested": args.mode, "supported": ["prepare", "run"]})
    if args.mode == "run":
        _refuse("generic-run-unsupported", "/mode",
                {"reason": "G4 implements prepare only; --mode run is owned by G5",
                 "supported": ["prepare"]})
    flows = tuple(args.flow)
    if not flows or any(type(flow) is not str or not flow for flow in flows):
        _refuse("generic-flow-unsupported", "/flow",
                {"reason": "nonempty-flow-required",
                 "supported": list(SUPPORTED_FLOWS)})
    if len(set(flows)) != len(flows):
        _refuse("generic-flow-unsupported", "/flow",
                {"reason": "duplicate-flow",
                 "flows": [flow for flow in flows
                           if flows.count(flow) > 1]})
    unsupported = sorted(set(flows) - set(SUPPORTED_FLOWS))
    if unsupported:
        _refuse("generic-flow-unsupported", "/flow",
                {"unsupported": unsupported,
                 "supported": list(SUPPORTED_FLOWS)})
    return tuple(sorted(flows))


def _assert_output_new(output: Path) -> None:
    if output.exists() or output.is_symlink():
        _refuse("generic-output-exists", "/output",
                {"path": str(output),
                 "reason": "output-directory-must-be-new"})


def _write_json(path: Path, document) -> str:
    payload = (json.dumps(document, sort_keys=True, indent=2,
                         ensure_ascii=False, allow_nan=False) + "\n").encode()
    path.write_bytes(payload)
    return sha256(payload).hexdigest()


def _write_refusal(output: Path, error: GenericRuntimeRefused, *, mode: str,
                   flows) -> None:
    """Write the structured refusal before anything could have started."""
    try:
        if not output.exists() and not output.is_symlink():
            output.mkdir(parents=True, exist_ok=False)
    except OSError:
        pass
    if not output.is_dir() or output.is_symlink():
        return
    document = {
        "schema_version": REFUSAL_SCHEMA,
        "task": TASK_ID,
        "mode": mode,
        "status": "refused",
        "process_started": False,
        "native_claimed": False,
        "flows": list(flows) if flows else None,
        "refusals": [error.document()],
    }
    try:
        _write_json(output / "refusals.json", document)
    except OSError:
        pass


def _input_document(path: Path, base: Path) -> dict:
    return {
        "path": _relative(path, base),
        "absolute_path": str(Path(path).resolve()),
        "sha256": sha256(Path(path).read_bytes()).hexdigest(),
    }


def _matching_table(bindings, requirements, selections, components) -> list[dict]:
    component_by_instance = {component.instance_id: component
                             for component in components}
    selection_by_artifact = {
        (selection.component_artifact_sha256,
         selection.semantic_contract_sha256): selection
        for selection in selections}
    rows = []
    for binding, requirement in zip(bindings, requirements):
        component = component_by_instance[binding.instance_id]
        selection = selection_by_artifact[
            (component.artifact_sha256, component.semantic_contract_sha256)]
        endpoint = next(row for row in component.endpoints()
                        if row["endpoint_id"] == binding.endpoint_id)
        rows.append({
            "instance_id": binding.instance_id,
            "endpoint_id": binding.endpoint_id,
            "role": binding.role,
            "protocol": list(binding.protocol),
            "template": list(binding.template),
            "semantic_kind": binding.semantic_kind,
            "required_operations": list(binding.required_operations),
            "required_evidence": list(binding.evidence_obligations),
            "supported_operations": endpoint["operations"],
            "supported_evidence": endpoint["evidence_capabilities"],
            "adapter_id": selection.adapter_id,
            "adapter_version": selection.adapter_version,
            "implementation_sha256": selection.implementation_sha256,
            "component_artifact_sha256": selection.component_artifact_sha256,
            "semantic_contract_sha256": selection.semantic_contract_sha256,
            "matched": True,
        })
    return rows


def _prepare(*, args, flows: tuple[str, ...], base: Path,
             output: Path) -> dict:
    compose = _resolve(args.compose, base)
    capabilities = tuple(sorted({_resolve(path, base)
                                 for path in args.ip_capability},
                                key=lambda path: str(path)))
    supplement = _resolve(args.supplement, base)
    context = create_preparation(
        base_dir=base, compose_path=compose, capability_paths=capabilities,
        supplement_path=supplement, generated_dir=output / "generated",
        flow_ids=flows)
    try:
        components = tuple(
            verify_component(context.artifact(instance_id),
                             preparation=context, base_dir=base)
            for instance_id in sorted(context.artifacts))
        bindings = plan_bindings(context)
        component_by_instance = {component.instance_id: component
                                 for component in components}
        requirements = []
        selections = []
        for binding in bindings:
            component = component_by_instance.get(binding.instance_id)
            if component is None:
                _refuse("generic-plan-mismatch", "/components",
                        {"reason": "binding-component-missing",
                         "instance_id": binding.instance_id})
            requirement = requirement_for_binding(component, binding)
            requirements.append(requirement)
            selections.append(select_adapter(component, requirement,
                                             preparation=context))
        plan = compile_execution_plan(
            context, components=components, selections=tuple(selections),
            requirements=tuple(requirements))
        # Static boundary recheck: the source pins and generated files this plan
        # was compiled from must still be the files on disk.
        context.assert_current()
        snapshot = context.snapshot()
        input_digests = context.input_digests
    finally:
        context.close()

    plan_path = output / "execution_plan.json"
    plan_path.write_bytes(plan.document_bytes)
    inputs_document = {
        "schema_version": INPUTS_SCHEMA,
        "task": TASK_ID,
        "mode": "prepare",
        "status": "prepared",
        "process_started": False,
        "native_claimed": False,
        "base_dir": str(base),
        "compose": _input_document(compose, base),
        "capability_paths": [_input_document(path, base)
                             for path in capabilities],
        "supplement": _input_document(supplement, base),
        "generated_dir": {
            "path": _relative(output / "generated", base),
            "absolute_path": str((output / "generated").resolve()),
        },
        "flows": list(flows),
        "input_digests": dict(input_digests),
        "preparation": snapshot,
    }
    capabilities_document = {
        "schema_version": CAPABILITIES_SCHEMA,
        "task": TASK_ID,
        "mode": "prepare",
        "status": "selected",
        "scope": "static_capability_selection_no_runtime_authority",
        "process_started": False,
        "native_claimed": False,
        "plan_identity_sha256": plan.identity_sha256,
        "input_digests": dict(input_digests),
        "components": [component.document() for component in components],
        "selections": [
            dict(selection.document(),
                 instance_id=binding.instance_id,
                 endpoint_id=binding.endpoint_id,
                 role=binding.role,
                 selection_sha256=selection.sha256())
            for binding, selection in zip(bindings, selections)],
        "requirements": [requirement.document()
                         for requirement in requirements],
        "matching_table": _matching_table(bindings, requirements, selections,
                                          components),
    }
    inputs_digest = _write_json(output / "inputs.json", inputs_document)
    capabilities_digest = _write_json(output / "capabilities.json",
                                      capabilities_document)
    refusals_digest = _write_json(output / "refusals.json", [])
    plan_digest = sha256(plan_path.read_bytes()).hexdigest()
    files = {
        "execution_plan.json": plan_digest,
        "inputs.json": inputs_digest,
        "capabilities.json": capabilities_digest,
        "refusals.json": refusals_digest,
    }
    _write_json(output / "digests.json", {
        "schema_version": DIGESTS_SCHEMA,
        "task": TASK_ID,
        "status": "prepared",
        "native_claimed": False,
        "d2": input_digests["d2"],
        "d3": input_digests["d3"],
        "plan_identity_sha256": plan.identity_sha256,
        "files": files,
    })
    document = plan.document()
    return {
        "task": TASK_ID,
        "status": "prepared",
        "mode": "prepare",
        "process_started": False,
        "native_claimed": False,
        "output": _relative(output, base),
        "plan_schema": plan.schema_version,
        "plan_identity_sha256": plan.identity_sha256,
        "input_digests": dict(input_digests),
        "flows": list(flows),
        "paths": [path["path_id"] for path in document["paths"]],
        "components": [component["instance_id"]
                       for component in document["components"]],
        "selections": [f"{row['instance_id']}:{row['endpoint_id']}="
                       f"{row['adapter_id']}@{row['adapter_version']}"
                       for row in document["selections"]],
        "evidence_obligations": document["evidence_obligations"],
        "outputs": sorted(files) + ["digests.json"],
    }


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    base = ROOT
    output = _resolve(args.output, base)
    flows = None
    try:
        flows = _validate_request(args)
        _assert_output_new(output)
    except GenericRuntimeRefused as error:
        _write_refusal(output, error, mode=args.mode, flows=flows)
        print(f"generic-runtime-refused: {error.code} at {error.pointer}",
              file=sys.stderr)
        return 2
    try:
        output.mkdir(parents=True, exist_ok=False)
    except OSError as error:
        refusal = GenericRuntimeRefused(
            "generic-output-exists", "/output",
            {"reason": "output-directory-must-be-new",
             "error_type": type(error).__name__})
        print(f"generic-runtime-refused: {refusal.code} at {refusal.pointer}",
              file=sys.stderr)
        return 2
    try:
        result = _prepare(args=args, flows=flows, base=base, output=output)
    except GenericRuntimeRefused as error:
        _write_refusal(output, error, mode=args.mode, flows=flows)
        print(f"generic-runtime-refused: {error.code} at {error.pointer}",
              file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError, TypeError) as error:
        # A preparation-surface error is still a refusal: it is recorded before
        # any process could start, and no success field is written.
        refusal = GenericRuntimeRefused(
            "generic-preparation-refused", "/preparation",
            {"error_type": type(error).__name__,
             "message": str(error)[:200]})
        _write_refusal(output, refusal, mode=args.mode, flows=flows)
        print(f"generic-runtime-refused: {refusal.code} at {refusal.pointer}",
              file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
