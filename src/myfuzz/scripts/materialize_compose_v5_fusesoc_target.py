#!/usr/bin/env python3
"""Materialize a compose-v5 manifest from an explicit FuseSoC target recipe."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Mapping

from myfuzz.builder.compose_v5 import compose_v5_manifest_from_dict
from myfuzz.builder.contracts import build_elaboration_manifest, canonical_json, content_digest
from myfuzz.builder.input_model import InputValidationError
from myfuzz.builder.rtl_analysis import analyze_elaboration
from myfuzz.scripts.edam_to_compose_v5_filelist import convert_edam
from myfuzz.scripts.write_compose_v5_fusesoc_wrapper import write_wrapper_core


RECIPE_SCHEMA = "myfuzz.compose-v5-fusesoc-recipe/v1"
_TOKEN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.+-]*$")
_ID = re.compile(r"^[a-z][a-z0-9_]*$")


class MaterializationError(ValueError):
    pass


def _objects(value: object, path: str) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
        raise MaterializationError(f"{path} must be an array of objects")
    return tuple(value)


def _strings(value: object, path: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise MaterializationError(f"{path} must be an array of non-empty strings")
    return tuple(value)


def _load_recipe(path: Path) -> Mapping[str, object]:
    try:
        value = json.loads(path.read_text(encoding="ascii"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MaterializationError(f"cannot read recipe {path}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise MaterializationError("recipe must be an object")
    expected = {"schema", "name", "mappings", "components", "digest"}
    if set(value) != expected or value.get("schema") != RECIPE_SCHEMA:
        raise MaterializationError("recipe fields or schema do not match compose-v5 FuseSoC v1")
    if not isinstance(value.get("name"), str) or not _ID.fullmatch(str(value["name"])):
        raise MaterializationError("recipe.name must be a lowercase identifier")
    mappings = _strings(value.get("mappings"), "recipe.mappings")
    if mappings != tuple(sorted(set(mappings))):
        raise MaterializationError("recipe.mappings must be unique and sorted")
    components = _objects(value.get("components"), "recipe.components")
    identifiers: list[str] = []
    roles: list[str] = []
    component_fields = {
        "id", "role", "core", "target", "tool", "top_module", "metadata_wrapper",
        "fusesoc_parameters", "module_parameters",
    }
    for index, component in enumerate(components):
        if set(component) != component_fields:
            raise MaterializationError(f"recipe.components[{index}] fields do not match v1")
        identifier = component.get("id")
        role = component.get("role")
        if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
            raise MaterializationError(f"recipe.components[{index}].id is invalid")
        if role not in {"cpu", "ram", "ip"}:
            raise MaterializationError(f"recipe.components[{index}].role is invalid")
        for field in ("core", "target", "tool", "top_module"):
            if not isinstance(component.get(field), str) or not component[field]:
                raise MaterializationError(f"recipe.components[{index}].{field} is invalid")
        if not isinstance(component.get("metadata_wrapper"), bool):
            raise MaterializationError(f"recipe.components[{index}].metadata_wrapper is invalid")
        for field in ("fusesoc_parameters", "module_parameters"):
            parameters = component.get(field)
            if not isinstance(parameters, Mapping):
                raise MaterializationError(f"recipe.components[{index}].{field} must be an object")
            for name, parameter in parameters.items():
                if not isinstance(name, str) or not _TOKEN.fullmatch(name):
                    raise MaterializationError(f"recipe.components[{index}].{field} key is invalid")
                if isinstance(parameter, (dict, list)) or parameter is None:
                    raise MaterializationError(f"recipe.components[{index}].{field}.{name} is invalid")
        identifiers.append(identifier)
        roles.append(str(role))
    if identifiers != sorted(set(identifiers)):
        raise MaterializationError("recipe components must be unique and sorted by id")
    if roles.count("cpu") != 1 or roles.count("ram") != 1 or roles.count("ip") < 2:
        raise MaterializationError("recipe requires exactly one CPU, one RAM, and at least two IPs")
    digest = value.get("digest")
    if not isinstance(digest, str) or len(digest) not in {0, 64}:
        raise MaterializationError("recipe.digest must be empty or a SHA-256 digest")
    payload = dict(value)
    payload.pop("digest")
    expected_digest = content_digest(payload)
    if digest and digest != expected_digest:
        raise MaterializationError("recipe digest mismatch")
    return dict(value, digest=digest or expected_digest)


def _parameter_text(value: object) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    return str(value)


def _run_fusesoc(
    *, source_root: Path, wrapper_root: Path | None, work_root: Path,
    component: Mapping[str, object], mappings: tuple[str, ...], timeout: int,
) -> tuple[Path, str]:
    executable = shutil.which("fusesoc")
    if not executable:
        raise MaterializationError("fusesoc executable is unavailable")
    argv = [executable, "--cores-root", str(source_root)]
    if wrapper_root is not None:
        argv.extend(("--cores-root", str(wrapper_root)))
    argv.extend((
        "run", "--setup", "--no-export", "--work-root", str(work_root),
        "--target", str(component["target"]), "--tool", str(component["tool"]),
    ))
    for mapping in mappings:
        argv.extend(("--mapping", mapping))
    argv.append(str(component["core"]))
    for name, value in sorted(component["fusesoc_parameters"].items()):
        argv.append(f"--{name}={_parameter_text(value)}")
    isolated_home = work_root.parent / ".home"
    isolated_home.mkdir(parents=True, exist_ok=True)
    environment = {
        "HOME": str(isolated_home),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONNOUSERSITE": "1",
        "XDG_CACHE_HOME": str(isolated_home / "cache"),
        "XDG_CONFIG_HOME": str(isolated_home / "config"),
    }
    try:
        result = subprocess.run(
            argv, cwd=source_root, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            encoding="utf-8", errors="replace", timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise MaterializationError(
            f"{component['id']}: FuseSoC setup exceeded {timeout} seconds"
        ) from exc
    if result.returncode:
        raise MaterializationError(
            f"{component['id']}: FuseSoC setup failed ({result.returncode}):\n{result.stdout[-4000:]}"
        )
    if "Non-deterministic selection of virtual core" in result.stdout:
        raise MaterializationError(f"{component['id']}: FuseSoC selected a virtual core nondeterministically")
    edam_files = tuple(sorted(work_root.glob("*.eda.yml")))
    if len(edam_files) != 1:
        raise MaterializationError(
            f"{component['id']}: expected one EDAM file, found {len(edam_files)}"
        )
    return edam_files[0], result.stdout


def materialize(
    recipe_path: Path, source_root: Path, output: Path, frontend_library: Path,
    *, timeout: int = 300,
) -> Mapping[str, object]:
    recipe = _load_recipe(recipe_path)
    source_root = source_root.resolve(strict=True)
    frontend_library = frontend_library.resolve(strict=True)
    output = output.resolve()
    if output.exists():
        raise MaterializationError(f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.preparing-", dir=output.parent))
    try:
        (temporary / "filelists").mkdir()
        (temporary / "logs").mkdir()
        source_sets: list[dict[str, object]] = []
        manifest_components: list[dict[str, object]] = []
        reports: list[dict[str, object]] = []
        mappings = tuple(recipe["mappings"])
        for component in recipe["components"]:
            identifier = str(component["id"])
            wrapper_root = None
            system = str(component["core"])
            if component["metadata_wrapper"]:
                wrapper_root = temporary / "wrappers" / identifier
                wrapper_name = f"myfuzz:compose_v5:{identifier}_wrapper:1"
                write_wrapper_core(
                    wrapper_root / "wrapper.core", name=wrapper_name, dependency=system,
                    top_module=str(component["top_module"]),
                )
                component = dict(component, core=wrapper_name)
            work_root = temporary / "edam" / identifier
            edam, log = _run_fusesoc(
                source_root=source_root, wrapper_root=wrapper_root, work_root=work_root,
                component=component, mappings=mappings, timeout=timeout,
            )
            (temporary / "logs" / f"{identifier}.log").write_text(log, encoding="utf-8")
            filelist = temporary / "filelists" / f"{identifier}.f"
            source_count = convert_edam(edam, source_root, filelist)
            elaboration = build_elaboration_manifest(
                top_module=str(component["top_module"]), filelists=[filelist],
                allow_roots=[source_root, temporary],
                parameters=component["module_parameters"],
                tools={"frontend": "myfuzz-verilator-ast"},
            )
            analysis = analyze_elaboration(
                elaboration, project_root=source_root, frontend_library=frontend_library,
            )
            if not any(
                module.original_name == component["top_module"] or module.name == component["top_module"]
                for module in analysis.modules
            ):
                raise MaterializationError(f"{identifier}: top module is absent from frontend output")
            source_id = f"{identifier}_src"
            source_sets.append({
                "id": source_id,
                "rtl_files": [],
                "filelists": [filelist.relative_to(temporary).as_posix()],
            })
            manifest_components.append({
                "id": identifier,
                "role": component["role"],
                "module": component["top_module"],
                "source_set": source_id,
                "parameters": dict(component["module_parameters"]),
            })
            reports.append({
                "id": identifier,
                "role": component["role"],
                "core": system,
                "top_module": component["top_module"],
                "source_count": source_count,
                "elaboration_digest": elaboration.digest,
                "frontend_schema": analysis.frontend_schema,
                "module_count": len(analysis.modules),
                "limitation_count": len(analysis.limitations),
                "log_sha256": hashlib.sha256(log.encode("utf-8")).hexdigest(),
            })
        manifest = compose_v5_manifest_from_dict({
            "schema": "myfuzz.compose-v5-manifest/v1",
            "name": str(recipe["name"]),
            "sources": source_sets,
            "components": manifest_components,
            "digest": "",
        })
        (temporary / "compose-v5-manifest.json").write_bytes(
            canonical_json(manifest.to_dict()) + b"\n"
        )
        report: dict[str, object] = {
            "schema": "myfuzz.compose-v5-fusesoc-materialization/v1",
            "recipe_digest": recipe["digest"],
            "source_root": str(source_root),
            "manifest_digest": manifest.digest,
            "mappings": list(mappings),
            "components": reports,
        }
        report["digest"] = content_digest(report)
        (temporary / "materialization.json").write_bytes(
            canonical_json(report) + b"\n"
        )
        temporary.rename(output)
        return report
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recipe", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--frontend-library", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=300)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report = materialize(
        args.recipe, args.source_root, args.output, args.frontend_library,
        timeout=args.timeout,
    )
    print(f"{report['digest']} materialized {args.output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (MaterializationError, InputValidationError) as exc:
        raise SystemExit(f"compose-v5 FuseSoC materialization: {exc}") from exc
