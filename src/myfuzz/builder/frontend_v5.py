"""Strict compose-v5 behavioral view of the shared Verilator frontend output."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .contracts.experiment import content_digest
from .input_model import InputValidationError


FRONTEND_BEHAVIOR_SCHEMA = "myfuzz.frontend-behavior/v1"


@dataclass(frozen=True)
class FrontendV5Expression:
    kind: str
    width: int | None
    signal: str | None
    value: str | None
    children: tuple["FrontendV5Expression", ...]


@dataclass(frozen=True)
class FrontendV5Sensitivity:
    edge: str
    expression: FrontendV5Expression | None
    signals: tuple[str, ...]


@dataclass(frozen=True)
class FrontendV5Guard:
    polarity: str
    expression: FrontendV5Expression


@dataclass(frozen=True)
class FrontendV5Transition:
    kind: str
    target_expression: FrontendV5Expression
    value_expression: FrontendV5Expression
    targets: tuple[str, ...]
    sources: tuple[str, ...]
    guards: tuple[FrontendV5Guard, ...]


@dataclass(frozen=True)
class FrontendV5Process:
    index: int
    kind: str
    sensitivities: tuple[FrontendV5Sensitivity, ...]
    transitions: tuple[FrontendV5Transition, ...]


@dataclass(frozen=True)
class FrontendV5ModuleBehavior:
    name: str
    original_name: str
    processes: tuple[FrontendV5Process, ...]


@dataclass(frozen=True)
class FrontendV5Behavior:
    top_module: str
    modules: tuple[FrontendV5ModuleBehavior, ...]
    digest: str
    schema: str = FRONTEND_BEHAVIOR_SCHEMA


def extract_frontend_v5_behavior(raw: Mapping[str, Any]) -> FrontendV5Behavior:
    if not isinstance(raw, Mapping):
        raise InputValidationError("compose-v5 frontend result must be an object")
    if raw.get("schema") != "myfuzz.frontend.v1" or raw.get("source") != "verilator-frontend-ast":
        raise InputValidationError("compose-v5 behavior requires the shared Verilator AST frontend")
    if raw.get("behaviorSchema") != FRONTEND_BEHAVIOR_SCHEMA:
        raise InputValidationError("compose-v5 frontend behavior schema is missing or unsupported")
    modules = tuple(_module(item, index) for index, item in enumerate(_objects(raw.get("modules"), "modules")))
    names = [item.name for item in modules]
    if len(names) != len(set(names)):
        raise InputValidationError("compose-v5 frontend behavior contains duplicate modules")
    top = _text(raw.get("topModule"), "topModule")
    if not any(item.name == top or item.original_name == top for item in modules):
        raise InputValidationError("compose-v5 frontend behavior is missing the elaborated top")
    payload = {
        "schema": FRONTEND_BEHAVIOR_SCHEMA,
        "top_module": top,
        "modules": [_module_payload(item) for item in modules],
    }
    return FrontendV5Behavior(top, modules, content_digest(payload))


def _module(value: Mapping[str, Any], index: int) -> FrontendV5ModuleBehavior:
    name = _text(value.get("name"), f"modules[{index}].name")
    original = _text(value.get("origName") or name, f"modules[{index}].origName")
    processes = tuple(
        _process(item, f"modules[{index}].behaviorProcesses[{process_index}]")
        for process_index, item in enumerate(
            _objects(value.get("behaviorProcesses", []), f"modules[{index}].behaviorProcesses")
        )
    )
    indices = [item.index for item in processes]
    if indices != list(range(len(indices))):
        raise InputValidationError(f"modules[{index}] behavior process indices must be dense")
    return FrontendV5ModuleBehavior(name, original, processes)


def _process(value: Mapping[str, Any], path: str) -> FrontendV5Process:
    return FrontendV5Process(
        _nonnegative(value.get("index"), f"{path}.index"),
        _text(value.get("kind"), f"{path}.kind"),
        tuple(_sensitivity(item, f"{path}.sensitivities")
              for item in _objects(value.get("sensitivities"), f"{path}.sensitivities")),
        tuple(_transition(item, f"{path}.transitions")
              for item in _objects(value.get("transitions"), f"{path}.transitions")),
    )


def _sensitivity(value: Mapping[str, Any], path: str) -> FrontendV5Sensitivity:
    raw_expression = value.get("expression")
    return FrontendV5Sensitivity(
        _text(value.get("edge"), f"{path}.edge"),
        None if raw_expression is None else _expression(raw_expression, f"{path}.expression", 0),
        tuple(_text(item, f"{path}.signals") for item in _array(value.get("signals"), f"{path}.signals")),
    )


def _transition(value: Mapping[str, Any], path: str) -> FrontendV5Transition:
    return FrontendV5Transition(
        _text(value.get("kind"), f"{path}.kind"),
        _expression(value.get("targetExpression"), f"{path}.targetExpression", 0),
        _expression(value.get("valueExpression"), f"{path}.valueExpression", 0),
        tuple(_text(item, f"{path}.targets") for item in _array(value.get("targets"), f"{path}.targets")),
        tuple(_text(item, f"{path}.sources") for item in _array(value.get("sources"), f"{path}.sources")),
        tuple(
            FrontendV5Guard(
                _text(item.get("polarity"), f"{path}.guards.polarity"),
                _expression(item.get("expression"), f"{path}.guards.expression", 0),
            )
            for item in _objects(value.get("guards"), f"{path}.guards")
        ),
    )


def _expression(value: object, path: str, depth: int) -> FrontendV5Expression:
    if depth > 64 or not isinstance(value, Mapping):
        raise InputValidationError(f"{path}: invalid or over-deep expression tree")
    kind = _text(value.get("kind"), f"{path}.kind")
    width = value.get("width")
    if width is not None:
        width = _positive(width, f"{path}.width")
    signal = value.get("signal")
    if signal is not None:
        signal = _text(signal, f"{path}.signal")
    literal = value.get("value")
    if literal is not None:
        literal = _text(literal, f"{path}.value")
    children = tuple(
        _expression(item, f"{path}.children[{index}]", depth + 1)
        for index, item in enumerate(_array(value.get("children"), f"{path}.children"))
    )
    return FrontendV5Expression(kind, width, signal, literal, children)


def _module_payload(module: FrontendV5ModuleBehavior) -> dict[str, object]:
    def expression(value: FrontendV5Expression | None) -> object:
        if value is None:
            return None
        return {"kind": value.kind, "width": value.width, "signal": value.signal,
                "value": value.value, "children": [expression(item) for item in value.children]}
    return {
        "name": module.name, "original_name": module.original_name,
        "processes": [{
            "index": process.index, "kind": process.kind,
            "sensitivities": [{"edge": item.edge, "expression": expression(item.expression),
                               "signals": list(item.signals)} for item in process.sensitivities],
            "transitions": [{
                "kind": item.kind, "target_expression": expression(item.target_expression),
                "value_expression": expression(item.value_expression), "targets": list(item.targets),
                "sources": list(item.sources),
                "guards": [{"polarity": guard.polarity, "expression": expression(guard.expression)}
                           for guard in item.guards],
            } for item in process.transitions],
        } for process in module.processes],
    }


def _objects(value: object, path: str) -> tuple[Mapping[str, Any], ...]:
    result = _array(value, path)
    if any(not isinstance(item, Mapping) for item in result):
        raise InputValidationError(f"{path}: expected an array of objects")
    return tuple(result)


def _array(value: object, path: str) -> tuple[object, ...]:
    if not isinstance(value, list):
        raise InputValidationError(f"{path}: expected an array")
    return tuple(value)


def _text(value: object, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise InputValidationError(f"{path}: expected a non-empty string")
    return value


def _nonnegative(value: object, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InputValidationError(f"{path}: expected a non-negative integer")
    return value


def _positive(value: object, path: str) -> int:
    result = _nonnegative(value, path)
    if result == 0:
        raise InputValidationError(f"{path}: expected a positive integer")
    return result
