"""RTL and filelist discovery normalized for the protocol-driven builder."""

from __future__ import annotations

import ast
import operator
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from myfuzz.scripts.source_only_frontend import (
    DECL_KEYWORDS,
    DIRECTION_WORDS,
    IDENT_RE,
    MODULE_RE,
    RANGE_RE,
    find_matching,
    mask_comments_and_strings,
    parse_flist,
    split_top_level_commas,
)

from .input_model import InputValidationError, PortDirection, SystemSpec


@dataclass(frozen=True)
class DiscoveredPort:
    name: str
    direction: PortDirection
    width: int | None
    width_expression: str | None


@dataclass(frozen=True)
class DiscoveredInstance:
    name: str
    module_type: str


@dataclass(frozen=True)
class DiscoveredModule:
    name: str
    source_file: str
    source_set: str
    parameters: dict[str, int | str]
    ports: tuple[DiscoveredPort, ...]
    instances: tuple[DiscoveredInstance, ...]
    top_candidate: bool
    top_reason: str


@dataclass(frozen=True)
class DiscoveryResult:
    files: tuple[str, ...]
    modules: tuple[DiscoveredModule, ...]


def discover_system(spec: SystemSpec, project_root: str | Path) -> DiscoveryResult:
    root = Path(project_root).resolve()
    ownership: dict[Path, str] = {}
    for source in spec.sources:
        for raw in source.rtl_files:
            _record_file(ownership, _resolve(root, raw), source.name)
        for raw in source.filelists:
            flist = _resolve(root, raw)
            if not flist.is_file():
                raise InputValidationError(f"filelist does not exist: {flist}")
            for rtl_file in parse_flist(flist, root):
                _record_file(ownership, rtl_file.resolve(), source.name)
    if not ownership:
        raise InputValidationError("discovery found no RTL files")

    raw_modules: list[tuple[str, Path, str, dict[str, int | str], tuple[DiscoveredPort, ...], str]] = []
    for path, source_set in sorted(ownership.items(), key=lambda item: item[0].as_posix()):
        if not path.is_file():
            raise InputValidationError(f"RTL source does not exist: {path}")
        text = path.read_text(encoding="utf-8", errors="ignore")
        for name, parameters, ports, body in _parse_module_facts(text):
            raw_modules.append((name, path, source_set, parameters, ports, body))
    names = [item[0] for item in raw_modules]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise InputValidationError(f"duplicate RTL module definition(s): {', '.join(duplicates)}")

    known_names = set(names)
    instantiated: set[str] = set()
    facts: list[tuple[str, Path, str, dict[str, int | str], tuple[DiscoveredPort, ...], tuple[DiscoveredInstance, ...]]] = []
    for name, path, source_set, parameters, ports, body in raw_modules:
        instances = _parse_instances(body, known_names - {name})
        instantiated.update(instance.module_type for instance in instances)
        facts.append((name, path, source_set, parameters, ports, instances))

    declared_tops = {module.name for module in spec.modules if module.top_candidate}
    unknown_tops = declared_tops - known_names
    if unknown_tops:
        raise InputValidationError(f"declared top candidate(s) not found in RTL: {', '.join(sorted(unknown_tops))}")
    inferred_tops = known_names - instantiated
    modules = tuple(
        DiscoveredModule(
            name=name,
            source_file=path.as_posix(),
            source_set=source_set,
            parameters=parameters,
            ports=ports,
            instances=instances,
            top_candidate=name in (declared_tops or inferred_tops),
            top_reason=("user declaration" if name in declared_tops else "not instantiated by another discovered module"),
        )
        for name, path, source_set, parameters, ports, instances in sorted(facts, key=lambda item: item[0])
    )
    return DiscoveryResult(
        files=tuple(path.as_posix() for path in sorted(ownership, key=lambda item: item.as_posix())),
        modules=modules,
    )


def _parse_module_facts(text: str) -> Iterable[tuple[str, dict[str, int | str], tuple[DiscoveredPort, ...], str]]:
    masked = mask_comments_and_strings(text)
    for match in MODULE_RE.finditer(masked):
        name = match.group(1)
        semicolon = masked.find(";", match.end())
        endmodule = re.search(r"\bendmodule\b", masked[semicolon + 1:]) if semicolon >= 0 else None
        if semicolon < 0 or endmodule is None:
            raise InputValidationError(f"module {name}: incomplete module declaration")
        body_end = semicolon + 1 + endmodule.start()
        header = text[match.end():semicolon]
        parameters = _parse_parameters(header)
        open_port = _find_port_open(masked, match.end(), semicolon)
        if open_port < 0:
            ports: tuple[DiscoveredPort, ...] = ()
        else:
            close_port = find_matching(masked, open_port, "(", ")")
            if close_port < 0 or close_port > semicolon:
                raise InputValidationError(f"module {name}: unbalanced port list")
            ports = _parse_ports(text[open_port + 1:close_port], parameters)
        yield name, parameters, ports, masked[semicolon + 1:body_end]


def _find_port_open(masked: str, start: int, end: int) -> int:
    position = start
    hash_pos = masked.find("#", start, end)
    if hash_pos >= 0:
        parameter_open = masked.find("(", hash_pos, end)
        if parameter_open >= 0:
            parameter_close = find_matching(masked, parameter_open, "(", ")")
            position = parameter_close + 1
    return masked.find("(", position, end)


def _parse_parameters(header: str) -> dict[str, int | str]:
    result: dict[str, int | str] = {}
    match = re.search(r"#\s*\((.*)\)\s*\(", header, re.S)
    if not match:
        return result
    for part in split_top_level_commas(match.group(1)):
        parameter = re.search(r"\bparameter\b(?:\s+\w+)*\s+([A-Za-z_]\w*)\s*=\s*(.+)$", part.strip(), re.S)
        if not parameter:
            continue
        name, expression = parameter.group(1), parameter.group(2).strip()
        value = _evaluate(expression, result)
        result[name] = expression if value is None else value
    return result


def _parse_ports(header: str, parameters: dict[str, int | str]) -> tuple[DiscoveredPort, ...]:
    ports: list[DiscoveredPort] = []
    current_direction = PortDirection.INPUT
    current_width: int | None = 1
    current_expression: str | None = None
    for raw in split_top_level_commas(header):
        part = raw.strip()
        direction_word = next((word for word in DIRECTION_WORDS if re.search(rf"\b{word}\b", part)), None)
        if direction_word:
            if direction_word == "ref":
                raise InputValidationError("ref ports are not supported by the protocol builder")
            current_direction = PortDirection(direction_word)
            ranges = RANGE_RE.findall(part)
            if ranges:
                expression = " * ".join(f"abs(({msb}) - ({lsb})) + 1" for msb, lsb in ranges)
                current_expression = expression
                current_width = _evaluate_width(ranges, parameters)
            else:
                current_expression = None
                current_width = 1
        tokens = IDENT_RE.findall(part)
        names = [token for token in tokens if token not in DECL_KEYWORDS and token not in parameters]
        if not names:
            continue
        ports.append(DiscoveredPort(names[-1], current_direction, current_width, current_expression))
    return tuple(ports)


def _evaluate_width(ranges: list[tuple[str, str]], parameters: dict[str, int | str]) -> int | None:
    width = 1
    for msb, lsb in ranges:
        high = _evaluate(msb, parameters)
        low = _evaluate(lsb, parameters)
        if high is None or low is None:
            return None
        width *= abs(high - low) + 1
    return width


def _evaluate(expression: str, parameters: dict[str, int | str]) -> int | None:
    normalized = re.sub(r"\b(\d+)\s*'\s*[dD]\s*([0-9_]+)", lambda m: m.group(2).replace("_", ""), expression)
    normalized = re.sub(r"\b(\d+)\s*'\s*[hH]\s*([0-9a-fA-F_]+)", lambda m: "0x" + m.group(2).replace("_", ""), normalized)
    for name, value in parameters.items():
        if isinstance(value, int):
            normalized = re.sub(rf"\b{re.escape(name)}\b", str(value), normalized)
    try:
        tree = ast.parse(normalized, mode="eval")
        return _eval_node(tree.body)
    except (SyntaxError, ValueError, TypeError, ZeroDivisionError):
        return None


_BINARY = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.FloorDiv: operator.floordiv, ast.Div: operator.floordiv,
    ast.Pow: operator.pow, ast.LShift: operator.lshift, ast.RShift: operator.rshift,
}


def _eval_node(node: ast.AST) -> int:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        value = _eval_node(node.operand)
        return value if isinstance(node.op, ast.UAdd) else -value
    if isinstance(node, ast.BinOp) and type(node.op) in _BINARY:
        return int(_BINARY[type(node.op)](_eval_node(node.left), _eval_node(node.right)))
    raise ValueError("unsupported constant expression")


def _parse_instances(body: str, module_names: set[str]) -> tuple[DiscoveredInstance, ...]:
    instances: list[DiscoveredInstance] = []
    for module_type in sorted(module_names, key=len, reverse=True):
        pattern = re.compile(
            rf"\b{re.escape(module_type)}\b\s*(?:#\s*\(.*?\)\s*)?([A-Za-z_]\w*)\s*\(", re.S
        )
        instances.extend(DiscoveredInstance(match.group(1), module_type) for match in pattern.finditer(body))
    return tuple(sorted(instances, key=lambda item: (item.name, item.module_type)))


def _resolve(root: Path, raw: str) -> Path:
    path = Path(raw)
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def _record_file(ownership: dict[Path, str], path: Path, source_set: str) -> None:
    previous = ownership.get(path)
    if previous is not None and previous != source_set:
        raise InputValidationError(
            f"RTL source {path} belongs to multiple source sets: {previous!r} and {source_set!r}"
        )
    ownership[path] = source_set
