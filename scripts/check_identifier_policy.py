#!/usr/bin/env python3
"""Reject identifier-text heuristics outside syntax and emission boundaries."""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat
import sys
from collections.abc import Iterable, Sequence


_SOURCE_SUFFIXES = frozenset({".py", ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp"})
_RAW_MAPPING_KEYS = frozenset(
    {
        "module_name",
        "instance_name",
        "port_name",
        "net_name",
        "file_name",
        "directory_name",
        "target_name",
        "design_name",
    }
)
_RAW_ATTRIBUTES = _RAW_MAPPING_KEYS - {"name", "original_name"}
_IDENTIFIER_VARIABLES = frozenset(
    {
        "name",
        "symbol",
        "identifier",
        "module_name",
        "instance_name",
        "port_name",
        "net_name",
        "file_name",
        "directory_name",
        "target_name",
        "design_name",
        "component_id",
        "candidate_id",
        "job_id",
        "target_id",
    }
)
_IDENTIFIER_SUFFIXES = (
    "_name",
    "_symbol",
    "_identifier",
)
_TARGET_KEYWORDS = frozenset({"rvx", "ibex", "opentitan", "uart", "gpio", "rv_timer"})
_AFFIX_METHODS = frozenset({"startswith", "endswith", "removeprefix", "removesuffix"})
_REGEX_FUNCTIONS = frozenset({"match", "search", "fullmatch", "findall", "finditer", "split", "sub", "subn"})
_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_SOURCE_FILES = 10_000
_DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[1]
_BOUNDARY_FILES = frozenset(
    {
        "src/myfuzz/harness/sv_emit.py",
        "src/myfuzz/scripts/frontend_api.py",
        "src/myfuzz/scripts/composition_api.py",
        "src/myfuzz/frontend/src/MyFuzzFrontend.cpp",
        "src/myfuzz/frontend/src/MyFuzzFrontendApi.cpp",
        "src/myfuzz/frontend/src/MyFuzzCompositionApi.cpp",
        "src/myfuzz/frontend/src/MyFuzzCompositionAstBuilder.cpp",
        "src/myfuzz/frontend/src/MyFuzzCompositionAstBuilder.h",
        "src/myfuzz/frontend/vendor/verilator/src/V3VIFrontend.cpp",
        "src/myfuzz/frontend/vendor/verilator/src/V3VIFrontend.h",
        "src/myfuzz/frontend/vendor/verilator/src/V3EmitV.cpp",
        "src/myfuzz/frontend/vendor/verilator/src/V3EmitV.h",
        "src/myfuzz/frontend/src/binding.py",
        "src/myfuzz/frontend/src/diagnostics.py",
        "src/myfuzz/frontend/src/emitter.py",
        "src/myfuzz/frontend/src/source_map.py",
    }
)


@dataclass(frozen=True, order=True)
class Violation:
    path: str
    line: int
    column: int
    code: str
    message: str

    def render(self) -> str:
        return f"{self.path}:{self.line}:{self.column}: {self.code}: {self.message}"


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _is_identifier_boundary(path: Path, repo_root: Path) -> bool:
    absolute = _absolute(path)
    root = _absolute(repo_root)
    try:
        relative = absolute.relative_to(root).as_posix()
    except ValueError:
        return False
    return relative in _BOUNDARY_FILES


def _identifier_like(name: str) -> bool:
    return name in _IDENTIFIER_VARIABLES or name.endswith(_IDENTIFIER_SUFFIXES)


def _assigned_names(node: ast.AST) -> tuple[str, ...]:
    if isinstance(node, ast.Name):
        return (node.id,)
    if isinstance(node, (ast.List, ast.Tuple)):
        return tuple(name for item in node.elts for name in _assigned_names(item))
    return ()


def _static_literal_strings(
    node: ast.AST,
    bindings: dict[str, tuple[str, ...]],
) -> tuple[str, ...]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return (node.value,)
    if isinstance(node, ast.Name):
        return bindings.get(node.id, ())
    if isinstance(node, (ast.List, ast.Set, ast.Tuple)):
        values: list[str] = []
        for item in node.elts:
            strings = _static_literal_strings(item, bindings)
            if not strings:
                return ()
            values.extend(strings)
        return tuple(values)
    return ()


def _literal_bindings(tree: ast.AST) -> dict[str, tuple[str, ...]]:
    assignments: list[tuple[tuple[str, ...], ast.AST]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            names = tuple(name for target in node.targets for name in _assigned_names(target))
            assignments.append((names, node.value))
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            assignments.append((_assigned_names(node.target), node.value))
    bindings: dict[str, tuple[str, ...]] = {}
    for _ in range(len(assignments) + 1):
        changed = False
        for names, value in assignments:
            strings = _static_literal_strings(value, bindings)
            if not strings:
                continue
            for name in names:
                if bindings.get(name) != strings:
                    bindings[name] = strings
                    changed = True
        if not changed:
            break
    return bindings


def _function_parameters(tree: ast.AST) -> dict[str, tuple[str, ...]]:
    result: dict[str, tuple[str, ...]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        arguments = (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
        names = [argument.arg for argument in arguments]
        if node.args.vararg is not None:
            names.append(node.args.vararg.arg)
        if node.args.kwarg is not None:
            names.append(node.args.kwarg.arg)
        result[node.name] = tuple(names)
    return result


def _mapping_literal_keys(
    node: ast.AST,
    bindings: dict[str, tuple[str, ...]],
) -> tuple[str, ...]:
    if not isinstance(node, ast.Dict):
        return ()
    values: list[str] = []
    for key in node.keys:
        if key is None:
            return ()
        strings = _static_literal_strings(key, bindings)
        if len(strings) != 1:
            return ()
        values.extend(strings)
    return tuple(values)


def _pattern_strings(
    pattern: ast.pattern,
    bindings: dict[str, tuple[str, ...]],
) -> tuple[str, ...]:
    if isinstance(pattern, ast.MatchValue):
        return _static_literal_strings(pattern.value, bindings)
    if isinstance(pattern, ast.MatchOr):
        return tuple(value for child in pattern.patterns for value in _pattern_strings(child, bindings))
    if isinstance(pattern, ast.MatchSequence):
        return tuple(value for child in pattern.patterns for value in _pattern_strings(child, bindings))
    return ()


class _PythonPolicyVisitor(ast.NodeVisitor):
    def __init__(
        self,
        path: Path,
        *,
        allow_identifier_reads: bool,
        literal_bindings: dict[str, tuple[str, ...]],
        function_parameters: dict[str, tuple[str, ...]],
        parameter_taints: frozenset[tuple[str, str]],
    ) -> None:
        self.path = _absolute(path).as_posix()
        self.allow_identifier_reads = allow_identifier_reads
        self.literal_bindings = literal_bindings
        self.function_parameters = function_parameters
        self.parameter_taints = parameter_taints
        self.discovered_parameter_taints: set[tuple[str, str]] = set()
        self.violations: list[Violation] = []
        self._seen: set[tuple[int, int, str]] = set()
        self._tainted_scopes: list[set[str]] = [set()]
        self._tainted_access_scopes: list[set[tuple[str, ...]]] = [set()]
        self._getter_scopes: list[dict[str, bool]] = [{}]
        self._getter_access_scopes: list[dict[tuple[str, ...], bool]] = [{}]
        self._getter_container_scopes: list[dict[tuple[str, ...], bool]] = [{}]

    def _literal_strings(self, node: ast.AST) -> tuple[str, ...]:
        return _static_literal_strings(node, self.literal_bindings)

    def _literal_key(self, node: ast.AST) -> str | None:
        strings = self._literal_strings(node)
        return strings[0] if len(strings) == 1 else None

    def _name_is_tainted(self, name: str) -> bool:
        return _identifier_like(name) or any(name in scope for scope in reversed(self._tainted_scopes))

    def _name_is_raw_getter(self, name: str) -> bool:
        for scope in reversed(self._getter_scopes):
            if name in scope:
                return scope[name]
        return False

    def _access_path(self, node: ast.AST) -> tuple[str, ...] | None:
        if isinstance(node, ast.Name):
            return (node.id,)
        if isinstance(node, ast.Attribute):
            base = self._access_path(node.value)
            return (*base, f".{node.attr}") if base is not None else None
        if isinstance(node, ast.Subscript):
            base = self._access_path(node.value)
            if base is None:
                return None
            if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, (str, int)):
                component = repr(node.slice.value)
            else:
                key = self._literal_key(node.slice)
                if key is None:
                    return None
                component = repr(key)
            return (*base, f"[{component}]")
        return None

    def _access_is_tainted(self, path: tuple[str, ...] | None) -> bool:
        if path is None:
            return False
        return any(
            candidate == path[: len(candidate)]
            for scope in reversed(self._tainted_access_scopes)
            for candidate in scope
        )

    def _access_is_raw_getter(self, path: tuple[str, ...] | None) -> bool:
        return self._access_raw_getter_value(path) is True

    def _access_raw_getter_value(self, path: tuple[str, ...] | None) -> bool | None:
        if path is None:
            return None
        for scope in reversed(self._getter_access_scopes):
            if path in scope:
                return scope[path]
        return None

    def _access_yields_raw_getter(self, path: tuple[str, ...] | None) -> bool:
        if path is None:
            return False
        for scope in reversed(self._getter_container_scopes):
            if path in scope:
                return scope[path]
        return False

    def _container_yields_raw_getter(self, node: ast.AST) -> bool:
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self._is_raw_getter(item) for item in node.elts)
        if isinstance(node, ast.Dict):
            return any(self._is_raw_getter(value) for value in node.values)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return self._comprehension_is_raw_getter(node.generators, (node.elt,))
        if isinstance(node, ast.DictComp):
            return self._comprehension_is_raw_getter(node.generators, (node.value,))
        return self._access_yields_raw_getter(self._access_path(node))

    def _literal_container_item(
        self,
        container: ast.AST,
        slice_node: ast.AST,
    ) -> ast.AST | None:
        if isinstance(container, (ast.List, ast.Tuple)):
            if isinstance(slice_node, ast.Constant) and type(slice_node.value) is int:
                index = slice_node.value
                if -len(container.elts) <= index < len(container.elts):
                    return container.elts[index]
            return None
        if isinstance(container, ast.Dict):
            requested = self._literal_key(slice_node)
            if requested is None:
                return None
            for key, value in zip(container.keys, container.values):
                if key is not None and self._literal_key(key) == requested:
                    return value
        return None

    def _is_raw_getter(self, node: ast.AST) -> bool:
        if (
            isinstance(node, ast.Attribute)
            and node.attr in {"get", "__getitem__"}
        ):
            return True
        if isinstance(node, ast.Name):
            return self._name_is_raw_getter(node.id)
        if isinstance(node, ast.Subscript):
            exact = self._access_raw_getter_value(self._access_path(node))
            if exact is not None:
                return exact
            item = self._literal_container_item(node.value, node.slice)
            if item is not None:
                return self._is_raw_getter(item)
            return self._container_yields_raw_getter(node.value)
        if isinstance(node, ast.Attribute):
            return self._access_is_raw_getter(self._access_path(node))
        return False

    def _comprehension_is_raw_getter(
        self,
        generators: list[ast.comprehension],
        values: tuple[ast.AST, ...],
    ) -> bool:
        saved_literals = dict(self.literal_bindings)
        self._tainted_scopes.append(set())
        self._tainted_access_scopes.append(set())
        self._getter_scopes.append({})
        self._getter_access_scopes.append({})
        self._getter_container_scopes.append({})
        try:
            for generator in generators:
                if self._container_yields_raw_getter(generator.iter):
                    self._set_getter_target(generator.target, True)
                strings = self._literal_strings(generator.iter)
                for name in _assigned_names(generator.target):
                    if strings:
                        self.literal_bindings[name] = strings
            return any(self._is_raw_getter(value) for value in values)
        finally:
            self.literal_bindings.clear()
            self.literal_bindings.update(saved_literals)
            self._getter_container_scopes.pop()
            self._getter_access_scopes.pop()
            self._getter_scopes.pop()
            self._tainted_access_scopes.pop()
            self._tainted_scopes.pop()

    def _comprehension_is_tainted(
        self,
        generators: list[ast.comprehension],
        values: tuple[ast.AST, ...],
    ) -> bool:
        saved_literals = dict(self.literal_bindings)
        self._tainted_scopes.append(set())
        self._tainted_access_scopes.append(set())
        self._getter_scopes.append({})
        self._getter_access_scopes.append({})
        self._getter_container_scopes.append({})
        try:
            for generator in generators:
                if self._iter_yields_tainted(generator.iter):
                    self._tainted_scopes[-1].update(_assigned_names(generator.target))
                strings = self._literal_strings(generator.iter)
                for name in _assigned_names(generator.target):
                    if strings:
                        self.literal_bindings[name] = strings
            return any(self._is_tainted(value) for value in values)
        finally:
            self.literal_bindings.clear()
            self.literal_bindings.update(saved_literals)
            self._getter_container_scopes.pop()
            self._getter_access_scopes.pop()
            self._getter_scopes.pop()
            self._tainted_access_scopes.pop()
            self._tainted_scopes.pop()

    def _is_tainted(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return self._name_is_tainted(node.id) or self._access_is_tainted((node.id,))
        if isinstance(node, ast.Attribute):
            return (
                node.attr in _RAW_ATTRIBUTES
                or self._access_is_tainted(self._access_path(node))
                or self._is_tainted(node.value)
            )
        if isinstance(node, ast.Subscript):
            key = self._literal_key(node.slice)
            return (
                key in _RAW_MAPPING_KEYS
                or self._access_is_tainted(self._access_path(node))
                or self._is_tainted(node.value)
            )
        if isinstance(node, ast.Call):
            if (
                self._is_raw_getter(node.func)
                and node.args
                and self._literal_key(node.args[0]) in _RAW_MAPPING_KEYS
            ):
                return True
            if isinstance(node.func, ast.Name) and node.func.id == "getattr" and len(node.args) >= 2:
                if self._literal_key(node.args[1]) in _RAW_MAPPING_KEYS:
                    return True
            if isinstance(node.func, ast.Attribute):
                if node.func.attr == "get" and node.args and self._literal_key(node.args[0]) in _RAW_MAPPING_KEYS:
                    return True
                if (
                    node.func.attr == "__getitem__"
                    and node.args
                    and self._literal_key(node.args[0]) in _RAW_MAPPING_KEYS
                ):
                    return True
                if self._is_tainted(node.func.value):
                    return True
            return any(self._is_tainted(argument) for argument in node.args) or any(
                self._is_tainted(keyword.value) for keyword in node.keywords
            )
        if isinstance(node, ast.Dict):
            return any(
                self._is_tainted(item)
                for item in (*node.keys, *node.values)
                if item is not None
            )
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self._is_tainted(item) for item in node.elts)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return self._comprehension_is_tainted(node.generators, (node.elt,))
        if isinstance(node, ast.DictComp):
            return self._comprehension_is_tainted(node.generators, (node.key, node.value))
        if isinstance(node, (ast.Constant, ast.operator, ast.unaryop, ast.boolop, ast.cmpop, ast.expr_context)):
            return False
        return any(self._is_tainted(child) for child in ast.iter_child_nodes(node))

    def _iter_yields_tainted(self, node: ast.AST) -> bool:
        if self._is_tainted(node):
            return True
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self._is_tainted(item) for item in node.elts)
        return False

    def _taint_target(self, target: ast.AST) -> None:
        if isinstance(target, ast.Name):
            self._tainted_scopes[-1].add(target.id)
            return
        if isinstance(target, (ast.List, ast.Tuple)):
            for item in target.elts:
                self._taint_target(item)
            return
        path = self._access_path(target)
        if path is not None:
            self._tainted_access_scopes[-1].add(path)
        elif isinstance(target, ast.Subscript):
            owner = self._access_path(target.value)
            if owner is not None:
                self._tainted_access_scopes[-1].add(owner)

    def _taint_targets(self, targets: Iterable[ast.AST], value: ast.AST) -> None:
        if self._is_tainted(value):
            for target in targets:
                self._taint_target(target)

    def _set_getter_target(self, target: ast.AST, getter: bool) -> None:
        if isinstance(target, (ast.List, ast.Tuple)):
            for item in target.elts:
                self._set_getter_target(item, getter)
            return
        for name in _assigned_names(target):
            self._getter_scopes[-1][name] = getter
        path = self._access_path(target)
        if path is not None and not isinstance(target, ast.Name):
            self._getter_access_scopes[-1][path] = getter
            if getter and len(path) > 1:
                self._getter_container_scopes[-1][path[:-1]] = True
        elif path is None and isinstance(target, ast.Subscript) and getter:
            owner = self._access_path(target.value)
            if owner is not None:
                self._getter_container_scopes[-1][owner] = True

    def _track_literal_getter_items(self, path: tuple[str, ...], value: ast.AST) -> None:
        items: list[tuple[str, ast.AST]] = []
        if isinstance(value, (ast.List, ast.Tuple)):
            items = [(f"[{index}]", item) for index, item in enumerate(value.elts)]
        elif isinstance(value, ast.Dict):
            for key, item in zip(value.keys, value.values):
                if key is None:
                    continue
                if isinstance(key, ast.Constant) and isinstance(key.value, (str, int)):
                    items.append((f"[{key.value!r}]", item))
                    continue
                literal = self._literal_key(key)
                if literal is not None:
                    items.append((f"[{literal!r}]", item))
        for component, item in items:
            item_path = (*path, component)
            self._getter_access_scopes[-1][item_path] = self._is_raw_getter(item)
            self._getter_container_scopes[-1][item_path] = self._container_yields_raw_getter(item)
            self._track_literal_getter_items(item_path, item)

    def _copy_access_state(self, target: ast.AST, value: ast.AST) -> None:
        target_path = self._access_path(target)
        source_path = self._access_path(value)
        if target_path is None or source_path is None or target_path == source_path:
            return
        for scope in self._tainted_access_scopes:
            for path in tuple(scope):
                if path[: len(source_path)] == source_path:
                    self._tainted_access_scopes[-1].add((*target_path, *path[len(source_path) :]))
        seen: set[tuple[str, ...]] = set()
        for scope in reversed(self._getter_access_scopes):
            for path, getter in tuple(scope.items()):
                if path in seen or path[: len(source_path)] != source_path:
                    continue
                seen.add(path)
                self._getter_access_scopes[-1][(*target_path, *path[len(source_path) :])] = getter
        seen.clear()
        for scope in reversed(self._getter_container_scopes):
            for path, yields_getter in tuple(scope.items()):
                if path in seen or path[: len(source_path)] != source_path:
                    continue
                seen.add(path)
                self._getter_container_scopes[-1][(*target_path, *path[len(source_path) :])] = yields_getter

    def _track_getter_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, (ast.List, ast.Tuple)):
            if isinstance(value, (ast.List, ast.Tuple)) and len(target.elts) == len(value.elts):
                for child_target, child_value in zip(target.elts, value.elts):
                    self._track_getter_target(child_target, child_value)
                return
            self._set_getter_target(target, self._is_raw_getter(value))
            return
        getter = self._is_raw_getter(value)
        self._set_getter_target(target, getter)
        path = self._access_path(target)
        if path is not None:
            self._getter_container_scopes[-1][path] = self._container_yields_raw_getter(value)
            self._track_literal_getter_items(path, value)
        elif isinstance(target, ast.Subscript) and getter:
            owner = self._access_path(target.value)
            if owner is not None:
                self._getter_container_scopes[-1][owner] = True

    def _track_getter_targets(self, targets: Iterable[ast.AST], value: ast.AST) -> None:
        for target in targets:
            self._track_getter_target(target, value)

    def _copy_access_targets(self, targets: Iterable[ast.AST], value: ast.AST) -> None:
        for target in targets:
            self._copy_access_state(target, value)

    def add(self, node: ast.AST, code: str, message: str) -> None:
        line = int(getattr(node, "lineno", 1))
        column = int(getattr(node, "col_offset", 0)) + 1
        identity = (line, column, code)
        if identity in self._seen:
            return
        self._seen.add(identity)
        self.violations.append(Violation(self.path, line, column, code, message))

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if not self.allow_identifier_reads and node.attr in _RAW_ATTRIBUTES:
            self.add(node, "raw-identifier-read", f"semantic code reads '{node.attr}'")
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        key = self._literal_key(node.slice)
        if not self.allow_identifier_reads and key in _RAW_MAPPING_KEYS:
            self.add(node, "raw-identifier-read", f"semantic code reads '{key}'")
        if not self.allow_identifier_reads and self._is_tainted(node.slice):
            mapping_keys = _mapping_literal_keys(node.value, self.literal_bindings)
            if mapping_keys:
                self._comparison_violation(node, mapping_keys)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._taint_targets(node.targets, node.value)
        self._track_getter_targets(node.targets, node.value)
        self._copy_access_targets(node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._taint_targets((node.target,), node.value)
            self._track_getter_targets((node.target,), node.value)
            self._copy_access_targets((node.target,), node.value)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self._taint_targets((node.target,), node.value)
        self._track_getter_targets((node.target,), node.value)
        self._copy_access_targets((node.target,), node.value)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if self._is_tainted(node.target) or self._is_tainted(node.value):
            self._taint_target(node.target)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self.visit(node.iter)
        if self._iter_yields_tainted(node.iter):
            self._taint_target(node.target)
        if self._container_yields_raw_getter(node.iter):
            self._set_getter_target(node.target, True)
        strings = self._literal_strings(node.iter)
        for name in _assigned_names(node.target):
            if strings:
                self.literal_bindings[name] = strings
        for statement in (*node.body, *node.orelse):
            self.visit(statement)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.visit_For(node)

    def _visit_comprehension(
        self,
        generators: list[ast.comprehension],
        values: tuple[ast.AST, ...],
    ) -> None:
        saved_literals = dict(self.literal_bindings)
        self._tainted_scopes.append(set())
        self._tainted_access_scopes.append(set())
        self._getter_scopes.append({})
        self._getter_access_scopes.append({})
        self._getter_container_scopes.append({})
        try:
            for generator in generators:
                self.visit(generator.iter)
                if self._iter_yields_tainted(generator.iter):
                    self._taint_target(generator.target)
                if self._container_yields_raw_getter(generator.iter):
                    self._set_getter_target(generator.target, True)
                strings = self._literal_strings(generator.iter)
                for name in _assigned_names(generator.target):
                    if strings:
                        self.literal_bindings[name] = strings
                for condition in generator.ifs:
                    self.visit(condition)
            for value in values:
                self.visit(value)
        finally:
            self.literal_bindings.clear()
            self.literal_bindings.update(saved_literals)
            self._getter_container_scopes.pop()
            self._getter_access_scopes.pop()
            self._getter_scopes.pop()
            self._tainted_access_scopes.pop()
            self._tainted_scopes.pop()

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node.generators, (node.elt,))

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node.generators, (node.elt,))

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node.generators, (node.elt,))

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node.generators, (node.key, node.value))

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)
        arguments = (
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        )
        scope = {
            argument.arg
            for argument in arguments
            if _identifier_like(argument.arg) or (node.name, argument.arg) in self.parameter_taints
        }
        if node.args.vararg is not None and _identifier_like(node.args.vararg.arg):
            scope.add(node.args.vararg.arg)
        if node.args.vararg is not None and (node.name, node.args.vararg.arg) in self.parameter_taints:
            scope.add(node.args.vararg.arg)
        if node.args.kwarg is not None and _identifier_like(node.args.kwarg.arg):
            scope.add(node.args.kwarg.arg)
        if node.args.kwarg is not None and (node.name, node.args.kwarg.arg) in self.parameter_taints:
            scope.add(node.args.kwarg.arg)
        self._tainted_scopes.append(scope)
        self._tainted_access_scopes.append(set())
        self._getter_scopes.append({})
        self._getter_access_scopes.append({})
        self._getter_container_scopes.append({})
        try:
            for statement in node.body:
                self.visit(statement)
        finally:
            self._getter_container_scopes.pop()
            self._getter_access_scopes.pop()
            self._getter_scopes.pop()
            self._tainted_access_scopes.pop()
            self._tainted_scopes.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_Call(self, node: ast.Call) -> None:
        if (
            self._is_raw_getter(node.func)
            and node.args
        ):
            key = self._literal_key(node.args[0])
            if not self.allow_identifier_reads and key in _RAW_MAPPING_KEYS:
                self.add(node, "raw-identifier-read", f"semantic code reads '{key}'")
        if isinstance(node.func, ast.Name):
            parameters = self.function_parameters.get(node.func.id, ())
            for parameter, argument in zip(parameters, node.args):
                if self._is_tainted(argument):
                    self.discovered_parameter_taints.add((node.func.id, parameter))
            by_name = {keyword.arg: keyword.value for keyword in node.keywords if keyword.arg is not None}
            for parameter in parameters:
                if parameter in by_name and self._is_tainted(by_name[parameter]):
                    self.discovered_parameter_taints.add((node.func.id, parameter))
        if isinstance(node.func, ast.Name) and node.func.id == "getattr" and len(node.args) >= 2:
            key = self._literal_key(node.args[1])
            if not self.allow_identifier_reads and key in _RAW_MAPPING_KEYS:
                self.add(node, "raw-identifier-read", f"semantic code reads '{key}'")
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "get" and node.args:
                key = self._literal_key(node.args[0])
                if not self.allow_identifier_reads and key in _RAW_MAPPING_KEYS:
                    self.add(node, "raw-identifier-read", f"semantic code reads '{key}'")
                if not self.allow_identifier_reads and self._is_tainted(node.args[0]):
                    mapping_keys = _mapping_literal_keys(node.func.value, self.literal_bindings)
                    if mapping_keys:
                        self._comparison_violation(node, mapping_keys)
            if node.func.attr == "__getitem__" and node.args:
                key = self._literal_key(node.args[0])
                if not self.allow_identifier_reads and key in _RAW_MAPPING_KEYS:
                    self.add(node, "raw-identifier-read", f"semantic code reads '{key}'")
            if (
                not self.allow_identifier_reads
                and node.func.attr in _AFFIX_METHODS
                and self._is_tainted(node.func.value)
                and not (
                    node.func.attr == "removeprefix"
                    and node.args
                    and self._literal_key(node.args[0]) == "sha256:"
                )
            ):
                self.add(
                    node,
                    "identifier-affix-classifier",
                    f"identifier text is classified with {node.func.attr}()",
                )
            if (
                not self.allow_identifier_reads
                and node.func.attr in _REGEX_FUNCTIONS
                and (
                    any(self._is_tainted(argument) for argument in node.args)
                    or any(self._is_tainted(keyword.value) for keyword in node.keywords)
                )
            ):
                self.add(node, "identifier-regex-classifier", "identifier text is classified by a regular expression")
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        if not self.allow_identifier_reads:
            operands = (node.left, *node.comparators)
            for left, right in zip(operands, operands[1:]):
                left_strings = self._literal_strings(left)
                right_strings = self._literal_strings(right)
                if self._is_tainted(left) and right_strings:
                    self._comparison_violation(node, right_strings)
                elif self._is_tainted(right) and left_strings:
                    self._comparison_violation(node, left_strings)
        self.generic_visit(node)

    def visit_Match(self, node: ast.Match) -> None:
        if not self.allow_identifier_reads and self._is_tainted(node.subject):
            for case in node.cases:
                strings = _pattern_strings(case.pattern, self.literal_bindings)
                if strings:
                    self._comparison_violation(case.pattern, strings)
        self.generic_visit(node)

    def _comparison_violation(self, node: ast.AST, values: tuple[str, ...]) -> None:
        if values and all(value and not any(character.isalnum() for character in value) for value in values):
            return
        keyword_values = sorted({value.casefold() for value in values} & _TARGET_KEYWORDS)
        if keyword_values:
            self.add(
                node,
                "target-keyword-classifier",
                "opaque identifier is compared with target keyword(s): " + ", ".join(keyword_values),
            )
        else:
            self.add(
                node,
                "identifier-string-comparison",
                "opaque identifier is compared with literal text",
            )


def _scan_python(path: Path, source: str, *, repo_root: Path) -> list[Violation]:
    try:
        tree = ast.parse(source, filename=path.as_posix())
    except SyntaxError as error:
        return [
            Violation(
                _absolute(path).as_posix(),
                error.lineno or 1,
                error.offset or 1,
                "syntax-error",
                error.msg,
            )
        ]
    parameters = _function_parameters(tree)
    parameter_taints: frozenset[tuple[str, str]] = frozenset()
    visitor: _PythonPolicyVisitor | None = None
    parameter_count = sum(len(items) for items in parameters.values())
    for _ in range(parameter_count + 2):
        visitor = _PythonPolicyVisitor(
            path,
            allow_identifier_reads=_is_identifier_boundary(path, repo_root),
            literal_bindings=_literal_bindings(tree),
            function_parameters=parameters,
            parameter_taints=parameter_taints,
        )
        visitor.visit(tree)
        expanded = parameter_taints | frozenset(visitor.discovered_parameter_taints)
        if expanded == parameter_taints:
            return visitor.violations
        parameter_taints = expanded
    assert visitor is not None
    return visitor.violations


_CPP_FIELD = (
    r"moduleName|module_name|instanceName|instance_name|portName|port_name|"
    r"netName|net_name|fileName|file_name|directoryName|directory_name|"
    r"targetName|target_name|designName|design_name|sourceSymbols|source_symbols"
)
_CPP_IDENTIFIER_NAMES = (
    "moduleName", "module_name", "instanceName", "instance_name", "portName", "port_name",
    "netName", "net_name", "fileName", "file_name", "directoryName", "directory_name",
    "targetName", "target_name", "designName", "design_name", "sourceSymbols", "source_symbols",
    "symbol", "identifier", "componentId", "component_id", "candidateId", "candidate_id",
    "jobId", "job_id", "targetId", "target_id",
)
_CPP_NORMAL_STRING = r'(?:u8|u|U|L)?"(?:\\.|[^"\\])*"'
_CPP_RAW_STRING = r'(?:u8|u|U|L)?R"[^\s()\\]{0,16}\([\s\S]*?\)[^\s()\\]{0,16}"'
_CPP_STRING = rf"(?:{_CPP_NORMAL_STRING}|{_CPP_RAW_STRING})"
_CPP_RAW_ACCESS = re.compile(
    rf"(?:\.|->)\s*(?:{_CPP_FIELD})\b"
    rf"|\[\s*{_CPP_NORMAL_STRING}\s*\]"
)
_CPP_RAW_SUBSCRIPT_KEY = re.compile(
    rf"^\[\s*(?:u8|u|U|L)?\"(?:{_CPP_FIELD})\"\s*\]$"
)
_CPP_TYPE = (
    r"(?:const\s+)?(?:auto|[A-Za-z_]\w*(?:\s*::\s*[A-Za-z_]\w*)*"
    r"(?:\s*<[^;]+?>)?)"
)
_CPP_ALIAS_DECLARATION = re.compile(
    rf"(?:\A|(?<=[;{{}}(]))\s*(?!(?:if|for|while|switch|return)\b){_CPP_TYPE}"
    r"\s+(?:[&*]\s*)?(?P<target>[A-Za-z_]\w*)\s*"
    r"(?:=(?!=)|\{|\((?![^;]*\)\s*\{))(?P<value>[^;]+);",
    re.MULTILINE,
)
_CPP_COMMA_DECLARATION = re.compile(
    rf"(?:\A|(?<=[;{{}}]))\s*{_CPP_TYPE}\s+"
    r"(?P<body>(?:[&*]\s*)?[A-Za-z_]\w*(?:\s*=[^,;]+)?\s*,[^;]+);",
    re.MULTILINE,
)
_CPP_ALIAS_LATE_ASSIGNMENT = re.compile(
    r"(?:\A|(?<=[;{}]))\s*(?P<target>[A-Za-z_]\w*)\s*(?<![=!<>])=(?!=)\s*(?P<value>[^;]+);",
    re.MULTILINE,
)
_CPP_ALIAS_METHOD_MUTATION = re.compile(
    r"(?:\A|(?<=[;{}]))\s*(?P<target>[A-Za-z_]\w*)\s*\.\s*"
    r"(?:assign|append|push_back|insert|replace|swap)"
    r"\s*\((?P<value>[^;]*)\)\s*;",
    re.MULTILINE,
)
_CPP_ALIAS_AUGMENTED_ASSIGNMENT = re.compile(
    r"(?:\A|(?<=[;{}]))\s*(?P<target>[A-Za-z_]\w*)\s*"
    r"(?:\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<=|>>=)\s*(?P<value>[^;]+);",
    re.MULTILINE,
)
_CPP_RAW_PREFIXES = ("u8R\"", "uR\"", "UR\"", "LR\"", "R\"")


def _cpp_raw_string_end(source: str, start: int) -> int | None:
    prefix = next((item for item in _CPP_RAW_PREFIXES if source.startswith(item, start)), None)
    if prefix is None:
        return None
    delimiter_start = start + len(prefix)
    opening = source.find("(", delimiter_start, delimiter_start + 17)
    if opening < 0:
        return None
    delimiter = source[delimiter_start:opening]
    if any(character.isspace() or character in "()\\" for character in delimiter):
        return None
    closing_token = ")" + delimiter + '"'
    closing = source.find(closing_token, opening + 1)
    return len(source) if closing < 0 else closing + len(closing_token)


def _cpp_quoted_end(source: str, start: int) -> int:
    quote = source[start]
    index = start + 1
    while index < len(source):
        if source[index] == "\\" and index + 1 < len(source):
            index += 2
        elif source[index] == quote:
            return index + 1
        else:
            index += 1
    return len(source)


def _cpp_string_spans(source: str) -> tuple[tuple[int, int], ...]:
    spans: list[tuple[int, int]] = []
    index = 0
    while index < len(source):
        raw_end = _cpp_raw_string_end(source, index)
        if raw_end is not None:
            spans.append((index, raw_end))
            index = raw_end
        elif source[index] in {'"', "'"}:
            quoted_end = _cpp_quoted_end(source, index)
            spans.append((index, quoted_end))
            index = quoted_end
        else:
            index += 1
    return tuple(spans)


def _strip_cpp_comments(source: str) -> str:
    output = list(source)
    index = 0
    state = "normal"
    quote = ""
    while index < len(source):
        if state == "normal":
            raw_end = _cpp_raw_string_end(source, index)
            if raw_end is not None:
                index = raw_end
            elif source.startswith("//", index):
                output[index] = output[index + 1] = " "
                index += 2
                state = "line-comment"
            elif source.startswith("/*", index):
                output[index] = output[index + 1] = " "
                index += 2
                state = "block-comment"
            elif source[index] in ('"', "'"):
                quote = source[index]
                state = "quoted"
                index += 1
            else:
                index += 1
        elif state == "line-comment":
            if source[index] == "\n":
                state = "normal"
            else:
                output[index] = " "
            index += 1
        elif state == "block-comment":
            if source.startswith("*/", index):
                output[index] = output[index + 1] = " "
                index += 2
                state = "normal"
            else:
                if source[index] != "\n":
                    output[index] = " "
                index += 1
        else:
            if source[index] == "\\" and index + 1 < len(source):
                index += 2
            elif source[index] == quote:
                state = "normal"
                index += 1
            else:
                index += 1
    return "".join(output)


def _line_column(source: str, offset: int) -> tuple[int, int]:
    line = source.count("\n", 0, offset) + 1
    previous_newline = source.rfind("\n", 0, offset)
    return line, offset - previous_newline


def _mask_cpp_string_literals(source: str) -> str:
    output = list(source)
    for start, end in _cpp_string_spans(source):
        for index in range(start, end):
            if output[index] != "\n":
                output[index] = " "
    return "".join(output)


def _cpp_split_declarators(body: str) -> tuple[str, ...]:
    parts: list[str] = []
    start = 0
    depths = {"(": 0, "[": 0, "{": 0}
    closing = {")": "(", "]": "[", "}": "{"}
    for index, character in enumerate(body):
        if character in depths:
            depths[character] += 1
        elif character in closing:
            opening = closing[character]
            depths[opening] = max(0, depths[opening] - 1)
        elif character == "," and not any(depths.values()):
            parts.append(body[start:index])
            start = index + 1
    parts.append(body[start:])
    return tuple(parts)


def _cpp_identifier_names(source: str) -> frozenset[str]:
    names = set(_CPP_IDENTIFIER_NAMES)
    taint_source = _mask_cpp_string_literals(source)
    assignments = [
        (match.group("target"), match.group("value"))
        for pattern in (
            _CPP_ALIAS_DECLARATION,
            _CPP_ALIAS_LATE_ASSIGNMENT,
            _CPP_ALIAS_METHOD_MUTATION,
            _CPP_ALIAS_AUGMENTED_ASSIGNMENT,
        )
        for match in pattern.finditer(taint_source)
    ]
    for declaration in _CPP_COMMA_DECLARATION.finditer(taint_source):
        for declarator in _cpp_split_declarators(declaration.group("body"))[1:]:
            match = re.fullmatch(
                r"\s*(?:[&*]\s*)?(?P<target>[A-Za-z_]\w*)\s*=\s*(?P<value>[\s\S]+?)\s*",
                declarator,
            )
            if match is not None:
                assignments.append((match.group("target"), match.group("value")))
    for _ in range(len(assignments) + 1):
        changed = False
        for target, value in assignments:
            if target not in names and any(
                re.search(rf"\b{re.escape(name)}\b", value) is not None
                for name in names
            ):
                names.add(target)
                changed = True
        if not changed:
            break
    return frozenset(names)


def _cpp_literal_value(literal: str) -> str:
    if 'R"' in literal:
        start = literal.find("(")
        end = literal.rfind(")")
        return literal[start + 1 : end] if start >= 0 and end > start else literal
    start = literal.find('"')
    return literal[start + 1 : -1]


def _scan_cpp(path: Path, source: str, *, repo_root: Path) -> list[Violation]:
    if _is_identifier_boundary(path, repo_root):
        return []
    cleaned = _strip_cpp_comments(source)
    masked = _mask_cpp_string_literals(cleaned)
    string_spans = _cpp_string_spans(cleaned)
    absolute = _absolute(path).as_posix()
    result: set[Violation] = set()
    identifier_names = _cpp_identifier_names(cleaned)
    identifiers = "(?:" + "|".join(re.escape(name) for name in sorted(identifier_names, key=lambda item: (-len(item), item))) + ")"
    affix_pattern = re.compile(
        rf"\b{identifiers}\b\s*\.\s*(?:starts_with|ends_with|startsWith|endsWith)\s*\("
    )
    regex_pattern = re.compile(
        rf"\b(?:std\s*::\s*)?regex_(?:match|search)\s*\([\s\S]{{0,1024}}?\b{identifiers}\b"
    )
    direct_compare_pattern = re.compile(
        rf"(?P<left>\b{identifiers}\b)\s*(?:==|!=)\s*(?P<right_literal>{_CPP_STRING})"
        rf"|(?P<left_literal>{_CPP_STRING})\s*(?:==|!=)\s*(?P<right>\b{identifiers}\b)"
    )

    for match in _CPP_RAW_ACCESS.finditer(cleaned):
        if any(start <= match.start() < end for start, end in string_spans):
            continue
        if match.group(0).startswith("[") and _CPP_RAW_SUBSCRIPT_KEY.fullmatch(match.group(0)) is None:
            continue
        line, column = _line_column(cleaned, match.start())
        result.add(Violation(absolute, line, column, "raw-identifier-read", "semantic code reads a raw identifier"))

    checks = (
        (affix_pattern, "identifier-affix-classifier", "identifier text is classified by prefix or suffix"),
        (regex_pattern, "identifier-regex-classifier", "identifier text is classified by a regular expression"),
    )
    for pattern, code, message in checks:
        for match in pattern.finditer(masked):
            line, column = _line_column(cleaned, match.start())
            result.add(Violation(absolute, line, column, code, message))

    for match in direct_compare_pattern.finditer(cleaned):
        literal = match.group("right_literal") or match.group("left_literal")
        literal_value = _cpp_literal_value(literal).casefold()
        if literal_value in _TARGET_KEYWORDS:
            code = "target-keyword-classifier"
            message = f"opaque identifier is compared with target keyword: {literal_value}"
        else:
            code = "identifier-string-comparison"
            message = "opaque identifier is compared with literal text"
        line, column = _line_column(cleaned, match.start())
        result.add(Violation(absolute, line, column, code, message))
    return sorted(result)


def _first_symlink_component(path: Path) -> Path | None:
    absolute = _absolute(path)
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError:
            return None
        if stat.S_ISLNK(metadata.st_mode):
            return current
    return None


def _source_files(paths: Sequence[Path]) -> tuple[list[Path], list[Violation]]:
    files: set[Path] = set()
    violations: list[Violation] = []
    for configured in paths:
        path = _absolute(Path(configured))
        symlink_component = _first_symlink_component(path)
        if symlink_component is not None:
            violations.append(
                Violation(path.as_posix(), 1, 1, "path-symlink", "symbolic-link path components are not scanned")
            )
            continue
        try:
            metadata = path.lstat()
        except OSError as error:
            violations.append(Violation(path.as_posix(), 1, 1, "path-error", str(error)))
            continue
        if stat.S_ISLNK(metadata.st_mode):
            violations.append(Violation(path.as_posix(), 1, 1, "path-symlink", "symbolic links are not scanned"))
            continue
        if stat.S_ISREG(metadata.st_mode):
            if path.suffix.lower() in _SOURCE_SUFFIXES:
                files.add(path)
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            violations.append(Violation(path.as_posix(), 1, 1, "path-error", "path is not a regular file or directory"))
            continue
        for current, directory_names, file_names in os.walk(path, followlinks=False):
            current_path = Path(current)
            for name in sorted(tuple(directory_names)):
                child = current_path / name
                try:
                    child_metadata = child.lstat()
                except OSError as error:
                    violations.append(Violation(child.as_posix(), 1, 1, "path-error", str(error)))
                    directory_names.remove(name)
                    continue
                if stat.S_ISLNK(child_metadata.st_mode):
                    violations.append(
                        Violation(child.as_posix(), 1, 1, "path-symlink", "symbolic links are not scanned")
                    )
                    directory_names.remove(name)
            for name in sorted(file_names):
                child = current_path / name
                try:
                    child_metadata = child.lstat()
                except OSError as error:
                    violations.append(Violation(child.as_posix(), 1, 1, "path-error", str(error)))
                    continue
                if stat.S_ISLNK(child_metadata.st_mode):
                    violations.append(
                        Violation(child.as_posix(), 1, 1, "path-symlink", "symbolic links are not scanned")
                    )
                    continue
                if stat.S_ISREG(child_metadata.st_mode) and child.suffix.lower() in _SOURCE_SUFFIXES:
                    files.add(child)
                if len(files) > _MAX_SOURCE_FILES:
                    violations.append(
                        Violation(path.as_posix(), 1, 1, "path-error", "source file limit exceeded")
                    )
                    return [], violations
    return sorted(files, key=lambda item: item.as_posix()), violations


def _read_source(path: Path) -> tuple[str | None, Violation | None]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            return None, Violation(path.as_posix(), 1, 1, "source-read-error", "source is not a regular file")
        if metadata.st_size > _MAX_SOURCE_BYTES:
            return None, Violation(path.as_posix(), 1, 1, "source-too-large", "source exceeds 2 MiB")
        chunks: list[bytes] = []
        remaining = _MAX_SOURCE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > _MAX_SOURCE_BYTES:
            return None, Violation(path.as_posix(), 1, 1, "source-too-large", "source exceeds 2 MiB")
        return payload.decode("utf-8"), None
    except (OSError, UnicodeError) as error:
        return None, Violation(path.as_posix(), 1, 1, "source-read-error", str(error))
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def scan_paths(
    paths: Sequence[Path],
    *,
    repo_root: Path | None = None,
) -> list[Violation]:
    """Return deterministic identifier-policy violations below ``paths``."""
    trusted_root = _absolute(_DEFAULT_REPO_ROOT if repo_root is None else repo_root)
    files, violations = _source_files(paths)
    for path in files:
        source, read_violation = _read_source(path)
        if read_violation is not None:
            violations.append(read_violation)
            continue
        assert source is not None
        if path.suffix.lower() == ".py":
            violations.extend(_scan_python(path, source, repo_root=trusted_root))
        else:
            violations.extend(_scan_cpp(path, source, repo_root=trusted_root))
    return sorted(set(violations))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Reject semantic inference based on opaque identifier text."
    )
    parser.add_argument("--paths", nargs="+", required=True, type=Path)
    parser.add_argument("--repo-root", type=Path, default=_DEFAULT_REPO_ROOT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    violations = scan_paths(args.paths, repo_root=args.repo_root)
    for violation in violations:
        print(violation.render())
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
