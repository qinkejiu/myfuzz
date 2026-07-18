"""Canonical RegisterModelIR v1 construction and CMSIS-SVD import."""

from __future__ import annotations

from pathlib import Path
from typing import Mapping
import xml.etree.ElementTree as ET

from .contracts import RegisterModelIRV1, seal_contract
from .input_model import InputValidationError


REGISTER_ACCESSES = {"ro", "rw", "wo", "w1c", "w1s", "rc"}


def build_register_model(value: Mapping[str, object], *, provenance: Mapping[str, object]) -> RegisterModelIRV1:
    _shape(value, {"schema", "name", "blocks"}, "register model")
    if value["schema"] != "myfuzz.register-source/v1":
        raise InputValidationError("register model source schema must be myfuzz.register-source/v1")
    name = _text(value["name"], "register model.name")
    raw_blocks = _array(value["blocks"], "register model.blocks")
    blocks = tuple(_block(block, index) for index, block in enumerate(raw_blocks))
    return seal_contract(RegisterModelIRV1(name, blocks, dict(provenance)))  # type: ignore[return-value]


def import_cmsis_svd(source: str | Path, *, peripheral: str | None = None) -> RegisterModelIRV1:
    path = Path(source)
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise InputValidationError(f"{path}: invalid CMSIS-SVD: {exc}") from exc
    candidates = root.findall("./peripherals/peripheral")
    if peripheral is not None:
        candidates = [item for item in candidates if _xml_text(item, "name") == peripheral]
    if len(candidates) != 1:
        raise InputValidationError(f"CMSIS-SVD import requires exactly one peripheral; found {len(candidates)}")
    item = candidates[0]
    name = _xml_text(item, "name")
    base = _xml_int(item, "baseAddress")
    registers = []
    for register in item.findall("./registers/register"):
        width = _xml_int(register, "size", default=32)
        access = _svd_access(_xml_text(register, "access", default="read-write"))
        reset = _xml_int(register, "resetValue", default=0)
        fields = []
        for field in register.findall("./fields/field"):
            field_access = _svd_access(_xml_text(field, "access", default=_svd_access_name(access)))
            fields.append({
                "name": _xml_text(field, "name"), "lsb": _xml_int(field, "bitOffset"),
                "width": _xml_int(field, "bitWidth"), "access": field_access,
                "reset": 0, "side_effect": "none", "volatile": False,
                "irq": None, "enum": (),
            })
        registers.append({
            "name": _xml_text(register, "name"), "offset": _xml_int(register, "addressOffset"),
            "width": width, "access": access, "reset": reset,
            "side_effect": "none", "volatile": False, "irq": None,
            "fields": tuple(fields),
        })
    source_value = {
        "schema": "myfuzz.register-source/v1", "name": name,
        "blocks": ({"name": name, "base": base, "registers": tuple(registers)},),
    }
    return build_register_model(source_value, provenance={"source": "cmsis-svd", "path": path.as_posix()})


def _block(value: object, index: int) -> Mapping[str, object]:
    path = f"blocks[{index}]"
    item = _mapping(value, path)
    _shape(item, {"name", "base", "registers"}, path)
    registers = tuple(_register(register, f"{path}.registers[{offset}]")
                      for offset, register in enumerate(_array(item["registers"], f"{path}.registers")))
    offsets = [(int(register["offset"]), int(register["width"]) // 8, str(register["name"])) for register in registers]
    for left, right in zip(sorted(offsets), sorted(offsets)[1:]):
        if left[0] + left[1] > right[0]:
            raise InputValidationError(f"{path}: registers {left[2]!r} and {right[2]!r} overlap")
    return {"name": _text(item["name"], f"{path}.name"), "base": _nonnegative(item["base"], f"{path}.base"), "registers": registers}


def _register(value: object, path: str) -> Mapping[str, object]:
    item = _mapping(value, path)
    required = {"name", "offset", "width", "access", "reset", "side_effect", "volatile", "irq", "fields"}
    _shape(item, required, path)
    width = _positive(item["width"], f"{path}.width")
    if width % 8:
        raise InputValidationError(f"{path}.width: expected a whole number of bytes")
    reset = _bounded(item["reset"], width, f"{path}.reset")
    access = _access(item["access"], f"{path}.access")
    fields = tuple(_field(field, f"{path}.fields[{index}]", width, access)
                   for index, field in enumerate(_array(item["fields"], f"{path}.fields")))
    used = 0
    for field in fields:
        mask = ((1 << int(field["width"])) - 1) << int(field["lsb"])
        if used & mask:
            raise InputValidationError(f"{path}: register fields overlap")
        used |= mask
    volatile = item["volatile"]
    if not isinstance(volatile, bool):
        raise InputValidationError(f"{path}.volatile: expected a boolean")
    irq = item["irq"]
    if irq is not None and not isinstance(irq, Mapping):
        raise InputValidationError(f"{path}.irq: expected an object or null")
    return {"name": _text(item["name"], f"{path}.name"), "offset": _nonnegative(item["offset"], f"{path}.offset"),
            "width": width, "access": access, "reset": reset,
            "side_effect": _text(item["side_effect"], f"{path}.side_effect"),
            "volatile": volatile, "irq": None if irq is None else dict(irq), "fields": fields}


def _field(value: object, path: str, register_width: int, default_access: str) -> Mapping[str, object]:
    item = _mapping(value, path)
    required = {"name", "lsb", "width", "access", "reset", "side_effect", "volatile", "irq", "enum"}
    _shape(item, required, path)
    lsb, width = _nonnegative(item["lsb"], f"{path}.lsb"), _positive(item["width"], f"{path}.width")
    if lsb + width > register_width:
        raise InputValidationError(f"{path}: field exceeds register width")
    access = _access(item.get("access", default_access), f"{path}.access")
    enum = _array(item["enum"], f"{path}.enum")
    for choice in enum:
        if not isinstance(choice, Mapping) or set(choice) != {"name", "value"}:
            raise InputValidationError(f"{path}.enum: expected name/value objects")
        _bounded(choice["value"], width, f"{path}.enum.value")
    volatile = item["volatile"]
    if not isinstance(volatile, bool):
        raise InputValidationError(f"{path}.volatile: expected a boolean")
    return {"name": _text(item["name"], f"{path}.name"), "lsb": lsb, "width": width,
            "access": access, "reset": _bounded(item["reset"], width, f"{path}.reset"),
            "side_effect": _text(item["side_effect"], f"{path}.side_effect"), "volatile": volatile,
            "irq": item["irq"], "enum": tuple(dict(choice) for choice in enum)}


def _svd_access(value: str) -> str:
    return {"read-only": "ro", "read-write": "rw", "write-only": "wo"}.get(value, value)


def _svd_access_name(value: str) -> str:
    return {"ro": "read-only", "rw": "read-write", "wo": "write-only"}.get(value, value)


def _xml_text(node: ET.Element, name: str, default: str | None = None) -> str:
    child = node.find(name)
    if child is None or child.text is None or not child.text.strip():
        if default is None: raise InputValidationError(f"CMSIS-SVD: missing {name}")
        return default
    return child.text.strip()


def _xml_int(node: ET.Element, name: str, default: int | None = None) -> int:
    text = _xml_text(node, name, None if default is None else str(default))
    try: return int(text, 0)
    except ValueError as exc: raise InputValidationError(f"CMSIS-SVD: {name} is not an integer") from exc


def _shape(value: Mapping[str, object], required: set[str], path: str) -> None:
    missing, unknown = required - set(value), set(value) - required
    if missing or unknown:
        values, kind = (missing, "missing") if missing else (unknown, "unknown")
        raise InputValidationError(f"{path}: {kind} field(s): {', '.join(sorted(values))}")


def _mapping(value: object, path: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping): raise InputValidationError(f"{path}: expected an object")
    return value


def _array(value: object, path: str) -> tuple[object, ...]:
    if not isinstance(value, (list, tuple)): raise InputValidationError(f"{path}: expected an array")
    return tuple(value)


def _text(value: object, path: str) -> str:
    if not isinstance(value, str) or not value.strip(): raise InputValidationError(f"{path}: expected text")
    return value


def _access(value: object, path: str) -> str:
    result = _text(value, path).lower()
    if result not in REGISTER_ACCESSES: raise InputValidationError(f"{path}: unsupported access {result!r}")
    return result


def _positive(value: object, path: str) -> int:
    result = _nonnegative(value, path)
    if result == 0: raise InputValidationError(f"{path}: expected a positive integer")
    return result


def _nonnegative(value: object, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0: raise InputValidationError(f"{path}: expected a non-negative integer")
    return value


def _bounded(value: object, width: int, path: str) -> int:
    result = _nonnegative(value, path)
    if result >= 1 << width: raise InputValidationError(f"{path}: value exceeds {width} bits")
    return result
