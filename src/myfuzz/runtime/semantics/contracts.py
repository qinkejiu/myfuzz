"""Closed semantic contracts: transport is not semantics.

A protocol token (``('apb', '3')``) never implies stable storage.  Each contract
names its source closure, decode, per-operation masks, reset declaration,
explicit side effects, observation capabilities and issuer contract.  Missing
semantics is never treated as storage.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from ..contracts import (
    GenericRuntimeRefused,
    canonical_json_bytes,
    parse_closed_json,
    require_digest,
    require_identifier,
    strict_json_loads,
)

SCHEMA = "semantic_contract.v1"
STORAGE_RW = "storage.rw.v1"

SEMANTIC_KINDS = frozenset({
    "storage.rw.v1",
    "storage.w1c.v1",
    "storage.w1s.v1",
    "fifo.push.v1",
    "fifo.pop.v1",
    "command.start.v1",
})

SIDE_EFFECT_KINDS = frozenset({
    "stable_storage",
    "read_only",
    "w1c",
    "w1s",
    "fifo_push",
    "fifo_pop",
    "command_start",
    "irq_source",
})

OBSERVATION_LAYERS = (
    "physical_protocol_sample",
    "component_semantic_effect",
    "cross_component_source",
    "cross_component_consumption",
)

REQUIRED_KIND_EFFECTS = {
    "storage.rw.v1": frozenset({"stable_storage"}),
    "storage.w1c.v1": frozenset({"w1c"}),
    "storage.w1s.v1": frozenset({"w1s"}),
    "fifo.push.v1": frozenset({"fifo_push"}),
    "fifo.pop.v1": frozenset({"fifo_pop"}),
    "command.start.v1": frozenset({"command_start"}),
}

_TOP_LEVEL = ("schema_version", "kind", "source", "endpoint", "decode",
              "operations", "reset", "side_effects", "observations",
              "issuer_contract")


def _refuse(code: str, pointer: str = "", detail=None) -> None:
    raise GenericRuntimeRefused(code, pointer, detail)


def _positive_int(value, pointer: str, *, maximum: int):
    if type(value) is not int or not 1 <= value <= maximum:
        _refuse("generic-contract-type", pointer,
                {"expected": "positive int", "maximum": maximum})
    return value


def _mask(value, pointer: str, *, width_bits: int):
    if type(value) is not int or not 0 <= value < (1 << width_bits):
        _refuse("generic-contract-type", pointer,
                {"expected": "int mask within width", "width_bits": width_bits})
    return value


def _source(document, pointer: str) -> dict:
    rows = parse_closed_json(document,
                             ("contract_id", "root", "revision", "top_module",
                              "files", "verifier", "identity_basis"),
                             pointer=pointer)
    require_identifier(rows["contract_id"], pointer + "/contract_id")
    for name in ("root", "revision", "top_module", "identity_basis"):
        if type(rows[name]) is not str or not rows[name]:
            _refuse("generic-contract-type", pointer + "/" + name,
                    {"expected": "nonempty string"})
    if type(rows["files"]) is not dict or not rows["files"]:
        _refuse("generic-contract-shape", pointer + "/files",
                {"expected": "nonempty name -> sha256 map"})
    for name, digest in rows["files"].items():
        if type(name) is not str or not name or name.startswith("/"):
            _refuse("generic-contract-type", pointer + "/files",
                    {"expected": "relative source file names"})
        require_digest(digest, pointer + "/files/" + name)
    verifier = parse_closed_json(rows["verifier"],
                                 ("id", "version", "implementation_sha256"),
                                 pointer=pointer + "/verifier")
    require_identifier(verifier["id"], pointer + "/verifier/id")
    require_identifier(verifier["version"], pointer + "/verifier/version")
    require_digest(verifier["implementation_sha256"],
                   pointer + "/verifier/implementation_sha256")
    return rows


def _endpoint(document, pointer: str, *, kind: str) -> dict:
    rows = parse_closed_json(document,
                             ("endpoint_id", "role", "protocol", "template",
                              "semantic_kind"),
                             pointer=pointer)
    require_identifier(rows["endpoint_id"], pointer + "/endpoint_id")
    for name in ("role", "semantic_kind"):
        require_identifier(rows[name], pointer + "/" + name)
    if rows["semantic_kind"] != kind:
        _refuse("generic-contract-mismatch", pointer + "/semantic_kind",
                {"expected": kind})
    for name, length in (("protocol", 2), ("template", 3)):
        value = rows[name]
        if type(value) is not list or len(value) != length or any(
                type(item) is not str or not item for item in value):
            _refuse("generic-contract-shape", pointer + "/" + name,
                    {"expected_length": length})
    return rows


def _decode(document, pointer: str) -> dict:
    rows = parse_closed_json(document,
                             ("address_width", "address_units",
                              "alignment_bytes", "mask", "value",
                              "alias_period_bytes", "expression"),
                             pointer=pointer)
    _positive_int(rows["address_width"], pointer + "/address_width",
                  maximum=64)
    if rows["address_units"] not in ("byte", "word"):
        _refuse("generic-contract-type", pointer + "/address_units",
                {"allowed": ["byte", "word"]})
    _positive_int(rows["alignment_bytes"], pointer + "/alignment_bytes",
                  maximum=4096)
    _mask(rows["mask"], pointer + "/mask",
          width_bits=rows["address_width"])
    _mask(rows["value"], pointer + "/value",
          width_bits=rows["address_width"])
    if rows["mask"] & rows["value"] != rows["value"]:
        _refuse("generic-contract-shape", pointer + "/value",
                {"expected": "value subset of mask"})
    _positive_int(rows["alias_period_bytes"], pointer + "/alias_period_bytes",
                  maximum=1 << 32)
    if type(rows["expression"]) is not str or not rows["expression"]:
        _refuse("generic-contract-type", pointer + "/expression")
    return rows


def _operations(document, pointer: str) -> list:
    rows = document
    if type(rows) is not list or not rows:
        _refuse("generic-contract-shape", pointer,
                {"expected": "nonempty operations list"})
    seen = []
    for index, operation in enumerate(rows):
        item_pointer = f"{pointer}/{index}"
        item = parse_closed_json(operation,
                                 ("operation", "width_bits", "read_mask",
                                  "write_mask", "byte_enable", "value_origin"),
                                 pointer=item_pointer)
        if item["operation"] not in ("read", "write"):
            _refuse("generic-contract-type", item_pointer + "/operation",
                    {"allowed": ["read", "write"]})
        _positive_int(item["width_bits"], item_pointer + "/width_bits",
                      maximum=4096)
        _mask(item["read_mask"], item_pointer + "/read_mask",
              width_bits=item["width_bits"])
        _mask(item["write_mask"], item_pointer + "/write_mask",
              width_bits=item["width_bits"])
        if type(item["byte_enable"]) is not bool:
            _refuse("generic-contract-type", item_pointer + "/byte_enable",
                    {"expected": "bool"})
        require_identifier(item["value_origin"], item_pointer + "/value_origin")
        if item["operation"] == "read" and item["write_mask"] != 0:
            _refuse("generic-contract-shape", item_pointer + "/write_mask",
                    {"expected": 0, "operation": "read"})
        if item["operation"] == "write" and item["write_mask"] == 0:
            _refuse("generic-contract-shape", item_pointer + "/write_mask",
                    {"expected": "nonzero writable lanes"})
        if item["operation"] in seen:
            _refuse("generic-contract-duplicate", item_pointer + "/operation")
        seen.append(item["operation"])
    return rows


def _reset(document, pointer: str) -> dict:
    rows = parse_closed_json(document,
                             ("declared", "port", "polarity", "observed",
                              "evidence_ref", "case_begin_is_reset"),
                             pointer=pointer)
    if type(rows["declared"]) is not bool or type(rows["observed"]) is not bool:
        _refuse("generic-contract-type", pointer,
                {"expected": "bool declared/observed"})
    if type(rows["case_begin_is_reset"]) is not bool or rows["case_begin_is_reset"]:
        _refuse("generic-contract-shape", pointer + "/case_begin_is_reset",
                {"expected": False,
                 "reason": "a case begin is not a source reset"})
    for name in ("port", "polarity"):
        if type(rows[name]) is not str or not rows[name]:
            _refuse("generic-contract-type", pointer + "/" + name)
    reference = rows["evidence_ref"]
    if reference is not None and (type(reference) is not str or not reference):
        _refuse("generic-contract-type", pointer + "/evidence_ref")
    if rows["observed"] and reference is None:
        _refuse("generic-contract-shape", pointer + "/observed",
                {"expected": False, "reason": "observed reset needs an actual reference"})
    return rows


def _side_effects(document, pointer: str) -> list:
    if type(document) is not list or not document:
        _refuse("generic-contract-shape", pointer,
                {"expected": "nonempty explicit side effects"})
    seen = []
    for index, row in enumerate(document):
        item_pointer = f"{pointer}/{index}"
        item = parse_closed_json(row, ("kind", "scope"), pointer=item_pointer)
        if item["kind"] not in SIDE_EFFECT_KINDS:
            _refuse("generic-semantic-unsupported", item_pointer + "/kind",
                    {"allowed": sorted(SIDE_EFFECT_KINDS)})
        if type(item["scope"]) is not str or not item["scope"]:
            _refuse("generic-contract-type", item_pointer + "/scope")
        if item["kind"] in seen:
            _refuse("generic-contract-duplicate", item_pointer + "/kind")
        seen.append(item["kind"])
    return document


def _observations(document, pointer: str) -> list:
    if type(document) is not list or not document:
        _refuse("generic-contract-shape", pointer,
                {"expected": "nonempty observation capabilities"})
    names = []
    for index, row in enumerate(document):
        item_pointer = f"{pointer}/{index}"
        item = parse_closed_json(row, ("name", "layer", "native", "reference"),
                                 pointer=item_pointer)
        require_identifier(item["name"], item_pointer + "/name")
        if item["layer"] not in OBSERVATION_LAYERS:
            _refuse("generic-contract-type", item_pointer + "/layer",
                    {"allowed": list(OBSERVATION_LAYERS)})
        if type(item["native"]) is not bool:
            _refuse("generic-contract-type", item_pointer + "/native",
                    {"expected": "bool"})
        if type(item["reference"]) is not str or not item["reference"]:
            _refuse("generic-contract-type", item_pointer + "/reference")
        if item["name"] in names:
            _refuse("generic-contract-duplicate", item_pointer + "/name")
        names.append(item["name"])
    return document


def _issuer_contract(document, pointer: str) -> dict:
    rows = parse_closed_json(document,
                             ("issuer_id", "version", "implementation_sha256",
                              "token_scope", "single_use", "authority"),
                             pointer=pointer)
    require_identifier(rows["issuer_id"], pointer + "/issuer_id")
    require_identifier(rows["version"], pointer + "/version")
    require_digest(rows["implementation_sha256"],
                   pointer + "/implementation_sha256")
    if type(rows["token_scope"]) is not str or not rows["token_scope"]:
        _refuse("generic-contract-type", pointer + "/token_scope")
    if type(rows["single_use"]) is not bool:
        _refuse("generic-contract-type", pointer + "/single_use")
    if rows["authority"] is not False:
        _refuse("generic-contract-shape", pointer + "/authority",
                {"expected": False,
                 "reason": "a static contract never carries runtime authority"})
    return rows


def validate_semantic_document(document, *, pointer: str = "/semantic") -> dict:
    rows = parse_closed_json(document, _TOP_LEVEL, pointer=pointer)
    if rows["schema_version"] != SCHEMA:
        _refuse("generic-contract-shape", pointer + "/schema_version",
                {"expected": SCHEMA})
    kind = rows["kind"]
    if kind not in SEMANTIC_KINDS:
        _refuse("generic-semantic-unsupported", pointer + "/kind",
                {"allowed": sorted(SEMANTIC_KINDS)})
    _source(rows["source"], pointer + "/source")
    _endpoint(rows["endpoint"], pointer + "/endpoint", kind=kind)
    _decode(rows["decode"], pointer + "/decode")
    _operations(rows["operations"], pointer + "/operations")
    _reset(rows["reset"], pointer + "/reset")
    effects = _side_effects(rows["side_effects"], pointer + "/side_effects")
    _observations(rows["observations"], pointer + "/observations")
    _issuer_contract(rows["issuer_contract"], pointer + "/issuer_contract")
    kinds = {row["kind"] for row in effects}
    required = REQUIRED_KIND_EFFECTS[kind]
    if not required <= kinds:
        _refuse("generic-semantic-unsupported", pointer + "/side_effects",
                {"kind": kind, "required": sorted(required),
                 "declared": sorted(kinds)})
    conflicting = kinds & (SIDE_EFFECT_KINDS - required - {"read_only", "irq_source"})
    if conflicting:
        _refuse("generic-semantic-unsupported", pointer + "/side_effects",
                {"kind": kind, "conflicting": sorted(conflicting),
                 "reason": "one contract describes one effect family"})
    operations = {row["operation"] for row in rows["operations"]}
    if kind == STORAGE_RW and operations != {"read", "write"}:
        _refuse("generic-semantic-unsupported", pointer + "/operations",
                {"required": ["read", "write"], "declared": sorted(operations)})
    return rows


@dataclass(frozen=True, slots=True)
class SemanticContract:
    """Canonical, detached semantic facts; never a live or native grant."""

    kind: str
    document_bytes: bytes
    sha256_hex: str

    def __post_init__(self) -> None:
        if type(self) is not SemanticContract:
            _refuse("generic-contract-type", "/semantic")
        if type(self.document_bytes) not in (bytes, bytearray):
            _refuse("generic-contract-type", "/document_bytes")
        object.__setattr__(self, "document_bytes", bytes(self.document_bytes))
        document = strict_json_loads(self.document_bytes, pointer="/semantic")
        validate_semantic_document(document)
        if canonical_json_bytes(document) != self.document_bytes:
            _refuse("generic-contract-shape", "/semantic",
                    {"expected": "canonical JSON bytes"})
        if sha256(self.document_bytes).hexdigest() != self.sha256_hex:
            _refuse("generic-contract-mismatch", "/sha256",
                    {"expected": "sha256(document_bytes)"})
        if document["kind"] != self.kind:
            _refuse("generic-contract-mismatch", "/kind")

    @classmethod
    def freeze(cls, document: dict) -> "SemanticContract":
        if type(document) is not dict:
            _refuse("generic-contract-type", "/semantic",
                    {"expected": "JSON object"})
        validate_semantic_document(document)
        frozen = canonical_json_bytes(document)
        return cls(document["kind"], frozen, sha256(frozen).hexdigest())

    def document(self) -> dict:
        return strict_json_loads(self.document_bytes, pointer="/semantic")

    def side_effect_kinds(self) -> tuple[str, ...]:
        return tuple(row["kind"] for row in self.document()["side_effects"])

    def operations(self) -> tuple[str, ...]:
        return tuple(row["operation"] for row in self.document()["operations"])

    def observation_names(self) -> tuple[str, ...]:
        return tuple(row["name"] for row in self.document()["observations"])
