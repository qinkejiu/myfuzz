"""Shared runner and artifact format for the input-dependency-repair tests.

A *case* is one declarative record: the candidate program it declares, the raw
words (or directed words and seeds) it applies, and the name of the capability
it exercises.  Running a case is deterministic -- the same record produces the
same program document, the same repaired request, the same frozen image and the
same refusal -- which is what makes the recorded artifact under
``runs/soc-input-repair/<name>/`` replayable by
``test_soc_input_repair_replay.py``.

Address tokens keep a case readable without hiding the numbers: ``@slot:<prefix>``
is that slot's declared address, ``@ram`` the declared writable region base,
``@mmio`` the lowest declared MMIO window base, ``@entry`` the declared reset
vector, ``@window`` the declared program base and ``@window+0xNN`` an offset
from it.  The resolved record is stored in the artifact, so a replay compares
concrete addresses, never tokens.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

from myfuzz.composition.soc_candidate_program import (
    CandidateProgram,
    CandidateProgramError,
    CandidateProgramPolicy,
    build_candidate_program,
)

from .soc_generation_fixture import ROOT, example_plan

ARTIFACT_ROOT = ROOT / "runs/soc-input-repair"
CASE_SCHEMA = "soc_input_repair_case.v1"

#: One ROM size override lets a case declare a region too small for its program
#: without editing the example profile.
DEFAULT_ROM_SIZE = 0x8000


def case_plan(spec: dict):
    """The example plan with the case's declared overrides applied."""
    plan = example_plan()
    extensions = spec.get("contract_extensions")
    rom_size = spec.get("rom_size")
    if extensions is None and rom_size is None:
        return plan
    if extensions is not None:
        cpu = next(item for item in plan.instances if item.kind == "cpu")
        contract = cpu.profile.cpu
        broken = replace(cpu, profile=replace(cpu.profile, cpu=replace(
            contract, extensions=tuple(extensions))))
        plan = replace(plan, instances=tuple(
            broken if item.instance_id == cpu.instance_id else item
            for item in plan.instances))
    if rom_size is not None:
        regions = [{**region, "size": int(rom_size)}
                   if region["region_id"] == "rom0" else dict(region)
                   for region in plan.plan["address_map"]["memory_regions"]]
        plan = replace(plan, plan={**plan.plan, "address_map": {
            **plan.plan["address_map"], "memory_regions": regions}})
    return plan


def program_for(spec: dict) -> CandidateProgram:
    policy = CandidateProgramPolicy(**dict(spec.get("policy") or {}))
    return build_candidate_program(
        case_plan(spec),
        instruction_candidates=int(spec.get("instruction_candidates", 1)),
        data_candidates=int(spec.get("data_candidates", 1)),
        policy=policy,
        isa_repair=bool(spec.get("isa_repair", True)))


def resolve_address(program: CandidateProgram, token: object) -> int:
    """Resolve one case address token against the program's declared facts."""
    if isinstance(token, int) and not isinstance(token, bool):
        return token
    if not isinstance(token, str) or not token.startswith("@"):
        raise ValueError(f"invalid case address: {token!r}")
    if token.startswith("@slot:"):
        return program.slots.slot(token[len("@slot:"):]).declared_address
    if token == "@ram":
        return int(program.register_bindings["data_base"]["value"])
    if token == "@mmio":
        return int(program.register_bindings["mmio_base"]["value"])
    if token == "@entry":
        return program.entry_address
    if token.startswith("@window+"):
        return program.program_base + int(token[len("@window+"):], 0)
    if token == "@window":
        return program.program_base
    raise ValueError(f"unknown case address token: {token}")


def build_request(program: CandidateProgram, entries: list[dict]) -> list[int]:
    """Encode a case's raw words from named (slot, address, word) records."""
    words: list[int] = []
    for entry in entries:
        slot = program.slots.slot(str(entry["slot"]))
        value = 1 << slot.segment("offer").raw_lo
        if "address" in entry:
            value |= (resolve_address(program, entry["address"]) & 0xFFFFFFFF) \
                << slot.segment("address").raw_lo
        role = "data" if slot.kind == "instruction" else "value"
        if "word" in entry:
            value |= (int(entry["word"]) & 0xFFFFFFFF) << slot.segment(role).raw_lo
        value |= (int(entry.get("be", 0xF)) & 0xF) << slot.segment("be").raw_lo
        words.append(value)
    return words


def resolved_spec(program: CandidateProgram, spec: dict) -> dict:
    """The case with every address token replaced by its declared number."""
    document = json.loads(json.dumps(spec))
    for entry in document.get("request", ()):
        if "address" in entry:
            entry["address"] = resolve_address(program, entry["address"])
    for name, binding in program.register_bindings.items():
        document.setdefault("resolved_bindings", {})[name] = int(binding["value"])
    document["resolved_slots"] = {
        slot.prefix: slot.declared_address for slot in program.slots.slots()}
    return document


def run_case(spec: dict) -> dict:
    """Run one declarative case and return its complete, canonical record."""
    record: dict[str, object] = {"name": str(spec["name"]), "item": str(spec["item"])}
    try:
        program = program_for(spec)
    except CandidateProgramError as error:
        record["spec"] = json.loads(json.dumps(spec))
        record["error"] = str(error)
        return record
    record["spec"] = resolved_spec(program, spec)
    document = program.document()
    if spec.get("compact"):
        # A case with thousands of declared slots records the identity of its
        # program document instead of the whole text; a replay recomputes the
        # same digest.
        record["program"] = {
            "compact": True,
            "slots": len(program.slots.slots()),
            "sha256": "sha256:" + hashlib.sha256(
                json.dumps(document, sort_keys=True).encode("utf-8")).hexdigest(),
        }
    else:
        record["program"] = document
    request = build_request(program, list(spec.get("request", ())))
    directed = {str(name): int(value) for name, value in
                (spec.get("directed") or {}).items()}
    seeds = {int(item["address"]): bytes.fromhex(str(item["bytes"]))
             for item in spec.get("seeds", ())}
    try:
        test = program.repairer().repair_test(request, directed=directed, seeds=seeds)
    except CandidateProgramError as error:
        record["error"] = str(error)
        return record
    record["test"] = test.document()
    record["request"] = list(test.request)
    record["image_hash"] = test.image.content_hash
    record["region_hashes"] = {
        name: "sha256:" + hashlib.sha256(payload).hexdigest()
        for name, payload in sorted(test.image.region_images.items())}
    record["boot_hex"] = "".join(f"{byte:02x}\n" for byte in test.image.image)
    return record


def record_case(spec: dict, *, root: Path = ARTIFACT_ROOT) -> Path:
    """Run one case and record it (plus the frozen image) under ``runs/``."""
    directory = root / str(spec["name"])
    directory.mkdir(parents=True, exist_ok=True)
    document = {"schema_version": CASE_SCHEMA, **run_case(spec)}
    (directory / "case.json").write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if "boot_hex" in document:
        (directory / "boot.hex").write_text(str(document["boot_hex"]), encoding="utf-8")
    return directory


def read_case(name: str, *, root: Path = ARTIFACT_ROOT) -> dict:
    return json.loads((root / name / "case.json").read_text(encoding="utf-8"))


__all__ = ["ARTIFACT_ROOT", "CASE_SCHEMA", "build_request", "case_plan",
           "program_for", "read_case", "record_case", "resolve_address",
           "resolved_spec", "run_case"]
