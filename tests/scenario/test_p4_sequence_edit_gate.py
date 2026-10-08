"""P4 online sequence-edit real gate: raw selection, joins and fail-closed paths.

These tests are written before ``scripts/run_p4_sequence_edit_gate.py`` exists.
They fix four things:

* the three declared eight-byte raws select the shipped operator's insert,
  delete and untouched two-word branches under the *real* decoder used by the
  Ibex online entry point (and under its runtime declaration), deterministically;
* the same raws lie in the byte image of the shipped Rust client's
  ``ScenarioDecisionMutator`` for the instruction source, so the deterministic
  seed mechanism and the client's own mutation layout agree;
* the verify mode's joins on the run's own artifacts (receipt -> plan
  admission -> trace fetch/retirement) accept real-shaped evidence and reject
  contradictions;
* every fail-closed path (BLOCKED / INCONCLUSIVE / FAIL) has its own precise
  reason, and both modes are deterministic.

No RTL is started here: the fixtures are real-shaped artifacts and the only
shipped code exercised is the decoder, the operator and the admission digest.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "run_p4_sequence_edit_gate.py"

sys.path.insert(0, (ROOT / "src").as_posix())

from myfuzz.scenario.ibex_pulp_dual_source import (  # noqa: E402
    make_ibex_pulp_dual_source_online_decoder,
    make_ibex_pulp_dual_source_stream_bootstrap,
)
from myfuzz.scenario.rv32i_sources import (  # noqa: E402
    instruction_operator_id, validate_instruction_bytes,
)
from myfuzz.scenario.session_runtime import OnlineInstruction  # noqa: E402
from myfuzz.scenario.source_provenance import SourceAdmission  # noqa: E402

_MODULE = None


def load_script():
    """Import the gate script under test (once per process)."""
    global _MODULE
    if _MODULE is not None:
        return _MODULE
    if not SCRIPT.is_file():
        raise AssertionError(f"the sequence-edit gate is not implemented: {SCRIPT}")
    spec = importlib.util.spec_from_file_location(
        "run_p4_sequence_edit_gate", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    _MODULE = module
    return module


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def runtime_decoder():
    """The declaration the shipped Ibex online entry point builds."""
    return make_ibex_pulp_dual_source_online_decoder(
        bootstrap=make_ibex_pulp_dual_source_stream_bootstrap(),
        result_slot_readback=True)


def entropy_of(raw: bytes) -> bytes:
    """The documented online entropy layout (raw[3:] repeated to twelve)."""
    payload = raw[3:]
    return (payload * ((12 + len(payload) - 1) // len(payload)))[:12]


# --------------------------------------------------------------------------
# raw selection: the shipped operator, the real decoder and the client layout
# --------------------------------------------------------------------------

def test_declared_raws_decode_to_the_shipped_operator_fragments():
    gate = load_script()
    assert set(gate.DECLARED_RAWS) == {"insert", "delete", "base"}
    assert set(gate.ARM_OPERATORS) == {"insert", "delete", "base"}
    for arm, raw_hex in gate.DECLARED_RAWS.items():
        raw = bytes.fromhex(raw_hex)
        assert len(raw) == 8
        case = gate.declared_case(arm)
        fragment = case.source.data
        assert fragment.hex() == gate.DECLARED_FRAGMENTS[arm]
        assert instruction_operator_id(fragment) == gate.ARM_OPERATORS[arm]
        assert len(fragment) == gate.ARM_LENGTHS[arm]
        # The operator's own rule: byte six of the entropy, high two bits.
        entropy = entropy_of(raw)
        edit = entropy[6] & 0xC0
        assert edit == gate.ARM_EDIT_BYTES[arm]
        assert entropy[0] % 5 == 2          # the arithmetic (sequence-edit) choice
        assert 1 + entropy[1] % 31 == 7     # a temporary register, not x1/x2
        validate_instruction_bytes(fragment)


def cpu_case_for_raw(raw: bytes):
    """Decode one raw with the real decoder, scanning the path byte if needed.

    Byte one is the client's path byte and is fixed by the hint in a live run;
    the raw's own hash draw decides the path.  Scanning it here keeps this test
    about the operator's fragment and not about the draw.
    """
    decoder = load_script().shipped_decoder()
    errors = []
    for selector in range(256):
        candidate = bytes((raw[0], selector, raw[2])) + raw[3:]
        try:
            case = decoder.decode(candidate)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if isinstance(case.source, OnlineInstruction):
            return case
    raise AssertionError(f"no online instruction source: {raw.hex()} {errors[:3]}")


def test_insert_and_delete_edit_one_two_word_base_between_its_words():
    """The same operands with only byte four's edit bits changed.

    ``0x44`` keeps the two-word base, ``0x82`` deletes the optional ``ADDI`` and
    ``0xC0`` inserts the ``XORI``; all three decode to register x7 (the same
    ``1 + entropy[1] % 31``), so the words are directly comparable.
    """
    gate = load_script()
    declared = bytes.fromhex(gate.DECLARED_RAWS["insert"])
    operands = (0x07, None, 0x02, 0x00, 0xFC)   # r3, r4, r5, r6, r7
    variants = {"base": 0x44, "delete": 0x82, "insert": 0xC0}
    words = {}
    for arm, edit in variants.items():
        raw = bytes((0, 0, 0, operands[0], edit, operands[2], operands[3],
                     operands[4]))
        case = cpu_case_for_raw(raw)
        fragment = case.source.data
        assert instruction_operator_id(fragment) == gate.ARM_OPERATORS[arm]
        assert len(fragment) == gate.ARM_LENGTHS[arm]
        assert 1 + gate._entropy_of(raw)[1] % 31 == 7
        words[arm] = [fragment[i:i + 4] for i in range(0, len(fragment), 4)]
    assert words["insert"][0] == words["base"][0]
    assert words["insert"][2] == words["base"][1]
    assert words["delete"] == words["base"][:1]
    assert len(set(word.hex() for word in words["insert"])) == 3
    assert words["insert"][1] != words["base"][0]
    # The deletion removes exactly the optional ADDI word of the base pair.
    assert words["base"][1] not in words["delete"]


def test_edit_byte_alone_selects_between_delete_base_and_insert():
    """Byte four's high two bits are the whole branch selector for choice 2."""
    gate = load_script()
    lengths = {0x00: 4, 0x40: 8, 0x80: 4, 0xC0: 12}
    for arm, raw_hex in gate.DECLARED_RAWS.items():
        raw = bytearray(bytes.fromhex(raw_hex))
        assert entropy_of(bytes(raw))[6] & 0xC0 == gate.ARM_EDIT_BYTES[arm]
        for edit, expected in lengths.items():
            mutated = bytearray(raw)
            mutated[4] = (mutated[4] & 0x3F) | edit
            case = cpu_case_for_raw(bytes(mutated))
            assert len(case.source.data) == expected, (arm, hex(edit))
        # The declared fragment is the one its own edit byte selects.
        declared = gate.declared_case(arm)
        assert len(declared.source.data) == lengths[gate.ARM_EDIT_BYTES[arm]]


def test_declared_raws_are_in_the_shipped_client_mutator_byte_image():
    """``mutation/scenario.rs::apply`` writes exactly these five payload bytes."""
    gate = load_script()
    for arm, raw_hex in gate.DECLARED_RAWS.items():
        raw = bytes.fromhex(raw_hex)
        assert gate.client_mutator_image(raw) is True, arm
        # For one eight-byte record the client writes template/path/source as
        # bytes zero..two and derives four..seven from one decision word.
        assert raw[0] == 0 and raw[1] == 0 and raw[2] == 0


def test_declared_raws_draw_the_instruction_path_with_margin():
    gate = load_script()
    for arm, raw_hex in gate.DECLARED_RAWS.items():
        draw = gate.path_draw(bytes.fromhex(raw_hex))
        # Two declared paths with equal weights: the instruction path owns the
        # lower half of the draw range, and the margin keeps the seed selected
        # even if the first case's symmetric weights move.
        assert draw["selector"] < draw["instruction_weight"]
        assert draw["margin"] >= 40, arm


def test_declared_decoding_is_deterministic_across_decoders_and_declarations():
    gate = load_script()
    first = {arm: (gate.declared_case(arm).source.data_hex,
                   gate.declared_case(arm).case_id,
                   gate.declared_case(arm).source.action_id)
             for arm in gate.DECLARED_RAWS}
    second = {arm: (gate.declared_case(arm).source.data_hex,
                    gate.declared_case(arm).case_id,
                    gate.declared_case(arm).source.action_id)
              for arm in gate.DECLARED_RAWS}
    assert first == second
    for arm, raw_hex in gate.DECLARED_RAWS.items():
        case = gate.declared_case(arm, readback=True)
        assert case.source.data_hex == gate.DECLARED_FRAGMENTS[arm]
        assert gate.declared_case(arm).path_id == case.path_id
    report = gate.declared_raw_report()
    assert canonical(report) == canonical(gate.declared_raw_report())
    assert report["executes_rtl"] is False


def test_seed_mechanism_is_the_shipped_entry_point_not_an_invention():
    gate = load_script()
    evidence = gate.seed_mechanism_evidence()
    assert evidence["verified"] is True
    assert evidence["executes_rtl"] is False
    kinds = {check["id"] for check in evidence["checks"]}
    assert {"cli_flag", "runner_seed_records", "seed_bin", "client_command",
            "client_identity_mutator"} <= kinds
    for check in evidence["checks"]:
        assert check["proven"] is True, check
        assert check["path"] and len(check["sha256"]) == 64
    assert evidence["seed_record_bytes"] == 8


def test_seed_mechanism_check_refuses_a_tampered_tree(tmp_path):
    """The source read-back is a real check, not a fixed verdict."""
    gate = load_script()
    fake = tmp_path / "run_ibex_pulp_online.py"
    fake.write_text("# no --initial-ram-record here\n", encoding="utf-8")
    evidence = gate.seed_mechanism_evidence(cli_path=fake)
    assert evidence["verified"] is False
    assert any(not check["proven"] for check in evidence["checks"])


# --------------------------------------------------------------------------
# synthetic-but-real-shaped run artifacts
# --------------------------------------------------------------------------

PIN8_SOURCE = {
    "action_id": "online-0-pin8:cpu.online_instruction",
    "component": "gpio_b", "port": "gpio_in", "value": 1,
    "bit_offset": 8, "width": 1, "kind": "source_event",
}


def _events_for_case(case, admission, *, fetch="memory_read",
                     fetch_bytes=None, retirement=True, retirement_insn=None,
                     include_source=True):
    """Real-shaped trace events for one admitted instruction case."""
    action_id = case.source.action_id
    admission_id = admission["admission_id"]
    fragment = bytes.fromhex(case.source.data_hex)
    address = case.source.address
    case_ref = {"case_id": case.case_id, "case_index": admission["case_index"]}
    provenance = {"schema_version": "event_source_provenance.v1",
                  "origin_status": "known",
                  "origin_admission_ids": [admission_id],
                  "observed_case": case_ref,
                  "edge_candidates": [], "invalid_origin_references": 0,
                  "proof_scope": "source_action", "resource": None,
                  "unknown_writer_ids": []}
    events = []
    if include_source:
        events.append({"kind": "source_admission", "event_id": 2,
                       "admission": admission,
                       "provenance": {**provenance, "proof_scope":
                                      "authorized_attempt"}})
        events.append({"kind": "instruction_source", "event_id": 3,
                       "component": "cpu", "address": address,
                       "data_hex": fragment.hex(), "generation": 0,
                       "producer_event_id": 2, "source_event_id": action_id,
                       "provenance": {**provenance,
                                      "resource": {"address": address,
                                                   "generation": 0}}})
    for index in range(len(fragment) // 4):
        word = fragment[index * 4:(index + 1) * 4]
        want = word if fetch_bytes is None else bytes.fromhex(fetch_bytes[index])
        offset = address + 4 * index
        if fetch == "memory_read":
            events.append({
                "kind": "memory_read", "event_id": 10 + index, "component": "cpu",
                "address": offset, "byte_offset": offset, "memory_id": "ram",
                "generation": 0, "data_hex": want.hex(),
                "value": int.from_bytes(want, "little"), "width_bytes": 4,
                "versions": [[0, 1]] * 4,
                "writer_event_ids": [action_id] * 4,
                "writer_kinds": ["INSTRUCTION_SOURCE"] * 4,
                "transaction": {"channel_id": "instr",
                                "execution_id": "local-execution",
                                "source_component": "cpu", "source_epoch": 0,
                                "source_sequence": 100 + index,
                                "testcase_id": "ibex-dual-source-stream"},
                "producer_event_id": 9 + index,
                "provenance": {**provenance, "proof_scope":
                               "memory_writer_snapshot",
                               "resource": {"address": offset,
                                            "byte_offset": offset,
                                            "memory_id": "ram", "generation": 0,
                                            "versions": [[0, 1]] * 4,
                                            "writer_event_ids": [action_id] * 4,
                                            "writer_kinds":
                                                ["INSTRUCTION_SOURCE"] * 4,
                                            "width_bytes": 4}}})
        elif fetch == "instr_response":
            events.append({
                "kind": "instr_response", "event_id": 10 + index,
                "component": "cpu", "address": offset, "rdata":
                    int.from_bytes(want, "little"), "error": 0, "status":
                    "accepted", "write": 0,
                "transaction": {"channel_id": "instr",
                                "execution_id": "local-execution",
                                "source_component": "cpu", "source_epoch": 0,
                                "source_sequence": 100 + index,
                                "testcase_id": "ibex-dual-source-stream"},
                "snapshot": {"value": int.from_bytes(want, "little"),
                             "data_hex": want.hex(), "address": offset,
                             "writer_event_ids": [action_id] * 4,
                             "writer_kinds": ["INSTRUCTION_SOURCE"] * 4,
                             "versions": [[0, 1]] * 4},
                "provenance": {**provenance,
                               "proof_scope": "instruction_fetch_response"}})
        if retirement:
            insn = int.from_bytes(word, "little")
            if retirement_insn is not None and index in retirement_insn:
                insn = retirement_insn[index]
            events.append({
                "kind": "cpu_retirement_match", "event_id": 30 + index,
                "schema_version": "cpu_retirement_match.v1",
                "status": "accepted", "reason": "matched_instruction",
                "proof_scope": "retired_instruction_origin",
                "cpu_scope": {"execution_id": "local-execution",
                              "source_component": "cpu", "source_epoch": 0},
                "order": index, "pc": offset, "insn": insn,
                "source_refs": [action_id],
                "instruction_origin_status": "typed_writer_refs",
                "instruction_responses": [{"event_id": 10 + index,
                                           "address": offset,
                                           "rdata": int.from_bytes(word,
                                                                   "little")}],
                "byte_cells": [{"writer_event_ids": [action_id] * 4,
                                "writer_kinds": ["INSTRUCTION_SOURCE"] * 4,
                                "versions": [[0, 1]] * 4}],
                "transaction_keys": [],
                "provenance": {**provenance, "proof_scope":
                               "retired_instruction_origin"}})
    return events


def make_run(tmp_path: Path, *, arm: str = "insert", name: str | None = None,
             seed: bytes | None = None, omit: tuple[str, ...] = (),
             fetch: str | None = "memory_read", fetch_bytes=None,
             retirement: bool = True, retirement_insn=None,
             disposition: str = "admitted", replay: bool | None = True,
             disposition_reason: str = "rtl_case_committed",
             boundary: str = "ok", manifest: str = "runtime",
             trace_format: str = "json", pin8_only: bool = False,
             status: str = "complete", recorded_data_hex: str | None = None):
    """Build one real-shaped run directory plus its fresh-replay log."""
    gate = load_script()
    run = tmp_path / (name or f"p4-sequence-edit-{arm}-20261008-online")
    run.mkdir(parents=True, exist_ok=True)
    for stale in run.iterdir():
        if stale.is_file():
            stale.unlink()
    started = gate.declared_case(arm)
    address = started.source.address
    case = started
    raw = bytes.fromhex(gate.DECLARED_RAWS[arm])
    if pin8_only:
        raw = bytes.fromhex(gate.DECLARED_RAWS["base"])
    fragment = bytes.fromhex(case.source.data_hex)
    if boundary == "beyond_end":
        address = 0x2FE00 - 4          # a twelve-byte fragment cannot fit
        case = gate.declared_case(arm, address=address)
        fragment = bytes.fromhex(case.source.data_hex)
    admission_document = SourceAdmission.create(
        case_id=case.case_id, case_index=0, source_id="cpu.online_instruction",
        path_id=case.path_id, direction=case.direction, component="cpu",
        action_id=case.source.action_id, role="fuzz_source",
        input_kind="instruction",
        input_sha256=gate.input_sha256(case.source)).document()
    plan_cases = [{
        "case_id": case.case_id, "direction": case.direction,
        "path_id": case.path_id, "source_role": "fuzz_source",
        "advances": [["cpu", "gpio_a", "gpio_b"]],
        "support_instructions": [],
        "source": {"action_id": case.source.action_id, "component": "cpu",
                   "address": case.source.address,
                   "data_hex": case.source.data_hex, "kind": "instruction"},
    }]
    if pin8_only:
        plan_cases = [{
            "case_id": "online-0-pin8", "direction": "IP_TO_CPU_TO_IP",
            "path_id": "ip-path", "source_role": "fuzz_source",
            "advances": [["cpu", "gpio_a", "gpio_b"]],
            "support_instructions": [],
            "source": {**PIN8_SOURCE},
        }]
    if boundary == "cursor_overrun":
        # The plan claims the fragment starts inside the reservation while the
        # previous admitted bytes already consumed it.
        plan_cases = [{
            **plan_cases[0],
            "support_instructions": [
                {"action_id": f"{case.case_id}:fixed-support",
                 "component": "cpu", "address": 0x11000,
                 "data_hex": "13000000" * 31617, "kind": "instruction"}],
        }]
    if boundary == "gap":
        plan_cases[0] = {**plan_cases[0],
                         "source": {**plan_cases[0]["source"],
                                    "address": address + 4}}
        case = gate.declared_case(arm, address=address + 4)
    plan = {
        "instruction_slots": [["cpu", 0x11000, 31616]],
        "warmup_advances": [["cpu", "gpio_a", "gpio_b"]],
        "cases": plan_cases,
        "source_admissions": {"schema_version": "source_admission_registry.v1",
                              "admissions": [admission_document]},
        "template": {"initial_images": [], "max_steps": 512},
    }
    receipts = []
    if not pin8_only:
        row = {
            "run_id": run.name, "buffer_id": 0, "slot": 0,
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "case_id": case.case_id, "direction": case.direction,
            "flow_id": "F4", "target_id": "cpu_to_ip_to_cpu.closed_loop",
            "path_id": case.path_id, "source_id": "cpu.online_instruction",
            "operator_id": instruction_operator_id(fragment),
            "candidate_id": "online-candidate.v1:" + hashlib.sha256(
                canonical({"path_id": case.path_id,
                           "source_id": "cpu.online_instruction",
                           "operator_id": instruction_operator_id(fragment)}
                          ).encode()).hexdigest(),
            "candidate_disposition": disposition,
            "candidate_disposition_reason": disposition_reason,
            "status": status,
            "online_raw_records_hex": [raw.hex()],
            "online_weights": {"cpu.online_instruction": 104,
                               "gpio_b.external_pin8": 104},
            "online_source": {"action_id": case.source.action_id,
                              "component": "cpu",
                              "address": case.source.address,
                              "data_hex": (case.source.data_hex
                                           if recorded_data_hex is None
                                           else recorded_data_hex),
                              "kind": "instruction"},
        }
        receipts.append(row)
    else:
        receipts.append({
            "run_id": run.name, "buffer_id": 0, "slot": 0,
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "case_id": "online-0-pin8", "direction": "IP_TO_CPU_TO_IP",
            "flow_id": "F1", "candidate_id": None, "status": "complete",
            "online_raw_records_hex": [raw.hex()],
            "online_weights": {"cpu.online_instruction": 104,
                               "gpio_b.external_pin8": 104},
            "online_source": {**PIN8_SOURCE},
        })
    events = []
    if not pin8_only:
        events = _events_for_case(case, admission_document,
                                  fetch="none" if fetch is None else fetch,
                                  fetch_bytes=fetch_bytes,
                                  retirement=retirement,
                                  retirement_insn=retirement_insn)
    if "receipts" not in omit:
        (run / "receipts.jsonl").write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in receipts),
            encoding="utf-8")
    if "plan" not in omit:
        (run / "online_plan.json").write_text(json.dumps(plan, sort_keys=True),
                                              encoding="utf-8")
    if "report" not in omit:
        (run / "report.json").write_text(json.dumps({
            "execution_status": "complete", "session_status": "complete",
            "client_returncode": 0, "tests": len(receipts),
            "statuses": {status: len(receipts)},
            "decoder_manifest_sha256": "0" * 64}, sort_keys=True),
            encoding="utf-8")
    if "manifest" not in omit:
        document = (runtime_decoder().document() if manifest == "runtime"
                    else {**runtime_decoder().document(), "support_words": 3})
        (run / "decoder_manifest.json").write_text(
            json.dumps(document, sort_keys=True), encoding="utf-8")
    if "seed" not in omit:
        (run / "seed.bin").write_bytes(
            raw if seed is None else seed)
    if trace_format == "json":
        if "trace" not in omit:
            (run / "online_final_trace.json").write_text(json.dumps({
                "events": events, "genome_sha256": "a" * 64,
                "local_ticks": {"cpu": 8, "gpio_a": 8, "gpio_b": 8},
                "manifest_sha256": "b" * 64, "semantic_sha256": "c" * 64,
                "status": "complete"}, sort_keys=True), encoding="utf-8")
    elif trace_format == "zlib":
        if "trace" not in omit:
            import myfuzz.integration.scenario_rfuzz_live as live
            from myfuzz.scenario.replay import ScenarioTrace
            trace = ScenarioTrace(events=events, genome_sha256="a" * 64,
                                  local_ticks={"cpu": 8, "gpio_a": 8, "gpio_b": 8},
                                  manifest_sha256="b" * 64,
                                  semantic_sha256="", status="complete")
            live._write_online_trace_zlib(run, trace)
    else:
        if "trace" not in omit:
            (run / "online_events.jsonl").write_text(
                "".join(json.dumps(event, sort_keys=True) + "\n"
                        for event in events), encoding="utf-8")
            (run / "online_final_trace.meta.json").write_text(json.dumps({
                "schema_version": "online_trace_jsonl.v1",
                "events_file": "online_events.jsonl",
                "event_count": len(events), "genome_sha256": "a" * 64,
                "local_ticks": {"cpu": 8, "gpio_a": 8, "gpio_b": 8},
                "manifest_sha256": "b" * 64, "semantic_sha256": "c" * 64,
                "status": "complete"}, sort_keys=True), encoding="utf-8")
    if replay is not None:
        log = tmp_path / f"{run.name}-replay.log"
        log.write_text(json.dumps({"matches": replay,
                                   "first_difference": None,
                                   "difference_context": None}) + "\n",
                       encoding="utf-8")
    return run


def verify(run: Path, **kwargs):
    gate = load_script()
    document, code = gate.verify_run(run, **kwargs)
    return document, code


# --------------------------------------------------------------------------
# verify mode: real-shaped evidence passes, contradictions fail
# --------------------------------------------------------------------------

@pytest.mark.parametrize("arm", ["insert", "delete"])
def test_verify_passes_on_full_real_shaped_evidence(tmp_path, arm):
    run = make_run(tmp_path, arm=arm)
    document, code = verify(run)
    assert code == load_script().EXIT_PASS, document["reasons"]
    assert document["verdict"] == "PASS"
    assert set(document["criteria"]) == {
        "deterministic_seed_injection", "operator_case_admitted",
        "fragment_fetch_evidence", "fragment_retirement_evidence",
        "reservation_boundary", "fresh_replay_matches"}
    for name, criterion in document["criteria"].items():
        assert criterion["status"] in ("proven", "not_applicable"), (name, criterion)
    proven = document["criteria"]["operator_case_admitted"]
    assert proven["arm"] == arm
    assert proven["candidate_id"] and proven["action_id"] and proven["case_id"]
    assert proven["fragment_hex"] == load_script().DECLARED_FRAGMENTS[arm]
    assert document["criteria"]["fragment_retirement_evidence"]["words"] == \
        len(load_script().DECLARED_FRAGMENTS[arm]) // 8
    assert document["criteria"]["fresh_replay_matches"]["logs"]


def test_verify_reads_the_streamed_jsonl_trace_with_its_meta(tmp_path):
    run = make_run(tmp_path, trace_format="jsonl")
    document, code = verify(run)
    assert code == load_script().EXIT_PASS, document["reasons"]
    assert document["artifacts"]["trace"]["file"] == "online_final_trace.meta.json"
    assert document["artifacts"]["trace"]["format"] == "jsonl.v1"


def test_verify_accepts_fetch_responses_as_instruction_fetch_evidence(tmp_path):
    run = make_run(tmp_path, fetch="instr_response")
    document, code = verify(run)
    assert code == load_script().EXIT_PASS, document["reasons"]
    fetch = document["criteria"]["fragment_fetch_evidence"]
    assert fetch["event_kinds"] == ["instr_response"]
    assert fetch["words"] == 3


def test_verify_is_deterministic_and_read_only(tmp_path):
    run = make_run(tmp_path)
    before = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
              for path in sorted(run.iterdir())}
    first = verify(run)[0]
    second = verify(run)[0]
    after = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
             for path in sorted(run.iterdir())}
    assert canonical(first) == canonical(second)
    assert before == after
    assert first["executes_rtl"] is False


def test_verify_allow_unseeded_audits_a_search_found_case(tmp_path):
    """--allow-unseeded drops only the prepared-injection criterion."""
    gate = load_script()
    run = make_run(tmp_path, seed=bytes(8))
    assert verify(run)[1] == gate.EXIT_INCONCLUSIVE
    document, code = verify(run, allow_unseeded=True)
    assert code == gate.EXIT_PASS, document["reasons"]
    assert document["criteria"]["deterministic_seed_injection"]["status"] == \
        "not_applicable"
    assert document["criteria"]["operator_case_admitted"]["declared_raw"] is True


def test_verify_blocked_when_required_artifacts_are_absent(tmp_path):
    gate = load_script()
    run = make_run(tmp_path, omit=("receipts",))
    document, code = verify(run)
    assert code == gate.EXIT_BLOCKED
    assert document["verdict"] == "BLOCKED"
    assert any("receipts.jsonl" in reason for reason in document["reasons"])
    run2 = make_run(tmp_path, omit=("trace",),
                    name="p4-sequence-edit-insert-20261008b-online")
    document2, code2 = verify(run2)
    assert code2 == gate.EXIT_BLOCKED
    assert any("trace" in reason for reason in document2["reasons"])


def test_verify_inconclusive_when_no_case_carried_the_operator(tmp_path):
    gate = load_script()
    run = make_run(tmp_path, pin8_only=True)
    document, code = verify(run)
    assert code == gate.EXIT_INCONCLUSIVE
    assert document["verdict"] == "INCONCLUSIVE"
    assert document["criteria"]["operator_case_admitted"]["status"] == "unproven"
    assert any("insert" in reason and "delete" in reason
               for reason in document["reasons"])


def test_verify_inconclusive_when_the_seed_was_not_a_declared_raw(tmp_path):
    gate = load_script()
    run = make_run(tmp_path, seed=bytes(8))
    document, code = verify(run)
    assert code == gate.EXIT_INCONCLUSIVE
    assert document["criteria"]["deterministic_seed_injection"]["status"] == \
        "unproven"
    assert any("seed.bin" in reason for reason in document["reasons"])


def test_verify_inconclusive_when_the_fragment_was_never_fetched(tmp_path):
    gate = load_script()
    run = make_run(tmp_path, fetch=None)
    document, code = verify(run)
    assert code == gate.EXIT_INCONCLUSIVE
    assert document["criteria"]["fragment_fetch_evidence"]["status"] == "unproven"
    assert any("fetch" in reason for reason in document["reasons"])


def test_verify_inconclusive_without_any_rvfi_retirement_observation(tmp_path):
    gate = load_script()
    run = make_run(tmp_path, retirement=False)
    document, code = verify(run)
    assert code == gate.EXIT_INCONCLUSIVE
    retirement = document["criteria"]["fragment_retirement_evidence"]
    assert retirement["status"] == "unproven"
    assert any("--cpu-retirement" in reason for reason in document["reasons"])


def test_verify_fails_when_fetched_bytes_are_not_the_fragment(tmp_path):
    gate = load_script()
    run = make_run(tmp_path, fetch_bytes=["00000013", "00000013", "00000013"])
    document, code = verify(run)
    assert code == gate.EXIT_FAIL
    assert document["verdict"] == "FAIL"
    assert document["criteria"]["fragment_fetch_evidence"]["status"] == "refuted"
    assert any("fetch" in reason for reason in document["reasons"])


def test_verify_fails_when_a_retirement_is_not_the_fragment_word(tmp_path):
    gate = load_script()
    run = make_run(tmp_path, retirement_insn={1: 0x00000013})
    document, code = verify(run)
    assert code == gate.EXIT_FAIL
    assert document["criteria"]["fragment_retirement_evidence"]["status"] == \
        "refuted"
    assert any("retire" in reason for reason in document["reasons"])


def test_verify_fails_when_the_reservation_boundary_is_crossed(tmp_path):
    gate = load_script()
    run = make_run(tmp_path, boundary="beyond_end")
    document, code = verify(run)
    assert code == gate.EXIT_FAIL
    assert document["criteria"]["reservation_boundary"]["status"] == "refuted"
    run2 = make_run(tmp_path, boundary="cursor_overrun")
    document2, code2 = verify(run2)
    assert code2 == gate.EXIT_FAIL
    assert any("reservation" in reason for reason in document2["reasons"])


def test_verify_fails_when_a_case_was_refused(tmp_path):
    gate = load_script()
    run = make_run(tmp_path, disposition="rejected",
                   disposition_reason="pre_submit_validation_rejected")
    document, code = verify(run)
    assert code == gate.EXIT_FAIL
    assert document["criteria"]["operator_case_admitted"]["status"] == "refuted"
    assert any("pre_submit_validation_rejected" in reason
               for reason in document["reasons"])


def test_verify_fails_when_the_fresh_replay_disagrees(tmp_path):
    gate = load_script()
    run = make_run(tmp_path, replay=False)
    document, code = verify(run)
    assert code == gate.EXIT_FAIL
    assert document["criteria"]["fresh_replay_matches"]["status"] == "refuted"


def test_verify_inconclusive_when_the_declaration_is_not_the_shipped_one(tmp_path):
    gate = load_script()
    run = make_run(tmp_path, manifest="foreign")
    document, code = verify(run)
    assert code == gate.EXIT_INCONCLUSIVE
    assert document["artifacts"]["decoder_manifest"]["identity"] == "foreign"
    assert document["criteria"]["operator_case_admitted"]["status"] == "unproven"


def test_verify_fails_when_a_claimed_fragment_is_not_reproducible(tmp_path):
    """A receipt that claims a sequence-edit fragment its own raw cannot make."""
    gate = load_script()
    other = gate.declared_case("base").source.data_hex + "13000000"
    assert len(other) == 24
    run = make_run(tmp_path, arm="insert", recorded_data_hex=other)
    document, code = verify(run)
    assert code == gate.EXIT_FAIL
    criterion = document["criteria"]["operator_case_admitted"]
    assert criterion["status"] == "refuted"
    assert "复算" in criterion["reason"]
    assert document["cases"]["unreproducible_rows"] == 1


def test_verify_reads_the_compressed_trace_blocks(tmp_path):
    run = make_run(tmp_path, trace_format="zlib")
    document, code = verify(run)
    assert code == load_script().EXIT_PASS, document["reasons"]
    assert document["artifacts"]["trace"]["format"] == "zlib.v1"


def test_verify_reports_the_admission_join_fields_and_citations(tmp_path):
    run = make_run(tmp_path)
    document, code = verify(run)
    assert code == load_script().EXIT_PASS
    joins = document["joins"]
    assert joins["admission"]["input_sha256_recomputed"] is True
    assert joins["admission"]["admission_id_authenticated"] is True
    assert joins["fetch"]["event_kind"] in (["memory_read"], ["instr_response"])
    assert joins["fetch"]["channel_id"] == "instr"
    assert joins["fetch"]["writer_kind"] == "INSTRUCTION_SOURCE"
    assert joins["retirement"]["event_kind"] == "cpu_retirement_match"
    assert joins["retirement"]["origin_status"] == "typed_writer_refs"


def test_verify_run_rejects_a_missing_directory(tmp_path):
    gate = load_script()
    document, code = gate.verify_run(tmp_path / "absent")
    assert code == gate.EXIT_BLOCKED
    assert document["verdict"] == "BLOCKED"


# --------------------------------------------------------------------------
# plan mode: the prepared commands, artifacts and criteria
# --------------------------------------------------------------------------

def test_plan_document_prescribes_seed_commands_and_read_back_fields():
    gate = load_script()
    document = gate.plan_document()
    assert document["schema_version"].endswith(".v1")
    assert document["executes_rtl"] is False
    assert document["seed_mechanism"]["verified"] is True
    for arm in ("insert", "delete"):
        arm_document = document["arms"][arm]
        assert arm_document["raw_hex"] == gate.DECLARED_RAWS[arm]
        assert arm_document["fragment_hex"] == gate.DECLARED_FRAGMENTS[arm]
        assert arm_document["operator_id"] == gate.ARM_OPERATORS[arm]
        command = arm_document["run_command"]
        assert "--initial-ram-record " + gate.DECLARED_RAWS[arm] in command
        assert "--cpu-retirement" in command
        assert arm_document["replay_command"].splitlines()[0].endswith("replay \\")
        assert "online_plan.json" in arm_document["replay_command"]
        assert "--trace" in arm_document["replay_command"]
        assert "#" not in arm_document["replay_command"]
        assert arm_document["replay_log"] in arm_document["replay_command"]
        assert arm_document["replay_trace_note"]
    assert document["artifacts"]["receipts"]["fields"]
    assert document["artifacts"]["trace"]["fields"]
    assert "deterministic_seed_injection" in document["criteria"]
    assert document["exit_codes"] == {"PASS": 0, "FAIL": 1, "BLOCKED": 3,
                                      "INCONCLUSIVE": 4}
    text = gate.render_plan(document)
    assert gate.DECLARED_RAWS["insert"] in text
    assert "--initial-ram-record" in text


def test_plan_mode_is_read_only_and_exits_zero(tmp_path, capsys):
    gate = load_script()
    workdir = tmp_path / "runs"
    workdir.mkdir()
    code = gate.main(["plan", "--runs-dir", str(workdir)])
    assert code == 0
    out = capsys.readouterr().out
    document = json.loads(out.split(gate.DOCUMENT_MARKER)[-1])
    assert document["arms"]["insert"]["raw_hex"] == gate.DECLARED_RAWS["insert"]
    assert list(workdir.iterdir()) == []


def test_verify_mode_exit_codes_through_main(tmp_path, capsys):
    gate = load_script()
    passing = make_run(tmp_path, arm="insert")
    assert gate.main(["verify", "--run", str(passing)]) == 0
    capsys.readouterr()
    blocked = make_run(tmp_path, arm="delete", omit=("receipts",))
    assert gate.main(["verify", "--run", str(blocked)]) == 3
    capsys.readouterr()
    failing = make_run(tmp_path, arm="delete", replay=False,
                       name="p4-sequence-edit-delete-20261008b-online")
    assert gate.main(["verify", "--run", str(failing)]) == 1
    capsys.readouterr()
    inconclusive = make_run(tmp_path, arm="delete", seed=bytes(8),
                            name="p4-sequence-edit-delete-20261008c-online")
    assert gate.main(["verify", "--run", str(inconclusive)]) == 4
