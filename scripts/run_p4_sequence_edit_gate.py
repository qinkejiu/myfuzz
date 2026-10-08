#!/usr/bin/env python3
"""P4 online instruction-sequence-edit real gate: prepared plan and verification.

The shipped online sequence-edit operator (``rv32i_sources.decode_instruction_fragment``)
can edit a still-uncommitted two-word ``LUI rd; ADDI rd,rd,imm12`` candidate:
entropy byte six's high two bits keep the two-word base (``0x40``), delete the
optional ``ADDI`` (``0x80``) or insert a ``XORI rd,rd,imm12`` between the words
(``0xC0``).  A software gate proved the semantics; this gate prepares and then
verifies the *real* evidence that a live Ibex + dual PULP GPIO session proposed,
fetched and retired an inserted (12-byte) or deleted (4-byte) fragment.

Two modes, both read-only with respect to the repository:

``plan``
    Prints the exact rfuzz-client command lines that would exercise the three
    declared eight-byte raws (one run per arm), the shipped mechanism that puts
    a raw in front of the decoder (the client seed record), the artifact fields
    to read back, the pass/fail criteria and the exit codes.  The seed
    mechanism is re-verified from the shipped sources on every call, so the
    plan is never an invented claim.

``verify --run <dir>``
    Joins the run's own artifacts by identity and fails closed:

    * (a) ``operator_case_admitted`` -- a receipt whose recorded fragment is the
      shipped decode of its own recorded raw, and whose replay of that raw
      selects the insert or delete branch, with its ``case_id``, ``action_id``
      and ``candidate_id``;
    * (b) ``fragment_fetch_evidence`` -- every fragment word appears in the
      run's real instruction-channel fetch evidence with the case's own writer
      identity (``memory_read`` with ``transaction.channel_id == "instr"`` or an
      ``instr_response`` snapshot), plus the trace's ``instruction_source``
      materialization of exactly those bytes;
    * (b') ``fragment_retirement_evidence`` -- under the authenticated RVFI
      observation, every fragment word retires with ``source_refs`` naming the
      case's action and ``pc``/``insn`` equal to that word (``cpu_retirement_match``);
    * (c) ``reservation_boundary`` -- the plan's own instruction slot and case
      walk show no fragment crossed the declared instruction end;
    * (d) ``fresh_replay_matches`` -- a fresh-replay log next to the run, when
      present, reports ``matches=true``.

    Verdicts: ``PASS`` (0), ``FAIL`` (1, a proved contradiction), ``BLOCKED``
    (3, a required artifact is missing or unreadable) and ``INCONCLUSIVE`` (4,
    readable evidence that does not yet prove the claim).

No RTL, Verilator, Rust or fuzz job is started by either mode.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.as_posix() not in sys.path:
    sys.path.insert(0, SRC.as_posix())

from myfuzz.scenario.ibex_pulp_dual_source import (  # noqa: E402
    make_ibex_pulp_dual_source_online_decoder,
    make_ibex_pulp_dual_source_stream_bootstrap,
)
from myfuzz.scenario.online_case_decoder import OnlineCaseDecoder  # noqa: E402
from myfuzz.scenario.rv32i_sources import (  # noqa: E402
    decode_instruction_fragment, fragment_bytes, instruction_operator_id,
)
from myfuzz.scenario.session_runtime import OnlineInstruction  # noqa: E402
from myfuzz.scenario.source_provenance import SourceAdmission  # noqa: E402

#: The schema family of every document this script prints (plan/verify/raw proof).
SCHEMA_VERSION = "p4_sequence_edit_gate.v1"
DOCUMENT_MARKER = "gate-document-json:"

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_BLOCKED = 3
EXIT_INCONCLUSIVE = 4

#: The RFuzz client binary the shipped online entry points are documented with.
CLIENT_BINARY = ("third_party/rfuzz/upstream/rfuzz_reference/fuzzer/"
                 "target/release/kfuzz")
#: The path-selection domain of ``OnlineCaseDecoder._decode_case``.
PATH_DOMAIN = b"myfuzz.online.path.v1\0"
#: ``_online_baseline_weights`` at the first case: source.weight * (8 + 64 + 32).
FIRST_CASE_SOURCE_WEIGHT = 104
#: The runner accepts exactly eight-byte seed records.
SEED_RECORD_BYTES = 8

#: The three declared raw inputs.  Byte two is the direct source byte of the
#: instruction source (index 0); byte three's remainder selects the arithmetic
#: (sequence-edit) choice; byte four's high two bits select the branch.
DECLARED_RAWS = {
    "base": "0000003e63010106",
    "insert": "00000007c00200fc",
    "delete": "00000011a10100aa",
}
#: The shipped operator's fragment for each raw, in fragment-word order.
DECLARED_FRAGMENTS = {
    "base": "b713106093831310",
    "insert": "b72300c093c3c37f93832300",
    "delete": "b71300a0",
}
ARM_OPERATORS = {
    "base": "rv32i:LUI+ADDI",
    "insert": "rv32i:LUI+XORI+ADDI",
    "delete": "rv32i:LUI",
}
ARM_LENGTHS = {"base": 8, "insert": 12, "delete": 4}
ARM_EDIT_BYTES = {"base": 0x40, "insert": 0xC0, "delete": 0x80}
ARM_READINGS = {
    "base": {"register": 7, "words": ["LUI x7,0x60101", "ADDI x7,x7,0x101"]},
    "insert": {"register": 7,
               "words": ["LUI x7,0xfc0002", "XORI x7,x7,-0x804",
                         "ADDI x7,x7,2"]},
    "delete": {"register": 7, "words": ["LUI x7,0xaa0001"]},
}
EDIT_ARMS = ("insert", "delete")

#: The shipped sources the seed mechanism is re-verified against.
SEED_MECHANISM_SOURCES = {
    "cli": "scripts/run_ibex_pulp_online.py",
    "runner": "src/myfuzz/integration/scenario_rfuzz_live.py",
    "client": ("third_party/rfuzz/upstream/rfuzz_reference/fuzzer/src/main.rs"),
    "client_mutator": ("third_party/rfuzz/upstream/rfuzz_reference/fuzzer/"
                       "src/mutation/scenario.rs"),
}

CRITERIA = {
    "deterministic_seed_injection": (
        "seed.bin 是本门禁声明的某个 8 字节 raw，且该 raw 作为一例的 "
        "online_raw_records_hex 出现在 receipts.jsonl 中：声明的原始输入确实"
        "经 shipped seed 机制到达在线解码器。"),
    "operator_case_admitted": (
        "至少一例被接纳的指令 case，其 online_source.data_hex 正是用该例自己的 "
        "raw 经 shipped decode_instruction_fragment 复算出的 insert(12B) 或 "
        "delete(4B) 片段，且其 case_id/action_id/candidate_id 齐备。"),
    "fragment_fetch_evidence": (
        "该 case 的每个 4 字节片段字都出现在运行自身的真实取指证据中："
        "memory_read(transaction.channel_id='instr') 或 instr_response，"
        "地址等于片段字地址、字节等于该字、writer 身份等于该 case 的 action_id；"
        "并有 trace 的 instruction_source 物化事件。"),
    "fragment_retirement_evidence": (
        "在 RVFI 退休观测下，该 case 的每个片段字都有 cpu_retirement_match："
        "status='accepted'、instruction_origin_status='typed_writer_refs'、"
        "source_refs==[该 case 的 action_id]、pc/insn 等于该字。"),
    "reservation_boundary": (
        "plan 自身的 instruction_slots 与逐例游标走查证明没有任何片段越过声明的 "
        "instruction_end，且累计接纳字节不超过保留区。"),
    "fresh_replay_matches": (
        "若运行旁存在 fresh replay 日志，其 matches 必须为 true（不存在时不据此"
        "判失败，只记为不适用）。"),
}

EXIT_CODES = {"PASS": EXIT_PASS, "FAIL": EXIT_FAIL, "BLOCKED": EXIT_BLOCKED,
              "INCONCLUSIVE": EXIT_INCONCLUSIVE}


# --------------------------------------------------------------------------
# canonical helpers
# --------------------------------------------------------------------------

def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _entropy_of(raw: bytes) -> bytes:
    """The twelve mutation-entropy bytes of one raw input.

    ``OnlineCaseDecoder._case_entropy``: payload bytes three onward lead and
    repeat to twelve bytes; a shorter raw is used as it is and the shipped
    operator zero-pads it.
    """
    if len(raw) >= 8:
        payload = raw[3:]
        return (payload * ((12 + len(payload) - 1) // len(payload)))[:12]
    return raw


def shipped_decoder(*, readback: bool = False):
    """A fresh instance of the shipped online declaration of this wiring."""
    if readback:
        return make_ibex_pulp_dual_source_online_decoder(
            bootstrap=make_ibex_pulp_dual_source_stream_bootstrap(),
            result_slot_readback=True)
    return make_ibex_pulp_dual_source_online_decoder()


def declared_case(arm: str, *, readback: bool = False, address: int | None = None):
    """The shipped decode of one declared raw (optionally re-addressed)."""
    if arm not in DECLARED_RAWS:
        raise ValueError(f"unknown declared arm: {arm!r}")
    case = shipped_decoder(readback=readback).decode(
        bytes.fromhex(DECLARED_RAWS[arm]))
    if address is not None:
        case = replace(case, source=replace(case.source, address=address))
    return case


def input_sha256(source: OnlineInstruction) -> str:
    """The admission's input digest (``session_runtime._case_admissions``)."""
    return _canonical_sha256({**asdict(source), "kind": "instruction"})


# --------------------------------------------------------------------------
# raw selection evidence (software)
# --------------------------------------------------------------------------

def client_mutator_image(raw: bytes) -> bool:
    """Whether one raw lies in the shipped Rust client's single-record image.

    ``ScenarioDecisionMutator::apply`` writes ``output[0] = template``,
    ``output[1] = path``, ``output[2] = source`` and derives the payload bytes
    three..seven from one decision word: ``[3] = decision & 255``,
    ``[4] = (decision / 16) & 255``, ``[5] = 2 if decision % 8 == 7 else 1``,
    ``[6] = (decision / 32) & 15`` and ``[7] = (decision >> 8) & 255``.  The
    four shared/derived relations below are exactly that image for one record.
    """
    if not isinstance(raw, bytes) or len(raw) != SEED_RECORD_BYTES:
        return False
    if raw[0] != 0 or raw[1] != 0 or raw[2] != 0:
        return False
    third, fourth, fifth, sixth, seventh = raw[3], raw[4], raw[5], raw[6], raw[7]
    if fifth not in (1, 2):
        return False
    if (fourth & 0x0F) != (third >> 4):
        return False
    if (fourth >> 4) != (seventh & 0x0F):
        return False
    if sixth != (((third >> 5) & 0x07) | ((seventh & 0x01) << 3)):
        return False
    return fifth == (2 if (third & 0x07) == 7 else 1)


def path_draw(raw: bytes) -> dict:
    """The declared path draw one raw makes, with the first case's weights.

    ``OnlineCaseDecoder._decode_case`` draws the path as
    ``sha256(b"myfuzz.online.path.v1\\0" + raw)[:8] % sum(path_weights)``.  Each
    path's weight is its strongest source; at the first case
    ``_online_baseline_weights`` gives every untouched source
    ``weight * (8 + 64 + 32)``, so the two declared paths of this wiring weigh
    the same and the instruction path owns the lower half.
    """
    if len(raw) != SEED_RECORD_BYTES:
        raise ValueError("the declared raws are eight byte records")
    decoder = shipped_decoder()
    rows = decoder.path_switch_targets()
    weights = []
    for row in rows:
        sources = [source for source in decoder.sources
                   if source.source_id in row["source_ids"]]
        weights.append(max(source.weight for source in sources)
                       * FIRST_CASE_SOURCE_WEIGHT)
    instruction_weight = weights[0]
    total = sum(weights)
    selector = int.from_bytes(
        hashlib.sha256(PATH_DOMAIN + raw).digest()[:8], "little") % total
    return {"path_ids": [row["path_id"] for row in rows],
            "weights": weights, "total_weight": total,
            "instruction_weight": instruction_weight, "selector": selector,
            "margin": min(selector, instruction_weight - 1 - selector),
            "instruction_path_selected": selector < instruction_weight}


def declared_raw_report() -> dict:
    """The software raw-selection proof for the three declared raws."""
    document = {"schema_version": "p4_sequence_edit_raw_selection.v1",
                "executes_rtl": False,
                "decoder_path_count": len(shipped_decoder().sources),
                "arms": {}}
    for arm, raw_hex in DECLARED_RAWS.items():
        raw = bytes.fromhex(raw_hex)
        entropy = _entropy_of(raw)
        case = declared_case(arm)
        runtime_case = declared_case(arm, readback=True)
        decoder = shipped_decoder()
        fragment = case.source.data
        document["arms"][arm] = {
            "raw_hex": raw_hex,
            "entropy_hex": entropy.hex(),
            "choice_remainder": entropy[0] % (3 + len(decoder.allowed_mmio_operations)),
            "edit_byte": entropy[6] & 0xC0,
            "fragment_hex": fragment.hex(),
            "fragment_words": [fragment[i:i + 4].hex()
                               for i in range(0, len(fragment), 4)],
            "fragment_bytes": len(fragment),
            "operator_id": instruction_operator_id(fragment),
            "readings": ARM_READINGS[arm],
            "register": 1 + entropy[1] % 31,
            "case_id": case.case_id,
            "action_id": case.source.action_id,
            "path_id": case.path_id,
            "direction": case.direction,
            "runtime_declaration_fragment_hex": runtime_case.source.data_hex,
            "runtime_declaration_matches": (
                runtime_case.source.data_hex == fragment.hex()),
            "path_draw": path_draw(raw),
            "client_mutator_image": client_mutator_image(raw),
        }
    document["insert_keeps_base_words"] = {
        "first_word_equal": (document["arms"]["insert"]["fragment_words"][0]
                             == document["arms"]["base"]["fragment_words"][0]),
        "last_word_equal": (document["arms"]["insert"]["fragment_words"][2]
                            == document["arms"]["base"]["fragment_words"][1]),
        "delete_is_base_prefix": (document["arms"]["delete"]["fragment_words"]
                                  == document["arms"]["base"]["fragment_words"][:1]),
    }
    return document


def seed_mechanism_evidence(*, cli_path: Path | None = None) -> dict:
    """Re-verify, from the shipped sources, how one raw reaches the decoder.

    The mechanism is not invented here: the shipped CLI passes the record both
    to the initial-RAM operator and to ``run_scenario_rfuzz_live`` as the client
    seed, the runner writes it verbatim to ``seed.bin`` and hands the client
    ``--seed-cycles``/``--seed-input``, and the client's seed cycle runs
    ``mutation::identity`` over those exact bytes, which the host then decodes
    as one raw input.
    """
    paths = {"cli": Path(cli_path) if cli_path is not None
             else ROOT / SEED_MECHANISM_SOURCES["cli"],
             "runner": ROOT / SEED_MECHANISM_SOURCES["runner"],
             "client": ROOT / SEED_MECHANISM_SOURCES["client"],
             "client_mutator": ROOT / SEED_MECHANISM_SOURCES["client_mutator"]}
    wants = {
        "cli_flag": ("cli", "--initial-ram-record"),
        "cli_forwards_record_to_client_seed": (
            "cli", "seed_records=(initial_ram_record,)"),
        "runner_seed_records": ("runner", "seed must contain complete eight byte records"),
        "seed_bin": ("runner", '(output / "seed.bin").write_bytes(b"".join(seed_records))'),
        "client_command": ("runner", '"--seed-input"'),
        "client_identity_mutator": ("client", "mutation::identity(input)"),
        "seed_cycle_count": ("client", "let expected = test_size.input * start_cycles;"),
        "client_payload_layout": ("client_mutator", "output[record + 3] = (decision & 255) as u8;"),
    }
    checks = []
    texts = {}
    for key, path in paths.items():
        if path.is_file():
            texts[key] = path.read_text(encoding="utf-8", errors="replace")
    for check_id, (key, token) in wants.items():
        path = paths[key]
        text = texts.get(key)
        checks.append({
            "id": check_id, "path": str(path.relative_to(ROOT))
            if path.is_relative_to(ROOT) else str(path),
            "sha256": _file_sha256(path) if text is not None else "",
            "token": token,
            "proven": bool(text is not None and token in text)})
    return {"verified": all(check["proven"] for check in checks),
            "executes_rtl": False,
            "seed_record_bytes": SEED_RECORD_BYTES,
            "how": ("scripts/run_ibex_pulp_online.py --initial-ram-record <hex> -> "
                    "run_scenario_rfuzz_live(seed_records=(record,)) -> "
                    "<run>/seed.bin -> client --seed-cycles 1 --seed-input "
                    "seed.bin -> fuzz_one(mutation::identity) -> the eight bytes "
                    "are submitted as the first case -> receipts.jsonl "
                    "online_raw_records_hex[0]"),
            "checks": checks}


# --------------------------------------------------------------------------
# plan mode
# --------------------------------------------------------------------------

RUN_FIELDS = {
    "receipts": ["case_id", "buffer_id", "slot", "status", "candidate_id",
                 "candidate_disposition", "candidate_disposition_reason",
                 "operator_id", "source_id", "online_raw_records_hex",
                 "online_source.{action_id,address,data_hex,kind}"],
    "plan": ["instruction_slots", "cases[].case_id",
             "cases[].source.{kind,address,data_hex,action_id}",
             "cases[].support_instructions[]",
             "source_admissions.admissions[].{case_id,case_index,source_id,"
             "action_id,admission_id,input_kind,input_sha256,role}"],
    "trace": ["events[kind=source_admission].admission",
              "events[kind=instruction_source].{source_event_id,address,data_hex}",
              "events[kind=memory_read].{address,data_hex,transaction.channel_id,"
              "provenance.resource.writer_event_ids,writer_kinds}",
              "events[kind=instr_response].{address,rdata,snapshot}",
              "events[kind=cpu_retirement_match].{status,instruction_origin_status,"
              "source_refs,pc,insn,order}"],
    "manifest": ["instruction_start", "instruction_end",
                 "initial_instruction_cursor", "mmio_windows",
                 "allowed_mmio_operations", "sources[].{source_id,kind,weight}"],
    "report": ["execution_status", "session_status", "client_returncode",
               "statuses", "tests"],
    "seed": ["the eight raw bytes of the arm (hex)"],
    "identity": ["trace_file", "trace_format", "session.manifest_sha256"],
    "replay": ["matches", "first_difference", "difference_context"],
}


def _run_command(*, arm: str, client_binary: str, cache_dir: Path,
                 output_dir: Path, seconds: float, max_tests: int,
                 search_seed: int, run_id: str) -> list[str]:
    return [
        "PYTHONPATH=src python3 scripts/run_ibex_pulp_online.py run \\",
        f"  --client-binary {client_binary} \\",
        f"  --cache-dir {cache_dir} \\",
        f"  --output {output_dir} \\",
        f"  --seconds {seconds:g} --max-tests {max_tests} "
        f"--seed {search_seed} \\",
        "  --cpu-retirement \\",
        f"  --run-id {run_id} \\",
        f"  --initial-ram-record {DECLARED_RAWS[arm]}",
    ]


REPLAY_TRACE_NOTE = (
    "--trace 指向该运行自己的 trace：事件数 < 100000 时是 "
    "online_final_trace.json；否则（或用 --compressed-trace 时）是 "
    "online_final_trace.meta.json —— 最终以该运行 online_run_identity.json 的 "
    "identity.trace_file 为准（shipped replay 也从它解析）")


def _replay_command(*, cache_dir: Path, output_dir: Path, log_path: Path) -> list[str]:
    # A comment must never precede a line continuation: bash would continue the
    # comment and swallow the pipe.  The trace caveat lives in the note instead.
    return [
        "PYTHONPATH=src python3 scripts/run_ibex_pulp_online.py replay \\",
        f"  --cache-dir {cache_dir} \\",
        f"  --plan {output_dir / 'online_plan.json'} \\",
        f"  --trace {output_dir / 'online_final_trace.json'} \\",
        f"  | tee {log_path}",
    ]


def plan_document(*, runs_dir: Path | None = None,
                  client_binary: str = CLIENT_BINARY,
                  cache_dir: Path | None = None, seconds: float = 25.0,
                  max_tests: int = 8, search_seed: int = 20261008) -> dict:
    """The prepared experiment: commands, read-back fields and criteria."""
    runs = Path(runs_dir) if runs_dir is not None else ROOT / "runs"
    arms = {}
    for arm in ("insert", "delete"):
        name = f"p4-sequence-edit-{arm}-20261008"
        output_dir = runs / f"{name}-online"
        arm_cache = Path(cache_dir) if cache_dir is not None else runs / f"{name}-cache"
        replay_cache = (Path(cache_dir) if cache_dir is not None
                        else runs / f"{name}-replay-cache")
        log_path = runs / f"{name}-online-replay.log"
        selection = declared_raw_report()["arms"][arm]
        arms[arm] = {
            **selection,
            "run_id": name,
            "output_dir": str(output_dir),
            "cache_dir": str(arm_cache),
            "run_command": "\n".join(_run_command(
                arm=arm, client_binary=client_binary, cache_dir=arm_cache,
                output_dir=output_dir, seconds=seconds, max_tests=max_tests,
                search_seed=search_seed, run_id=name)),
            "replay_command": "\n".join(_replay_command(
                cache_dir=replay_cache, output_dir=output_dir,
                log_path=log_path)),
            "replay_log": str(log_path),
            "replay_trace_note": REPLAY_TRACE_NOTE,
            "verify_command": (f"PYTHONPATH=src python3 "
                               f"scripts/run_p4_sequence_edit_gate.py verify "
                               f"--run {output_dir} --replay-log {log_path}"),
            "expected_evidence": {
                "first_case": ("seed.bin 的 8 字节即本 arm 的 raw，客户端把它作为"
                               "第一例原样提交；receipts.jsonl 第一行的 "
                               "online_raw_records_hex[0] 必须等于它"),
                "fragment": ("online_source.data_hex = "
                             f"{DECLARED_FRAGMENTS[arm]}（"
                             f"{ARM_LENGTHS[arm]} 字节，{ARM_OPERATORS[arm]}）"),
                "fetch": ("该片段每个字都必须在 memory_read(channel='instr')/"
                          "instr_response 中以上述字节与 action_id 身份出现"),
                "retirement": ("每个字都必须有 accepted 的 cpu_retirement_match，"
                               "source_refs=[该 case 的 action_id]，pc/insn 等于该字"),
            },
        }
    return {
        "schema_version": "p4_sequence_edit_gate_plan.v1",
        "executes_rtl": False,
        "generated_by": "scripts/run_p4_sequence_edit_gate.py plan",
        "family": SCHEMA_VERSION,
        "operator": ("rv32i_sources.decode_instruction_fragment choice 2 with "
                     "edit = entropy[6] & 0xC0"),
        "seed_mechanism": seed_mechanism_evidence(),
        "raw_selection": declared_raw_report(),
        "arms": arms,
        "control_arm": {
            "raw_hex": DECLARED_RAWS["base"],
            "fragment_hex": DECLARED_FRAGMENTS["base"],
            "operator_id": ARM_OPERATORS["base"],
            "why": ("未编辑的两字基序列：证明同一 raw 形状在高两位为 0x40 时仍产生 "
                    "8 字节 LUI+ADDI，因此 insert/delete 不是无条件发生的；"
                    "verify 只接受 insert/delete，控制臂因此应判 INCONCLUSIVE，"
                    "其作用是用 raw_selection 与回执片段字节做对照"),
            "run_command": "\n".join(_run_command(
                arm="base", client_binary=client_binary,
                cache_dir=Path(cache_dir) if cache_dir is not None
                else runs / "p4-sequence-edit-base-20261008-cache",
                output_dir=runs / "p4-sequence-edit-base-20261008-online",
                seconds=seconds, max_tests=max_tests,
                search_seed=search_seed, run_id="p4-sequence-edit-base-20261008")),
        },
        "arms_to_run": ["insert", "delete"],
        "artifacts": {
            "run_dir": ("<output_dir>：由 shipped 入口点写出，含 receipts.jsonl、"
                        "online_plan.json、decoder_manifest.json、seed.bin、"
                        "report.json、online_run_identity.json 与 trace"),
            **{key: {"fields": value} for key, value in RUN_FIELDS.items()},
        },
        "criteria": CRITERIA,
        "joins": {
            "admission": ("receipts.jsonl case_id/online_source.action_id/address/"
                          "data_hex -> online_plan.json source_admissions row，"
                          "input_sha256 由 OnlineInstruction 规范化摘要复算，"
                          "admission_id 由 shipped SourceAdmission 校验"),
            "fetch": ("receipts address+4i/data_hex -> trace memory_read"
                      "(transaction.channel_id='instr')/instr_response 的 "
                      "address/data_hex(rdata) 与 provenance.resource."
                      "writer_event_ids == {action_id}"),
            "retirement": ("receipts action_id -> trace cpu_retirement_match 的 "
                           "source_refs/instruction_origin_status/pc/insn"),
            "boundary": ("online_plan.json instruction_slots + cases 逐例游标 -> "
                         "decoder_manifest.json instruction_start/instruction_end"),
        },
        "exit_codes": EXIT_CODES,
        "stopping_rules": {
            "PASS": "六个判据全部 proven（fresh replay 日志不存在时记 not_applicable）",
            "FAIL": "任一判据被运行自身证据反驳",
            "BLOCKED": "必需产物缺失或不可解析",
            "INCONCLUSIVE": "产物可读但不足以证明（未触及算子、无 RVFI 退休观测等）",
        },
        "honesty": ("本模式只打印计划，不运行任何 RTL/Verilator/Rust/fuzz 作业；"
                    "在真实运行与 verify 通过之前，本门禁不声称任何真实 RTL 结论。"),
    }


def render_plan(document: Mapping) -> str:
    """The human-readable plan, including the exact command lines."""
    lines = [
        "P4 在线指令序列编辑（insert XORI / delete ADDI）真实门禁 —— 计划（只读）",
        "=" * 72,
        f"算子：{document['operator']}",
        "",
        "声明的 raw 选择（软件证明，见 raw_selection）：",
    ]
    for arm in ("insert", "delete", "base"):
        row = document["raw_selection"]["arms"][arm]
        lines += [
            f"  {arm:6s} raw={row['raw_hex']}  edit=0x{row['edit_byte']:02x}  "
            f"{row['fragment_bytes']}B  {row['operator_id']}",
            f"         片段={row['fragment_hex']}",
            f"         {', '.join(row['readings']['words'])}  "
            f"rd=x{row['register']}",
            f"         路径抽签 selector={row['path_draw']['selector']}"
            f"/{row['path_draw']['total_weight']}"
            f"（margin={row['path_draw']['margin']}）"
            f" 客户端变异字节像={row['client_mutator_image']}",
        ]
    lines += ["", "raw 如何到达客户端（每次调用都从 shipped 源码复核）：",
              f"  {document['seed_mechanism']['how']}",
              "  逐条源码证据："]
    for check in document["seed_mechanism"]["checks"]:
        lines.append(f"    [{'OK' if check['proven'] else 'FAIL'}] "
                     f"{check['id']}: {check['path']} :: {check['token']}")
    for arm in document["arms_to_run"]:
        row = document["arms"][arm]
        lines += ["", "-" * 72,
                  f"{arm} arm（run_id={row['run_id']}）",
                  "  运行命令：", f"    cd {ROOT}",
                  *[f"    {line}" for line in row["run_command"].splitlines()],
                  "  fresh replay（独立 cache）：",
                  *[f"    {line}" for line in row["replay_command"].splitlines()],
                  "  读回证据：",
                  *[f"    - {key}: {value}"
                    for key, value in row["expected_evidence"].items()]]
    lines += ["", "-" * 72, "判据（verify 模式）："]
    for name, text in document["criteria"].items():
        lines.append(f"  {name}: {text}")
    lines += ["", "退出码：" + ", ".join(f"{key}={value}"
                                        for key, value in document["exit_codes"].items()),
              f"真实性声明：{document['honesty']}",
              "-" * 72,
              "本脚本不运行 RTL/Verilator/Rust/fuzz；计划本身不含真实 RTL 结论。"]
    return "\n".join(lines)


# --------------------------------------------------------------------------
# verify mode
# --------------------------------------------------------------------------

def _criterion(status: str, reason: str, **detail) -> dict:
    return {"status": status, "reason": reason, **detail}


def _read_json(path: Path) -> tuple[object | None, str | None]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _resolve_trace(run: Path) -> tuple[Path | None, str, str]:
    """The run's own trace file, its declared format, and a refusal reason."""
    identity, _ = _read_json(run / "online_run_identity.json")
    trace_file = None
    if isinstance(identity, Mapping):
        inner = identity.get("identity")
        if isinstance(inner, Mapping) and isinstance(inner.get("trace_file"), str):
            trace_file = inner["trace_file"]
    candidates = ([trace_file] if trace_file else []) + [
        "online_final_trace.json", "online_final_trace.meta.json"]
    for name in candidates:
        path = run / name
        if path.is_file():
            if name.endswith(".meta.json") or name == "online_final_trace.json":
                document, error = _read_json(path)
                if error is None and isinstance(document, Mapping):
                    schema = document.get("schema_version")
                    if schema == "online_trace_jsonl.v1":
                        return path, "jsonl.v1", ""
                    if schema == "online_trace_zlib_chunks.v1":
                        return path, "zlib.v1", ""
            return path, "json.v1", ""
    if (run / "online_events.jsonl").is_file():
        return run / "online_events.jsonl", "jsonl-bare.v1", ""
    return None, "", ("未找到 trace：期望 online_run_identity.json 的 "
                      "identity.trace_file、online_final_trace.json 或 "
                      "online_final_trace.meta.json")


def _event_sequence(trace: Path, fmt: str) -> tuple[Sequence | None, str]:
    """The shipped lazy event views, so a large JSONL trace stays streamable."""
    if fmt == "json.v1":
        document, error = _read_json(trace)
        if error is not None:
            return None, f"trace 不可解析：{error}"
        if not isinstance(document, Mapping) or not isinstance(
                document.get("events"), list):
            return None, "trace 缺少 events 列表"
        return document["events"], ""
    if fmt in ("jsonl.v1", "zlib.v1"):
        meta, error = _read_json(trace)
        if error is not None:
            return None, f"trace meta 不可解析：{error}"
        try:
            count = int(meta["event_count"])
            events_file = run_relative = meta["events_file"]
            path = trace.parent / events_file
            if fmt == "jsonl.v1":
                from myfuzz.scenario.event_journal import JsonlEventView
                return JsonlEventView(path, count), ""
            from myfuzz.scenario.event_journal import ZlibChunkEventView
            return ZlibChunkEventView(path, count), ""
        except (KeyError, TypeError, ValueError, OSError) as exc:
            return None, f"trace 事件流不可读：{type(exc).__name__}: {exc}"
    if fmt == "jsonl-bare.v1":
        try:
            from myfuzz.scenario.event_journal import JsonlEventView
            with trace.open("rb") as handle:
                count = sum(1 for line in handle if line.strip())
            return JsonlEventView(trace, count), ""
        except (OSError, ValueError) as exc:
            return None, f"trace JSONL 不可读：{type(exc).__name__}: {exc}"
    return None, f"不支持的 trace 格式：{fmt or 'unknown'}"


def _branch_of(entropy: bytes, data_hex: str, decoder) -> str | None:
    """Which shipped branch produced one fragment, from its own raw bytes."""
    if len(entropy) < 7:
        return None
    choice = entropy[0] % ((3 + len(decoder.allowed_mmio_operations))
                           if decoder.windows else 3)
    if choice != 2:
        return None
    edit = entropy[6] & 0xC0
    length = len(data_hex) // 2
    if edit == 0xC0 and length == 12:
        return "insert"
    if edit == 0x80 and length == 4:
        return "delete"
    if edit == 0x40 and length == 8:
        return "base"
    return None


def _reproduce(decoder, data_hex: str, raw: bytes) -> str | None:
    try:
        return fragment_bytes(decode_instruction_fragment(
            _entropy_of(raw), windows=decoder.windows,
            allowed_mmio_operations=decoder.allowed_mmio_operations)).hex()
    except ValueError:
        return None


def _instruction_rows(receipts: list) -> list[dict]:
    rows = []
    for index, row in enumerate(receipts):
        if not isinstance(row, Mapping):
            continue
        source = row.get("online_source")
        if not isinstance(source, Mapping) or source.get("kind") != "instruction":
            continue
        rows.append({"index": index, "row": row, "source": source})
    return rows


def _classify_rows(rows: list[dict], decoder) -> list[dict]:
    """Attach the shipped recomputation and the branch to every instruction case."""
    classified = []
    for entry in rows:
        row, source = entry["row"], entry["source"]
        data_hex = source.get("data_hex")
        records = row.get("online_raw_records_hex")
        item = {
            "receipt_index": entry["index"],
            "case_id": row.get("case_id"),
            "candidate_id": row.get("candidate_id"),
            "status": row.get("status"),
            "disposition": row.get("candidate_disposition"),
            "disposition_reason": row.get("candidate_disposition_reason"),
            "operator_id": row.get("operator_id"),
            "source_id": row.get("source_id"),
            "action_id": source.get("action_id"),
            "component": source.get("component"),
            "address": source.get("address"),
            "data_hex": data_hex if isinstance(data_hex, str) else None,
            "raw_hex": None, "reproduced_hex": None, "reproducible": False,
            "branch": None, "claimed_operator": False,
            "reason": None,
        }
        claimed = (item["operator_id"] == ARM_OPERATORS["insert"]
                   or (item["operator_id"] == ARM_OPERATORS["delete"]
                       and isinstance(data_hex, str) and len(data_hex) == 8))
        item["claimed_operator"] = bool(claimed)
        if not isinstance(records, list) or len(records) != 1 \
                or not isinstance(records[0], str):
            item["reason"] = "online_raw_records_hex 不是单条 8 字节记录"
            classified.append(item)
            continue
        try:
            raw = bytes.fromhex(records[0])
        except ValueError:
            item["reason"] = "online_raw_records_hex 不是十六进制"
            classified.append(item)
            continue
        item["raw_hex"] = raw.hex()
        if len(raw) != SEED_RECORD_BYTES:
            item["reason"] = "raw 记录不是 8 字节"
            classified.append(item)
            continue
        reproduced = _reproduce(decoder, data_hex or "", raw)
        item["reproduced_hex"] = reproduced
        item["reproducible"] = bool(reproduced is not None
                                    and reproduced == item["data_hex"])
        if item["reproducible"]:
            item["branch"] = _branch_of(_entropy_of(raw), item["data_hex"],
                                        decoder)
        classified.append(item)
    return classified


def _discover_replay_logs(run: Path, explicit: Path | None) -> tuple[list[Path], str]:
    if explicit is not None:
        path = Path(explicit)
        if not path.is_file():
            return [], f"显式指定的 fresh replay 日志不存在：{path}"
        return [path], ""
    parent = run.parent
    stem = run.name[:-len("-online")] if run.name.endswith("-online") else run.name
    found = set()
    for pattern in (f"{run.name}-replay.log", f"{run.name}-replay.json",
                    f"{run.name}_replay.log", f"{run.name}*replay*.log",
                    f"{run.name}*replay*.json", f"{stem}*replay*.log",
                    f"{stem}*replay*.json"):
        found.update(path for path in parent.glob(pattern) if path.is_file())
    return sorted(found), ""


def _replay_verdict(text: str) -> bool | None:
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        matches = re.findall(r'"matches"\s*:\s*(true|false)', text)
        if not matches:
            return None
        return matches[-1] == "true"
    if isinstance(document, Mapping) and isinstance(document.get("matches"), bool):
        return document["matches"]
    return None


def _criterion_seed(run: Path, receipts: list) -> dict:
    """(C1) the declared raw was the run's seed and reached the decoder."""
    path = run / "seed.bin"
    try:
        seed = path.read_bytes()
    except OSError as exc:
        return _criterion("missing", f"缺少 seed.bin：{type(exc).__name__}: {exc}")
    arm = next((name for name, raw in DECLARED_RAWS.items()
                if bytes.fromhex(raw) == seed), None)
    submitted = sorted({raw for row in receipts
                        if isinstance(row, Mapping)
                        for raw in (row.get("online_raw_records_hex") or [])
                        if isinstance(raw, str)})
    detail = {"seed_hex": seed.hex(), "arm": arm,
              "submitted_raws": submitted[:8],
              "submitted_raw_count": len(submitted)}
    if arm is None:
        return _criterion(
            "unproven",
            f"seed.bin={seed.hex()} 不是本门禁声明的三类 raw（"
            f"{', '.join(DECLARED_RAWS.values())}）：该运行不是准备好的确定性注入实验",
            **detail)
    if seed.hex() not in submitted:
        return _criterion(
            "refuted",
            f"seed.bin 等于声明的 {arm} raw，但 receipts.jsonl 中没有任何一例的 "
            "online_raw_records_hex 等于它：注入未到达在线解码器",
            **detail)
    return _criterion(
        "proven",
        f"seed.bin 等于声明的 {arm} raw={seed.hex()}，且该 raw 作为一例的 "
        "online_raw_records_hex 出现在 receipts.jsonl 中",
        **detail)


def _criterion_operator(classified: list[dict], manifest_identity: str,
                        seed_criterion: Mapping,
                        allow_unseeded: bool) -> dict:
    """(C2) an admitted case carried a declared inserted/deleted fragment."""
    if manifest_identity == "foreign":
        return _criterion(
            "unproven",
            "运行自身保存的 decoder_manifest.json 与 shipped Ibex 在线声明不一致："
            "其片段无法归因到冻结的 shipped 算子")
    claimed = [item for item in classified if item["claimed_operator"]]
    unreproducible_claims = [item for item in claimed if not item["reproducible"]]
    if unreproducible_claims:
        item = unreproducible_claims[0]
        return _criterion(
            "refuted",
            f"该运行声称携带序列编辑片段（case_id={item['case_id']}，"
            f"operator_id={item['operator_id']}，data_hex={item['data_hex']}），"
            f"但用该例自己的 raw={item['raw_hex']} 经 shipped "
            f"decode_instruction_fragment 复算得到 {item['reproduced_hex']}："
            "回执身份与冻结算子不符",
            case_id=item["case_id"], action_id=item["action_id"],
            candidate_id=item["candidate_id"])
    candidates = [item for item in classified
                  if item["reproducible"] and item["branch"] in EDIT_ARMS]
    seed_arm = seed_criterion.get("arm")
    detail = {
        "attributable_counts": {
            arm: sum(1 for item in candidates if item["branch"] == arm)
            for arm in EDIT_ARMS},
        "seed_arm": seed_arm,
        "declared_raw_case_counts": {
            arm: sum(1 for item in classified if item["raw_hex"] == raw)
            for arm, raw in DECLARED_RAWS.items()},
    }
    if seed_arm in EDIT_ARMS and not allow_unseeded:
        chosen = next((item for item in candidates
                       if item["raw_hex"] == DECLARED_RAWS[seed_arm]), None)
        if chosen is None:
            return _criterion(
                "refuted",
                f"声明的 {seed_arm} raw 已被提交，但没有产生携带该片段的指令例："
                "该例的源选择或接纳未按准备好的实验发生",
                **detail)
    else:
        chosen = next((item for item in candidates
                       if item["raw_hex"] == DECLARED_RAWS[item["branch"]]),
                      candidates[0] if candidates else None)
        if chosen is None:
            return _criterion(
                "unproven",
                "没有任何一例携带 insert(12B=LUI+XORI+ADDI) 或 delete(4B=LUI) "
                "片段：运行窗口内在线 RFuzz 未触及该算子",
                **detail)
    if chosen["status"] != "complete":
        return _criterion(
            "refuted",
            f"携带 {chosen['branch']} 片段的一例 status={chosen['status']}，"
            "不是完整运行的一例",
            case_id=chosen["case_id"], action_id=chosen["action_id"], **detail)
    if chosen["disposition"] not in (None, "admitted"):
        return _criterion(
            "refuted",
            f"携带 {chosen['branch']} 片段的一例 candidate_disposition="
            f"{chosen['disposition']}"
            f"（{chosen['disposition_reason']}）：该片段未被接纳",
            case_id=chosen["case_id"], action_id=chosen["action_id"], **detail)
    return _criterion(
        "proven",
        f"case_id={chosen['case_id']} 携带 {chosen['branch']} 片段 "
        f"{chosen['data_hex']}（{ARM_LENGTHS[chosen['branch']]} 字节，"
        f"{chosen['operator_id']}），由该例自己的 raw={chosen['raw_hex']} "
        "经 shipped 算子复算一致，且已接纳",
        arm=chosen["branch"], case_id=chosen["case_id"],
        action_id=chosen["action_id"], candidate_id=chosen["candidate_id"],
        address=chosen["address"], fragment_hex=chosen["data_hex"],
        raw_hex=chosen["raw_hex"], operator_id=chosen["operator_id"],
        declared_raw=(chosen["raw_hex"] == DECLARED_RAWS[chosen["branch"]]),
        **detail)


def _plan_lookup(plan: Mapping) -> dict:
    """The plan's instruction-case and admission rows indexed by case identity."""
    lookup = {"cases": {}, "admissions": {}, "supports": {}}
    for index, case in enumerate(plan.get("cases") or ()):
        if not isinstance(case, Mapping):
            continue
        source = case.get("source")
        if isinstance(source, Mapping) and isinstance(source.get("action_id"), str):
            lookup["cases"][source["action_id"]] = {"index": index, "case": case}
        for support in case.get("support_instructions") or ():
            if isinstance(support, Mapping) and isinstance(
                    support.get("action_id"), str):
                lookup["supports"][support["action_id"]] = case
    registry = plan.get("source_admissions")
    rows = registry.get("admissions") if isinstance(registry, Mapping) else None
    for row in rows or ():
        if isinstance(row, Mapping) and isinstance(row.get("action_id"), str):
            lookup["admissions"][row["action_id"]] = row
    return lookup


def _scan_trace(events: Sequence, focus: Sequence[dict]) -> dict:
    """One pass over the run's events, keeping only the focused identities."""
    words = {}
    for case in focus:
        fragment = bytes.fromhex(case["fragment_hex"])
        for index in range(len(fragment) // 4):
            words[(case["address"] + 4 * index, index)] = case
    actions = {case["action_id"]: case for case in focus}
    admissions = {case.get("admission_id"): case for case in focus
                  if case.get("admission_id")}
    seen = {"retirement_matches": 0, "instruction_source": {}, "admissions": {},
            "memory_read": {}, "instr_response": {}}
    memory_targets = {address for address, _ in words}
    for event in events:
        if not isinstance(event, Mapping):
            continue
        kind = event.get("kind")
        if kind == "cpu_retirement_match":
            seen["retirement_matches"] += 1
            refs = event.get("source_refs")
            pc = event.get("pc")
            if (isinstance(refs, list) and any(ref in actions for ref in refs)) \
                    or pc in memory_targets:
                seen.setdefault("retirements", []).append(event)
        elif kind == "instruction_source":
            action = event.get("source_event_id")
            if action in actions:
                seen["instruction_source"][action] = event
        elif kind == "source_admission":
            admission = event.get("admission")
            action = admission.get("action_id") if isinstance(admission,
                                                              Mapping) else None
            if action in actions:
                seen["admissions"][action] = event
        elif kind == "memory_read":
            transaction = event.get("transaction")
            address = event.get("address")
            if (isinstance(transaction, Mapping)
                    and transaction.get("channel_id") == "instr"
                    and address in memory_targets):
                seen["memory_read"].setdefault(address, []).append(event)
        elif kind == "instr_response":
            address = event.get("address")
            if address in memory_targets:
                seen["instr_response"].setdefault(address, []).append(event)
    return seen


def _word_identity(event: Mapping, action_id: str) -> bool:
    provenance = event.get("provenance")
    resource = provenance.get("resource") if isinstance(provenance, Mapping) else None
    refs = resource.get("writer_event_ids") if isinstance(resource, Mapping) else None
    kinds = resource.get("writer_kinds") if isinstance(resource, Mapping) else None
    if not isinstance(refs, list) or not refs or not isinstance(kinds, list):
        return False
    return set(refs) == {action_id} and set(kinds) == {"INSTRUCTION_SOURCE"}


def _criterion_fetch(case: Mapping, seen: Mapping) -> dict:
    """(C3) every fragment word appears in real instruction-fetch evidence."""
    action_id = case["action_id"]
    fragment = bytes.fromhex(case["fragment_hex"])
    address = case["address"]
    words = [fragment[i:i + 4] for i in range(0, len(fragment), 4)]
    materialized = seen["instruction_source"].get(action_id)
    admission_event = seen["admissions"].get(action_id)
    if admission_event is None:
        return _criterion(
            "unproven",
            f"trace 中没有该 case（action_id={action_id}）的 source_admission "
            "事件：接纳身份无法与运行自身证据对齐",
            words=len(words))
    if materialized is None or materialized.get("address") != address \
            or materialized.get("data_hex") != case["fragment_hex"]:
        return _criterion(
            "unproven",
            f"trace 中没有把该 case 的 {len(fragment)} 字节片段物化到 "
            f"{hex(address)} 的 instruction_source 事件",
            words=len(words))
    covered = 0
    kinds_used = set()
    evidence = []
    for index, word in enumerate(words):
        offset = address + 4 * index
        found = None
        for event in seen["memory_read"].get(offset, ()):
            if event.get("data_hex") == word.hex() \
                    and _word_identity(event, action_id):
                found = ("memory_read", event.get("event_id"))
                break
        if found is None:
            for event in seen["instr_response"].get(offset, ()):
                snapshot = event.get("snapshot")
                rdata = event.get("rdata")
                refs = snapshot.get("writer_event_ids") \
                    if isinstance(snapshot, Mapping) else None
                if rdata == int.from_bytes(word, "little") \
                        and isinstance(refs, list) and set(refs) == {action_id}:
                    found = ("instr_response", event.get("event_id"))
                    break
        if found is None:
            conflicting = (list(seen["memory_read"].get(offset, ()))
                           + list(seen["instr_response"].get(offset, ())))
            for event in conflicting:
                data = event.get("data_hex")
                if event.get("kind") == "instr_response":
                    data = (event.get("snapshot") or {}).get("data_hex") \
                        if isinstance(event.get("snapshot"), Mapping) else None
                if isinstance(data, str) and data != word.hex():
                    return _criterion(
                        "refuted",
                        f"片段字 {index}（{hex(offset)}）在运行自身证据中是 "
                        f"{data} 而不是 {word.hex()}：取指字节与回执片段不符",
                        word_index=index, address=offset, observed=data,
                        expected=word.hex())
            continue
        covered += 1
        kinds_used.add(found[0])
        evidence.append({"word_index": index, "address": offset,
                         "word_hex": word.hex(), "event_kind": found[0],
                         "event_id": found[1]})
    if covered != len(words):
        return _criterion(
            "unproven",
            f"片段 {len(words)} 个字中只有 {covered} 个出现在真实取指证据中"
            "（窗口内未取指或未观测）",
            words=len(words), covered=covered,
            missing=[index for index in range(len(words))
                     if index not in {row["word_index"] for row in evidence}])
    return _criterion(
        "proven",
        f"片段 {len(words)} 个字全部出现在运行自身的指令通道取指证据中，"
        f"writer 身份为 {action_id}",
        words=len(words), covered=covered,
        event_kinds=sorted(kinds_used),
        materialization_event_id=materialized.get("event_id"),
        admission_event_id=admission_event.get("event_id"),
        evidence=evidence)


def _criterion_retirement(case: Mapping, seen: Mapping) -> dict:
    """(C4) every fragment word retires under the authenticated RVFI view."""
    if not seen["retirement_matches"]:
        return _criterion(
            "unproven",
            "该运行的 trace 中没有任何 cpu_retirement_match 事件：本运行未开启 "
            "RVFI 退休观测，片段退休无法证明（请用 --cpu-retirement 重跑）")
    action_id = case["action_id"]
    fragment = bytes.fromhex(case["fragment_hex"])
    address = case["address"]
    words = [fragment[i:i + 4] for i in range(0, len(fragment), 4)]
    retirements = seen.get("retirements", ())
    covered = 0
    evidence = []
    for index, word in enumerate(words):
        offset = address + 4 * index
        insn = int.from_bytes(word, "little")
        conflicting = None
        for event in retirements:
            if event.get("pc") != offset:
                continue
            refs = event.get("source_refs")
            if event.get("insn") == insn and isinstance(refs, list) \
                    and refs == [action_id] \
                    and event.get("status") == "accepted" \
                    and event.get("instruction_origin_status") == "typed_writer_refs":
                covered += 1
                evidence.append({"word_index": index, "pc": offset,
                                 "insn": event.get("insn"), "order":
                                     event.get("order"),
                                 "event_id": event.get("event_id")})
                conflicting = None
                break
            conflicting = event
        if conflicting is not None and conflicting.get("insn") != insn:
            return _criterion(
                "refuted",
                f"片段字 {index}（pc={hex(offset)}）的退休观测是 insn="
                f"{conflicting.get('insn'):#010x} 而不是 {insn:#010x}："
                "该片段字未被退休",
                word_index=index, pc=offset, observed=conflicting.get("insn"),
                expected=insn)
    if covered != len(words):
        return _criterion(
            "unproven",
            f"片段 {len(words)} 个字中只有 {covered} 个有该 case 的 accepted "
            "typed 退休观测（窗口内未退休或证据不足）",
            words=len(words), covered=covered)
    return _criterion(
        "proven",
        f"片段 {len(words)} 个字全部以 status=accepted、"
        f"instruction_origin_status=typed_writer_refs、source_refs=[{action_id}] "
        "的身份退休，pc/insn 与片段逐字相等",
        words=len(words), covered=covered, evidence=evidence)


def _criterion_boundary(plan: Mapping, manifest: Mapping, case: Mapping | None) -> dict:
    """(C5) no admitted fragment crossed the declared instruction end."""
    slots = plan.get("instruction_slots")
    cases = plan.get("cases")
    if not isinstance(slots, list) or not slots or not isinstance(cases, list):
        return _criterion("missing",
                          "online_plan.json 缺少 instruction_slots 或 cases："
                          "保留区边界不可复算")
    component = (case or {}).get("component") or "cpu"
    slot = next((row for row in slots if isinstance(row, list) and len(row) == 3
                 and row[0] == component), None)
    if slot is None:
        return _criterion("missing",
                          f"online_plan.json 没有组件 {component} 的指令保留区声明")
    start, reserved_words = slot[1], slot[2]
    if not isinstance(start, int) or not isinstance(reserved_words, int):
        return _criterion("missing", "instruction_slots 的起始地址或字数不是整数")
    end = start + 4 * reserved_words
    declared_start = manifest.get("instruction_start")
    declared_end = manifest.get("instruction_end")
    if declared_start != start or declared_end != end:
        return _criterion(
            "refuted",
            f"plan 的保留区 [{hex(start)},{hex(end)}) 与 decoder_manifest.json "
            f"声明的 [{declared_start!r},{declared_end!r}) 不一致",
            reservation={"start": start, "end": end})
    cursor = start
    admitted = 0
    for index, case_row in enumerate(cases):
        if not isinstance(case_row, Mapping):
            return _criterion("missing", f"plan case {index} 不是对象")
        source = case_row.get("source") or {}
        if source.get("kind") == "instruction":
            address, data_hex = source.get("address"), source.get("data_hex")
            if not isinstance(address, int) or not isinstance(data_hex, str):
                return _criterion("missing",
                                  f"plan case {index} 的指令源缺少地址或字节")
            length = len(data_hex) // 2
            if address != cursor:
                return _criterion(
                    "refuted",
                    f"plan case {index} 的片段地址 {hex(address)} 不等于保留区游标 "
                    f"{hex(cursor)}：接纳序列与游标推进不一致",
                    case_index=index, cursor=cursor, address=address)
            if address + length > end:
                return _criterion(
                    "refuted",
                    f"plan case {index} 的 {length} 字节片段越过声明的 "
                    f"instruction_end={hex(end)}：{hex(address)}+{length}",
                    case_index=index, address=address, length=length, end=end)
            cursor += length
            admitted += length
        for support in case_row.get("support_instructions") or ():
            if not isinstance(support, Mapping):
                return _criterion("missing", f"plan case {index} 的 support 不是对象")
            address, data_hex = support.get("address"), support.get("data_hex")
            if not isinstance(address, int) or not isinstance(data_hex, str):
                return _criterion("missing",
                                  f"plan case {index} 的 support 缺少地址或字节")
            length = len(data_hex) // 2
            if address != cursor:
                return _criterion(
                    "refuted",
                    f"plan case {index} 的固定支撑片段地址 {hex(address)} 不等于"
                    f"游标 {hex(cursor)}",
                    case_index=index, cursor=cursor, address=address)
            if address + length > end:
                return _criterion(
                    "refuted",
                    f"plan case {index} 的支撑片段越过 instruction_end={hex(end)}",
                    case_index=index, address=address, length=length, end=end)
            cursor += length
            admitted += length
    if admitted > 4 * reserved_words:
        return _criterion(
            "refuted",
            f"累计接纳 {admitted} 字节超过保留区 {4 * reserved_words} 字节",
            admitted=admitted, reserved=4 * reserved_words)
    return _criterion(
        "proven",
        f"逐例游标走查通过：保留区 [{hex(start)},{hex(end)})，接纳 {admitted} 字节，"
        f"没有片段越过 instruction_end",
        reservation={"start": start, "end": end, "component": component},
        admitted_bytes=admitted, reserved_bytes=4 * reserved_words,
        final_cursor=cursor)


def _criterion_replay(run: Path, explicit: Path | None) -> dict:
    """(C6) a fresh-replay log next to the run, when present, matches."""
    logs, refusal = _discover_replay_logs(run, explicit)
    if refusal:
        return _criterion("missing", refusal)
    if not logs:
        return _criterion(
            "not_applicable",
            "运行旁未发现 fresh replay 日志：本项不作为 PASS 的证明，也不据此判失败",
            logs=[])
    reports = []
    for path in logs:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            return _criterion("refuted",
                              f"fresh replay 日志不可读：{path}：{exc}")
        verdict = _replay_verdict(text)
        reports.append({"path": path.name, "matches": verdict})
        if verdict is False:
            return _criterion(
                "refuted",
                f"fresh replay 日志 {path.name} 报告 matches=false："
                "新 RTL 重放与保存证据不一致",
                logs=reports)
        if verdict is None:
            return _criterion(
                "refuted",
                f"fresh replay 日志 {path.name} 没有可解析的 matches 字段",
                logs=reports)
    return _criterion(
        "proven",
        "fresh replay 日志报告 matches=true：" + ", ".join(
            row["path"] for row in reports),
        logs=reports)


def verify_run(run: Path, *, replay_log: Path | None = None,
               allow_unseeded: bool = False) -> tuple[dict, int]:
    """Verify one run directory; returns the document and its exit code."""
    run = Path(run)
    document = {
        "schema_version": "p4_sequence_edit_gate_verify.v1",
        "executes_rtl": False,
        "run_dir": str(run),
        "declared_raws": dict(DECLARED_RAWS),
        "verdict": None,
        "exit_code": None,
        "reasons": [],
        "criteria": {},
        "joins": {},
        "artifacts": {},
        "notes": [],
    }
    required = {
        "receipts": run / "receipts.jsonl",
        "plan": run / "online_plan.json",
        "manifest": run / "decoder_manifest.json",
        "report": run / "report.json",
        "seed": run / "seed.bin",
    }
    missing = [f"{key}（{path.name}）" for key, path in required.items()
               if not path.is_file()]
    if not run.is_dir():
        missing = [f"运行目录不存在：{run}"]
    trace_path, trace_format, trace_refusal = _resolve_trace(run)
    if trace_path is None:
        missing.append(f"trace（{trace_refusal}）")
    if missing:
        reason = "必需产物缺失： " + "; ".join(missing)
        for name in CRITERIA:
            document["criteria"][name] = _criterion("missing", reason)
        document["reasons"].append(reason)
        document.update(verdict="BLOCKED", exit_code=EXIT_BLOCKED)
        return document, EXIT_BLOCKED

    receipts_document, receipts_error = None, None
    receipts = []
    try:
        with required["receipts"].open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    receipts.append(json.loads(line))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        receipts_error = f"{type(exc).__name__}: {exc}"
    plan, plan_error = _read_json(required["plan"])
    manifest, manifest_error = _read_json(required["manifest"])
    report, report_error = _read_json(required["report"])
    broken = [f"{key}（{path.name}）：{error}" for key, path, error in (
        ("receipts", required["receipts"], receipts_error),
        ("plan", required["plan"], plan_error),
        ("manifest", required["manifest"], manifest_error),
        ("report", required["report"], report_error)) if error]
    if broken or not isinstance(plan, Mapping) or not isinstance(manifest, Mapping) \
            or not isinstance(report, Mapping):
        reason = "必需产物不可解析： " + "; ".join(broken or ["plan/manifest/report 不是对象"])
        for name in CRITERIA:
            document["criteria"][name] = _criterion("missing", reason)
        document["reasons"].append(reason)
        document.update(verdict="BLOCKED", exit_code=EXIT_BLOCKED)
        return document, EXIT_BLOCKED

    document["artifacts"] = {
        "receipts": {"file": "receipts.jsonl", "rows": len(receipts),
                     "sha256": _file_sha256(required["receipts"])},
        "plan": {"file": "online_plan.json", "cases": len(plan.get("cases") or ()),
                 "sha256": _file_sha256(required["plan"])},
        "decoder_manifest": {"file": "decoder_manifest.json",
                             "sha256": _file_sha256(required["manifest"])},        "report": {"file": "report.json",
                   "execution_status": report.get("execution_status"),
                   "session_status": report.get("session_status"),
                   "client_returncode": report.get("client_returncode"),
                   "sha256": _file_sha256(required["report"])},
        "seed": {"file": "seed.bin",
                 "sha256": _file_sha256(required["seed"])},
        "trace": {"file": trace_path.name, "format": trace_format,
                  "sha256": _file_sha256(trace_path)},
    }

    # The run's own declaration must be a shipped declaration before any
    # fragment can be attributed to the frozen operator.
    shipped = {"runtime": shipped_decoder(readback=True).document(),
               "default": shipped_decoder().document()}
    identity = "foreign"
    for name, version in shipped.items():
        if _canonical(manifest) == _canonical(version):
            identity = "shipped_runtime" if name == "runtime" else "shipped_default"
            break
    document["artifacts"]["decoder_manifest"]["identity"] = identity
    document["artifacts"]["decoder_manifest"]["is_shipped_declaration"] = \
        identity != "foreign"
    if identity == "foreign":
        document["notes"].append(
            "decoder_manifest.json 不是当前 shipped 声明：算子归因不可判定")

    run_decoder = shipped_decoder(readback=(identity == "shipped_runtime"))
    try:
        rebuilt = OnlineCaseDecoder.from_document(manifest)
        run_decoder = rebuilt
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        document["notes"].append(
            f"无法用运行自身 manifest 重建解码器（{type(exc).__name__}）："
            "片段复算回退到 shipped 声明")

    classified = _classify_rows(_instruction_rows(receipts), run_decoder)
    document["cases"] = {
        "instruction_rows": len(classified),
        "reproducible_rows": sum(1 for item in classified if item["reproducible"]),
        "unreproducible_rows": sum(1 for item in classified
                                   if not item["reproducible"]),
        "branch_counts": {arm: sum(1 for item in classified
                                   if item["branch"] == arm)
                          for arm in ("insert", "delete", "base")},
        "declared_raw_rows": {arm: [item["case_id"] for item in classified
                                    if item["raw_hex"] == raw]
                              for arm, raw in DECLARED_RAWS.items()},
    }

    incomplete_run = (report.get("execution_status") not in ("complete", None)
                      or report.get("session_status") not in ("complete", None))

    seed_criterion = _criterion_seed(run, receipts)
    if allow_unseeded and seed_criterion["status"] == "unproven":
        # The prepared experiment seeds a declared raw; --allow-unseeded audits
        # a run that found its operator case by search instead, so that one
        # criterion is not evaluated rather than counted as missing.
        seed_criterion = _criterion(
            "not_applicable",
            "使用 --allow-unseeded：本运行不是声明的播种实验，确定性注入判据"
            "不计入 PASS 条件（" + seed_criterion["reason"] + "）",
            **{key: value for key, value in seed_criterion.items()
               if key not in ("status", "reason")})
    operator_criterion = _criterion_operator(classified, identity, seed_criterion,
                                             allow_unseeded)

    events, events_error = _event_sequence(trace_path, trace_format)
    if events is None:
        reason = f"trace 不可读：{events_error}"
        document["criteria"] = {name: _criterion("missing", reason)
                                for name in CRITERIA}
        document["reasons"].append(reason)
        document.update(verdict="BLOCKED", exit_code=EXIT_BLOCKED)
        return document, EXIT_BLOCKED

    plan_lookup = _plan_lookup(plan)
    focus = []
    if operator_criterion["status"] == "proven":
        focus.append({
            "case_id": operator_criterion["case_id"],
            "action_id": operator_criterion["action_id"],
            "address": operator_criterion["address"],
            "fragment_hex": operator_criterion["fragment_hex"],
            "admission_id": None,
            "component": _source_component(plan_lookup, operator_criterion),
        })
    admission_digest_ok = True
    admission_id = None
    input_digest_ok = None
    admission_row = None
    if focus:
        action = focus[0]["action_id"]
        admission_row = plan_lookup["admissions"].get(action)
        case_row = plan_lookup["cases"].get(action)
        if admission_row is None or case_row is None:
            operator_criterion.update(
                status="refuted",
                reason=(f"该 case（action_id={action}）在 online_plan.json 的 "
                        "cases/source_admissions 中没有对应行：回执与计划身份不符"))
        else:
            try:
                SourceAdmission.from_document(admission_row)
            except (TypeError, ValueError) as exc:
                admission_digest_ok = False
                operator_criterion.update(
                    status="refuted",
                    reason=f"计划的接纳行自身不一致：{type(exc).__name__}: {exc}")
            admission_id = admission_row.get("admission_id")
            focus[0]["admission_id"] = admission_id
            expected_input = _canonical_sha256({
                "action_id": action, "component": "cpu",
                "address": focus[0]["address"],
                "data_hex": focus[0]["fragment_hex"], "kind": "instruction"})
            input_digest_ok = (admission_row.get("input_sha256") == expected_input)
            if input_digest_ok is False:
                operator_criterion.update(
                    status="refuted",
                    reason=("计划接纳行的 input_sha256 与该 case 回执片段不符："
                            "接纳身份与片段字节不一致"))
            if admission_row.get("case_id") != focus[0]["case_id"]:
                operator_criterion.update(
                    status="refuted",
                    reason="计划接纳行的 case_id 与回执不一致")
            if not _same_fragment(plan_lookup["cases"][action]["case"],
                                  focus[0]):
                operator_criterion.update(
                    status="refuted",
                    reason=("online_plan.json 的 case 片段与 receipts.jsonl "
                            "的片段不一致"))

    seen = _scan_trace(events, focus) if focus else {
        "retirement_matches": 0, "instruction_source": {}, "admissions": {},
        "memory_read": {}, "instr_response": {}}
    fetch_criterion = (_criterion_fetch(focus[0], seen) if focus
                       else _criterion("unproven",
                                       "没有可归因的 insert/delete case，"
                                       "取指判据不适用"))
    retirement_criterion = (_criterion_retirement(focus[0], seen) if focus
                            else _criterion("unproven",
                                            "没有可归因的 insert/delete case，"
                                            "退休判据不适用"))
    boundary_criterion = _criterion_boundary(plan, manifest, focus[0] if focus
                                             else None)
    replay_criterion = _criterion_replay(run, replay_log)

    if incomplete_run:
        # A run that did not finish cannot support any positive claim.
        for criterion in (operator_criterion, fetch_criterion,
                          retirement_criterion):
            if criterion["status"] == "proven":
                criterion.update(
                    status="unproven",
                    reason=("运行未正常结束（report.execution_status="
                            f"{report.get('execution_status')!r}，session_status="
                            f"{report.get('session_status')!r}），"
                            "该判据不作为证明"))

    document["criteria"] = {
        "deterministic_seed_injection": seed_criterion,
        "operator_case_admitted": operator_criterion,
        "fragment_fetch_evidence": fetch_criterion,
        "fragment_retirement_evidence": retirement_criterion,
        "reservation_boundary": boundary_criterion,
        "fresh_replay_matches": replay_criterion,
    }
    document["joins"] = {
        "admission": {
            "plan_row_found": admission_row is not None,
            "admission_id_authenticated": admission_digest_ok,
            "input_sha256_recomputed": input_digest_ok,
            "admission_id": admission_id,
            "rule": ("input_sha256 = sha256(canonical({action_id,component,"
                     "address,data_hex,kind='instruction'}))，见 "
                     "session_runtime._case_admissions；admission_id 由 shipped "
                     "SourceAdmission 校验"),
        },
        "fetch": {
            "event_kind": fetch_criterion.get("event_kinds", []),
            "channel_id": "instr",
            "writer_kind": "INSTRUCTION_SOURCE",
            "rule": ("memory_read(transaction.channel_id='instr',address,data_hex,"
                     "provenance.resource.writer_event_ids/writer_kinds) 或 "
                     "instr_response(address,rdata,snapshot.writer_event_ids)"),
            "citation": ("src/myfuzz/scenario/memory_service.py:accept_instructions/"
                         "read；src/myfuzz/scenario/chain_certificates.py 的 "
                         "instruction_fetch 跳"),
        },
        "retirement": {
            "event_kind": "cpu_retirement_match",
            "origin_status": "typed_writer_refs",
            "rule": ("status='accepted' 且 instruction_origin_status="
                     "'typed_writer_refs' 且 source_refs==[action_id] 且 "
                     "pc/insn 等于片段字"),
            "citation": ("src/myfuzz/scenario/cpu_retirement.py:_retire_witness/"
                         "_sources"),
        },
        "boundary": {
            "rule": ("online_plan.json instruction_slots 起点/字数 + cases 的 "
                     "source/support 逐例游标，对照 decoder_manifest.json 的 "
                     "instruction_start/instruction_end"),
        },
    }
    statuses = [criterion["status"] for criterion in document["criteria"].values()]
    if "refuted" in statuses:
        verdict, code = "FAIL", EXIT_FAIL
    elif "missing" in statuses:
        verdict, code = "BLOCKED", EXIT_BLOCKED
    elif "unproven" in statuses:
        verdict, code = "INCONCLUSIVE", EXIT_INCONCLUSIVE
    else:
        verdict, code = "PASS", EXIT_PASS
    document["reasons"] = [
        f"{name}[{criterion['status']}]: {criterion['reason']}"
        for name, criterion in document["criteria"].items()
        if criterion["status"] not in ("proven", "not_applicable")]
    if not document["reasons"]:
        document["reasons"] = ["六个判据全部 proven"]
    document.update(verdict=verdict, exit_code=code)
    return document, code


def _source_component(plan_lookup: Mapping, criterion: Mapping) -> str:
    """The instruction source's component, from the plan's own case row."""
    entry = plan_lookup["cases"].get(criterion["action_id"]) or {}
    source = (entry.get("case") or {}).get("source") or {}
    component = source.get("component")
    return component if isinstance(component, str) and component else "cpu"


def _same_fragment(plan_case: Mapping, focus: Mapping) -> bool:
    source = plan_case.get("source") or {}
    return (source.get("data_hex") == focus["fragment_hex"]
            and source.get("address") == focus["address"])


def render_verification(document: Mapping) -> str:
    """The human-readable verdict with the per-criterion reasons."""
    lines = [f"P4 序列编辑真实门禁 verify：{document['verdict']} "
             f"(exit {document['exit_code']})",
             f"运行目录：{document['run_dir']}"]
    if document.get("artifacts"):
        artifacts = document["artifacts"]
        lines.append("产物： " + ", ".join(
            f"{key}={value.get('file')}" for key, value in artifacts.items()))
        manifest = artifacts.get("decoder_manifest") or {}
        lines.append(f"解码声明身份：{manifest.get('identity')}")
        cases = document.get("cases") or {}
        if cases:
            lines.append(f"指令回执行：{cases.get('instruction_rows')}；"
                         f"可复算：{cases.get('reproducible_rows')}；"
                         f"分支计数：{cases.get('branch_counts')}")
    lines.append("判据：")
    for name, criterion in document["criteria"].items():
        lines.append(f"  [{criterion['status']}] {name}: {criterion['reason']}")
    if document.get("notes"):
        lines.append("备注：")
        lines.extend(f"  - {note}" for note in document["notes"])
    lines.append("本脚本未运行任何 RTL/Verilator/Rust/fuzz 作业。")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan", help="print the prepared gate (read-only)")
    plan.add_argument("--runs-dir", type=Path, default=ROOT / "runs")
    plan.add_argument("--client-binary", default=CLIENT_BINARY)
    plan.add_argument("--cache-dir", type=Path)
    plan.add_argument("--seconds", type=float, default=25.0)
    plan.add_argument("--max-tests", type=int, default=8)
    plan.add_argument("--search-seed", type=int, default=20261008)
    plan.add_argument("--write", type=Path)
    verify = commands.add_parser("verify", help="verify one run directory")
    verify.add_argument("--run", type=Path, required=True)
    verify.add_argument("--replay-log", type=Path)
    verify.add_argument("--allow-unseeded", action="store_true",
                        help="accept any attributable insert/delete case, not "
                             "only a case carrying a declared raw")
    verify.add_argument("--write", type=Path)
    args = parser.parse_args(argv)
    if args.command == "plan":
        document = plan_document(runs_dir=args.runs_dir,
                                 client_binary=args.client_binary,
                                 cache_dir=args.cache_dir, seconds=args.seconds,
                                 max_tests=args.max_tests,
                                 search_seed=args.search_seed)
        print(render_plan(document))
        print(DOCUMENT_MARKER)
        print(json.dumps(document, indent=1, sort_keys=True, ensure_ascii=False))
        if args.write is not None:
            args.write.write_text(
                json.dumps(document, indent=1, sort_keys=True,
                           ensure_ascii=False) + "\n", encoding="utf-8")
        return EXIT_PASS
    document, code = verify_run(args.run, replay_log=args.replay_log,
                                allow_unseeded=args.allow_unseeded)
    print(render_verification(document))
    print(DOCUMENT_MARKER)
    print(json.dumps(document, indent=1, sort_keys=True, ensure_ascii=False))
    if args.write is not None:
        args.write.write_text(
            json.dumps(document, indent=1, sort_keys=True,
                       ensure_ascii=False) + "\n", encoding="utf-8")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
