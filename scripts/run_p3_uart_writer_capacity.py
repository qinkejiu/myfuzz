#!/usr/bin/env python3
"""Directed real RTL UART-seeded host RAM writer and late LW readback gate.

The fixed warmup supplies UART RDATA to x3. A legal online RV32I fragment
then executes repeated SW x3, 0(x5) through Ibex and MemoryService.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.integration.ibex_uart_online import (  # noqa: E402
    make_ibex_uart_online_runtime, _read_uart_online_trace)
from myfuzz.integration.scenario_rfuzz_live import _write_online_trace_zlib  # noqa: E402
from myfuzz.scenario.batch import BatchAdvance  # noqa: E402
from myfuzz.scenario.replay import ScenarioTrace  # noqa: E402
from myfuzz.scenario.session_runtime import OnlineCase, OnlineInstruction, replay_online_session  # noqa: E402
from myfuzz.scenario.ibex_uart_online_checker import IbexUartOnlineChecker  # noqa: E402
from myfuzz.scenario.ledger import TransactionKey  # noqa: E402


def _write(path, value):
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def _capacity_gate_passed(result):
    requested = result["stores_requested"]
    counts = result["counts"]
    return (
        requested > 256
        and result["trace_status"] == "complete"
        and bool(result["case_statuses"])
        and all(status == "running" for status in result["case_statuses"])
        and not result["violations"]
        and not result["readback_degraded"]
        and counts.get("memory_write_commit:", 0) >= requested
        and counts.get("uart_store_memory_match:accepted", 0) >= requested
        and result["distinct_writer_identities"] >= requested
        and 0 <= result["writer_cache_count"] <= 256
        and result["writer_cache_count"] < result["distinct_writer_identities"]
    )


_DATA_KEY_FIELDS = frozenset(("execution_id", "testcase_id", "source_component",
                              "source_epoch", "channel_id", "source_sequence"))


def _stream_data_key(key):
    return (type(key) is dict and set(key) == _DATA_KEY_FIELDS
            and key["execution_id"] == "local-execution"
            and key["testcase_id"] == "ibex-uart-online-stream"
            and key["source_component"] == "cpu" and key["channel_id"] == "data"
            and type(key["source_epoch"]) is int and key["source_epoch"] >= 0
            and type(key["source_sequence"]) is int and key["source_sequence"] >= 0)


def _first_lane_matches(event, identity):
    return (type(event.get("versions")) is list and len(event["versions"]) == 4
            and type(event.get("writer_event_ids")) is list
            and len(event["writer_event_ids"]) == 4
            and type(event.get("writer_kinds")) is list
            and len(event["writer_kinds"]) == 4
            and event["versions"][0] == identity[3]
            and event["writer_event_ids"][0] == identity[4]
            and event["writer_kinds"][0] == "STORE")


def _observed_case(event):
    provenance = event.get("provenance")
    return provenance.get("observed_case") if type(provenance) is dict else None


def _word_matches(data_hex, value):
    if (type(data_hex) is not str or len(data_hex) != 8
            or type(value) is not int or not 0 <= value <= 0xffffffff):
        return False
    try:
        return int.from_bytes(bytes.fromhex(data_hex), "little") == value
    except ValueError:
        return False


def _late_readback_evidence(events, load_pc):
    """Check the final certified writer against a later real read and RVFI LW."""
    indexed = list(enumerate(events))
    writers = [(i, e) for i, e in indexed
               if e.get("kind") == "uart_store_memory_match"
               and e.get("status") == "accepted"
               and type(e.get("store_order")) is int]
    if not writers:
        return {"passed": False, "reason": "missing_certified_writer"}
    writer_i, writer = max(writers, key=lambda item: item[1]["store_order"])
    identity = (writer.get("memory_id"), writer.get("generation"),
                writer.get("byte_offset"), writer.get("byte_version"),
                writer.get("writer_event_id"))
    store_key = writer.get("store_fullkey")
    source = writer.get("source_admission")
    observed_store = _observed_case(writer)
    case_match = (re.fullmatch(r"p3-directed-repeated-store-(\d+)",
                               observed_store.get("case_id", ""))
                  if type(observed_store) is dict
                  and type(observed_store.get("case_id")) is str else None)
    if (not _stream_data_key(store_key)
            or not case_match or type(observed_store.get("case_index")) is not int
            or observed_store["case_index"] != int(case_match.group(1)) + 1
            or type(load_pc) is not int or load_pc <= 0x11000 or load_pc % 4
            or identity[:3] != ("ram", 0, 65536)
            or type(identity[3]) is not list or len(identity[3]) != 2
            or identity[3][0] != identity[1]
            or identity[4] != str(TransactionKey(**store_key))
            or type(writer.get("byte_value")) is not int
            or not 0 <= writer["byte_value"] <= 255
            or writer.get("source_path_certified") is not True
            or type(source) is not dict
            or any(source.get(k) != v for k, v in {
                "case_id": "uart-fixed-warmup", "action_id": "uart-fixed-warmup-rx",
                "component": "uart", "source_id": "uart.external_rx_byte",
                "direction": "IP_TO_CPU", "input_kind": "source_event",
                "role": "bootstrap"}.items())):
        return {"passed": False, "reason": "invalid_final_writer_identity"}
    store_retires = [(i, e) for i, e in indexed[:writer_i]
                     if e.get("kind") == "cpu_retire"
                     and e.get("event_id") == writer.get("store_retirement_event_id")]
    if len(store_retires) != 1:
        return {"passed": False, "reason": "missing_final_store_retirement"}
    store_retire_i, store_retire = store_retires[0]
    store_physical = store_retire.get("observation", {}).get("physical", {})
    if (store_retire.get("order") != writer["store_order"]
            or store_retire.get("pc_rdata") != load_pc - 4
            or store_retire.get("insn") != 0x0032a023
            or store_retire.get("valid") != 1 or store_retire.get("trap") != 0
            or store_retire.get("mem_addr") != 0x20000
            or store_retire.get("mem_wmask") != 15
            or type(store_retire.get("mem_wdata")) is not int
            or store_retire["mem_wdata"] & 255 != writer["byte_value"]
            or store_physical.get("rvfi_valid") != 1
            or store_physical.get("rvfi_insn") != 0x0032a023
            or _observed_case(store_retire) != observed_store):
        return {"passed": False, "reason": "wrong_final_store_slot"}
    for proof_i, proof in indexed:
        if proof_i <= writer_i or proof.get("kind") != "uart_memory_readback" \
                or proof.get("status") != "accepted":
            continue
        if (proof.get("store_fullkey") != writer.get("store_fullkey")
                or proof.get("store_retirement_event_id") != writer.get("store_retirement_event_id")
                or proof.get("store_commit_id") != writer.get("commit_id")
                or proof.get("store_byte_version") != identity[3]
                or (proof.get("memory_id"), proof.get("generation"),
                    proof.get("byte_offset")) != identity[:3]
                or proof.get("byte_value") != writer.get("byte_value")
                or proof.get("source_case_id") != writer.get("source_admission", {}).get("case_id")
                or proof.get("influenced_bits") != [0, 8]
                or proof.get("load_observed_case") != {
                    "case_id": "p3-directed-late-lw",
                    "case_index": observed_store["case_index"] + 1}):
            continue
        key = proof.get("load_fullkey")
        if (not _stream_data_key(key)
                or any(key[field] != store_key[field] for field in
                       ("execution_id", "testcase_id", "source_component", "source_epoch"))
                or key["source_sequence"] != store_key["source_sequence"] + 1):
            continue
        if any(e.get("kind") in ("memory_write", "memory_write_commit",
                                  "cpu_reset", "uart_reset", "memory_reset", "cpu_flush")
               for _, e in indexed[store_retire_i + 1:proof_i]):
            continue
        matching = lambda kind: [(i, e) for i, e in indexed[writer_i + 1:proof_i]
                                 if e.get("kind") == kind]
        for read_i, read in matching("memory_read"):
            if (read.get("transaction") != key or read.get("address") != 0x20000
                    or (read.get("memory_id"), read.get("generation"),
                        read.get("byte_offset")) != identity[:3]
                    or read.get("width_bytes") != 4
                    or type(read.get("value")) is not int
                    or read["value"] & 255 != writer["byte_value"]
                    or not _word_matches(read.get("data_hex"), read["value"])
                    or not _first_lane_matches(read, identity)
                    or _observed_case(read) != proof["load_observed_case"]):
                continue
            for issue_i, issue in matching("memory_read_issuance"):
                if (issue_i <= read_i or issue.get("status") != "accepted"
                        or issue.get("fullkey") != key or issue.get("address") != 0x20000
                        or (issue.get("memory_id"), issue.get("generation"),
                            issue.get("byte_offset")) != identity[:3]
                        or issue.get("width_bytes") != 4
                        or issue.get("value") != read["value"]
                        or issue.get("data_hex") != read.get("data_hex")
                        or not _first_lane_matches(issue, identity)
                        or _observed_case(issue) != proof["load_observed_case"]):
                    continue
                for response_i, response in matching("data_response"):
                    snapshot = response.get("snapshot") or {}
                    if (response_i <= issue_i or response.get("transaction") != key
                            or response.get("raw_address") != 0x20000
                            or response.get("write") != 0 or response.get("be") != 15
                            or response.get("error") != 0
                            or response.get("rdata") != issue.get("value")
                            or snapshot.get("memory_id") != identity[0]
                            or snapshot.get("generation") != identity[1]
                            or snapshot.get("byte_offset") != identity[2]
                            or snapshot.get("transaction_id") != str(TransactionKey(**key))
                            or snapshot.get("data_hex") != issue.get("data_hex")
                            or not _first_lane_matches(snapshot, identity)
                            or snapshot.get("value") != issue.get("value")
                            or _observed_case(response) != proof["load_observed_case"]):
                        continue
                    for retire_i, retire in matching("cpu_retire"):
                        physical = retire.get("observation", {}).get("physical", {})
                        if (retire_i <= response_i
                                or retire.get("event_id") != proof.get("load_retirement_event_id")
                                or retire.get("order") != proof.get("load_order")
                                or type(retire.get("order")) is not int
                                or retire["order"] <= writer["store_order"]
                                or retire.get("pc_rdata") != load_pc
                                or retire.get("insn") != 0x0002a303
                                or retire.get("valid") != 1 or retire.get("trap") != 0
                                or retire.get("mem_addr") != 0x20000
                                or retire.get("mem_rmask") != 15 or retire.get("mem_wmask") != 0
                                or retire.get("mem_rdata") != response.get("rdata")
                                or retire.get("rd_addr") != 6
                                or retire.get("rd_wdata") != response.get("rdata")
                                or physical.get("rvfi_valid") != 1
                                or physical.get("rvfi_insn") != 0x0002a303
                                or physical.get("rvfi_mem_rdata") != response.get("rdata")
                                or physical.get("rvfi_rd_wdata") != response.get("rdata")
                                or _observed_case(retire) != proof["load_observed_case"]):
                            continue
                        return {"passed": True, "writer_event_id": identity[4],
                                "writer_version": identity[3], "writer_store_order": writer["store_order"],
                                "writer_certificate_event_id": writer.get("event_id"),
                                "read_event_id": read.get("event_id"),
                                "issuance_event_id": issue.get("event_id"),
                                "response_event_id": response.get("event_id"),
                                "retirement_event_id": retire.get("event_id"),
                                "readback_certificate_event_id": proof.get("event_id"),
                                "load_pc": load_pc, "load_value": response.get("rdata")}
    return {"passed": False, "reason": "no_exact_late_retired_readback",
            "last_writer_event_id": identity[4], "last_writer_version": identity[3]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--cache-dir", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--stores", type=int, required=True)
    run.add_argument("--ticks", type=int, required=True)
    run.add_argument("--paired-ticks", type=int, default=0)
    run.add_argument("--next-ticks", type=int)
    run.add_argument("--chunk-size", type=int, default=512)
    run.add_argument("--read-ticks", type=int, default=100)
    replay = commands.add_parser("replay")
    replay.add_argument("--cache-dir", type=Path, required=True)
    replay.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "replay":
        plan = (args.output / "online_plan.json").read_bytes()
        reference = _read_uart_online_trace(args.output / "online_final_trace.meta.json")
        runtime = make_ibex_uart_online_runtime(
            cache_dir=args.cache_dir, run_id="p3-capacity-replay",
            cpu_retirement=True, uart_fifo=True, memory_commit=True,
            memory_readback=True)
        # Replay creates its own fresh runner from the factory, after closing
        # the throwaway startup created for runtime construction.
        runtime.session.finish()
        comparison = replay_online_session(plan, runtime.factory, reference,
                                           checker=IbexUartOnlineChecker())
        result = {"matches": comparison.matches,
                  "first_difference": comparison.first_difference,
                  "difference_context": comparison.difference_context,
                  "actual_status": comparison.actual_trace.status,
                  "actual_local_ticks": comparison.actual_trace.local_ticks}
        _write(args.output / "fresh_replay.json", result)
        print(json.dumps(result, sort_keys=True))
        return 0 if comparison.matches else 2
    if (not 1 <= args.stores <= 512 or not 1 <= args.ticks <= 1200
            or not 0 <= args.paired_ticks <= args.ticks
            or args.next_ticks is not None and not 1 <= args.next_ticks <= 1200
            or not 1 <= args.chunk_size <= 512
            or not 1 <= args.read_ticks <= 1200):
        parser.error("stores and ticks are outside the directed gate bounds")
    if args.output.exists():
        parser.error("output directory must be new")
    args.output.mkdir(parents=True)
    runtime = make_ibex_uart_online_runtime(
        cache_dir=args.cache_dir, run_id="p3-capacity-directed",
        cpu_retirement=True, uart_fifo=True, memory_commit=True,
        memory_readback=True)
    session = runtime.session
    path_id = next(runtime.decoder.graph.path_identity(path, direction=direction)
                   for direction, path in runtime.decoder.runtime_paths
                   if direction == "CPU_TO_IP" and path.target == "cpu_to_uart_tx")
    # RV32I SW x3, 0(x5). Every store is retired by real Ibex; no host write
    # is called directly by this script.
    sw = 0x0032a023
    receipts = []
    completed = 0
    while completed < args.stores:
        count = min(args.chunk_size, args.stores - completed)
        tick_count = args.ticks if not receipts else (args.next_ticks or args.ticks)
        paired = args.paired_ticks if not receipts else 0
        index = len(receipts)
        case = OnlineCase(
            f"p3-directed-repeated-store-{index}", "CPU_TO_IP", path_id,
            OnlineInstruction(f"p3-directed-sw-fragment-{index}", "cpu",
                              0x11000 + 4 * completed,
                              sw.to_bytes(4, "little").hex() * count),
            ((BatchAdvance(("uart", "cpu")),) * paired
             + (BatchAdvance(("cpu",)),) * (tick_count - paired)))
        receipts.append(session.submit_case(case))
        completed += count
    # Reserve the very next instruction after all directed stores. LW x6, 0(x5)
    # reads the host RAM word through the real Ibex data port and service.
    load_pc = 0x11000 + 4 * args.stores
    receipts.append(session.submit_case(OnlineCase(
        "p3-directed-late-lw", "CPU_TO_IP", path_id,
        OnlineInstruction("p3-directed-late-lw-fragment", "cpu", load_pc,
                          (0x0002a303).to_bytes(4, "little").hex()),
        (BatchAdvance(("cpu",)),) * args.read_ticks)))
    trace = session.finish(defer_semantic_hash=True)
    plan = session.encode_plan()
    (args.output / "online_plan.json").write_bytes(plan)
    _write(args.output / "online_session_manifest.json", session.manifest_document)
    trace = ScenarioTrace(hashlib.sha256(plan).hexdigest(), trace.status,
                          trace.events, trace.local_ticks, "", trace.manifest_sha256)
    trace = _write_online_trace_zlib(args.output, trace)
    # Audit the exact lossless artifact used by fresh replay. The live journal
    # view can differ from its final archived observation overlay.
    trace = _read_uart_online_trace(args.output / "online_final_trace.meta.json")
    counts = {}
    writer_identities = set()
    for event in trace.events:
        if event.get("kind") in ("memory_write", "memory_write_commit",
                                  "uart_store_memory_match", "uart_memory_readback",
                                  "cpu_retire"):
            key = (event["kind"], event.get("status", ""))
            counts[key] = counts.get(key, 0) + 1
            if key == ("uart_store_memory_match", "accepted"):
                version = event.get("byte_version")
                identity = (event.get("memory_id"), event.get("generation"),
                            event.get("byte_offset"),
                            tuple(version) if isinstance(version, list) else (),
                            event.get("writer_event_id"))
                if (isinstance(identity[0], str) and identity[0]
                        and type(identity[1]) is int
                        and type(identity[2]) is int
                        and len(identity[3]) == 2
                        and all(type(value) is int for value in identity[3])
                        and isinstance(identity[4], str) and identity[4]):
                    writer_identities.add(identity)
    result = {"stores_requested": args.stores, "ticks_requested": args.ticks,
              "paired_ticks_requested": args.paired_ticks,
              "next_ticks_requested": args.next_ticks,
              "read_ticks_requested": args.read_ticks,
              "chunk_size": args.chunk_size,
              "case_statuses": [receipt.status for receipt in receipts],
              "violations": [v for receipt in receipts for v in receipt.violations],
              "trace_status": trace.status, "event_count": len(trace.events),
              "local_ticks": trace.local_ticks,
              "writer_cache_count": len(session.runner._uart_memory_readback_join._writers),
              "distinct_writer_identities": len(writer_identities),
              "readback_degraded": session.runner._uart_memory_readback_join.degraded,
              "counts": {f"{kind}:{status}": value for (kind, status), value in counts.items()}}
    result["late_readback"] = _late_readback_evidence(trace.events, load_pc)
    result["gate_passed"] = (_capacity_gate_passed(result)
                             and result["late_readback"]["passed"])
    _write(args.output / "capacity_result.json", result)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["gate_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
