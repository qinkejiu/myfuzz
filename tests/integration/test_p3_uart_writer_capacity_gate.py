"""The directed capacity CLI must reject an unfinished Store witness stream."""

import importlib.util
from copy import deepcopy
from pathlib import Path
from myfuzz.scenario.ledger import TransactionKey


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/run_p3_uart_writer_capacity.py"
SPEC = importlib.util.spec_from_file_location("p3_uart_writer_capacity", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def complete_result():
    return {
        "stores_requested": 270,
        "case_statuses": ["running"] * 5,
        "violations": [],
        "trace_status": "complete",
        "readback_degraded": False,
        "counts": {"uart_store_memory_match:accepted": 271,
                   "memory_write_commit:": 272},
        "distinct_writer_identities": 271,
        "writer_cache_count": 15,
    }


def test_gate_rejects_cases_that_never_reached_a_store():
    result = complete_result()
    result["counts"] = {}
    result["distinct_writer_identities"] = 0
    assert not MODULE._capacity_gate_passed(result)


def test_gate_requires_complete_trace_real_commits_and_distinct_writers():
    result = complete_result()
    assert MODULE._capacity_gate_passed(result)
    result["trace_status"] = "running"
    assert not MODULE._capacity_gate_passed(result)
    result = complete_result()
    result["counts"]["memory_write_commit:"] = 269
    assert not MODULE._capacity_gate_passed(result)
    result = complete_result()
    result["distinct_writer_identities"] = 269
    assert not MODULE._capacity_gate_passed(result)
    result = complete_result()
    result["counts"]["uart_store_memory_match:accepted"] = 269
    assert not MODULE._capacity_gate_passed(result)


def test_gate_requires_crossing_capacity_and_bounded_retained_history():
    result = complete_result()
    result["stores_requested"] = 1
    assert not MODULE._capacity_gate_passed(result)
    result = complete_result()
    result["writer_cache_count"] = 271
    assert not MODULE._capacity_gate_passed(result)


def late_events():
    stream = {"execution_id": "local-execution", "testcase_id": "ibex-uart-online-stream",
              "source_component": "cpu", "source_epoch": 0, "channel_id": "data"}
    store_key = {**stream, "source_sequence": 277}
    key = {**stream, "source_sequence": 278}
    writer_id = str(TransactionKey(**store_key))
    store_retire = {"kind": "cpu_retire", "event_id": 9, "valid": 1, "trap": 0,
                    "order": 355, "insn": 0x0032a023, "pc_rdata": 0x11434,
                    "mem_addr": 131072, "mem_wmask": 15, "mem_wdata": 90,
                    "provenance": {"observed_case": {"case_id": "p3-directed-repeated-store-4", "case_index": 5}},
                    "observation": {"physical": {"rvfi_valid": 1, "rvfi_insn": 0x0032a023}}}
    writer = {"kind": "uart_store_memory_match", "status": "accepted",
              "event_id": 10, "store_order": 355, "store_fullkey": store_key,
              "store_retirement_event_id": 9, "commit_id": "last-commit",
              "byte_version": [0, 282], "writer_event_id": writer_id,
              "memory_id": "ram", "generation": 0, "byte_offset": 65536,
              "byte_value": 90, "source_path_certified": True,
              "source_admission": {"case_id": "uart-fixed-warmup", "action_id": "uart-fixed-warmup-rx",
                                   "component": "uart", "source_id": "uart.external_rx_byte",
                                   "direction": "IP_TO_CPU", "input_kind": "source_event", "role": "bootstrap"},
              "provenance": {"observed_case": {"case_id": "p3-directed-repeated-store-4", "case_index": 5}}}
    read = {"kind": "memory_read", "event_id": 11, "transaction": key,
            "address": 131072, "value": 90, "memory_id": "ram", "generation": 0,
            "byte_offset": 65536, "width_bytes": 4, "data_hex": "5a000000",
            "versions": [[0, 282]] * 4,
            "writer_event_ids": [writer_id] * 4, "writer_kinds": ["STORE"] * 4,
            "provenance": {"observed_case": {"case_id": "p3-directed-late-lw", "case_index": 6}}}
    issued = {"kind": "memory_read_issuance", "event_id": 12,
              "status": "accepted", "fullkey": key, "address": 131072,
              "value": 90, "memory_id": "ram", "generation": 0,
              "byte_offset": 65536, "width_bytes": 4, "data_hex": "5a000000",
              "versions": [[0, 282]] * 4,
              "writer_event_ids": [writer_id] * 4, "writer_kinds": ["STORE"] * 4,
              "provenance": {"observed_case": {"case_id": "p3-directed-late-lw", "case_index": 6}}}
    response = {"kind": "data_response", "event_id": 13, "transaction": key,
                "raw_address": 131072, "write": 0, "rdata": 90, "be": 15, "error": 0,
                "snapshot": {"memory_id": "ram", "generation": 0,
                             "byte_offset": 65536, "value": 90, "data_hex": "5a000000",
                             "transaction_id": str(TransactionKey(**key)),
                             "versions": [[0, 282]] * 4,
                             "writer_event_ids": [writer_id] * 4,
                             "writer_kinds": ["STORE"] * 4},
                "provenance": {"observed_case": {"case_id": "p3-directed-late-lw", "case_index": 6}}}
    retire = {"kind": "cpu_retire", "event_id": 14, "valid": 1,
              "insn": 0x0002a303, "pc_rdata": 0x11438, "order": 356,
              "trap": 0, "mem_addr": 131072, "mem_rmask": 15,
              "mem_wmask": 0, "mem_rdata": 90, "rd_addr": 6, "rd_wdata": 90,
              "observation": {"physical": {"rvfi_valid": 1, "rvfi_insn": 0x0002a303,
                                            "rvfi_mem_rdata": 90, "rvfi_rd_wdata": 90}},
              "provenance": {"observed_case": {"case_id": "p3-directed-late-lw", "case_index": 6}}}
    proof = {"kind": "uart_memory_readback", "event_id": 15,
             "status": "accepted", "store_fullkey": writer["store_fullkey"],
             "store_retirement_event_id": 9, "store_commit_id": "last-commit",
             "store_byte_version": [0, 282], "load_fullkey": key,
             "load_retirement_event_id": 14, "load_order": 356,
             "load_observed_case": {"case_id": "p3-directed-late-lw", "case_index": 6},
             "memory_id": "ram", "generation": 0, "byte_offset": 65536,
             "byte_value": 90, "source_case_id": "uart-fixed-warmup",
             "influenced_bits": [0, 8]}
    return [store_retire, writer, read, issued, response, retire, proof]


def test_late_readback_gate_requires_last_writer_real_read_response_and_rvfi():
    events = late_events()
    assert MODULE._late_readback_evidence(events, 0x11438)["passed"]
    for index, field, replacement in ((3, "writer_event_ids", ["old-writer"] * 4),
                                      (4, "rdata", 0),
                                      (5, "rd_wdata", 0),
                                      (5, "pc_rdata", 0x11434),
                                      (6, "store_byte_version", [0, 281])):
        changed = [dict(event) for event in events]
        changed[index][field] = replacement
        assert not MODULE._late_readback_evidence(changed, 0x11438)["passed"]


def test_late_readback_rejects_a_consistent_but_wrong_loaded_value():
    events = deepcopy(late_events())
    events[2]["value"] = 0
    events[3]["value"] = 0
    events[4]["rdata"] = 0
    events[4]["snapshot"]["value"] = 0
    events[5]["mem_rdata"] = events[5]["rd_wdata"] = 0
    events[5]["observation"]["physical"]["rvfi_mem_rdata"] = 0
    events[5]["observation"]["physical"]["rvfi_rd_wdata"] = 0
    assert not MODULE._late_readback_evidence(events, 0x11438)["passed"]


def test_late_readback_rejects_load_order_before_store():
    events = deepcopy(late_events())
    events[5]["order"] = events[6]["load_order"] = 354
    assert not MODULE._late_readback_evidence(events, 0x11438)["passed"]


def test_late_readback_rejects_partial_fullkey_and_unbound_snapshot():
    events = deepcopy(late_events())
    events[6]["load_fullkey"] = {"channel_id": "data", "source_sequence": 278}
    events[2]["transaction"] = events[3]["fullkey"] = events[4]["transaction"] = events[6]["load_fullkey"]
    assert not MODULE._late_readback_evidence(events, 0x11438)["passed"]
    events = deepcopy(late_events())
    events[4]["snapshot"]["transaction_id"] = "unrelated"
    assert not MODULE._late_readback_evidence(events, 0x11438)["passed"]


def test_late_readback_rejects_wrong_store_slot_or_uart_source():
    events = deepcopy(late_events())
    events[1]["provenance"] = {"observed_case": {"case_id": "unrelated", "case_index": 5}}
    assert not MODULE._late_readback_evidence(events, 0x11438)["passed"]
    events = deepcopy(late_events())
    events[0]["pc_rdata"] = 0x11430
    assert not MODULE._late_readback_evidence(events, 0x11438)["passed"]
    events = deepcopy(late_events())
    events[1]["source_admission"]["case_id"] = "unrelated"
    events[6]["source_case_id"] = "unrelated"
    assert not MODULE._late_readback_evidence(events, 0x11438)["passed"]


def test_late_readback_rejects_intervening_commit_or_reset():
    for kind in ("memory_write_commit", "cpu_reset", "uart_reset"):
        events = deepcopy(late_events())
        events.insert(2, {"kind": kind, "event_id": 100})
        assert not MODULE._late_readback_evidence(events, 0x11438)["passed"]


def test_late_readback_rejects_an_inconsistent_ram_word_or_pre_certificate_commit():
    events = deepcopy(late_events())
    for index in (2, 3):
        events[index]["data_hex"] = "00000000"
    events[4]["snapshot"]["data_hex"] = "00000000"
    assert not MODULE._late_readback_evidence(events, 0x11438)["passed"]
    events = deepcopy(late_events())
    events.insert(1, {"kind": "memory_write_commit", "event_id": 100})
    assert not MODULE._late_readback_evidence(events, 0x11438)["passed"]
