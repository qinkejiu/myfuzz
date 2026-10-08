"""Bounded RVFI and transaction checks for a computed UART byte store."""

import pytest

from scripts.runs.audit_p4_uart_compute_store import audit_compute_store


ACTION = "online-2:cpu.online_instruction"
TX = {"execution_id": "execution", "testcase_id": "case", "source_component": "cpu",
      "channel_id": "data", "source_epoch": 0, "source_sequence": 11}


def witnessed_events():
    events = []
    words = (0x00000137, 0x00C10113, 0x400000B7, 0x00208E23)
    pcs = (0x11014, 0x11018, 0x1101C, 0x11020)
    rows = ((2, 0, 0, 0, 0, 0), (2, 12, 2, 0, 0, 0),
            (1, 0x40000000, 0, 0, 0, 0), (0, 0, 1, 0x40000000, 2, 12))
    for order, (word, pc, row) in enumerate(zip(words, pcs, rows), 161):
        rd, result, rs1, value1, rs2, value2 = row
        events.append({"event_id": len(events) + 1, "kind": "cpu_retire",
                       "order": order, "pc_rdata": pc, "insn": word,
                       "rd_addr": rd, "rd_wdata": result, "rs1_addr": rs1,
                       "rs1_rdata": value1, "rs2_addr": rs2,
                       "rs2_rdata": value2, "mem_addr": 0x4000001C if order == 164 else 0,
                       "mem_wmask": 1 if order == 164 else 0,
                       "mem_wdata": 12 if order == 164 else 0,
                       "valid": 1, "trap": 0, "execution_id": "execution",
                       "reset_epoch": 0, "schema_version": "cpu_retire.v2",
                       "phase": "post"})
        match = {"event_id": len(events) + 1,
                 "kind": "cpu_retirement_match", "order": order,
                 "status": "accepted", "source_refs": [ACTION]}
        if order == 164:
            match["transaction_keys"] = [TX]
        events.append(match)
    events.extend((
        {"event_id": 9, "component": "uart", "outputs": {
            "serial_tx_count": 0, "serial_tx_last": 0}},
        {"event_id": 10, "kind": "data_accept", "transaction": TX, "write": 1,
         "address": 0x4000001C, "be": 1, "wdata": 12},
        {"event_id": 11, "kind": "mmio_delivery", "source_transaction": TX,
         "write": True, "address": 0x4000001C, "offset": 0x1C,
         "byte_enable": 1, "write_value": 12},
        {"event_id": 12, "kind": "data_response", "transaction": TX, "write": 1,
         "address": 0x4000001C, "be": 1, "wdata": 12, "error": 0},
        {"event_id": 13, "component": "uart", "outputs": {
            "serial_tx_count": 1, "serial_tx_last": 12}},
    ))
    events = events[:6] + events[8:12] + events[6:8] + events[12:]
    return [{**event, "event_id": index} for index, event in enumerate(events, 1)]


def test_compute_store_audit_accepts_actual_register_and_transaction_chain():
    certificate = audit_compute_store(witnessed_events(), action_id=ACTION)
    assert certificate["value"] == 12
    assert certificate["retire_orders"] == [161, 162, 163, 164]
    assert certificate["transaction"] == TX


@pytest.mark.parametrize("index,field,value", [
    (2, "rd_wdata", 13), (10, "rs2_rdata", 13),
    (8, "byte_enable", 15), (9, "transaction", {**TX, "source_sequence": 12}),
    (11, "transaction_keys", [{**TX, "source_sequence": 12}]),
    (7, "wdata", 13), (9, "error", 1),
    (10, "valid", 0), (10, "trap", 1), (2, "reset_epoch", 1),
    (12, "outputs", {"serial_tx_count": 1, "serial_tx_last": 13}),
])
def test_compute_store_audit_rejects_broken_chain(index, field, value):
    events = witnessed_events()
    events[index] = {**events[index], field: value}
    with pytest.raises(ValueError):
        audit_compute_store(events, action_id=ACTION)


def test_compute_store_audit_rejects_reset_before_serial_observation():
    events = witnessed_events()
    events.insert(-1, {"event_id": 13, "kind": "reset_barrier", "component": "uart"})
    events[-1]["event_id"] = 14
    with pytest.raises(ValueError):
        audit_compute_store(events, action_id=ACTION)


def test_compute_store_audit_rejects_late_instruction_match():
    events = witnessed_events()
    # Move the first instruction's match after the Store retirement.
    events[1]["event_id"] = 13
    with pytest.raises(ValueError):
        audit_compute_store(events, action_id=ACTION)
