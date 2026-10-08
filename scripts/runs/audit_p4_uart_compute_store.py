"""Audit the fixed Ibex RVFI arithmetic-to-UART WDATA lane-0 chain."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def _one(items, label):
    if len(items) != 1:
        raise ValueError(f"expected one {label}, got {len(items)}")
    return items[0]


def _signed_12(value):
    value &= 0xfff
    return value - 0x1000 if value & 0x800 else value


def audit_compute_store(events, *, action_id):
    """Return a bounded architectural association, rejecting broken joins.

    This checks observed RVFI register values and a CPU transaction. It does
    not claim an RTL source token inside the register file or UART TX FIFO.
    """
    if not isinstance(events, list) or not isinstance(action_id, str) or not action_id:
        raise ValueError("events and action ID are required")
    retires = [event for event in events if event.get("kind") == "cpu_retire"]
    store = _one([event for event in retires
                  if event.get("mem_addr") == 0x4000001c
                  and event.get("mem_wmask") == 1], "UART lane-0 retirement")
    order = store.get("order")
    by_order = {event.get("order"): event for event in retires}
    if type(order) is not int or len(by_order) != len(retires):
        raise ValueError("retirement order is incomplete or duplicated")
    try:
        value_lui, compute, address_lui = (by_order[order - offset]
                                           for offset in (3, 2, 1))
    except KeyError as exc:
        raise ValueError("computed store lacks consecutive RVFI retirement") from exc
    sequence = (value_lui, compute, address_lui, store)
    if any(event.get("valid") != 1 or event.get("trap") != 0
           or event.get("schema_version") != "cpu_retire.v2"
           or event.get("phase") != "post"
           or event.get("execution_id") != store.get("execution_id")
           or event.get("reset_epoch") != store.get("reset_epoch")
           for event in sequence):
        raise ValueError("computed Store lacks valid same-execution RVFI retirement")
    if any(type(event.get("pc_rdata")) is not int
           or event["pc_rdata"] != value_lui["pc_rdata"] + index * 4
           for index, event in enumerate(sequence)):
        raise ValueError("computed store RVFI PC sequence differs")
    value_word, compute_word, address_word, store_word = (event.get("insn")
                                                          for event in sequence)
    if any(type(word) is not int for word in
           (value_word, compute_word, address_word, store_word)):
        raise ValueError("computed store instruction word is missing")
    if ((value_word & 0x7f) != 0x37 or (value_word >> 7 & 31) != 2
            or (compute_word & 0x707f) != 0x13
            or (compute_word >> 7 & 31) != 2
            or (compute_word >> 15 & 31) != 2
            or (address_word & 0x7f) != 0x37
            or (address_word >> 7 & 31) != 1
            or (store_word & 0x707f) != 0x23
            or (store_word >> 15 & 31) != 1
            or (store_word >> 20 & 31) != 2):
        raise ValueError("computed store uses unexpected RV32I operations")
    store_offset = ((store_word >> 25 & 0x7f) << 5) | (store_word >> 7 & 31)
    if _signed_12(store_offset) != 0x1c:
        raise ValueError("computed store targets another UART offset")
    base_value = value_word & 0xfffff000
    computed_value = (base_value + _signed_12(compute_word >> 20)) & 0xffffffff
    address_value = address_word & 0xfffff000
    if (value_lui.get("rd_addr") != 2 or value_lui.get("rd_wdata") != base_value
            or compute.get("rs1_addr") != 2 or compute.get("rs1_rdata") != base_value
            or compute.get("rd_addr") != 2 or compute.get("rd_wdata") != computed_value
            or address_lui.get("rd_addr") != 1
            or address_lui.get("rd_wdata") != address_value
            or store.get("rs1_addr") != 1 or store.get("rs1_rdata") != address_value
            or store.get("rs2_addr") != 2
            or store.get("rs2_rdata") != computed_value
            or store.get("mem_wdata") != (computed_value & 0xff)
            or address_value + 0x1c != store.get("mem_addr")):
        raise ValueError("computed register value differs from actual Store operand")
    matches = [event for event in events
               if event.get("kind") == "cpu_retirement_match"
               and event.get("order") in {row["order"] for row in sequence}]
    if (len(matches) != 4
            or {event["order"] for event in matches}
            != {row["order"] for row in sequence}
            or any(event.get("status") != "accepted"
                   or event.get("source_refs") != [action_id]
                   for event in matches)):
        raise ValueError("instruction source admission is not fully matched")
    for index, row in enumerate(sequence):
        matched = _one([match for match in matches
                        if match["order"] == row["order"]], "ordered instruction match")
        next_retire = (sequence[index + 1]["event_id"]
                       if index + 1 < len(sequence) else None)
        if (matched["event_id"] <= row["event_id"]
                or next_retire is not None and matched["event_id"] >= next_retire):
            raise ValueError("instruction source match is outside retirement interval")
    delivery = _one([event for event in events
                     if event.get("kind") == "mmio_delivery"
                     and event.get("address") == 0x4000001c
                     and event.get("write") is True], "UART WDATA delivery")
    transaction = delivery.get("source_transaction")
    store_match = _one([event for event in matches
                        if event["order"] == store["order"]], "Store retirement match")
    accepted = _one([event for event in events
                     if event.get("kind") == "data_accept"
                     and event.get("transaction") == transaction], "CPU data accept")
    response = _one([event for event in events
                     if event.get("kind") == "data_response"
                     and event.get("transaction") == transaction], "CPU data response")
    if (not isinstance(transaction, dict)
            or transaction.get("execution_id") != store.get("execution_id")
            or transaction.get("source_epoch") != store.get("reset_epoch")
            or store_match.get("transaction_keys") != [transaction]
            or not accepted.get("write") or not response.get("write")
            or not accepted["event_id"] < delivery["event_id"]
            < response["event_id"] < store["event_id"]
            or delivery.get("offset") != 0x1c
            or delivery.get("byte_enable") != 1
            or delivery.get("write_value") != (computed_value & 0xff)
            or any(event.get("address") != 0x4000001c
                   or event.get("be") != 1
                   or event.get("wdata") != (computed_value & 0xff)
                   for event in (accepted, response))
            or response.get("error") != 0):
        raise ValueError("computed Store did not reach the same UART byte transaction")
    before = [event for event in events if event.get("component") == "uart"
              and isinstance(event.get("outputs"), dict)
              and type(event["outputs"].get("serial_tx_count")) is int
              and event["event_id"] < delivery["event_id"]]
    after = [event for event in events if event.get("component") == "uart"
             and isinstance(event.get("outputs"), dict)
             and event["event_id"] > store["event_id"]
             and event["outputs"].get("serial_tx_count") == 1
             and event["outputs"].get("serial_tx_last") == (computed_value & 0xff)]
    if not before or before[-1]["outputs"]["serial_tx_count"] != 0 or not after:
        raise ValueError("UART serial output did not transition to computed byte")
    if any(delivery["event_id"] < event.get("event_id", -1) < after[0]["event_id"]
           and event.get("kind") in ("reset_barrier", "uart_reset", "cpu_reset")
           for event in events):
        raise ValueError("UART serial association crosses a reset")
    return {"schema_version": "p4_uart_compute_store_architectural_audit.v1",
            "action_id": action_id, "retire_orders": [event["order"] for event in sequence],
            "retire_event_ids": [event["event_id"] for event in sequence],
            "transaction": transaction, "delivery_event_id": delivery["event_id"],
            "serial_event_id": after[0]["event_id"],
            "value": computed_value & 0xff,
            "proof_scope": "bounded_architectural_association"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--action-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    document = json.loads(args.trace.read_bytes())
    result = audit_compute_store(document["events"], action_id=args.action_id)
    args.output.write_text(json.dumps(result, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
