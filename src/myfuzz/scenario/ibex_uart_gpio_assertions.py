"""End-to-end observations for the real Ibex, OpenTitan UART and GPIO case.

These assertions inspect recorded facts after a testcase. They never supply a
DUT result or suppress an unexpected output while generating inputs.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping


def check_ibex_uart_gpio_chain(
    events: Iterable[Mapping], expected_bytes: tuple[int, ...]
) -> dict:
    """Require every source frame to traverse UART, Ibex and GPIO in order."""
    if (not expected_bytes or any(type(byte) is not int or byte < 0 or byte > 255
                                  for byte in expected_bytes)):
        raise ValueError("expected_bytes must contain UART octets")
    stream = tuple(events)
    findings: list[str] = []
    ids = [event.get("event_id") for event in stream]
    if any(type(event_id) is not int for event_id in ids) or ids != sorted(set(ids)):
        findings.append("event_ids_not_strictly_ordered")
    if any(event.get("kind") == "reset_barrier" for event in stream):
        findings.append("unexpected_reset")

    def find(after: int, before: int | None, predicate):
        return next((event for event in stream
                     if type(event.get("event_id")) is int
                     and event["event_id"] > after
                     and (before is None or event["event_id"] < before)
                     and predicate(event)), None)

    prior_end = 0
    seen_transactions: set[tuple] = set()
    closed = 0
    for index, expected in enumerate(expected_bytes, 1):
        prefix = f"frame-{index}-bit-"
        injections = [find(prior_end, None, lambda e, bit=bit:
                           e.get("kind") == "source_injection"
                           and e.get("component") == "uart"
                           and e.get("port") == "uart_rx"
                           and e.get("action_id") == prefix + str(bit))
                      for bit in range(10)]
        if any(event is None for event in injections):
            findings.append(f"round_{index}:source_frame_missing")
            break
        assert all(event is not None for event in injections)
        levels = tuple(event["value"] for event in injections)
        expected_levels = (0, *((expected >> bit) & 1 for bit in range(8)), 1)
        if levels != expected_levels or [event["event_id"] for event in injections] != sorted(
                event["event_id"] for event in injections):
            findings.append(f"round_{index}:source_frame_invalid")
            break
        frame_end = injections[-1]["event_id"]
        next_frame = find(frame_end, None, lambda e:
                          e.get("kind") == "source_injection"
                          and e.get("action_id") == f"frame-{index + 1}-bit-0")
        boundary = next_frame["event_id"] if next_frame else None
        irq = find(frame_end, boundary, lambda e:
                   e.get("kind") == "dataflow_delivery"
                   and tuple(e.get("source", ())) == ("uart", "irq")
                   and tuple(e.get("target", ())) == ("cpu", "irq")
                   and e.get("value") == 1)
        take = find(irq["event_id"] if irq else frame_end, boundary, lambda e:
                    e.get("component") == "cpu"
                    and e.get("inputs", {}).get("irq") == 1
                    and e.get("outputs", {}).get("irq_taken_pre") == 1)
        read = find(take["event_id"] if take else frame_end, boundary, lambda e:
                    e.get("kind") == "mmio_delivery"
                    and e.get("device_id") == "uart" and e.get("offset") == 0x18
                    and e.get("write") is False)
        if read is not None and (type(read.get("read_value")) is not int
                                 or read["read_value"] & 0xff != expected):
            findings.append(f"round_{index}:uart_data_mismatch")
        transaction = read.get("source_transaction", {}) if read else {}
        consumed = find(read["event_id"] if read else frame_end, boundary, lambda e:
                        e.get("component") == "cpu"
                        and e.get("outputs", {}).get("data_rsp_consumed") == 1
                        and e["outputs"].get("data_rsp_source_epoch") ==
                        transaction.get("source_epoch")
                        and e["outputs"].get("data_rsp_source_sequence") ==
                        transaction.get("source_sequence"))
        if consumed is not None and read is not None and (
                consumed["outputs"].get("data_rsp_rdata") != read.get("read_value")):
            findings.append(f"round_{index}:cpu_response_mismatch")
        write = find(consumed["event_id"] if consumed else frame_end, boundary,
                     lambda e: e.get("kind") == "mmio_delivery"
                     and e.get("device_id") == "gpio" and e.get("offset") == 0x14
                     and e.get("write") is True)
        if write is not None and read is not None and (
                type(write.get("write_value")) is not int
                or type(read.get("read_value")) is not int
                or write["write_value"] & 0xff != read["read_value"] & 0xff):
            findings.append(f"round_{index}:gpio_write_mismatch")
        first_output = find(write["event_id"] if write else frame_end, boundary,
                            lambda e: e.get("component") == "gpio"
                            and "gpio_out" in e.get("outputs", {}))
        output = find(write["event_id"] if write else frame_end, boundary,
                      lambda e: e.get("component") == "gpio"
                      and e.get("outputs", {}).get("gpio_out") ==
                      (write.get("write_value") if write else None))
        if first_output is not None and output is None:
            findings.append(f"round_{index}:gpio_output_mismatch")
        ram = find(write["event_id"] if write else frame_end, boundary,
                   lambda e: e.get("kind") == "memory_write"
                   and e.get("component") == "cpu" and e.get("address") == 0x200)
        if ram is not None and read is not None and (
                ram.get("value") != read.get("read_value")):
            findings.append(f"round_{index}:persistent_ram_mismatch")
        stages = (irq, take, read, consumed, write, output, ram)
        if any(stage is None for stage in stages):
            labels = ("uart_irq_delivery", "cpu_irq_take", "uart_fifo_read",
                      "cpu_response", "gpio_write", "gpio_real_output", "ram_write")
            findings.append(f"round_{index}:{labels[next(i for i, stage in enumerate(stages)
                                                      if stage is None)]}_missing")
            break
        for event in (read, write, ram):
            tx = event.get("source_transaction", event.get("transaction", {}))
            key = tuple(tx.get(field) for field in (
                "execution_id", "testcase_id", "source_component", "source_epoch",
                "channel_id", "source_sequence")) if isinstance(tx, Mapping) else ()
            if not key or any(part is None for part in key):
                findings.append(f"round_{index}:transaction_identity_missing")
            elif key in seen_transactions:
                findings.append(f"round_{index}:transaction_reused")
            seen_transactions.add(key)
        prior_end = ram["event_id"]
        closed += 1
    if closed != len(expected_bytes):
        findings.append("too_few_closed_rounds")
    return {"complete": not findings, "closed_rounds": closed,
            "findings": findings}
