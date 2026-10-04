"""Offline properties evaluated from accepted transactions and real RTL outputs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping


@dataclass(frozen=True)
class CheckFinding:
    finding_id: str
    event_id: int
    expected: int
    observed: int


def check_pulp_gpio_irq_chain(events: Iterable[Mapping], *, expected_value: int) -> dict:
    """Check one generated Ibex→PULP A→PULP B→Ibex IRQ round.

    Missing propagation is an incomplete path. A concrete output/readback
    contradicting an accepted transaction is a DUT violation candidate.
    The checker reads observations; it never drives a DUT output.
    """
    if (type(expected_value) is not int or not 0 < expected_value < 256
            or not expected_value & 1):
        raise ValueError('expected_value must be an odd GPIO byte')
    stream = tuple(events)
    incomplete: list[str] = []
    violations: list[str] = []

    def find(after: int, predicate):
        return next((event for event in stream
                     if type(event.get('event_id')) is int
                     and event['event_id'] > after and predicate(event)), None)

    if any(event.get('kind') == 'reset_barrier' for event in stream):
        incomplete.append('unexpected_reset')
    ids = [event.get('event_id') for event in stream]
    if any(type(event_id) is not int for event_id in ids) or ids != sorted(set(ids)):
        incomplete.append('event_order_invalid')
    padout_writes = [event for event in stream
                     if event.get('kind') == 'mmio_delivery'
                     and event.get('device_id') == 'gpio_a'
                     and event.get('offset') == 0x0c and event.get('write') is True]
    seen_padout_transactions: set[tuple] = set()
    for event in padout_writes:
        tx = event.get('source_transaction')
        if not isinstance(tx, Mapping):
            continue
        key = tuple(tx.get(field) for field in (
            'execution_id', 'testcase_id', 'source_component', 'source_epoch',
            'channel_id', 'source_sequence'))
        if any(part is None for part in key):
            continue
        if key in seen_padout_transactions:
            incomplete.append('gpio_a_padout_transaction_reused')
            break
        seen_padout_transactions.add(key)
    padout_start = padout_writes[0]['event_id'] if padout_writes else None
    for offset, value, name in ((4, 0xff, 'gpio_b_enable'),
                                (0x18, 1, 'gpio_b_irq_enable'),
                                (0x1c, 1, 'gpio_b_irq_rising')):
        if find(0, lambda e: e.get('kind') == 'mmio_delivery'
                and e.get('component') == 'cpu' and e.get('device_id') == 'gpio_b'
                and e.get('offset') == offset and e.get('write') is True
                and e.get('write_value') == value
                and (padout_start is None or e['event_id'] < padout_start)) is None:
            incomplete.append(name + '_missing')
    write = find(0, lambda e: e.get('kind') == 'mmio_delivery'
                 and e.get('component') == 'cpu' and e.get('device_id') == 'gpio_a'
                 and e.get('offset') == 0x0c and e.get('write') is True
                 and e.get('byte_enable') == 15
                 and e.get('write_value') == expected_value)
    if write is None:
        incomplete.append('gpio_a_padout_write_missing')
    direction = find(0, lambda e: e.get('kind') == 'mmio_delivery'
                     and e.get('component') == 'cpu' and e.get('device_id') == 'gpio_a'
                     and e.get('offset') == 0 and e.get('write') is True
                     and e.get('byte_enable') == 15 and e.get('write_value') == 0xff
                     and (write is None or e['event_id'] < write['event_id']))
    if direction is None:
        incomplete.append('gpio_a_direction_missing')
    first_observed = None if write is None else find(write['event_id'], lambda e:
                          e.get('component') == 'gpio_a'
                          and isinstance(e.get('outputs'), Mapping)
                          and type(e['outputs'].get('gpio_out')) is int)
    next_write = None if write is None else find(write['event_id'], lambda e:
                      e.get('kind') == 'mmio_delivery'
                      and e.get('device_id') == 'gpio_a'
                      and e.get('offset') == 0x0c and e.get('write') is True)
    first_tick = first_observed.get('local_tick') if first_observed else None
    # The APB receipt can include pre/post samples from the same accepted
    # access. Allow four GPIO-local clocks for its registered PADOUT result;
    # later unrelated writes cannot satisfy this obligation.
    observed = None if type(first_tick) is not int else find(write['event_id'], lambda e:
                    e.get('component') == 'gpio_a'
                    and (next_write is None or e['event_id'] < next_write['event_id'])
                    and type(e.get('local_tick')) is int
                    and first_tick <= e['local_tick'] <= first_tick + 4
                    and e.get('outputs', {}).get('gpio_out') == expected_value)
    if write is not None and first_observed is None:
        incomplete.append('gpio_a_output_missing')
    if first_observed is not None and type(first_tick) is not int:
        incomplete.append('gpio_a_local_tick_missing')
    if first_observed is not None and observed is None and type(first_tick) is int:
        settled = find(first_observed['event_id'], lambda e:
                       e.get('component') == 'gpio_a'
                       and (next_write is None or e['event_id'] < next_write['event_id'])
                       and type(e.get('local_tick')) is int
                       and e['local_tick'] >= first_tick + 4)
        if settled is None:
            incomplete.append('gpio_a_settle_window_incomplete')
        else:
            violations.append('gpio_a_output_mismatch')
    delivery = None if observed is None else find(observed['event_id'], lambda e:
                    e.get('kind') == 'dataflow_delivery'
                    and tuple(e.get('source', ())) == ('gpio_a', 'gpio_out')
                    and tuple(e.get('target', ())) == ('gpio_b', 'gpio_in')
                    and e.get('value') == expected_value
                    and e.get('producer_event_id') == observed['event_id'])
    if observed is not None and delivery is None:
        incomplete.append('gpio_a_to_b_delivery_missing')
    rise = None if delivery is None else find(delivery['event_id'], lambda e:
               e.get('component') == 'gpio_b'
               and e.get('inputs', {}).get('gpio_in', 0) & 0xff == expected_value
               and e.get('outputs', {}).get('irq') == 1)
    if delivery is not None and rise is None:
        incomplete.append('gpio_b_irq_missing')
    source = None if rise is None else find(rise['event_id'], lambda e:
                 e.get('kind') == 'source_start'
                 and tuple(e.get('source', ())) == ('gpio_b', 'irq')
                 and tuple(e.get('target', ())) == ('cpu', 'irq'))
    pulse = None if source is None else find(source['event_id'], lambda e:
                e.get('kind') == 'pulse_start'
                and tuple(e.get('source', ())) == ('gpio_b', 'irq')
                and tuple(e.get('target', ())) == ('cpu', 'irq'))
    if rise is not None and (source is None or pulse is None):
        incomplete.append('gpio_b_irq_pulse_delivery_missing')
    cpu_irq = None if pulse is None else find(pulse['event_id'], lambda e:
                  e.get('component') == 'cpu' and e.get('inputs', {}).get('irq') == 1)
    vector = None if cpu_irq is None else find(cpu_irq['event_id'], lambda e:
                 e.get('component') == 'cpu'
                 and e.get('outputs', {}).get('instr_req_accepted') == 1
                 and e.get('outputs', {}).get('instr_addr') == 0x1012c)
    if pulse is not None and (cpu_irq is None or vector is None):
        incomplete.append('cpu_irq_vector_missing')
    read = None if vector is None else find(vector['event_id'], lambda e:
               e.get('kind') == 'mmio_delivery'
               and e.get('component') == 'cpu' and e.get('device_id') == 'gpio_b'
               and e.get('offset') == 8 and e.get('write') is False)
    if vector is not None and read is None:
        incomplete.append('gpio_b_padin_read_missing')
    configured = direction is not None and not any(name in incomplete for name in (
        'gpio_b_enable_missing', 'gpio_b_irq_enable_missing',
        'gpio_b_irq_rising_missing'))
    if (read is not None and read.get('read_value') != expected_value
            and configured):
        violations.append('gpio_b_padin_read_mismatch')
    tx = read.get('source_transaction', {}) if read else {}
    tx_valid = (isinstance(tx, Mapping)
                and tx.get('source_component') == 'cpu'
                and tx.get('channel_id') == 'data'
                and all(isinstance(tx.get(field), str) and tx[field]
                        for field in ('execution_id', 'testcase_id'))
                and type(tx.get('source_epoch')) is int
                and type(tx.get('source_sequence')) is int)
    if read is not None and not tx_valid:
        incomplete.append('gpio_b_padin_transaction_missing')
    consumed = None if not tx_valid else find(read['event_id'], lambda e:
                   e.get('component') == 'cpu'
                   and e.get('outputs', {}).get('data_rsp_consumed') == 1
                   and e['outputs'].get('data_rsp_source_epoch') == tx.get('source_epoch')
                   and e['outputs'].get('data_rsp_source_sequence') == tx.get('source_sequence'))
    if consumed is not None and consumed['outputs'].get('data_rsp_rdata') != read.get('read_value'):
        violations.append('cpu_padin_response_mismatch')
    def same_cpu_case_store(event):
        identity = event.get('transaction')
        return (isinstance(identity, Mapping)
                and all(identity.get(field) == tx.get(field) for field in (
                    'execution_id', 'testcase_id', 'source_component',
                    'source_epoch', 'channel_id'))
                and type(identity.get('source_sequence')) is int
                and identity['source_sequence'] > tx['source_sequence'])

    stored = None if consumed is None else find(consumed['event_id'], lambda e:
                 e.get('kind') == 'memory_write' and e.get('component') == 'cpu'
                 and e.get('address') == 0x20000 and same_cpu_case_store(e)
                 and e.get('byte_enable') == 15)
    if stored is not None and stored.get('value') != read.get('read_value'):
        violations.append('cpu_padin_store_mismatch')
    if read is not None and (consumed is None or stored is None):
        incomplete.append('cpu_padin_response_or_store_missing')
    status = None if stored is None else find(stored['event_id'], lambda e:
                 e.get('kind') == 'mmio_delivery'
                 and e.get('component') == 'cpu' and e.get('device_id') == 'gpio_b'
                 and e.get('offset') == 0x24 and e.get('write') is False)
    if stored is not None and status is None:
        incomplete.append('gpio_b_irq_status_read_missing')
    if status is not None and status.get('read_value', 0) & 1 != 1:
        violations.append('gpio_b_irq_status_mismatch')
    status_store = None if status is None else find(status['event_id'], lambda e:
                   e.get('kind') == 'memory_write' and e.get('component') == 'cpu'
                   and e.get('address') == 0x20004
                   and e.get('value') == status.get('read_value')
                   and e.get('byte_enable') == 15)
    if status is not None and status_store is None:
        incomplete.append('cpu_irq_status_store_missing')
    return {'complete': not incomplete and not violations,
            'path_incomplete': incomplete, 'dut_violations': violations,
            'endpoint_event_id': status_store['event_id'] if status_store else None}


def check_uart_early_irq_chain(events: Iterable[Mapping],
                               final_state: Mapping) -> dict:
    """Check real UART IRQ→Ibex consumption before the real TX_DONE observation.

    The checker consumes recorded RTL observations and accepted transactions.
    It never predicts a UART output from an earlier configuration write.
    """
    stream = tuple(events)
    findings: list[str] = []
    ids = [event.get("event_id") for event in stream]
    if any(type(item) is not int for item in ids) or ids != sorted(set(ids)):
        findings.append("event_ids_not_strictly_ordered")
    if any(event.get("kind") == "reset_barrier" for event in stream):
        findings.append("unexpected_reset")

    def first(after: int, before: int | None, predicate):
        return next((event for event in stream
                     if event.get("event_id", 0) > after
                     and (before is None or event["event_id"] < before)
                     and predicate(event)), None)

    config = first(0, None, lambda e:
                   e.get("kind") == "mmio_delivery"
                   and e.get("device_id") == "uart"
                   and e.get("offset") == 0x10 and e.get("write") is True)
    write = first(config["event_id"] if config else 0, None, lambda e:
                  e.get("kind") == "mmio_delivery"
                  and e.get("device_id") == "uart"
                  and e.get("offset") == 0x1c and e.get("write") is True)
    done = first(write["event_id"] if write else 0, None, lambda e:
                 e.get("component") == "uart"
                 and e.get("outputs", {}).get("tx_done") == 1)
    cutoff = done["event_id"] if done else None
    early = first(write["event_id"] if write else 0, cutoff, lambda e:
                  e.get("component") == "uart"
                  and e.get("outputs", {}).get("irq") == 1
                  and e.get("outputs", {}).get("tx_done") == 0)
    delivery = first(early["event_id"] if early else 0, cutoff, lambda e:
                     e.get("kind") == "dataflow_delivery"
                     and tuple(e.get("source", ())) == ("uart", "irq")
                     and tuple(e.get("target", ())) == ("cpu", "irq")
                     and e.get("value") == 1
                     and e.get("producer_event_id") >= early["event_id"])
    take = first(delivery["event_id"] if delivery else 0, cutoff, lambda e:
                 e.get("component") == "cpu"
                 and e.get("inputs", {}).get("irq") == 1
                 and e.get("outputs", {}).get("irq_taken_pre") == 1)
    read = first(take["event_id"] if take else 0, cutoff, lambda e:
                 e.get("kind") == "mmio_delivery"
                 and e.get("device_id") == "uart"
                 and e.get("offset") == 0 and e.get("write") is False
                 and isinstance(e.get("read_value"), int)
                 and e["read_value"] & 1 and not e["read_value"] & 4)
    tx = read.get("source_transaction", {}) if read else {}
    consumed = first(read["event_id"] if read else 0, cutoff, lambda e:
                     e.get("component") == "cpu"
                     and e.get("outputs", {}).get("data_rsp_consumed") == 1
                     and e["outputs"].get("data_rsp_rdata") ==
                     (read.get("read_value") if read else None)
                     and e["outputs"].get("data_rsp_source_epoch") ==
                     tx.get("source_epoch")
                     and e["outputs"].get("data_rsp_source_sequence") ==
                     tx.get("source_sequence"))
    stored = first(consumed["event_id"] if consumed else 0, cutoff, lambda e:
                   e.get("kind") == "memory_write"
                   and e.get("address") == 0x200
                   and e.get("value") == (read.get("read_value") if read else None))
    for name, event in (("uart_config_missing", config),
                        ("uart_wdata_missing", write),
                        ("uart_tx_done_missing", done),
                        ("uart_early_irq_missing", early),
                        ("uart_early_irq_delivery_missing", delivery),
                        ("cpu_early_irq_take_missing", take),
                        ("uart_early_status_read_missing", read),
                        ("cpu_early_status_consume_missing", consumed),
                        ("cpu_early_status_store_missing", stored)):
        if event is None:
            findings.append(name)
    return {"complete": not findings, "findings": findings,
            "early_irq_event_id": early["event_id"] if early else None,
            "tx_done_event_id": cutoff}


def check_gpio_direct_out(events: Iterable[Mapping],
                          device_ids: tuple[str, ...]) -> tuple[CheckFinding, ...]:
    """Check a full DIRECT_OUT write against later OpenTitan GPIO output.

    A partial or masked output write retires the previous expectation because
    this checker does not reconstruct those register semantics. Reset also
    retires it. No value is inferred before an accepted write.
    """
    if (not isinstance(device_ids, tuple) or not device_ids
            or any(not isinstance(item, str) or not item for item in device_ids)
            or len(set(device_ids)) != len(device_ids)):
        raise ValueError("checker needs unique GPIO device identities")
    devices = set(device_ids)
    expected: dict[str, int] = {}
    reported: set[str] = set()
    findings: list[CheckFinding] = []
    for event in events:
        if event.get("kind") == "reset_barrier":
            expected.clear()
            reported.clear()
            continue
        if event.get("kind") == "mmio_delivery" and event.get("write"):
            device = event.get("device_id")
            offset = event.get("offset")
            if device in devices and offset in (0x14, 0x18, 0x1c):
                expected.pop(device, None)
                reported.discard(device)
                if offset == 0x14 and event.get("byte_enable") == 15:
                    value = event.get("write_value")
                    if isinstance(value, int) and not isinstance(value, bool) \
                            and 0 <= value < 1 << 32:
                        expected[device] = value
            continue
        device = event.get("component")
        if device not in expected or device in reported:
            continue
        outputs = event.get("outputs")
        if not isinstance(outputs, Mapping):
            continue
        observed = outputs.get("gpio_out")
        if isinstance(observed, int) and not isinstance(observed, bool) \
                and observed != expected[device]:
            findings.append(CheckFinding(f"gpio_direct_out_mismatch:{device}",
                                         event["event_id"], expected[device], observed))
            reported.add(device)
    return tuple(findings)


def check_cpu_gpio_closed_chain(events: Iterable[Mapping], final_state: Mapping,
                                *, expected_value: int,
                                min_rounds: int = 2) -> dict:
    """Check ordered CPU→GPIO A→GPIO B→CPU rounds using observed facts.

    This checker is specific to the reference Ibex plus two OpenTitan GPIO
    program. A scheduler's ``complete`` status never substitutes for it.
    """
    if (isinstance(expected_value, bool) or not isinstance(expected_value, int)
            or not 0 <= expected_value < 256 or isinstance(min_rounds, bool)
            or not isinstance(min_rounds, int) or min_rounds < 1):
        raise ValueError("expected GPIO byte and positive round count are required")
    stream = tuple(events)
    findings: list[str] = []
    if any(event.get("kind") == "reset_barrier" for event in stream):
        findings.append("unexpected_reset")
    ids = [event.get("event_id") for event in stream]
    if any(type(item) is not int for item in ids) or ids != sorted(set(ids)):
        findings.append("event_ids_not_strictly_ordered")

    def find(after: int, predicate):
        return next((event for event in stream
                     if event.get("event_id", 0) > after and predicate(event)), None)

    b_prior = 0
    rising_b: set[int] = set()
    falling_b: set[int] = set()
    for event in stream:
        if event.get("component") != "gpio_b" or "outputs" not in event:
            continue
        current = event["outputs"].get("irq")
        if current == 1 and b_prior == 0:
            rising_b.add(event["event_id"])
        if current == 0 and b_prior == 1:
            falling_b.add(event["event_id"])
        if current in (0, 1):
            b_prior = current

    def transaction_identity(event: Mapping) -> tuple:
        tx = event.get("source_transaction", event.get("transaction", {}))
        if not isinstance(tx, Mapping):
            return ()
        return tuple(tx.get(key) for key in (
            "execution_id", "testcase_id", "source_component", "source_epoch",
            "channel_id", "source_sequence"))

    previous_end = 0
    used_transactions: set[tuple] = set()
    rounds = 0
    while rounds < min_rounds:
        write_a = find(previous_end, lambda e:
                       e.get("kind") == "mmio_delivery"
                       and e.get("device_id") == "gpio_a"
                       and e.get("offset") == 0x14 and e.get("write") is True
                       and e.get("write_value") == expected_value)
        if write_a is None:
            findings.append(f"round_{rounds + 1}:cpu_write_a_missing")
            break
        a_output = find(write_a["event_id"], lambda e:
                        e.get("component") == "gpio_a"
                        and e.get("outputs", {}).get("gpio_out") == expected_value)
        a_delivery = None if a_output is None else find(a_output["event_id"], lambda e:
                        e.get("kind") == "dataflow_delivery"
                        and tuple(e.get("source", ())) == ("gpio_a", "gpio_out")
                        and tuple(e.get("target", ())) == ("gpio_b", "gpio_in")
                        and e.get("producer_event_id") == a_output["event_id"]
                        and e.get("value") == expected_value)
        b_rise = None if a_delivery is None else find(a_delivery["event_id"], lambda e:
                        e.get("event_id") in rising_b
                        and e.get("inputs", {}).get("gpio_in", -1) & 0xff ==
                        expected_value)
        irq_delivery = None if b_rise is None else find(b_rise["event_id"], lambda e:
                        e.get("kind") == "dataflow_delivery"
                        and tuple(e.get("source", ())) == ("gpio_b", "irq")
                        and tuple(e.get("target", ())) == ("cpu", "irq")
                        and e.get("producer_event_id") == b_rise["event_id"]
                        and e.get("value") == 1)
        cpu_take = None if irq_delivery is None else find(
            irq_delivery["event_id"], lambda e:
            e.get("component") == "cpu" and e.get("inputs", {}).get("irq") == 1
            and e.get("outputs", {}).get("irq_taken_pre") == 1)
        read_b = None if cpu_take is None else find(cpu_take["event_id"], lambda e:
                      e.get("kind") == "mmio_delivery"
                      and e.get("device_id") == "gpio_b"
                      and e.get("offset") == 0x10 and e.get("write") is False
                      and e.get("read_value") == expected_value)
        tx = read_b.get("source_transaction", {}) if read_b else {}
        consumed = None if read_b is None else find(read_b["event_id"], lambda e:
                       e.get("component") == "cpu"
                       and e.get("outputs", {}).get("data_rsp_consumed") == 1
                       and e["outputs"].get("data_rsp_rdata") == expected_value
                       and e["outputs"].get("data_rsp_source_epoch") ==
                       tx.get("source_epoch")
                       and e["outputs"].get("data_rsp_source_sequence") ==
                       tx.get("source_sequence"))
        ram_write = None if consumed is None else find(consumed["event_id"], lambda e:
                         e.get("kind") == "memory_write"
                         and e.get("address") == 0x200
                         and e.get("value") == expected_value)
        clear_b = None if ram_write is None else find(ram_write["event_id"], lambda e:
                       e.get("kind") == "mmio_delivery"
                       and e.get("device_id") == "gpio_b"
                       and e.get("offset") == 0 and e.get("write") is True
                       and e.get("write_value", 0) & 1 == 1)
        b_fall = None if clear_b is None else find(clear_b["event_id"], lambda e:
                      e.get("event_id") in falling_b)
        cpu_low = None if b_fall is None else find(b_fall["event_id"], lambda e:
                      e.get("component") == "cpu"
                      and e.get("inputs", {}).get("irq") == 0)
        stages = (write_a, a_output, a_delivery, b_rise, irq_delivery, cpu_take,
                  read_b, consumed, ram_write, clear_b, b_fall, cpu_low)
        if any(stage is None for stage in stages):
            names = ("cpu_write_a", "a_output", "a_to_b", "b_irq_rise",
                     "b_to_cpu", "cpu_take", "cpu_read_b", "cpu_consume_rdata",
                     "cpu_ram_write", "cpu_clear_b", "b_irq_fall", "cpu_irq_low")
            findings.append(f"round_{rounds + 1}:" +
                            names[next(i for i, stage in enumerate(stages)
                                       if stage is None)] + "_missing")
            break
        for stage in (write_a, read_b, ram_write, clear_b):
            identity = transaction_identity(stage)
            if not identity or any(value is None for value in identity):
                findings.append(f"round_{rounds + 1}:transaction_identity_missing")
            elif identity in used_transactions:
                findings.append(f"round_{rounds + 1}:transaction_reused")
            used_transactions.add(identity)
        previous_end = cpu_low["event_id"]
        rounds += 1

    pending = final_state.get("pending_responses", {})
    if not isinstance(pending, Mapping) or any(value != 0 for value in pending.values()):
        findings.append("pending_responses_at_end")
    inputs = final_state.get("inputs", {})
    if not isinstance(inputs, Mapping) or inputs.get("cpu", {}).get("irq") != 0:
        findings.append("cpu_irq_high_at_end")
    if b_prior != 0:
        findings.append("gpio_b_irq_high_at_end")
    if rounds < min_rounds:
        findings.append("too_few_closed_rounds")
    return {"complete": not findings, "rounds": rounds, "findings": findings}


def check_gpio_cpu_gpio_closed_chain(events: Iterable[Mapping], final_state: Mapping,
                                     *, expected_values: tuple[int, ...]) -> dict:
    """Check external B input→real IRQ→Ibex ISR→real GPIO A output rounds."""
    if (not isinstance(expected_values, tuple) or len(expected_values) < 2
            or any(isinstance(value, bool) or not isinstance(value, int)
                   or not 0 < value < 1 << 32 for value in expected_values)):
        raise ValueError("two or more positive external GPIO values are required")
    stream = tuple(events)
    findings: list[str] = []
    if any(event.get("kind") == "reset_barrier" for event in stream):
        findings.append("unexpected_reset")
    ids = [event.get("event_id") for event in stream]
    if any(type(item) is not int for item in ids) or ids != sorted(set(ids)):
        findings.append("event_ids_not_strictly_ordered")

    def find(after: int, predicate):
        return next((event for event in stream
                     if event.get("event_id", 0) > after and predicate(event)), None)

    b_prior = 0
    rising_b: set[int] = set()
    falling_b: set[int] = set()
    for event in stream:
        if event.get("component") != "gpio_b" or "outputs" not in event:
            continue
        current = event["outputs"].get("irq")
        if current == 1 and b_prior == 0:
            rising_b.add(event["event_id"])
        if current == 0 and b_prior == 1:
            falling_b.add(event["event_id"])
        if current in (0, 1):
            b_prior = current

    def identity(event: Mapping) -> tuple:
        tx = event.get("source_transaction", event.get("transaction", {}))
        if not isinstance(tx, Mapping):
            return ()
        return tuple(tx.get(key) for key in (
            "execution_id", "testcase_id", "source_component", "source_epoch",
            "channel_id", "source_sequence"))

    previous_end = 0
    used_transactions: set[tuple] = set()
    rounds = 0
    for value in expected_values:
        injection = find(previous_end, lambda e:
                         e.get("kind") == "source_injection"
                         and e.get("component") == "gpio_b"
                         and e.get("port") == "gpio_in"
                         and e.get("value") == value)
        b_rise = None if injection is None else find(injection["event_id"], lambda e:
                        e.get("event_id") in rising_b
                        and e.get("inputs", {}).get("gpio_in") == value)
        irq_delivery = None if b_rise is None else find(b_rise["event_id"], lambda e:
                        e.get("kind") == "dataflow_delivery"
                        and tuple(e.get("source", ())) == ("gpio_b", "irq")
                        and tuple(e.get("target", ())) == ("cpu", "irq")
                        and e.get("producer_event_id") == b_rise["event_id"]
                        and e.get("value") == 1)
        cpu_take = None if irq_delivery is None else find(
            irq_delivery["event_id"], lambda e:
            e.get("component") == "cpu" and e.get("inputs", {}).get("irq") == 1
            and e.get("outputs", {}).get("irq_taken_pre") == 1)
        read_b = None if cpu_take is None else find(cpu_take["event_id"], lambda e:
                      e.get("kind") == "mmio_delivery"
                      and e.get("device_id") == "gpio_b"
                      and e.get("offset") == 0x10 and e.get("write") is False
                      and e.get("read_value") == value)
        tx = read_b.get("source_transaction", {}) if read_b else {}
        consumed = None if read_b is None else find(read_b["event_id"], lambda e:
                       e.get("component") == "cpu"
                       and e.get("outputs", {}).get("data_rsp_consumed") == 1
                       and e["outputs"].get("data_rsp_rdata") == value
                       and e["outputs"].get("data_rsp_source_epoch") ==
                       tx.get("source_epoch")
                       and e["outputs"].get("data_rsp_source_sequence") ==
                       tx.get("source_sequence"))
        write_a = None if consumed is None else find(consumed["event_id"], lambda e:
                       e.get("kind") == "mmio_delivery"
                       and e.get("device_id") == "gpio_a"
                       and e.get("offset") == 0x14 and e.get("write") is True
                       and e.get("write_value") == value)
        a_output = None if write_a is None else find(write_a["event_id"], lambda e:
                        e.get("component") == "gpio_a"
                        and e.get("outputs", {}).get("gpio_out") == value)
        ram_write = None if a_output is None else find(a_output["event_id"], lambda e:
                         e.get("kind") == "memory_write"
                         and e.get("address") == 0x200 and e.get("value") == value)
        clear_b = None if ram_write is None else find(ram_write["event_id"], lambda e:
                       e.get("kind") == "mmio_delivery"
                       and e.get("device_id") == "gpio_b"
                       and e.get("offset") == 0 and e.get("write") is True
                       and e.get("write_value", 0) & 0x100 == 0x100)
        b_fall = None if clear_b is None else find(clear_b["event_id"], lambda e:
                      e.get("event_id") in falling_b)
        cpu_low = None if b_fall is None else find(b_fall["event_id"], lambda e:
                      e.get("component") == "cpu"
                      and e.get("inputs", {}).get("irq") == 0)
        stages = (injection, b_rise, irq_delivery, cpu_take, read_b, consumed,
                  write_a, a_output, ram_write, clear_b, b_fall, cpu_low)
        if any(stage is None for stage in stages):
            names = ("external_injection", "b_irq_rise", "b_to_cpu", "cpu_take",
                     "cpu_read_b", "cpu_consume_rdata", "cpu_write_a",
                     "a_output", "cpu_ram_write", "cpu_clear_b", "b_irq_fall",
                     "cpu_irq_low")
            findings.append(f"round_{rounds + 1}:" +
                            names[next(i for i, stage in enumerate(stages)
                                       if stage is None)] + "_missing")
            break
        for stage in (read_b, write_a, ram_write, clear_b):
            txid = identity(stage)
            if not txid or any(part is None for part in txid):
                findings.append(f"round_{rounds + 1}:transaction_identity_missing")
            elif txid in used_transactions:
                findings.append(f"round_{rounds + 1}:transaction_reused")
            used_transactions.add(txid)
        previous_end = cpu_low["event_id"]
        rounds += 1

    pending = final_state.get("pending_responses", {})
    if not isinstance(pending, Mapping) or any(value != 0 for value in pending.values()):
        findings.append("pending_responses_at_end")
    inputs = final_state.get("inputs", {})
    if not isinstance(inputs, Mapping) or inputs.get("cpu", {}).get("irq") != 0:
        findings.append("cpu_irq_high_at_end")
    if b_prior != 0:
        findings.append("gpio_b_irq_high_at_end")
    if rounds < len(expected_values):
        findings.append("too_few_closed_rounds")
    return {"complete": not findings, "rounds": rounds, "findings": findings}
