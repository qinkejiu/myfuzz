"""A computed RV32I value is certified only when a real device consumed the same value.

The positive journal is built from the shapes the frozen online traces actually
carry: an RVFI ``cpu_retire`` arithmetic retirement, the MMIO store hops
(``mmio_acceptance``/``data_accept``/``gpio_target_receipt``/``mmio_delivery``),
and a device-internal consumption witness (``gpio_register_commit``,
``gpio_apb_access`` with observed APB probes, or a UART serial byte/count
change).  Every negative case must produce no certified certificate and must be
accounted in ``rejections``.

The real-trace tests at the end only read already-frozen artifacts through
``TraceEventStream``; they never start RTL.
"""

import pytest

from myfuzz.scenario.acceptance_metrics import TraceEventStream
from myfuzz.scenario.computed_value_certificates import (
    SCHEMA_VERSION,
    ComputedValueCertificates,
    decode_computed_value,
)


# --------------------------------------------------------------------------
# journal builders
# --------------------------------------------------------------------------

OP_IMM = 0x13
LUI = 0x37


def key(sequence, case="case-1", epoch=0, execution="local-execution"):
    return {"channel_id": "data", "execution_id": execution, "source_component": "cpu",
            "source_epoch": epoch, "source_sequence": sequence, "testcase_id": case}


def encode_itype(rd, rs1, funct3, imm, funct7=0):
    word = ((funct7 & 0x7f) << 25) | ((imm & 0xfff) << 20) | (rs1 << 15)
    return (word | (funct3 << 12) | (rd << 7) | OP_IMM)


def encode_lui(rd, imm20):
    return ((imm20 & 0xfffff) << 12) | (rd << 7) | LUI


def retire(event_id, order, insn, rd, value, *, rs1=0, rs1_rdata=0,
           pc=0x10000, epoch=0, trap=0, **overrides):
    event = {"kind": "cpu_retire", "event_id": event_id, "order": order,
             "pc_rdata": pc, "insn": insn, "trap": trap, "valid": 1, "phase": "post",
             "schema_version": "cpu_retire.v2", "component": "cpu",
             "execution_id": "local-execution", "source_component": "cpu",
             "source_epoch": epoch, "reset_epoch": epoch,
             "rd_addr": rd, "rd_wdata": value, "rs1_addr": rs1, "rs1_rdata": rs1_rdata,
             "rs2_addr": 0, "rs2_rdata": 0, "mem_addr": 0, "mem_rmask": 0,
             "mem_wmask": 0, "mem_rdata": 0, "mem_wdata": 0}
    event.update(overrides)
    return event


def mmio_acceptance(event_id, txn, *, address, offset, device="gpio_b", be=15, value=0,
                    **overrides):
    event = {"kind": "mmio_acceptance", "event_id": event_id, "address": address,
             "offset": offset, "device_id": device, "write": True, "byte_enable": be,
             "beat_bytes": 4, "acceptance_order": 1,
             "source_sequence": txn["source_sequence"],
             "source_transaction": dict(txn), "write_value": value}
    event.update(overrides)
    return event


def mmio_delivery(event_id, txn, *, address, offset, device="gpio_b", be=15, value=0,
                  **overrides):
    event = {"kind": "mmio_delivery", "event_id": event_id, "address": address,
             "offset": offset, "device_id": device, "write": True, "byte_enable": be,
             "beat_bytes": 4, "delivery_order": 1, "read_value": None,
             "source_sequence": txn["source_sequence"],
             "source_transaction": dict(txn), "target_delivery_order": 1,
             "write_value": value}
    event.update(overrides)
    return event


def data_accept(event_id, txn, *, address, be=15, value=0, **overrides):
    event = {"kind": "data_accept", "event_id": event_id, "write": 1, "be": be,
             "wdata": value, "raw_address": address, "aligned_address": address & ~3,
             "address": address & ~3, "transaction": dict(txn)}
    event.update(overrides)
    return event


def data_response(event_id, txn, *, address, be=15, value=0, error=0, **overrides):
    event = {"kind": "data_response", "event_id": event_id, "write": 1, "be": be,
             "wdata": value, "error": error, "rdata": 0, "raw_address": address,
             "aligned_address": address & ~3, "address": address & ~3,
             "transaction": dict(txn)}
    event.update(overrides)
    return event


def gpio_receipt(event_id, txn, *, offset, value, write=True, status="received",
                 **overrides):
    event = {"kind": "gpio_target_receipt", "event_id": event_id, "component": "gpio_b",
             "write": write, "raw_offset": offset, "wdata": value if write else None,
             "status": status, "source_transaction": dict(txn)}
    event.update(overrides)
    return event


def gpio_apb(event_id, txn, *, offset, value, write=True, status="observed",
             **overrides):
    probes = {"psel": 1, "penable": 1, "pwrite": int(write), "pwdata": value,
              "pready": 1, "pslverr": 0, "apb_addr": offset}
    pre = {"gpio_probe_" + name: probe for name, probe in probes.items()}
    event = {"kind": "gpio_apb_access", "event_id": event_id, "component": "gpio_b",
             "write": write, "raw_offset": offset, "decoded_offset": offset & ~3,
             "wdata": value if write else None, "status": status, "pre": pre,
             "post": {"gpio_probe_psel": 0},
             "target_response": {"rdata": 0, "error": 0},
             "source_transaction": dict(txn)}
    event.update(overrides)
    return event


def gpio_commit(event_id, txn, *, offset, value, register="gpioen", apb_event_id,
                status="observed", pre_value=0, bits=32, **overrides):
    resources = [{"bit": bit, "component": "gpio_b", "register": register,
                  "value": (value >> bit) & 1,
                  "transaction": dict(txn) if bit < 32 else None,
                  "version": 100 + bit, "observation_event_id": apb_event_id}
                 for bit in range(bits)]
    event = {"kind": "gpio_register_commit", "event_id": event_id,
             "component": "gpio_b", "register": register, "raw_offset": offset,
             "decoded_offset": offset & ~3, "fullkey": dict(txn),
             "write_value": value, "pre_value": pre_value, "post_value": value,
             "changed_mask": pre_value ^ value, "operation": "overwrite",
             "status": status, "observation_event_id": apb_event_id,
             "proof_scope": "gpio_native_resource_observation",
             "reason": "actual_apb_register_write", "bit_resources": resources}
    event.update(overrides)
    return event


def uart_observation(event_id, *, count, byte, tick=1):
    return {"event_id": event_id, "component": "uart", "local_tick": tick,
            "inputs": {"uart_rx_byte": 0},
            "outputs": {"serial_rx_read": 0, "serial_rx_word": 0,
                        "serial_tx_count": count, "serial_tx_last": byte,
                        "uart_tx": 1, "uart_tx_done": 0, "uart_tx_empty": 0}}


def uart_access_observation(event_id, txn, *, offset, value, tick=1):
    return {"kind": "uart_tick_observation", "event_id": event_id, "component": "uart",
            "local_tick": tick, "physical_rx_ref": None, "physical_rx_value": 1,
            "access": {"access_id": f"uart-access:uart:0:{event_id}",
                       "address": 0x40000000 + offset, "raw_offset": offset,
                       "write": True,
                       "source_transaction": dict(txn),
                       "delivery_context": {"address": 0x40000000 + offset,
                                            "be": 15, "device_id": "uart",
                                            "offset": offset,
                                            "source_transaction": dict(txn),
                                            "value": value, "window_base": 0x40000000,
                                            "window_size": 4096, "write": True}}}


def reset(event_id, epoch=1):
    return {"kind": "reset_barrier", "event_id": event_id, "component": "cpu",
            "reset_epoch": epoch}


def journal(*events):
    """Renumber nothing: builders already take explicit contiguous ids."""
    return list(events)


def consume(events, consumer, *, flush=True):
    certificates = []
    for event in events:
        certificates.extend(consumer.ingest((event,)))
    if flush:
        certificates.extend(consumer.flush())
    return certificates


# --------------------------------------------------------------------------
# decoder
# --------------------------------------------------------------------------

def test_decoder_accepts_supported_rv32i_arithmetic_immediates():
    assert decode_computed_value(encode_lui(5, 0x12345)) == {
        "operation": "lui", "immediate": 0x12345000, "computed_value": 0x12345000}
    assert decode_computed_value(encode_itype(2, 0, 0, 0x101), 0)["computed_value"] == 0x101
    assert decode_computed_value(encode_itype(2, 3, 4, 0x0ff), 0x100)["computed_value"] == 0x1ff
    assert decode_computed_value(encode_itype(2, 3, 6, 0x0f0), 0x10f)["computed_value"] == 0x1ff
    assert decode_computed_value(encode_itype(2, 3, 7, 0x0f0), 0x1ff)["computed_value"] == 0x0f0
    assert decode_computed_value(encode_itype(2, 3, 1, 12, 0), 1)["computed_value"] == 0x1000
    assert decode_computed_value(encode_itype(2, 3, 5, 4, 0), 0x1000)["computed_value"] == 0x100
    assert decode_computed_value(encode_itype(2, 3, 5, 4, 0b0100000), 0xfffffff0)[
        "computed_value"] == 0xffffffff


def test_decoder_rejects_reserved_and_unsupported_encodings():
    # A shift with a reserved funct7 must never be re-read as a wider shamt.
    assert decode_computed_value(encode_itype(2, 3, 1, 1, 0b0100000), 1) is None
    assert decode_computed_value(encode_itype(2, 3, 5, 1, 0b0000001), 1) is None
    assert decode_computed_value(0x00000013, 0) is None          # NOP padding is not a value
    assert decode_computed_value(0x00000023, 0) is None          # store encoding
    assert decode_computed_value(0x00000003, 0) is None          # load encoding


# --------------------------------------------------------------------------
# positive synthetic journals
# --------------------------------------------------------------------------

def _gpio_chain(txn, value=0x101):
    """compute -> acceptance -> cpu acceptance -> receipt -> apb -> commit -> delivery."""
    return journal(
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(2, txn, address=0x40001004, offset=4, value=value),
        data_accept(3, txn, address=0x40001004, value=value),
        gpio_receipt(4, txn, offset=4, value=value),
        gpio_apb(5, txn, offset=4, value=value),
        gpio_commit(6, txn, offset=4, value=value, apb_event_id=5),
        mmio_delivery(7, txn, address=0x40001004, offset=4, value=value),
        data_response(8, txn, address=0x40001004, value=value),
    )


def test_compute_to_gpio_register_commit_is_certified_with_full_hop_order():
    txn = key(1)
    consumer = ComputedValueCertificates()
    certificates = consume(_gpio_chain(txn), consumer)

    assert len(certificates) == 1
    certificate = certificates[0]
    assert certificate["schema_version"] == SCHEMA_VERSION
    assert certificate["status"] == "certified"
    assert certificate["reason"] is None
    assert certificate["missing_hops"] == []
    assert certificate["transaction"] == txn
    assert certificate["execution"] == {
        "execution_id": "local-execution", "testcase_id": "case-1", "source_epoch": 0}
    assert certificate["computed"]["event_id"] == 1
    assert certificate["computed"]["operation"] == "addi"
    assert certificate["computed"]["rd_addr"] == 5
    assert certificate["computed"]["computed_value"] == 0x101
    assert certificate["computed"]["alternative_event_ids"] == []
    assert certificate["enabled_lanes"] == [0, 1, 2, 3]
    assert certificate["lane_values"] == {"0": 0x01, "1": 0x01, "2": 0x00, "3": 0x00}
    assert certificate["store_value"] == 0x101
    assert certificate["event_ids"] == [1, 2, 3, 4, 5, 6, 7, 8]
    assert [hop["hop_id"] for hop in certificate["hops"]] == [
        "cpu_compute", "mmio_acceptance", "data_accept", "gpio_target_receipt",
        "device_consumption", "device_consumption", "mmio_delivery", "data_response"]
    assert [hop["kind"] for hop in certificate["hops"]][4:6] == [
        "gpio_apb_access", "gpio_register_commit"]
    assert certificate["consumption"]["kind"] == "gpio_register_commit"
    assert certificate["consumption"]["event_id"] == 6
    assert certificate["consumption"]["register"] == "gpioen"
    assert certificate["consumption"]["observation_event_id"] == 5
    assert [w["kind"] for w in certificate["consumption_witnesses"]] == [
        "gpio_apb_access", "gpio_register_commit"]
    assert certificate["proof_scope"] == (
        "exact_value_identity_on_enabled_lanes_from_rvfi_compute_to_device_consumption")
    assert "register_file_internal_source_token" in certificate["not_proof_of"]
    assert "cross_instruction_data_dependency" in certificate["not_proof_of"]
    assert "computed_value_was_used_by_a_later_instruction" in certificate["not_proof_of"]
    assert consumer.rejections == {}
    assert consumer.pending_count == 0


def test_lane_enabled_bytes_only_are_compared():
    txn = key(1)
    # The high lanes of rs2 carry unrelated bits; only be=1 lane 0 is certified.
    events = journal(
        uart_observation(1, count=0, byte=0),
        retire(2, 1, encode_lui(6, 0x12345), 6, 0x12345000),
        mmio_acceptance(3, txn, address=0x4000101c, offset=28, device="uart", be=1,
                        value=0x92345abc),
        uart_access_observation(4, txn, offset=28, value=0x92345abc),
        mmio_delivery(5, txn, address=0x4000101c, offset=28, device="uart", be=1,
                      value=0x92345abc),
        uart_observation(6, count=1, byte=0xbc),
    )
    # lane 0 of the computed LUI value is 0x00 and the store lane 0 is 0xbc.
    consumer = ComputedValueCertificates()
    certificates = consume(events, consumer)
    assert certificates == []
    # Counted once for the store transaction, not once per hop event.
    assert consumer.rejections["mmio_store_without_computed_value"] == 1
    assert consumer.rejections["terminal_without_chain"] == 1

    events = journal(
        uart_observation(1, count=0, byte=0),
        retire(2, 1, encode_lui(6, 0x12345), 6, 0x12345000),
        mmio_acceptance(3, txn, address=0x4000101c, offset=28, device="uart", be=1,
                        value=0x92345000),
        uart_access_observation(4, txn, offset=28, value=0x92345000),
        mmio_delivery(5, txn, address=0x4000101c, offset=28, device="uart", be=1,
                      value=0x92345000),
        uart_observation(6, count=1, byte=0x00),
    )
    consumer = ComputedValueCertificates()
    certificates = consume(events, consumer)
    assert [c["status"] for c in certificates] == ["certified"]
    certificate = certificates[0]
    assert certificate["enabled_lanes"] == [0]
    assert certificate["lane_values"] == {"0": 0x00}
    assert [w["kind"] for w in certificate["consumption_witnesses"]] == [
        "uart_tick_observation_access", "uart_serial_observation"]
    assert certificate["consumption"]["kind"] == "uart_serial_observation"
    assert certificate["consumption"]["serial_tx_count"] == 1
    assert certificate["consumption"]["serial_tx_last"] == 0x00


def test_uart_serial_byte_must_be_the_first_increment_after_delivery():
    txn = key(9)
    events = journal(
        uart_observation(1, count=0, byte=0),
        retire(2, 1, encode_itype(2, 0, 0, 0x0c), 2, 0x0c),
        mmio_acceptance(3, txn, address=0x4000001c, offset=28, device="uart", be=1,
                        value=0x0c),
        uart_access_observation(4, txn, offset=28, value=0x0c),
        mmio_delivery(5, txn, address=0x4000001c, offset=28, device="uart", be=1,
                      value=0x0c),
        uart_observation(6, count=1, byte=0x0d),
    )
    consumer = ComputedValueCertificates()
    certificates = consume(events, consumer)
    # The serial byte is refused, but the independently verified device access
    # witness is untouched and still certifies the exact value identity.
    assert [c["status"] for c in certificates] == ["certified"]
    assert [w["kind"] for w in certificates[0]["consumption_witnesses"]] == [
        "uart_tick_observation_access"]
    assert certificates[0]["consumption"]["kind"] == "uart_tick_observation_access"
    assert consumer.rejections["uart_serial_observation_mismatch"] == 1

    # Without any device witness the mismatching byte leaves an incomplete chain.
    consumer = ComputedValueCertificates()
    certificates = consume(journal(
        uart_observation(1, count=0, byte=0),
        retire(2, 1, encode_itype(2, 0, 0, 0x0c), 2, 0x0c),
        mmio_acceptance(3, txn, address=0x4000001c, offset=28, device="uart", be=1,
                        value=0x0c),
        mmio_delivery(4, txn, address=0x4000001c, offset=28, device="uart", be=1,
                      value=0x0c),
        uart_observation(5, count=1, byte=0x0d),
    ), consumer)
    assert [c["status"] for c in certificates] == ["incomplete"]
    assert certificates[0]["missing_hops"] == ["device_consumption"]
    assert consumer.rejections["uart_serial_observation_mismatch"] == 1


# --------------------------------------------------------------------------
# negative journals
# --------------------------------------------------------------------------

def test_store_value_off_by_one_is_never_certified():
    txn = key(1)
    events = journal(
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(2, txn, address=0x40001004, offset=4, value=0x102),
        gpio_apb(3, txn, offset=4, value=0x102),
        gpio_commit(4, txn, offset=4, value=0x102, apb_event_id=3),
    )
    consumer = ComputedValueCertificates()
    assert consume(events, consumer) == []
    assert consumer.rejections["mmio_store_without_computed_value"] == 1


def test_retirement_value_that_the_instruction_did_not_compute_is_not_a_start():
    txn = key(1)
    # ADDI x5, x0, 0x101 can only produce 0x101; the frame claims 0x777.
    events = journal(
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x777),
        mmio_acceptance(2, txn, address=0x40001004, offset=4, value=0x777),
        gpio_apb(3, txn, offset=4, value=0x777),
        gpio_commit(4, txn, offset=4, value=0x777, apb_event_id=3),
    )
    consumer = ComputedValueCertificates()
    assert consume(events, consumer) == []
    assert consumer.rejections["illegal_computed_value"] == 1
    assert consumer.rejections["mmio_store_without_computed_value"] == 1


def test_trap_and_zero_register_and_invalid_retirement_are_not_starts():
    txn = key(1)
    events = journal(
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101, trap=1),
        retire(2, 2, encode_itype(0, 0, 0, 0x101), 0, 0x101),
        retire(3, 3, encode_itype(5, 0, 0, 0x101), 5, 0x101, valid=0),
        retire(4, 4, encode_itype(5, 0, 0, 0x101), 5, 0x101, phase="pre"),
        mmio_acceptance(5, txn, address=0x40001004, offset=4, value=0x101),
        gpio_apb(6, txn, offset=4, value=0x101),
    )
    consumer = ComputedValueCertificates()
    assert consume(events, consumer) == []
    assert consumer.rejections["retirement_trap_observation_only"] == 1
    assert consumer.rejections["discarded_zero_register_write"] == 1
    assert consumer.rejections["invalid_retirement_valid"] == 1
    assert consumer.rejections["retirement_phase_not_post"] == 1
    assert consumer.rejections["mmio_store_without_computed_value"] == 1


def test_lane_mismatch_between_acceptance_and_delivery_drops_the_chain():
    txn = key(1)
    events = journal(
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(2, txn, address=0x40001004, offset=4, be=15, value=0x101),
        mmio_delivery(3, txn, address=0x40001004, offset=4, be=1, value=0x101),
        gpio_apb(4, txn, offset=4, value=0x101),
        gpio_commit(5, txn, offset=4, value=0x101, apb_event_id=4),
    )
    consumer = ComputedValueCertificates()
    assert consume(events, consumer) == []
    assert consumer.rejections["hop_lane_mismatch"] == 1
    assert consumer.rejections["terminal_without_chain"] == 2


def test_hop_value_mismatch_on_a_later_hop_drops_the_chain():
    txn = key(1)
    events = journal(
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(2, txn, address=0x40001004, offset=4, value=0x101),
        mmio_delivery(3, txn, address=0x40001004, offset=4, value=0x102),
        gpio_apb(4, txn, offset=4, value=0x101),
        gpio_commit(5, txn, offset=4, value=0x101, apb_event_id=4),
    )
    consumer = ComputedValueCertificates()
    assert consume(events, consumer) == []
    assert consumer.rejections["hop_value_mismatch"] == 1
    assert consumer.rejections["terminal_without_chain"] == 2


def test_hop_address_mismatch_drops_the_chain():
    txn = key(1)
    events = journal(
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(2, txn, address=0x40001004, offset=4, value=0x101),
        data_accept(3, txn, address=0x40001008, value=0x101),
        gpio_apb(4, txn, offset=4, value=0x101),
    )
    consumer = ComputedValueCertificates()
    assert consume(events, consumer) == []
    assert consumer.rejections["hop_address_mismatch"] == 1
    assert consumer.rejections["terminal_without_chain"] == 1


def test_transaction_key_mismatch_never_yields_a_certificate():
    txn = key(1)
    other = key(2)
    events = journal(
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(2, txn, address=0x40001004, offset=4, value=0x101),
        mmio_delivery(3, txn, address=0x40001004, offset=4, value=0x101),
        gpio_apb(4, other, offset=4, value=0x101),
        gpio_commit(5, other, offset=4, value=0x101, apb_event_id=4),
    )
    consumer = ComputedValueCertificates()
    certificates = consume(events, consumer)
    assert [c["status"] for c in certificates] == ["incomplete"]
    assert certificates[0]["missing_hops"] == ["device_consumption"]
    assert certificates[0]["transaction"] == txn
    assert certificates[0]["consumption"] is None
    assert consumer.rejections["terminal_without_chain"] == 2
    assert consumer.certified_count == 0


def test_commit_observation_event_id_must_point_at_the_certified_apb_access():
    txn = key(1)
    events = journal(
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(2, txn, address=0x40001004, offset=4, value=0x101),
        gpio_apb(3, txn, offset=4, value=0x101),
        gpio_commit(4, txn, offset=4, value=0x101, apb_event_id=99),
    )
    consumer = ComputedValueCertificates()
    assert consume(events, consumer) == []
    assert consumer.rejections["terminal_identity_mismatch"] == 1


def test_forged_commit_bit_resource_value_is_rejected():
    txn = key(1)
    forged = gpio_commit(4, txn, offset=4, value=0x101, apb_event_id=3)
    forged["bit_resources"][0]["value"] = 0
    events = journal(
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(2, txn, address=0x40001004, offset=4, value=0x101),
        gpio_apb(3, txn, offset=4, value=0x101),
        forged,
    )
    consumer = ComputedValueCertificates()
    assert consume(events, consumer) == []
    assert consumer.rejections["terminal_value_mismatch"] == 1


def test_missing_device_consumption_stays_incomplete():
    txn = key(1)
    events = journal(
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(2, txn, address=0x40001004, offset=4, value=0x101),
        gpio_receipt(3, txn, offset=4, value=0x101),
        mmio_delivery(4, txn, address=0x40001004, offset=4, value=0x101),
    )
    consumer = ComputedValueCertificates()
    certificates = consume(events, consumer)
    assert [c["status"] for c in certificates] == ["incomplete"]
    certificate = certificates[0]
    assert certificate["missing_hops"] == ["device_consumption"]
    assert certificate["reason"] == "expired_without_device_consumption"
    assert certificate["consumption"] is None
    assert consumer.rejections["expired_without_device_consumption"] == 1
    assert consumer.certified_count == 0
    assert consumer.incomplete_count == 1


def test_forged_event_id_gap_drops_every_pending_chain():
    txn = key(1)
    events = journal(
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(2, txn, address=0x40001004, offset=4, value=0x101),
        gpio_apb(5, txn, offset=4, value=0x101),
        gpio_commit(6, txn, offset=4, value=0x101, apb_event_id=5),
    )
    consumer = ComputedValueCertificates()
    assert consume(events, consumer) == []
    assert consumer.rejections["journal_gap"] == 1
    assert consumer.rejections["terminal_without_chain"] == 2


def test_non_monotonic_event_id_is_rejected():
    txn = key(1)
    events = journal(
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(2, txn, address=0x40001004, offset=4, value=0x101),
        mmio_acceptance(2, txn, address=0x40001004, offset=4, value=0x101),
        gpio_apb(3, txn, offset=4, value=0x101),
    )
    consumer = ComputedValueCertificates()
    assert consume(events, consumer) == []
    assert consumer.rejections["non_monotonic_event_id"] == 1
    assert consumer.rejections["terminal_without_chain"] == 1

def test_malformed_journal_event_is_counted_and_cancels_pending_work():
    txn = key(1)
    consumer = ComputedValueCertificates()
    certificates = consume(journal(
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(2, txn, address=0x40001004, offset=4, value=0x101),
        {"kind": "mmio_delivery", "no_event_id": True},
        gpio_apb(4, txn, offset=4, value=0x101),
    ), consumer)
    assert certificates == []
    assert consumer.rejections["malformed_event"] == 1


def test_reset_between_compute_and_consumption_cancels_the_chain():
    txn = key(1)
    events = journal(
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(2, txn, address=0x40001004, offset=4, value=0x101),
        reset(3),
        gpio_apb(4, txn, offset=4, value=0x101),
        gpio_commit(5, txn, offset=4, value=0x101, apb_event_id=4),
    )
    consumer = ComputedValueCertificates()
    assert consume(events, consumer) == []
    assert consumer.rejections["reset_barrier_cancelled_pending"] == 1
    assert consumer.rejections["terminal_without_chain"] == 2


def test_epoch_mismatch_between_compute_and_store_is_not_certified():
    txn = key(1, epoch=1)
    events = journal(
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101, epoch=0),
        mmio_acceptance(2, txn, address=0x40001004, offset=4, value=0x101),
        gpio_apb(3, txn, offset=4, value=0x101),
        gpio_commit(4, txn, offset=4, value=0x101, apb_event_id=3),
    )
    consumer = ComputedValueCertificates()
    assert consume(events, consumer) == []
    assert consumer.rejections["mmio_store_without_computed_value"] == 1


def test_malformed_transaction_key_is_counted_not_certified():
    consumer = ComputedValueCertificates()
    certificates = consume(journal(
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        {"kind": "mmio_acceptance", "event_id": 2, "address": 0x40001004,
         "offset": 4, "device_id": "gpio_b", "write": True, "byte_enable": 15,
         "write_value": 0x101,
         "source_transaction": {"execution_id": "local-execution", "channel_id": "data"}},
    ), consumer)
    assert certificates == []
    assert consumer.rejections["malformed_transaction_key"] == 1


def test_read_only_mmio_traffic_is_never_a_propagation_hop():
    txn = key(1)
    consumer = ComputedValueCertificates()
    certificates = consume(journal(
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(2, txn, address=0x40001008, offset=8, value=None, write=False),
        gpio_apb(3, txn, offset=8, value=None, write=False),
    ), consumer)
    assert certificates == []
    assert consumer.rejections == {}


# --------------------------------------------------------------------------
# bounds
# --------------------------------------------------------------------------

def test_value_history_is_bounded_and_older_candidates_expire():
    consumer = ComputedValueCertificates(max_value_history=2)
    events = [retire(index, index, encode_itype(5, 0, 0, 0x100 + index), 5,
                     0x100 + index) for index in range(1, 5)]
    txn = key(1)
    events.append(mmio_acceptance(5, txn, address=0x40001004, offset=4, value=0x101))
    events.append(gpio_apb(6, txn, offset=4, value=0x101))
    events.append(gpio_commit(7, txn, offset=4, value=0x101, apb_event_id=6))
    certificates = consume(events, consumer)
    assert certificates == []
    assert consumer.rejections["mmio_store_without_computed_value"] == 1
    assert consumer.counters["value_history_evicted"] == 2
    assert consumer.pending_count == 0


def test_hop_gap_bound_expires_the_chain_before_a_late_consumption():
    txn = key(1)
    events = journal(
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(2, txn, address=0x40001004, offset=4, value=0x101),
    )
    consumer = ComputedValueCertificates(max_event_gap=4)
    certificates = consume(events, consumer)
    assert [c["status"] for c in certificates] == ["incomplete"]
    assert certificates[0]["missing_hops"] == ["device_consumption"]
    late = journal(
        gpio_apb(20, txn, offset=4, value=0x101),
        gpio_commit(21, txn, offset=4, value=0x101, apb_event_id=20),
    )
    assert consume(late, consumer) == []
    assert consumer.rejections["terminal_without_chain"] == 2


def test_pending_chains_are_bounded_and_never_exceed_max_pending():
    consumer = ComputedValueCertificates(max_pending=2, max_event_gap=64)
    emitted = []
    peak = 0
    for sequence in range(1, 7):
        txn = key(sequence)
        events = journal(
            retire(3 * sequence - 2, sequence,
                   encode_itype(5, 0, 0, 0x101), 5, 0x101),
            mmio_acceptance(3 * sequence - 1, txn, address=0x40001004 + 4 * sequence,
                            offset=4 * sequence, value=0x101),
            mmio_delivery(3 * sequence, txn, address=0x40001004 + 4 * sequence,
                          offset=4 * sequence, value=0x101),
        )
        for event in events:
            emitted.extend(consumer.ingest((event,)))
            peak = max(peak, consumer.pending_count)
    emitted.extend(consumer.flush())
    assert peak <= consumer.max_pending
    assert consumer.pending_count == 0
    assert all(c["status"] == "incomplete" for c in emitted)
    assert consumer.counters["chain_capacity_expired"] >= 1


def test_earlier_compute_candidates_are_reported_as_alternatives():
    txn = key(1)
    events = journal(
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        retire(2, 2, encode_itype(6, 0, 0, 0x101), 6, 0x101),
        mmio_acceptance(3, txn, address=0x40001004, offset=4, value=0x101),
        gpio_apb(4, txn, offset=4, value=0x101),
        gpio_commit(5, txn, offset=4, value=0x101, apb_event_id=4),
    )
    consumer = ComputedValueCertificates()
    certificates = consume(events, consumer)
    assert [c["status"] for c in certificates] == ["certified"]
    assert certificates[0]["computed"]["event_id"] == 2
    assert certificates[0]["computed"]["alternative_event_ids"] == [1]


def test_constructor_bounds_must_be_positive():
    with pytest.raises(ValueError):
        ComputedValueCertificates(max_pending=0)
    with pytest.raises(ValueError):
        ComputedValueCertificates(max_event_gap=0)
    with pytest.raises(ValueError):
        ComputedValueCertificates(max_value_history=0)


# --------------------------------------------------------------------------
# frozen real traces (read-only streaming recomputation)
#
# The pinned numbers below were measured by
# ``scripts/report_computed_value_certificates.py`` over the frozen artifacts and
# then written down here, so any drift in the consumer or in the trace is a test
# failure.  No RTL is started: every run is read through ``TraceEventStream``.
# --------------------------------------------------------------------------

LANE_RUN = "runs/p3-lane-selectivity2-20261007-online"
SB_REAL_RUN = "runs/current-dataflow-p4-uart-sb-real-online"
SB_FINAL_RUN = "runs/current-dataflow-p4-sb-final-online-20261007"
SHIFT_RUN = "runs/p4-shift-fuzz-20261007-online"


def _replay(run_dir, consumer):
    stream = TraceEventStream(run_dir)
    certificates = []
    peak = 0
    for event in stream.events():
        certificates.extend(consumer.ingest((event,)))
        peak = max(peak, consumer.pending_count)
    certificates.extend(consumer.flush())
    assert stream.semantic_sha256_verified() is True
    return certificates, peak


def _assert_self_consistent(certificates):
    for certificate in certificates:
        if certificate["status"] != "certified":
            continue
        assert certificate["schema_version"] == SCHEMA_VERSION
        assert certificate["proof_scope"] == (
            "exact_value_identity_on_enabled_lanes_from_rvfi_compute_"
            "to_device_consumption")
        ids = [hop["event_id"] for hop in certificate["hops"]]
        assert ids == sorted(ids) and len(set(ids)) == len(ids)
        assert certificate["event_ids"] == ids
        lanes = certificate["enabled_lanes"]
        assert lanes and all(0 <= lane < 4 for lane in lanes)
        for lane in lanes:
            assert certificate["lane_values"][str(lane)] == \
                (certificate["store_value"] >> (8 * lane)) & 0xff
        assert certificate["consumption"] is not None
        assert certificate["consumption"] in certificate["consumption_witnesses"]
        assert certificate["missing_hops"] == [] and certificate["reason"] is None
        for name in ("register_file_internal_source_token",
                     "cross_instruction_data_dependency",
                     "computed_value_was_used_by_a_later_instruction",
                     "device_internal_fifo_or_serializer_token"):
            assert name in certificate["not_proof_of"]


def test_real_lane_selectivity_trace_certifies_computed_gpio_register_values():
    import pathlib
    if not pathlib.Path(LANE_RUN).is_dir():
        pytest.skip(f"saved trace is not available: {LANE_RUN}")
    consumer = ComputedValueCertificates()
    certificates, peak = _replay(LANE_RUN, consumer)
    certified = [c for c in certificates if c["status"] == "certified"]
    assert peak <= consumer.max_pending == 64
    assert (len(certified), len(certificates) - len(certified), peak) == (30, 0, 5)
    assert consumer.rejections == {
        "discarded_zero_register_write": 254,
        "mmio_store_without_computed_value": 1,
        "terminal_without_chain": 2,
        "unsupported_instruction_observation_only": 292,
    }
    assert consumer.counters == {"chains_opened": 30, "computed_values_seen": 172,
                                 "mmio_hops": 120, "terminal_witnesses": 60}
    _assert_self_consistent(certificates)
    assert sorted({c["device"] for c in certified}) == ["gpio_a", "gpio_b"]
    by_device = {}
    for certificate in certified:
        by_device[certificate["device"]] = by_device.get(certificate["device"], 0) + 1
    assert by_device == {"gpio_a": 27, "gpio_b": 3}
    assert sorted({c["computed"]["operation"] for c in certified}) == ["addi", "srli"]
    assert {c["consumption"]["kind"] for c in certified} == {"gpio_register_commit"}

    first = certified[0]
    assert first["computed"]["event_id"] == 194
    assert first["computed"]["operation"] == "addi"
    assert first["computed"]["pc"] == 0x10084
    assert first["computed"]["computed_value"] == 0x101
    assert first["transaction"] == {
        "channel_id": "data", "execution_id": "local-execution",
        "source_component": "cpu", "source_epoch": 0, "source_sequence": 1,
        "testcase_id": "ibex-dual-source-stream"}
    assert [(hop["kind"], hop["event_id"]) for hop in first["hops"]] == [
        ("cpu_retire", 194), ("mmio_acceptance", 267), ("data_accept", 269),
        ("gpio_target_receipt", 300), ("gpio_apb_access", 304),
        ("gpio_register_commit", 306), ("mmio_delivery", 313),
        ("data_response", 332)]
    assert first["consumption"]["kind"] == "gpio_register_commit"
    assert first["consumption"]["event_id"] == 306
    assert first["consumption"]["register"] == "gpioen"
    assert first["consumption"]["pre_value"] == 0
    assert first["consumption"]["post_value"] == 0x101
    assert first["consumption"]["changed_mask"] == 0x101
    assert first["consumption"]["observation_event_id"] == 304
    assert first["event_gap"] == {"compute_to_store": 73, "store_to_last_hop": 65}


def test_real_uart_sb_trace_certifies_the_device_access_and_stays_honest():
    import pathlib
    if not pathlib.Path(SB_REAL_RUN).is_dir():
        pytest.skip(f"saved trace is not available: {SB_REAL_RUN}")
    consumer = ComputedValueCertificates()
    certificates, peak = _replay(SB_REAL_RUN, consumer)
    certified = [c for c in certificates if c["status"] == "certified"]
    incomplete = [c for c in certificates if c["status"] != "certified"]
    assert (len(certified), len(incomplete), peak) == (2, 1, 2)
    assert consumer.rejections == {
        "discarded_zero_register_write": 201,
        "expired_without_device_consumption": 1,
        "unsupported_instruction_observation_only": 21,
    }
    assert consumer.counters == {"chains_opened": 3, "computed_values_seen": 18,
                                 "mmio_hops": 7, "serial_observations": 4102,
                                 "terminal_witnesses": 8}
    _assert_self_consistent(certificates)
    # This run never observes a UART serial byte, so no serial witness exists.
    assert {c["consumption"]["kind"] for c in certified} == {
        "uart_tick_observation_access"}
    for certificate in certified:
        assert certificate["device"] == "uart"
        assert certificate["computed"]["operation"] == "addi"
        assert certificate["computed"]["rd_addr"] == 2
    first = certified[0]
    assert first["computed"]["event_id"] == 140
    assert first["computed"]["computed_value"] == 0x80000003
    assert first["transaction"]["source_sequence"] == 1
    assert [(hop["kind"], hop["event_id"]) for hop in first["hops"]] == [
        ("cpu_retire", 140), ("mmio_acceptance", 170), ("data_accept", 172),
        ("uart_tick_observation_access", 182), ("uart_tick_observation_access", 183),
        ("uart_tick_observation_access", 191), ("uart_tick_observation_access", 199),
        ("mmio_delivery", 200), ("data_response", 235)]
    assert first["consumption"]["event_id"] == 182
    assert first["consumption"]["wdata"] == 0x80000003
    assert first["consumption"]["offset"] == 16
    # The last chain is cut off by the recorded harness failure: no device ever
    # consumed it, so it stays incomplete instead of being credited.
    assert incomplete[0]["transaction"]["source_sequence"] == 15
    assert incomplete[0]["missing_hops"] == ["device_consumption"]
    assert incomplete[0]["reason"] == "expired_without_device_consumption"
    assert incomplete[0]["store_value"] == 0xc8
    assert [hop["hop_id"] for hop in incomplete[0]["hops"]] == [
        "cpu_compute", "mmio_acceptance", "data_accept"]
    assert [hop["kind"] for hop in incomplete[0]["hops"]] == [
        "cpu_retire", "mmio_acceptance", "data_accept"]


def test_real_p4_sb_final_trace_reproduces_the_audited_serial_byte():
    import pathlib
    if not (pathlib.Path(SB_FINAL_RUN) / "online_final_trace.json").is_file():
        pytest.skip(f"saved trace is not available: {SB_FINAL_RUN}")
    consumer = ComputedValueCertificates()
    certificates, peak = _replay(SB_FINAL_RUN, consumer)
    certified = [c for c in certificates if c["status"] == "certified"]
    assert (len(certified), len(certificates) - len(certified), peak) == (3, 0, 2)
    assert consumer.rejections == {"discarded_zero_register_write": 338,
                                   "unsupported_instruction_observation_only": 32}
    assert consumer.counters == {"chains_opened": 3, "computed_values_seen": 19,
                                 "mmio_hops": 9, "serial_observations": 6660,
                                 "terminal_witnesses": 13}
    _assert_self_consistent(certificates)
    serial = [c for c in certified
              if c["consumption"]["kind"] == "uart_serial_observation"]
    assert len(serial) == 1
    certificate = serial[0]
    # Exactly the frozen architectural audit of the computed 0x0c byte.
    assert certificate["computed"]["event_id"] == 25068
    assert certificate["computed"]["pc"] == 69656
    assert certificate["computed"]["operation"] == "addi"
    assert certificate["computed"]["rd_addr"] == 2
    assert certificate["computed"]["computed_value"] == 0x0c
    assert certificate["computed"]["alternative_event_ids"] == [24052]
    assert certificate["enabled_lanes"] == [0]
    assert certificate["lane_values"] == {"0": 0x0c}
    assert certificate["store_value"] == 0x0c
    assert certificate["transaction"]["source_sequence"] == 11
    assert [(hop["kind"], hop["event_id"]) for hop in certificate["hops"]] == [
        ("cpu_retire", 25068), ("mmio_acceptance", 25121), ("data_accept", 25122),
        ("uart_tick_observation_access", 25132),
        ("uart_tick_observation_access", 25133),
        ("uart_tick_observation_access", 25141),
        ("uart_tick_observation_access", 25149), ("mmio_delivery", 25150),
        ("data_response", 25176), ("uart_serial_observation", 28002)]
    assert certificate["consumption"]["event_id"] == 28002
    assert certificate["consumption"]["serial_tx_count"] == 1
    assert certificate["consumption"]["serial_tx_last"] == 0x0c
    assert certificate["consumption"]["lane"] == 0
    assert certificate["consumption"]["serial_base"] == 0
    assert certificate["event_gap"] == {"compute_to_store": 53,
                                        "store_to_last_hop": 2881}


def test_real_shift_fuzz_trace_pins_its_certified_count():
    import pathlib
    if not pathlib.Path(SHIFT_RUN).is_dir():
        pytest.skip(f"saved trace is not available: {SHIFT_RUN}")
    consumer = ComputedValueCertificates()
    certificates, peak = _replay(SHIFT_RUN, consumer)
    certified = [c for c in certificates if c["status"] == "certified"]
    assert (len(certified), len(certificates) - len(certified), peak) == (33, 0, 6)
    assert consumer.rejections == {
        "discarded_zero_register_write": 189,
        "mmio_store_without_computed_value": 1,
        "terminal_without_chain": 2,
        "unsupported_instruction_observation_only": 259,
    }
    assert consumer.counters == {"chains_opened": 33, "computed_values_seen": 135,
                                 "mmio_hops": 132, "terminal_witnesses": 66}
    _assert_self_consistent(certificates)
    by_device = {}
    for certificate in certified:
        by_device[certificate["device"]] = by_device.get(certificate["device"], 0) + 1
    assert by_device == {"gpio_a": 30, "gpio_b": 3}
    assert sorted({c["computed"]["operation"] for c in certified}) == ["addi", "srli"]
    assert {c["consumption"]["kind"] for c in certified} == {"gpio_register_commit"}
    assert certified[0]["computed"]["event_id"] == 194
    assert certified[0]["consumption"]["register"] == "gpioen"
