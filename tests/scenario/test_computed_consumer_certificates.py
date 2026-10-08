"""Generic consumer-endpoint certificates over a declared device-witness registry.

The consumer generalises ``computed_value_certificate.v1``: the endpoint is no
longer one hard-wired peripheral but a *declared* registry of device-internal
witness kinds.  Each declaration states the event kind (or the raw-observation
shape), the field paths that carry the delivered value, and the exact identity
keys it can join on.  A certificate is emitted only when every declared hop
joins by exact identity; otherwise the settlement is an explicit refusal that
names the first missing hop and the first missing identity, or -- when the
artifact carries no evidence at all for the device -- an explicit ``unknown``
with a reason and ``null`` counts (never a fabricated 0).

The synthetic journals below are built from shapes the frozen online traces
actually carry (``cpu_retire``, ``mmio_acceptance``/``data_accept``/
``gpio_target_receipt``/``gpio_apb_access``/``gpio_register_commit``/
``gpio_consumption_match``, ``uart_tick_observation.access``, the raw UART
serial observation, ``uart_fifo_push``/``uart_fifo_pop``, ``uart_rdata_access``
and the raw GPIO pad observation).  The real-trace tests only read already
frozen artifacts through ``TraceEventStream``; they never start RTL.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from myfuzz.scenario.acceptance_metrics import TraceEventStream
from myfuzz.scenario.computed_consumer_certificates import (
    ABSENT_WITNESS_KINDS,
    NOT_PROOF_OF,
    PROOF_SCOPE,
    SCHEMA_VERSION,
    WITNESS_REGISTRY,
    ComputedConsumerCertificates,
    declared_witness_names,
    witness_registry,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_cli():
    script = REPO_ROOT / "scripts" / "report_computed_consumer_certificates.py"
    spec = importlib.util.spec_from_file_location(
        "report_computed_consumer_certificates", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------
# journal builders -- field names copied from the frozen traces
# --------------------------------------------------------------------------

OP_IMM = 0x13
LUI = 0x37


def key(sequence, case="case-1", epoch=0, execution="local-execution"):
    return {"channel_id": "data", "execution_id": execution, "source_component": "cpu",
            "source_epoch": epoch, "source_sequence": sequence, "testcase_id": case}


def encode_itype(rd, rs1, funct3, imm, funct7=0):
    word = ((funct7 & 0x7f) << 25) | ((imm & 0xfff) << 20) | (rs1 << 15)
    return word | (funct3 << 12) | (rd << 7) | OP_IMM


def encode_lui(rd, imm20):
    return ((imm20 & 0xfffff) << 12) | (rd << 7) | LUI


def retire(event_id, order, insn, rd, value, *, rs1=0, rs1_rdata=0, pc=0x10000,
           epoch=0, trap=0, **overrides):
    event = {"kind": "cpu_retire", "event_id": event_id, "order": order,
             "pc_rdata": pc, "insn": insn, "trap": trap, "valid": 1, "phase": "post",
             "component": "cpu", "execution_id": "local-execution",
             "source_component": "cpu", "source_epoch": epoch, "reset_epoch": epoch,
             "rd_addr": rd, "rd_wdata": value, "rs1_addr": rs1, "rs1_rdata": rs1_rdata,
             "mem_addr": 0, "mem_wmask": 0, "mem_wdata": 0}
    event.update(overrides)
    return event


def mmio_acceptance(event_id, txn, *, address, offset, device="gpio_b", be=15, value=0,
                    **overrides):
    event = {"kind": "mmio_acceptance", "event_id": event_id, "component": "cpu",
             "address": address, "offset": offset, "device_id": device, "write": True,
             "byte_enable": be, "beat_bytes": 4, "acceptance_order": 1,
             "source_sequence": txn["source_sequence"],
             "source_transaction": dict(txn), "write_value": value}
    event.update(overrides)
    return event


def mmio_delivery(event_id, txn, *, address, offset, device="gpio_b", be=15, value=0,
                  **overrides):
    event = {"kind": "mmio_delivery", "event_id": event_id, "component": "cpu",
             "address": address, "offset": offset, "device_id": device, "write": True,
             "byte_enable": be, "beat_bytes": 4, "delivery_order": 1, "read_value": None,
             "source_sequence": txn["source_sequence"],
             "source_transaction": dict(txn), "target_delivery_order": 1,
             "write_value": value}
    event.update(overrides)
    return event


def data_accept(event_id, txn, *, address, be=15, value=0, **overrides):
    event = {"kind": "data_accept", "event_id": event_id, "component": "cpu",
             "write": 1, "be": be, "wdata": value, "raw_address": address,
             "aligned_address": address & ~3, "address": address & ~3,
             "execution_id": "local-execution", "source_epoch": 0,
             "transaction": dict(txn)}
    event.update(overrides)
    return event


def data_response(event_id, txn, *, address, be=15, value=0, error=0, **overrides):
    event = {"kind": "data_response", "event_id": event_id, "component": "cpu",
             "write": 1, "be": be, "wdata": value, "error": error, "rdata": 0,
             "raw_address": address, "aligned_address": address & ~3,
             "address": address & ~3, "execution_id": "local-execution",
             "source_epoch": 0, "transaction": dict(txn)}
    event.update(overrides)
    return event


def gpio_receipt(event_id, txn, *, offset, value, device="gpio_b", write=True,
                 status="received", **overrides):
    event = {"kind": "gpio_target_receipt", "event_id": event_id, "component": device,
             "write": write, "raw_offset": offset, "decoded_offset": offset & ~3,
             "wdata": value if write else None, "status": status,
             "access_id": f"gpio-access:{device}:0:1",
             "source_transaction": dict(txn)}
    event.update(overrides)
    return event


def gpio_apb(event_id, txn, *, offset, value, device="gpio_b", write=True,
             status="observed", **overrides):
    probes = {"psel": 1, "penable": 1, "pwrite": int(write), "pwdata": value,
              "pready": 1, "pslverr": 0, "apb_addr": offset}
    pre = {"gpio_probe_" + name: probe for name, probe in probes.items()}
    event = {"kind": "gpio_apb_access", "event_id": event_id, "component": device,
             "write": write, "raw_offset": offset, "decoded_offset": offset & ~3,
             "wdata": value if write else None, "status": status, "pre": pre,
             "post": {"gpio_probe_psel": 0}, "read_rdata": 0,
             "access_id": f"gpio-access:{device}:0:1",
             "target_response": {"rdata": 0, "error": 0},
             "source_transaction": dict(txn)}
    event.update(overrides)
    return event


def bit_resources(txn, value, *, register="gpioen", observation_event_id=None,
                  bits=32):
    return [{"bit": bit, "component": "gpio_b", "register": register, "value": (value >> bit) & 1,
             "transaction": dict(txn), "version": 100 + bit,
             "observation_event_id": observation_event_id} for bit in range(bits)]


def gpio_commit(event_id, txn, *, offset, value, register="gpioen", apb_event_id,
                device="gpio_b", status="observed", pre_value=0, **overrides):
    event = {"kind": "gpio_register_commit", "event_id": event_id, "component": device,
             "register": register, "raw_offset": offset, "decoded_offset": offset & ~3,
             "fullkey": dict(txn), "write_value": value, "pre_value": pre_value,
             "post_value": value, "changed_mask": pre_value ^ value,
             "operation": "overwrite", "status": status,
             "observation_event_id": apb_event_id,
             "access_id": f"gpio-access:{device}:0:1",
             "proof_scope": "gpio_native_resource_observation",
             "reason": "actual_apb_register_write",
             "bit_resources": bit_resources(txn, value, register=register,
                                            observation_event_id=apb_event_id)}
    event.update(overrides)
    return event


def gpio_consumption_match(event_id, txn, *, observation_event_id, value,
                           device="gpio_b", status="accepted", register="gpioen",
                           **overrides):
    """The real match row carries the per-bit resource list, not a word field.

    Real statuses are ``accepted`` (matched, known fuzz origin) and ``unknown``
    (matched, lineage unknown); ``rejected`` rows never join.
    """
    event = {"kind": "gpio_consumption_match", "event_id": event_id, "component": device,
             "fullkey": dict(txn), "status": status,
             "observation_event_id": observation_event_id,
             "proof_scope": "gpio_native_resource_observation",
             "reason": "actual_apb_register_write",
             "registered_origins": [], "retirement_delivery_event_id": None,
             "proof_resource": bit_resources(txn, value, register=register,
                                             observation_event_id=observation_event_id)}
    event.update(overrides)
    return event


def gpio_register_read(event_id, txn, *, value, register="gpioen", device="gpio_b",
                       status="observed", **overrides):
    event = {"kind": "gpio_register_read", "event_id": event_id, "component": device,
             "register": register, "fullkey": dict(txn), "status": status,
             "status_outcome": "observed", "read_value": value, "pre_value": value,
             "post_value": value, "access_id": f"gpio-access:{device}:0:2",
             "bit_resources": bit_resources(txn, value, register=register),
             "post_bit_resources": bit_resources(txn, value, register=register)}
    event.update(overrides)
    return event


def uart_write_access(event_id, txn, *, offset, value, be=15, tick=1, write=True,
                      access_id=None, **overrides):
    access = {"access_id": access_id or f"uart-access:uart:0:{event_id}",
              "address": 0x40000000 + offset, "raw_offset": offset,
              "byte_enable": be, "window_base": 0x40000000, "window_size": 4096,
              "write": write, "source_transaction": dict(txn),
              "delivery_context": {"address": 0x40000000 + offset, "be": be,
                                   "device_id": "uart", "offset": offset,
                                   "source_transaction": dict(txn), "value": value,
                                   "window_base": 0x40000000, "window_size": 4096,
                                   "write": write}}
    event = {"kind": "uart_tick_observation", "event_id": event_id, "component": "uart",
             "local_tick": tick, "physical_rx_ref": None, "physical_rx_value": 1,
             "access": access}
    event.update(overrides)
    return event


def uart_serial_observation(event_id, *, count, byte, tick=1, rx_word=0):
    """Raw peripheral sample: the artifact writes no ``kind`` at all."""
    return {"event_id": event_id, "component": "uart", "local_tick": tick,
            "inputs": {"uart_rx_byte": 0},
            "outputs": {"serial_rx_read": 0, "serial_rx_word": rx_word,
                        "serial_tx_count": count, "serial_tx_last": byte,
                        "uart_tx": 1, "uart_tx_done": 0, "uart_tx_empty": 0,
                        "uart_tx_en": 1, "uart_tx_watermark": 0}}


def uart_fifo_push(event_id, *, value, entry=("uart", 0, 0, 2),
                   frame="uart-frame:0:1", observation_event_id=None):
    return {"kind": "uart_fifo_push", "event_id": event_id, "component": "uart",
            "entry_id": list(entry), "frame_id": frame, "value": value,
            "retained": True, "receiver_id": ["uart", 0, 1],
            "completion_event": event_id - 1,
            "observation_event_id": observation_event_id or event_id - 1,
            "origin_status": "unknown", "local_tick": 100}


def uart_fifo_pop(event_id, read_txn, *, value, entry=("uart", 0, 0, 2),
                  frame="uart-frame:0:1", offset=24):
    return {"kind": "uart_fifo_pop", "event_id": event_id, "component": "uart",
            "entry_id": list(entry), "frame_id": frame, "value": value,
            "clear": False, "observation_event_id": event_id - 1, "local_tick": 200,
            "access": {"access_id": f"uart-access:uart:0:{event_id}",
                       "address": 0x40000000 + offset, "raw_offset": offset,
                       "byte_enable": 15, "write": False,
                       "source_transaction": dict(read_txn),
                       "delivery_context": {"address": 0x40000000 + offset, "be": 15,
                                            "device_id": "uart", "offset": offset,
                                            "source_transaction": dict(read_txn),
                                            "value": 0, "write": False}}}


def uart_rdata_access(event_id, read_txn, *, value, offset=24):
    return {"kind": "uart_rdata_access", "event_id": event_id, "component": "uart",
            "access_id": f"uart-access:uart:0:{event_id}", "raw_offset": offset,
            "read_value": value, "error": 0,
            "delivery_context": {"address": 0x40000000 + offset, "be": 15,
                                 "device_id": "uart", "offset": offset,
                                 "source_transaction": dict(read_txn),
                                 "value": 0, "write": False},
            "read_capture": {"post": {"probe_uart_fifo_data": value,
                                      "probe_uart_captured_rdata": value}}}


def gpio_pad_observation(event_id, *, out_value, tick=1, device="gpio_b"):
    """Raw GPIO pad sample: outputs only, no transaction identity at all."""
    return {"event_id": event_id, "component": device, "local_tick": tick,
            "inputs": {},
            "outputs": {"gpio_out": out_value, "gpio_dir": 0xffffffff,
                        "gpio_in_sync": 0, "gpio_padcfg": "0" * 32, "rdata": out_value,
                        "error": 0, "interrupt": 0, "irq": 0}}


def reset(event_id, epoch=1):
    return {"kind": "reset_barrier", "event_id": event_id, "component": "cpu",
            "reset_epoch": epoch}


def consume(events, consumer, *, flush=True):
    records = []
    for event in events:
        records.extend(consumer.ingest((event,)))
    if flush:
        records.extend(consumer.flush())
    return records


def certified(records):
    return [r for r in records if r["status"] == "certified"]


def refused(records):
    return [r for r in records if r["status"] == "refused"]


def unknown(records):
    return [r for r in records if r["status"] == "unknown"]


# --------------------------------------------------------------------------
# declared registry
# --------------------------------------------------------------------------

def test_registry_declares_event_kind_value_fields_and_identity_keys():
    registry = witness_registry()
    assert declared_witness_names() == tuple(kind.name for kind in WITNESS_REGISTRY)
    for name, kind in registry.items():
        assert kind.name == name
        assert kind.event_kind is not None or kind.shape == "raw_peripheral_observation"
        assert kind.components
        assert kind.identity_keys, f"{name} must declare the keys it can join on"
        for identity in kind.identity_keys:
            assert identity.name and identity.join and identity.field_path
        if kind.carries_value and kind.joinable:
            assert kind.value_paths, f"{name} claims a value but declares no field path"
        if not kind.joinable:
            assert kind.unjoinable_reason, f"{name} must state why it cannot join"


def test_registry_declares_gpio_uart_and_declared_absent_transport_witnesses():
    registry = witness_registry()
    for name in ("gpio_register_commit", "gpio_apb_access", "gpio_consumption_match",
                 "uart_tick_observation_access", "uart_serial_observation",
                 "uart_fifo_push", "uart_fifo_pop", "uart_rdata_access",
                 "gpio_pad_observation", "spi_transfer", "timer_tick"):
        assert name in registry, name
    assert registry["gpio_register_commit"].event_kind == "gpio_register_commit"
    commit_paths = [value.path for value in registry["gpio_register_commit"].value_paths]
    assert ("write_value",) in commit_paths
    assert registry["uart_serial_observation"].shape == "raw_peripheral_observation"
    # Kinds with no exact store identity at all are declared unjoinable ...
    assert not registry["uart_fifo_push"].joinable
    assert not registry["gpio_pad_observation"].joinable
    # ... while read-direction access kinds declare the read transaction key and
    # are refused by exact mismatch instead of by declaration.
    assert registry["uart_rdata_access"].joinable
    assert "read access transaction" in \
        registry["uart_rdata_access"].identity_keys[0].note
    assert registry["gpio_register_read"].joinable
    # Kinds the framework supports but the studied artifacts do not carry: they
    # are declared so a refusal can name them instead of inventing a 0.
    absent = {kind.name: kind for kind in ABSENT_WITNESS_KINDS}
    assert absent["spi_transfer"].reason == "declared_witness_kind_absent_from_artifact"
    assert absent["timer_tick"].reason == "declared_witness_kind_absent_from_artifact"


def test_registry_report_is_serialisable_and_declares_the_honest_boundaries():
    report = ComputedConsumerCertificates().registry_table()
    assert json.loads(json.dumps(report, sort_keys=True))
    names = [row["name"] for row in report]
    assert names == list(declared_witness_names())
    for row in report:
        assert row["event_kind"] or row["shape"] == "raw_peripheral_observation"
        assert row["identity_keys"]
        assert row["proof_scope"] == PROOF_SCOPE
        assert row["not_proof_of"] == list(NOT_PROOF_OF)


# --------------------------------------------------------------------------
# positive chains: every declared witness kind that can join
# --------------------------------------------------------------------------

def _gpio_anchor(txn, value=0x101, device="gpio_b", offset=4):
    return [
        mmio_acceptance(2, txn, address=0x40001000 + offset, offset=offset,
                        device=device, value=value),
        data_accept(3, txn, address=0x40001000 + offset, value=value),
        gpio_receipt(4, txn, offset=offset, value=value, device=device),
        mmio_delivery(5, txn, address=0x40001000 + offset, offset=offset,
                      device=device, value=value),
        data_response(6, txn, address=0x40001000 + offset, value=value),
    ]


def test_gpio_register_commit_chain_is_certified_with_all_declared_joins():
    txn = key(1)
    consumer = ComputedConsumerCertificates()
    records = consume([
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        *_gpio_anchor(txn),
        gpio_apb(7, txn, offset=4, value=0x101),
        gpio_commit(8, txn, offset=4, value=0x101, apb_event_id=7),
    ], consumer)

    assert len(certified(records)) == 1
    certificate = certified(records)[0]
    assert certificate["schema_version"] == SCHEMA_VERSION
    assert certificate["witness_kind"] == "gpio_register_commit"
    assert certificate["witness_event_id"] == 8
    assert certificate["device"] == "gpio_b"
    assert certificate["transaction"] == txn
    assert certificate["computed"]["event_id"] == 1
    assert certificate["computed"]["operation"] == "addi"
    assert certificate["computed"]["computed_value"] == 0x101
    assert certificate["enabled_lanes"] == [0, 1, 2, 3]
    assert certificate["lane_values"] == {"0": 0x01, "1": 0x01, "2": 0x00, "3": 0x00}
    assert certificate["store_value"] == 0x101
    assert certificate["event_ids"] == [1, 2, 3, 4, 5, 6, 7, 8]
    joins = {join["name"]: join for join in certificate["identity_joins"]}
    assert joins["store_transaction_key"]["status"] == "matched"
    assert joins["store_transaction_key"]["observed"] == txn
    assert joins["routed_device_component"]["observed"] == "gpio_b"
    assert joins["store_offset"]["observed"] == 4
    assert joins["certified_upstream_hop_event_id"]["observed"] == 7
    assert all(join["status"] == "matched" for join in certificate["identity_joins"])
    assert certificate["reason"] is None and certificate["missing_hop"] is None
    assert consumer.certified_count == 1 and consumer.refused_count == 0
    assert consumer.rejections == {}


def test_gpio_consumption_match_proof_resource_is_a_joining_witness():
    txn = key(1)
    consumer = ComputedConsumerCertificates()
    records = consume([
        retire(1, 1, encode_lui(6, 0x12345), 6, 0x12345000),
        mmio_acceptance(2, txn, address=0x40001004, offset=4, device="gpio_b",
                        value=0x12345000),
        mmio_delivery(3, txn, address=0x40001004, offset=4, device="gpio_b",
                      value=0x12345000),
        gpio_consumption_match(4, txn, observation_event_id=3, value=0x12345000),
    ], consumer)
    assert len(certified(records)) == 1
    certificate = certified(records)[0]
    assert certificate["witness_kind"] == "gpio_consumption_match"
    assert certificate["event_ids"] == [1, 2, 3, 4]
    assert certificate["identity_joins"][0]["join"] == "store_transaction_key"
    # The shape carries no offset field: that identity is declared absent, not
    # silently skipped, and the declared statuses are accepted/unknown.
    offset_join = [join for join in certificate["identity_joins"]
                   if join["join"] == "store_offset"][0]
    assert offset_join["status"] == "absent_by_declaration"


def test_consumption_match_with_a_rejected_status_never_joins():
    txn = key(1)
    consumer = ComputedConsumerCertificates()
    records = consume([
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(2, txn, address=0x40001004, offset=4, device="gpio_b",
                        value=0x101),
        mmio_delivery(3, txn, address=0x40001004, offset=4, device="gpio_b",
                      value=0x101),
        gpio_consumption_match(4, txn, observation_event_id=3, value=0x101,
                               status="rejected"),
    ], consumer)
    assert certified(records) == []
    assert refused(records)[0]["missing_identity"] == "witness_status:accepted/unknown"
    assert consumer.witness_evidence["gpio_consumption_match"]["status_rejections"] == 1


def test_gpio_apb_access_alone_is_a_declared_device_witness():
    txn = key(1)
    consumer = ComputedConsumerCertificates()
    records = consume([
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(2, txn, address=0x40001004, offset=4, value=0x101),
        gpio_apb(3, txn, offset=4, value=0x101),
    ], consumer)
    assert len(certified(records)) == 1
    assert certified(records)[0]["witness_kind"] == "gpio_apb_access"
    assert certified(records)[0]["witness_event_id"] == 3


def test_uart_write_access_certifies_the_computed_value():
    txn = key(9)
    consumer = ComputedConsumerCertificates()
    records = consume([
        retire(1, 1, encode_itype(2, 0, 0, 0x0c), 2, 0x0c),
        mmio_acceptance(2, txn, address=0x4000001c, offset=28, device="uart", be=1,
                        value=0x0c),
        uart_write_access(3, txn, offset=28, value=0x0c, be=1),
        mmio_delivery(4, txn, address=0x4000001c, offset=28, device="uart", be=1,
                      value=0x0c),
    ], consumer)
    assert len(certified(records)) == 1
    certificate = certified(records)[0]
    assert certificate["witness_kind"] == "uart_tick_observation_access"
    assert certificate["device"] == "uart"
    assert certificate["enabled_lanes"] == [0]
    assert certificate["event_ids"] == [1, 2, 3, 4]


def test_uart_serial_byte_is_a_witness_when_the_counter_advances_by_one():
    txn = key(7)
    consumer = ComputedConsumerCertificates()
    records = consume([
        uart_serial_observation(1, count=0, byte=0),           # baseline before delivery
        retire(2, 1, encode_itype(2, 0, 0, 0x0c), 2, 0x0c),
        mmio_acceptance(3, txn, address=0x4000001c, offset=28, device="uart", be=1,
                        value=0x0c),
        mmio_delivery(4, txn, address=0x4000001c, offset=28, device="uart", be=1,
                      value=0x0c),
        uart_serial_observation(5, count=1, byte=0x0c),
    ], consumer)
    assert len(certified(records)) == 1
    certificate = certified(records)[0]
    assert certificate["witness_kind"] == "uart_serial_observation"
    assert certificate["witness_event_id"] == 5
    assert certificate["event_ids"] == [2, 3, 4, 5]
    assert certificate["identity_joins"][-1]["name"] == "serial_counter_increment"
    assert certificate["identity_joins"][-1]["status"] == "matched"


def test_serial_without_a_baseline_never_certifies():
    """An assumed zero baseline could credit an unrelated byte."""
    txn = key(7)
    consumer = ComputedConsumerCertificates()
    records = consume([
        retire(1, 1, encode_itype(2, 0, 0, 0x0c), 2, 0x0c),
        mmio_acceptance(2, txn, address=0x4000001c, offset=28, device="uart", be=1,
                        value=0x0c),
        mmio_delivery(3, txn, address=0x4000001c, offset=28, device="uart", be=1,
                      value=0x0c),
        uart_serial_observation(4, count=1, byte=0x0c),
    ], consumer)
    assert certified(records) == []
    assert refused(records)[0]["missing_hop"] == "device_consumption:uart_serial_observation"
    assert refused(records)[0]["missing_identity"] == "serial_counter_increment"
    assert refused(records)[0]["reason"] == "no_observed_serial_baseline"
    assert consumer.witness_evidence["uart_serial_observation"]["events"] == 1
    assert consumer.witness_evidence["uart_serial_observation"]["certified"] == 0


def test_serial_sample_that_does_not_advance_keeps_the_store_eligible():
    """A transport sample with no new byte neither joins nor burns the claim."""
    txn = key(7)
    consumer = ComputedConsumerCertificates()
    records = consume([
        uart_serial_observation(1, count=0, byte=0),      # baseline
        retire(2, 1, encode_itype(2, 0, 0, 0x0c), 2, 0x0c),
        mmio_acceptance(3, txn, address=0x4000001c, offset=28, device="uart", be=1,
                        value=0x0c),
        mmio_delivery(4, txn, address=0x4000001c, offset=28, device="uart", be=1,
                      value=0x0c),
        uart_serial_observation(5, count=0, byte=0),      # no new byte yet
        uart_serial_observation(6, count=1, byte=0x0c),   # the store's byte
    ], consumer)
    assert len(certified(records)) == 1
    certificate = certified(records)[0]
    assert certificate["witness_kind"] == "uart_serial_observation"
    assert certificate["witness_event_id"] == 6
    assert consumer.witness_evidence["uart_serial_observation"]["join_failures"] == 0
    assert consumer.counters.get("witness_join_failures", 0) == 0


def test_a_second_serial_byte_is_never_attributed_to_the_same_store():
    txn = key(7)
    consumer = ComputedConsumerCertificates()
    records = consume([
        uart_serial_observation(1, count=0, byte=0),
        retire(2, 1, encode_itype(2, 0, 0, 0x0c), 2, 0x0c),
        mmio_acceptance(3, txn, address=0x4000001c, offset=28, device="uart", be=1,
                        value=0x0c),
        mmio_delivery(4, txn, address=0x4000001c, offset=28, device="uart", be=1,
                      value=0x0c),
        uart_serial_observation(5, count=1, byte=0x0c),
        uart_serial_observation(6, count=2, byte=0x0c),
    ], consumer)
    certificate = certified(records)[0]
    serial_witnesses = [witness for witness in certificate["witnesses"]
                        if witness["kind"] == "uart_serial_observation"]
    assert [witness["event_id"] for witness in serial_witnesses] == [5]
    assert certificate["witness_event_id"] == 5


def test_only_the_enabled_lane_bytes_are_compared():
    txn = key(1)
    consumer = ComputedConsumerCertificates()
    records = consume([
        retire(1, 1, encode_lui(6, 0x12345), 6, 0x12345000),
        mmio_acceptance(2, txn, address=0x4000001c, offset=28, device="uart", be=1,
                        value=0x123450aa),
        uart_write_access(3, txn, offset=28, value=0x123450aa, be=1),
        mmio_delivery(4, txn, address=0x4000001c, offset=28, device="uart", be=1,
                      value=0x123450aa),
    ], consumer)
    # lane 0 of the computed LUI is 0x00, the store lane 0 is 0xaa: no chain.
    assert certified(records) == []
    assert any(r["missing_hop"] == "rvfi_compute" for r in refused(records))


# --------------------------------------------------------------------------
# refusals: the first missing hop must be named
# --------------------------------------------------------------------------

def test_anchored_chain_without_a_witness_is_refused_with_the_declared_hop():
    txn = key(4)
    consumer = ComputedConsumerCertificates()
    records = consume([
        # A witness kind for the device is observed elsewhere in the run: the
        # endpoint exists, so this is a refusal, not "no evidence".
        gpio_apb(1, key(98), offset=0, value=0),
        retire(2, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(3, txn, address=0x40001004, offset=4, value=0x101),
        mmio_delivery(4, txn, address=0x40001004, offset=4, value=0x101),
    ], consumer)
    assert certified(records) == []
    record = refused(records)[0]
    assert record["missing_hop"] == "device_consumption:gpio_register_commit"
    assert record["missing_identity"] == "store_transaction_key"
    assert record["reason"] == "no_declared_device_witness_joined"
    assert record["device"] == "gpio_b"
    assert record["transaction"] == txn


def test_store_without_a_matching_computed_value_refuses_the_rvfi_hop():
    txn = key(4)
    consumer = ComputedConsumerCertificates()
    records = consume([
        retire(1, 1, encode_itype(5, 0, 0, 0x202), 5, 0x202),
        mmio_acceptance(2, txn, address=0x40001004, offset=4, value=0x101),
        mmio_delivery(3, txn, address=0x40001004, offset=4, value=0x101),
    ], consumer)
    assert certified(records) == []
    record = refused(records)[0]
    assert record["missing_hop"] == "rvfi_compute"
    assert record["missing_identity"] == "computed_value_history"
    assert record["reason"] == "no_matching_computed_value_within_max_event_gap"


def test_computed_value_that_never_reaches_a_store_refuses_the_route_hop():
    consumer = ComputedConsumerCertificates()
    records = consume([
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
    ], consumer)
    assert certified(records) == []
    record = refused(records)[0]
    assert record["missing_hop"] == "mmio_store_route"
    assert record["missing_identity"] == "store_transaction_key"
    assert record["reason"] == "computed_value_never_reached_a_store"
    assert record["computed"]["event_id"] == 1


def test_witness_with_the_right_value_but_a_foreign_key_is_refused():
    txn = key(4)
    foreign = key(5)
    consumer = ComputedConsumerCertificates()
    records = consume([
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(2, txn, address=0x40001004, offset=4, value=0x101),
        mmio_delivery(3, txn, address=0x40001004, offset=4, value=0x101),
        gpio_commit(4, foreign, offset=4, value=0x101, apb_event_id=3),
    ], consumer)
    assert certified(records) == []
    record = refused(records)[0]
    assert record["missing_hop"] == "device_consumption:gpio_register_commit"
    assert record["missing_identity"] == "store_transaction_key"
    assert record["reason"] == "witness_identity_mismatch"
    assert consumer.counters["witness_join_failures"] == 1


def test_witness_value_mismatch_on_an_enabled_lane_is_refused():
    txn = key(4)
    consumer = ComputedConsumerCertificates()
    records = consume([
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(2, txn, address=0x40001004, offset=4, value=0x101),
        mmio_delivery(3, txn, address=0x40001004, offset=4, value=0x101),
        gpio_commit(4, txn, offset=4, value=0x202, apb_event_id=3),
    ], consumer)
    assert certified(records) == []
    record = refused(records)[0]
    assert record["missing_hop"] == "device_consumption:gpio_register_commit"
    assert record["missing_identity"] == "store_enabled_lane_value"
    assert record["reason"] == "witness_value_mismatch"


def test_unjoinable_fifo_witness_is_refused_not_adjacency_joined():
    txn = key(4)
    consumer = ComputedConsumerCertificates()
    records = consume([
        retire(1, 1, encode_itype(2, 0, 0, 0x0c), 2, 0x0c),
        mmio_acceptance(2, txn, address=0x4000001c, offset=28, device="uart", be=1,
                        value=0x0c),
        mmio_delivery(3, txn, address=0x4000001c, offset=28, device="uart", be=1,
                      value=0x0c),
        uart_fifo_push(4, value=0x0c),
    ], consumer)
    assert certified(records) == []
    record = refused(records)[0]
    assert record["missing_hop"] == "device_consumption:uart_fifo_push"
    assert record["missing_identity"] == "store_transaction_key"
    assert record["reason"] == "declared_witness_cannot_join"
    assert consumer.witness_evidence["uart_fifo_push"]["events"] == 1
    assert consumer.witness_evidence["uart_fifo_push"]["certified"] == 0


def test_raw_pad_observation_with_the_same_value_never_certifies():
    txn = key(4)
    consumer = ComputedConsumerCertificates()
    records = consume([
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(2, txn, address=0x40001004, offset=4, value=0x101),
        mmio_delivery(3, txn, address=0x40001004, offset=4, value=0x101),
        gpio_pad_observation(4, out_value=0x101),
    ], consumer)
    assert certified(records) == []
    record = refused(records)[0]
    assert record["missing_hop"] == "device_consumption:gpio_pad_observation"
    assert record["missing_identity"] == "store_transaction_key"
    assert record["reason"] == "declared_witness_cannot_join"


def test_read_access_witness_cannot_join_a_store_transaction_key():
    store_txn = key(4)
    read_txn = key(5)
    consumer = ComputedConsumerCertificates()
    records = consume([
        retire(1, 1, encode_itype(2, 0, 0, 0x0c), 2, 0x0c),
        mmio_acceptance(2, store_txn, address=0x4000001c, offset=28, device="uart",
                        be=1, value=0x0c),
        mmio_delivery(3, store_txn, address=0x4000001c, offset=28, device="uart",
                      be=1, value=0x0c),
        uart_fifo_pop(4, read_txn, value=0x0c),
        uart_rdata_access(5, read_txn, value=0x0c),
    ], consumer)
    assert certified(records) == []
    hops = {r["missing_hop"] for r in refused(records)}
    assert hops <= {"device_consumption:uart_fifo_pop",
                    "device_consumption:uart_rdata_access"}
    for record in refused(records):
        assert record["missing_identity"] == "store_transaction_key"
    assert consumer.witness_evidence["uart_rdata_access"]["events"] == 1


def test_readback_witness_is_refused_when_its_key_is_the_read_transaction():
    store_txn = key(4)
    read_txn = key(6)
    consumer = ComputedConsumerCertificates()
    records = consume([
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(2, store_txn, address=0x40001004, offset=4, value=0x101),
        mmio_delivery(3, store_txn, address=0x40001004, offset=4, value=0x101),
        gpio_register_read(4, read_txn, value=0x101),
    ], consumer)
    assert certified(records) == []
    assert refused(records)[0]["missing_hop"] == \
        "device_consumption:gpio_register_read"
    assert refused(records)[0]["missing_identity"] == "store_transaction_key"
    assert consumer.witness_evidence["gpio_register_read"]["events"] == 1
    assert consumer.witness_evidence["gpio_register_read"]["certified"] == 0


def test_spi_chain_refuses_with_the_declared_absent_transport_kind():
    txn = key(4)
    consumer = ComputedConsumerCertificates()
    records = consume([
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(2, txn, address=0x40002004, offset=4, device="spi0",
                        value=0x101),
        mmio_delivery(3, txn, address=0x40002004, offset=4, device="spi0",
                      value=0x101),
    ], consumer)
    assert certified(records) == []
    record = refused(records)[0]
    assert record["missing_hop"] == "device_consumption:spi_transfer"
    assert record["missing_identity"] == "store_transaction_key"
    assert record["reason"] == "declared_witness_kind_absent_from_artifact"
    per_kind = consumer.witness_evidence["spi_transfer"]
    assert per_kind["events"] == 0
    assert per_kind["status"] == "absent_from_artifact"


def test_events_after_a_reset_barrier_never_extend_a_chain():
    txn = key(4)
    consumer = ComputedConsumerCertificates()
    records = consume([
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(2, txn, address=0x40001004, offset=4, value=0x101),
        mmio_delivery(3, txn, address=0x40001004, offset=4, value=0x101),
        reset(4, epoch=1),
        gpio_commit(5, txn, offset=4, value=0x101, apb_event_id=3),
    ], consumer)
    assert certified(records) == []
    assert consumer.rejections.get("reset_barrier_cancelled_pending") == 1


def test_journal_gap_cancels_every_pending_candidate():
    txn = key(4)
    consumer = ComputedConsumerCertificates()
    records = consume([
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(2, txn, address=0x40001004, offset=4, value=0x101),
        mmio_delivery(3, txn, address=0x40001004, offset=4, value=0x101),
        gpio_commit(9, txn, offset=4, value=0x101, apb_event_id=3),
    ], consumer)
    assert certified(records) == []
    assert consumer.rejections.get("journal_gap") == 1
    assert consumer.pending_count == 0


# --------------------------------------------------------------------------
# unknown / no evidence
# --------------------------------------------------------------------------

def test_device_without_a_declared_witness_kind_is_unknown_not_refused():
    txn = key(4)
    consumer = ComputedConsumerCertificates()
    records = consume([
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(2, txn, address=0x40003004, offset=4, device="i2c0",
                        value=0x101),
        mmio_delivery(3, txn, address=0x40003004, offset=4, device="i2c0",
                      value=0x101),
    ], consumer)
    assert certified(records) == [] and refused(records) == []
    record = unknown(records)[0]
    assert record["status"] == "unknown"
    assert record["reason"] == "no_declared_witness_kind_for_device:i2c0"
    assert record["missing_hop"] is None and record["missing_identity"] is None
    assert consumer.unknown_count == 1
    assert consumer.refused_count == 0


def test_every_record_carries_the_mandatory_proof_boundaries():
    consumer = ComputedConsumerCertificates()
    records = consume([
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(2, key(4), address=0x40003004, offset=4, device="i2c0",
                        value=0x101),
        mmio_delivery(3, key(4), address=0x40003004, offset=4, device="i2c0",
                      value=0x101),
        retire(4, 2, encode_itype(6, 0, 0, 0x202), 6, 0x202),
    ], consumer)
    assert {record["status"] for record in records} == {"unknown", "refused"}
    for record in records:
        assert record["proof_scope"] == PROOF_SCOPE
        assert record["not_proof_of"] == list(NOT_PROOF_OF)
        assert "register_file_internal_source_token" in record["not_proof_of"]
        assert "device_internal_register_or_fifo_provenance" in record["not_proof_of"]
        assert "cross_instruction_data_dependency" in record["not_proof_of"]
        assert "device_consuming_logic_correctness" in record["not_proof_of"]


def test_uncertified_run_never_reports_a_certified_count_of_zero_without_reason():
    """A run with no RVFI retirement is unknown evidence, not a proven zero."""
    consumer = ComputedConsumerCertificates()
    consume([gpio_pad_observation(1, out_value=0)], consumer)
    assert consumer.certified_count == 0
    assert consumer.rvfi_retirement_count == 0
    assert consumer.evidence_status() == "unknown"
    assert consumer.evidence_reason() == "no_rvfi_retirement_events"


# --------------------------------------------------------------------------
# bounded retention and explicit eviction accounting
# --------------------------------------------------------------------------

def test_chain_capacity_eviction_is_reported():
    first, second = key(1), key(2)
    consumer = ComputedConsumerCertificates(max_pending=1)
    records = consume([
        gpio_apb(1, key(99), offset=0, value=0),               # device evidence
        retire(2, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(3, first, address=0x40001004, offset=4, value=0x101),
        retire(4, 2, encode_itype(6, 0, 0, 0x202), 6, 0x202),
        mmio_acceptance(5, second, address=0x40001004, offset=4, value=0x202),
    ], consumer)
    assert consumer.counters["chain_capacity_expired"] == 1
    assert consumer.max_pending == 1
    # The evicted chain is reported, never silently dropped.
    assert any(r["transaction"] == first for r in refused(records))
    assert consumer.refused_count >= 1


def test_value_history_eviction_is_reported_and_costs_the_start_hop():
    consumer = ComputedConsumerCertificates(max_value_history=1)
    records = []
    for event in [retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
                  retire(2, 2, encode_itype(6, 0, 0, 0x202), 6, 0x202),
                  mmio_acceptance(3, key(1), address=0x40001004, offset=4, value=0x101),
                  mmio_delivery(4, key(1), address=0x40001004, offset=4, value=0x101)]:
        records.extend(consumer.ingest((event,)))
    assert consumer.counters["value_history_evicted"] == 1
    assert consumer.computed_value_count == 1        # only the latest value is kept
    records.extend(consumer.flush())
    assert refused(records)[0]["missing_hop"] == "rvfi_compute"


def test_refusal_sample_retention_is_bounded_and_reported():
    consumer = ComputedConsumerCertificates(max_records=1)
    events = []
    for index in range(3):
        events.append(retire(index + 1, index + 1,
                             encode_itype(5, 0, 0, 0x100 + index), 5, 0x100 + index))
    records = consume(events, consumer)
    assert consumer.refused_count == 3
    assert len(consumer.refusals) == 1
    assert consumer.counters["refusal_records_evicted"] == 2
    assert len(refused(records)) == 3  # every refusal is still returned once


def test_event_gap_bound_expires_a_chain_and_names_the_missing_hop():
    consumer = ComputedConsumerCertificates(max_event_gap=4)
    records = consume([
        gpio_apb(1, key(99), offset=0, value=0),
        retire(2, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(3, key(1), address=0x40001004, offset=4, value=0x101),
    ], consumer)
    assert consumer.max_event_gap == 4
    assert refused(records)[0]["missing_hop"] == "device_consumption:gpio_register_commit"
    assert consumer.pending_count == 0


def test_bounds_must_be_positive_integers():
    with pytest.raises(ValueError):
        ComputedConsumerCertificates(max_pending=0)
    with pytest.raises(ValueError):
        ComputedConsumerCertificates(max_event_gap=-1)
    with pytest.raises(ValueError):
        ComputedConsumerCertificates(max_value_history=True)


# --------------------------------------------------------------------------
# CLI: read-only, fail-closed, deterministic
# --------------------------------------------------------------------------

def _write_run(run_dir: Path, events: list[dict], *, digest: bool = False) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(event, sort_keys=True) for event in events]
    (run_dir / "online_events.jsonl").write_text("\n".join(lines) + "\n",
                                                 encoding="utf-8")
    metadata = {"schema_version": "online_trace_jsonl.v1",
                "events_file": "online_events.jsonl",
                "event_count": len(events), "local_ticks": {"cpu": 1},
                "status": "complete"}
    if digest:
        import hashlib
        from myfuzz.scenario.acceptance_metrics import _canonical_bytes
        sha = hashlib.sha256(b'{"events":[')
        for index, event in enumerate(events):
            if index:
                sha.update(b",")
            sha.update(_canonical_bytes(event))
        sha.update(b'],"local_ticks":')
        sha.update(_canonical_bytes(metadata["local_ticks"]))
        sha.update(b',"status":')
        sha.update(_canonical_bytes(metadata["status"]))
        sha.update(b"}")
        metadata["semantic_sha256"] = sha.hexdigest()
    (run_dir / "online_final_trace.meta.json").write_text(
        json.dumps(metadata, sort_keys=True), encoding="utf-8")
    return run_dir


def _synthetic_run(tmp_path: Path, *, device="gpio_b", witness=True) -> Path:
    txn = key(1)
    events = [
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        mmio_acceptance(2, txn, address=0x40001004, offset=4, device=device,
                        value=0x101),
        data_accept(3, txn, address=0x40001004, value=0x101),
        gpio_receipt(4, txn, offset=4, value=0x101, device=device),
        mmio_delivery(5, txn, address=0x40001004, offset=4, device=device,
                      value=0x101),
        data_response(6, txn, address=0x40001004, value=0x101),
    ]
    if witness:
        events.extend([
            gpio_apb(7, txn, offset=4, value=0x101, device=device),
            gpio_commit(8, txn, offset=4, value=0x101, apb_event_id=7,
                        device=device),
        ])
    return _write_run(tmp_path / "synthetic-run", events, digest=True)


def test_cli_summarizes_a_synthetic_run_with_exact_event_ids_and_keys(tmp_path):
    cli = _load_cli()
    run_dir = _synthetic_run(tmp_path)
    summary = cli.summarize_run(run_dir)
    assert summary["status"] == "ok"
    assert summary["reason"] is None
    assert summary["certified"] == 1
    assert summary["refused"] == 0
    assert summary["unknown"] == 0
    assert summary["semantic_sha256_matches"] is True
    certificate = summary["certificates"][0]
    assert certificate["witness_kind"] == "gpio_register_commit"
    assert certificate["event_ids"] == [1, 2, 3, 4, 5, 6, 7, 8]
    assert certificate["transaction"] == key(1)
    assert certificate["identity_joins"][0]["status"] == "matched"
    kinds = summary["witness_kinds"]
    assert kinds["gpio_register_commit"]["events_seen"] == 1
    assert kinds["gpio_register_commit"]["certified"] == 1
    assert kinds["gpio_register_commit"]["status"] == "observed"
    assert kinds["spi_transfer"]["events_seen"] == 0
    assert kinds["spi_transfer"]["status"] == "absent_from_artifact"
    assert kinds["spi_transfer"]["reason"] == "declared_witness_kind_absent_from_artifact"


def test_cli_reports_refusals_per_witness_kind_with_the_first_missing_hop(tmp_path):
    cli = _load_cli()
    run_dir = _synthetic_run(tmp_path, witness=False)
    summary = cli.summarize_run(run_dir)
    assert summary["status"] == "ok"
    assert summary["certified"] == 0
    assert summary["refused"] == 1
    assert summary["refusals_by_missing_hop"] == {
        "device_consumption:gpio_register_commit": 1}
    assert summary["refusals_by_missing_identity"] == {"store_transaction_key": 1}
    assert summary["witness_kinds"]["gpio_register_commit"]["events_seen"] == 0
    assert summary["witness_kinds"]["gpio_register_commit"]["certified"] == 0


def test_cli_fails_closed_when_the_run_has_no_streamable_artifact(tmp_path):
    cli = _load_cli()
    missing = tmp_path / "no-such-run"
    summary = cli.summarize_run(missing)
    assert summary["status"] == "unknown"
    assert summary["reason"].startswith("artifact_unavailable:")
    assert summary["certified"] is None
    assert summary["refused"] is None
    assert summary["unknown"] is None
    assert all(row["certified"] is None for row in summary["witness_kinds"].values())
    exit_code = cli.main([str(missing)])
    assert exit_code != 0


def test_cli_fails_closed_when_the_declared_digest_does_not_match(tmp_path):
    cli = _load_cli()
    run_dir = _synthetic_run(tmp_path)
    metadata = json.loads((run_dir / "online_final_trace.meta.json").read_text())
    metadata["semantic_sha256"] = "0" * 64
    (run_dir / "online_final_trace.meta.json").write_text(
        json.dumps(metadata, sort_keys=True), encoding="utf-8")
    summary = cli.summarize_run(run_dir)
    assert summary["status"] == "unknown"
    assert summary["reason"] == "semantic_sha256_mismatch"
    assert summary["certified"] is None
    assert cli.main([str(run_dir)]) != 0


def test_cli_fails_closed_when_the_run_carries_no_rvfi_retirement(tmp_path):
    cli = _load_cli()
    run_dir = _write_run(tmp_path / "no-rvfi", [gpio_pad_observation(1, out_value=0)])
    summary = cli.summarize_run(run_dir)
    assert summary["status"] == "unknown"
    assert summary["reason"] == "no_rvfi_retirement_events"
    assert summary["certified"] is None
    assert cli.main([str(run_dir)]) != 0


def test_cli_output_is_byte_identical_across_runs(tmp_path):
    cli = _load_cli()
    run_dir = _synthetic_run(tmp_path)
    first = json.dumps(cli.summarize_run(run_dir), indent=1, sort_keys=True)
    second = json.dumps(cli.summarize_run(run_dir), indent=1, sort_keys=True)
    assert first == second
    out_a = tmp_path / "a.json"
    out_b = tmp_path / "b.json"
    assert cli.main([str(run_dir), "--output", str(out_a)]) == 0
    assert cli.main([str(run_dir), "--output", str(out_b)]) == 0
    assert out_a.read_bytes() == out_b.read_bytes()


def test_two_consumers_over_the_same_journal_agree_exactly():
    txn = key(1)
    events = [
        retire(1, 1, encode_itype(5, 0, 0, 0x101), 5, 0x101),
        *_gpio_anchor(txn),
        gpio_apb(7, txn, offset=4, value=0x101),
        gpio_commit(8, txn, offset=4, value=0x101, apb_event_id=7),
    ]
    first = ComputedConsumerCertificates()
    second = ComputedConsumerCertificates()
    assert consume(list(events), first) == consume(list(events), second)


# --------------------------------------------------------------------------
# real frozen runs (read-only; no RTL is started)
# --------------------------------------------------------------------------

REAL_UART_RUN = REPO_ROOT / "runs" / "p3-capacity-probe-paired-20261007"
REAL_GPIO_RUN = REPO_ROOT / "runs" / "current-dataflow-p5-fault-calibration-20261007-online"


@pytest.mark.skipif(not REAL_UART_RUN.is_dir(), reason="frozen run not present")
def test_real_uart_run_certifies_a_uart_consumer_read_only():
    cli = _load_cli()
    summary = cli.summarize_run(REAL_UART_RUN)
    assert summary["status"] == "ok"
    assert summary["semantic_sha256_matches"] is True
    assert summary["rvfi_retirements"] > 0
    assert summary["certified"] >= 1
    uart = [c for c in summary["certificates"]
            if c["witness_kind"] == "uart_tick_observation_access"]
    assert uart, "the frozen UART run must yield a UART consumer certificate"
    certificate = uart[0]
    assert certificate["device"] == "uart"
    assert certificate["event_ids"][0] < certificate["event_ids"][-1]
    assert certificate["transaction"]["channel_id"] == "data"
    assert certificate["witness_event_id"] in certificate["event_ids"]
    # Kinds the artifact does not carry are reported as absent, not as a zero
    # certificate claim.
    assert summary["witness_kinds"]["gpio_register_commit"]["status"] == \
        "absent_from_artifact"
    assert summary["witness_kinds"]["uart_fifo_push"]["status"] == "observed"
    assert summary["witness_kinds"]["uart_fifo_push"]["certified"] == 0
    assert "store_transaction_key" in summary["witness_kinds"]["uart_fifo_push"][
        "unjoinable_reason"]


@pytest.mark.skipif(not REAL_GPIO_RUN.is_dir(), reason="frozen run not present")
def test_real_gpio_run_certifies_register_commits_read_only():
    cli = _load_cli()
    summary = cli.summarize_run(REAL_GPIO_RUN)
    assert summary["status"] == "ok"
    assert summary["rvfi_retirements"] > 0
    assert summary["certified"] >= 1
    kinds = {c["witness_kind"] for c in summary["certificates"]}
    assert "gpio_register_commit" in kinds
    assert summary["witness_kinds"]["gpio_register_commit"]["events_seen"] > 0
    assert 1 <= summary["witness_kinds"]["gpio_register_commit"]["certified"] <= \
        summary["witness_kinds"]["gpio_register_commit"]["events_seen"]


@pytest.mark.skipif(not REAL_UART_RUN.is_dir(), reason="frozen run not present")
def test_real_run_stream_is_only_read_through_the_shipped_view():
    stream = TraceEventStream(REAL_UART_RUN)
    kinds = set()
    for event in stream.events():
        kinds.add(str(event.get("kind")))
    assert stream.semantic_sha256_verified() is True
    assert stream.descriptor["declared_event_count"] == 16492
    assert "cpu_retire" in kinds and "uart_tick_observation" in kinds
