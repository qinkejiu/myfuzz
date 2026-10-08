"""End-to-end chain certificates over a contiguous runtime event journal.

Positive cases are hand-built journals whose every hop is an exact identity
join; negative cases delete, reorder or tamper single hops and require
fail-closed ``incomplete`` results. Journals are declared with symbolic event
references (``"@name"``) that are resolved once, at build time, so a test may
insert, drop or renumber events without ever corrupting a cross reference.

The real-fixture tests stream the 163 MiB ``pin8-cpu-irq-events.jsonl`` fixture
line by line and never materialise the event stream in memory.
"""

import hashlib
import json
from pathlib import Path

import pytest

from myfuzz.scenario.chain_certificates import (
    CPU_TO_IP_TO_CPU,
    IP_TO_CPU_TO_IP,
    SCHEMA_VERSION,
    ChainCertificates,
)
from myfuzz.scenario.source_provenance import SourceAdmission
from tests.scenario.test_gpio_consumption_versions import probes, tick


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / ".superpowers/sdd/fixtures/pin8-cpu-irq-events.jsonl"

# Independent copy of the frozen hop contracts used by the expectations below.
IP_HOPS = (
    "pin8_admission", "pin8_injection", "pin8_segment_applied",
    "pin8_input_resource", "pin8_sync0_sample", "pin8_sync1_sample",
    "gpio_b_native_irq_trigger", "gpio_b_native_irq_observation",
    "cpu_irq_input", "cpu_irq_taken",
    "isr_padin_mmio_acceptance", "isr_padin_target_receipt",
    "isr_padin_target_access", "isr_padin_register_read",
    "isr_padin_mmio_delivery", "isr_padin_data_response",
    "isr_padin_retirement",
)
CPU_HOPS = (
    "instruction_admission", "instruction_source", "instruction_fetch",
    "mmio_write_acceptance", "mmio_write_data_acceptance",
    "gpio_a_target_receipt", "gpio_a_target_access",
    "gpio_a_register_commit", "mmio_write_delivery",
    "mmio_write_data_response", "instruction_retirement",
    "instruction_retirement_match", "retired_target_delivery",
)
PADIN_OFFSET = 8
PADOUT_OFFSET = 12
GPIO_B_ADDRESS = 0x40000000
GPIO_A_ADDRESS = 0x40001000


def _provenance(case_index, *, case_id=None, origin="unknown", admissions=()):
    return {"schema_version": "event_source_provenance.v1",
            "observed_case": {"case_id": case_id or f"case-{case_index}",
                              "case_index": case_index},
            "origin_status": origin, "origin_admission_ids": list(admissions),
            "invalid_origin_references": 0, "unknown_writer_ids": [],
            "edge_candidates": [], "resource": None,
            "proof_scope": "observation_only"}


def _transaction(sequence):
    return {"channel_id": "data", "execution_id": "local-execution",
            "source_component": "cpu", "source_epoch": 0,
            "source_sequence": sequence, "testcase_id": "synthetic"}


def _resolve(value, ids):
    if isinstance(value, str) and value.startswith("@"):
        name, _, delta = value[1:].partition("+")
        assert name in ids, name
        return ids[name] + (int(delta) if delta else 0)
    if isinstance(value, dict):
        return {key: _resolve(item, ids) for key, item in value.items()}
    if isinstance(value, list):
        return [_resolve(item, ids) for item in value]
    return value


class _Journal:
    """Ordered journal builder with lazily assigned event ids.

    Rows hold symbolic references; ``events`` and ``ids`` are recomputed after
    every structural change, so inserting or removing a row never leaves a
    stale cross reference behind.
    """

    def __init__(self, tag=""):
        self._rows = []
        self._tag = tag
        self._built = None

    def add(self, name, event):
        self._rows.append([None if name is None else self._tag + name,
                           dict(event)])
        self._built = None
        return self

    def append_journal(self, other):
        self._rows.extend([list(row) for row in other._rows])
        self._built = None
        return self

    def ref(self, name):
        """Symbolic reference to one of this journal's named events."""
        return "@" + self._tag + name

    def index(self, name):
        for index, row in enumerate(self._rows):
            if row[0] == self._tag + name:
                return index
        raise KeyError(f"{self._tag}{name}")

    def insert_before(self, name, event):
        self._rows.insert(self.index(name), [None, dict(event)])
        self._built = None
        return self

    def without(self, name):
        self._rows.pop(self.index(name))
        self._built = None
        return self

    def drop(self, name):
        """Blank one hop while keeping every other event id untouched."""
        index = self.index(name)
        self._rows[index][1] = {"kind": "state_dependency"}
        self._built = None
        return self

    def mutate(self, name, **changes):
        index = self.index(name)
        self._rows[index][1] = {**self._rows[index][1], **changes}
        self._built = None
        return self

    def edit(self, name, editor):
        index = self.index(name)
        self._rows[index][1] = editor(dict(self._rows[index][1]))
        self._built = None
        return self

    def _build(self):
        if self._built is None:
            ids = {}
            for position, row in enumerate(self._rows):
                if row[0] is not None:
                    assert row[0] not in ids, row[0]
                    ids[row[0]] = position + 1
            events = []
            for position, row in enumerate(self._rows):
                event = {**row[1], "event_id": position + 1}
                events.append(_resolve(event, ids))
            self._built = (events, {key[len(self._tag):]: value for key, value
                                    in ids.items()})
        return self._built

    @property
    def events(self):
        return self._build()[0]

    @property
    def ids(self):
        return self._build()[1]


def _pin8_admission(case_index=1):
    return SourceAdmission.create(
        case_id=f"case-{case_index}", case_index=case_index,
        source_id="gpio_b.external_pin8", path_id="pin-path",
        direction=IP_TO_CPU_TO_IP, component="gpio_b",
        action_id=f"case-{case_index}:gpio_b.external_pin8", role="fuzz_source",
        input_kind="source_event", input_sha256="a" * 64)


def _cpu_admission(case_index=1):
    return SourceAdmission.create(
        case_id=f"case-{case_index}", case_index=case_index,
        source_id="cpu.online_instruction", path_id="cpu-path",
        direction=CPU_TO_IP_TO_CPU, component="cpu",
        action_id=f"case-{case_index}:cpu.online_instruction", role="fuzz_source",
        input_kind="instruction", input_sha256="b" * 64)


def _resource(register, version, observed_id, origin, value, predecessor=None):
    return {"component": "gpio_b", "reset_epoch": 0, "register": register,
            "bit": 8, "version": version, "value": value,
            "observation_event_id": observed_id, "local_tick": version,
            "origin_status": "known", "origin_refs": [origin],
            "dependencies": [] if predecessor is None else
            [{key: predecessor[key] for key in
              ("component", "reset_epoch", "register", "bit", "version",
               "value", "observation_event_id", "local_tick")}]}


def _ip_journal(case_index=1, admission=None, tag=""):
    """Complete, exactly joined pin8 -> IRQ -> ISR PADIN read chain."""
    admission = admission or _pin8_admission(case_index)
    origin = admission.document()
    case = case_index
    journal = _Journal(tag)

    # Tick 1: pin 8 is high on the pad; synchronizers still hold zero. INTTYPE
    # selects the mode-1 (rise) edge for pin 8, i.e. bits 17:16.
    pre1 = probes(gpioen=256, inten=256, inttype=1 << 16, input_clock_enable=4)
    pre1["gpio_in"] = 256
    post1 = dict(pre1)
    post1["gpio_probe_sync0"] = 256
    journal.add("tick_first", {**tick(1, pre1, post1, component="gpio_b"),
                               "local_tick": 1, "provenance": _provenance(case)})
    journal.add("pin8_admission", {
        "kind": "source_admission", "admission": origin,
        "provenance": _provenance(case, origin="known",
                                  admissions=[admission.admission_id])})
    journal.add("pin8_injection", {
        "kind": "source_injection", "action_id": admission.action_id,
        "component": "gpio_b", "port": "gpio_in", "bit_offset": 8, "width": 1,
        "value": 1, "source_ref": "external_b.pin8",
        "provenance": _provenance(case, origin="known",
                                  admissions=[admission.admission_id])})
    journal.add("pin8_segment_applied", {
        "kind": "gpio_input_segment_applied", "component": "gpio_b",
        "port": "gpio_in", "bit_lo": 8, "width": 1, "value": 1,
        "reset_epoch": 0, "local_tick": 1,
        "actual_receipt_event_id": journal.ref("tick_first"), "actual_input_value": 256,
        "origin": {"kind": "source_admission", "action_id": admission.action_id},
        "provenance": _provenance(case)})
    input_resource = _resource("input", 11, journal.ref("pin8_segment_applied"), origin, 1)
    input_resource["actual_receipt_event_id"] = journal.ref("tick_first")
    journal.add("pin8_input_resource", {
        "kind": "gpio_input_applied_resource", "component": "gpio_b",
        "status": "observed", "origin_status": "known", "reset_epoch": 0,
        "local_tick": 1, "observation_event_id": journal.ref("pin8_segment_applied"),
        "producer_event_id": journal.ref("pin8_segment_applied"),
        "schema_version": "gpio_input_applied_resource.v1",
        "proof_scope": "gpio_native_resource_observation",
        "bit_resources": [input_resource], "provenance": _provenance(case)})
    sync0 = _resource("sync0", 12, journal.ref("tick_first"), origin, 1,
                      predecessor=input_resource)
    journal.add("pin8_sync0_sample", {
        "kind": "gpio_input_sample", "component": "gpio_b",
        "status": "observed", "reset_epoch": 0, "local_tick": 1,
        "observation_event_id": journal.ref("tick_first"), "producer_event_id": journal.ref("tick_first"),
        "schema_version": "gpio_input_sample.v1",
        "proof_scope": "gpio_native_resource_observation",
        "enabled_mask": 256, "stages": {"sync0": [sync0]},
        "provenance": _provenance(case)})

    # Tick 2: sync0 captures the pin value and the native IRQ rises.
    pre2 = dict(post1)
    post2 = dict(pre2)
    post2["gpio_probe_sync1"] = 256
    post2["gpio_probe_rise"] = 256
    post2["gpio_probe_irq_trigger_mask"] = 256
    post2["gpio_probe_native_irq"] = 1
    journal.add("tick_second", {**tick(2, pre2, post2, component="gpio_b"),
                                "local_tick": 2, "provenance": _provenance(case)})
    sync1 = _resource("sync1", 13, journal.ref("tick_second"), origin, 1, predecessor=sync0)
    journal.add("pin8_sync1_sample", {
        "kind": "gpio_input_sample", "component": "gpio_b",
        "status": "observed", "reset_epoch": 0, "local_tick": 2,
        "observation_event_id": journal.ref("tick_second"),
        "producer_event_id": journal.ref("tick_second"),
        "schema_version": "gpio_input_sample.v1",
        "proof_scope": "gpio_native_resource_observation",
        "enabled_mask": 256, "stages": {"sync1": [sync1]},
        "provenance": _provenance(case)})
    prior = {"component": "gpio_b", "register": "padin_latch", "bit": 8,
             "value": 0, "version": 10, "reset_epoch": 0,
             "origin_status": "unknown", "origin_refs": [], "phase": None,
             "trigger_id": None, "dependencies": [],
             "observation_event_id": journal.ref("tick_second"), "local_tick": 2}
    causes = [{"pin": 8, "prior_sample": prior, "current_sample": dict(sync1),
               "configuration": {}}]
    journal.add("gpio_b_native_irq_trigger", {
        "kind": "gpio_irq_trigger", "component": "gpio_b", "mask": 256,
        "trigger_id": "gpio_b:0:trigger:1", "phase": "post",
        "status": "observed", "origin_status": "known",
        "proof_scope": "gpio_native_resource_observation",
        "schema_version": "gpio_irq_trigger.v1",
        "observation_event_id": journal.ref("tick_second"),
        "producer_event_id": journal.ref("tick_second"), "local_tick": 2, "reset_epoch": 0,
        "causes": causes, "provenance": _provenance(case)})

    # Tick 3: the trigger is observed high before the pulse returns low.
    pre3 = dict(post2)
    post3 = dict(pre3)
    post3["gpio_probe_padin_latch"] = 256
    post3["gpio_probe_rise"] = 0
    post3["gpio_probe_irq_trigger_mask"] = 0
    post3["gpio_probe_native_irq"] = 0
    post3["gpio_probe_status"] = 256
    journal.add("tick_third", {**tick(3, pre3, post3, component="gpio_b"),
                               "local_tick": 3, "provenance": _provenance(case)})
    journal.add("gpio_b_native_irq_observation", {
        "kind": "gpio_irq_observation", "component": "gpio_b", "mask": 256,
        "trigger_id": "gpio_b:0:trigger:1", "phase": "pre",
        "status": "observed",
        "proof_scope": "gpio_native_resource_observation",
        "schema_version": "gpio_irq_observation.v1",
        "observation_event_id": journal.ref("tick_third"), "producer_event_id": journal.ref("tick_third"),
        "local_tick": 3, "reset_epoch": 0, "causes": causes,
        "provenance": _provenance(case)})
    journal.add("ip_irq_sample", {
        "kind": "local_tick_sample", "component": "gpio_b", "phase": "post",
        "local_tick": 2, "reset_epoch": 0, "outputs": {"interrupt": 1, "irq": 1},
        "provenance": _provenance(case)})
    reference = {"trigger_id": "gpio_b:0:trigger:1",
                 "trigger_event_id": journal.ref("gpio_b_native_irq_trigger"),
                 "observation_event_id": journal.ref("tick_second"),
                 "sample_event_id": journal.ref("ip_irq_sample")}
    journal.add("ip_source_start", {
        "kind": "source_start", "source": ["gpio_b", "irq"],
        "target": ["cpu", "irq"], "source_bit_offset": 0,
        "target_bit_offset": 0, "width": 1, "source_event_id": 1,
        "source_tick": 2, "cpu_tick": 40, "source_trigger": dict(reference),
        "provenance": _provenance(case)})
    journal.add("ip_pulse_start", {
        "kind": "pulse_start", "source": ["gpio_b", "irq"],
        "target": ["cpu", "irq"], "source_bit_offset": 0,
        "target_bit_offset": 0, "width": 1, "source_event_id": 1,
        "start_cpu_tick": 41, "end_cpu_tick_exclusive": 45,
        "source_trigger": dict(reference), "provenance": _provenance(case)})
    journal.add("ip_step", {
        "component": "cpu", "local_tick": 41, "inputs": {"irq": 1},
        "outputs": {"irq_taken_pre": 1, "rvfi_valid": 0},
        "provenance": _provenance(case)})
    journal.add("cpu_irq_input", {
        "kind": "cpu_irq_input", "source": ["gpio_b", "irq"],
        "target": ["cpu", "irq"], "source_bit_offset": 0,
        "target_bit_offset": 0, "width": 1, "value": 1, "source_event_id": 1,
        "cpu_tick": 41, "cpu_step_event_id": journal.ref("ip_step"),
        "source_trigger": dict(reference), "provenance": _provenance(case)})
    journal.add("cpu_irq_taken", {
        "kind": "cpu_irq_taken", "source": ["gpio_b", "irq"],
        "target": ["cpu", "irq"], "source_bit_offset": 0,
        "target_bit_offset": 0, "width": 1, "source_event_id": 1,
        "cpu_tick": 41, "cpu_step_event_id": journal.ref("ip_step"),
        "source_trigger": dict(reference), "provenance": _provenance(case)})

    # The ISR loads GPIO B PADIN and retires with the delivered value.
    transaction = _transaction(11)
    access_id = "gpio-access:gpio_b:0:4"
    journal.add("isr_padin_mmio_acceptance", {
        "kind": "mmio_acceptance", "component": "cpu", "device_id": "gpio_b",
        "offset": PADIN_OFFSET, "write": False, "write_value": None,
        "address": GPIO_B_ADDRESS + PADIN_OFFSET, "beat_bytes": 4,
        "byte_enable": 15, "acceptance_order": 8, "source_sequence": 11,
        "source_transaction": dict(transaction), "producer_event_id": 900,
        "provenance": _provenance(case)})
    journal.add("isr_padin_data_acceptance", {
        "kind": "data_accept", "component": "cpu",
        "execution_id": "local-execution", "write": 0,
        "address": GPIO_B_ADDRESS + PADIN_OFFSET,
        "aligned_address": GPIO_B_ADDRESS + PADIN_OFFSET,
        "raw_address": GPIO_B_ADDRESS + PADIN_OFFSET, "be": 15, "wdata": 0,
        "tick": 206, "acceptance_tick": 206, "reset_epoch": 0,
        "source_epoch": 0, "source_component": "cpu",
        "transaction": dict(transaction), "producer_event_id": 900,
        "provenance": _provenance(case)})
    journal.add("isr_padin_target_receipt", {
        "kind": "gpio_target_receipt", "component": "gpio_b",
        "access_id": access_id, "raw_offset": PADIN_OFFSET,
        "decoded_offset": PADIN_OFFSET, "write": False, "wdata": 0,
        "status": "received", "producer_event_id": 901,
        "source_transaction": dict(transaction),
        "provenance": _provenance(case)})
    journal.add("isr_padin_target_access", {
        "kind": "gpio_apb_access", "component": "gpio_b",
        "access_id": access_id, "raw_offset": PADIN_OFFSET,
        "decoded_offset": PADIN_OFFSET, "write": False, "wdata": 0,
        "status": "observed", "phase": "pre", "local_tick": 221,
        "reset_epoch": 0, "source_epoch": 0, "producer_event_id": 901,
        "source_transaction": dict(transaction),
        "provenance": _provenance(case)})
    read_bits = [{"component": "gpio_b", "register": "padin_latch", "bit": bit,
                  "value": 1 if bit == 8 else 0, "version": 100 + bit,
                  "observation_event_id": journal.ref("isr_padin_target_access"),
                  "local_tick": 221, "reset_epoch": 0,
                  "origin_status": "unknown", "origin_refs": [],
                  "dependencies": [], "phase": None, "trigger_id": None}
                 for bit in range(32)]
    read_bits[8]["origin_status"] = "known"
    read_bits[8]["origin_refs"] = [origin]
    journal.add("isr_padin_register_read", {
        "kind": "gpio_register_read", "component": "gpio_b",
        "access_id": access_id, "register": "padin_latch",
        "status": "observed", "local_tick": 221, "reset_epoch": 0,
        "observation_event_id": journal.ref("isr_padin_target_access"),
        "producer_event_id": journal.ref("isr_padin_target_access"),
        "bit_resources": read_bits, "provenance": _provenance(case)})
    journal.add("isr_padin_mmio_delivery", {
        "kind": "mmio_delivery", "component": "cpu", "device_id": "gpio_b",
        "offset": PADIN_OFFSET, "write": False, "read_value": 262,
        "address": GPIO_B_ADDRESS + PADIN_OFFSET, "beat_bytes": 4,
        "byte_enable": 15, "delivery_order": 8, "source_sequence": 11,
        "target_access_id": access_id, "target_delivery_order": 8,
        "source_transaction": dict(transaction), "producer_event_id": 901,
        "provenance": _provenance(case)})
    journal.add("isr_padin_data_response", {
        "kind": "data_response", "component": "cpu",
        "execution_id": "local-execution", "write": 0,
        "address": GPIO_B_ADDRESS + PADIN_OFFSET, "rdata": 262, "error": 0,
        "be": 15, "tick": 207, "response_tick": 207, "acceptance_tick": 206,
        "reset_epoch": 0, "source_epoch": 0, "source_component": "cpu",
        "transaction": dict(transaction), "producer_event_id": 902,
        "provenance": _provenance(case)})
    journal.add("ip_fetch", {
        "kind": "instr_response", "component": "cpu", "address": 0x10200,
        "aligned_address": 0x10200, "raw_address": 0x10200, "rdata": 8429827,
        "wdata": 0, "write": 0, "be": 15, "tick": 202, "acceptance_tick": 201,
        "response_tick": 202, "error": 0, "reset_epoch": 0,
        "source_component": "cpu", "source_epoch": 0,
        "provenance": _provenance(case)})
    journal.add("ip_retire", {
        "kind": "cpu_retire", "component": "cpu", "valid": 1, "trap": 0,
        "intr": 0, "insn": 8429827, "order": 42, "pc_rdata": 0x10200,
        "pc_wdata": 0x10204, "mem_addr": GPIO_B_ADDRESS + PADIN_OFFSET,
        "mem_rmask": 15, "mem_wmask": 0, "mem_rdata": 262, "mem_wdata": 0,
        "tick": 208, "reset_epoch": 0, "source_component": "cpu",
        "source_epoch": 0, "execution_id": "local-execution",
        "provenance": _provenance(case)})
    journal.add("ip_match", {
        "kind": "cpu_retirement_match", "component": "cpu",
        "schema_version": "cpu_retirement_match.v1", "status": "accepted",
        "reason": "matched_ordered_retired_transaction",
        "instruction_origin_status": "unknown",
        "origin_relation": "retired_instruction_bytes",
        "proof_scope": "retired_instruction_origin",
        "producer_event_id": journal.ref("ip_retire"), "insn": 8429827, "pc": 0x10200,
        "order": 42, "source_refs": [], "transaction_keys": [dict(transaction)],
        "byte_cells": [{"versions": [[0, 0]] * 4,
                        "writer_event_ids": ["initial-image"] * 4,
                        "writer_kinds": ["INITIAL_IMAGE"] * 4}],
        "instruction_responses": [{
            "event_id": journal.ref("ip_fetch"), "address": 0x10200, "rdata": 8429827,
            "tick": 202, "acceptance_tick": 201,
            "snapshot": {"writer_event_ids": ["initial-image"] * 4,
                         "writer_kinds": ["INITIAL_IMAGE"] * 4}}],
        "data_beats": [{
            "event_id": journal.ref("isr_padin_data_acceptance"), "write": 0,
            "address": GPIO_B_ADDRESS + PADIN_OFFSET, "wdata": 0, "tick": 206,
            "acceptance_tick": 206, "transaction": dict(transaction),
            "response": {"event_id": journal.ref("isr_padin_data_response"), "write": 0,
                         "rdata": 262, "tick": 207, "response_tick": 207,
                         "transaction": dict(transaction)}}],
        "provenance": _provenance(case)})
    journal.add("isr_padin_retirement", {
        "kind": "cpu_retired_transaction_target_delivery", "component": "cpu",
        "schema_version": "cpu_retired_transaction_target_delivery.v1",
        "status": "linked_raw", "reason": "matched_fullkey_actual_delivery",
        "proof_scope": "retired_instruction_transaction_delivery",
        "producer_event_id": journal.ref("ip_match"), "retirement_event_id": journal.ref("ip_match"),
        "raw_rvfi_event_id": journal.ref("ip_retire"),
        "delivery_event_id": journal.ref("isr_padin_mmio_delivery"),
        "raw_delivery_event_id": 901, "known_fuzz_origin": False,
        "registered_origin_status": "unknown", "registered_origins": [],
        "source_refs": [], "instruction_all_beats_linked": True,
        "cpu_scope": {"execution_id": "local-execution",
                      "source_component": "cpu", "source_epoch": 0},
        "consumer_resource": {
            "device_id": "gpio_b", "offset": PADIN_OFFSET, "write": False,
            "read_value": 262, "target_access_id": access_id,
            "delivery_order": 8, "byte_enable": 15, "beat_bytes": 4,
            "address": GPIO_B_ADDRESS + PADIN_OFFSET, "write_value": None,
            "target_delivery_order": 8},
        "provenance": _provenance(case)})
    return journal


def _cpu_journal(case_index=1, admission=None, tag=""):
    """Complete, exactly joined instruction -> GPIO A PADOUT write chain."""
    admission = admission or _cpu_admission(case_index)
    origin = admission.document()
    case = case_index
    journal = _Journal(tag)
    instruction = 2139683
    write_value = 214085638
    transaction = _transaction(7)
    access_id = "gpio-access:gpio_a:0:4"
    journal.add("instruction_admission", {
        "kind": "source_admission", "admission": origin,
        "provenance": _provenance(case, origin="known",
                                  admissions=[admission.admission_id])})
    journal.add("instruction_source", {
        "kind": "instruction_source", "component": "cpu",
        "source_event_id": admission.action_id, "address": 0x11004,
        "data_hex": "37b1c20c13016100b710004023a62000", "generation": 0,
        "producer_event_id": 800,
        "provenance": _provenance(case, origin="known",
                                  admissions=[admission.admission_id])})
    journal.add("instruction_fetch", {
        "kind": "instr_response", "component": "cpu", "address": 0x11010,
        "aligned_address": 0x11010, "raw_address": 0x11010,
        "rdata": instruction, "wdata": 0, "write": 0, "be": 15, "tick": 92,
        "acceptance_tick": 91, "response_tick": 92, "error": 0,
        "reset_epoch": 0, "source_component": "cpu", "source_epoch": 0,
        "provenance": _provenance(case)})
    journal.add("mmio_write_acceptance", {
        "kind": "mmio_acceptance", "component": "cpu", "device_id": "gpio_a",
        "offset": PADOUT_OFFSET, "write": True, "write_value": write_value,
        "address": GPIO_A_ADDRESS + PADOUT_OFFSET, "beat_bytes": 4,
        "byte_enable": 15, "acceptance_order": 7, "source_sequence": 7,
        "source_transaction": dict(transaction), "producer_event_id": 810,
        "provenance": _provenance(case)})
    journal.add("mmio_write_data_acceptance", {
        "kind": "data_accept", "component": "cpu",
        "execution_id": "local-execution", "write": 1,
        "address": GPIO_A_ADDRESS + PADOUT_OFFSET,
        "aligned_address": GPIO_A_ADDRESS + PADOUT_OFFSET,
        "raw_address": GPIO_A_ADDRESS + PADOUT_OFFSET, "be": 15,
        "wdata": write_value, "tick": 94, "acceptance_tick": 94,
        "reset_epoch": 0, "source_epoch": 0, "source_component": "cpu",
        "transaction": dict(transaction), "producer_event_id": 810,
        "provenance": _provenance(case)})
    journal.add("gpio_a_target_receipt", {
        "kind": "gpio_target_receipt", "component": "gpio_a",
        "access_id": access_id, "raw_offset": PADOUT_OFFSET,
        "decoded_offset": PADOUT_OFFSET, "write": True, "wdata": write_value,
        "status": "received", "producer_event_id": 811,
        "source_transaction": dict(transaction),
        "provenance": _provenance(case)})
    journal.add("gpio_a_target_access", {
        "kind": "gpio_apb_access", "component": "gpio_a",
        "access_id": access_id, "raw_offset": PADOUT_OFFSET,
        "decoded_offset": PADOUT_OFFSET, "write": True, "wdata": write_value,
        "status": "observed", "phase": "pre", "local_tick": 109,
        "reset_epoch": 0, "source_epoch": 0, "producer_event_id": 811,
        "source_transaction": dict(transaction),
        "provenance": _provenance(case)})
    journal.add("gpio_a_register_commit", {
        "kind": "gpio_register_commit", "component": "gpio_a",
        "access_id": access_id, "register": "out", "raw_offset": PADOUT_OFFSET,
        "decoded_offset": PADOUT_OFFSET, "write_value": write_value,
        "status": "observed", "schema_version": "gpio_register_commit.v1",
        "local_tick": 109, "reset_epoch": 0,
        "observation_event_id": journal.ref("gpio_a_target_access"),
        "producer_event_id": journal.ref("gpio_a_target_access"),
        "bit_resources": [
            {"component": "gpio_a", "register": "out", "bit": bit,
             "value": (write_value >> bit) & 1, "version": 2185 + bit,
             "observation_event_id": journal.ref("gpio_a_target_access"),
             "local_tick": 109, "reset_epoch": 0, "dependencies": [],
             "origin_status": "unknown", "origin_refs": [],
             "transaction": dict(transaction)}
            for bit in range(4)],
        "provenance": _provenance(case)})
    journal.add("mmio_write_delivery", {
        "kind": "mmio_delivery", "component": "cpu", "device_id": "gpio_a",
        "offset": PADOUT_OFFSET, "write": True, "write_value": write_value,
        "read_value": None, "address": GPIO_A_ADDRESS + PADOUT_OFFSET,
        "beat_bytes": 4, "byte_enable": 15, "delivery_order": 7,
        "source_sequence": 7, "target_access_id": access_id,
        "target_delivery_order": 7,
        "source_transaction": dict(transaction), "producer_event_id": 811,
        "provenance": _provenance(case)})
    journal.add("mmio_write_data_response", {
        "kind": "data_response", "component": "cpu",
        "execution_id": "local-execution", "write": 1,
        "address": GPIO_A_ADDRESS + PADOUT_OFFSET, "rdata": 0, "error": 0,
        "be": 15, "wdata": write_value, "tick": 95, "response_tick": 95,
        "acceptance_tick": 94, "reset_epoch": 0, "source_epoch": 0,
        "source_component": "cpu", "transaction": dict(transaction),
        "producer_event_id": 812, "provenance": _provenance(case)})
    journal.add("instruction_retirement", {
        "kind": "cpu_retire", "component": "cpu", "valid": 1, "trap": 0,
        "intr": 0, "insn": instruction, "order": 29, "pc_rdata": 0x11010,
        "pc_wdata": 0x11014, "mem_addr": GPIO_A_ADDRESS + PADOUT_OFFSET,
        "mem_wmask": 15, "mem_rmask": 0, "mem_wdata": write_value,
        "mem_rdata": 0, "tick": 96, "reset_epoch": 0,
        "source_component": "cpu", "source_epoch": 0,
        "execution_id": "local-execution", "provenance": _provenance(case)})
    journal.add("instruction_retirement_match", {
        "kind": "cpu_retirement_match", "component": "cpu",
        "schema_version": "cpu_retirement_match.v1", "status": "accepted",
        "reason": "matched_ordered_retired_transaction",
        "instruction_origin_status": "typed_writer_refs",
        "origin_relation": "retired_instruction_bytes",
        "proof_scope": "retired_instruction_origin",
        "producer_event_id": journal.ref("instruction_retirement"), "insn": instruction,
        "pc": 0x11010, "order": 29, "source_refs": [admission.action_id],
        "transaction_keys": [dict(transaction)],
        "byte_cells": [{"versions": [[0, 4]] * 4,
                        "writer_event_ids": [admission.action_id] * 4,
                        "writer_kinds": ["INSTRUCTION_SOURCE"] * 4}],
        "instruction_responses": [{
            "event_id": journal.ref("instruction_fetch"), "address": 0x11010,
            "rdata": instruction, "tick": 92, "acceptance_tick": 91,
            "snapshot": {"byte_offset": 4112, "memory_id": "ram",
                         "writer_event_ids": [admission.action_id] * 4,
                         "writer_kinds": ["INSTRUCTION_SOURCE"] * 4}}],
        "data_beats": [{
            "event_id": journal.ref("mmio_write_data_acceptance"), "write": 1,
            "address": GPIO_A_ADDRESS + PADOUT_OFFSET, "wdata": write_value,
            "tick": 94, "acceptance_tick": 94, "transaction": dict(transaction),
            "response": {"event_id": journal.ref("mmio_write_data_response"), "write": 1,
                         "rdata": 0, "tick": 95, "response_tick": 95,
                         "transaction": dict(transaction)}}],
        "provenance": _provenance(case)})
    journal.add("retired_target_delivery", {
        "kind": "cpu_retired_transaction_target_delivery", "component": "cpu",
        "schema_version": "cpu_retired_transaction_target_delivery.v1",
        "status": "linked_raw", "reason": "matched_fullkey_actual_delivery",
        "proof_scope": "retired_instruction_transaction_delivery",
        "producer_event_id": journal.ref("instruction_retirement_match"),
        "retirement_event_id": journal.ref("instruction_retirement_match"),
        "raw_rvfi_event_id": journal.ref("instruction_retirement"),
        "delivery_event_id": journal.ref("mmio_write_delivery"),
        "raw_delivery_event_id": 811, "known_fuzz_origin": True,
        "registered_origin_status": "known",
        "registered_origin": _provenance(case, origin="known",
                                         admissions=[admission.admission_id]),
        "registered_origins": [origin],
        "source_refs": [admission.action_id],
        "instruction_all_beats_linked": True,
        "cpu_scope": {"execution_id": "local-execution",
                      "source_component": "cpu", "source_epoch": 0},
        "consumer_resource": {
            "device_id": "gpio_a", "offset": PADOUT_OFFSET, "write": True,
            "write_value": write_value, "read_value": None,
            "target_access_id": access_id, "delivery_order": 7,
            "byte_enable": 15, "beat_bytes": 4,
            "address": GPIO_A_ADDRESS + PADOUT_OFFSET,
            "target_delivery_order": 7},
        "provenance": _provenance(case)})
    return journal


def _merge(*journals):
    merged = _Journal()
    for journal in journals:
        merged.append_journal(journal)
    events = merged.events
    assert [event["event_id"] for event in events] == list(
        range(1, len(events) + 1))
    return merged


def _certificates(journal, **kwargs):
    consumer = ChainCertificates(**kwargs)
    result = list(consumer.ingest(journal.events))
    result.extend(consumer.flush())
    assert consumer.pending_count == 0
    return result, consumer


def _assert_hop_partition(certificate, hops):
    observed = [hop["hop_id"] for hop in certificate["hops"]]
    assert observed == [name for name in hops
                        if name not in certificate["missing_hops"]]
    assert certificate["missing_hops"] == [name for name in hops
                                           if name not in observed]
    assert [hop["event_id"] for hop in certificate["hops"]] == sorted(
        hop["event_id"] for hop in certificate["hops"])
    for hop in certificate["hops"]:
        assert type(hop["event_id"]) is int and hop["event_id"] > 0
        assert isinstance(hop["evidence"], dict) and hop["evidence"]
    if certificate["status"] == "certified":
        assert certificate["missing_hops"] == []
        assert certificate["completed_event_id"] == \
            certificate["hops"][-1]["event_id"]
    else:
        assert certificate["missing_hops"]


def test_synthetic_ip_chain_certifies_with_ordered_hops():
    journal = _ip_journal()
    certificates, _ = _certificates(journal)
    assert len(certificates) == 1
    certificate = certificates[0]
    admission = _pin8_admission()
    assert certificate["schema_version"] == SCHEMA_VERSION
    assert certificate["status"] == "certified"
    assert certificate["direction"] == IP_TO_CPU_TO_IP
    assert certificate["source_admission_id"] == admission.admission_id
    assert certificate["source_action_id"] == admission.action_id
    assert certificate["source_component"] == "gpio_b"
    assert certificate["source_id"] == "gpio_b.external_pin8"
    assert certificate["source_case_id"] == "case-1"
    assert certificate["source_case_index"] == 1
    assert certificate["endpoint_case_id"] == "case-1"
    assert certificate["endpoint_case_index"] == 1
    assert certificate["proof_scope"] == "ip_to_cpu_to_ip_certified_hops"
    assert [hop["hop_id"] for hop in certificate["hops"]] == list(IP_HOPS)
    assert [hop["event_id"] for hop in certificate["hops"]] == [
        journal.ids[name] for name in IP_HOPS]
    assert certificate["completed_event_id"] == \
        journal.ids["isr_padin_retirement"]
    assert certificate["completed_local_ticks"] == {"gpio_b": 221, "cpu": 207}
    expected = hashlib.sha256(json.dumps(
        [IP_TO_CPU_TO_IP, admission.admission_id],
        separators=(",", ":")).encode("utf-8")).hexdigest()
    assert certificate["certificate_id"] == expected
    _assert_hop_partition(certificate, IP_HOPS)


def test_synthetic_cpu_chain_certifies_with_ordered_hops():
    journal = _cpu_journal()
    certificates, _ = _certificates(journal)
    assert len(certificates) == 1
    certificate = certificates[0]
    admission = _cpu_admission()
    assert certificate["status"] == "certified"
    assert certificate["direction"] == CPU_TO_IP_TO_CPU
    assert certificate["source_admission_id"] == admission.admission_id
    assert certificate["source_id"] == "cpu.online_instruction"
    assert certificate["proof_scope"] == "cpu_to_ip_to_cpu_certified_hops"
    assert certificate["missing_hops"] == []
    assert [hop["hop_id"] for hop in certificate["hops"]] == list(CPU_HOPS)
    assert [hop["event_id"] for hop in certificate["hops"]] == [
        journal.ids[name] for name in CPU_HOPS]
    assert certificate["completed_event_id"] == \
        journal.ids["retired_target_delivery"]
    assert certificate["completed_local_ticks"] == {"gpio_a": 109, "cpu": 96}
    _assert_hop_partition(certificate, CPU_HOPS)


def test_weaker_receipt_requirement_drops_receipt_and_retirement_hops():
    for builder, hops, dropped in (
            (_ip_journal, IP_HOPS, ("isr_padin_target_receipt",
                                    "isr_padin_retirement")),
            (_cpu_journal, CPU_HOPS, ("gpio_a_target_receipt",
                                      "retired_target_delivery"))):
        journal = builder()
        certificates, _ = _certificates(journal, require_native_receipts=False)
        assert len(certificates) == 1
        certificate = certificates[0]
        assert certificate["status"] == "certified"
        required = tuple(name for name in hops if name not in dropped)
        assert [hop["hop_id"] for hop in certificate["hops"]] == list(required)
        _assert_hop_partition(certificate, required)


def test_interleaved_directions_certify_independently():
    journal = _merge(_ip_journal(),
                     _cpu_journal(case_index=2, admission=_cpu_admission(2)))
    certificates, _ = _certificates(journal)
    assert len(certificates) == 2
    assert {c["direction"] for c in certificates} == {IP_TO_CPU_TO_IP,
                                                      CPU_TO_IP_TO_CPU}
    assert {c["status"] for c in certificates} == {"certified"}
    assert len({c["certificate_id"] for c in certificates}) == 2


@pytest.mark.parametrize("hops,builder", ((IP_HOPS, _ip_journal),
                                          (CPU_HOPS, _cpu_journal)))
def test_every_required_hop_is_mandatory(hops, builder):
    for hop in hops[1:]:
        certificates, _ = _certificates(builder().drop(hop))
        assert len(certificates) == 1, hop
        certificate = certificates[0]
        assert certificate["status"] == "incomplete", hop
        assert hop in certificate["missing_hops"], hop
        _assert_hop_partition(certificate, hops)


@pytest.mark.parametrize("builder,hop", (
    (_ip_journal, "isr_padin_mmio_acceptance"),
    (_ip_journal, "isr_padin_mmio_delivery"),
    (_ip_journal, "isr_padin_data_response"),
    (_ip_journal, "isr_padin_retirement"),
    (_cpu_journal, "mmio_write_acceptance"),
    (_cpu_journal, "gpio_a_target_receipt"),
    (_cpu_journal, "gpio_a_register_commit"),
    (_cpu_journal, "mmio_write_delivery"),
    (_cpu_journal, "mmio_write_data_response"),
    (_cpu_journal, "retired_target_delivery"),
))
def test_missing_hop_is_reported_as_the_first_gap(builder, hop):
    certificates, _ = _certificates(builder().drop(hop))
    assert len(certificates) == 1
    certificate = certificates[0]
    assert certificate["status"] == "incomplete"
    assert certificate["missing_hops"][0] == hop


def test_deleting_the_admission_yields_no_certificate_at_all():
    for builder, name in ((_ip_journal, "pin8_admission"),
                          (_cpu_journal, "instruction_admission")):
        certificates, consumer = _certificates(builder().drop(name))
        assert certificates == []
        assert consumer.pending_count == 0


@pytest.mark.parametrize("fault", (
    "ip_wrong_trigger_id", "ip_wrong_admission_provenance",
    "ip_read_origin_other_admission", "ip_read_value_zero",
    "ip_read_bit_value_boolean", "ip_read_access_mismatch",
    "ip_delivery_access_mismatch", "ip_acceptance_write_flag",
    "ip_acceptance_transaction_mismatch", "ip_response_transaction_mismatch",
    "ip_retirement_wrong_delivery", "ip_retirement_before_take",
    "cpu_writer_refs_other_action", "cpu_writer_kind_initial_image",
    "cpu_write_value_mismatch", "cpu_delivery_not_a_write",
    "cpu_origin_other_admission", "cpu_source_unknown_origin",
    "cpu_commit_observation_mismatch", "cpu_commit_register_mismatch",
    "cpu_fetch_address_string", "cpu_retire_trap", "cpu_retire_intr",
    "cpu_match_insn_mismatch", "cpu_beat_write_zero",
))
def test_tampered_identity_or_value_never_certifies(fault):
    if fault.startswith("ip_"):
        journal = _ip_journal()
        if fault == "ip_wrong_trigger_id":
            journal.mutate("cpu_irq_taken", source_trigger={
                "trigger_id": "gpio_b:0:trigger:9", "trigger_event_id": 1,
                "observation_event_id": 1, "sample_event_id": 1})
        elif fault == "ip_wrong_admission_provenance":
            journal.mutate("pin8_injection", provenance=_provenance(
                1, origin="known", admissions=["0" * 64]))
        elif fault == "ip_read_origin_other_admission":
            journal.edit("isr_padin_register_read", lambda event: {
                **event, "bit_resources": [
                    {**bit, "origin_refs": [_pin8_admission(6).document()]}
                    if bit["bit"] == 8 else bit
                    for bit in event["bit_resources"]]})
        elif fault == "ip_read_value_zero":
            journal.edit("isr_padin_register_read", lambda event: {
                **event, "bit_resources": [
                    {**bit, "value": 0} if bit["bit"] == 8 else bit
                    for bit in event["bit_resources"]]})
        elif fault == "ip_read_bit_value_boolean":
            journal.edit("isr_padin_register_read", lambda event: {
                **event, "bit_resources": [
                    {**bit, "value": True} if bit["bit"] == 8 else bit
                    for bit in event["bit_resources"]]})
        elif fault == "ip_read_access_mismatch":
            journal.mutate("isr_padin_register_read",
                           access_id="gpio-access:gpio_b:0:9")
        elif fault == "ip_delivery_access_mismatch":
            journal.mutate("isr_padin_mmio_delivery",
                           target_access_id="gpio-access:gpio_b:0:9")
        elif fault == "ip_acceptance_write_flag":
            journal.mutate("isr_padin_mmio_acceptance", write=True)
        elif fault == "ip_acceptance_transaction_mismatch":
            journal.mutate("isr_padin_data_acceptance",
                           transaction=_transaction(12))
        elif fault == "ip_response_transaction_mismatch":
            journal.mutate("isr_padin_data_response",
                           transaction=_transaction(12))
        elif fault == "ip_retirement_wrong_delivery":
            journal.mutate("isr_padin_retirement",
                           delivery_event_id="@isr_padin_mmio_acceptance")
        else:
            journal.mutate("isr_padin_retirement",
                           retirement_event_id="@isr_padin_data_response")
    else:
        journal = _cpu_journal()
        if fault == "cpu_writer_refs_other_action":
            journal.mutate("instruction_retirement_match",
                           source_refs=["other:action"])
        elif fault == "cpu_writer_kind_initial_image":
            journal.edit("instruction_retirement_match", lambda event: {
                **event, "byte_cells": [
                    {**cell, "writer_kinds": ["INITIAL_IMAGE"] * 4}
                    for cell in event["byte_cells"]]})
        elif fault == "cpu_write_value_mismatch":
            journal.mutate("mmio_write_delivery", write_value=1)
        elif fault == "cpu_delivery_not_a_write":
            journal.mutate("mmio_write_delivery", write=False)
        elif fault == "cpu_origin_other_admission":
            journal.mutate("retired_target_delivery",
                           registered_origins=[_cpu_admission(7).document()])
        elif fault == "cpu_source_unknown_origin":
            journal.mutate("instruction_source", provenance=_provenance(1))
        elif fault == "cpu_commit_observation_mismatch":
            journal.mutate("gpio_a_register_commit",
                           observation_event_id="@instruction_fetch")
        elif fault == "cpu_commit_register_mismatch":
            journal.mutate("gpio_a_register_commit", register="dir")
        elif fault == "cpu_fetch_address_string":
            journal.mutate("instruction_fetch", address=str(0x11010))
        elif fault == "cpu_retire_trap":
            journal.mutate("instruction_retirement", trap=1)
        elif fault == "cpu_retire_intr":
            journal.mutate("instruction_retirement", intr=1)
        elif fault == "cpu_match_insn_mismatch":
            journal.mutate("instruction_retirement_match", insn=1)
        else:
            journal.edit("instruction_retirement_match", lambda event: {
                **event, "data_beats": [
                    {**beat, "write": 0} for beat in event["data_beats"]]})
    certificates, _ = _certificates(journal)
    assert certificates, fault
    assert all(c["status"] != "certified" for c in certificates), fault


def test_reset_barrier_invalidates_pending_candidate():
    for builder, hop in ((_ip_journal, "isr_padin_retirement"),
                         (_cpu_journal, "retired_target_delivery")):
        journal = builder()
        journal.insert_before(hop, {"kind": "reset_barrier"})
        certificates, _ = _certificates(journal)
        assert len(certificates) == 1
        assert certificates[0]["status"] == "incomplete"
        assert certificates[0]["missing_hops"]
        assert certificates[0]["completed_event_id"] == \
            journal.ids[hop] - 1


def test_max_event_gap_expiry_invalidates_candidate():
    for builder in (_ip_journal, _cpu_journal):
        assert _certificates(builder())[0][0]["status"] == "certified"
        certificates, _ = _certificates(builder(), max_event_gap=6)
        assert len(certificates) == 1
        assert certificates[0]["status"] == "incomplete"
        assert certificates[0]["missing_hops"]


def test_max_pending_eviction_never_restores_credit():
    stale = _cpu_admission(1)
    other = _cpu_admission(2)
    evicted = _Journal()
    evicted.add("stale_admission", {
        "kind": "source_admission", "admission": stale.document(),
        "provenance": _provenance(1, origin="known",
                                  admissions=[stale.admission_id])})
    evicted.append_journal(_cpu_journal(case_index=2, admission=other,
                                        tag="other_"))
    evicted.add("duplicate_admission", {
        "kind": "source_admission", "admission": stale.document(),
        "provenance": _provenance(1, origin="known",
                                  admissions=[stale.admission_id])})
    rest = _cpu_journal(case_index=1, admission=stale, tag="stale_")
    rest.without("instruction_admission")
    evicted.append_journal(rest)
    consumer = ChainCertificates(max_pending=1)
    certificates = []
    for event in evicted.events:
        certificates.extend(consumer.ingest((event,)))
        assert consumer.pending_count <= 1
    certificates.extend(consumer.flush())
    by_admission = {}
    for certificate in certificates:
        by_admission.setdefault(certificate["source_admission_id"],
                                []).append(certificate)
    assert sorted(by_admission) == sorted([stale.admission_id,
                                           other.admission_id])
    # The evicted admission keeps its single incomplete settlement forever.
    assert len(by_admission[stale.admission_id]) == 1
    evicted_stale = by_admission[stale.admission_id][0]
    assert evicted_stale["status"] == "incomplete"
    assert [hop["hop_id"] for hop in evicted_stale["hops"]] == [
        "instruction_admission"]
    # Settled by the next admission event, which evicted it.
    assert evicted_stale["completed_event_id"] == \
        evicted.ids["stale_admission"] + 1
    assert by_admission[other.admission_id][0]["status"] == "certified"


def test_non_contiguous_or_malformed_event_ids_raise():
    journal = _cpu_journal()
    damaged = (journal.events[1:],
               [journal.events[0], journal.events[0]] + journal.events[1:],
               [{**journal.events[0], "event_id": True}] + journal.events[1:],
               [{"kind": "state_dependency"}] + journal.events[1:])
    for events in damaged:
        with pytest.raises(ValueError):
            ChainCertificates().ingest(events)


def test_pending_count_is_bounded_on_long_stream():
    consumer = ChainCertificates(max_pending=8)
    journal = _cpu_journal()
    events = list(journal.events) + [
        {"kind": "state_dependency", "event_id": index}
        for index in range(len(journal.events) + 1, 50001)]
    produced = 0
    for event in events:
        produced += len(consumer.ingest((event,)))
        assert consumer.pending_count <= 8
    produced += len(consumer.flush())
    assert produced == 1
    assert consumer.pending_count == 0


def test_unfinished_candidate_flushes_as_incomplete_with_certified_prefix():
    admission = _cpu_admission(1)
    consumer = ChainCertificates(max_pending=4)
    events = [{"kind": "source_admission", "admission": admission.document(),
               "provenance": _provenance(1, origin="known",
                                         admissions=[admission.admission_id])},
              {"kind": "instruction_source", "component": "cpu",
               "source_event_id": admission.action_id, "address": 0x11004,
               "data_hex": "23a62000", "generation": 0,
               "producer_event_id": 1,
               "provenance": _provenance(1, origin="known",
                                         admissions=[admission.admission_id])}]
    events.extend({"kind": "state_dependency"} for _ in range(1000))
    for index, event in enumerate(events, start=1):
        consumer.ingest(({**event, "event_id": index},))
        assert consumer.pending_count <= 4
    certificates = consumer.flush()
    assert len(certificates) == 1
    certificate = certificates[0]
    assert certificate["status"] == "incomplete"
    assert [hop["hop_id"] for hop in certificate["hops"]] == [
        "instruction_admission", "instruction_source"]
    assert certificate["missing_hops"] == list(CPU_HOPS[2:])
    assert certificate["completed_event_id"] == len(events)
    assert certificate["endpoint_case_id"] == "case-1"
    assert consumer.flush() == ()


def _stream_fixture(consumer):
    """Stream the fixture line by line; never hold the event stream in memory."""
    admissions = []
    produced = []
    peak = 0
    with FIXTURE.open() as handle:
        for line in handle:
            event = json.loads(line)
            if event.get("kind") == "source_admission":
                admission = event["admission"]
                if admission.get("role") == "fuzz_source":
                    admissions.append(admission["admission_id"])
            produced.extend(consumer.ingest((event,)))
            peak = max(peak, consumer.pending_count)
    produced.extend(consumer.flush())
    return admissions, produced, peak


def test_real_fixture_certificate_counts_and_missing_hops():
    assert FIXTURE.is_file(), FIXTURE
    consumer = ChainCertificates()
    admissions, certificates, peak = _stream_fixture(consumer)
    assert len(admissions) == 25
    assert len(set(admissions)) == 25
    assert consumer.pending_count == 0
    assert peak <= consumer.max_pending
    # Exactly one certificate per fuzz source admission: never more, never less.
    assert len(certificates) == len(admissions)
    by_id = {c["source_admission_id"]: c for c in certificates}
    assert sorted(by_id) == sorted(admissions)
    certified = [c for c in certificates if c["status"] == "certified"]
    incomplete = [c for c in certificates if c["status"] == "incomplete"]
    # Manually audited against the raw journal (see the next test): exactly the
    # five pin8 admissions whose native IRQ reached cpu_irq_taken and whose ISR
    # PADIN read names the admission document on bit 8 certify, and exactly two
    # admitted instructions own a known-origin retired GPIO A PADOUT write.
    assert [c["direction"] for c in certified].count(IP_TO_CPU_TO_IP) == 5
    assert [c["direction"] for c in certified].count(CPU_TO_IP_TO_CPU) == 2
    assert len(incomplete) == 18
    assert sorted(c["source_case_index"] for c in certified) == [1, 4, 6, 10, 16,
                                                                20, 22]
    for certificate in incomplete:
        hops = IP_HOPS if certificate["direction"] == IP_TO_CPU_TO_IP \
            else CPU_HOPS
        _assert_hop_partition(certificate, hops)
    # Real gaps. Eight pin-8 admissions never had a native GPIO B IRQ whose
    # cause names them, so their certified prefix stops at the admission hop.
    # Ten admitted instructions retire only from retirements that carry either
    # no data beat at all or a read beat (write=0), so no GPIO A PADOUT write
    # is ever exactly joined to them and the prefix stops after the source hop.
    ip_incomplete = [c for c in incomplete
                     if c["direction"] == IP_TO_CPU_TO_IP]
    cpu_incomplete = [c for c in incomplete
                      if c["direction"] == CPU_TO_IP_TO_CPU]
    assert len(ip_incomplete) == 8
    assert len(cpu_incomplete) == 10
    for certificate in ip_incomplete:
        assert certificate["missing_hops"][0] == "pin8_injection"
        assert [hop["hop_id"] for hop in certificate["hops"]] == [
            "pin8_admission"]
    for certificate in cpu_incomplete:
        assert certificate["missing_hops"][0] == "instruction_fetch"
        assert [hop["hop_id"] for hop in certificate["hops"]] == [
            "instruction_admission", "instruction_source"]


def test_real_fixture_certified_hops_match_raw_journal_fields():
    """Re-read the fixture and check every certified hop field by field.

    Manual audit conclusion for the two spot-checked certificates (event IDs
    read back from the raw journal in this test):

    * pin8 case ``online-4-f13d49307cfb514a7489f1b1``: admission 6349 ->
      injection 6350 -> segment 6390 / applied 6391 / sync0 6392 / sync1 6434
      -> trigger 6435 (``causes[0].current_sample.origin_refs == [admission]``)
      -> observation 6475 -> cpu_irq_input 6524 -> cpu_irq_taken 6525 ->
      MMIO acceptance 7312 (gpio_b offset 8 = PADIN, write false, transaction
      sequence 11) -> receipt 7347 / access 7351 -> register read 7353 whose
      bit-8 resource has ``origin_refs == [admission]`` and value 1 -> delivery
      7360 -> data response 7379 -> retired delivery 7416 (``linked_raw``,
      retirement 7415).  Every hop field equals the raw event field.
    * instruction case ``online-1-3343cb2bebd72e5c1d75fb8a``: admission 3157 ->
      instruction source 3159 (bytes [69636, 69652)) -> fetch 3389 at 69648 with
      rdata 2139683 -> MMIO acceptance 3454 (gpio_a offset 12 = PADOUT, write
      214085638) -> data acceptance 3455 -> receipt 3464 / access 3468 ->
      register commit 3470 (``out``, observation 3468) -> delivery 3477 ->
      data response 3517 -> retirement 3549 (insn 2139683, mem_addr
      1073745932) -> retirement match 3550 -> known-origin retired delivery
      3551.  Every hop field equals the raw event field.
    """
    consumer = ChainCertificates()
    _, certificates, _ = _stream_fixture(consumer)
    certified = [c for c in certificates if c["status"] == "certified"]
    assert len(certified) == 7
    wanted = set()
    for certificate in certified:
        wanted.update(hop["event_id"] for hop in certificate["hops"])
    raw = {}
    admission_documents = {}
    with FIXTURE.open() as handle:
        for line in handle:
            event = json.loads(line)
            if event.get("event_id") in wanted:
                raw[event["event_id"]] = event
            if event.get("kind") == "source_admission":
                admission_documents[event["admission"]["admission_id"]] = \
                    event["admission"]
    assert set(raw) == wanted

    def hop_of(certificate, name):
        return next(hop for hop in certificate["hops"] if hop["hop_id"] == name)

    ip = next(c for c in certified if c["direction"] == IP_TO_CPU_TO_IP)
    origin = admission_documents[ip["source_admission_id"]]
    trigger = raw[hop_of(ip, "gpio_b_native_irq_trigger")["event_id"]]
    assert trigger["kind"] == "gpio_irq_trigger"
    assert trigger["component"] == "gpio_b"
    assert trigger["mask"] == 1 << 8
    assert trigger["causes"][0]["current_sample"]["origin_refs"] == [origin]
    assert raw[hop_of(ip, "pin8_admission")["event_id"]]["admission"] == origin
    taken = raw[hop_of(ip, "cpu_irq_taken")["event_id"]]
    assert taken["kind"] == "cpu_irq_taken"
    assert taken["source_trigger"]["trigger_id"] == trigger["trigger_id"]
    assert taken["source_trigger"]["trigger_event_id"] == trigger["event_id"]
    assert taken["source_trigger"]["observation_event_id"] == \
        trigger["observation_event_id"]
    read = raw[hop_of(ip, "isr_padin_register_read")["event_id"]]
    assert read["kind"] == "gpio_register_read"
    assert read["register"] == "padin_latch"
    assert read["component"] == "gpio_b"
    bit = next(b for b in read["bit_resources"] if b["bit"] == 8)
    assert bit["origin_status"] == "known"
    assert bit["origin_refs"] == [origin]
    assert bit["value"] == 1
    acceptance = raw[hop_of(ip, "isr_padin_mmio_acceptance")["event_id"]]
    delivery = raw[hop_of(ip, "isr_padin_mmio_delivery")["event_id"]]
    assert (acceptance["device_id"], acceptance["offset"],
            acceptance["write"]) == ("gpio_b", 8, False)
    assert delivery["target_access_id"] == read["access_id"]
    assert delivery["source_transaction"] == acceptance["source_transaction"]
    assert raw[hop_of(ip, "isr_padin_retirement")["event_id"]][
        "retirement_event_id"] == hop_of(ip, "isr_padin_retirement")["event_id"] \
        - 1
    assert [hop["event_id"] for hop in ip["hops"]] == sorted(
        hop["event_id"] for hop in ip["hops"])
    assert ip["completed_event_id"] > taken["event_id"]

    cpu = next(c for c in certified if c["direction"] == CPU_TO_IP_TO_CPU)
    cpu_origin = admission_documents[cpu["source_admission_id"]]
    source = raw[hop_of(cpu, "instruction_source")["event_id"]]
    assert source["kind"] == "instruction_source"
    assert source["source_event_id"] == cpu["source_action_id"]
    assert source["provenance"]["origin_admission_ids"] == [
        cpu["source_admission_id"]]
    fetch = raw[hop_of(cpu, "instruction_fetch")["event_id"]]
    retire = raw[hop_of(cpu, "instruction_retirement")["event_id"]]
    match = raw[hop_of(cpu, "instruction_retirement_match")["event_id"]]
    assert match["instruction_origin_status"] == "typed_writer_refs"
    assert match["source_refs"] == [cpu["source_action_id"]]
    assert match["instruction_responses"][0]["event_id"] == fetch["event_id"]
    assert fetch["rdata"] == retire["insn"]
    assert source["address"] <= fetch["address"] < source["address"] + \
        len(source["data_hex"]) // 2
    assert match["producer_event_id"] == retire["event_id"]
    assert match["order"] == retire["order"]
    commit = raw[hop_of(cpu, "gpio_a_register_commit")["event_id"]]
    access = raw[hop_of(cpu, "gpio_a_target_access")["event_id"]]
    assert commit["register"] == "out"
    assert commit["observation_event_id"] == access["event_id"]
    assert commit["write_value"] == access["wdata"] == retire["mem_wdata"]
    assert commit["decoded_offset"] == access["decoded_offset"]
    link = raw[hop_of(cpu, "retired_target_delivery")["event_id"]]
    assert link["kind"] == "cpu_retired_transaction_target_delivery"
    assert link["status"] == "linked_raw"
    assert link["registered_origin_status"] == "known"
    assert link["registered_origins"] == [cpu_origin]
    assert link["source_refs"] == [cpu["source_action_id"]]
    assert link["retirement_event_id"] == match["event_id"]
    assert link["delivery_event_id"] == hop_of(
        cpu, "mmio_write_delivery")["event_id"]
    consumer_spec = link["consumer_resource"]
    assert (consumer_spec["device_id"], consumer_spec["offset"],
            consumer_spec["write"]) == ("gpio_a", 12, True)
    assert consumer_spec["write_value"] == commit["write_value"]
    assert [hop["event_id"] for hop in cpu["hops"]] == sorted(
        hop["event_id"] for hop in cpu["hops"])
