"""Unified P5 controlled fault family: calibration-only checker-input faults.

Every case here works on synthetic observations that mirror saved real RTL
event shapes (field names taken from
``runs/current-dataflow-p4-xori-certified-20261007-online/online_final_trace.json``).
No RTL is built, started or replayed by this file.
"""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path

from myfuzz.scenario.ibex_pulp_online_checker import IbexPulpOnlineChecker
from myfuzz.scenario.p5_fault_family import (
    FAULT_SCHEMA_VERSION,
    FINDING_SCHEMA_VERSION,
    REPLAY_SCHEMA_VERSION,
    ControlledFaultCalibrationError,
    ControlledFaultConfigError,
    ControlledFaultFamily,
    controlled_fault_checker,
)
from myfuzz.scenario.replay import ScenarioTrace
from myfuzz.scenario.session_runtime import OnlineCaseReceipt, _checker_identity


def receipt(case_id, events):
    return OnlineCaseReceipt(case_id, 0, len(events), tuple(events), {}, {}, "running")


def canonical_sha256(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")).hexdigest()


def container_ids(value, out):
    """Collect object identities so an in-place rewrite cannot hide."""
    if isinstance(value, dict):
        out.append(id(value))
        for item in value.values():
            container_ids(item, out)
    elif isinstance(value, (list, tuple)):
        out.append(id(value))
        for item in value:
            container_ids(item, out)
    return out


def transaction(sequence):
    return {"execution_id": "local-execution",
            "testcase_id": "ibex-dual-source-stream",
            "source_component": "cpu", "source_epoch": 0,
            "channel_id": "data", "source_sequence": sequence}


def replace_events(events, event_id, **fields):
    return tuple({**event, **fields} if event.get("event_id") == event_id else event
                 for event in events)


def drop_events(events, *event_ids):
    return tuple(event for event in events if event.get("event_id") not in event_ids)


# --- one scenario per fault variant -----------------------------------------
# Each scenario returns (case_id, events, fault entry, expected findings,
# negative events that must not witness the fault).

def irq_level_scenario():
    events = (
        {"event_id": 1, "kind": "source_admission",
         "admission": {"admission_id": "admission-4", "case_id": "case-irq"}},
        {"event_id": 2, "kind": "gpio_irq_trigger", "component": "gpio_b",
         "local_tick": 12, "causes": [{"bit": 8}]},
        {"event_id": 3, "component": "gpio_b", "local_tick": 12,
         "inputs": {"gpio_in": 0},
         "outputs": {"irq": 1, "interrupt": 1, "gpio_in_sync": 0},
         "provenance": {"origin_status": "known",
                        "origin_admission_ids": ["admission-4"]}},
        {"event_id": 4, "kind": "source_start", "source_tick": 12,
         "source": ["gpio_b", "irq"], "target": ["cpu", "irq"],
         "provenance": {"origin_status": "known",
                        "origin_admission_ids": ["admission-4"]}},
        {"event_id": 5, "component": "cpu", "inputs": {"irq": 1}, "outputs": {}},
    )
    entry = {"kind": "wrong_irq", "variant": "observation_irq_level",
             "checker": "ibex_pulp_online",
             "expected_finding": "gpio_b_irq_source_mismatch",
             "operation": "rewrite", "selector": {},
             "mutation": {"field": "outputs.irq", "replacement": 0}}
    return ("case-irq", events, entry, ("gpio_b_irq_source_mismatch",),
            drop_events(events, 3))


def cpu_irq_bit_scenario():
    events = (
        {"event_id": 10, "kind": "pulse_start", "source": ["gpio_b", "irq"],
         "target": ["cpu", "irq"], "width": 1, "end_cpu_tick_exclusive": 188},
        {"event_id": 11, "component": "cpu", "local_tick": 184,
         "inputs": {"irq": 1}, "outputs": {}},
        {"event_id": 12, "component": "cpu", "local_tick": 186,
         "inputs": {"irq": 0}, "outputs": {}},
    )
    entry = {"kind": "wrong_irq", "variant": "cpu_irq_input_bit",
             "checker": "ibex_pulp_online",
             "expected_finding": "cpu_irq_pulse_input_mismatch",
             "operation": "rewrite", "selector": {},
             "mutation": {"field": "inputs.irq", "replacement": 0}}
    return ("case-irq-bit", events, entry, ("cpu_irq_pulse_input_mismatch",),
            drop_events(events, 10))


def gpio_b_response_scenario():
    events = (
        {"event_id": 20, "kind": "mmio_delivery", "component": "cpu",
         "device_id": "gpio_b", "offset": 8, "write": False,
         "read_value": 0x5a, "source_transaction": transaction(7)},
        {"event_id": 21, "component": "cpu", "local_tick": 9,
         "inputs": {"irq": 0},
         "outputs": {"data_rsp_consumed": 1, "data_rsp_source_epoch": 0,
                     "data_rsp_source_sequence": 7, "data_rsp_rdata": 0x5a}},
    )
    entry = {"kind": "wrong_read_data", "variant": "cpu_response_data",
             "checker": "ibex_pulp_online",
             "expected_finding": "cpu_gpio_b_padin_response_mismatch",
             "operation": "rewrite", "selector": {},
             "mutation": {"field": "outputs.data_rsp_rdata", "replacement": 0x5b}}
    return ("case-read", events, entry,
            ("cpu_gpio_b_padin_response_mismatch",), drop_events(events, 21))


def gpio_b_delivery_read_scenario():
    case_id, events, entry, _expected, negative = gpio_b_response_scenario()
    entry = {**entry, "variant": "delivery_read_data",
             "mutation": {"field": "read_value", "replacement": 0x5b}}
    return (case_id, events, entry,
            ("cpu_gpio_b_padin_response_mismatch",), negative)


def uart_response_scenario():
    events = (
        {"event_id": 30, "kind": "mmio_delivery", "component": "cpu",
         "device_id": "uart", "offset": 0x18, "write": False,
         "read_value": 0x5a,
         "source_transaction": {"source_epoch": 0, "source_sequence": 5}},
        {"event_id": 31, "component": "cpu", "kind": None,
         "outputs": {"data_rsp_consumed": 1, "data_rsp_source_epoch": 0,
                     "data_rsp_source_sequence": 5, "data_rsp_rdata": 0x5a}},
    )
    entry = {"kind": "wrong_read_data", "variant": "uart_cpu_response_data",
             "checker": "ibex_uart_online",
             "expected_finding": "cpu_uart_rxdata_response_mismatch",
             "operation": "rewrite", "selector": {},
             "mutation": {"field": "outputs.data_rsp_rdata", "replacement": 0x5b}}
    return ("case-uart", events, entry,
            ("cpu_uart_rxdata_response_mismatch",), drop_events(events, 31))


def pulse_resubmission_scenario():
    events = (
        {"event_id": 40, "kind": "pulse_start", "source": ["gpio_b", "irq"],
         "target": ["cpu", "irq"], "width": 1},
        {"event_id": 41, "component": "cpu", "inputs": {"irq": 1},
         "outputs": {}},
        {"event_id": 42, "component": "cpu", "inputs": {"irq": 0},
         "outputs": {}},
    )
    entry = {"kind": "duplicate_submission", "variant": "irq_pulse_resubmission",
             "checker": "ibex_pulp_online",
             "expected_finding": "cpu_irq_pulse_input_mismatch",
             "operation": "duplicate", "selector": {},
             "mutation": {"field": "pulse_start", "replacement": None}}
    return ("case-pulse", events, entry, ("cpu_irq_pulse_input_mismatch",),
            drop_events(events, 42))


def delivery_replay_scenario():
    case_id, events, entry, _expected, negative = gpio_b_response_scenario()
    entry = {"kind": "duplicate_submission", "variant": "mmio_delivery_replay",
             "checker": "ibex_pulp_online",
             "expected_finding": "cpu_gpio_b_padin_response_mismatch",
             "operation": "duplicate", "selector": {},
             "mutation": {"field": "read_value", "replacement": 0x5b}}
    return (case_id, events, entry,
            ("cpu_gpio_b_padin_response_mismatch",), negative)


def binding_delivery_scenario():
    events = (
        {"event_id": 50, "component": "gpio_a", "local_tick": 200,
         "outputs": {"gpio_out": 0x06, "gpio_dir": 0xff}},
        {"event_id": 51, "kind": "dataflow_delivery", "producer_event_id": 50,
         "source": ["gpio_a", "gpio_out"], "source_bit_offset": 0,
         "target": ["gpio_b", "gpio_in"], "target_bit_offset": 0,
         "width": 8, "value": 0x06},
        {"event_id": 52, "component": "gpio_b", "local_tick": 201,
         "inputs": {"gpio_in": 0x06}, "outputs": {"irq": 0}},
    )
    entry = {"kind": "broken_binding_value", "variant": "delivery_value",
             "checker": "ibex_pulp_online",
             "expected_finding": "gpio_a_to_b_delivery_mismatch",
             "operation": "rewrite", "selector": {},
             "mutation": {"field": "value", "replacement": 0x07}}
    return ("case-binding", events, entry,
            ("gpio_a_to_b_delivery_mismatch", "gpio_b_bound_input_mismatch"),
            drop_events(events, 50))


def binding_input_scenario():
    case_id, events, entry, _expected, negative = binding_delivery_scenario()
    entry = {**entry, "variant": "bound_input_value",
             "expected_finding": "gpio_b_bound_input_mismatch",
             "mutation": {"field": "inputs.gpio_in", "replacement": 0x07}}
    return (case_id, events, entry, ("gpio_b_bound_input_mismatch",),
            drop_events(events, 51))


SCENARIOS = (irq_level_scenario, cpu_irq_bit_scenario, gpio_b_response_scenario,
             gpio_b_delivery_read_scenario, uart_response_scenario,
             pulse_resubmission_scenario, delivery_replay_scenario,
             binding_delivery_scenario, binding_input_scenario)


def document_for(*entries):
    return {"schema_version": FAULT_SCHEMA_VERSION, "faults": list(entries)}


def valid_entry(**overrides):
    entry = {"kind": "wrong_irq", "variant": "observation_irq_level",
             "checker": "ibex_pulp_online",
             "expected_finding": "gpio_b_irq_source_mismatch",
             "operation": "rewrite",
             "selector": {"case_id": "case-irq"},
             "mutation": {"field": "outputs.irq", "replacement": 0}}
    entry.update(overrides)
    return entry


class FaultVariantTest(unittest.TestCase):
    def test_each_variant_reaches_its_declared_invariant(self):
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario.__name__):
                case_id, events, entry, expected, _negative = scenario()
                family = ControlledFaultFamily.from_document(document_for(entry))
                run = family.inject(receipt(case_id, events))
                self.assertEqual(run.violations, expected)
                self.assertEqual(run.baseline_findings, ())
                self.assertEqual(run.injected_findings, expected)
                self.assertEqual(len(run.observations), 1)
                observation = run.observations[0]
                self.assertEqual(observation.checker_findings, expected)
                finding = observation.finding
                self.assertEqual(finding["schema_version"], FINDING_SCHEMA_VERSION)
                self.assertEqual(finding["detected_by"], entry["expected_finding"])
                self.assertIs(finding["calibration_only"], True)
                self.assertEqual(finding["observation_boundary"],
                                 "checker_input_copy")
                self.assertEqual(finding["case_id"], case_id)
                self.assertTrue(finding["finding_id"].startswith(
                    "p5_controlled_fault_" + entry["kind"] + "_"))
                self.assertEqual(finding["fault_id"], entry.get("fault_id", family.document()["faults"][0]["fault_id"]))
                chain = finding["source_chain"]
                self.assertEqual(chain["mutated_field"], entry["mutation"]["field"])
                self.assertIsInstance(chain["original_value"], int)
                self.assertNotEqual(chain["original_value"],
                                    chain["injected_value"])
                self.assertNotEqual(finding["raw_observation_sha256"],
                                    finding["checker_input_sha256"])
                self.assertEqual(finding["raw_observation_sha256"],
                                 canonical_sha256(list(events)))
                self.assertTrue(chain["related_event_ids"])
                self.assertIn("observation_event_id", chain)

    def test_each_variant_leaves_the_original_events_untouched(self):
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario.__name__):
                case_id, events, entry, _expected, _negative = scenario()
                before_bytes = canonical_sha256(list(events))
                before_ids = container_ids(events, [])
                before_copy = copy.deepcopy(events)
                before_tuple = events
                family = ControlledFaultFamily.from_document(document_for(entry))
                family.inject(receipt(case_id, events))
                self.assertIs(events, before_tuple)
                self.assertEqual(canonical_sha256(list(events)), before_bytes)
                self.assertEqual(events, before_copy)
                self.assertEqual(container_ids(events, []), before_ids)
                for index, event in enumerate(events):
                    self.assertIs(event, before_tuple[index])
                    self.assertEqual(set(event), set(before_copy[index]))

    def test_unwitnessed_observation_injects_nothing(self):
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario.__name__):
                case_id, _events, entry, _expected, negative = scenario()
                family = ControlledFaultFamily.from_document(document_for(entry))
                run = family.inject(receipt(case_id, negative))
                self.assertEqual(run.violations, ())
                self.assertEqual(run.baseline_findings, ())
                self.assertEqual(run.observations, ())
                self.assertEqual(family.finding_documents, ())

    def test_natural_findings_are_baseline_not_calibration(self):
        case_id, events, entry, _expected, _negative = irq_level_scenario()
        natural = replace_events(events, 3,
                                 outputs={"irq": 0, "interrupt": 0,
                                          "gpio_in_sync": 0})
        family = ControlledFaultFamily.from_document(document_for(entry))
        run = family.inject(receipt(case_id, natural))
        self.assertEqual(run.violations, ("gpio_b_irq_source_mismatch",))
        self.assertEqual(run.baseline_findings, ("gpio_b_irq_source_mismatch",))
        self.assertEqual(run.injected_findings, ())
        self.assertEqual(run.observations, ())
        self.assertEqual(len(run.skipped), 1)
        self.assertEqual(
            run.skipped[0]["reason"],
            "unperturbed_observation_already_reports_expected_finding")
        self.assertEqual(family.finding_documents, ())


class FaultFamilyConfigurationTest(unittest.TestCase):
    def test_document_round_trip_and_checker_identity_are_stable(self):
        case_id, events, entry, expected, _negative = irq_level_scenario()
        family = ControlledFaultFamily.from_document(document_for(entry))
        document = family.document()
        self.assertEqual(document["schema_version"], FAULT_SCHEMA_VERSION)
        self.assertEqual(len(document["faults"]), 1)
        self.assertRegex(document["faults"][0]["fault_id"],
                         r"^p5_controlled_fault_wrong_irq_[0-9a-f]{16}$")
        again = ControlledFaultFamily.from_document(document)
        self.assertEqual(again.document(), document)
        self.assertEqual(json.dumps(again.document(), sort_keys=True),
                         json.dumps(document, sort_keys=True))
        identity = _checker_identity(family)
        self.assertEqual(identity["config"]["fault_document"], document)
        self.assertEqual(identity["config"]["fault_mode"], FAULT_SCHEMA_VERSION)
        self.assertEqual(family(receipt(case_id, events)), expected)
        self.assertEqual(_checker_identity(family), identity)

    def test_minimal_replay_document_reproduces_identical_findings(self):
        case_id, events, entry, expected, _negative = irq_level_scenario()
        first = ControlledFaultFamily.from_document(document_for(entry))
        first.inject(receipt(case_id, events))
        replay = first.minimal_replay_document()
        self.assertEqual(replay["schema_version"], REPLAY_SCHEMA_VERSION)
        self.assertIs(replay["calibration_only"], True)
        self.assertEqual(replay["findings"][0]["detected_by"],
                         "gpio_b_irq_source_mismatch")
        self.assertEqual(len(replay["findings"]), 1)
        pinned = replay["fault_document"]
        self.assertEqual(pinned["schema_version"], FAULT_SCHEMA_VERSION)
        selector = pinned["faults"][0]["selector"]
        self.assertEqual(selector["case_id"], case_id)
        self.assertEqual(selector["observation_event_id"], 3)
        self.assertEqual(selector["source_start_event_id"], 4)
        self.assertEqual(selector["source_tick"], 12)
        self.assertEqual(selector["original_value"], 1)
        second = ControlledFaultFamily.from_document(pinned)
        third = ControlledFaultFamily.from_document(pinned)
        self.assertEqual(second(receipt(case_id, events)), expected)
        self.assertEqual(third(receipt(case_id, events)), expected)
        self.assertEqual(second.finding_documents, third.finding_documents)
        # The pinned configuration is a different configuration identity, but
        # it reproduces the identical finding identity and source chain.
        self.assertEqual(second.finding_documents[0]["finding_id"],
                         first.finding_documents[0]["finding_id"])
        self.assertEqual(second.finding_documents[0]["source_chain"],
                         first.finding_documents[0]["source_chain"])
        self.assertEqual(second.finding_documents[0]["checker_input_sha256"],
                         first.finding_documents[0]["checker_input_sha256"])
        self.assertEqual(
            json.dumps(second.finding_documents, sort_keys=True),
            json.dumps(third.finding_documents, sort_keys=True))
        self.assertEqual(replay["fault_document_sha256"], canonical_sha256(pinned))
        # Repeating the same configuration on the same observation is stable.
        first_run_again = first.inject(receipt(case_id, events))
        self.assertEqual(first_run_again.violations, expected)
        self.assertEqual(first_run_again.finding_documents,
                         first.finding_documents)

    def test_pinned_replay_refuses_a_changed_observation(self):
        case_id, events, entry, _expected, _negative = irq_level_scenario()
        family = ControlledFaultFamily.from_document(document_for(entry))
        family.inject(receipt(case_id, events))
        pinned = ControlledFaultFamily.from_document(
            family.minimal_replay_document()["fault_document"])
        changed = replace_events(events, 3,
                                 outputs={"irq": 0, "interrupt": 0,
                                          "gpio_in_sync": 0})
        with self.assertRaises(ControlledFaultCalibrationError):
            pinned.inject(receipt(case_id, changed))
        self.assertEqual(pinned.finding_documents, ())

    def test_mutation_that_would_not_change_the_observation_is_refused(self):
        case_id, events, entry, _expected, _negative = irq_level_scenario()
        entry = {**entry, "mutation": {"field": "outputs.irq", "replacement": 1}}
        family = ControlledFaultFamily.from_document(document_for(entry))
        with self.assertRaises(ControlledFaultCalibrationError):
            family.inject(receipt(case_id, events))
        self.assertEqual(family.finding_documents, ())

    def test_perturbation_that_misses_the_invariant_is_refused(self):
        events = (
            {"event_id": 60, "kind": "mmio_delivery", "component": "cpu",
             "device_id": "gpio_b", "offset": 8, "write": False,
             "read_value": 0x5a, "source_transaction": transaction(7)},
            {"event_id": 61, "kind": "reset_barrier", "component": "cpu"},
            {"event_id": 62, "component": "cpu", "local_tick": 9,
             "inputs": {"irq": 0},
             "outputs": {"data_rsp_consumed": 1,
                         "data_rsp_source_epoch": 0,
                         "data_rsp_source_sequence": 7,
                         "data_rsp_rdata": 0x5a}},
        )
        entry = {"kind": "wrong_read_data", "variant": "cpu_response_data",
                 "checker": "ibex_pulp_online",
                 "expected_finding": "cpu_gpio_b_padin_response_mismatch",
                 "operation": "rewrite", "selector": {},
                 "mutation": {"field": "outputs.data_rsp_rdata",
                              "replacement": 0x5b}}
        family = ControlledFaultFamily.from_document(document_for(entry))
        self.assertEqual(
            IbexPulpOnlineChecker()(receipt("case-reset", events)), ())
        with self.assertRaises(ControlledFaultCalibrationError):
            family.inject(receipt("case-reset", events))
        self.assertEqual(family.finding_documents, ())

    def test_duplicate_injection_inserts_one_renumbered_copy(self):
        case_id, events, entry, expected, _negative = pulse_resubmission_scenario()
        family = ControlledFaultFamily.from_document(document_for(entry))
        run = family.inject(receipt(case_id, events))
        self.assertEqual(run.violations, expected)
        perturbed = run.observations[0].perturbed_events
        self.assertEqual([event["event_id"] for event in perturbed], [40, 41, 42, 43])
        self.assertEqual(perturbed[2], {**events[0], "event_id": 42})
        self.assertEqual(perturbed[3], {**events[2], "event_id": 43})
        self.assertEqual(events[2]["event_id"], 42)
        finding = run.observations[0].finding
        self.assertEqual(finding["event_id_shift"], 1)
        self.assertEqual(finding["source_chain"]["inserted_checker_input_event_id"], 42)
        self.assertEqual(finding["source_chain"]["duplicated_event_id"], 40)
        self.assertEqual(
            finding["source_chain"]["related_event_ids"]["insert_before_event_id"],
            42)
        later = ControlledFaultFamily.from_document(document_for(entry))
        later.inject(receipt(case_id, events))
        following = (
            {"event_id": 43, "kind": "pulse_start", "source": ["gpio_b", "irq"],
             "target": ["cpu", "irq"], "width": 1},
            {"event_id": 44, "component": "cpu", "inputs": {"irq": 1},
             "outputs": {}},
        )
        self.assertEqual(later(receipt("case-pulse-next", following)), ())

    def test_offline_trace_checker_adapter_uses_the_same_family(self):
        case_id, events, entry, expected, _negative = gpio_b_response_scenario()
        family = ControlledFaultFamily.from_document(document_for(entry))
        trace = ScenarioTrace(case_id, "running", events, {}, canonical_sha256(list(events)))
        self.assertEqual(family.trace_checker()(trace), expected)
        self.assertEqual(len(family.finding_documents), 1)
        with self.assertRaises(ValueError):
            family.trace_checker()(object())


def chain_value(chain, key):
    """Read a source-chain field, including the nested related event IDs."""
    if key in chain:
        return chain[key]
    return chain["related_event_ids"][key]


REAL_WINDOW_FIXTURE = (Path(__file__).with_name("fixtures")
                       / "p5_fault_family_real_window.json")
REAL_WINDOW_FIXTURE_SHA256 = (
    "272b57e682e1513f5b7576f491ada08462ab8ad39b34d49db43cd190572c7c1e")


def real_windows():
    raw = REAL_WINDOW_FIXTURE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != REAL_WINDOW_FIXTURE_SHA256:
        raise AssertionError("real saved observation window fixture changed")
    document = json.loads(raw)
    if document["source_trace_sha256"] != (
            "f8ae9a898b2916521feab45591da4138f493a4eae221909232beaaf9f9da9d18"):
        raise AssertionError("real saved trace identity changed")
    return {window["window_id"]: window for window in document["windows"]}


def real_receipt(window):
    events = tuple(window["events"])
    return OnlineCaseReceipt(window["case_id"], 0, len(events), events, {},
                             {}, "running")


class RealSavedObservationTest(unittest.TestCase):
    """Calibrate against unmodified events of the saved 2026-10-07 RTL run.

    Only *saved* events are read; no RTL is built, started or replayed.
    """

    def fault(self, entry):
        return ControlledFaultFamily.from_document(document_for(entry))

    def test_saved_windows_have_no_natural_finding(self):
        for window in real_windows().values():
            with self.subTest(window=window["window_id"]):
                self.assertEqual(
                    IbexPulpOnlineChecker()(real_receipt(window)), ())

    def test_saved_rtl_trace_bytes_are_untouched_by_injection(self):
        trace = (Path(__file__).resolve().parents[2] / "runs"
                 / "current-dataflow-p4-xori-certified-20261007-online"
                 / "online_final_trace.json")
        if not trace.is_file():
            self.skipTest("saved real RTL trace is not present")
        before = hashlib.sha256(trace.read_bytes()).hexdigest()
        self.assertEqual(
            before,
            "f8ae9a898b2916521feab45591da4138f493a4eae221909232beaaf9f9da9d18")
        for window in real_windows().values():
            family = self.fault(
                {"kind": "wrong_irq", "variant": "observation_irq_level",
                 "checker": "ibex_pulp_online",
                 "expected_finding": "gpio_b_irq_source_mismatch",
                 "operation": "rewrite", "selector": {},
                 "mutation": {"field": "outputs.irq", "replacement": 0}})
            family(real_receipt(window))
        self.assertEqual(hashlib.sha256(trace.read_bytes()).hexdigest(), before)

    def test_saved_window_calibrates_irq_and_binding_faults(self):
        window = real_windows()["irq_binding_6436_6452"]
        cases = (
            ({"kind": "wrong_irq", "variant": "observation_irq_level",
              "checker": "ibex_pulp_online",
              "expected_finding": "gpio_b_irq_source_mismatch",
              "operation": "rewrite", "selector": {},
              "mutation": {"field": "outputs.irq", "replacement": 0}},
             ("gpio_b_irq_source_mismatch",),
             {"observation_event_id": 6437, "source_start_event_id": 6438,
              "original_value": 1, "injected_value": 0}),
            ({"kind": "broken_binding_value", "variant": "delivery_value",
              "checker": "ibex_pulp_online",
              "expected_finding": "gpio_a_to_b_delivery_mismatch",
              "operation": "rewrite", "selector": {},
              "mutation": {"field": "value", "replacement": 7}},
             ("gpio_a_to_b_delivery_mismatch",),
             {"observation_event_id": 6449, "producer_event_id": 6448,
              "original_value": 6, "injected_value": 7}),
            ({"kind": "broken_binding_value", "variant": "bound_input_value",
              "checker": "ibex_pulp_online",
              "expected_finding": "gpio_b_bound_input_mismatch",
              "operation": "rewrite", "selector": {},
              "mutation": {"field": "inputs.gpio_in", "replacement": 7}},
             ("gpio_b_bound_input_mismatch",),
             {"observation_event_id": 6452, "delivery_event_id": 6449,
              "original_value": 6, "injected_value": 7}),
        )
        for entry, expected, chain_expected in cases:
            with self.subTest(variant=entry["variant"]):
                family = self.fault(entry)
                run = family.inject(real_receipt(window))
                self.assertEqual(run.violations, expected)
                self.assertEqual(run.baseline_findings, ())
                chain = run.observations[0].finding["source_chain"]
                for key, value in chain_expected.items():
                    self.assertEqual(chain_value(chain, key), value)

    def test_saved_window_calibrates_read_data_and_duplicate_faults(self):
        window = real_windows()["padin_read_7356_7365"]
        cases = (
            ({"kind": "wrong_read_data", "variant": "cpu_response_data",
              "checker": "ibex_pulp_online",
              "expected_finding": "cpu_gpio_b_padin_response_mismatch",
              "operation": "rewrite", "selector": {},
              "mutation": {"field": "outputs.data_rsp_rdata",
                           "replacement": 0x107}},
             {"observation_event_id": 7365, "read_event_id": 7356,
              "original_value": 262, "injected_value": 263}),
            ({"kind": "wrong_read_data", "variant": "delivery_read_data",
              "checker": "ibex_pulp_online",
              "expected_finding": "cpu_gpio_b_padin_response_mismatch",
              "operation": "rewrite", "selector": {},
              "mutation": {"field": "read_value", "replacement": 0x107}},
             {"observation_event_id": 7356, "response_event_id": 7365,
              "original_value": 262, "injected_value": 263}),
            ({"kind": "duplicate_submission", "variant": "mmio_delivery_replay",
              "checker": "ibex_pulp_online",
              "expected_finding": "cpu_gpio_b_padin_response_mismatch",
              "operation": "duplicate", "selector": {},
              "mutation": {"field": "read_value", "replacement": 0x107}},
             {"observation_event_id": 7356, "insert_before_event_id": 7365,
              "duplicated_event_id": 7356,
              "inserted_checker_input_event_id": 7365,
              "original_value": 262, "injected_value": 263}),
        )
        for entry, chain_expected in cases:
            with self.subTest(variant=entry["variant"]):
                family = self.fault(entry)
                run = family.inject(real_receipt(window))
                self.assertEqual(
                    run.violations, ("cpu_gpio_b_padin_response_mismatch",))
                self.assertEqual(run.baseline_findings, ())
                finding = run.observations[0].finding
                self.assertEqual(finding["event_id_shift"],
                                 1 if entry["operation"] == "duplicate" else 0)
                for key, value in chain_expected.items():
                    self.assertEqual(chain_value(finding["source_chain"], key),
                                     value)
                self.assertEqual(
                    finding["raw_observation_sha256"],
                    canonical_sha256(list(window["events"])))

    def test_saved_window_minimal_replay_is_stable(self):
        window = real_windows()["padin_read_7356_7365"]
        entry = {"kind": "duplicate_submission",
                 "variant": "mmio_delivery_replay",
                 "checker": "ibex_pulp_online",
                 "expected_finding": "cpu_gpio_b_padin_response_mismatch",
                 "operation": "duplicate", "selector": {},
                 "mutation": {"field": "read_value", "replacement": 0x107}}
        first = self.fault(entry)
        first.inject(real_receipt(window))
        replay = first.minimal_replay_document()
        self.assertEqual(replay["fault_document_sha256"],
                         canonical_sha256(replay["fault_document"]))
        documents = []
        for _ in range(2):
            family = ControlledFaultFamily.from_document(
                replay["fault_document"])
            run = family.inject(real_receipt(window))
            self.assertEqual(
                run.violations, ("cpu_gpio_b_padin_response_mismatch",))
            documents.append(run.finding_documents)
        self.assertEqual(documents[0], documents[1])
        self.assertEqual(documents[0][0]["finding_id"],
                         first.finding_documents[0]["finding_id"])
        self.assertEqual(documents[0][0]["checker_input_sha256"],
                         first.finding_documents[0]["checker_input_sha256"])

    def test_one_document_injects_independent_faults_per_class(self):
        window = real_windows()["irq_binding_6436_6452"]
        entries = (
            {"kind": "wrong_irq", "variant": "observation_irq_level",
             "checker": "ibex_pulp_online",
             "expected_finding": "gpio_b_irq_source_mismatch",
             "operation": "rewrite", "selector": {},
             "mutation": {"field": "outputs.irq", "replacement": 0}},
            {"kind": "broken_binding_value", "variant": "delivery_value",
             "checker": "ibex_pulp_online",
             "expected_finding": "gpio_a_to_b_delivery_mismatch",
             "operation": "rewrite", "selector": {},
             "mutation": {"field": "value", "replacement": 7}},
        )
        family = ControlledFaultFamily.from_faults(entries)
        run = family.inject(real_receipt(window))
        self.assertEqual(run.violations,
                         ("gpio_b_irq_source_mismatch",
                          "gpio_a_to_b_delivery_mismatch"))
        self.assertEqual(len(run.observations), 2)
        self.assertEqual([observation.variant for observation in run.observations],
                         ["observation_irq_level", "delivery_value"])
        replay = family.minimal_replay_document()
        self.assertEqual(len(replay["fault_document"]["faults"]), 2)
        again = ControlledFaultFamily.from_document(replay["fault_document"])
        self.assertEqual(again(real_receipt(window)), run.violations)

    def test_wiring_helper_returns_the_same_checker_callable(self):
        from myfuzz.scenario.p5_fault_family import controlled_fault_checker

        window = real_windows()["irq_binding_6436_6452"]
        entry = valid_entry(selector={})
        checker = controlled_fault_checker(document_for(entry))
        self.assertIsInstance(checker, ControlledFaultFamily)
        self.assertEqual(checker(real_receipt(window)),
                         ("gpio_b_irq_source_mismatch",))
        self.assertEqual(_checker_identity(checker)["config"]["fault_document"],
                         checker.document())


class FaultFamilyWiringTest(unittest.TestCase):
    """The family is injectable at the existing checker call sites.

    These assertions only inspect the public signatures; nothing here builds,
    starts or replays RTL.
    """

    def test_existing_call_sites_accept_a_checker_callable(self):
        import inspect

        from myfuzz.integration.ibex_pulp_online import (
            make_ibex_pulp_online_runtime)
        from myfuzz.integration.ibex_uart_online import (
            make_ibex_uart_online_runtime)
        from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
        from myfuzz.integration.scenario_rfuzz_replay import (
            replay_scenario_rfuzz_continuous)

        call_sites = (
            (make_ibex_pulp_online_runtime, "checker"),
            (make_ibex_uart_online_runtime, "checker"),
            (ScenarioRfuzzExecutor.__init__, "checker"),
            (replay_scenario_rfuzz_continuous, "session_checker"),
        )
        for target, name in call_sites:
            with self.subTest(target=getattr(target, "__qualname__", str(target))):
                self.assertIn(name, inspect.signature(target).parameters)

    def test_family_and_trace_adapter_are_checker_callables(self):
        import inspect

        from myfuzz.scenario.session_runtime import OnlineCaseReceipt

        window = real_windows()["irq_binding_6436_6452"]
        entry = valid_entry(selector={})
        family = controlled_fault_checker(document_for(entry))
        self.assertTrue(callable(family))
        self.assertIsInstance(family, ControlledFaultFamily)
        self.assertTrue(callable(family.trace_checker()))
        self.assertEqual(
            list(inspect.signature(family.inject).parameters), ["receipt"])
        self.assertEqual(
            list(inspect.signature(family.trace_checker()).parameters), ["trace"])
        self.assertEqual(family(real_receipt(window)),
                         ("gpio_b_irq_source_mismatch",))
        self.assertEqual(
            family.trace_checker()(ScenarioTrace(
                window["case_id"], "running", tuple(window["events"]), {},
                canonical_sha256(list(window["events"])))),
            ("gpio_b_irq_source_mismatch",))
        self.assertIsInstance(real_receipt(window), OnlineCaseReceipt)


class FaultFamilyValidationTest(unittest.TestCase):
    def assert_rejected(self, document, message=None):
        with self.assertRaises(ControlledFaultConfigError) as caught:
            ControlledFaultFamily.from_document(document)
        if message is not None:
            self.assertIn(message, str(caught.exception))

    def test_document_rejects_unknown_or_missing_configuration(self):
        self.assert_rejected({"faults": [valid_entry()]}, "schema_version")
        self.assert_rejected({"schema_version": "p5_controlled_fault.v2",
                              "faults": [valid_entry()]}, "schema_version")
        self.assert_rejected(document_for(), "faults")
        self.assert_rejected({"schema_version": FAULT_SCHEMA_VERSION,
                              "faults": [valid_entry()], "extra": 1}, "extra")
        self.assert_rejected(document_for(valid_entry(kind="wrong_irq_v2")),
                             "kind")
        self.assert_rejected(document_for(valid_entry(variant="guess")),
                             "variant")
        self.assert_rejected(document_for({**valid_entry(), "checker": "guess"}),
                             "checker")
        missing = valid_entry()
        del missing["expected_finding"]
        self.assert_rejected(document_for(missing), "expected_finding")
        self.assert_rejected(
            document_for(valid_entry(expected_finding="cpu_irq_pulse_input_mismatch")),
            "expected_finding")
        self.assert_rejected(document_for(valid_entry(operation="delete")),
                             "operation")
        mismatched = valid_entry(operation="duplicate",
                                 mutation={"field": "pulse_start",
                                           "replacement": None})
        self.assert_rejected(document_for(mismatched), "operation")
        self.assert_rejected(document_for({**valid_entry(),
                                           "fault_id": "p5_controlled_fault_wrong_irq_0000000000000000"}),
                             "fault_id")

    def test_document_rejects_illegal_values(self):
        self.assert_rejected(
            document_for(valid_entry(mutation={"field": "outputs.irq",
                                               "replacement": 2})),
            "replacement")
        self.assert_rejected(
            document_for(valid_entry(mutation={"field": "outputs.irq",
                                               "replacement": True})),
            "replacement")
        self.assert_rejected(
            document_for(valid_entry(mutation={"field": "outputs.irq"})),
            "mutation")
        self.assert_rejected(
            document_for(valid_entry(mutation={"field": "inputs.irq",
                                               "replacement": 0})),
            "field")
        self.assert_rejected(document_for(valid_entry(selector={"case": "x"})),
                             "selector")
        self.assert_rejected(
            document_for(valid_entry(selector={"observation_event_id": 3})),
            "case_id")
        self.assert_rejected(
            document_for(valid_entry(selector={"case_id": 4})), "case_id")
        entry = {"kind": "duplicate_submission",
                 "variant": "mmio_delivery_replay",
                 "checker": "ibex_pulp_online",
                 "expected_finding": "cpu_gpio_b_padin_response_mismatch",
                 "operation": "duplicate", "selector": {},
                 "mutation": {"field": "read_value", "replacement": None}}
        self.assert_rejected(document_for(entry), "replacement")
        entry = {"kind": "duplicate_submission",
                 "variant": "irq_pulse_resubmission",
                 "checker": "ibex_pulp_online",
                 "expected_finding": "cpu_irq_pulse_input_mismatch",
                 "operation": "duplicate", "selector": {},
                 "mutation": {"field": "pulse_start", "replacement": 1}}
        self.assert_rejected(document_for(entry), "replacement")

    def test_document_rejects_real_dut_or_trace_write_targets(self):
        self.assert_rejected(
            document_for(valid_entry(mutation={"field": "outputs.irq",
                                               "replacement": 0,
                                               "dut_port": 3})),
            "DUT")
        self.assert_rejected(
            document_for(valid_entry(selector={"case_id": "case-irq",
                                               "apply_to_dut": True})),
            "DUT")
        self.assert_rejected(
            document_for(valid_entry(selector={"case_id": "case-irq",
                                               "rtl_write": {"port": "gpio_in"}})),
            "DUT")
        self.assert_rejected(
            document_for({**valid_entry(), "write_to_dut": ["gpio_in"]}),
            "DUT")
        self.assert_rejected(
            {"schema_version": FAULT_SCHEMA_VERSION,
             "faults": [valid_entry()], "hardware": {"port": "gpio_a"}}, "DUT")


if __name__ == "__main__":
    unittest.main()
