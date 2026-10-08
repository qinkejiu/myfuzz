"""P5 受控故障**同条件质量对照**（``p5_fault_quality.v1``）的软件测试。

边界（先读）：
* 本文件只构造**合成但与真实产物同形**的校准根目录（事件形状取自保存的真实在线
  运行），再用被测模块只读地分析它。**不渲染 harness、不启动 Verilator、不跑
  fuzz、不写入任何已保存运行。**
* 合成根里的 ``fault_document.json`` / ``minimal_replay.json`` 由 shipped 的
  ``ControlledFaultFamily`` 真实注入产生（复用校准运行器的定位器与钉住规则），
  因此"读了一个并不存在的字段"这类错误会在软件阶段被抓住。
* 断言只针对**被测量的事实**：期望 finding 与收据里的 observed findings、锚点
  事件的逐字段相等/不等、minimal replay 的摘要连接、按故障类的计数；缺失输入
  必须是精确拒绝，绝不静默通过、绝不写 0。
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/compare_p5_fault_quality.py"

from myfuzz.scenario import p5_fault_quality as quality  # noqa: E402

_RUNNER = None


def load_runner():
    """导入校准运行器脚本（只读），复用它的定位器/钉住规则构造真实形状夹具。"""
    global _RUNNER
    if _RUNNER is not None:
        return _RUNNER
    path = ROOT / "scripts/run_p5_fault_calibration_family.py"
    spec = importlib.util.spec_from_file_location("run_p5_fault_calibration_family",
                                                  path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    _RUNNER = module
    return module


_SCRIPT_MODULE = None


def load_script():
    """导入被测 CLI 脚本（``scripts/compare_p5_fault_quality.py``）。"""
    global _SCRIPT_MODULE
    if _SCRIPT_MODULE is not None:
        return _SCRIPT_MODULE
    if not SCRIPT.is_file():
        raise AssertionError(f"quality comparison script is missing: {SCRIPT}")
    spec = importlib.util.spec_from_file_location("compare_p5_fault_quality", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    _SCRIPT_MODULE = module
    return module


def canonical_text(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def digest(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def file_sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path: Path, document) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n",
                    encoding="utf-8")
    return digest(canonical_text(document))


# --------------------------------------------------------------------------
# 合成事件：形状与保存的真实在线事件一致
# --------------------------------------------------------------------------

def observed(event: dict, case_id: str) -> dict:
    provenance = dict(event.get("provenance") or {})
    provenance["observed_case"] = {"case_id": case_id, "case_index": 0}
    return {**event, "provenance": provenance}


def edge_candidates(seed: str, count: int = 2) -> dict:
    """真实 trace 里 source_start 事件携带的逐会话图身份字段。"""
    return {"edge_candidates": [
        {"graph_sha256": digest(f"{seed}-graph"),
         "path_ids": [digest(f"{seed}-path-{index}")],
         "relation": "delivery", "rule_index": index}
        for index in range(count)]}


def transaction(sequence: int) -> dict:
    return {"execution_id": "local-execution",
            "testcase_id": "ibex-dual-source-stream",
            "source_component": "cpu", "source_epoch": 0,
            "channel_id": "data", "source_sequence": sequence}


def variant_case(variant: str) -> tuple[str, tuple[dict, ...]]:
    case_id = f"case-{variant}"
    if variant == "observation_irq_level":
        events = (
            {"event_id": 1, "component": "gpio_b", "kind": "local_tick_sample",
             "local_tick": 12, "inputs": {"gpio_in": 0},
             "outputs": {"irq": 1, "interrupt": 1},
             "provenance": {"origin_status": "known",
                            "origin_admission_ids": ["admission-1"]}},
            {"event_id": 2, "kind": "source_start", "source_tick": 12,
             "source": ["gpio_b", "irq"], "target": ["cpu", "irq"],
             "provenance": {"origin_status": "known",
                            "origin_admission_ids": ["admission-1"],
                            **edge_candidates("control")}},
        )
    elif variant == "cpu_irq_input_bit":
        events = (
            {"event_id": 1, "kind": "pulse_start", "source": ["gpio_b", "irq"],
             "target": ["cpu", "irq"], "width": 1},
            {"event_id": 2, "component": "cpu", "local_tick": 20,
             "inputs": {"irq": 1}, "outputs": {}},
        )
    elif variant in ("cpu_response_data", "delivery_read_data",
                     "mmio_delivery_replay"):
        events = (
            {"event_id": 1, "kind": "mmio_delivery", "component": "cpu",
             "device_id": "gpio_b", "offset": 8, "write": False,
             "read_value": 0x5a, "source_transaction": transaction(7)},
            {"event_id": 2, "component": "cpu", "local_tick": 30,
             "inputs": {"irq": 0},
             "outputs": {"data_rsp_consumed": 1, "data_rsp_source_epoch": 0,
                         "data_rsp_source_sequence": 7, "data_rsp_rdata": 0x5a}},
        )
    elif variant == "uart_cpu_response_data":
        events = (
            {"event_id": 1, "kind": "mmio_delivery", "component": "cpu",
             "device_id": "uart", "offset": 0x18, "write": False,
             "read_value": 0x5a,
             "source_transaction": {"source_epoch": 0, "source_sequence": 5}},
            {"event_id": 2, "component": "cpu", "kind": None, "local_tick": 30,
             "outputs": {"data_rsp_consumed": 1, "data_rsp_source_epoch": 0,
                         "data_rsp_source_sequence": 5, "data_rsp_rdata": 0x5a}},
        )
    elif variant == "irq_pulse_resubmission":
        events = (
            {"event_id": 1, "kind": "pulse_start", "source": ["gpio_b", "irq"],
             "target": ["cpu", "irq"], "width": 1},
            {"event_id": 2, "component": "cpu", "local_tick": 21,
             "inputs": {"irq": 1}, "outputs": {}},
            {"event_id": 3, "component": "cpu", "local_tick": 22,
             "inputs": {"irq": 0}, "outputs": {}},
        )
    elif variant in ("delivery_value", "bound_input_value"):
        events = (
            {"event_id": 1, "component": "gpio_a", "local_tick": 40,
             "outputs": {"gpio_out": 0x06, "gpio_dir": 0xff}},
            {"event_id": 2, "kind": "dataflow_delivery", "producer_event_id": 1,
             "source": ["gpio_a", "gpio_out"], "source_bit_offset": 0,
             "target": ["gpio_b", "gpio_in"], "target_bit_offset": 0,
             "width": 8, "value": 0x06},
            {"event_id": 3, "component": "gpio_b", "local_tick": 41,
             "inputs": {"gpio_in": 0x06}, "outputs": {"irq": 0}},
        )
    else:  # pragma: no cover - defensive
        raise AssertionError(f"unknown synthetic variant {variant!r}")
    return case_id, tuple(observed(event, case_id) for event in events)


def write_trace(run_dir: Path, events) -> Path:
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / "online_final_trace.json"
    path.write_text(json.dumps({"events": list(events), "status": "running",
                                "local_ticks": {}}, sort_keys=True) + "\n",
                    encoding="utf-8")
    return path


def write_receipts(run_dir: Path, rows) -> Path:
    path = Path(run_dir) / "receipts.jsonl"
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n"
                            for row in rows), encoding="utf-8")
    return path


def identity_document(run_id: str, *, session_seed: str) -> dict:
    return {
        "schema_version": "online_run_identity.v1",
        "identity": {
            "run_config": {"run_id": run_id, "search_seed": 20261007,
                           "max_tests": 24},
            "session": {"manifest_file": "online_session_manifest.json",
                        "manifest_sha256": digest(f"{session_seed}-manifest")},
            "runtime_paths": {
                "declaration": {"contract": {
                    "graph_sha256": digest(f"{session_seed}-graph")}},
                "compiled": {"session": {
                    "graph_sha256": digest(f"{session_seed}-graph"),
                    "topology_sha256": digest("shared-topology")}},
            },
            "source_files": [
                {"path": "src/myfuzz/scenario/p5_fault_family.py",
                 "sha256": digest("p5_fault_family.py")},
                {"path": "src/myfuzz/scenario/ibex_pulp_online_checker.py",
                 "sha256": digest("ibex_pulp_online_checker.py")},
            ],
            "dependency_graph": {"sha256": digest("dependency-graph")},
        },
    }


# --------------------------------------------------------------------------
# 合成校准根
# --------------------------------------------------------------------------

CALIBRATED = "calibrated"
NOT_FIRED = "not_fired"
ERROR = "error"
NO_WITNESS = "no_witness_window"
SELECTED = "selected"

SESSION_STATUSES = (CALIBRATED, NOT_FIRED)


class BuiltRoot:
    def __init__(self, root: Path, control: Path, aggregate: dict, variants: dict,
                 cases: dict):
        self.root = root
        self.control = control
        self.aggregate = aggregate
        self.variants = variants
        self.cases = cases

    def session(self, variant: str) -> Path:
        return self.variants[variant]["session"]


class _RootCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runner = load_runner()
        self.quality = quality

    # -- fixture -----------------------------------------------------------
    def build_root(self, statuses=None, *, identity_differ: bool = True,
                   control_identity: bool = True) -> BuiltRoot:
        runner = self.runner
        statuses = dict(statuses or {"observation_irq_level": CALIBRATED})
        cases = {variant: variant_case(variant) for variant in statuses}
        root = self.root / "calibration"
        control = root / "control"
        control.mkdir(parents=True, exist_ok=True)
        everything = [event for _case_id, events in cases.values()
                      for event in events]
        control_trace = write_trace(control, everything)
        write_receipts(control, [
            {"case_id": case_id, "status": "complete", "violations": []}
            for case_id, _events in cases.values()])
        if control_identity:
            write_json(control / "online_run_identity.json",
                       identity_document("control-run", session_seed="control"))

        entries = []
        variants: dict = {}
        for variant, status in statuses.items():
            spec = runner.SPEC_BY_VARIANT[variant]
            case_id, events = cases[variant]
            session = root / variant / "session"
            record = {"session": session, "case_id": case_id, "status": status}
            entry = {
                "kind": spec.kind, "variant": variant, "checker": spec.checker,
                "status": status, "reason": None,
                "expected_finding": spec.expected_finding,
                "operation": spec.operation, "mutated_field": spec.field,
                "case_id": None, "selector": None, "mutation": None,
                "observation_event_id": None, "related_event_ids": None,
                "original_value": None, "injected_value": None,
                "finding_id": None, "window": None,
                "source_run": {
                    "path": str(control), "resolved": str(control.resolve()),
                    "trace_file": "online_final_trace.json",
                    "trace_bytes": control_trace.stat().st_size,
                    "trace_sha256": file_sha256(control_trace),
                    "cases_scanned": 1, "complete_scan": False,
                },
                "observed_findings": None, "family_findings": None,
                "finding_ids": None, "fault_document": None,
                "minimal_replay": None, "minimal_replay_error": None,
                "run": None,
                "command": "synthetic-fixture",
            }
            if status == CALIBRATED:
                document, replay, observation = self._pin(
                    variant, case_id, events)
                document_path = root / variant / "fault_document.json"
                document_sha = write_json(document_path, document)
                replay_path = root / variant / "minimal_replay.json"
                replay_sha = write_json(replay_path, replay)
                write_trace(session, self._session_events(events, variant,
                                                          identity_differ))
                write_receipts(session, [
                    {"case_id": f"unrelated-{variant}", "status": "complete",
                     "violations": []},
                    {"case_id": case_id, "status": "dut_violation",
                     "violations": [spec.expected_finding]},
                ])
                write_json(session / "online_run_identity.json",
                           identity_document(
                               f"fault-{variant}",
                               session_seed="fault" if identity_differ else "control"))
                chain = observation.finding["source_chain"]
                entry.update({
                    "reason": None, "case_id": case_id,
                    "selector": observation.pinned_entry["selector"],
                    "mutation": observation.pinned_entry["mutation"],
                    "observation_event_id": chain["observation_event_id"],
                    "related_event_ids": chain["related_event_ids"],
                    "original_value": chain["original_value"],
                    "injected_value": chain["injected_value"],
                    "finding_id": observation.finding_id,
                    "window": {"first_event_id": events[0]["event_id"],
                               "last_event_id": events[-1]["event_id"],
                               "event_count": len(events)},
                    "observed_findings": [spec.expected_finding],
                    "family_findings": list(observation.checker_findings),
                    "finding_ids": [observation.finding_id],
                    "fault_document": {
                        "path": str(document_path),
                        "resolved": str(document_path.resolve()),
                        "sha256": document_sha},
                    "minimal_replay": {
                        "path": str(replay_path),
                        "resolved": str(replay_path.resolve()),
                        "sha256": replay_sha},
                    "run": {
                        "output_dir": {"path": str(session),
                                       "resolved": str(session.resolve())},
                        "tests": 2, "statuses": {"complete": 1,
                                                 "dut_violation": 1},
                        "effective_search_seconds": 1.0,
                        "case_status": "dut_violation",
                        "case_violations": [spec.expected_finding],
                        "runtime_profile": {},
                    },
                })
                record["document"] = document_path
                record["replay"] = replay_path
                record["finding_id"] = observation.finding_id
                record["observation"] = observation
            elif status == NOT_FIRED:
                document, _replay, observation = self._pin(
                    variant, case_id, events)
                document_path = root / variant / "fault_document.json"
                document_sha = write_json(document_path, document)
                write_trace(session, self._session_events(events, variant,
                                                          identity_differ))
                write_receipts(session, [
                    {"case_id": case_id, "status": "complete", "violations": []},
                ])
                error_path = root / variant / "minimal_replay.error"
                error_path.write_text("ControlledFaultCalibrationError: "
                                      "no controlled fault was calibrated\n",
                                      encoding="utf-8")
                chain = observation.finding["source_chain"]
                entry.update({
                    "reason": f"故障运行未报告 {spec.expected_finding}",
                    "case_id": case_id,
                    "selector": observation.pinned_entry["selector"],
                    "mutation": observation.pinned_entry["mutation"],
                    "observation_event_id": chain["observation_event_id"],
                    "related_event_ids": chain["related_event_ids"],
                    "original_value": chain["original_value"],
                    "injected_value": chain["injected_value"],
                    "finding_id": observation.finding_id,
                    "window": {"first_event_id": events[0]["event_id"],
                               "last_event_id": events[-1]["event_id"],
                               "event_count": len(events)},
                    "observed_findings": [], "family_findings": [],
                    "finding_ids": [],
                    "fault_document": {
                        "path": str(document_path),
                        "resolved": str(document_path.resolve()),
                        "sha256": document_sha},
                    "minimal_replay_error": {
                        "path": str(error_path),
                        "resolved": str(error_path.resolve())},
                    "run": {
                        "output_dir": {"path": str(session),
                                       "resolved": str(session.resolve())},
                        "tests": 1, "statuses": {"complete": 1},
                        "effective_search_seconds": 1.0,
                        "case_status": "complete", "case_violations": [],
                        "runtime_profile": {},
                    },
                })
                record["document"] = document_path
                record["observation"] = observation
            elif status == ERROR:
                entry["reason"] = "RuntimeError: synthetic session failure"
                entry["observed_findings"] = None
                entry["minimal_replay_error"] = {
                    "path": str(root / variant / "minimal_replay.error"),
                    "resolved": str((root / variant / "minimal_replay.error").resolve())}
                (root / variant).mkdir(parents=True, exist_ok=True)
                (root / variant / "minimal_replay.error").write_text(
                    "RuntimeError: synthetic session failure\n", encoding="utf-8")
            elif status == NO_WITNESS:
                entry["reason"] = (f"no witnessed anchor for {spec.kind}/"
                                   f"{variant} | candidate source runs: "
                                   f"{control}[cases=3,events=7,scan=full]")
            elif status == SELECTED:
                entry["reason"] = None
            entries.append(entry)
            variants[variant] = record

        aggregate = {
            "schema_version": runner.SCHEMA_VERSION,
            "calibration_only": True,
            "observation_boundary": "checker_input_copy",
            "select_only": all(status == SELECTED for status in statuses.values()),
            "output_root": {"path": str(root), "resolved": str(root.resolve())},
            "budget": {"duration_seconds": 120.0, "max_tests": 24,
                       "search_seed": 20261007, "max_runs_per_batch": 1},
            "scan": {"max_cases": None},
            "source_runs": [], "missing_candidate_runs": [],
            "variants": entries,
            "limits": [],
        }
        write_json(root / "fault_family_calibration.json", aggregate)
        return BuiltRoot(root, control, aggregate, variants, cases)

    def _pin(self, variant: str, case_id: str, events):
        """用 shipped family 真实注入一次，得到钉住配置与最小重放文档。"""
        runner = self.runner
        spec = runner.SPEC_BY_VARIANT[variant]
        search = runner._Search(list(events), strict=False)
        anchor = runner._LOCATORS[(spec.kind, spec.variant)](search, {})
        self.assertIsNotNone(anchor, f"fixture anchor missing for {variant}")
        replacement = runner._replacement_for(spec, anchor.get("original_value"))
        entry = runner._entry_for(spec, {}, replacement)
        family = runner.ControlledFaultFamily.from_document(
            runner._document_for(entry))
        receipt = runner.OnlineCaseReceipt(case_id, 0, len(events),
                                           tuple(events), {}, {}, "running")
        run = family.inject(receipt)
        self.assertTrue(run.observations, f"fixture injection failed for {variant}")
        observation = run.observations[0]
        document = runner._document_for(observation.pinned_entry)
        return document, family.minimal_replay_document(), observation

    @staticmethod
    def _session_events(events, variant: str, identity_differ: bool):
        """故障会话的真实 trace：与对照相同的观测，仅逐会话身份字段不同。"""
        if not identity_differ:
            return tuple(events)
        patched = []
        for event in events:
            provenance = event.get("provenance")
            if isinstance(provenance, dict) and "edge_candidates" in provenance:
                changed = dict(provenance)
                changed["edge_candidates"] = edge_candidates("fault")[
                    "edge_candidates"]
                event = {**event, "provenance": changed}
            patched.append(event)
        return tuple(patched)

    # -- helpers -----------------------------------------------------------
    def analyze(self, built: BuiltRoot, **kwargs) -> dict:
        return self.quality.analyze_calibration_root(built.root, **kwargs)

    def variant_doc(self, document: dict, variant: str) -> dict:
        for item in document["variants"]:
            if item["variant"] == variant:
                return item
        raise AssertionError(f"{variant} missing from {[v['variant'] for v in
                                                      document['variants']]}")

    def failure_reasons(self, document: dict) -> str:
        return " | ".join(item["reason"] for item in document["failures"])

    def patch_trace(self, run_dir: Path, event_id: int, mutate) -> None:
        path = Path(run_dir) / "online_final_trace.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        for event in document["events"]:
            if event.get("event_id") == event_id:
                mutate(event)
        path.write_text(json.dumps(document, sort_keys=True) + "\n",
                        encoding="utf-8")

    def drop_event(self, run_dir: Path, event_id: int) -> None:
        path = Path(run_dir) / "online_final_trace.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["events"] = [event for event in document["events"]
                              if event.get("event_id") != event_id]
        path.write_text(json.dumps(document, sort_keys=True) + "\n",
                        encoding="utf-8")

    def append_event(self, run_dir: Path, event: dict) -> None:
        path = Path(run_dir) / "online_final_trace.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["events"].append(event)
        path.write_text(json.dumps(document, sort_keys=True) + "\n",
                        encoding="utf-8")


# --------------------------------------------------------------------------
# 1. 逐变体提取
# --------------------------------------------------------------------------

class DetectionExtractionTest(_RootCase):
    def test_detection_names_finding_case_and_receipt_status(self):
        built = self.build_root({"observation_irq_level": CALIBRATED})
        document = self.analyze(built)
        variant = self.variant_doc(document, "observation_irq_level")
        detection = variant["detection"]
        self.assertEqual(detection["expected_finding"],
                         "gpio_b_irq_source_mismatch")
        self.assertIs(detection["detected"], True)
        self.assertEqual(detection["expected_finding_present_in_receipts"], True)
        self.assertEqual(detection["fired_case_id"],
                         built.variants["observation_irq_level"]["case_id"])
        self.assertEqual(detection["fired_receipt_status"], "dut_violation")
        self.assertEqual([row["finding"] for row in detection["observed_findings"]],
                         ["gpio_b_irq_source_mismatch"])
        self.assertEqual(detection["observed_findings"][0]["receipt_line"], 2)
        self.assertEqual(detection["family_finding_ids"],
                         [built.variants["observation_irq_level"]["finding_id"]])
        self.assertIs(detection["finding_ids_joined"], True)
        self.assertEqual(detection["receipt_cases"], 2)

    def test_not_fired_variant_reports_empty_observation_without_fabricating(self):
        built = self.build_root({"delivery_value": NOT_FIRED})
        document = self.analyze(built)
        variant = self.variant_doc(document, "delivery_value")
        detection = variant["detection"]
        self.assertIs(detection["detected"], False)
        self.assertEqual(detection["observed_findings"], [])
        self.assertEqual(detection["expected_finding_present_in_receipts"], False)
        self.assertIn("gpio_a_to_b_delivery_mismatch", variant["failures"][0]["reason"] \
                      if variant["failures"] else detection["reason"])
        self.assertIn("delivery_value", document["never_calibrated"])
        self.assertIs(document["fault_class_rollup"]["broken_binding_value"]
                      ["not_fired"], 1)

    def test_error_variant_without_session_is_reported_not_refused(self):
        built = self.build_root({"observation_irq_level": ERROR})
        document = self.analyze(built)
        variant = self.variant_doc(document, "observation_irq_level")
        self.assertEqual(variant["status"], ERROR)
        self.assertIs(variant["detection"]["observable"], False)
        self.assertIn("synthetic session failure", variant["inputs"]["reason"])
        self.assertIn("observation_irq_level", document["never_calibrated"])
        self.assertIs(document["ok"], True)
        self.assertEqual(self.quality.status_exit_code(document),
                         self.quality.EXIT_INCOMPLETE)


# --------------------------------------------------------------------------
# 2. 注入边界：控制/故障锚点逐字段对照
# --------------------------------------------------------------------------

class InjectionBoundaryTest(_RootCase):
    def test_anchor_events_are_compared_field_by_field(self):
        built = self.build_root({"observation_irq_level": CALIBRATED},
                               identity_differ=True)
        document = self.analyze(built)
        variant = self.variant_doc(document, "observation_irq_level")
        boundary = variant["injection_boundary"]
        self.assertIs(boundary["measured"], True)
        self.assertIs(boundary["ok"], True, boundary["reason"])
        self.assertEqual(boundary["anchored_event_ids"], [1, 2])
        events = {item["event_id"]: item for item in boundary["anchor_events"]}
        self.assertEqual(sorted(events), [1, 2])
        self.assertIs(events[1]["dataflow_identical"], True)
        self.assertIs(events[1]["identical"], True)
        source_start = events[2]
        self.assertIs(source_start["dataflow_identical"], True,
                      source_start["differing_fields"])
        self.assertIs(source_start["identical"], False)
        paths = {item["path"]: item for item in source_start["differing_fields"]}
        self.assertEqual(sorted(paths),
                         ["provenance.edge_candidates[0].graph_sha256",
                          "provenance.edge_candidates[0].path_ids[0]",
                          "provenance.edge_candidates[1].graph_sha256",
                          "provenance.edge_candidates[1].path_ids[0]"])
        for item in paths.values():
            self.assertEqual(item["class"], "session_identity")
            self.assertNotEqual(item["control"], item["fault"])
        self.assertGreater(source_start["compared_fields"], 0)
        self.assertEqual(source_start["dataflow_sha256"]["control"],
                         source_start["dataflow_sha256"]["fault"])
        ticks = {item["key"]: item for item in boundary["ticks"]}
        self.assertEqual(ticks["source_tick"]["selector"], 12)
        self.assertEqual(ticks["source_tick"]["control"], 12)
        self.assertEqual(ticks["source_tick"]["fault"], 12)
        self.assertIs(ticks["source_tick"]["equal"], True)
        mutated = boundary["mutated_field"]
        self.assertEqual(mutated["field"], "outputs.irq")
        self.assertEqual(mutated["original_value"], 1)
        self.assertEqual(mutated["injected_value"], 0)
        self.assertEqual(mutated["control_value"], 1)
        self.assertEqual(mutated["fault_value"], 1)
        self.assertIs(mutated["fault_equals_original"], True)
        self.assertIs(mutated["injected_absent_from_recorded_trace"], True)
        recorded = boundary["recorded_traces"]
        self.assertIs(recorded["case_window_identical"], False)
        self.assertIs(recorded["case_window_dataflow_identical"], True)
        window_diff = recorded["case_window_diff"]
        self.assertEqual(window_diff["differing_event_count"], 0)
        self.assertEqual(window_diff["differing_event_count_raw"], 1)
        self.assertEqual(window_diff["identity_only_differing_event_count"], 1)
        self.assertEqual(
            recorded["control"]["case_window"]["dataflow_sha256"],
            recorded["fault"]["case_window"]["dataflow_sha256"])
        self.assertEqual(
            recorded["control"]["trace_sha256_measured"],
            recorded["control"]["trace_sha256_recorded"])
        condition = variant["same_condition"]
        self.assertIs(condition["available"], True)
        self.assertIs(condition["graph_sha256_equal"], False)
        self.assertIs(condition["topology_sha256_equal"], True)
        self.assertIs(condition["source_files_equal"], True)
        self.assertIs(condition["dependency_graph_sha256_equal"], True)
        self.assertIs(condition["degraded"], True)
        self.assertTrue(any("graph_sha256" in note for note in condition["notes"]))

    def test_dataflow_field_difference_is_a_failure_not_a_pass(self):
        built = self.build_root({"observation_irq_level": CALIBRATED})
        self.patch_trace(built.session("observation_irq_level"), 1,
                         lambda event: event["outputs"].update({"irq": 0,
                                                                "interrupt": 0}))
        document = self.analyze(built)
        variant = self.variant_doc(document, "observation_irq_level")
        self.assertIs(document["ok"], False)
        self.assertIs(variant["injection_boundary"]["ok"], False)
        checks = {item["check"] for item in document["failures"]}
        self.assertIn("anchor_dataflow_fields", checks)
        reason = self.failure_reasons(document)
        self.assertIn("outputs.irq", reason)
        self.assertIn("event_id=1", reason)
        self.assertIn("observation_irq_level", reason)
        self.assertEqual(self.quality.status_exit_code(document),
                         self.quality.EXIT_MISMATCH)

    def test_missing_anchor_event_is_a_refusal(self):
        built = self.build_root({"observation_irq_level": CALIBRATED})
        self.drop_event(built.session("observation_irq_level"), 2)
        with self.assertRaises(quality.FaultQualityError) as caught:
            self.analyze(built)
        self.assertIn("event_id=2", str(caught.exception))
        self.assertIn("observation_irq_level", str(caught.exception))

    def test_missing_receipts_is_a_refusal(self):
        built = self.build_root({"observation_irq_level": CALIBRATED})
        (built.session("observation_irq_level") / "receipts.jsonl").unlink()
        with self.assertRaises(quality.FaultQualityError) as caught:
            self.analyze(built)
        self.assertIn("receipts.jsonl", str(caught.exception))
        self.assertIn("observation_irq_level", str(caught.exception))

    def test_duplicate_variant_measures_the_claim_count_in_both_traces(self):
        built = self.build_root({"irq_pulse_resubmission": CALIBRATED})
        document = self.analyze(built)
        variant = self.variant_doc(document, "irq_pulse_resubmission")
        boundary = variant["injection_boundary"]
        duplicate = boundary["duplicate"]
        self.assertIs(duplicate["applicable"], True)
        self.assertEqual(duplicate["duplicated_kind"], "pulse_start")
        self.assertEqual(duplicate["control_claim_count"], 1)
        self.assertEqual(duplicate["fault_claim_count"], 1)
        self.assertIs(duplicate["equal"], True)
        self.assertIs(boundary["ok"], True, boundary["reason"])
        self.assertIs(boundary["mutated_field"]["applicable"], False)

    def test_window_diff_decomposes_identity_digests_from_real_content(self):
        built = self.build_root({"observation_irq_level": CALIBRATED})
        case_id = built.variants["observation_irq_level"]["case_id"]
        control = built.control
        session = built.session("observation_irq_level")
        self.append_event(control, observed({
            "event_id": 900, "component": "cpu", "kind": "memory_read",
            "admission": {"action_id": "a", "case_id": case_id, "case_index": 0,
                          "component": "cpu", "direction": "IP_TO_CPU",
                          "input_kind": "instruction", "role": "fuzz_source",
                          "source_id": "s", "input_sha256": digest("x"),
                          "admission_id": digest("ctl-admission"),
                          "path_id": digest("ctl-path")}}, case_id))
        self.append_event(session, observed({
            "event_id": 900, "component": "cpu", "kind": "memory_read",
            "admission": {"action_id": "a", "case_id": case_id, "case_index": 0,
                          "component": "cpu", "direction": "IP_TO_CPU",
                          "input_kind": "instruction", "role": "fuzz_source",
                          "source_id": "s", "input_sha256": digest("x"),
                          "admission_id": digest("fault-admission"),
                          "path_id": digest("fault-path")}}, case_id))
        self.append_event(control, observed(
            {"event_id": 901, "component": "cpu", "kind": "memory_read",
             "byte_cells": {"0": [0]}}, case_id))
        self.append_event(session, observed(
            {"event_id": 901, "component": "cpu", "kind": "memory_read",
             "byte_cells": {"0": [1]}}, case_id))
        document = self.analyze(built)
        variant = self.variant_doc(document, "observation_irq_level")
        boundary = variant["injection_boundary"]
        self.assertIs(boundary["ok"], True, boundary["reason"])
        recorded = boundary["recorded_traces"]
        self.assertIs(recorded["case_window_dataflow_identical"], False)
        diff = recorded["case_window_diff"]
        self.assertEqual(diff["differing_event_count"], 2)
        self.assertEqual(diff["session_identity_digest_field_count"], 2)
        self.assertEqual(diff["other_dataflow_field_count"], 1)
        self.assertEqual(diff["other_dataflow_paths"],
                         [{"path": "byte_cells.0[0]", "occurrences": 1}])
        events = {item["event_id"]: item for item in diff["events"]}
        self.assertEqual(events[900]["session_identity_digest_field_count"], 2)
        self.assertEqual(events[900]["other_dataflow_field_count"], 0)
        self.assertEqual(events[901]["other_dataflow_field_count"], 1)
        self.assertIn("byte_cells.0[0]",
                      [item["path"] for item in events[901]["example_paths"]])
        self.assertIn("身份摘要字段", " ".join(variant["same_condition"]["notes"]))

    def test_window_diff_is_empty_when_the_windows_match(self):
        built = self.build_root({"uart_cpu_response_data": CALIBRATED})
        document = self.analyze(built)
        variant = self.variant_doc(document, "uart_cpu_response_data")
        recorded = variant["injection_boundary"]["recorded_traces"]
        self.assertIs(recorded["case_window_identical"], True)
        self.assertEqual(recorded["case_window_diff"]["differing_event_count"], 0)
        self.assertEqual(recorded["case_window_diff"]["other_dataflow_paths"], [])

    def test_source_file_diff_names_the_changed_files(self):
        built = self.build_root({"observation_irq_level": CALIBRATED})
        identity_path = (built.session("observation_irq_level")
                         / "online_run_identity.json")
        identity = json.loads(identity_path.read_text(encoding="utf-8"))
        identity["identity"]["source_files"][0]["sha256"] = digest("changed")
        write_json(identity_path, identity)
        document = self.analyze(built)
        variant = self.variant_doc(document, "observation_irq_level")
        condition = variant["same_condition"]
        self.assertIs(condition["source_files_equal"], False)
        diff = condition["source_file_diff"]
        self.assertEqual(diff["changed"],
                         ["src/myfuzz/scenario/p5_fault_family.py"])
        self.assertEqual(diff["changed_count"], 1)
        self.assertIn("p5_fault_family.py",
                      " ".join(condition["notes"]))


# --------------------------------------------------------------------------
# 3. 可重放材料：minimal replay 摘要连接
# --------------------------------------------------------------------------

class ReproducibilityTest(_RootCase):
    def test_minimal_replay_digest_joins_the_fault_document(self):
        built = self.build_root({"observation_irq_level": CALIBRATED})
        document = self.analyze(built)
        variant = self.variant_doc(document, "observation_irq_level")
        reproducibility = variant["reproducibility"]
        self.assertIs(reproducibility["minimal_replay_present"], True)
        self.assertIs(reproducibility["digest_equal"], True)
        self.assertIs(reproducibility["ok"], True, reproducibility["reason"])
        expected = digest(canonical_text(
            json.loads((built.root / "observation_irq_level" /
                        "fault_document.json").read_text(encoding="utf-8"))))
        self.assertEqual(reproducibility["fault_document_canonical_sha256"],
                         expected)
        self.assertEqual(
            reproducibility["minimal_replay_fault_document_sha256"], expected)
        self.assertEqual(reproducibility["finding_ids"],
                         [built.variants["observation_irq_level"]["finding_id"]])

    def test_digest_mismatch_is_reported_with_both_values(self):
        built = self.build_root({"observation_irq_level": CALIBRATED})
        replay_path = built.root / "observation_irq_level" / "minimal_replay.json"
        replay = json.loads(replay_path.read_text(encoding="utf-8"))
        replay["fault_document_sha256"] = "0" * 64
        write_json(replay_path, replay)
        document = self.analyze(built)
        variant = self.variant_doc(document, "observation_irq_level")
        self.assertIs(variant["reproducibility"]["ok"], False)
        self.assertIn("minimal_replay_digest_join",
                      {item["check"] for item in document["failures"]})
        reason = self.failure_reasons(document)
        self.assertIn("0" * 64, reason)
        self.assertEqual(self.quality.status_exit_code(document),
                         self.quality.EXIT_MISMATCH)

    def test_missing_minimal_replay_for_calibrated_variant_is_a_refusal(self):
        built = self.build_root({"observation_irq_level": CALIBRATED})
        (built.root / "observation_irq_level" / "minimal_replay.json").unlink()
        with self.assertRaises(quality.FaultQualityError) as caught:
            self.analyze(built)
        self.assertIn("minimal_replay.json", str(caught.exception))
        self.assertIn("observation_irq_level", str(caught.exception))

    def test_not_fired_variant_records_absent_replay_with_reason(self):
        built = self.build_root({"delivery_value": NOT_FIRED})
        document = self.analyze(built)
        variant = self.variant_doc(document, "delivery_value")
        reproducibility = variant["reproducibility"]
        self.assertIs(reproducibility["minimal_replay_present"], False)
        self.assertIsNone(reproducibility["digest_equal"])
        self.assertIn("not_fired", reproducibility["reason"])


# --------------------------------------------------------------------------
# 4. 拒绝路径
# --------------------------------------------------------------------------

class RefusalTest(_RootCase):
    def test_missing_aggregate_is_a_refusal(self):
        with self.assertRaises(quality.FaultQualityError) as caught:
            self.quality.analyze_calibration_root(self.root / "nope")
        self.assertIn("fault_family_calibration.json", str(caught.exception))

    def test_wrong_aggregate_schema_is_a_refusal(self):
        built = self.build_root({"observation_irq_level": CALIBRATED})
        aggregate_path = built.root / "fault_family_calibration.json"
        aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
        aggregate["schema_version"] = "p5_fault_family_calibration.v0"
        write_json(aggregate_path, aggregate)
        with self.assertRaises(quality.FaultQualityError) as caught:
            self.analyze(built)
        self.assertIn("schema_version", str(caught.exception))

    def test_unknown_variant_filter_is_a_refusal(self):
        built = self.build_root({"observation_irq_level": CALIBRATED})
        with self.assertRaises(quality.FaultQualityError) as caught:
            self.analyze(built, variants=["not_a_variant"])
        self.assertIn("not_a_variant", str(caught.exception))

    def test_missing_control_trace_is_a_refusal(self):
        built = self.build_root({"observation_irq_level": CALIBRATED})
        (built.control / "online_final_trace.json").unlink()
        with self.assertRaises(quality.FaultQualityError) as caught:
            self.analyze(built)
        self.assertIn("observation_irq_level", str(caught.exception))

    def test_expected_finding_contract_drift_is_a_refusal(self):
        built = self.build_root({"observation_irq_level": CALIBRATED})
        aggregate_path = built.root / "fault_family_calibration.json"
        aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
        aggregate["variants"][0]["expected_finding"] = "some_other_finding"
        write_json(aggregate_path, aggregate)
        with self.assertRaises(quality.FaultQualityError) as caught:
            self.analyze(built)
        self.assertIn("some_other_finding", str(caught.exception))


# --------------------------------------------------------------------------
# 5. 按故障类汇总 + 未校准清单
# --------------------------------------------------------------------------

class RollupTest(_RootCase):
    def statuses(self):
        return {
            "observation_irq_level": CALIBRATED,     # wrong_irq
            "cpu_irq_input_bit": NOT_FIRED,          # wrong_irq
            "cpu_response_data": CALIBRATED,         # wrong_read_data
            "irq_pulse_resubmission": ERROR,         # duplicate_submission
            "mmio_delivery_replay": NO_WITNESS,      # duplicate_submission
            "delivery_value": CALIBRATED,            # broken_binding_value
        }

    def test_rollup_counts_every_fault_class(self):
        built = self.build_root(self.statuses())
        document = self.analyze(built)
        rollup = document["fault_class_rollup"]
        self.assertEqual(sorted(rollup), sorted(
            ["wrong_irq", "wrong_read_data", "duplicate_submission",
             "broken_binding_value"]))
        self.assertEqual(rollup["wrong_irq"]["calibrated"], 1)
        self.assertEqual(rollup["wrong_irq"]["not_fired"], 1)
        self.assertEqual(rollup["wrong_irq"]["error"], 0)
        self.assertEqual(rollup["wrong_irq"]["no_witness_window"], 0)
        self.assertEqual(rollup["wrong_irq"]["total"], 2)
        self.assertEqual(rollup["wrong_read_data"]["calibrated"], 1)
        self.assertEqual(rollup["duplicate_submission"]["error"], 1)
        self.assertEqual(rollup["duplicate_submission"]["no_witness_window"], 1)
        self.assertEqual(rollup["duplicate_submission"]["calibrated"], 0)
        self.assertEqual(rollup["broken_binding_value"]["calibrated"], 1)
        totals = document["rollup"]
        self.assertEqual(totals["calibrated"], 3)
        self.assertEqual(totals["total"], 6)
        self.assertEqual(sorted(document["never_calibrated"]),
                         ["cpu_irq_input_bit", "irq_pulse_resubmission",
                          "mmio_delivery_replay"])
        self.assertIs(document["fully_calibrated"], False)
        self.assertIs(document["ok"], True)
        self.assertEqual(self.quality.status_exit_code(document),
                         self.quality.EXIT_INCOMPLETE)

    def test_variant_filter_marks_unanalyzed_variants(self):
        built = self.build_root({"observation_irq_level": CALIBRATED})
        document = self.analyze(built, variants=["observation_irq_level"])
        self.assertEqual(document["analyzed_variants"], ["observation_irq_level"])
        self.assertIn("cpu_irq_input_bit", document["not_analyzed_variants"])
        self.assertEqual(document["rollup"]["total"], 1)
        self.assertEqual(
            document["fault_class_rollup"]["wrong_irq"]["declared"], 2)

    def test_all_calibrated_root_exits_zero(self):
        built = self.build_root({"observation_irq_level": CALIBRATED,
                                 "delivery_value": CALIBRATED})
        document = self.analyze(built)
        self.assertIs(document["fully_calibrated"], True)
        self.assertIs(document["ok"], True)
        self.assertEqual(document["never_calibrated"], [])
        self.assertEqual(self.quality.status_exit_code(document),
                         self.quality.EXIT_OK)


# --------------------------------------------------------------------------
# 6. 标记、声明与确定性
# --------------------------------------------------------------------------

class DocumentContractTest(_RootCase):
    def test_calibration_only_marker_and_statement(self):
        built = self.build_root({"observation_irq_level": CALIBRATED})
        document = self.analyze(built)
        self.assertEqual(document["schema_version"], "p5_fault_quality.v1")
        self.assertIs(document["calibration_only"], True)
        self.assertEqual(document["observation_boundary"], "checker_input_copy")
        statement = document["statement"]
        self.assertIs(statement["calibration_only"], True)
        self.assertIs(statement["injected_findings_are_natural_dut_defects"], False)
        self.assertIn("calibration_only", statement["text"])
        self.assertIn("DUT", statement["text"])
        for variant in document["variants"]:
            conclusions = variant["conclusions"]
            self.assertIn("established", conclusions)
            self.assertIn("not_established", conclusions)

    def test_two_runs_are_byte_identical(self):
        built = self.build_root({"observation_irq_level": CALIBRATED,
                                 "delivery_value": NOT_FIRED,
                                 "cpu_irq_input_bit": ERROR})
        first = self.quality.render_document(self.analyze(built))
        second = self.quality.render_document(self.analyze(built))
        self.assertEqual(first, second)
        self.assertEqual(hashlib.sha256(first.encode()).hexdigest(),
                         hashlib.sha256(second.encode()).hexdigest())

    def test_cli_writes_the_same_document_and_reports_exit_codes(self):
        built = self.build_root({"observation_irq_level": CALIBRATED})
        script = load_script()
        first = self.root / "first.json"
        second = self.root / "second.json"
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = script.main(["--calibration-root", str(built.root),
                                "--output", str(first), "--quiet"])
        self.assertEqual(code, 0)
        self.assertEqual(out.getvalue(), "")
        with contextlib.redirect_stdout(io.StringIO()):
            script.main(["--calibration-root", str(built.root),
                         "--output", str(second), "--quiet"])
        self.assertEqual(first.read_bytes(), second.read_bytes())
        document = json.loads(first.read_text(encoding="utf-8"))
        self.assertEqual(document["schema_version"], "p5_fault_quality.v1")

    def test_cli_refusal_exit_code_and_reason(self):
        script = load_script()
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = script.main(["--calibration-root", str(self.root / "nope")])
        self.assertEqual(code, 1)
        self.assertIn("fault_family_calibration.json", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
