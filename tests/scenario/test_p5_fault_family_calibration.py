"""P5 受控故障族**真实校准运行器**与**独立复核器**的软件测试。

边界（先读）：
* 本文件只（1）构造合成事件、(2) 读取保存的真实运行目录（只读）、(3) 调用
  运行器的软件路径。**不渲染 harness、不启动 Verilator、不跑在线 fuzz**；
  真实 RTL 会话由 root 在软件侧全绿之后串行执行。
* `run` 模式的真实会话通过 `session_runner` 注入点在软件测试里被替换成一个
  **只回放保存事件**的假会话；CLI 永远走真实 RTL 会话（默认注入点）。
* 选择器只来自**被见证的真实事件字段**：测试断言选择器键集合等于 `_SPECS`
  为该变体声明的键，且 `original_value` 等于事件里的真实值——绝不接受猜测。
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/run_p5_fault_calibration_family.py"

#: 真实保存运行：UART 侧见证（`ibex_uart_online` 的 `uart_cpu_response_data`）。
REAL_UART_RUN = ROOT / "runs/p5-uart-gate2-20261007-online"
#: 真实保存运行：PULP 侧见证（其余 8 个变体）。
REAL_PULP_RUN = ROOT / "runs/current-dataflow-p5-paired-20261007-online"

_MODULE = None


def load_script():
    """导入被测脚本模块（同一进程内只导入一次）。"""
    global _MODULE
    if _MODULE is not None:
        return _MODULE
    if not SCRIPT.is_file():
        raise AssertionError(f"calibration runner is not implemented: {SCRIPT}")
    spec = importlib.util.spec_from_file_location(
        "run_p5_fault_calibration_family", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    _MODULE = module
    return module


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def canonical_sha256(value) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# --------------------------------------------------------------------------
# 合成观测：每个变体一份"与保存真实事件同形"的最小 case
# --------------------------------------------------------------------------

def observed(event: dict, case_id: str) -> dict:
    provenance = dict(event.get("provenance") or {})
    provenance["observed_case"] = {"case_id": case_id, "case_index": 0}
    return {**event, "provenance": provenance}


def transaction(sequence: int) -> dict:
    return {"execution_id": "local-execution",
            "testcase_id": "ibex-dual-source-stream",
            "source_component": "cpu", "source_epoch": 0,
            "channel_id": "data", "source_sequence": sequence}


def variant_case(variant: str) -> tuple[str, tuple[dict, ...]]:
    """返回 (case_id, events)：形状取自保存的真实运行事件。"""
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
                            "origin_admission_ids": ["admission-1"]}},
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


def write_source_run(run_dir: Path, cases) -> Path:
    """写一个最小的保存运行目录：事件 trace + 逐例 receipts（全部无 finding）。"""
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    events = [event for _case_id, case_events in cases for event in case_events]
    (run_dir / "online_final_trace.json").write_text(
        json.dumps({"events": events, "status": "running",
                    "local_ticks": {}}, sort_keys=True) + "\n",
        encoding="utf-8")
    receipts = [{"case_id": case_id, "status": "complete", "violations": [],
                 "events": len(case_events)}
                for case_id, case_events in cases]
    (run_dir / "receipts.jsonl").write_text(
        "".join(json.dumps(receipt, sort_keys=True) + "\n"
                for receipt in receipts), encoding="utf-8")
    return run_dir


def all_variant_cases():
    module = load_script()
    return [variant_case(spec.variant) for spec in module._SPECS]


def case_window(run_dir: Path, case_id: str) -> tuple:
    """从保存 trace 里取一个 case 的完整事件窗口（真实 run 的 receipt 语义）。"""
    document = json.loads(
        (Path(run_dir) / "online_final_trace.json").read_text(encoding="utf-8"))
    window, inside = [], False
    for event in document["events"]:
        provenance = event.get("provenance")
        observed = provenance.get("observed_case") if isinstance(provenance, dict) else None
        found = observed.get("case_id") if isinstance(observed, dict) else None
        if found == case_id:
            inside = True
            window.append(event)
        elif inside:
            break
    return tuple(window)


CONTROL_FINDING = "gpio_b_irq_source_mismatch"


class _TempCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.module = load_script()

    def fake_client(self) -> Path:
        """run 模式只校验 client 路径存在；软件测试用不可执行的占位文件。"""
        path = self.root / "kfuzz"
        path.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        path.chmod(0o755)
        return path


# --------------------------------------------------------------------------
# 1. 见证窗口选择
# --------------------------------------------------------------------------

class WitnessSelectionTest(_TempCase):
    def test_every_variant_selects_its_declared_selector_keys(self):
        for spec in self.module._SPECS:
            with self.subTest(variant=spec.variant):
                run_dir = write_source_run(
                    self.root / f"source-{spec.variant}", [variant_case(spec.variant)])
                selection = self.module.select_witnesses([run_dir])
                witness = selection.witnesses.get(spec.variant)
                self.assertIsNotNone(witness, selection.reasons.get(spec.variant))
                selector = witness.selector
                self.assertEqual(set(selector), set(spec.selector_keys))
                self.assertEqual(selector["case_id"], f"case-{spec.variant}")
                document = witness.document
                self.assertEqual(document["schema_version"],
                                 self.module.FAULT_SCHEMA_VERSION)
                # 文档必须能通过故障族自己的严格校验（canonical 往返）。
                family = self.module.ControlledFaultFamily.from_document(document)
                self.assertEqual(family.document(), document)
                entry = document["faults"][0]
                self.assertEqual(entry["variant"], spec.variant)
                self.assertEqual(entry["checker"], spec.checker)
                self.assertEqual(entry["expected_finding"], spec.expected_finding)
                self.assertEqual(entry["operation"], spec.operation)
                self.assertEqual(entry["mutation"]["field"], spec.field)
                self.assertEqual(witness.finding_id,
                                 family.inject(self.module.OnlineCaseReceipt(
                                     selector["case_id"], 0, 0,
                                     variant_case(spec.variant)[1], {}, {},
                                     "running")).finding_documents[0]["finding_id"])

    def test_selector_values_are_witnessed_and_never_guessed(self):
        run_dir = write_source_run(
            self.root / "source-irq", [variant_case("observation_irq_level")])
        selection = self.module.select_witnesses([run_dir])
        witness = selection.witnesses["observation_irq_level"]
        self.assertEqual(witness.selector["observation_event_id"], 1)
        self.assertEqual(witness.selector["source_start_event_id"], 2)
        self.assertEqual(witness.selector["source_tick"], 12)
        self.assertEqual(witness.selector["original_value"], 1)
        self.assertEqual(witness.original_value, 1)
        self.assertEqual(witness.injected_value, 0)
        run_dir = write_source_run(
            self.root / "source-read", [variant_case("cpu_response_data")])
        selection = self.module.select_witnesses([run_dir])
        witness = selection.witnesses["cpu_response_data"]
        self.assertEqual(witness.selector["read_event_id"], 1)
        self.assertEqual(witness.selector["response_event_id"], 2)
        self.assertEqual(witness.selector["original_value"], 0x5a)
        self.assertEqual(witness.original_value, 0x5a)
        self.assertEqual(witness.injected_value, 0x5b)

    def test_missing_window_fails_closed_with_a_precise_reason(self):
        run_dir = write_source_run(
            self.root / "source-partial", [variant_case("delivery_value")])
        selection = self.module.select_witnesses([run_dir])
        self.assertIn("delivery_value", selection.witnesses)
        self.assertNotIn("cpu_response_data", selection.witnesses)
        reason = selection.reasons["cpu_response_data"]
        self.assertIn("no witnessed anchor", reason)
        self.assertIn("cpu_response_data", reason)
        self.assertIn(str(run_dir), reason)

    def test_selection_is_read_only_on_the_source_run(self):
        run_dir = write_source_run(
            self.root / "source-readonly", all_variant_cases())
        before = sorted(path.name for path in run_dir.iterdir())
        trace = run_dir / "online_final_trace.json"
        before_sha = file_sha256(trace)
        before_bytes = trace.read_bytes()
        self.module.select_witnesses([run_dir])
        self.assertEqual(sorted(path.name for path in run_dir.iterdir()), before)
        self.assertEqual(file_sha256(trace), before_sha)
        self.assertEqual(trace.read_bytes(), before_bytes)

    def test_selection_over_a_saved_real_run_is_read_only(self):
        if not REAL_UART_RUN.is_dir():
            self.skipTest("saved UART run is not present")
        trace = REAL_UART_RUN / "online_final_trace.json"
        before_sha = file_sha256(trace)
        before_names = sorted(path.name for path in REAL_UART_RUN.iterdir())
        selection = self.module.select_witnesses(
            [REAL_UART_RUN], variants=["uart_cpu_response_data"], max_cases=3)
        witness = selection.witnesses["uart_cpu_response_data"]
        self.assertEqual(witness.selector["case_id"],
                         "online-1-819b265ed890cbfc934efd3e")
        self.assertEqual(witness.selector["read_event_id"], 13712)
        self.assertEqual(witness.selector["response_event_id"], 13737)
        self.assertEqual(witness.selector["original_value"], 90)
        self.assertEqual(witness.checker, "ibex_uart_online")
        self.assertEqual(witness.document["faults"][0]["checker"],
                         "ibex_uart_online")
        self.assertEqual(file_sha256(trace), before_sha)
        self.assertEqual(sorted(path.name for path in REAL_UART_RUN.iterdir()),
                         before_names)

    def test_selection_over_a_saved_pulp_run_covers_eight_variants(self):
        if not REAL_PULP_RUN.is_dir():
            self.skipTest("saved PULP run is not present")
        trace = REAL_PULP_RUN / "online_final_trace.json"
        before_sha = file_sha256(trace)
        selection = self.module.select_witnesses(
            [REAL_PULP_RUN],
            variants=[spec.variant for spec in self.module._SPECS
                      if spec.checker == "ibex_pulp_online"],
            max_cases=3)
        self.assertEqual(len(selection.witnesses), 8)
        self.assertEqual(selection.reasons, {})
        self.assertEqual(
            selection.witnesses["observation_irq_level"].selector, {
                "case_id": "online-2-604caae5c07e4c776cb357d1",
                "observation_event_id": 4609,
                "original_value": 1,
                "source_start_event_id": 4610,
                "source_tick": 131})
        self.assertEqual(file_sha256(trace), before_sha)


# --------------------------------------------------------------------------
# 2. --select-only：只写文档、不启动任何 RTL
# --------------------------------------------------------------------------

class SelectOnlyCliTest(_TempCase):
    def select_only(self, source_run: Path, output_root: Path, *extra: str) -> int:
        return self.module.main([
            "run", "--select-only",
            "--continuous-run", str(source_run),
            "--output-root", str(output_root),
            *extra])

    def test_select_only_writes_documents_without_rtl(self):
        source = write_source_run(self.root / "source", all_variant_cases())
        output = self.root / "calibration"
        # 故意给不存在的 cache/client：select-only 不允许触碰任何 RTL 路径。
        code = self.select_only(
            source, output,
            "--cache-dir", str(self.root / "missing-cache"),
            "--client-binary", str(self.root / "missing-kfuzz"))
        self.assertEqual(code, 0, "every variant must be selectable offline")
        aggregate = json.loads((output / "fault_family_calibration.json")
                               .read_text(encoding="utf-8"))
        self.assertEqual(aggregate["schema_version"],
                         self.module.SCHEMA_VERSION)
        self.assertIs(aggregate["select_only"], True)
        self.assertIs(aggregate["calibration_only"], True)
        self.assertEqual(aggregate["observation_boundary"],
                         "checker_input_copy")
        self.assertEqual(len(aggregate["variants"]),
                         len(self.module._SPECS))
        for entry in aggregate["variants"]:
            with self.subTest(variant=entry["variant"]):
                self.assertEqual(entry["status"], self.module.STATUS_SELECTED)
                self.assertIsNone(entry["reason"])
                self.assertIsNotNone(entry["selector"])
                self.assertEqual(
                    set(entry["selector"]),
                    set(self.module.SPEC_BY_VARIANT[entry["variant"]]
                        .selector_keys))
                document_path = Path(entry["fault_document"]["resolved"])
                document = json.loads(document_path.read_text(encoding="utf-8"))
                self.assertEqual(canonical_sha256(document),
                                 entry["fault_document"]["sha256"])
                self.assertEqual(
                    self.module.ControlledFaultFamily.from_document(document)
                    .document(), document)
                self.assertFalse((document_path.parent / "receipts.jsonl").exists(),
                                 "select-only must not run a session")
                self.assertIsNone(entry["minimal_replay"])
                self.assertIn("run_p5_fault_calibration_family.py run",
                              entry["command"])
                self.assertIn("--variant", entry["command"])

    def test_select_only_aggregate_reports_missing_windows(self):
        source = write_source_run(
            self.root / "source-partial", [variant_case("delivery_value")])
        output = self.root / "calibration-partial"
        code = self.select_only(source, output)
        self.assertEqual(code, 3, "a missing witness window is not success")
        aggregate = json.loads((output / "fault_family_calibration.json")
                               .read_text(encoding="utf-8"))
        entries = {entry["variant"]: entry for entry in aggregate["variants"]}
        self.assertEqual(entries["delivery_value"]["status"],
                         self.module.STATUS_SELECTED)
        missing = entries["observation_irq_level"]
        self.assertEqual(missing["status"], self.module.STATUS_NO_WITNESS)
        self.assertIsNone(missing["selector"])
        self.assertIsNone(missing["fault_document"])
        self.assertIn("no witnessed anchor", missing["reason"])
        self.assertFalse((output / "observation_irq_level").exists())

    def test_select_only_honours_variant_filter(self):
        source = write_source_run(self.root / "source", all_variant_cases())
        output = self.root / "calibration-one"
        code = self.select_only(
            source, output, "--variant", "delivery_value")
        self.assertEqual(code, 0)
        aggregate = json.loads((output / "fault_family_calibration.json")
                               .read_text(encoding="utf-8"))
        self.assertEqual([entry["variant"] for entry in aggregate["variants"]],
                         ["delivery_value"])
        self.assertTrue((output / "delivery_value/fault_document.json").is_file())

    def test_run_mode_refuses_missing_client_binary(self):
        source = write_source_run(self.root / "source", all_variant_cases())
        output = self.root / "must-not-exist"
        code = self.module.main([
            "run", "--continuous-run", str(source),
            "--output-root", str(output),
            "--cache-dir", str(self.root / "cache"),
            "--client-binary", str(self.root / "missing-kfuzz"),
            "--variant", "delivery_value"])
        self.assertEqual(code, 1)
        self.assertFalse(output.exists())

    def test_run_mode_refuses_an_existing_output_root(self):
        source = write_source_run(self.root / "source", all_variant_cases())
        output = self.root / "already-there"
        output.mkdir()
        (output / "keep.txt").write_text("keep\n", encoding="utf-8")
        code = self.module.main([
            "run", "--continuous-run", str(source),
            "--output-root", str(output),
            "--cache-dir", str(self.root / "cache"),
            "--client-binary", str(self.fake_client()),
            "--variant", "delivery_value"])
        self.assertEqual(code, 1)
        self.assertEqual((output / "keep.txt").read_text(encoding="utf-8"),
                         "keep\n")


# --------------------------------------------------------------------------
# 3. 运行模式（软件注入的假会话；CLI 默认走真实 RTL）
# --------------------------------------------------------------------------

class SessionRunnerContractTest(unittest.TestCase):
    """调用点与真实运行器的关键字集合必须一致（软件，无 RTL）。"""

    def test_default_session_runner_accepts_every_call_site_keyword(self):
        module = load_script()
        import inspect

        keywords = module._session_runner_kwargs(
            spec=object(), witness=object(), output_dir=Path("out"),
            cache_dir=Path("cache"), client_binary=Path("bin"),
            budget={"duration_seconds": 1.0}, runtime_profile={},
            command="python3 scripts/run_p5_fault_calibration_family.py run ...")
        parameters = inspect.signature(module._default_session_runner).parameters
        # 一条真实的 `run` 调用会因为缺键或多键而 TypeError；这里在软件里
        # 提前断言同一件事，避免"整轮 9 个变体全部 error"这种只能靠真实会话
        # 才暴露的签名漂移。
        self.assertEqual(set(keywords) - set(parameters), set())
        for name in keywords:
            self.assertEqual(parameters[name].kind,
                             inspect.Parameter.KEYWORD_ONLY)
        # 反过来：真实运行器不能有调用点没提供的必填参数，否则真实会话会在
        # 构造运行时之前就 TypeError。
        required = {name for name, parameter in parameters.items()
                    if parameter.default is inspect.Parameter.empty}
        self.assertEqual(required - set(keywords), set())


class ReceiptCaseIdTest(unittest.TestCase):
    """会话收据 → case id：两种 shipped 形状都要能读（软件，无 RTL）。"""

    def test_reads_both_shipped_receipt_shapes_and_refuses_the_rest(self):
        module = load_script()

        class Live:
            #: The live writer's receipt has no case_id attribute.
            online_case = {"case_id": "online-2-abc"}

        class Slim:
            case_id = "online-1-def"

        self.assertEqual(module._receipt_case_id(Live()), "online-2-abc")
        self.assertEqual(module._receipt_case_id(Slim()), "online-1-def")
        self.assertEqual(module._receipt_case_id({"case_id": "online-0-ghi"}),
                         "online-0-ghi")
        # 没有 case 身份的收据（例如解码拒绝）绝不能猜出一个 id。
        self.assertIsNone(module._receipt_case_id(object()))
        self.assertIsNone(module._receipt_case_id({"case_id": None}))
        self.assertIsNone(module._receipt_case_id(type(
            "X", (), {"online_case": {"case_id": 7}})()))


class FamilyFindingsTest(_TempCase):
    """默认运行器读的是 shipped API：观测里的 checker_findings。

    软件夹具用真实 ``ControlledFaultFamily.inject()`` 的返回值做对照，因此
    "读了 family 上不存在的属性" 这类错误会在软件阶段被抓住。
    """

    def test_derivation_matches_the_inject_result(self):
        module = self.module
        source = write_source_run(self.root / "source", all_variant_cases())
        selection = module.select_witnesses([source])
        witness = selection.witnesses["observation_irq_level"]
        events = case_window(source, witness.selector["case_id"])
        self.assertTrue(events)
        family = module.ControlledFaultFamily.from_document(witness.document)
        receipt = module.OnlineCaseReceipt(witness.selector["case_id"], 0,
                                           len(events), tuple(events), {}, {},
                                           "running")
        run = family.inject(receipt)
        self.assertTrue(run.injected_findings)
        self.assertEqual(module._family_injected_findings(family),
                         run.injected_findings)


class RunModeTest(_TempCase):
    """用软件假会话驱动 run 模式的全部写入路径，不启动任何 RTL。"""

    def _fake_runner(self, *, finding: bool = True, fail_on: str | None = None,
                     finding_absent_in_family: bool = False):
        module = self.module

        def runner(*, spec, witness, output_dir, cache_dir, client_binary,
                   budget, runtime_profile, command):
            if fail_on is not None and spec.variant == fail_on:
                raise RuntimeError("synthetic session failure")
            case_id = witness.selector["case_id"]
            events = case_window(Path(witness.source_run["resolved"]), case_id)
            self.assertTrue(events, f"no saved window for {case_id}")
            document = witness.document
            family = module.ControlledFaultFamily.from_document(document)
            receipt = module.OnlineCaseReceipt(case_id, 0, len(events), events,
                                               {}, {}, "running")
            run = family.inject(receipt)
            expected = spec.expected_finding
            violations = [expected] if (finding and not finding_absent_in_family) else []
            output_dir.mkdir(parents=True, exist_ok=False)
            (output_dir / "online_final_trace.json").write_text(
                json.dumps({"events": list(events), "status": "running",
                            "local_ticks": {}}, sort_keys=True) + "\n",
                encoding="utf-8")
            (output_dir / "receipts.jsonl").write_text(json.dumps(
                {"case_id": case_id, "status": "dut_violation" if violations else "complete",
                 "violations": violations}, sort_keys=True) + "\n", encoding="utf-8")
            if not violations:
                return {"tests": 1, "statuses": {"complete": 1},
                        "effective_search_seconds": 1.0, "violations": [],
                        "family_findings": [], "finding_ids": [],
                        "case_status": "complete", "case_violations": [],
                        "minimal_replay": None,
                        "minimal_replay_error": "ControlledFaultCalibrationError: "
                                                "no controlled fault was calibrated",
                        "runtime_profile": dict(runtime_profile)}
            return {"tests": 1, "statuses": {"dut_violation": 1},
                    "effective_search_seconds": 1.0, "violations": violations,
                    "family_findings": list(run.injected_findings),
                    "finding_ids": [observation.finding_id
                                    for observation in run.observations],
                    "case_status": "dut_violation",
                    "case_violations": violations,
                    "minimal_replay": family.minimal_replay_document(),
                    "minimal_replay_error": None,
                    "runtime_profile": dict(runtime_profile)}

        return runner

    def calibrate(self, output_root: Path, source_run: Path, *extra, **kwargs):
        return self.module.main([
            "run", "--continuous-run", str(source_run),
            "--output-root", str(output_root),
            "--cache-dir", str(self.root / "cache"),
            "--client-binary", str(self.fake_client()),
            *extra], **kwargs)

    def test_calibrated_variant_writes_every_document(self):
        source = write_source_run(self.root / "source", all_variant_cases())
        output = self.root / "calibration"
        code = self.calibrate(output, source, "--variant", "observation_irq_level",
                              session_runner=self._fake_runner())
        self.assertEqual(code, 0)
        variant_dir = output / "observation_irq_level"
        self.assertTrue((variant_dir / "fault_document.json").is_file())
        self.assertTrue((variant_dir / "fault_run_summary.json").is_file())
        self.assertTrue((variant_dir / "minimal_replay.json").is_file())
        self.assertFalse((variant_dir / "minimal_replay.error").exists())
        aggregate = json.loads((output / "fault_family_calibration.json")
                               .read_text(encoding="utf-8"))
        entry = aggregate["variants"][0]
        self.assertEqual(entry["status"], self.module.STATUS_CALIBRATED)
        self.assertEqual(entry["expected_finding"], CONTROL_FINDING)
        self.assertEqual(entry["observed_findings"], [CONTROL_FINDING])
        self.assertIn(CONTROL_FINDING, entry["family_findings"])
        self.assertEqual(entry["case_id"], "case-observation_irq_level")
        self.assertEqual(entry["run"]["statuses"], {"dut_violation": 1})
        replay = json.loads((variant_dir / "minimal_replay.json")
                            .read_text(encoding="utf-8"))
        self.assertEqual(replay["schema_version"], self.module.REPLAY_SCHEMA_VERSION)
        self.assertIs(replay["calibration_only"], True)
        self.assertEqual(replay["fault_document_sha256"],
                         canonical_sha256(replay["fault_document"]))

    def test_not_fired_variant_records_null_and_reason(self):
        source = write_source_run(self.root / "source", all_variant_cases())
        output = self.root / "calibration-not-fired"
        code = self.calibrate(output, source, "--variant", "delivery_value",
                              session_runner=self._fake_runner(finding=False))
        self.assertEqual(code, 3)
        variant_dir = output / "delivery_value"
        self.assertTrue((variant_dir / "minimal_replay.error").is_file())
        self.assertFalse((variant_dir / "minimal_replay.json").exists())
        aggregate = json.loads((output / "fault_family_calibration.json")
                               .read_text(encoding="utf-8"))
        entry = aggregate["variants"][0]
        self.assertEqual(entry["status"], self.module.STATUS_NOT_FIRED)
        self.assertEqual(entry["observed_findings"], [])
        self.assertIn("未报告", entry["reason"])
        self.assertIn(self.module.SPEC_BY_VARIANT["delivery_value"].expected_finding,
                      entry["reason"])
        self.assertIsNone(entry["minimal_replay"])

    def test_session_error_is_recorded_and_other_variants_continue(self):
        source = write_source_run(self.root / "source", all_variant_cases())
        output = self.root / "calibration-error"
        code = self.calibrate(
            output, source,
            "--variant", "delivery_value", "--variant", "observation_irq_level",
            session_runner=self._fake_runner(fail_on="delivery_value"))
        self.assertEqual(code, 3)
        aggregate = json.loads((output / "fault_family_calibration.json")
                               .read_text(encoding="utf-8"))
        entries = {entry["variant"]: entry for entry in aggregate["variants"]}
        self.assertEqual(entries["delivery_value"]["status"],
                         self.module.STATUS_ERROR)
        self.assertIn("synthetic session failure",
                      entries["delivery_value"]["reason"])
        self.assertIsNone(entries["delivery_value"]["observed_findings"])
        error_dir = output / "delivery_value"
        self.assertTrue((error_dir / "fault_run_summary.json").is_file())
        self.assertTrue((error_dir / "minimal_replay.error").is_file())
        summary = json.loads((error_dir / "fault_run_summary.json")
                             .read_text(encoding="utf-8"))
        self.assertEqual(summary["status"], self.module.STATUS_ERROR)
        self.assertIn("synthetic session failure", summary["error"])
        self.assertEqual(entries["observation_irq_level"]["status"],
                         self.module.STATUS_CALIBRATED)


# --------------------------------------------------------------------------
# 4. 独立复核器
# --------------------------------------------------------------------------

class AnchorTickTest(unittest.TestCase):
    """每个变体只钉住一对 (tick, 承载事件)；另一对缺失不得报成"缺少锚点"。"""

    def test_only_a_pinned_pair_is_compared(self):
        module = load_script()
        events = {7: {"event_id": 7, "local_tick": 5}}
        selector = {"local_tick": 5, "insert_before_event_id": 7}
        self.assertIsNone(module._anchor_tick_failure(
            selector, "local_tick", "insert_before_event_id", events, "control"))
        # cpu_event_id 不在这个变体的选择器里——跳过，而不是报缺少事件。
        self.assertIsNone(module._anchor_tick_failure(
            selector, "local_tick", "cpu_event_id", events, "control"))
        # 真正钉住却缺失的事件仍然失败。
        self.assertIn("缺少", module._anchor_tick_failure(
            {"local_tick": 5, "cpu_event_id": 9}, "local_tick", "cpu_event_id",
            events, "control"))
        # 钉住的事件 tick 不同仍然失败。
        self.assertIn("不一致", module._anchor_tick_failure(
            {"local_tick": 6, "insert_before_event_id": 7}, "local_tick",
            "insert_before_event_id", events, "control"))


class VerifierTest(_TempCase):
    def build_calibration(self, output_root: Path, source: Path,
                          variants=("observation_irq_level", "delivery_value")):
        runner = RunModeTest._fake_runner(self)
        argv = ["run", "--continuous-run", str(source),
                "--output-root", str(output_root),
                "--cache-dir", str(self.root / "cache"),
                "--client-binary", str(self.fake_client())]
        for variant in variants:
            argv += ["--variant", variant]
        code = self.module.main(argv, session_runner=runner)
        self.assertEqual(code, 0)
        return json.loads((output_root / "fault_family_calibration.json")
                          .read_text(encoding="utf-8"))

    def setUp(self) -> None:
        super().setUp()
        self.source = write_source_run(self.root / "source", all_variant_cases())
        self.calibration = self.root / "calibration"
        self.aggregate = self.build_calibration(self.calibration, self.source)

    def verify(self):
        return self.module.verify_calibration(self.calibration)

    def fault_session(self, variant: str) -> Path:
        return self.calibration / variant / "session"

    def test_accepts_a_consistent_calibration(self):
        report = self.verify()
        self.assertTrue(report["ok"], report["failures"])
        self.assertEqual(report["schema_version"],
                         self.module.VERIFY_SCHEMA_VERSION)
        self.assertEqual([item["variant"] for item in report["variants"]],
                         ["observation_irq_level", "delivery_value"])
        for item in report["variants"]:
            self.assertTrue(
                item["ok"], [check for check in item["checks"] if not check["ok"]])

    def test_refuses_when_the_finding_is_absent_from_the_fault_run(self):
        variant_dir = self.fault_session("observation_irq_level")
        (variant_dir / "receipts.jsonl").write_text(json.dumps(
            {"case_id": "case-observation_irq_level", "status": "complete",
             "violations": []}, sort_keys=True) + "\n", encoding="utf-8")
        report = self.verify()
        self.assertFalse(report["ok"])
        reason = " ".join(item["reason"] for item in report["failures"])
        self.assertIn(CONTROL_FINDING, reason)
        self.assertIn("observation_irq_level", reason)

    def test_refuses_when_the_anchored_field_differs(self):
        trace_path = self.fault_session("observation_irq_level") / "online_final_trace.json"
        document = json.loads(trace_path.read_text(encoding="utf-8"))
        for event in document["events"]:
            if event.get("event_id") == 1:
                event["outputs"]["irq"] = 0
                event["outputs"]["interrupt"] = 0
        trace_path.write_text(json.dumps(document, sort_keys=True) + "\n",
                              encoding="utf-8")
        report = self.verify()
        self.assertFalse(report["ok"])
        reason = " ".join(item["reason"] for item in report["failures"])
        self.assertIn("event_id=1", reason)
        self.assertIn("outputs.irq", reason)

    def test_refuses_when_the_control_trace_bytes_changed(self):
        trace_path = self.source / "online_final_trace.json"
        document = json.loads(trace_path.read_text(encoding="utf-8"))
        document["events"][0]["outputs"]["irq"] = 0
        trace_path.write_text(json.dumps(document, sort_keys=True) + "\n",
                              encoding="utf-8")
        report = self.verify()
        self.assertFalse(report["ok"])
        reason = " ".join(item["reason"] for item in report["failures"])
        self.assertIn("sha256", reason)

    def test_refuses_a_non_canonical_fault_document(self):
        variant_dir = self.calibration / "delivery_value"
        document = json.loads((variant_dir / "fault_document.json")
                              .read_text(encoding="utf-8"))
        document["faults"][0]["fault_id"] = "p5_controlled_fault_wrong_irq_0" * 1
        (variant_dir / "fault_document.json").write_text(
            json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
        report = self.verify()
        self.assertFalse(report["ok"])
        reason = " ".join(item["reason"] for item in report["failures"])
        self.assertIn("fault_id", reason)

    def test_refuses_when_the_control_run_reports_the_finding(self):
        receipts = self.source / "receipts.jsonl"
        receipts.write_text(json.dumps(
            {"case_id": "case-observation_irq_level", "status": "dut_violation",
             "violations": [CONTROL_FINDING]}, sort_keys=True) + "\n",
            encoding="utf-8")
        report = self.verify()
        self.assertFalse(report["ok"])
        reason = " ".join(item["reason"] for item in report["failures"])
        self.assertIn("control", reason)
        self.assertIn(CONTROL_FINDING, reason)

    def test_main_exit_codes(self):
        self.assertEqual(self.module.main(["verify", "--calibration-root",
                                           str(self.calibration)]), 0)
        variant_dir = self.fault_session("delivery_value")
        (variant_dir / "receipts.jsonl").write_text("", encoding="utf-8")
        self.assertEqual(self.module.main(["verify", "--calibration-root",
                                           str(self.calibration)]), 4)


if __name__ == "__main__":
    unittest.main()
