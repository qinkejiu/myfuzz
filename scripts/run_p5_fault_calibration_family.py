#!/usr/bin/env python3
"""P5 受控故障族**真实校准运行器**与**独立复核器**（fail-closed）。

用途（软件优先，真实 RTL 由调用方串行触发）
--------------------------------------------
对 ``p5_fault_family.py`` 的 9 个变体，逐个在**已保存的真实在线运行事件**里
选择精确见证窗口（真实 case_id / 事件 ID / tick / 原值；键集合严格等于该变体在
``_SPECS`` 里声明的 ``selector_keys``），据此构造并校验
``p5_controlled_fault.v1`` 文档，然后用与既有单变体门禁完全相同的调用方式启动
一次**新的真实在线会话**（``make_ibex_*_online_runtime(checker=family)`` +
``run_scenario_rfuzz_live``，默认 120 s / 24 例 / seed 20261007 /
``max_runs_per_batch=1``），最后写出逐变体产物与一份版本化汇总
``fault_family_calibration.json``。

硬边界
------
* **只读源运行目录**：选择阶段只流式读取（``TraceEventStream``），扫描前后各做一次
  目录指纹（名字/大小/mtime 清单 SHA-256）并要求相等；源目录内不写任何文件。
* **不伪造**：见证锚点找不到就是 ``no_witness_window``（``selector`` 与文档为
  ``null`` 并给出精确原因）；扰动后既有 checker 不变量没触发就是 ``not_fired``；
  抛错就是 ``error``。任何一条都不会被写成 ``calibrated``。
* **与运行时同一套定位器**：发现阶段直接复用故障族模块自己的
  ``_LOCATORS``/``_Search``（与 ``family.inject`` 注入时同一函数），因此选择规则
  与真实注入规则不可能漂移；钉住后的文档必须再由
  ``ControlledFaultFamily.from_document`` 严格校验，并在同一窗口上**第二次**注入
  复现同一 ``finding_id``。
* **不改真实 DUT**：注入只作用于交给 checker 的 deepcopy 事件副本；复核器逐字段
  比对控制/故障两份真实 trace 的锚点事件，并核对控制 trace 文件 SHA-256 未变。
* ``session_runner`` 形参只用于**软件测试注入**（用保存事件驱动 run 模式的全部写入
  路径）；CLI 永远使用真实 RTL 会话（``_default_session_runner``）。

状态（汇总 ``variants[].status``）
----------------------------------
``selected``          仅 ``--select-only``：见证与文档已定，未启动任何 RTL。
``calibrated``        真实会话中声明的既有不变量确实触发（收据 + 故障族 finding 双证）。
``no_witness_window`` 保存事件里没有该变体的见证锚点（``selector``/文档为 ``null``+原因）。
``not_fired``         会话跑完但没报告期望 finding（``observed_findings`` 如实记录）。
``error``             会话或产物写入抛错（``reason`` 为异常类型与消息）。

退出码
------
``0`` 全部请求变体达到目标状态；``1`` 参数/路径/IO 错误；``3`` 有变体未达标；
``4`` ``verify`` 发现不一致。
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.as_posix() not in sys.path:
    sys.path.insert(0, SRC.as_posix())

from myfuzz.scenario.acceptance_metrics import TraceEventStream  # noqa: E402
from myfuzz.scenario.p5_fault_family import (  # noqa: E402
    FAULT_SCHEMA_VERSION,
    REPLAY_SCHEMA_VERSION,
    ControlledFaultCalibrationError,
    ControlledFaultConfigError,
    ControlledFaultFamily,
    _CHECKER_FACTORIES,
    _LOCATORS,
    _SPECS,
    _Search,
    _VariantSpec,
    _canonical_sha256,
    _field_value,
)
from myfuzz.scenario.session_runtime import OnlineCaseReceipt  # noqa: E402


SCHEMA_VERSION = "p5_fault_family_calibration.v1"
VERIFY_SCHEMA_VERSION = "p5_fault_family_calibration_verify.v1"

STATUS_SELECTED = "selected"
STATUS_CALIBRATED = "calibrated"
STATUS_NO_WITNESS = "no_witness_window"
STATUS_NOT_FIRED = "not_fired"
STATUS_ERROR = "error"

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_INCOMPLETE = 3
EXIT_VERIFY_FAILED = 4

DEFAULT_DURATION_SECONDS = 120.0
DEFAULT_MAX_TESTS = 24
DEFAULT_SEARCH_SEED = 20261007
DEFAULT_MAX_RUNS_PER_BATCH = 1
DEFAULT_CLIENT_BINARY = (
    "third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz")

#: 每个 checker 的候选源运行（按优先级）：只放**已核实真的带有所需事件字段**的运行。
#: * ``ibex_pulp_online``：24 例的 paired 运行（既有真实 IRQ 门禁的同一份控制运行，
#:   已验证同 seed 会复现相同 case 身份），备选是 368 例的 600 s chain 运行。
#: * ``ibex_uart_online``：UART 异构门禁运行（唯一带 UART 0x18 RXDATA 读/响应对的运行）。
CANDIDATE_SOURCE_RUNS = {
    "ibex_pulp_online": (
        "runs/current-dataflow-p5-paired-20261007-online",
        "runs/current-dataflow-p5-chain-600s-20261007-online",
    ),
    "ibex_uart_online": ("runs/p5-uart-gate2-20261007-online",),
}

#: 新会话的运行时开关：逐字照抄**源运行自己的声明**，不引入新默认。
#: * ``ibex_pulp_online``：`runs/current-dataflow-p5-final-20261007-logs/fault_calibration_gate.py`
#:   与真实 IRQ 校准报告里的门禁调用（RVFI 退休 + GPIO 消费 + 原生 IRQ 收据）。
#: * ``ibex_uart_online``：UART 异构门禁报告里的真实运行命令
#:   （RVFI + UART FIFO + memory commit/readback + WDATA lane0 字节写）。
RUNTIME_PROFILES = {
    "ibex_pulp_online": {"cpu_retirement": True, "gpio_consumption": True,
                         "native_irq_receipts": True},
    "ibex_uart_online": {"cpu_retirement": True, "uart_fifo": True,
                         "memory_commit": True, "memory_readback": True,
                         "uart_wdata_byte_store": True},
}

_OBSERVATION_BOUNDARY = "checker_input_copy"
_ENTRY_KEYS = ("kind", "variant", "checker", "expected_finding", "operation",
               "selector", "mutation")
#: case 边界的哨兵：与任何真实 case_id（含 None）都不相等。
_UNSET = object()
_FIELD_READERS = ("outputs.irq", "inputs.irq", "inputs.gpio_in",
                  "outputs.data_rsp_rdata", "read_value", "value")
_COMMAND_TEMPLATE = (
    "PYTHONPATH=src python3 scripts/run_p5_fault_calibration_family.py run"
    " --continuous-run {source} --output-root {output} --cache-dir {cache}"
    " --client-binary {client} --variant {variant}")

_LIMITS = (
    "verify 只读取已保存产物：它证明校准产物自洽、控制/故障两份真实 trace 的锚点"
    "事件逐字段相同、控制 trace 文件字节未变；它不重新运行 RTL，也不证明新进程复现。",
    "选择器只钉住本报告记录的事件 ID / tick / 原值；跨 case 边界的见证不会被利用"
    "（同一个 receipt 内才注入）。",
    "单变体 status=calibrated 只表示该变体在本轮真实会话中触发了声明的既有不变量，"
    "不表示对该故障类的检测灵敏度。",
    "故障注入只改交给 checker 的观测副本，不能用于声称 DUT 缺陷；本运行的 finding "
    "一律 calibration_only，绝不并入自然缺陷统计。",
)


class CalibrationError(RuntimeError):
    """校准流程前置条件不满足（参数、路径、只读性、模块契约漂移）。"""


def _canonical_text(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _directory_fingerprint(run_dir: Path) -> dict:
    """源运行目录的只读指纹：名字/大小/mtime 清单的 SHA-256。"""
    entries = []
    total = 0
    for path in sorted(Path(run_dir).rglob("*")):
        if path.is_dir():
            continue
        stat = path.stat()
        entries.append(
            f"{path.relative_to(run_dir).as_posix()}:{stat.st_size}:{stat.st_mtime_ns}")
        total += stat.st_size
    return {"files": len(entries), "bytes": total,
            "listing_sha256": hashlib.sha256(
                "\n".join(entries).encode("utf-8")).hexdigest()}


def _case_of(event: Mapping) -> str | None:
    provenance = event.get("provenance")
    observed = provenance.get("observed_case") if isinstance(provenance, Mapping) else None
    if isinstance(observed, Mapping) and isinstance(observed.get("case_id"), str):
        return observed["case_id"]
    return None


SPEC_BY_VARIANT = {spec.variant: spec for spec in _SPECS}


def resolve_specs(names: Sequence[str] | None) -> tuple[_VariantSpec, ...]:
    """按 ``_SPECS`` 声明顺序解析 ``--variant``（接受 ``variant``、``kind/variant``）。"""
    if not names:
        return tuple(_SPECS)
    requested = set()
    for name in names:
        key = str(name).replace(":", "/").split("/")[-1].strip()
        if key not in SPEC_BY_VARIANT:
            raise CalibrationError(
                f"unknown variant {name!r}; known variants: "
                f"{', '.join(spec.variant for spec in _SPECS)}")
        requested.add(key)
    return tuple(spec for spec in _SPECS if spec.variant in requested)


# --------------------------------------------------------------------------
# 见证窗口选择
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Witness:
    """一个**被见证**的注入锚点：选择器取值全部来自真实事件字段。"""

    kind: str
    variant: str
    checker: str
    expected_finding: str
    operation: str
    mutated_field: str
    case_id: str
    selector: dict
    mutation: dict
    observation_event_id: int | None
    related_event_ids: dict
    original_value: int | None
    injected_value: int | None
    event_id_shift: int
    inserted_checker_input_event_id: int | None
    finding_id: str
    document: dict
    window: dict
    source_run: dict


@dataclass(frozen=True)
class Selection:
    witnesses: dict
    reasons: dict
    scans: tuple
    specs: tuple

    @property
    def complete(self) -> bool:
        return all(spec.variant in self.witnesses for spec in self.specs)


def _replacement_for(spec: _VariantSpec, original: object) -> int | None:
    """由**被见证的原值**推导替换值：必须与观测到该值不同且在声明范围内。"""
    if spec.replacement == "forbidden":
        return None
    if type(original) is not int:
        raise CalibrationError(
            f"{spec.kind}/{spec.variant} 的见证锚点没有整数原值 {original!r}")
    if spec.irq_level:
        return 0 if original != 0 else 1
    if spec.bit_clear:
        return original & ~1
    if spec.maximum is not None:
        return (original + 1) & spec.maximum
    return (original + 1) & 0xffffffff


def _entry_for(spec: _VariantSpec, selector: Mapping,
               replacement: int | None) -> dict:
    return {"kind": spec.kind, "variant": spec.variant, "checker": spec.checker,
            "expected_finding": spec.expected_finding,
            "operation": spec.operation, "selector": dict(selector),
            "mutation": {"field": spec.field, "replacement": replacement}}


def _document_for(entry: Mapping) -> dict:
    return {"schema_version": FAULT_SCHEMA_VERSION, "faults": [dict(entry)]}


def _process_case(case_id: str, events: list, specs: Sequence[_VariantSpec],
                  witnesses: dict, issues: list,
                  source_run: Mapping) -> None:
    """在一个 case 窗口上（与运行时同一个 receipt 语义）尝试每个待定变体。"""
    receipt = OnlineCaseReceipt(case_id, 0, len(events), tuple(events), {}, {},
                                "running")
    window = {"first_event_id": events[0].get("event_id"),
              "last_event_id": events[-1].get("event_id"),
              "event_count": len(events)}
    for spec in specs:
        if spec.variant in witnesses:
            continue
        anchor = _LOCATORS[(spec.kind, spec.variant)](
            _Search(events, strict=False), {})
        if anchor is None:
            continue
        try:
            replacement = _replacement_for(spec, anchor.get("original_value"))
            family = ControlledFaultFamily.from_document(
                _document_for(_entry_for(spec, {}, replacement)))
            run = family.inject(receipt)
        except (ControlledFaultConfigError, ControlledFaultCalibrationError) as exc:
            issues.append(f"{spec.variant}@{case_id}: {type(exc).__name__}: {exc}")
            continue
        if not run.observations:
            issues.append(
                f"{spec.variant}@{case_id}: 定位到锚点但扰动后没有 finding")
            continue
        observation = run.observations[0]
        pinned = observation.pinned_entry
        if set(pinned["selector"]) != set(spec.selector_keys):
            raise CalibrationError(
                f"{spec.variant} 的钉住选择器键集合与 _SPECS 声明不一致: "
                f"{sorted(pinned['selector'])} != {sorted(spec.selector_keys)}")
        # 第二次独立注入：钉住配置必须在同一窗口复现同一 finding。
        again = ControlledFaultFamily.from_document(
            _document_for(pinned)).inject(receipt)
        if not again.observations or (again.observations[0].finding_id
                                      != observation.finding_id):
            issues.append(
                f"{spec.variant}@{case_id}: 钉住配置未能复现同一 finding")
            continue
        chain = observation.finding["source_chain"]
        witnesses[spec.variant] = Witness(
            kind=spec.kind, variant=spec.variant, checker=spec.checker,
            expected_finding=spec.expected_finding, operation=spec.operation,
            mutated_field=spec.field, case_id=case_id,
            selector=dict(pinned["selector"]),
            mutation=dict(pinned["mutation"]),
            observation_event_id=chain["observation_event_id"],
            related_event_ids=dict(chain["related_event_ids"]),
            original_value=chain["original_value"],
            injected_value=chain["injected_value"],
            event_id_shift=chain["event_id_shift"],
            inserted_checker_input_event_id=chain["inserted_checker_input_event_id"],
            finding_id=observation.finding_id,
            document=_document_for(pinned), window=dict(window),
            source_run=dict(source_run))


def _scan_run(run_dir: Path, specs: Sequence[_VariantSpec], witnesses: dict,
              issues: list, *, max_cases: int | None) -> dict:
    """流式扫描一个源运行：按 case 边界增量处理，内存只保留当前 case。"""
    if not run_dir.is_dir():
        raise CalibrationError(f"source run directory does not exist: {run_dir}")
    try:
        stream = TraceEventStream(run_dir)
    except ValueError as exc:
        raise CalibrationError(
            f"source run has no streamable event artifact: {run_dir}: {exc}") from exc
    trace_file = stream.descriptor["events_file"]
    before = _directory_fingerprint(run_dir)
    trace_sha256 = _file_sha256(stream.path)
    run_record = {
        "path": str(run_dir), "resolved": str(run_dir.resolve()),
        "trace_file": trace_file, "trace_format": stream.descriptor["format"],
        "trace_bytes": stream.descriptor["bytes"], "trace_sha256": trace_sha256,
        "max_cases": max_cases, "cases_scanned": 0, "events_scanned": 0,
        "complete_scan": False, "stopped_early": False,
        "case_ids": [],
    }
    pending = [spec for spec in specs if spec.variant not in witnesses]
    current: object = _UNSET
    buffer: list = []
    seen_cases: set = set()
    stopped = False

    def close(group_case_id: str, group: list) -> bool:
        """处理一个已闭合的 case；返回是否应当停止扫描。"""
        nonlocal stopped
        run_record["cases_scanned"] += 1
        run_record["case_ids"].append(group_case_id)
        source_run = {
            "path": run_record["path"], "resolved": run_record["resolved"],
            "trace_file": trace_file, "trace_format": run_record["trace_format"],
            "trace_bytes": run_record["trace_bytes"],
            "trace_sha256": trace_sha256, "cases_scanned": run_record["cases_scanned"],
            "events_scanned": run_record["events_scanned"],
            "complete_scan": False, "max_cases": max_cases,
        }
        _process_case(group_case_id, group, pending, witnesses, issues, source_run)
        if not any(spec.variant not in witnesses for spec in pending):
            stopped = True
            run_record["stopped_early"] = True
            return True
        if max_cases is not None and run_record["cases_scanned"] >= max_cases:
            stopped = True
            run_record["stopped_early"] = True
            return True
        return False

    for event in stream.events():
        run_record["events_scanned"] += 1
        case_id = _case_of(event)
        if current is _UNSET or case_id != current:
            if current is not _UNSET and buffer and current is not None:
                if close(current, buffer):
                    break
            if case_id is not None:
                if case_id in seen_cases:
                    raise CalibrationError(
                        f"case id {case_id!r} appears in two non-adjacent groups "
                        f"of {run_dir}; 见证窗口有歧义")
                seen_cases.add(case_id)
            current = case_id
            buffer = []
        buffer.append(event)
    else:
        if buffer and current is not _UNSET and current is not None:
            close(current, buffer)
    run_record["complete_scan"] = not stopped and stream.exhausted
    after = _directory_fingerprint(run_dir)
    if after != before:
        raise CalibrationError(
            f"source run directory changed during the read-only scan: {run_dir}")
    run_record["read_only"] = {"unchanged": True, **before}
    return run_record


def select_witnesses(source_runs: Sequence[Path], *,
                     variants: Sequence[str] | None = None,
                     max_cases: int | None = None) -> Selection:
    """在给定源运行（按顺序）里为每个变体选择**首个**见证窗口。

    早期停止是安全的：每个变体取工件顺序上的第一个见证，后续 case 不会改变它。
    未找到的变体在 ``reasons`` 里给出精确原因（扫了多少 case/事件、是否全量扫描），
    绝不编造索引或取值。
    """
    specs = resolve_specs(variants)
    witnesses: dict = {}
    issues: list = []
    scans: list = []
    tried: dict = {spec.variant: [] for spec in specs}
    for run_dir in source_runs:
        pending = [spec for spec in specs if spec.variant not in witnesses]
        if not pending:
            break
        record = _scan_run(Path(run_dir), pending, witnesses, issues, max_cases=max_cases)
        scans.append(record)
        for spec in pending:
            tried[spec.variant].append(record)
    reasons = {}
    for spec in specs:
        if spec.variant in witnesses:
            continue
        parts = [f"no witnessed anchor for {spec.kind}/{spec.variant}"]
        records = tried[spec.variant] or scans
        if records:
            parts.append("candidate source runs: " + "; ".join(
                f"{record['path']}[cases={record['cases_scanned']},"
                f"events={record['events_scanned']},"
                f"scan={'full' if record['complete_scan'] else 'stopped_early'}]"
                for record in records))
        relevant = [item for item in issues if item.startswith(f"{spec.variant}@")]
        if relevant:
            parts.append("located anchors that did not fire: " + "; ".join(relevant))
        reasons[spec.variant] = " | ".join(parts)
    return Selection(witnesses=witnesses, reasons=reasons,
                     scans=tuple(scans), specs=specs)


# --------------------------------------------------------------------------
# 真实在线会话（唯一会启动 RTL 的路径）
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class SessionOutcome:
    tests: int
    statuses: dict
    effective_search_seconds: float | None
    violations: tuple
    family_findings: tuple
    finding_ids: tuple
    case_status: str | None
    case_violations: tuple
    minimal_replay: dict | None
    minimal_replay_error: str | None
    runtime_profile: dict


def _normalize_outcome(value: object) -> SessionOutcome:
    if isinstance(value, SessionOutcome):
        return value
    if isinstance(value, Mapping):
        return SessionOutcome(
            tests=int(value.get("tests") or 0),
            statuses=dict(value.get("statuses") or {}),
            effective_search_seconds=value.get("effective_search_seconds"),
            violations=tuple(value.get("violations") or ()),
            family_findings=tuple(value.get("family_findings") or ()),
            finding_ids=tuple(value.get("finding_ids") or ()),
            case_status=value.get("case_status"),
            case_violations=tuple(value.get("case_violations") or ()),
            minimal_replay=value.get("minimal_replay"),
            minimal_replay_error=value.get("minimal_replay_error"),
            runtime_profile=dict(value.get("runtime_profile") or {}))
    raise CalibrationError(f"session runner returned {type(value).__name__}")


def _family_injected_findings(family) -> tuple:
    """The findings a real session's injections actually produced.

    ``ControlledFaultFamily`` exposes per-observation ``checker_findings``; the
    per-run ``injected_findings`` tuple lives on the object ``inject()`` returns,
    which only the runtime sees.  This derives the same ordered, de-duplicated
    tuple from the family's own observations (the shipped ``inject`` builds it by
    extending the same ``chain_findings``), so the real-session summary reads the
    shipped API instead of an attribute that does not exist.
    """
    return tuple(dict.fromkeys(
        finding for observation in family.observations
        for finding in observation.checker_findings))


def _receipt_case_id(receipt) -> str | None:
    """One session receipt's case id, whichever shipped shape carries it.

    ``ScenarioRfuzzReceipt`` (what the live writer returns) has no ``case_id``
    attribute; its decoded case document does.  Rows read back from
    ``receipts.jsonl`` carry the key at the top level.  Reading both shapes here
    keeps the session runner from dying on the summary step *after* a real
    session already ran.
    """
    value = getattr(receipt, "case_id", None)
    if isinstance(value, str):
        return value
    document = getattr(receipt, "online_case", None)
    if isinstance(document, Mapping):
        value = document.get("case_id")
        if isinstance(value, str):
            return value
    if isinstance(receipt, Mapping):
        value = receipt.get("case_id")
        if isinstance(value, str):
            return value
    return None


def _session_runner_kwargs(*, spec: _VariantSpec, witness: Witness,
                           output_dir: Path, cache_dir: Path,
                           client_binary: Path, budget: Mapping,
                           runtime_profile: Mapping,
                           command: str) -> dict:
    """唯一一处构造会话运行器关键字的地方。

    默认的真实 RTL 运行器与测试注入的假运行器都通过它取参，因此"调用点传了
    运行器不接受的键"这种签名漂移可以被一条软件断言抓住（见
    ``test_default_session_runner_accepts_every_call_site_keyword``）。
    """
    return {"spec": spec, "witness": witness, "output_dir": output_dir,
            "cache_dir": cache_dir, "client_binary": client_binary,
            "budget": budget, "runtime_profile": runtime_profile,
            "command": command}


def _default_session_runner(*, spec: _VariantSpec, witness: Witness,
                            output_dir: Path, cache_dir: Path,
                            client_binary: Path, budget: Mapping,
                            runtime_profile: Mapping,
                            command: str | None = None) -> SessionOutcome:
    """真实 RTL：构造运行时、跑一次在线会话、收集收据（与既有单变体门禁同构）。

    ``command`` 是调用方为审计记录下来的可复现命令字符串；真实会话不需要它
    （命令已经写进逐变体汇总），这里只作为签名的一部分接受，绝不据此改变行为。
    """
    del command
    from myfuzz.integration.ibex_pulp_online import make_ibex_pulp_online_runtime
    from myfuzz.integration.ibex_uart_online import make_ibex_uart_online_runtime
    from myfuzz.integration.scenario_rfuzz_live import run_scenario_rfuzz_live

    family = ControlledFaultFamily.from_document(witness.document)
    run_id = f"p5-fault-calibration-{spec.variant}"
    if spec.checker == "ibex_pulp_online":
        runtime = make_ibex_pulp_online_runtime(
            cache_dir=Path(cache_dir), run_id=run_id,
            checker=family, **dict(runtime_profile))
    elif spec.checker == "ibex_uart_online":
        runtime = make_ibex_uart_online_runtime(
            cache_dir=Path(cache_dir), run_id=run_id,
            checker=family, **dict(runtime_profile))
    else:  # pragma: no cover - 由 _SPECS 覆盖
        raise CalibrationError(f"no runtime factory for checker {spec.checker!r}")
    result = run_scenario_rfuzz_live(
        executor=runtime.executor, client_binary=Path(client_binary),
        output_dir=Path(output_dir),
        duration_seconds=budget["duration_seconds"],
        max_tests=budget["max_tests"], search_seed=budget["search_seed"],
        max_runs_per_batch=budget["max_runs_per_batch"])
    receipts = tuple(runtime.executor.receipts)
    violations = tuple(dict.fromkeys(
        item for receipt in receipts for item in (receipt.violations or ())))
    case_receipt = next((receipt for receipt in receipts
                         if _receipt_case_id(receipt) == witness.case_id), None)
    try:
        minimal_replay = family.minimal_replay_document()
        minimal_replay_error = None
    except Exception as exc:  # 无 observation 时故障族自己拒绝
        minimal_replay = None
        minimal_replay_error = f"{type(exc).__name__}: {exc}"
    return SessionOutcome(
        tests=result.tests,
        statuses=dict(result.statuses),
        effective_search_seconds=result.effective_search_seconds,
        violations=violations,
        family_findings=_family_injected_findings(family),
        finding_ids=tuple(observation.finding_id for observation in family.observations),
        case_status=None if case_receipt is None else case_receipt.status,
        case_violations=() if case_receipt is None else tuple(case_receipt.violations or ()),
        minimal_replay=minimal_replay,
        minimal_replay_error=minimal_replay_error,
        runtime_profile=dict(runtime_profile))


# --------------------------------------------------------------------------
# run / select-only
# --------------------------------------------------------------------------

def _write_json(path: Path, document: object) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(document, indent=1, sort_keys=True, allow_nan=False)
    path.write_text(text + "\n", encoding="utf-8")
    return _canonical_sha256(document)


def _path_record(path: Path) -> dict:
    return {"path": str(path), "resolved": str(Path(path).resolve())}


def _candidate_runs(spec: _VariantSpec,
                    explicit: Sequence[Path] | None) -> tuple[Path, ...]:
    if explicit:
        return tuple(Path(item) for item in explicit)
    return tuple(ROOT / relative for relative in CANDIDATE_SOURCE_RUNS[spec.checker])


def _require_streamable(run_dir: Path) -> None:
    if not Path(run_dir).is_dir():
        raise CalibrationError(f"source run directory does not exist: {run_dir}")
    try:
        TraceEventStream(Path(run_dir))
    except ValueError as exc:
        raise CalibrationError(
            f"source run has no streamable event artifact: {run_dir}: {exc}") from exc


def calibrate(*, source_runs: Sequence[Path] | None, output_root: Path,
              cache_dir: Path | None = None, client_binary: Path | None = None,
              variants: Sequence[str] | None = None,
              budget: Mapping | None = None, max_cases: int | None = None,
              select_only: bool = False,
              session_runner=None) -> dict:
    """选择见证 → 写文档 →（可选）跑真实会话 → 返回汇总文档。"""
    specs = resolve_specs(variants)
    budget = dict(budget or {
        "duration_seconds": DEFAULT_DURATION_SECONDS,
        "max_tests": DEFAULT_MAX_TESTS,
        "search_seed": DEFAULT_SEARCH_SEED,
        "max_runs_per_batch": DEFAULT_MAX_RUNS_PER_BATCH})
    output_root = Path(output_root)
    explicit = tuple(Path(item) for item in source_runs) if source_runs else None
    if explicit:
        for run_dir in explicit:
            _require_streamable(run_dir)
    else:
        for spec in specs:
            present = [path for path in _candidate_runs(spec, None) if path.is_dir()]
            if not present:
                raise CalibrationError(
                    f"no default source run exists for {spec.checker}; pass "
                    "--continuous-run explicitly")
    if not select_only:
        if cache_dir is None or client_binary is None:
            raise CalibrationError(
                "run mode requires --cache-dir and --client-binary")
        if not Path(client_binary).is_file():
            raise CalibrationError(
                f"kfuzz client binary does not exist: {client_binary}")
        if output_root.exists() and any(output_root.iterdir()):
            raise CalibrationError(
                f"run mode requires a new or empty output root: {output_root}"
                "（--select-only 的产物根不能直接复用；真实运行请换一个新的根目录）")
    output_root.mkdir(parents=True, exist_ok=True)
    runner = session_runner or _default_session_runner

    # 逐变体解析候选源运行，并按"第 N 候选"分轮扫描（早期的候选先扫，命中即停）。
    candidate_lists = {spec.variant: _candidate_runs(spec, explicit) for spec in specs}
    missing_candidates = sorted({
        str(path) for paths in candidate_lists.values() for path in paths
        if not path.is_dir()})
    for variant, paths in candidate_lists.items():
        candidate_lists[variant] = tuple(path for path in paths if path.is_dir())

    witnesses: dict = {}
    reasons: dict = {}
    scans: list = []
    issues: list = []
    depth = 0
    while any(spec.variant not in witnesses for spec in specs):
        rounds: dict = {}
        for spec in specs:
            if spec.variant in witnesses:
                continue
            paths = candidate_lists[spec.variant]
            if depth >= len(paths):
                continue
            rounds.setdefault(paths[depth], []).append(spec)
        if not rounds:
            break
        for run_dir in rounds:
            pending = rounds[run_dir]
            record = _scan_run(run_dir, pending, witnesses, issues,
                               max_cases=max_cases)
            scans.append(record)
        depth += 1
    for spec in specs:
        if spec.variant in witnesses:
            continue
        parts = [f"no witnessed anchor for {spec.kind}/{spec.variant}"]
        records = [record for record in scans
                   if str(record["path"]) in
                   [str(path) for path in candidate_lists[spec.variant]]]
        if records:
            parts.append("candidate source runs: " + "; ".join(
                f"{record['path']}[cases={record['cases_scanned']},"
                f"events={record['events_scanned']},"
                f"scan={'full' if record['complete_scan'] else 'stopped_early'}]"
                for record in records))
        if missing_candidates:
            parts.append("missing candidate runs: " + ", ".join(missing_candidates))
        relevant = [item for item in issues if item.startswith(f"{spec.variant}@")]
        if relevant:
            parts.append("located anchors that did not fire: " + "; ".join(relevant))
        reasons[spec.variant] = " | ".join(parts)

    entries = []
    for spec in specs:
        witness = witnesses.get(spec.variant)
        candidates = candidate_lists[spec.variant]
        if witness is not None:
            command_source = str(witness.source_run["path"])
        elif candidates:
            command_source = str(candidates[0])
        else:
            command_source = "MISSING_SOURCE_RUN"
        entry = {
            "kind": spec.kind, "variant": spec.variant, "checker": spec.checker,
            "status": STATUS_NO_WITNESS if witness is None else STATUS_SELECTED,
            "reason": reasons.get(spec.variant),
            "expected_finding": spec.expected_finding,
            "operation": spec.operation, "mutated_field": spec.field,
            "case_id": None, "selector": None, "mutation": None,
            "observation_event_id": None, "related_event_ids": None,
            "original_value": None, "injected_value": None,
            "finding_id": None, "window": None, "source_run": None,
            "observed_findings": None, "family_findings": None,
            "finding_ids": None,
            "fault_document": None, "minimal_replay": None,
            "minimal_replay_error": None, "run": None,
            "command": _COMMAND_TEMPLATE.format(
                source=command_source, output=output_root,
                cache=(cache_dir if cache_dir is not None else "CACHE_DIR"),
                client=(client_binary if client_binary is not None
                        else DEFAULT_CLIENT_BINARY),
                variant=spec.variant),
        }
        if witness is not None:
            variant_dir = output_root / spec.variant
            variant_dir.mkdir(parents=True, exist_ok=True)
            document_path = variant_dir / "fault_document.json"
            document_sha = _write_json(document_path, witness.document)
            entry.update({
                "status": STATUS_CALIBRATED if not select_only else STATUS_SELECTED,
                "reason": None,
                "case_id": witness.case_id,
                "selector": witness.selector,
                "mutation": witness.mutation,
                "observation_event_id": witness.observation_event_id,
                "related_event_ids": witness.related_event_ids,
                "original_value": witness.original_value,
                "injected_value": witness.injected_value,
                "finding_id": witness.finding_id,
                "window": witness.window,
                "source_run": witness.source_run,
                "fault_document": {**_path_record(document_path),
                                   "sha256": document_sha},
            })
            if select_only:
                entries.append(entry)
                continue
            # 真实会话必须拥有一个全新的输出目录，因此运行产物落在
            # <root>/<variant>/session/，而校准文档留在 <root>/<variant>/。
            output_dir = variant_dir / "session"
            try:
                outcome = _normalize_outcome(runner(**_session_runner_kwargs(
                    spec=spec, witness=witness, output_dir=output_dir,
                    cache_dir=cache_dir, client_binary=client_binary,
                    budget=budget,
                    runtime_profile=RUNTIME_PROFILES[spec.checker],
                    command=entry["command"])))
            except Exception as exc:
                entry["status"] = STATUS_ERROR
                entry["reason"] = f"{type(exc).__name__}: {exc}"
                _write_json(variant_dir / "fault_run_summary.json", {
                    "schema_version": SCHEMA_VERSION,
                    "calibration_only": True,
                    "observation_boundary": _OBSERVATION_BOUNDARY,
                    "status": STATUS_ERROR,
                    "kind": spec.kind, "variant": spec.variant,
                    "checker": spec.checker,
                    "expected_finding": spec.expected_finding,
                    "case_id": witness.case_id, "selector": witness.selector,
                    "mutation": witness.mutation,
                    "output_dir": _path_record(output_dir),
                    "error": entry["reason"], "observed_findings": None,
                    "budget": budget, "command": entry["command"],
                    "limits": list(_LIMITS)})
                error_path = variant_dir / "minimal_replay.error"
                error_path.write_text(
                    f"{entry['reason']}（会话未产出可重放的最小配置）\n",
                    encoding="utf-8")
                entry["minimal_replay_error"] = _path_record(error_path)
                entries.append(entry)
                continue
            observed = list(outcome.violations)
            entry["observed_findings"] = observed
            entry["family_findings"] = list(outcome.family_findings)
            entry["finding_ids"] = list(outcome.finding_ids)
            entry["run"] = {
                "output_dir": _path_record(output_dir),
                "tests": outcome.tests, "statuses": outcome.statuses,
                "effective_search_seconds": outcome.effective_search_seconds,
                "case_status": outcome.case_status,
                "case_violations": list(outcome.case_violations),
                "runtime_profile": outcome.runtime_profile,
            }
            summary = {
                "schema_version": SCHEMA_VERSION,
                "calibration_only": True,
                "observation_boundary": _OBSERVATION_BOUNDARY,
                "kind": spec.kind, "variant": spec.variant,
                "checker": spec.checker,
                "expected_finding": spec.expected_finding,
                "case_id": witness.case_id, "selector": witness.selector,
                "mutation": witness.mutation,
                "output_dir": _path_record(output_dir),
                "finding_ids": list(outcome.finding_ids),
                "observed_findings": observed,
                "family_findings": list(outcome.family_findings),
                "tests": outcome.tests, "statuses": outcome.statuses,
                "effective_search_seconds": outcome.effective_search_seconds,
                "violations": observed,
                "runtime_profile": outcome.runtime_profile,
                "budget": budget, "command": entry["command"],
                "limits": list(_LIMITS),
            }
            _write_json(variant_dir / "fault_run_summary.json", summary)
            if outcome.minimal_replay is not None:
                path = variant_dir / "minimal_replay.json"
                replay_sha = _write_json(path, outcome.minimal_replay)
                entry["minimal_replay"] = {**_path_record(path),
                                           "sha256": replay_sha}
            if outcome.minimal_replay_error is not None:
                path = variant_dir / "minimal_replay.error"
                path.write_text(outcome.minimal_replay_error + "\n",
                                encoding="utf-8")
                entry["minimal_replay_error"] = _path_record(path)
            if (spec.expected_finding in observed
                    and spec.expected_finding in outcome.family_findings):
                entry["status"] = STATUS_CALIBRATED
                entry["reason"] = None
            else:
                entry["status"] = STATUS_NOT_FIRED
                entry["reason"] = (
                    f"故障运行未报告 {spec.expected_finding}"
                    f"（observed={observed}, family={list(outcome.family_findings)}）；"
                    "不声称校准成功")
        entries.append(entry)

    aggregate = {
        "schema_version": SCHEMA_VERSION,
        "calibration_only": True,
        "observation_boundary": _OBSERVATION_BOUNDARY,
        "select_only": bool(select_only),
        "output_root": _path_record(output_root),
        "client_binary": (None if client_binary is None
                          else _path_record(Path(client_binary))),
        "cache_dir": (None if cache_dir is None
                      else _path_record(Path(cache_dir))),
        "budget": budget,
        "scan": {"max_cases": max_cases},
        "runtime_profiles": {name: dict(profile)
                             for name, profile in sorted(RUNTIME_PROFILES.items())},
        "source_runs": list(scans),
        "missing_candidate_runs": missing_candidates,
        "variants": entries,
        "limits": list(_LIMITS),
    }
    _write_json(output_root / "fault_family_calibration.json", aggregate)
    return aggregate


def _aggregate_statuses(aggregate: Mapping) -> dict:
    return {entry["variant"]: entry["status"] for entry in aggregate["variants"]}


def _exit_code(aggregate: Mapping) -> int:
    target = STATUS_SELECTED if aggregate.get("select_only") else STATUS_CALIBRATED
    statuses = _aggregate_statuses(aggregate)
    return EXIT_OK if all(status == target for status in statuses.values()) \
        else EXIT_INCOMPLETE


# --------------------------------------------------------------------------
# 独立复核
# --------------------------------------------------------------------------

class VerificationError(RuntimeError):
    """复核前置条件不满足（缺少产物、schema 不符）。"""


def _read_json(path: Path, label: str) -> dict:
    if not Path(path).is_file():
        raise VerificationError(f"{label} is missing: {path}")
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise VerificationError(f"{label} is not valid JSON: {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise VerificationError(f"{label} is not a JSON object: {path}")
    return document


def _read_receipts(run_dir: Path) -> dict:
    path = Path(run_dir) / "receipts.jsonl"
    if not path.is_file():
        raise VerificationError(f"receipts.jsonl is missing: {path}")
    receipts = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            receipt = json.loads(line)
        except ValueError as exc:
            raise VerificationError(
                f"invalid receipt on line {number} of {path}: {exc}") from exc
        if not isinstance(receipt, dict) or not isinstance(receipt.get("case_id"), str):
            raise VerificationError(
                f"receipt on line {number} of {path} has no case_id")
        receipts.setdefault(receipt["case_id"], []).append(receipt)
    return receipts


def _collect_case_events(run_dir: Path, case_id: str,
                         event_ids: Sequence[int]) -> dict:
    """在**同一个 case 窗口内**按 event_id 精确取事件（不做全局事件相邻性推断）。"""
    wanted = {event_id for event_id in event_ids}
    if not wanted:
        return {}
    stream = TraceEventStream(run_dir)
    found: dict = {}
    inside = False
    for event in stream.events():
        if _case_of(event) == case_id:
            inside = True
            event_id = event.get("event_id")
            if event_id in wanted:
                found[event_id] = event
            if len(found) == len(wanted):
                break
            continue
        if inside:
            break
    return found


def _case_window(run_dir: Path, case_id: str) -> tuple | None:
    stream = TraceEventStream(run_dir)
    inside = False
    buffer: list = []
    for event in stream.events():
        if _case_of(event) == case_id:
            inside = True
            buffer.append(event)
            continue
        if inside:
            return tuple(buffer)
    return tuple(buffer) if inside else None


def _anchored_event_ids(selector: Mapping) -> list:
    return sorted({value for key, value in selector.items()
                   if key.endswith("_event_id") and type(value) is int})


def _provenance_graph_sha(event: Mapping) -> str | None:
    """一个事件 provenance 里记录的第一个图摘要（声明漂移对照用）。"""
    provenance = event.get("provenance")
    if not isinstance(provenance, Mapping):
        return None
    candidates = provenance.get("edge_candidates")
    if isinstance(candidates, Sequence) and candidates:
        first = candidates[0]
        if isinstance(first, Mapping) and isinstance(first.get("graph_sha256"), str):
            return first["graph_sha256"]
    return None


def _mutated_event_id(spec: _VariantSpec, selector: Mapping,
                      control_events: Mapping) -> int | None:
    """哪个锚点事件会被 ``rewrite`` 注入改写（``duplicate`` 不改写任何事件）。

    判定只用一条可验证事实：该事件在**控制枝**里带着声明字段且值等于选择器
    记录的原值；找不到就返回 ``None``，让调用方按"任何差异都算问题"失败关闭，
    绝不猜一个事件来放行。
    """
    if spec.operation != "rewrite" or spec.field not in _FIELD_READERS:
        return None
    expected = selector.get("original_value")
    for event_id, event in sorted(control_events.items()):
        try:
            value = _field_value(event, spec.field)
        except ControlledFaultConfigError:
            continue
        if expected is None or value == expected:
            return event_id
    return None


def _anchor_field_failure(spec: _VariantSpec, selector: Mapping,
                          event: Mapping, role: str) -> str | None:
    """锚点事件上的字段值必须与**该枝应处的值**一致（只比对可读字段）。

    两支都必须还是被见证的原值：注入只改写交给 checker 的观测副本，保存下来的
    真实 trace 不变，因此"故障枝=替换值"是错误的期望（会把正确注入误判为失败）。
    """
    if spec.field not in _FIELD_READERS:
        return None
    try:
        value = _field_value(event, spec.field)
    except ControlledFaultConfigError as exc:  # pragma: no cover - 防御
        return f"{role} trace 读取 {spec.field} 失败: {exc}"
    expected = selector.get("original_value")
    if expected is not None and value != expected:
        return (f"{role} trace 的事件 {event.get('event_id')} 字段 "
                f"{spec.field}={value!r} 与 {role} 枝应有的值 {expected!r} 不一致")
    return None


def _diff_paths(left: object, right: object, prefix: str = "") -> list[dict]:
    """递归列出两份 JSON 的差异路径（精确到键/下标，绝不只报"不一致"）。"""
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        paths: list[dict] = []
        for key in sorted(set(left) | set(right)):
            path = f"{prefix}.{key}" if prefix else str(key)
            paths.extend(_diff_paths(left.get(key), right.get(key), path))
        return paths
    if isinstance(left, list) and isinstance(right, list):
        paths = []
        for index in range(max(len(left), len(right))):
            path = f"{prefix}[{index}]"
            paths.extend(_diff_paths(left[index] if index < len(left) else None,
                                     right[index] if index < len(right) else None,
                                     path))
        return paths
    if _canonical_text(left) != _canonical_text(right):
        return [{"path": prefix, "control": left, "fault": right}]
    return []


def _declaration_drift(paths: Sequence[Mapping]) -> tuple[list, list]:
    """把差异路径分成"声明漂移"与"其余不一致"。

    控制枝与故障枝是两次独立会话：控制枝可能是更早保存的运行，其
    ``provenance.edge_candidates`` 记录的是**当时**的运行时路径声明。这类字段
    不是被注入的事件内容，必须单独记为声明漂移并原样列出，而不是当作注入越界，
    也不能被悄悄忽略。
    """
    drift, real = [], []
    for item in paths:
        path = str(item.get("path") or "")
        if (path.startswith("provenance.edge_candidates")
                or path.endswith(".graph_sha256")
                or path.endswith(".path_ids")):
            drift.append(item)
        else:
            real.append(item)
    return drift, real


def _anchor_tick_failure(selector: Mapping, key: str, event_id_key: str,
                         events: Mapping, role: str) -> str | None:
    """选择器记录的 tick 必须来自真实的同一个事件（不允许事件相邻性推断）。

    只有当选择器**同时**钉住了 tick 与承载它的锚点事件时才比对；一个变体只用
    其中一对（例如 ``cpu_event_id`` 或 ``insert_before_event_id``），另一对缺失
    不是"缺少锚点事件"，否则会把正确的校准误判为失败。
    """
    if key not in selector or event_id_key not in selector:
        return None
    event_id = selector.get(event_id_key)
    event = events.get(event_id)
    if event is None:
        return (f"{role} trace 缺少承载 {key} 的锚点事件 "
                f"{event_id_key}={event_id}")
    if event.get(key) != selector[key]:
        return (f"{role} trace 的事件 event_id={event_id} {key}="
                f"{event.get(key)!r} 与选择器记录的 {selector[key]!r} 不一致")
    return None


def _verify_variant(entry: Mapping, aggregate: Mapping) -> dict:
    variant = entry.get("variant")
    checks: list = []

    def record(name: str, ok: bool, reason: str | None = None) -> None:
        checks.append({"name": name, "ok": bool(ok), "reason": reason})

    if entry.get("status") != STATUS_CALIBRATED:
        return {"variant": variant, "kind": entry.get("kind"),
                "status": entry.get("status"), "verified": False,
                "ok": True, "reason": f"status={entry.get('status')} 没有真实运行可复核",
                "checks": []}
    spec = SPEC_BY_VARIANT.get(variant)
    if spec is None:
        return {"variant": variant, "kind": entry.get("kind"),
                "status": entry.get("status"), "verified": False, "ok": False,
                "reason": f"unknown variant {variant!r}", "checks": []}
    expected = entry.get("expected_finding")
    if expected != spec.expected_finding:
        record("expected_finding_declared", False,
               f"{variant} 汇总里的 expected_finding={expected!r} 与该变体声明 "
               f"{spec.expected_finding!r} 不一致")

    # 1) 故障文档 canonical 且必须能被故障族严格校验。
    document_record = entry.get("fault_document") or {}
    document_path = Path(document_record.get("resolved", ""))
    document = None
    try:
        document = _read_json(document_path, f"{variant} fault document")
        canonical = ControlledFaultFamily.from_document(document).document()
        if _canonical_text(canonical) != _canonical_text(document):
            record("fault_document_canonical", False,
                   f"{variant} 故障文档不是 canonical 形式（含未规范化字段）")
        elif document_record.get("sha256") != _canonical_sha256(document):
            record("fault_document_canonical", False,
                   f"{variant} 故障文档 sha256 与汇总记录不一致")
        else:
            faults = document["faults"]
            if len(faults) != 1:
                record("fault_document_canonical", False,
                       f"{variant} 故障文档必须恰好 1 条配置，实际 {len(faults)}")
            elif (_canonical_text({key: faults[0][key] for key in _ENTRY_KEYS})
                  != _canonical_text({key: entry.get(key) for key in _ENTRY_KEYS})):
                record("fault_document_canonical", False,
                       f"{variant} 故障文档内容与汇总记录的选择器/变更不一致")
            else:
                record("fault_document_canonical", True)
    except (ControlledFaultConfigError, VerificationError) as exc:
        record("fault_document_canonical", False,
               f"{variant} 故障文档校验失败: {type(exc).__name__}: {exc}")

    # 2) minimal replay 文档（若已保存）同样 canonical 且自洽。
    replay_record = entry.get("minimal_replay")
    if not replay_record:
        record("minimal_replay_canonical", False,
               f"{variant} 没有 minimal_replay.json（calibrated 必须有）")
    else:
        try:
            replay = _read_json(Path(replay_record["resolved"]),
                                f"{variant} minimal replay")
            problems = []
            if replay.get("schema_version") != REPLAY_SCHEMA_VERSION:
                problems.append(f"schema_version={replay.get('schema_version')!r}")
            if replay.get("calibration_only") is not True:
                problems.append("calibration_only 不是 true")
            if replay.get("observation_boundary") != _OBSERVATION_BOUNDARY:
                problems.append("observation_boundary 不是 checker_input_copy")
            pinned = replay.get("fault_document")
            if not isinstance(pinned, Mapping):
                problems.append("fault_document 缺失")
            else:
                canonical = ControlledFaultFamily.from_document(pinned).document()
                if _canonical_text(canonical) != _canonical_text(pinned):
                    problems.append("fault_document 不是 canonical 形式")
                if replay.get("fault_document_sha256") != _canonical_sha256(pinned):
                    problems.append("fault_document_sha256 不一致")
            findings = replay.get("findings")
            if not isinstance(findings, list) or not findings:
                problems.append("findings 为空")
            elif findings[0].get("detected_by") != expected:
                problems.append(
                    f"findings[0].detected_by={findings[0].get('detected_by')!r}")
            elif replay_record.get("sha256") != _canonical_sha256(replay):
                problems.append("minimal_replay.json sha256 与汇总记录不一致")
            record("minimal_replay_canonical", not problems,
                   None if not problems else f"{variant} minimal replay: "
                   + "; ".join(problems))
        except (ControlledFaultConfigError, VerificationError) as exc:
            record("minimal_replay_canonical", False,
                   f"{variant} minimal replay 校验失败: {type(exc).__name__}: {exc}")

    # 3) 故障运行收据里必须出现期望 finding（直接读 receipts，不信汇总字段）。
    run = entry.get("run") or {}
    fault_dir = Path((run.get("output_dir") or {}).get("resolved", ""))
    try:
        fault_receipts = _read_receipts(fault_dir)
        observed = [finding for receipts in fault_receipts.values()
                    for receipt in receipts
                    for finding in (receipt.get("violations") or ())]
        case_receipts = fault_receipts.get(entry.get("case_id"), [])
        if expected not in observed:
            record("fault_run_finding", False,
                   f"{variant} 故障运行 {fault_dir} 的 receipts 没有报告 "
                   f"{expected}（observed={sorted(set(observed))}）")
        elif not any(expected in (receipt.get("violations") or ())
                     for receipt in case_receipts):
            record("fault_run_finding", False,
                   f"{variant} 期望 finding {expected} 不在 case "
                   f"{entry.get('case_id')} 的收据里")
        else:
            record("fault_run_finding", True)
    except VerificationError as exc:
        record("fault_run_finding", False, f"{variant}: {exc}")

    # 4) 控制运行（源运行）不得已经报告该 finding，且必须有该 case。
    source_run = entry.get("source_run") or {}
    control_dir = Path(source_run.get("resolved", ""))
    try:
        control_receipts = _read_receipts(control_dir)
        control_findings = sorted({finding for receipts in control_receipts.values()
                                   for receipt in receipts
                                   for finding in (receipt.get("violations") or ())})
        if entry.get("case_id") not in control_receipts:
            record("control_run_clean", False,
                   f"{variant} 控制运行 {control_dir} 的 receipts 没有 case "
                   f"{entry.get('case_id')}")
        elif expected in control_findings:
            record("control_run_clean", False,
                   f"{variant} 控制运行 {control_dir} 已报告 {expected}"
                   f"（control findings={control_findings}）；不是自然对照")
        else:
            record("control_run_clean", True)
    except VerificationError as exc:
        record("control_run_clean", False, f"{variant}: {exc}")

    # 5) 控制窗口自身在未扰动观测上的 baseline 必须为空（独立于 receipts 再算一次）。
    selector = entry.get("selector") or {}
    try:
        window = _case_window(control_dir, entry.get("case_id"))
        if window is None:
            record("control_window_baseline", False,
                   f"{variant} 控制 trace 里找不到 case {entry.get('case_id')} 的事件窗口")
        else:
            checker = _CHECKER_FACTORIES[spec.checker]()
            baseline = tuple(checker(OnlineCaseReceipt(
                entry["case_id"], 0, len(window), window, {}, {}, "running")))
            if baseline:
                record("control_window_baseline", False,
                       f"{variant} 控制窗口的未扰动观测已报告 {list(baseline)}"
                       "（注入 finding 会与自然 finding 无法区分）")
            else:
                record("control_window_baseline", True)
    except (VerificationError, ValueError) as exc:
        record("control_window_baseline", False, f"{variant}: {exc}")

    # 6) 注入只改 checker 输入副本：控制/故障两份真实 trace 的锚点事件必须逐字段相同。
    anchored = _anchored_event_ids(selector)
    try:
        control_events = _collect_case_events(control_dir, entry.get("case_id"),
                                              anchored)
        fault_events = _collect_case_events(fault_dir, entry.get("case_id"),
                                            anchored)
        missing = [event_id for event_id in anchored
                   if event_id not in control_events or event_id not in fault_events]
        if missing:
            record("anchored_events_identical", False,
                   f"{variant} 锚点事件 {missing} 在控制或故障 trace 中缺失"
                   "（运行未到达见证窗口？）")
        else:
            problems = []
            drift_records = []
            for event_id in anchored:
                control_event = control_events[event_id]
                fault_event = fault_events[event_id]
                if _canonical_text(control_event) == _canonical_text(fault_event):
                    continue
                # 注入只写 checker 观测副本，保存的真实 trace 必须逐字段不变；
                # 唯一允许的差异是两次独立会话各自的运行时路径声明
                # （provenance.edge_candidates），且必须原样记录为声明漂移。
                drift, real = _declaration_drift(
                    _diff_paths(control_event, fault_event))
                if drift:
                    drift_records.append({"event_id": event_id,
                                          "paths": [item["path"] for item in drift],
                                          "graph_sha256": {
                                              "control": _provenance_graph_sha(control_event),
                                              "fault": _provenance_graph_sha(fault_event)}})
                if real:
                    detail = "; ".join(
                        f"{item['path']}（控制={item['control']!r} "
                        f"故障={item['fault']!r}）" for item in real[:4])
                    more = "" if len(real) <= 4 else f" 等 {len(real)} 处"
                    problems.append(
                        f"{variant}: 锚点事件 event_id={event_id} 在控制与故障 trace "
                        f"中不一致：{detail}{more}")
                    break
            if not problems:
                observation_id = entry.get("observation_event_id")
                if observation_id in control_events:
                    for role, events in (("control", control_events),
                                         ("fault", fault_events)):
                        failure = _anchor_field_failure(
                            spec, selector, events[observation_id], role)
                        if failure is not None:
                            problems.append(f"{variant}: {failure}")
                            break
                if not problems:
                    tick_sources = (
                        ("local_tick", "cpu_event_id"),
                        ("local_tick", "insert_before_event_id"),
                        ("source_tick", "source_start_event_id"))
                    for key, event_id_key in tick_sources:
                        for role, events in (("control", control_events),
                                             ("fault", fault_events)):
                            failure = _anchor_tick_failure(
                                selector, key, event_id_key, events, role)
                            if failure is not None:
                                problems.append(f"{variant}: {failure}")
                                break
                        if problems:
                            break
            drift_note = None
            if drift_records:
                drift_note = (
                    "控制枝与故障枝是两次独立会话，锚点事件的运行时路径声明不同"
                    f"（记为 declaration_drift，不当作注入越界）：{drift_records}")
            record("anchored_events_identical", not problems,
                   " | ".join(problems) if problems else drift_note)
    except (VerificationError, ValueError) as exc:
        record("anchored_events_identical", False, f"{variant}: {exc}")

    # 7) 控制 trace 文件字节未变（与选择时刻记录的 SHA-256 比对）。
    try:
        trace_path = control_dir / source_run.get("trace_file", "")
        if not trace_path.is_file():
            record("control_trace_unchanged", False,
                   f"{variant} 控制 trace 文件缺失: {trace_path}")
        else:
            digest = _file_sha256(trace_path)
            size = trace_path.stat().st_size
            if digest != source_run.get("trace_sha256"):
                record("control_trace_unchanged", False,
                       f"{variant} 控制 trace 的 sha256 已改变: {trace_path} "
                       f"记录={source_run.get('trace_sha256')} 现在={digest}")
            elif size != source_run.get("trace_bytes"):
                record("control_trace_unchanged", False,
                       f"{variant} 控制 trace 的字节数已改变: {trace_path} "
                       f"记录={source_run.get('trace_bytes')} 现在={size}")
            else:
                record("control_trace_unchanged", True)
    except (VerificationError, OSError) as exc:
        record("control_trace_unchanged", False, f"{variant}: {exc}")

    return {"variant": variant, "kind": entry.get("kind"),
            "status": entry.get("status"), "verified": True,
            "ok": all(check["ok"] for check in checks), "checks": checks,
            "declaration_drift": list(locals().get("drift_records") or ())}


def verify_calibration(calibration_root: Path, *,
                       variants: Sequence[str] | None = None) -> dict:
    """独立复核一个已完成的校准根目录；任何不一致都带精确原因返回。"""
    root = Path(calibration_root)
    aggregate_path = root / "fault_family_calibration.json"
    aggregate = _read_json(aggregate_path, "calibration aggregate")
    if aggregate.get("schema_version") != SCHEMA_VERSION:
        raise VerificationError(
            f"aggregate schema_version must be {SCHEMA_VERSION!r}, "
            f"found {aggregate.get('schema_version')!r}")
    requested = ({spec.variant for spec in resolve_specs(variants)}
                 if variants else None)
    results = []
    for entry in aggregate.get("variants") or ():
        if requested is not None and entry.get("variant") not in requested:
            continue
        results.append(_verify_variant(entry, aggregate))
    failures = [{"variant": item["variant"], "check": check["name"],
                 "reason": check["reason"]}
                for item in results for check in item["checks"] if not check["ok"]]
    failures += [{"variant": item["variant"], "check": "variant",
                  "reason": item["reason"]}
                 for item in results if not item["verified"] and not item["ok"]]
    verified = [item for item in results if item["verified"]]
    if not verified:
        failures.append({"variant": None, "check": "calibration",
                         "reason": "没有任何 status=calibrated 的变体可供复核"})
    report = {
        "schema_version": VERIFY_SCHEMA_VERSION,
        "ok": not failures,
        "calibration_root": _path_record(root),
        "aggregate": {**_path_record(aggregate_path),
                      "sha256": _file_sha256(aggregate_path),
                      "select_only": aggregate.get("select_only"),
                      "source_runs": [record.get("path")
                                      for record in aggregate.get("source_runs") or ()]},
        "variants": results,
        "failures": failures,
        "limits": list(_LIMITS),
    }
    return report


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser(
        "run", help="select witnesses, write fault documents, calibrate on RTL")
    run.add_argument("--continuous-run", type=Path, action="append",
                     help="saved online run directory (repeatable; default: "
                          "the declared candidate per checker)")
    run.add_argument("--output-root", type=Path, required=True)
    run.add_argument("--cache-dir", type=Path)
    run.add_argument("--client-binary", type=Path)
    run.add_argument("--variant", action="append",
                     help="variant name or kind/variant (repeatable)")
    run.add_argument("--select-only", action="store_true",
                     help="select witnesses and write documents without any RTL")
    run.add_argument("--duration-seconds", type=float,
                     default=DEFAULT_DURATION_SECONDS)
    run.add_argument("--max-tests", type=int, default=DEFAULT_MAX_TESTS)
    run.add_argument("--search-seed", type=int, default=DEFAULT_SEARCH_SEED)
    run.add_argument("--max-runs-per-batch", type=int,
                     default=DEFAULT_MAX_RUNS_PER_BATCH)
    run.add_argument("--max-cases", type=int, default=None,
                     help="bound the witness scan (default: full scan)")
    verify = commands.add_parser(
        "verify", help="independently re-check a completed calibration run")
    verify.add_argument("--calibration-root", type=Path, required=True)
    verify.add_argument("--variant", action="append")
    return parser


def main(argv: list[str] | None = None, *, session_runner=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            report = verify_calibration(args.calibration_root,
                                        variants=args.variant)
            _write_json(Path(args.calibration_root)
                        / "fault_family_calibration_verify.json", report)
            print(json.dumps({"ok": report["ok"],
                              "failures": len(report["failures"]),
                              "schema_version": report["schema_version"]},
                             sort_keys=True))
            return EXIT_OK if report["ok"] else EXIT_VERIFY_FAILED
        aggregate = calibrate(
            source_runs=args.continuous_run, output_root=args.output_root,
            cache_dir=args.cache_dir, client_binary=args.client_binary,
            variants=args.variant, max_cases=args.max_cases,
            select_only=args.select_only,
            budget={"duration_seconds": args.duration_seconds,
                    "max_tests": args.max_tests,
                    "search_seed": args.search_seed,
                    "max_runs_per_batch": args.max_runs_per_batch},
            session_runner=session_runner)
    except CalibrationError as exc:
        print(f"p5-fault-calibration-error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"p5-fault-calibration-error: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return EXIT_USAGE
    statuses = _aggregate_statuses(aggregate)
    print(json.dumps({
        "aggregate": str(Path(args.output_root) / "fault_family_calibration.json"),
        "select_only": aggregate["select_only"],
        "statuses": statuses}, sort_keys=True))
    return _exit_code(aggregate)


if __name__ == "__main__":
    raise SystemExit(main())
