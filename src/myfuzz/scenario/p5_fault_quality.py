"""P5 受控故障**同条件质量对照**（``p5_fault_quality.v1``，只读、fail-closed）。

用途
-----
读一个**已完成的校准根目录**（``run_p5_fault_calibration_family.py`` 的产物），
逐变体、逐故障类地回答"这次检测究竟建立了什么、没有建立什么"：

1. **检测**：声明的期望 finding 与故障会话 ``receipts.jsonl`` 里的 observed
   findings 对照（精确 finding 字符串、它命中的 case id、该收据的 status），
   并与故障族自己的观测记录（``finding_ids`` / ``minimal_replay.findings``）连接；
2. **注入边界**：把选择器钉住的事件在**对照运行 trace** 与**故障会话 trace** 里
   逐字段对照（精确 event id / tick / 原值）。差异分成两类：
   * ``session_identity``：逐会话的运行时图身份字段（``provenance.edge_candidates
     [*].graph_sha256`` / ``path_ids[*]``）。它们是每次会话编译出的图摘要，不是
     数据流观测；本模块把它们的差异**逐个列出**（值不同也算差异），而不是当成
     相等。
   * 其它任何差异都是 ``dataflow``/``structure`` 差异 → 该变体的注入边界不成立，
     文档 ``ok=false``、退出码 4（绝不静默通过）。
   另外还测量：故障 trace 的锚点事件里，被扰动字段**仍是原值**（注入值不出现），
   以及重复提交类变体在记录 trace 里的声明计数对照相等——即"注入只改了交给
   checker 的副本"是**被测量的等式**，不是假设。
   锚点之外，本模块还把"同一 case 的事件窗口"在两次会话之间做窗口级分解
   （``case_window_diff``：哪些事件不同、差在逐会话身份字段 / 身份摘要字段
   （``admission_id`` / ``path_id`` / ``origin_admission_ids``）/ 其它数据流字段）。
   窗口分解是**信息性**的，不参与 ``ok`` 判定；它把"同条件"到底同到什么程度写成
   可核对的数字，而不是一句结论。
3. **可重放材料**：``minimal_replay.json`` 是否存在，其 ``fault_document_sha256``
   是否等于该变体 ``fault_document.json`` 的 canonical 摘要（并与汇总登记值核对）。
4. **按故障类汇总**：四个 kind 的 ``calibrated`` / ``not_fired`` / ``error`` /
   ``no_witness_window``（以及 ``selected``）计数，外加**从未校准**的变体清单。
5. **边界声明**：``calibration_only=true``，且注入 finding **永远不是**自然 DUT
   缺陷证据。

拒绝规则（fail-closed）
-----------------------
必需输入缺失、不可解析、或与 ``_SPECS``/汇总声明不一致 → 抛
:class:`FaultQualityError`（CLI 非零退出 + 精确原因），**不写文档**、不写 0。
``error``/``no_witness_window``/``selected`` 变体的会话产物缺失是**已被状态声明**
的事实，如实计入汇总，而不是拒绝。详见文档里的 ``input_policy``。

硬边界
------
* 只读：不写任何校准产物、不跑 RTL/fuzz、不重放 minimal replay。
* 不导入在线运行路径：本模块不被运行器/checker 引用，只被
  ``scripts/compare_p5_fault_quality.py`` 与测试使用。
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
import re
import sys

from .acceptance_metrics import TraceEventStream
from .p5_fault_family import (
    FAULT_KINDS,
    ControlledFaultConfigError,
    _SPECS,
    _field_value,
)


SCHEMA_VERSION = "p5_fault_quality.v1"
CALIBRATION_SCHEMA_VERSION = "p5_fault_family_calibration.v1"
OBSERVATION_BOUNDARY = "checker_input_copy"

STATUS_SELECTED = "selected"
STATUS_CALIBRATED = "calibrated"
STATUS_NO_WITNESS = "no_witness_window"
STATUS_NOT_FIRED = "not_fired"
STATUS_ERROR = "error"
KNOWN_STATUSES = (STATUS_CALIBRATED, STATUS_NOT_FIRED, STATUS_ERROR,
                  STATUS_NO_WITNESS, STATUS_SELECTED)
COUNTED_STATUSES = (STATUS_CALIBRATED, STATUS_NOT_FIRED, STATUS_ERROR,
                    STATUS_NO_WITNESS, STATUS_SELECTED)
#: 这些状态必须带一次真实故障会话的产物；缺任何一件都是拒绝。
SESSION_STATUSES = (STATUS_CALIBRATED, STATUS_NOT_FIRED)

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_INCOMPLETE = 3
EXIT_MISMATCH = 4

#: 可读字段集合必须与 ``p5_fault_family._FIELD_READERS`` 一致；``pulse_start``
#: 是纯重复提交的"声明"字段（不承载取值），单独按声明计数测量。
READABLE_FIELDS = frozenset((
    "outputs.irq", "inputs.irq", "inputs.gpio_in",
    "outputs.data_rsp_rdata", "read_value", "value"))

#: tick 键 → 承载它的事件 ID 键（与 ``p5_fault_family`` 的定位器一致）。
TICK_CARRIERS = (
    ("source_tick", ("source_start_event_id",)),
    ("local_tick", ("cpu_event_id", "insert_before_event_id")),
)

#: 逐会话身份字段：只在**值**上允许不同，且必须逐条列出；键缺失/多出算结构差异。
SESSION_IDENTITY_PATH_PATTERNS = (
    re.compile(r"^provenance\.edge_candidates\[\d+\]\.graph_sha256$"),
    re.compile(r"^provenance\.edge_candidates\[\d+\]\.path_ids\[\d+\]$"),
)
SESSION_IDENTITY_PLACEHOLDER = "<session_identity>"

#: 身份**摘要**叶子（仅用于窗口级信息性分解，不参与锚点 gating）：
#: ``admission_id`` 是 source admission 材料（含 ``path_id``）的 canonical 摘要
#: （``src/myfuzz/scenario/source_provenance.py`` 的 ``_admission_digest``），
#: ``path_id`` 是每次会话编译出的运行时路径摘要。两者都随逐会话图声明漂移；它们
#: 的材料字段（action_id / case_id / component / direction / input_kind /
#: input_sha256 / source_id / role）仍然逐字段参与 dataflow 对照，因此真实的输入
#: 变化不可能藏在摘要后面。
IDENTITY_DIGEST_LEAF_PATTERN = re.compile(r"(^|\.)(admission_id|path_id)$")
IDENTITY_DIGEST_LIST_PATTERN = re.compile(
    r"^provenance\.origin_admission_ids\[\d+\]$")

MAX_LISTED_FIELD_DIFFS = 24
MAX_LISTED_WINDOW_EVENTS = 8
MAX_DECOMPOSED_WINDOW_EVENTS = 512
MAX_LISTED_WINDOW_PATHS = 12
MAX_LISTED_SOURCE_FILES = 12

SPEC_BY_VARIANT = {spec.variant: spec for spec in _SPECS}
DECLARED_VARIANTS = tuple(spec.variant for spec in _SPECS)
KIND_BY_VARIANT = {spec.variant: spec.kind for spec in _SPECS}

STATEMENT_TEXT = (
    "本文件中每个 finding 都由受控故障注入产生（calibration_only）：注入只改写"
    "交给 checker 的事件副本（observation_boundary=checker_input_copy），真实 "
    "trace、RTL 与 DUT 均未被改写；因此这些 finding 只能用于校准检测链，绝不能"
    "作为 DUT 缺陷证据，也不得并入自然缺陷统计。")

LIMITS = (
    "本对照只读取已保存产物：它不重新运行 RTL、不重放 minimal_replay.json，"
    "因此不证明在新进程中复现。",
    "单个变体 detected=true 只表示该变体在钉住的 case 上触发了声明的既有不变量；"
    "一个见证点不构成对该故障类的检测灵敏度或覆盖率结论。",
    "锚点逐字段相等只覆盖选择器钉住的事件：它证明记录下来的真实 trace 未被注入"
    "改写，不证明整条 trace 在两次会话间逐字节相同；窗口级差异在 "
    "case_window_diff 里逐个事件列出。",
    "同条件对照以 case_id + 事件 ID / tick / 原值为准；两次会话的 run_id、图摘要、"
    "manifest 等逐会话身份字段可以不同，本文件把它们与数据流字段分开列出。",
    "任何必需输入缺失、不可解析或与声明不一致都是拒绝（非零退出 + 精确原因），"
    "绝不静默通过、绝不写 0。",
)


class FaultQualityError(RuntimeError):
    """质量对照的前置输入不满足：拒绝并给出精确原因（fail-closed）。"""


# --------------------------------------------------------------------------
# canonical / IO helpers
# --------------------------------------------------------------------------

def _canonical_text(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_text(value).encode("utf-8")).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _path_record(path: Path) -> dict:
    return {"path": str(path), "resolved": str(Path(path).resolve())}


def _read_json(path: Path, label: str) -> dict:
    path = Path(path)
    if not path.is_file():
        raise FaultQualityError(f"{label} is missing: {path}")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise FaultQualityError(f"{label} is not valid JSON: {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise FaultQualityError(f"{label} is not a JSON object: {path}")
    return document


def _try_read_json(path: Path) -> tuple[dict | None, str | None]:
    path = Path(path)
    if not path.is_file():
        return None, f"文件不存在: {path}"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return None, f"不是合法 JSON: {path}: {exc}"
    if not isinstance(document, dict):
        return None, f"不是 JSON 对象: {path}"
    return document, None


def _case_of(event: Mapping) -> str | None:
    provenance = event.get("provenance")
    observed = provenance.get("observed_case") if isinstance(provenance, Mapping) else None
    if isinstance(observed, Mapping) and isinstance(observed.get("case_id"), str):
        return observed["case_id"]
    return None


# --------------------------------------------------------------------------
# 字段路径与分类
# --------------------------------------------------------------------------

def classify_path(path: str) -> str:
    """把一个扁平字段路径分类为 ``session_identity`` 或 ``dataflow``。"""
    for pattern in SESSION_IDENTITY_PATH_PATTERNS:
        if pattern.match(path):
            return "session_identity"
    return "dataflow"


def _leaf_paths(value: object, prefix: str = "") -> dict:
    leaves: dict = {}
    if isinstance(value, Mapping):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            leaves.update(_leaf_paths(item, path))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            leaves.update(_leaf_paths(item, f"{prefix}[{index}]"))
    else:
        leaves[prefix] = value
    return leaves


def _masked(value: object, prefix: str = "") -> object:
    if isinstance(value, Mapping):
        return {key: _masked(item, f"{prefix}.{key}" if prefix else str(key))
                for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_masked(item, f"{prefix}[{index}]")
                for index, item in enumerate(value)]
    if classify_path(prefix) == "session_identity":
        return SESSION_IDENTITY_PLACEHOLDER
    return value


def compare_events(control: Mapping, fault: Mapping, *,
                   cap: int | None = MAX_LISTED_FIELD_DIFFS) -> dict:
    """逐字段对照两个锚点事件；差异按类别（身份 / 数据流）分开列出。"""
    control_leaves = _leaf_paths(control)
    fault_leaves = _leaf_paths(fault)
    paths = sorted(set(control_leaves) | set(fault_leaves))
    differing = []
    for path in paths:
        in_control = path in control_leaves
        in_fault = path in fault_leaves
        if in_control and in_fault and control_leaves[path] == fault_leaves[path]:
            continue
        kind = classify_path(path) if (in_control and in_fault) else "structure"
        differing.append({
            "path": path, "class": kind,
            "present_in_control": in_control, "present_in_fault": in_fault,
            "control": control_leaves.get(path), "fault": fault_leaves.get(path)})
    identity = [item for item in differing if item["class"] == "session_identity"]
    dataflow = [item for item in differing if item["class"] != "session_identity"]
    listed = differing if cap is None else differing[:cap]
    return {
        "identical": not differing,
        "dataflow_identical": not dataflow,
        "compared_fields": len(paths),
        "dataflow_compared_fields": sum(
            1 for path in paths if classify_path(path) != "session_identity"),
        "differing_fields": listed,
        "differing_field_count": len(differing),
        "identity_differing_fields": [item for item in listed
                                      if item["class"] == "session_identity"],
        "identity_differing_field_count": len(identity),
        "dataflow_differing_fields": [item for item in listed
                                      if item["class"] != "session_identity"],
        "dataflow_differing_field_count": len(dataflow),
        "dataflow_sha256": {
            "control": _canonical_sha256(_masked(control)),
            "fault": _canonical_sha256(_masked(fault))},
    }


def classify_differing_leaf(path: str) -> str:
    """差异叶子的信息性分类（仅用于窗口级分解，不参与锚点 gating）。"""
    if classify_path(path) == "session_identity":
        return "session_identity"
    if (IDENTITY_DIGEST_LEAF_PATTERN.search(path)
            or IDENTITY_DIGEST_LIST_PATTERN.match(path)):
        return "session_identity_digest"
    return "other_dataflow"


def _endpoint(value: object):
    if (isinstance(value, (list, tuple)) and len(value) == 2
            and all(isinstance(item, str) for item in value)):
        return [value[0], value[1]]
    return None


def _claim_identity(event: Mapping) -> dict:
    """重复提交类变体"声明"的身份：只看 (component, kind, source, target)。"""
    return {"component": event.get("component"), "kind": event.get("kind"),
            "source": _endpoint(event.get("source")),
            "target": _endpoint(event.get("target"))}


def _anchored_event_ids(selector: Mapping) -> list:
    return sorted({value for key, value in selector.items()
                   if key.endswith("_event_id") and type(value) is int})


# --------------------------------------------------------------------------
# 只读扫描
# --------------------------------------------------------------------------

def scan_case(run_dir: Path, case_id: str, wanted_event_ids: Sequence[int], *,
              claim_identity: Mapping | None = None) -> dict:
    """流式读取一个 case 窗口：锚点事件、窗口摘要、声明计数。

    只保留需要的事件，内存与窗口大小无关。窗口摘要分两份：原始 canonical
    事件串（``window_sha256``）与掩掉逐会话身份字段后的事件串
    （``window_dataflow_sha256``）；另外记录逐事件的数据流摘要
    （``_event_digests``，内部使用），用于定位两次会话之间到底哪些事件不同。
    """
    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        raise FaultQualityError(f"run directory does not exist: {run_dir}")
    try:
        stream = TraceEventStream(run_dir)
    except ValueError as exc:
        raise FaultQualityError(
            f"run has no streamable event artifact: {run_dir}: {exc}") from exc
    wanted = {event_id for event_id in wanted_event_ids if type(event_id) is int}
    found: dict = {}
    events = 0
    first_id = None
    last_id = None
    raw_digest = hashlib.sha256()
    dataflow_digest = hashlib.sha256()
    event_digests: dict = {}
    raw_event_digests: dict = {}
    claim_key = (None if claim_identity is None
                 else _canonical_text(_claim_identity(claim_identity)))
    claim_count = 0
    inside = False
    for event in stream.events():
        if _case_of(event) == case_id:
            inside = True
            events += 1
            if events > 1:
                raw_digest.update(b",")
                dataflow_digest.update(b",")
            raw_text = _canonical_text(event)
            raw_digest.update(raw_text.encode("utf-8"))
            dataflow_text = _canonical_text(_masked(event))
            dataflow_digest.update(dataflow_text.encode("utf-8"))
            event_id = event.get("event_id")
            if type(event_id) is int:
                event_digests[event_id] = hashlib.sha256(
                    dataflow_text.encode("utf-8")).hexdigest()
                raw_event_digests[event_id] = hashlib.sha256(
                    raw_text.encode("utf-8")).hexdigest()
            if first_id is None:
                first_id = event_id
            last_id = event_id
            if event_id in wanted:
                found.setdefault(event_id, event)
            if claim_key is not None and _canonical_text(
                    _claim_identity(event)) == claim_key:
                claim_count += 1
            continue
        if inside:
            break
    return {
        "run_dir": str(run_dir), "resolved_run_dir": str(run_dir.resolve()),
        "trace_file": stream.descriptor["events_file"],
        "trace_format": stream.descriptor["format"],
        "trace_bytes": stream.descriptor["bytes"],
        "case_id": case_id, "found": inside, "events": events,
        "first_event_id": first_id, "last_event_id": last_id,
        "window_sha256": raw_digest.hexdigest(),
        "window_dataflow_sha256": dataflow_digest.hexdigest(),
        "events_by_id": found,
        "missing_event_ids": sorted(wanted - set(found)),
        "claim_count": claim_count,
        "_event_digests": event_digests,
        "_raw_event_digests": raw_event_digests,
    }


def _trace_sha256(run_dir: Path, trace_file: str, cache: dict) -> str | None:
    path = Path(run_dir) / trace_file
    key = ("file_sha256", str(path))
    if key in cache:
        return cache[key]
    value = _file_sha256(path) if path.is_file() else None
    cache[key] = value
    return value


def _cached_scan(run_dir: Path, case_id: str, wanted: Sequence[int], *,
                 claim_identity: Mapping | None, cache: dict) -> dict:
    claim_key = (None if claim_identity is None
                 else _canonical_text(_claim_identity(claim_identity)))
    key = ("scan", str(Path(run_dir).resolve()), case_id,
           tuple(sorted(wanted)), claim_key)
    if key not in cache:
        cache[key] = scan_case(run_dir, case_id, wanted,
                               claim_identity=claim_identity)
    return cache[key]


# --------------------------------------------------------------------------
# 逐变体分析
# --------------------------------------------------------------------------

def _read_receipts(run_dir: Path, variant: str) -> dict:
    path = Path(run_dir) / "receipts.jsonl"
    if not path.is_file():
        raise FaultQualityError(
            f"{variant}: receipts.jsonl is missing: {path}"
            "（故障会话的观测收据是检测对照的必需输入）")
    rows = []
    number = 0
    for number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            receipt = json.loads(line)
        except ValueError as exc:
            raise FaultQualityError(
                f"{variant}: invalid receipt on line {number} of {path}: "
                f"{exc}") from exc
        if not isinstance(receipt, dict):
            raise FaultQualityError(
                f"{variant}: receipt on line {number} of {path} is not a "
                "JSON object")
        case_id = receipt.get("case_id")
        status = receipt.get("status")
        raw_violations = receipt.get("violations")
        violations = ([item for item in raw_violations
                       if isinstance(item, str)]
                      if isinstance(raw_violations, (list, tuple)) else [])
        rows.append({
            "receipt_line": number,
            "case_id": case_id if isinstance(case_id, str) else None,
            "status": status if isinstance(status, str) else None,
            "violations": violations,
            "non_string_violations": (
                0 if not isinstance(raw_violations, (list, tuple))
                else sum(1 for item in raw_violations
                         if not isinstance(item, str)))})
    return {"path": _path_record(path), "sha256": _file_sha256(path),
            "lines": number, "receipts": len(rows), "rows": rows}


def _detection(entry: Mapping, spec, receipts: Mapping | None,
               reproducibility: Mapping) -> dict:
    variant = entry["variant"]
    expected = entry.get("expected_finding")
    pinned_case = entry.get("case_id")
    if receipts is None:
        return {
            "observable": False, "expected_finding": expected,
            "expected_finding_present_in_receipts": None,
            "fired_case_id": None, "fired_receipt_status": None,
            "matches_pinned_case": None, "observed_findings": None,
            "receipt_path": None, "receipt_sha256": None, "receipt_cases": None,
            "family_finding_ids": entry.get("finding_ids"),
            "family_findings": entry.get("family_findings"),
            "declared_finding_id": entry.get("finding_id"),
            "finding_ids_joined": None, "detected": False,
            "reason": (f"status={entry.get('status')} 没有可读的故障会话收据："
                       f"{entry.get('reason')}"),
        }
    observed = [{"finding": finding, "case_id": row["case_id"],
                 "status": row["status"], "receipt_line": row["receipt_line"]}
                for row in receipts["rows"] for finding in row["violations"]]
    fired = [row for row in observed if row["finding"] == expected]
    on_pinned = [row for row in fired if row["case_id"] == pinned_case]
    family_findings = [item for item in (entry.get("family_findings") or [])
                       if isinstance(item, str)]
    finding_ids = [item for item in (entry.get("finding_ids") or [])
                   if isinstance(item, str)]
    declared_id = entry.get("finding_id")
    declared_id_in_family = (isinstance(declared_id, str)
                             and declared_id in finding_ids)
    joined = reproducibility.get("finding_ids_joined")
    reasons = []
    if not fired:
        reasons.append(f"故障会话 receipts 里没有 {expected}"
                       f"（observed={sorted({row['finding'] for row in observed})}）")
    elif not on_pinned:
        reasons.append(f"{expected} 不在钉住 case {pinned_case} 的收据里"
                       f"（它命中的是 {sorted({row['case_id'] for row in fired})}）")
    if expected not in family_findings:
        reasons.append(f"故障族自身的观测没有报告 {expected}"
                       f"（family_findings={family_findings}）")
    if not finding_ids:
        reasons.append("故障族的观测记录没有 finding_ids")
    if not declared_id_in_family:
        reasons.append(f"汇总登记的 finding_id={declared_id!r} 不在故障族观测的 "
                       f"finding_ids={finding_ids} 里")
    if joined is False:
        reasons.append("minimal_replay.json 的 findings 与故障族观测的 finding_ids "
                       "不一致")
    detected = not reasons
    return {
        "observable": True, "expected_finding": expected,
        "expected_finding_present_in_receipts": bool(fired),
        "fired_case_id": fired[0]["case_id"] if fired else None,
        "fired_receipt_status": fired[0]["status"] if fired else None,
        "matches_pinned_case": bool(on_pinned),
        "observed_findings": observed,
        "receipt_path": receipts["path"],
        "receipt_sha256": receipts["sha256"],
        "receipt_lines": receipts["lines"],
        "receipt_cases": len({row["case_id"] for row in receipts["rows"]}),
        "receipt_finding_count": len(observed),
        "family_finding_ids": finding_ids,
        "family_findings": family_findings,
        "declared_finding_id": declared_id,
        "declared_finding_id_in_family_ids": declared_id_in_family,
        "finding_ids_joined": joined,
        "detected": detected,
        "reason": None if detected else "；".join(reasons),
    }


def _mutated_field_measurement(entry: Mapping, spec, selector: Mapping,
                               control_events: Mapping, fault_events: Mapping,
                               variant: str) -> dict:
    field = spec.field
    if field not in READABLE_FIELDS:
        if spec.operation != "duplicate":
            raise FaultQualityError(
                f"{variant}: 故障字段 {field!r} 既不在可读字段集合 "
                f"{sorted(READABLE_FIELDS)} 里，也不是纯重复提交的声明字段；"
                "无法逐字段测量注入边界")
        return {
            "applicable": False, "field": field,
            "reason": ("operation=duplicate 且字段不承载取值（声明计数语义）："
                       "注入改变的是声明计数，按 duplicate 计数测量"),
        }
    observation_id = entry.get("observation_event_id")
    if type(observation_id) is not int:
        raise FaultQualityError(
            f"{variant}: 汇总没有整数 observation_event_id，无法测量被扰动字段")
    control_event = control_events.get(observation_id)
    fault_event = fault_events.get(observation_id)
    if control_event is None or fault_event is None:
        raise FaultQualityError(
            f"{variant}: 被扰动事件 event_id={observation_id} 在对照或故障 trace "
            "中缺失，无法测量注入边界")
    control_value = _read_field(control_event, field)
    fault_value = _read_field(fault_event, field)
    original = selector.get("original_value")
    injected = entry.get("injected_value")
    equals_original = (None if original is None
                       else control_value == original and fault_value == original)
    injected_absent = (None if injected is None
                       else control_value != injected and fault_value != injected)
    return {
        "applicable": True, "field": field,
        "observation_event_id": observation_id,
        "original_value": original, "injected_value": injected,
        "control_value": control_value, "fault_value": fault_value,
        "control_equals_original": (None if original is None
                                    else control_value == original),
        "fault_equals_original": (None if original is None
                                  else fault_value == original),
        "injected_absent_from_recorded_trace": injected_absent,
        "recorded_trace_keeps_original": equals_original,
        "reason": None,
    }


def _read_field(event: Mapping, field: str):
    try:
        return _field_value(event, field)
    except ControlledFaultConfigError:
        return None


def _tick_comparisons(variant: str, selector: Mapping,
                      control_events: Mapping, fault_events: Mapping) -> list:
    results = []
    for key, carriers in TICK_CARRIERS:
        if key not in selector:
            continue
        carrier = next((name for name in carriers
                        if type(selector.get(name)) is int), None)
        if carrier is None:
            raise FaultQualityError(
                f"{variant}: 选择器钉住了 {key}={selector[key]!r} 却没有承载它的"
                f"事件 ID 键 {list(carriers)}；无法逐字段对照 tick")
        event_id = selector[carrier]
        control_event = control_events.get(event_id)
        fault_event = fault_events.get(event_id)
        control_value = (None if control_event is None
                         else control_event.get(key))
        fault_value = None if fault_event is None else fault_event.get(key)
        results.append({
            "key": key, "selector": selector[key],
            "carrier_event_id_key": carrier, "carrier_event_id": event_id,
            "control": control_value, "fault": fault_value,
            "equal": (control_event is not None and fault_event is not None
                      and control_value == fault_value == selector[key]),
        })
    return results


def _injection_boundary(entry: Mapping, spec, *, control_scan: Mapping,
                        fault_scan: Mapping, control_dir: Path,
                        fault_dir: Path, cache: dict,
                        failures: list) -> dict:
    variant = entry["variant"]
    selector = entry.get("selector")
    if not isinstance(selector, Mapping) or not selector:
        raise FaultQualityError(
            f"{variant}: 汇总没有可用 selector（{selector!r}）；注入边界无法测量")
    anchored = _anchored_event_ids(selector)
    if not anchored:
        raise FaultQualityError(
            f"{variant}: selector={dict(selector)!r} 没有 *_event_id 锚点；"
            "注入边界无法测量")
    control_events = control_scan["events_by_id"]
    fault_events = fault_scan["events_by_id"]
    anchor_events = []
    for event_id in anchored:
        control_event = control_events.get(event_id)
        fault_event = fault_events.get(event_id)
        if control_event is None or fault_event is None:
            raise FaultQualityError(
                f"{variant}: 锚点事件 event_id={event_id} 在"
                f"{'对照' if control_event is None else '故障'} trace 中缺失"
                f"（对照 {control_scan['run_dir']} / 故障 {fault_scan['run_dir']}）；"
                "注入边界无法测量")
        comparison = compare_events(control_event, fault_event)
        comparison.update({
            "event_id": event_id,
            "kind": control_event.get("kind"),
            "component": control_event.get("component"),
            "local_tick": control_event.get("local_tick"),
        })
        anchor_events.append(comparison)
        for item in comparison["dataflow_differing_fields"]:
            failures.append({
                "variant": variant, "check": "anchor_dataflow_fields",
                "reason": (
                    f"{variant}: 锚点事件 event_id={event_id} 在对照与故障 trace 中"
                    f" {item['path']} 不一致（control={item['control']!r} "
                    f"fault={item['fault']!r}）；注入边界不成立")})

    ticks = _tick_comparisons(variant, selector, control_events, fault_events)
    for item in ticks:
        if not item["equal"]:
            failures.append({
                "variant": variant, "check": "anchor_ticks",
                "reason": (
                    f"{variant}: 锚点事件 event_id={item['carrier_event_id']} 的 "
                    f"{item['key']} 在对照={item['control']!r} / 故障="
                    f"{item['fault']!r} / 选择器={item['selector']!r} 之间不一致；"
                    "注入边界不成立")})

    mutated = _mutated_field_measurement(entry, spec, selector, control_events,
                                         fault_events, variant)
    if mutated.get("recorded_trace_keeps_original") is False:
        failures.append({
            "variant": variant, "check": "mutated_field_persisted",
            "reason": (
                f"{variant}: 故障 trace 的锚点事件 event_id="
                f"{mutated['observation_event_id']} 字段 {mutated['field']}="
                f"{mutated['fault_value']!r} 不等于选择器记录的原值 "
                f"{mutated['original_value']!r}（对照={mutated['control_value']!r}）"
                "：注入疑似改写了记录的真实 trace，而不是 checker 输入副本")})
    if mutated.get("injected_absent_from_recorded_trace") is False:
        failures.append({
            "variant": variant, "check": "injected_value_in_recorded_trace",
            "reason": (
                f"{variant}: 注入值 {mutated['injected_value']!r} 出现在记录 trace 的"
                f"锚点事件 event_id={mutated['observation_event_id']} 上"
                "（应只存在于 checker 输入副本）")})

    duplicate = {"applicable": False, "reason": None}
    if spec.operation == "duplicate":
        observation_id = entry.get("observation_event_id")
        anchor_event = fault_events.get(observation_id)
        if anchor_event is None:  # pragma: no cover - 上面已拒绝
            raise FaultQualityError(
                f"{variant}: 重复提交的锚点事件 event_id={observation_id} 缺失")
        identity = _claim_identity(anchor_event)
        duplicate = {
            "applicable": True,
            "duplicated_kind": anchor_event.get("kind"),
            "claim_identity": identity,
            "claim_identity_sha256": _canonical_sha256(identity),
            "control_claim_count": control_scan["claim_count"],
            "fault_claim_count": fault_scan["claim_count"],
            "equal": control_scan["claim_count"] == fault_scan["claim_count"],
            "reason": ("重复提交只存在于 checker 输入副本：记录 trace 里同一身份"
                       " (component, kind, source, target) 的事件数在对照与故障之间"
                       "相等即为此事实的测量"),
        }
        if not duplicate["equal"]:
            failures.append({
                "variant": variant, "check": "duplicate_claim_count",
                "reason": (
                    f"{variant}: 记录 trace 中身份 {identity!r} 的事件数在对照="
                    f"{control_scan['claim_count']} / 故障="
                    f"{fault_scan['claim_count']} 之间不等；重复提交疑似落进了"
                    "记录的真实 trace")})

    ok = (not any(item["dataflow_differing_field_count"] for item in anchor_events)
          and all(item["equal"] for item in ticks)
          and mutated.get("recorded_trace_keeps_original") is not False
          and mutated.get("injected_absent_from_recorded_trace") is not False
          and duplicate.get("equal") is not False)
    recorded_traces = {
        "control": {
            **_path_record(control_dir),
            "trace_file": control_scan["trace_file"],
            "trace_sha256_measured": _trace_sha256(
                control_dir, control_scan["trace_file"], cache),
            "trace_sha256_recorded": (entry.get("source_run") or {}).get(
                "trace_sha256"),
            "trace_bytes_measured": control_scan["trace_bytes"],
            "case_window": _window_record(control_scan)},
        "fault": {
            **_path_record(fault_dir),
            "trace_file": fault_scan["trace_file"],
            "trace_sha256_measured": _trace_sha256(
                fault_dir, fault_scan["trace_file"], cache),
            "trace_bytes_measured": fault_scan["trace_bytes"],
            "case_window": _window_record(fault_scan)},
        "case_window_identical": (control_scan["window_sha256"]
                                  == fault_scan["window_sha256"]),
        "case_window_dataflow_identical": (
            control_scan["window_dataflow_sha256"]
            == fault_scan["window_dataflow_sha256"]),
        "case_window_diff": _window_diff(
            control_scan, fault_scan, control_dir=control_dir,
            fault_dir=fault_dir, cache=cache),
    }
    return {
        "measured": True, "ok": ok, "anchored_event_ids": anchored,
        "anchor_events": anchor_events, "ticks": ticks,
        "mutated_field": mutated, "duplicate": duplicate,
        "recorded_traces": recorded_traces,
        "identity_differing_field_count": sum(
            item["identity_differing_field_count"] for item in anchor_events),
        "dataflow_differing_field_count": sum(
            item["dataflow_differing_field_count"] for item in anchor_events),
        "reason": None if ok else "锚点逐字段对照未全部相等（见 failures）",
    }


def _window_record(scan: Mapping) -> dict:
    return {"case_id": scan["case_id"], "events": scan["events"],
            "first_event_id": scan["first_event_id"],
            "last_event_id": scan["last_event_id"],
            "sha256": scan["window_sha256"],
            "dataflow_sha256": scan["window_dataflow_sha256"]}


def _window_diff(control_scan: Mapping, fault_scan: Mapping, *,
                 control_dir: Path, fault_dir: Path, cache: dict) -> dict:
    """窗口级信息性分解：两次会话之间到底哪些事件不同、差在哪一类字段。

    它**不参与**变体 ``ok`` 的判定（ok 只看选择器钉住的锚点事件），但把
    ``case_window_dataflow_identical=false`` 从一句结论变成可核对的事实：
    逐事件列出差异字段数，并把差异叶子分成逐会话身份字段、身份摘要字段
    （``admission_id`` / ``path_id`` / ``origin_admission_ids``）与其它数据流字段。
    """
    control_digests = control_scan["_event_digests"]
    fault_digests = fault_scan["_event_digests"]
    differing_ids = sorted(
        event_id for event_id in set(control_digests) | set(fault_digests)
        if control_digests.get(event_id) != fault_digests.get(event_id))
    control_raw = control_scan["_raw_event_digests"]
    fault_raw = fault_scan["_raw_event_digests"]
    raw_differing = {
        event_id for event_id in set(control_raw) | set(fault_raw)
        if control_raw.get(event_id) != fault_raw.get(event_id)}
    record = {
        "differing_event_count": len(differing_ids),
        # 掩掉逐会话身份字段后仍不同 vs 原始 canonical 就不同：
        # 两者之差 = 只在逐会话身份字段上不同的事件数。
        "differing_event_count_raw": len(raw_differing),
        "identity_only_differing_event_count": len(
            raw_differing - set(differing_ids)),
        "listed_event_count": min(len(differing_ids), MAX_LISTED_WINDOW_EVENTS),
        "decomposed_event_count": min(len(differing_ids),
                                      MAX_DECOMPOSED_WINDOW_EVENTS),
        "decomposition_truncated": (len(differing_ids)
                                    > MAX_DECOMPOSED_WINDOW_EVENTS),
        "session_identity_field_count": 0,
        "session_identity_digest_field_count": 0,
        "other_dataflow_field_count": 0,
        "other_dataflow_paths": [],
        "events": [],
    }
    if not differing_ids:
        return record
    # 计数对**全部**（有上限的）差异事件求和；events 只列前若干个示例。
    decomposed = differing_ids[:MAX_DECOMPOSED_WINDOW_EVENTS]
    listed = set(differing_ids[:MAX_LISTED_WINDOW_EVENTS])
    control_events = _cached_scan(control_dir, control_scan["case_id"],
                                  decomposed, claim_identity=None,
                                  cache=cache)["events_by_id"]
    fault_events = _cached_scan(fault_dir, fault_scan["case_id"], decomposed,
                                claim_identity=None, cache=cache)["events_by_id"]
    other_paths: dict = {}
    events = []
    for event_id in decomposed:
        control_event = control_events.get(event_id)
        fault_event = fault_events.get(event_id)
        counts = {"session_identity_field_count": 0,
                  "session_identity_digest_field_count": 0,
                  "other_dataflow_field_count": 0}
        examples = []
        if control_event is None or fault_event is None:
            # 事件只在一边出现：记成一条其它数据流差异（结构差异）。
            counts["other_dataflow_field_count"] = 1
            other_paths["<event present in only one trace>"] = (
                other_paths.get("<event present in only one trace>", 0) + 1)
            label = {"path": "<event present in only one trace>",
                     "control": control_event is not None,
                     "fault": fault_event is not None}
            examples.append(label)
        else:
            comparison = compare_events(control_event, fault_event, cap=None)
            for item in comparison["differing_fields"]:
                kind = classify_differing_leaf(item["path"])
                if kind == "other_dataflow":
                    counts["other_dataflow_field_count"] += 1
                    other_paths[item["path"]] = other_paths.get(item["path"], 0) + 1
                    if len(examples) < 5:
                        examples.append({"path": item["path"],
                                         "control": item["control"],
                                         "fault": item["fault"]})
                else:
                    counts[f"{kind}_field_count"] += 1
        record["session_identity_field_count"] += counts[
            "session_identity_field_count"]
        record["session_identity_digest_field_count"] += counts[
            "session_identity_digest_field_count"]
        record["other_dataflow_field_count"] += counts[
            "other_dataflow_field_count"]
        if event_id in listed:
            events.append({
                "event_id": event_id,
                "kind": (control_event or {}).get("kind"),
                "component": (control_event or {}).get("component"),
                **counts, "example_paths": examples})
    record["events"] = events
    record["other_dataflow_paths"] = [
        {"path": path, "occurrences": count}
        for path, count in sorted(other_paths.items(),
                                  key=lambda item: (-item[1], item[0]))
    ][:MAX_LISTED_WINDOW_PATHS]
    return record


def _reproducibility(entry: Mapping, spec, *, variant_dir: Path,
                     status: str, failures: list) -> dict:
    variant = entry["variant"]
    document_path = variant_dir / "fault_document.json"
    replay_path = variant_dir / "minimal_replay.json"
    document_present = document_path.is_file()
    replay_present = replay_path.is_file()
    if status == STATUS_CALIBRATED and not document_present:
        raise FaultQualityError(
            f"{variant}: calibrated 变体缺少 fault_document.json（必需输入）: "
            f"{document_path}")
    if status == STATUS_CALIBRATED and not replay_present:
        raise FaultQualityError(
            f"{variant}: calibrated 变体缺少 minimal_replay.json（必需输入）: "
            f"{replay_path}")
    if not replay_present:
        reason = (f"没有 minimal_replay.json（status={status}；期望的重放材料"
                  f"不存在）: {replay_path}")
        return {
            "minimal_replay_present": False, "fault_document_present":
                document_present,
            "minimal_replay": None, "fault_document": None,
            "digest_equal": None, "embedded_document_digest_equal": None,
            "recorded_fault_document_sha256_matches": None,
            "minimal_replay_file_sha256_matches": None,
            "finding_ids_joined": None, "finding_ids": None,
            "fault_document_canonical_sha256": None,
            "minimal_replay_fault_document_sha256": None,
            "ok": False, "reason": reason,
        }
    document = _read_json(document_path, f"{variant} fault document")
    canonical_sha = _canonical_sha256(document)
    replay = _read_json(replay_path, f"{variant} minimal replay")
    recorded = entry.get("fault_document") or {}
    replay_recorded = entry.get("minimal_replay") or {}
    replay_sha = replay.get("fault_document_sha256")
    embedded = replay.get("fault_document")
    embedded_sha = (None if not isinstance(embedded, Mapping)
                    else _canonical_sha256(embedded))
    replay_finding_ids = [item.get("finding_id")
                          for item in (replay.get("findings") or [])
                          if isinstance(item, Mapping)]
    family_ids = [item for item in (entry.get("finding_ids") or [])
                  if isinstance(item, str)]
    joined = (None if not replay_finding_ids
              else set(replay_finding_ids) == set(family_ids))
    recorded_match = recorded.get("sha256") == canonical_sha
    replay_file_match = replay_recorded.get("sha256") == _canonical_sha256(replay)
    digest_equal = replay_sha == canonical_sha
    embedded_match = embedded_sha is None or embedded_sha == canonical_sha
    ok = bool(digest_equal and embedded_match and recorded_match
              and replay_file_match and joined is not False)
    if not digest_equal:
        failures.append({
            "variant": variant, "check": "minimal_replay_digest_join",
            "reason": (
                f"{variant}: minimal_replay.json 的 fault_document_sha256="
                f"{replay_sha!r} 不等于 fault_document.json 的 canonical 摘要="
                f"{canonical_sha!r}；可重放材料与故障配置对不上")})
    if not embedded_match:
        failures.append({
            "variant": variant, "check": "minimal_replay_embedded_document",
            "reason": (
                f"{variant}: minimal_replay.json 内嵌 fault_document 的 canonical "
                f"摘要={embedded_sha!r} 与其 fault_document_sha256/故障文档="
                f"{canonical_sha!r} 不一致")})
    if not recorded_match:
        failures.append({
            "variant": variant, "check": "fault_document_recorded_sha256",
            "reason": (
                f"{variant}: 汇总登记的 fault_document sha256="
                f"{recorded.get('sha256')!r} 不等于文件实测 canonical 摘要="
                f"{canonical_sha!r}（文件 {document_path}）")})
    if not replay_file_match:
        failures.append({
            "variant": variant, "check": "minimal_replay_recorded_sha256",
            "reason": (
                f"{variant}: 汇总登记的 minimal_replay sha256="
                f"{replay_recorded.get('sha256')!r} 不等于文件实测 canonical 摘要="
                f"{_canonical_sha256(replay)!r}（文件 {replay_path}）")})
    if joined is False:
        failures.append({
            "variant": variant, "check": "replay_finding_ids",
            "reason": (
                f"{variant}: minimal_replay.json 的 finding_ids="
                f"{sorted(replay_finding_ids)} 与故障族观测的 finding_ids="
                f"{sorted(family_ids)} 不一致")})
    return {
        "minimal_replay_present": True, "fault_document_present": True,
        "fault_document": {**_path_record(document_path),
                           "schema_version": document.get("schema_version"),
                           "faults": len(document.get("faults") or []),
                           "canonical_sha256": canonical_sha,
                           "recorded_sha256": recorded.get("sha256")},
        "minimal_replay": {**_path_record(replay_path),
                           "schema_version": replay.get("schema_version"),
                           "calibration_only": replay.get("calibration_only"),
                           "observation_boundary":
                               replay.get("observation_boundary"),
                           "findings": len(replay.get("findings") or []),
                           "sha256": _canonical_sha256(replay),
                           "recorded_sha256": replay_recorded.get("sha256")},
        "fault_document_canonical_sha256": canonical_sha,
        "minimal_replay_fault_document_sha256": replay_sha,
        "embedded_fault_document_sha256": embedded_sha,
        "digest_equal": bool(digest_equal),
        "embedded_document_digest_equal": bool(embedded_match),
        "recorded_fault_document_sha256_matches": bool(recorded_match),
        "minimal_replay_file_sha256_matches": bool(replay_file_match),
        "finding_ids": replay_finding_ids,
        "finding_ids_joined": joined,
        "ok": ok, "reason": None if ok else "可重放材料与故障文档未全部对上",
    }


def _identity_record(run_dir: Path) -> dict:
    path = Path(run_dir) / "online_run_identity.json"
    document, problem = _try_read_json(path)
    if document is None:
        return {"available": False, "path": str(path), "reason": problem,
                "run_id": None, "manifest_sha256": None, "graph_sha256": None,
                "topology_sha256": None, "dependency_graph_sha256": None,
                "source_files_count": None, "source_files_sha256": None,
                "declaration_sha256": None, "_declaration_leaves": {}}
    identity = document.get("identity")
    identity = identity if isinstance(identity, Mapping) else {}
    run_config = identity.get("run_config")
    run_config = run_config if isinstance(run_config, Mapping) else {}
    session = identity.get("session")
    session = session if isinstance(session, Mapping) else {}
    runtime_paths = identity.get("runtime_paths")
    runtime_paths = runtime_paths if isinstance(runtime_paths, Mapping) else {}
    declaration = runtime_paths.get("declaration")
    declaration = declaration if isinstance(declaration, Mapping) else {}
    compiled = runtime_paths.get("compiled")
    compiled = compiled if isinstance(compiled, Mapping) else {}
    compiled_session = compiled.get("session")
    compiled_session = (compiled_session
                        if isinstance(compiled_session, Mapping) else {})
    contract = declaration.get("contract")
    contract = contract if isinstance(contract, Mapping) else {}
    dependency = identity.get("dependency_graph")
    dependency = dependency if isinstance(dependency, Mapping) else {}
    source_files = identity.get("source_files")
    source_files = source_files if isinstance(source_files, list) else None
    return {
        "available": True, "path": str(path), "reason": None,
        "run_id": run_config.get("run_id"),
        "manifest_sha256": session.get("manifest_sha256"),
        "graph_sha256": (compiled_session.get("graph_sha256")
                         or contract.get("graph_sha256")),
        "topology_sha256": compiled_session.get("topology_sha256"),
        "dependency_graph_sha256": dependency.get("sha256"),
        "source_files_count": (None if source_files is None
                               else len(source_files)),
        "source_files_sha256": (None if source_files is None
                                else _canonical_sha256(source_files)),
        "declaration_sha256": (_canonical_sha256(declaration)
                               if declaration else None),
        "_declaration_leaves": _leaf_paths(declaration) if declaration else {},
        "_source_files": ({} if source_files is None else {
            str(item.get("path")): item.get("sha256")
            for item in source_files if isinstance(item, Mapping)}),
    }


def _source_file_diff(control: Mapping, fault: Mapping) -> dict:
    left = control.get("_source_files") or {}
    right = fault.get("_source_files") or {}
    changed = sorted(path for path in set(left) & set(right)
                     if left[path] != right[path])
    removed = sorted(set(left) - set(right))
    added = sorted(set(right) - set(left))
    return {
        "equal": set(left) == set(right) and not changed,
        "changed": changed[:MAX_LISTED_SOURCE_FILES],
        "changed_count": len(changed),
        "removed": removed[:MAX_LISTED_SOURCE_FILES],
        "removed_count": len(removed),
        "added": added[:MAX_LISTED_SOURCE_FILES],
        "added_count": len(added),
    }


def _same_condition(entry: Mapping, *, control_dir: Path, fault_dir: Path,
                    boundary: Mapping, cache: dict) -> dict:
    key = ("identity", str(Path(control_dir).resolve()),
           str(Path(fault_dir).resolve()))
    if key not in cache:
        cache[key] = (_identity_record(control_dir), _identity_record(fault_dir))
    control, fault = cache[key]
    if not (control["available"] and fault["available"]):
        missing = [item["path"] for item in (control, fault)
                   if not item["available"]]
        return {
            "available": False, "degraded": None,
            "reason": f"缺少可读的 online_run_identity.json：{missing}",
            "case_window_dataflow_identical":
                boundary["recorded_traces"]["case_window_dataflow_identical"],
            "control_trace_sha256_recorded": (entry.get("source_run") or {}).get(
                "trace_sha256"),
            "control_trace_sha256_measured":
                boundary["recorded_traces"]["control"]["trace_sha256_measured"],
            "control_trace_unchanged": (
                boundary["recorded_traces"]["control"]["trace_sha256_measured"]
                == (entry.get("source_run") or {}).get("trace_sha256")),
        }
    control_leaves = control.pop("_declaration_leaves", {})
    fault_leaves = fault.pop("_declaration_leaves", {})
    diff = []
    for path in sorted(set(control_leaves) | set(fault_leaves)):
        if control_leaves.get(path) == fault_leaves.get(path):
            continue
        diff.append({"path": path, "control": control_leaves.get(path),
                     "fault": fault_leaves.get(path)})
    differing = {
        name: control.get(name) != fault.get(name)
        for name in ("manifest_sha256", "graph_sha256", "topology_sha256",
                     "dependency_graph_sha256", "source_files_sha256",
                     "declaration_sha256")}
    source_files = _source_file_diff(control, fault)
    degraded = any(differing.values())
    notes = []
    if differing["graph_sha256"]:
        notes.append(
            "对照运行与故障会话的 runtime path graph_sha256 不同"
            f"（{control.get('graph_sha256')} -> {fault.get('graph_sha256')}）："
            "两次会话不是逐图同条件；注入边界仍按锚点事件逐字段测量")
    if differing["manifest_sha256"]:
        notes.append("两次会话的 online_session_manifest 摘要不同（会话身份，"
                     "不参与数据流对照）")
    if differing["source_files_sha256"]:
        notes.append(
            "两次会话钉住的 source_files 清单不同（改动的文件 "
            f"{source_files['changed']}，新增 {source_files['added']}，"
            f"移除 {source_files['removed']}）：这不是同源码条件")
    if differing["declaration_sha256"]:
        notes.append(
            f"runtime path declaration 有 {len(diff)} 个字段不同"
            "（例如持久状态规则），同条件仅限 case_id + 事件 ID / tick / 原值")
    window_diff = boundary["recorded_traces"]["case_window_diff"]
    if not boundary["recorded_traces"]["case_window_dataflow_identical"]:
        notes.append(
            f"同一 case {entry.get('case_id')} 的事件窗口在两次会话之间并非逐字段"
            f"相同：{window_diff['differing_event_count']} 个事件不同（逐会话身份"
            f"字段 {window_diff['session_identity_field_count']} 个、身份摘要字段 "
            f"{window_diff['session_identity_digest_field_count']} 个、其它数据流"
            f"字段 {window_diff['other_dataflow_field_count']} 个；其它数据流示例 "
            f"{window_diff['other_dataflow_paths'][:3]}）：锚点相等只覆盖被钉住的事件")
    control_trace_measured = (boundary["recorded_traces"]["control"]
                              ["trace_sha256_measured"])
    recorded = (entry.get("source_run") or {}).get("trace_sha256")
    return {
        "available": True, "degraded": degraded, "reason": None,
        "control_run_id": control.get("run_id"),
        "fault_run_id": fault.get("run_id"),
        "run_id_differs": control.get("run_id") != fault.get("run_id"),
        "manifest_sha256_equal": not differing["manifest_sha256"],
        "graph_sha256_equal": not differing["graph_sha256"],
        "topology_sha256_equal": not differing["topology_sha256"],
        "dependency_graph_sha256_equal": not differing["dependency_graph_sha256"],
        "source_files_equal": not differing["source_files_sha256"],
        "source_files_count": control.get("source_files_count"),
        "source_file_diff": source_files,
        "path_declaration_equal": not differing["declaration_sha256"],
        "path_declaration_differing_field_count": len(diff),
        "path_declaration_differing_fields": diff[:MAX_LISTED_FIELD_DIFFS],
        "case_window_identical":
            boundary["recorded_traces"]["case_window_identical"],
        "case_window_dataflow_identical":
            boundary["recorded_traces"]["case_window_dataflow_identical"],
        "control_trace_sha256_recorded": recorded,
        "control_trace_sha256_measured": control_trace_measured,
        "control_trace_unchanged": control_trace_measured == recorded,
        "notes": notes,
    }


def _unavailable_variant_report(entry: Mapping, spec, *, variant_dir: Path,
                                reason: str) -> dict:
    variant = entry["variant"]
    return {
        "kind": entry.get("kind"), "variant": variant,
        "checker": entry.get("checker"), "status": entry.get("status"),
        "expected_finding": entry.get("expected_finding"),
        "declared_expected_finding": spec.expected_finding,
        "case_id": entry.get("case_id"),
        "inputs": {
            "fault_session_dir": {"path": str(variant_dir / "session"),
                                  "present": (variant_dir / "session").is_dir()},
            "fault_receipts": None, "control_run_dir": None,
            "control_trace": None, "fault_trace": None,
            "minimal_replay": None, "fault_document": None,
            "run_identity": None, "reason": reason},
        "detection": _detection(entry, spec, None,
                                {"finding_ids_joined": None}),
        "injection_boundary": {"measured": False, "ok": None,
                               "reason": reason},
        "same_condition": {"available": False, "degraded": None,
                           "reason": reason},
        "reproducibility": {
            "minimal_replay_present": (variant_dir / "minimal_replay.json").is_file(),
            "minimal_replay": None, "fault_document": None,
            "digest_equal": None, "finding_ids_joined": None,
            "finding_ids": None, "ok": None, "reason": reason},
        "conclusions": _conclusions(entry, spec, detection=None,
                                    boundary=None, reproducibility=None,
                                    same_condition=None, reason=reason),
        "failures": [],
    }


def _conclusions(entry: Mapping, spec, *, detection, boundary, reproducibility,
                 same_condition, reason: str | None = None) -> dict:
    variant = entry["variant"]
    established: list = []
    not_established: list = [
        f"{variant}: 不构成对故障类 {spec.kind} 的检测灵敏度/覆盖率结论"
        "（单点见证，未做同类多变体扫描）",
        "注入 finding 不是自然 DUT 缺陷：不得作为 DUT 缺陷证据，不得并入自然缺陷统计",
        "本对照不运行 RTL、不重放 minimal_replay.json，因此不证明新进程可复现",
    ]
    if reason is not None:
        not_established.insert(0, f"{variant}: 未检测（{reason}）")
    if detection is not None and detection.get("detected"):
        established.append(
            f"检测：{detection['expected_finding']} 在故障会话 case "
            f"{detection['fired_case_id']} 的收据里触发（收据状态 "
            f"{detection['fired_receipt_status']}），且故障族观测给出 "
            f"finding_ids={detection['family_finding_ids']}")
    elif detection is not None:
        not_established.insert(0, f"检测未建立：{detection.get('reason')}")
    if boundary is not None:
        if boundary.get("ok"):
            mutated = boundary["mutated_field"]
            detail = ("" if not mutated.get("applicable")
                      else (f"；记录的故障 trace 在锚点上仍是原值 "
                            f"{mutated['original_value']!r}（注入值 "
                            f"{mutated['injected_value']!r} 未出现）"))
            established.append(
                "注入边界：选择器钉住的 "
                f"{len(boundary['anchored_event_ids'])} 个事件在对照/故障 trace 中"
                f"数据流字段逐字段相等（身份字段差异 "
                f"{boundary['identity_differing_field_count']} 个已单独列出）"
                f"{detail}")
        else:
            not_established.insert(0,
                                   f"注入边界未建立：{boundary.get('reason')}")
    if reproducibility is not None and reproducibility.get("ok"):
        established.append(
            "可重放材料：minimal_replay.json 存在，且 fault_document_sha256 == "
            f"该变体 fault_document.json 的 canonical 摘要 "
            f"（{reproducibility.get('fault_document_canonical_sha256')}）")
    elif reproducibility is not None and reproducibility.get("ok") is False:
        not_established.insert(0, "可重放材料未建立："
                               f"{reproducibility.get('reason')}")
    if same_condition is not None and same_condition.get("notes"):
        label = ("同条件降级：" if same_condition.get("degraded")
                 else "同条件注意：")
        not_established.insert(0, label + "；".join(same_condition["notes"]))
    return {
        "detection_established": (None if detection is None
                                  else bool(detection.get("detected"))),
        "boundary_established": (None if boundary is None
                                 else boundary.get("ok")),
        "reproducibility_established": (None if reproducibility is None
                                        else reproducibility.get("ok")),
        "same_condition_degraded": (None if same_condition is None
                                    else same_condition.get("degraded")),
        "established": established, "not_established": not_established,
    }


def _analyze_variant(entry: Mapping, *, calibration_root: Path,
                     cache: dict) -> tuple[dict, list]:
    variant = entry.get("variant")
    if not isinstance(variant, str):
        raise FaultQualityError(
            f"calibration aggregate variant entry has no variant name: {entry!r}")
    spec = SPEC_BY_VARIANT.get(variant)
    if spec is None:
        raise FaultQualityError(
            f"unknown variant {variant!r} in calibration aggregate; known "
            f"variants: {', '.join(DECLARED_VARIANTS)}")
    status = entry.get("status")
    if status not in KNOWN_STATUSES:
        raise FaultQualityError(
            f"{variant}: unknown status {status!r}（已知状态 "
            f"{list(KNOWN_STATUSES)}）；无法如实归类")
    if entry.get("kind") != spec.kind:
        raise FaultQualityError(
            f"{variant}: aggregate kind={entry.get('kind')!r} 与声明 "
            f"{spec.kind!r} 不一致")
    if entry.get("checker") != spec.checker:
        raise FaultQualityError(
            f"{variant}: aggregate checker={entry.get('checker')!r} 与声明 "
            f"{spec.checker!r} 不一致")
    if entry.get("expected_finding") != spec.expected_finding:
        raise FaultQualityError(
            f"{variant}: aggregate expected_finding="
            f"{entry.get('expected_finding')!r} 与声明 "
            f"{spec.expected_finding!r} 不一致（契约漂移）")
    variant_dir = calibration_root / variant
    if status not in SESSION_STATUSES:
        reason = (f"status={status}：该变体没有可对照的故障会话"
                  + (f"（{entry.get('reason')}）" if entry.get("reason") else ""))
        report = _unavailable_variant_report(entry, spec,
                                             variant_dir=variant_dir,
                                             reason=reason)
        return report, []

    failures: list = []
    run = entry.get("run") if isinstance(entry.get("run"), Mapping) else None
    output_dir_record = (run or {}).get("output_dir") if run else None
    if not isinstance(output_dir_record, Mapping) or not (
            output_dir_record.get("resolved") or output_dir_record.get("path")):
        raise FaultQualityError(
            f"{variant}: status={status} 但没有 run.output_dir 记录；"
            "故障会话产物是必需输入")
    fault_dir = Path(output_dir_record.get("resolved")
                     or output_dir_record.get("path"))
    if not fault_dir.is_dir():
        raise FaultQualityError(
            f"{variant}: status={status} 记录的故障会话目录不存在: {fault_dir}")
    source_run = entry.get("source_run")
    if not isinstance(source_run, Mapping):
        raise FaultQualityError(
            f"{variant}: 汇总缺少 source_run（对照运行）记录；无法建立同条件对照")
    control_dir = Path(source_run.get("resolved") or source_run.get("path") or "")
    if not control_dir.is_dir():
        raise FaultQualityError(
            f"{variant}: 对照运行目录不存在: {control_dir}")
    case_id = entry.get("case_id")
    if not isinstance(case_id, str):
        raise FaultQualityError(
            f"{variant}: status={status} 但没有钉住的 case_id；无法对照")
    selector = entry.get("selector")
    if not isinstance(selector, Mapping) or not selector:
        raise FaultQualityError(
            f"{variant}: 汇总没有可用 selector；注入边界无法测量")
    anchored = _anchored_event_ids(selector)
    if not anchored:
        raise FaultQualityError(
            f"{variant}: selector 没有 *_event_id 锚点；注入边界无法测量")
    observation_id = entry.get("observation_event_id")
    claim_identity = None
    if spec.operation == "duplicate":
        if type(observation_id) is not int:
            raise FaultQualityError(
                f"{variant}: 重复提交变体没有整数 observation_event_id；"
                "无法测量记录 trace 中的声明计数")
        probe = _cached_scan(control_dir, case_id, anchored,
                             claim_identity=None, cache=cache)
        if not probe["found"]:
            raise FaultQualityError(
                f"{variant}: 对照 trace {control_dir} 里找不到 case {case_id}")
        anchor_event = probe["events_by_id"].get(observation_id)
        if anchor_event is None:
            raise FaultQualityError(
                f"{variant}: 对照 trace 的 case {case_id} 缺少重复提交锚点事件 "
                f"event_id={observation_id}")
        claim_identity = anchor_event

    receipts = _read_receipts(fault_dir, variant)
    try:
        control_scan = _cached_scan(control_dir, case_id, anchored,
                                    claim_identity=claim_identity, cache=cache)
    except FaultQualityError as exc:
        raise FaultQualityError(f"{variant}: 对照 trace 不可读: {exc}") from exc
    try:
        fault_scan = _cached_scan(fault_dir, case_id, anchored,
                                  claim_identity=claim_identity, cache=cache)
    except FaultQualityError as exc:
        raise FaultQualityError(f"{variant}: 故障 trace 不可读: {exc}") from exc
    for role, scan in (("对照", control_scan), ("故障", fault_scan)):
        if not scan["found"]:
            raise FaultQualityError(
                f"{variant}: {role} trace {scan['run_dir']} 里找不到 case "
                f"{case_id}")
        if scan["missing_event_ids"]:
            raise FaultQualityError(
                f"{variant}: 锚点事件 "
                + ", ".join(f"event_id={item}"
                            for item in scan["missing_event_ids"])
                + f" 在{role} trace 中缺失: {scan['run_dir']}"
                "（注入边界无法测量）")

    reproducibility = _reproducibility(entry, spec, variant_dir=variant_dir,
                                       status=status, failures=failures)
    boundary = _injection_boundary(entry, spec, control_scan=control_scan,
                                   fault_scan=fault_scan, control_dir=control_dir,
                                   fault_dir=fault_dir, cache=cache,
                                   failures=failures)
    detection = _detection(entry, spec, receipts, reproducibility)
    same_condition = _same_condition(entry, control_dir=control_dir,
                                     fault_dir=fault_dir, boundary=boundary,
                                     cache=cache)
    inputs = {
        "fault_session_dir": {**_path_record(fault_dir), "present": True},
        "fault_receipts": {**receipts["path"], "present": True,
                           "sha256": receipts["sha256"],
                           "lines": receipts["lines"]},
        "control_run_dir": {**_path_record(control_dir), "present": True},
        "control_trace": {
            **_path_record(control_dir / control_scan["trace_file"]),
            "present": True,
            "sha256_measured": boundary["recorded_traces"]["control"]
            ["trace_sha256_measured"],
            "sha256_recorded": source_run.get("trace_sha256")},
        "fault_trace": {
            **_path_record(fault_dir / fault_scan["trace_file"]),
            "present": True,
            "sha256_measured": boundary["recorded_traces"]["fault"]
            ["trace_sha256_measured"]},
        "minimal_replay": (reproducibility.get("minimal_replay")
                           if reproducibility.get("minimal_replay_present")
                           else {"path": str(variant_dir / "minimal_replay.json"),
                                 "present": False}),
        "fault_document": (reproducibility.get("fault_document")
                           if reproducibility.get("fault_document_present")
                           else {"path": str(variant_dir / "fault_document.json"),
                                 "present": False}),
        "run_identity": {
            "control": same_condition.get("control_run_id"),
            "fault": same_condition.get("fault_run_id"),
            "available": same_condition.get("available")},
        "reason": None,
    }
    return {
        "kind": spec.kind, "variant": variant, "checker": spec.checker,
        "status": status, "expected_finding": entry.get("expected_finding"),
        "declared_expected_finding": spec.expected_finding,
        "case_id": case_id, "operation": spec.operation,
        "mutated_field": spec.field,
        "selector": dict(selector), "mutation": entry.get("mutation"),
        "inputs": inputs, "detection": detection,
        "injection_boundary": boundary, "same_condition": same_condition,
        "reproducibility": reproducibility,
        "conclusions": _conclusions(entry, spec, detection=detection,
                                    boundary=boundary,
                                    reproducibility=reproducibility,
                                    same_condition=same_condition),
        "failures": failures,
    }, failures


# --------------------------------------------------------------------------
# 汇总
# --------------------------------------------------------------------------

def _rollup(entries: Sequence[Mapping]) -> tuple[dict, dict]:
    per_kind: dict = {}
    for kind in FAULT_KINDS:
        declared = sorted(spec.variant for spec in _SPECS if spec.kind == kind)
        items = sorted((item for item in entries if item["kind"] == kind),
                       key=lambda item: item["variant"])
        counts = {status: sum(1 for item in items if item["status"] == status)
                  for status in COUNTED_STATUSES}
        per_kind[kind] = {
            "declared": len(declared), "analyzed": len(items),
            "total": len(items),
            **counts,
            "variants": [item["variant"] for item in items],
            "never_calibrated": sorted(
                item["variant"] for item in items
                if item["status"] != STATUS_CALIBRATED),
            "declared_variants": declared,
        }
    totals = {
        "total": len(entries),
        **{status: sum(1 for item in entries if item["status"] == status)
           for status in COUNTED_STATUSES},
        "detected": sum(1 for item in entries
                        if item["detection"].get("detected") is True),
        "boundary_measured": sum(1 for item in entries
                                 if item["injection_boundary"].get("measured")),
        "boundary_ok": sum(1 for item in entries
                           if item["injection_boundary"].get("ok") is True),
        "reproducibility_ok": sum(
            1 for item in entries
            if item["reproducibility"].get("ok") is True),
        "same_condition_degraded": sum(
            1 for item in entries
            if item["same_condition"].get("degraded") is True),
    }
    return per_kind, totals


INPUT_POLICY = {
    "required_for_any": ["<root>/fault_family_calibration.json"],
    "required_per_status": {
        STATUS_CALIBRATED: [
            "<variant>/fault_document.json", "<variant>/minimal_replay.json",
            "<variant>/session/receipts.jsonl", "<variant>/session/<trace>",
            "<control-run>/<trace>"],
        STATUS_NOT_FIRED: [
            "<variant>/fault_document.json", "<variant>/session/receipts.jsonl",
            "<variant>/session/<trace>", "<control-run>/<trace>"],
        STATUS_ERROR: ["<variant>/minimal_replay.error"],
        STATUS_NO_WITNESS: [],
        STATUS_SELECTED: [],
    },
    "optional": ["<run>/online_run_identity.json"],
    "refusal_rule": (
        "任何必需输入缺失、不可解析或与 _SPECS/汇总声明不一致都是 refusal"
        "（非零退出 + 精确原因），绝不静默通过、绝不写 0；"
        "error/no_witness_window/selected 的会话缺失是被状态声明的既定事实，"
        "如实计入汇总而不是拒绝。"),
    "exit_codes": {
        str(EXIT_OK): "全部已分析变体 calibrated 且所有完整性检查通过",
        str(EXIT_REFUSED): "参数/路径/必需输入缺失或不可解析（拒绝）",
        str(EXIT_INCOMPLETE): "完整性检查通过但有变体从未校准",
        str(EXIT_MISMATCH): "测量到不一致（锚点数据流字段、摘要连接等）",
    },
}


def resolve_variants(names: Sequence[str] | None) -> tuple[str, ...] | None:
    if not names:
        return None
    requested = []
    for name in names:
        key = str(name).replace(":", "/").split("/")[-1].strip()
        if key not in SPEC_BY_VARIANT:
            raise FaultQualityError(
                f"unknown variant {name!r}; known variants: "
                f"{', '.join(DECLARED_VARIANTS)}")
        if key not in requested:
            requested.append(key)
    return tuple(sorted(requested))


def analyze_calibration_root(calibration_root: Path, *,
                             variants: Sequence[str] | None = None) -> dict:
    """只读分析一个已完成的校准根目录，返回 ``p5_fault_quality.v1`` 文档。"""
    root = Path(calibration_root)
    aggregate_path = root / "fault_family_calibration.json"
    if not root.is_dir():
        raise FaultQualityError(
            f"calibration root does not exist: {root}"
            f"（校准汇总期望在 {aggregate_path}）")
    aggregate = _read_json(aggregate_path, "calibration aggregate")
    if aggregate.get("schema_version") != CALIBRATION_SCHEMA_VERSION:
        raise FaultQualityError(
            f"calibration aggregate schema_version must be "
            f"{CALIBRATION_SCHEMA_VERSION!r}, found "
            f"{aggregate.get('schema_version')!r}: {aggregate_path}")
    entries = aggregate.get("variants")
    if not isinstance(entries, list) or not entries:
        raise FaultQualityError(
            f"calibration aggregate has no variants list: {aggregate_path}")
    requested = resolve_variants(variants)
    reports = []
    analyzed = []
    failures: list = []
    cache: dict = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise FaultQualityError(
                f"calibration aggregate variant entry is not an object: "
                f"{entry!r}")
        name = entry.get("variant")
        if requested is not None and name not in requested:
            continue
        report, variant_failures = _analyze_variant(
            entry, calibration_root=root, cache=cache)
        reports.append(report)
        analyzed.append(report["variant"])
        failures.extend(variant_failures)
    if requested is not None:
        absent = sorted(set(requested) - set(analyzed))
        if absent:
            raise FaultQualityError(
                f"requested variant(s) {absent} 不在校准汇总 {aggregate_path} 的 "
                f"variants 里（已有：{sorted(str(item.get('variant')) for item in entries)}）")
    reports.sort(key=lambda item: item["variant"])
    failures.sort(key=lambda item: (item["variant"], item["check"], item["reason"]))
    per_kind, totals = _rollup(reports)
    never_calibrated = sorted(item["variant"] for item in reports
                              if item["status"] != STATUS_CALIBRATED)
    document = {
        "schema_version": SCHEMA_VERSION,
        "calibration_only": True,
        "observation_boundary": OBSERVATION_BOUNDARY,
        "statement": {
            "calibration_only": True,
            "observation_boundary": OBSERVATION_BOUNDARY,
            "injected_findings_are_natural_dut_defects": False,
            "text": STATEMENT_TEXT,
        },
        "calibration_root": _path_record(root),
        "aggregate": {
            **_path_record(aggregate_path),
            "sha256": _file_sha256(aggregate_path),
            "schema_version": aggregate.get("schema_version"),
            "select_only": bool(aggregate.get("select_only")),
        },
        "requested_variants": (None if requested is None else list(requested)),
        "analyzed_variants": sorted(analyzed),
        "not_analyzed_variants": sorted(set(DECLARED_VARIANTS) - set(analyzed)),
        "input_policy": INPUT_POLICY,
        "variants": reports,
        "fault_class_rollup": per_kind,
        "rollup": totals,
        "never_calibrated": never_calibrated,
        "fully_calibrated": not never_calibrated,
        "ok": not failures,
        "failures": failures,
        "limits": list(LIMITS),
    }
    return document


def status_exit_code(document: Mapping) -> int:
    if not document.get("ok"):
        return EXIT_MISMATCH
    if not document.get("fully_calibrated"):
        return EXIT_INCOMPLETE
    return EXIT_OK


def render_document(document: Mapping) -> str:
    """确定性渲染：两次运行的输出逐字节相同。"""
    return json.dumps(document, indent=1, sort_keys=True,
                      ensure_ascii=False, allow_nan=False) + "\n"


def write_document(path: Path, document: Mapping) -> str:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_document(document), encoding="utf-8")
    return _canonical_sha256(document)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="P5 受控故障同条件质量对照（只读，calibration-only）")
    parser.add_argument("--calibration-root", type=Path, required=True,
                        help="已完成的校准根目录（含 fault_family_calibration.json）")
    parser.add_argument("--variant", action="append",
                        help="只对照指定变体（variant 或 kind/variant，可重复）")
    parser.add_argument("--output", type=Path,
                        help="把文档写到该路径（默认只打印到 stdout）")
    parser.add_argument("--quiet", action="store_true",
                        help="配合 --output 时不打印文档")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        document = analyze_calibration_root(args.calibration_root,
                                            variants=args.variant)
    except FaultQualityError as exc:
        print(f"p5-fault-quality-error: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    except (ValueError, OSError, RuntimeError) as exc:  # pragma: no cover - 防御
        print(f"p5-fault-quality-error: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return EXIT_REFUSED
    text = render_document(document)
    if args.output is not None:
        write_document(args.output, document)
    if not (args.quiet and args.output is not None):
        sys.stdout.write(text)
    return status_exit_code(document)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
