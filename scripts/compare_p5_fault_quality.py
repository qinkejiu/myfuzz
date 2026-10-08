#!/usr/bin/env python3
"""P5 受控故障**同条件质量对照** CLI（只读，calibration-only）。

用法::

    PYTHONPATH=src python3 scripts/compare_p5_fault_quality.py \
        --calibration-root runs/<completed-calibration-root> [--variant V ...] \
        [--output docs/reports/<name>.json] [--quiet]

行为
----
* 只读取已完成的校准产物（``fault_family_calibration.json`` + 逐变体
  ``fault_document.json`` / ``minimal_replay.json`` / ``session/receipts.jsonl``
  / trace），**不写任何输入目录、不跑 RTL、不重放**。
* 输出一份 ``p5_fault_quality.v1`` 文档（默认 stdout；``--output`` 同时落盘），
  两次运行逐字节相同。
* 退出码：``0`` 全部已分析变体 calibrated 且完整性检查全过；``1`` 参数/路径/
  必需输入缺失或不可解析（拒绝，stderr 给出精确原因）；``3`` 完整性通过但有变体
  从未校准；``4`` 测量到不一致（锚点数据流字段、摘要连接等）。
"""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.as_posix() not in sys.path:
    sys.path.insert(0, SRC.as_posix())

from myfuzz.scenario.p5_fault_quality import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
