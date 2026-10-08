# P4 候选拒绝码（`candidate_rejection.v1`）软件门禁

日期：2026-10-07。P4 的验收要求包含"受信字段描述拒绝协议保留位、错误宽度和已绑定输入"以及"每种操作子保存采用/拒绝原因"；此前在线回执只有自然语言 `candidate_disposition_reason`，无法机器复算。本轮把 CPU 侧候选的拒绝原因细化为**版本化、分层、带失败指针**的拒绝码。

## 交付

| 文件 | 内容 |
|---|---|
| `src/myfuzz/scenario/rejection_codes.py`（新增） | `REJECTION_SCHEMA_VERSION = "candidate_rejection.v1"`；35 个分层码（`StrEnum`）＋英文说明；`frozen` 值对象 `Rejection(code, pointer, detail, schema_version)` 与 `document()`/`from_document()`；`RejectionError(ValueError)`（携带 `.rejection`）；`rejection_of()` 桥；冻结目录摘要 `rejection_code_catalog_sha256()` |
| `src/myfuzz/scenario/rv32i_sources.py` | 46 处校验分支改为 `reject()`，**0 处裸 `raise`**；自然语言消息逐字保留；新增 `validate_instruction_bytes_detailed()` |
| `src/myfuzz/scenario/online_case_decoder.py` | `decode_candidate()` / `commit_candidate()` 返回结构化 `CandidateDisposition`；保留旧键 `candidate_disposition`、`candidate_disposition_reason`、`source_selection_reason`，新增 `rejection` |
| `tests/scenario/test_rv32i_rejection_codes.py`（新增） | 66 个用例：每个码至少一个真实负例、指针断言、跨路径一致性、目录摘要稳定性、未知码拒绝 |
| `tests/scenario/test_rv32i_mmio_permissions.py` | 追加结构化码断言 |

分层与触发条件（每条均有真实负例）：`isa.*`（非白名单操作/编码、非法操作数组合）、`field.*`（寄存器、立即数、对齐、地址、寄存器冲突）、`fragment.*`（非法序列、越地址空间）、`mmio.*`（窗口声明、权限、宽度、越界、只读/只写、无对齐地址）、`decode.*`（记录/熵/种子/输入边界/覆盖提示）、`ownership.*`（已绑定/固定/未声明字段、范围越界、生产者歧义）、`slot.*`（超出指令预留、已物化、已消费、提案不匹配）、`budget.exhausted`、`path.*`（未声明路径、源不匹配）。

## 门禁

```bash
# 契约缺失 RED：临时移除 rejection_codes.py
PYTHONPATH=src python3 -m pytest tests/scenario/test_rv32i_rejection_codes.py -q -p no:randomly
# 1 error（ModuleNotFoundError）

# 行为 RED：把 reject() 临时退回裸 ValueError
# 39 failed, 27 passed in 0.64s

PYTHONPATH=src python3 -m pytest tests/scenario/test_rv32i_rejection_codes.py -q -p no:randomly
# 66 passed in 0.07s（随机序同）

PYTHONPATH=src python3 -m pytest tests/scenario/test_rv32i_*.py tests/scenario/test_online_*.py -q -p no:randomly
# 151 passed, 35 subtests passed

# 全部 import 被改模块的 14 个测试文件
# 226 passed, 57 subtests passed
```

冻结目录摘要：`f8181f5c93628aedc801c2feb043bc126bfdb6d4383e36ee9706f8beca996464`（本报告写作时的 35 码；改名/增删即失败）。未知码、自造码、错误 `schema_version`、非法 `pointer`、浮点或非 JSON 的 `detail` 一律拒绝。旧 API 返回值、异常消息与 `document()` 规范化清单未变，`except ValueError` 依旧成立。

**后续更新（2026-10-07，移位操作子扩展）：** 为 RV32I `SLLI`/`SRLI`/`SRAI` 新增 `field.bad_shamt`（指针 `instruction.shamt`）与 `isa.reserved_imm_bit`（指针 `fragment[i].immediate`），目录变为 **37 码**，冻结摘要更新为 `86d03337fa3955b18ea05429a1c0eaa8c3c5bb21a56332d02a6a390d7e560577`；两个摘要测试（`tests/scenario/test_rv32i_rejection_codes.py`、`tests/scenario/test_online_candidate_rejection_receipt.py`）已显式更新并注明"35→37，无既有码改名或删除"。本报告表格中的 35 码语义与触发条件不变。

## 限制

- `OnlineCaseDecoder.__init__` 等**声明期**配置校验（约 35 处）仍是普通 `ValueError`：此时尚无候选，`candidate_rejection.v1` 边界只覆盖候选解码/提交路径。
- `slot.materialized` 与 `slot.already_consumed` 通过 `rejection_of(..., occupant_writer_kinds=ReadSnapshot.writer_kinds)` 桥接；无占用者证据时统一判为 `slot.materialized`。
- 未被码覆盖的 memory 分支：片段跨窗口、槽位跨窗口、未接纳先取指、空 `source_event_id`。
- 仓库现有受信描述里没有"协议保留位"语义，最接近的是 `ownership.fixed_input`/`bound_input`；真正的保留位约束应落在字段描述模块。
- **在线 live 回执尚未改用** `decode_candidate()`/`commit_candidate()`（该调用点在 `src/myfuzz/integration/scenario_rfuzz.py`，不在本轮改动集），因此真实运行的回执目前仍只带旧文本原因。
- 本轮为纯软件门禁：未运行任何真实 RTL，未验收真实拒绝／不确定例，也未改变 P4 阶段状态。
