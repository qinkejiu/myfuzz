# Generic RISC-V CPU Targets Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** 将处理器自动组合扩展为支持分离内存端点和带显式取指身份的统一内存端点，并用 CV32E40P 类 OBI 与 PicoRV32 类 valid/ready fixture 验证同一套 ISA/协议转导器。

**Architecture:** 在 `ProcessorBoundary` 中提取 `RequestClassification`，分离端点用函数名分类，统一端点用有 HDL 源证据的 `instruction_identity` 字段分类。`ProcessorExecution` 继续只按协议选择适配器；新增 `ready-valid-memory@1` 适配器把 valid/ready 总线归一化到 `processor-memory-beat@1`。顶层生成器根据分类记录驱动现有 `req_instruction_i`，契约转导器接口和 ISA 约束保持不变。

**Tech Stack:** Python 3、pytest/unittest、SystemVerilog、Icarus Verilog 或 Verilator、现有协议插件和源爬取器。

## Global Constraints

* 不按 CPU 名称、RTL 路径名称或地址范围选择取指/数据。
* 统一端点缺少有源证据的单比特 `instruction_identity` 时，约束模式必须 fail closed。
* 保持现有 Ibex 分离 OBI 行为和 `processor-memory-beat@1` 接口兼容。
* 不修改或提交 `third_party/` 下任何文件；不覆盖用户已有的 `.superpowers/sdd/task-2-report.md` 修改。
* 每个任务遵守 TDD：先写一个最小失败测试，运行确认失败，再写最小生产代码，运行确认通过。
* 生成物必须继续包含稳定的来源、分类记录、适配器和内容哈希证据。

---

### Task 1: Add request classification to the processor boundary

**Files:**
- Modify: `src/myfuzz/composition/processor_boundary.py`
- Modify: `src/myfuzz/composition/__init__.py`
- Test: `tests/composition/test_processor_boundary.py`

**Interfaces:**
- Consumes: `EndpointCapability`、协议 catalog、现有 memory endpoint functions。
- Produces: `RequestClassification` dataclass、`ProcessorBoundary.classification`、boundary document classification evidence。

- [x] **Step 1: Write the failing tests**

在 `ProcessorBoundaryTests` 添加行为测试：统一端点带 `instruction_identity` 时生成 `mode == "explicit_signal"`、`field_role == "instruction_identity"`、`port == "mem_instr"`；统一端点缺少该字段时抛出 `missing-instruction-identity`；字段宽度不是 1、方向不是输出或没有 source 时分别抛出稳定错误；分离端点生成 `mode == "split_function"`。

~~~python
def test_unified_memory_uses_source_backed_instruction_identity(self):
    document = _valid_document()
    document["endpoints"][-1]["fields"].append(
        _field("instruction_identity", "mem_instr", "output")
    )
    boundary = self.build(document)
    self.assertEqual("explicit_signal", boundary.classification.mode)
    self.assertEqual("instruction_identity", boundary.classification.field_role)
~~~

- [x] **Step 2: Run the focused tests and verify RED**

~~~bash
pytest -q tests/composition/test_processor_boundary.py -k 'instruction_identity or function_classification'
~~~

Expected: FAIL because `classification` does not exist and a unified endpoint without identity currently passes.

- [x] **Step 3: Implement the minimal boundary model**

添加：

~~~python
@dataclass(frozen=True, slots=True)
class RequestClassification:
    mode: str
    field_role: str | None
    port: str | None
    member_path: tuple[str, ...]
    instruction_value: int
    data_value: int
    source: SourceReference | None
    evidence: tuple[str, ...]
~~~

`ProcessorBoundary` 增加 `classification` 字段。分离端点生成 `split_function`；统一端点只接受一个源证据充分、输出方向、宽度为 1 的 `instruction_identity`。该字段从协议适配器连接字段中排除，但保留在 boundary document。错误分别使用 `missing-instruction-identity`、`instruction-identity-width`、`instruction-identity-direction`。

- [x] **Step 4: Run boundary tests and commit**

~~~bash
pytest -q tests/composition/test_processor_boundary.py
git add src/myfuzz/composition/processor_boundary.py src/myfuzz/composition/__init__.py tests/composition/test_processor_boundary.py
git commit -m "feat: model explicit processor request classification"
~~~

### Task 2: Preserve classification in execution IR and add valid/ready adapter

**Files:**
- Modify: `src/myfuzz/composition/processor_execution.py`
- Modify: `src/myfuzz/composition/processor_adapters.py`
- Create: `src/myfuzz/protocols/plugins/ready_valid_memory.json`
- Create: `src/myfuzz/protocols/rtl/ready_valid_processor_memory_adapter.sv`
- Test: `tests/composition/test_processor_execution.py`
- Test: `tests/composition/test_processor_adapters.py`

**Interfaces:**
- Consumes: `ProcessorBoundary.classification` and protocol registry。
- Produces: route-level classification evidence and `ready-valid-memory@1` → `processor-memory-beat@1` adapter。

- [x] **Step 1: Write and run RED tests**

添加执行记录测试：统一 boundary 的 execution document 必须含 `classification.mode == "explicit_signal"` 和 `field_role`；添加 adapter 测试，`resolve_processor_adapter` 对 `ready-valid-memory@1` 返回 `ready-valid-to-processor-memory-beat`，未知扩展抛 `unsupported-extension`。

~~~bash
pytest -q tests/composition/test_processor_execution.py tests/composition/test_processor_adapters.py -k 'classification or ready_valid'
~~~

Expected: FAIL because neither the route record nor protocol adapter exists。

- [x] **Step 2: Add the protocol plugin and adapter registry entry**

插件字段为 `valid`、`ready`、`addr`、`wdata`、`wstrb`、`rdata`，限制为单 outstanding、支持 byte enable 和 bounded response。适配器 source ports 使用：

~~~python
("valid", "valid_i", "input"), ("ready", "ready_o", "output"),
("addr", "addr_i", "input"), ("wdata", "wdata_i", "input"),
("wstrb", "wstrb_i", "input"), ("rdata", "rdata_o", "output"),
~~~

适配器由 `wstrb != 0` 派生 write，缺少 CPU error 信号时将 backend error 置零。

- [x] **Step 3: Implement route evidence and the adapter FSM**

执行路由构造时将 `instruction_identity` 从 protocol fields 连接中排除，并增加 `classification` 对象，记录 `_physical(...)`、源 evidence 和 route endpoint。更新 `processor_execution.v1` 哈希文档。

新增 SystemVerilog FSM：`IDLE` 接受一个 `valid && ready` 请求，`WAIT_BACKEND` 保持地址/数据/strobes 等待后端 response 或 bounded timeout，`RESPOND` 输出 `rdata` 并完成一次 transfer；禁止第二个 outstanding 请求。

- [x] **Step 4: Run focused tests and compile adapter**

~~~bash
pytest -q tests/composition/test_processor_execution.py tests/composition/test_processor_adapters.py
if command -v iverilog >/dev/null; then iverilog -g2012 -s ready_valid_processor_memory_adapter -o /tmp/myfuzz-ready-valid-adapter.vvp src/myfuzz/protocols/rtl/ready_valid_processor_memory_adapter.sv; fi
~~~

- [x] **Step 5: Commit**

~~~bash
git add src/myfuzz/composition/processor_execution.py src/myfuzz/composition/processor_adapters.py src/myfuzz/protocols/plugins/ready_valid_memory.json src/myfuzz/protocols/rtl/ready_valid_processor_memory_adapter.sv tests/composition/test_processor_execution.py tests/composition/test_processor_adapters.py
git commit -m "feat: add unified valid-ready processor adapter"
~~~

### Task 3: Render constrained split and unified processor topologies

**Files:**
- Modify: `src/myfuzz/composition/protocol_composer.py`
- Modify: `src/myfuzz/composition/auto.py`
- Test: `tests/composition/test_protocol_composer.py`
- Test: `tests/integration/test_processor_auto_wiring.py`

**Interfaces:**
- Consumes: execution route classification and existing `ContractTransducerPlan`。
- Produces: top RTL that drives `req_instruction_i` from either route function or explicit physical identity signal。

- [x] **Step 1: Write and run RED renderer tests**

用临时 unified source fixture 生成一条带 `mem_instr` 的 route，要求 constrained renderer 成功；没有 identity 的 fixture 要在 plan 阶段抛 `missing-instruction-identity`。

~~~bash
pytest -q tests/composition/test_protocol_composer.py tests/integration/test_processor_auto_wiring.py -k 'unified or instruction_identity'
~~~

Expected: FAIL because `_validate_processor_transducer` 当前只接受两个 split route。

- [x] **Step 2: Expand topology validation**

保留现有宽度、协议、wait bound、backend capability 校验，并接受以下两个且仅两个拓扑：

~~~python
split = len(routes) == 2 and functions == {
    "instruction_memory_master", "data_memory_master"
}
unified = (
    len(routes) == 1
    and functions <= {"memory_master", "processor_memory_master"}
    and execution.get("classification", {}).get("mode") == "explicit_signal"
)
~~~

其它拓扑继续拒绝。

- [x] **Step 3: Wire and latch the classifier**

将分类物理端口加入 `internal_ports`，确保它由 source module 驱动而不是外部 RFuzz 输入。split 路由继续按函数名生成 0/1；unified 路由在 adapter 接受请求时采样物理 `instruction_identity`，再在 backend request 接受前锁存。现有 transducer 的 ISA、memory domain 和 `req_instruction_i` 接口不变。

- [x] **Step 4: Run constrained suites and commit**

~~~bash
pytest -q tests/composition/test_protocol_composer.py tests/integration/test_processor_auto_wiring.py tests/integration/test_constrained_backend_rtl.py
git add src/myfuzz/composition/protocol_composer.py src/myfuzz/composition/auto.py tests/composition/test_protocol_composer.py tests/integration/test_processor_auto_wiring.py
git commit -m "feat: render constrained unified processor routes"
~~~

### Task 4: Add CPU-neutral CV32E40P/PicoRV32 fixture targets

**Files:**
- Create: `configs/cpus/cv32e40p/official_core_interface_description.json`
- Create: `configs/cpus/picorv32/official_core_interface_description.json`
- Create: `tests/integration/test_generic_cpu_targets.py`

**Interfaces:**
- Consumes: generic interface description schema, adapters and dual-topology renderer。
- Produces: source-pinned manifest templates and fixture-only end-to-end coverage; no third-party source is copied into this repository。

- [x] **Step 1: Write and run RED fixture tests**

添加参数化测试：临时 RTL 使用重命名端口；CV32 fixture 期望两个 OBI route 和 `split_function`；Pico fixture 期望一条 valid-ready route 和 `explicit_signal`；交错 `mem_instr=1,0,1,0` 后检查生成顶层能编译。

~~~bash
pytest -q tests/integration/test_generic_cpu_targets.py
~~~

Expected: FAIL because target templates and unified fixture helper do not exist。

- [x] **Step 2: Add manifests and fixture helper**

CV32 manifest 声明分离 OBI instruction/data endpoint，Pico manifest 声明 `ready-valid-memory@1` 和 `instruction_identity -> mem_instr`。source root/revision 使用已有 schema 的相对路径和 pinned checkout 约定；测试只在临时目录生成 RTL，不触碰 `third_party/`。

- [x] **Step 3: Run fixture tests, compile when available, and commit**

~~~bash
pytest -q tests/integration/test_generic_cpu_targets.py
git add configs/cpus/cv32e40p/official_core_interface_description.json configs/cpus/picorv32/official_core_interface_description.json tests/integration/test_generic_cpu_targets.py
git commit -m "test: add generic CV32E40P and PicoRV32 target fixtures"
~~~

### Task 5: Add a concise usage guide and perform full verification

**Files:**
- Create: `docs/superpowers/examples/generic-riscv-cpu-direct-integration.md`
- Modify: `scripts/generate_composition.py`
- Modify: `README.md`
- Test: `tests/integration/test_generic_cpu_targets.py`

**Interfaces:**
- Consumes: manifests, composition API and fixture acceptance results。
- Produces: Chinese usage guide with input JSON, compose command, constrained RFuzz command and fail-closed diagnostics。

- [x] **Step 1: Write and run RED documentation test**

测试读取 guide 并检查包含 `plan_generic_composition`、`write_generic_composition`、`compile_contract_transducer`、`mem_instr` 和 `missing-instruction-identity`。

~~~bash
pytest -q tests/integration/test_generic_cpu_targets.py -k documentation
~~~

- [x] **Step 2: Write the standardized CLI test first**

添加 subprocess 测试，运行以下统一命令：

~~~bash
PYTHONPATH=src python3 scripts/generate_composition.py \\
  --interface-description configs/cpus/picorv32/official_core_interface_description.json \\
  --base-dir . --out-dir runs/examples/myfuzz-picorv32-composition \\
  --isa-xlen 32 --isa-extension I --isa-extension M --isa-extension C \\
  --constrained
~~~

测试解析 stdout JSON，断言 `complete == true`、`top_path`、`processor_execution_path` 和 `contract_transducer_path` 存在；没有 `instruction_identity` 的输入必须返回非零并在 stderr 包含 `missing-instruction-identity`。

- [x] **Step 3: Implement the standardized CLI and write the guide**

扩展 `scripts/generate_composition.py`，增加 `--constrained`、`--max-wait-cycles`、`--memory-capacity-entries` 和 `--allow-error/--no-allow-error`。generic 模式从已验证 route 推导 address/data width，使用逻辑域 `instruction_memory_master -> main` 与 `data_memory_master -> main` 构造 `ContractTransducerPlan`，再将其传给 `write_generic_composition`。保持 legacy 和 unconstrained 模式兼容。stdout JSON 增加生成 top、execution record 和 contract record 的路径。

把上述命令写入 `README.md` 和中文 guide，说明 `--base-dir` 如何解析 manifest 的 source root，以及 `--out-dir` 是发布目录。

- [x] **Step 4: Run CLI and documentation tests**

文档说明接口描述 → 源分析 → 协议适配 → 顶层生成 → compile/sim → RFuzz/replay 的路径，明确真实 CPU 源未验证时只能称为 fixture-only。

~~~bash
pytest -q tests/integration/test_generic_cpu_targets.py
PYTHONPATH=src python3 scripts/generate_composition.py --help
~~~

- [x] **Step 5: Run focused and full verification**

~~~bash
pytest -q tests/composition/test_processor_boundary.py tests/composition/test_processor_adapters.py tests/composition/test_processor_execution.py tests/composition/test_protocol_composer.py tests/integration/test_processor_auto_wiring.py tests/integration/test_constrained_backend_rtl.py tests/integration/test_generic_cpu_targets.py
pytest -q --ignore=third_party
git diff --check
git status --short
~~~

记录准确的 passed/skipped/failed 数量；确认 `task-2-report` 的修改仍未被覆盖，`third_party/` 没有本次变更。修复只提交到对应任务 commit，并在最终报告中提供命令和实际输出。
