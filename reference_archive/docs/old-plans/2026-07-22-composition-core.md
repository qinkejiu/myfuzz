# Composition Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** 在不读取参考 SoC、也不使用任何 RTL 标识符语义的前提下，把 Verilator 提取的 hdl_facts.v2 和显式协议声明转换为可复现的 Top-K composition_ir.v1，再用版本匹配的 Verilator AST/emitter 生成经过重解析门禁的候选 top，并输出 top_validated 的 candidate_manifest.v1。

**Architecture:** 终端 A 保留现有 Verilator 前端作为唯一 RTL parser。C++ 前端只产生带稳定整数 ID、源码定位和 opaque symbol 的结构事实；Python 声明绑定层把用户显式 role/field binding 与事实对齐，随后以只含整数 ID 和声明语义的 typed constraint graph 搜索连接和地址布局。Composition IR 与 Verilator AST 解耦，AST builder 只在 emitter 边界读取原始 RTL symbol；每个候选单独构建、发射、重新 parse/elaborate，并流式保留 Top-K。

**Tech Stack:** C++20、项目内 vendored Verilator AST/link passes、Python 3 标准库（dataclasses、json、hashlib、unittest、ctypes、heapq、tempfile）。不得为本计划新增 Python 或 C++ 第三方依赖。

## Global Constraints

- 共享契约由 C1 提供；A 只调用 myfuzz.contracts.validate.validate_contract(document, schema_id) -> None、myfuzz.contracts.canonical.canonical_bytes(document) -> bytes 和 myfuzz.contracts.canonical.content_hash(document) -> str，失败时让 ContractError 原样传播；A 不创建或修改 schema、canonical helper 或 tests/contracts fixture。
- content_hash 的结果格式必须是 sha256:<64 个小写十六进制字符>。路径、时间戳、进程地址和线程顺序不能进入语义哈希。
- 生成器只消费 hdl_facts.v2、声明式 protocol.v1 文档和通用约束；不得读取、解析、评分、缓存或接受 RVX reference top 的路径或内容。
- 模块名、实例名、端口名、net 名、文件名、目录名和设计名都是 opaque symbol。只有 Verilator 语法绑定、source map、诊断和 emitter 可以读取原始名称；graph、search、address、Top-K 和 IR hash 层不得读取名称文本。
- 角色、clock/reset 属性、protocol ID、field-to-port binding、required/optional 和 externalize 选择必须由输入显式提供；缺失声明是错误，不得名称回退。
- 推断事实使用稳定整数 ID。所有排序用整数 ID、声明的数值属性和规范化关系；不能依赖 JSON 数组原始顺序、文件系统顺序、线程调度或名称排序。
- provenance 只允许 declared、rtl、protocol、inferred、assumed。任何地址假设、降级连接或未验证关系都必须写入 evidence、assumptions 或 rejected alternatives。
- Top-K 使用有界堆和 graph hash 去重，每次最多保留 K 个 IR；一次只构造一个 Verilator AST。默认实验 K 由调用方传入，测试使用 K=3。
- Python 测试统一使用标准库 unittest 和 python3 -m unittest；不加入 pytest、hypothesis、networkx、jsonschema 或 nlohmann-json。
- 当前 checkout 缺少 cmake 和 C++ 编译器。C++ 节点在工具链预检通过前不得开始，也不得以 Python 测试通过代替 emitter/AST 验证。
- 每个节点使用 feature/composition-core 分支和 .worktrees/composition-core 工作树；每个节点必须通过指定测试、本地 git diff --check、原子提交和 GitHub push 才能标记完成。禁止 force push、提交构建产物/波形/完整 corpus/大日志或将 B/C 节点文件混入 A 提交。

---

## Prerequisite Gates

这些是开始 A1 之前的阻塞门禁，不创建 A 节点提交。

### Gate C1: shared contracts are reachable

工作树必须从已推送的共同基线创建，并且下列文件存在：

~~~text
src/myfuzz/contracts/canonical.py
src/myfuzz/contracts/validate.py
tests/contracts/hdl_facts.v2.valid.json
tests/contracts/protocol.v1.valid.json
tests/contracts/composition_ir.v1.valid.json
tests/contracts/candidate_manifest.v1.valid.json
~~~

运行：

~~~bash
test "$(git branch --show-current)" = feature/composition-core
test -f src/myfuzz/contracts/canonical.py
test -f src/myfuzz/contracts/validate.py
PYTHONPATH=src python3 -m unittest discover -s tests/contracts -p 'test_*.py' -v
~~~

期望：四个 fixture 的 contract tests 全部 OK。任一文件缺失或 fixture 测试失败时记录 blocked-prerequisite:C1，不改动 A 文件。

### Gate TOOLCHAIN: CMake and C++20

运行：

~~~bash
command -v cmake
cmake --version
command -v c++
c++ --version
command -v verilator
verilator --version
~~~

期望：cmake >= 3.20、可用 C++20 编译器和能执行 verilator --lint-only 的 Verilator binary。当前已知 checkout 的预检结果是 cmake: command not found 和 c++: command not found；这必须由执行环境补齐，不能在计划中静默跳过。若系统只有另一套编译器，设置 CXX 并重新运行预检，不能修改 vendored AST 以适应未验证的 ABI。

### Gate WORKTREE: ownership and memory

运行：

~~~bash
git status --short
git branch --show-current
git worktree list
git ls-remote --heads origin feature/composition-core
~~~

期望：工作树干净、分支准确、远端分支已建立或可首次发布；本机约 7.3 GiB RAM 上的 C++ 构建和候选 smoke 串行执行，所有构建使用 JOBS=1。Gate 通过后才开始 A1。

## Contract Boundary Owned by C1

A 不实现以下公共文件，只依赖其 API：

~~~python
from myfuzz.contracts.canonical import canonical_bytes, content_hash
from myfuzz.contracts.validate import ContractError, validate_contract

validate_contract(document: object, schema_id: str) -> None
canonical_bytes(document: object) -> bytes
content_hash(document: object) -> str
~~~

A 假定 C1 的 hdl_facts.v2 至少提供 schema_version、tool/input metadata、整数 ID 的 modules/parameters/ports/instances、pin bindings、normalized expression/dataflow facts、clock/reset validation、local address facts、source locations、provenance/confidence 以及 errors/warnings/unsupported constructs。A 只把原始名称放在 frontend/source-map 区域；solver 输入在边界处剥离这些字段。

A 假定 protocol.v1 消费对象包含 protocol/plugin ID/version、endpoint side、channels/fields、相对 initiator 的方向、width/type constraints、required/optional、bounded temporal rules、dependency edges、legal adapters、projection actions 和 capability limits。infer_candidates 不根据 module/component 名称选择 plugin；调用方必须先把显式 protocol ID 编译成该对象。

A 产生并在写出前调用 validate_contract 的对象：

~~~text
hdl_facts.v2          frontend producer (A1-A3)
composition_ir.v1     infer_candidates / Top-K producer (A7)
candidate_manifest.v1 emitter + validator (A10), lifecycle=top_validated
~~~

candidate_manifest.v1 中 harness 文件和 raw-bit mappings 在 A 阶段使用空数组并标记 not_enriched_by_composition_core；B 在后续节点 enrich，不得把 A 的 top_validated 状态改写成已 fuzz 的结果。

## File Map

Files are deliberately split so terminal B does not need to edit them.

~~~text
Modify:  src/myfuzz/frontend/vendor/verilator/src/V3VIFrontend.h
Modify:  src/myfuzz/frontend/vendor/verilator/src/V3VIFrontend.cpp
Modify:  src/myfuzz/frontend/src/MyFuzzFrontend.h
Modify:  src/myfuzz/frontend/src/MyFuzzFrontend.cpp
Modify:  src/myfuzz/frontend/src/MyFuzzFrontendApi.cpp
Modify:  src/myfuzz/frontend/src/MyFuzzFrontendStubs.cpp
Modify:  src/myfuzz/frontend/CMakeLists.txt
Create:  src/myfuzz/frontend/python_api.py
Create:  src/myfuzz/frontend/facts.py
Create:  src/myfuzz/frontend/src/MyFuzzCompositionAstBuilder.h
Create:  src/myfuzz/frontend/src/MyFuzzCompositionAstBuilder.cpp
Create:  src/myfuzz/frontend/src/MyFuzzCompositionApi.h
Create:  src/myfuzz/frontend/src/MyFuzzCompositionApi.cpp
Create:  src/myfuzz/frontend/src/MyFuzzVerilatorEmitter.h
Create:  src/myfuzz/frontend/src/MyFuzzVerilatorEmitter.cpp
Create:  src/myfuzz/frontend/vendor/verilator/src/V3EmitV.cpp
Create:  src/myfuzz/frontend/vendor/verilator/UPSTREAM_REVISION
Create:  src/myfuzz/frontend/scripts/verify_vendor.py

Create:  src/myfuzz/composition/__init__.py
Create:  src/myfuzz/composition/model.py
Create:  src/myfuzz/composition/graph.py
Create:  src/myfuzz/composition/search.py
Create:  src/myfuzz/composition/address.py
Create:  src/myfuzz/composition/ir.py
Create:  src/myfuzz/composition/topk.py
Create:  src/myfuzz/composition/pipeline.py
Create:  src/myfuzz/composition/emitter.py
Create:  src/myfuzz/composition/manifest.py

Create:  tests/frontend/fixtures/opaque_cpu_ip.sv
Create:  tests/frontend/fixtures/opaque_cpu_ip_renamed.sv
Create:  tests/frontend/fixtures/declarations.json
Create:  tests/frontend/test_hdl_facts_v2.py
Create:  tests/frontend/test_declaration_binding.py
Create:  tests/frontend/test_emitter_provenance.py
Create:  tests/composition/test_model_graph.py
Create:  tests/composition/test_connection_search.py
Create:  tests/composition/test_address.py
Create:  tests/composition/test_topk_ir.py
Create:  tests/composition/test_ast_builder.py
Create:  tests/composition/test_candidate_manifest.py
~~~

No task creates src/myfuzz/contracts/** or tests/contracts/**. Small RTL fixtures use arbitrary names and include one renamed copy；fixture 名称和源码 identifier 都不能进入 solver assertion。

## Node A1: Stable Verilator fact skeleton

**Deliverable:** embedded Verilator pass emits a deterministic raw fact document with integer IDs and every hdl_facts.v2 top-level section. Existing frontendManifestJson behavior remains compatible with the current instrumentation flow.

**Files:**
- Modify: src/myfuzz/frontend/vendor/verilator/src/V3VIFrontend.h
- Modify: src/myfuzz/frontend/vendor/verilator/src/V3VIFrontend.cpp
- Modify: src/myfuzz/frontend/src/MyFuzzFrontend.h
- Modify: src/myfuzz/frontend/src/MyFuzzFrontend.cpp
- Modify: src/myfuzz/frontend/src/MyFuzzFrontendApi.cpp
- Create: src/myfuzz/frontend/python_api.py
- Create: tests/frontend/fixtures/opaque_cpu_ip.sv
- Create: tests/frontend/test_hdl_facts_v2.py

**Interfaces:**
- C++: std::string myfuzz::frontendHdlFactsJson(const std::vector<std::string>& args) returns UTF-8 JSON with schema_version=hdl_facts.v2 and does not generate a top.
- C ABI: char* myfuzz_frontend_hdl_facts_json(int argc, const char* const* argv) follows the existing allocation/free and last-error ABI.
- Python: FrontendLibrary.hdl_facts(args: list[str], cwd: Path) -> dict and run_hdl_facts(library: Path, args: list[str], cwd: Path) -> dict.
- IDs are assigned by source traversal ordinal and local declaration ordinal, never by sorting identifier text. Names remain only under source_symbols/source_locations.

- [ ] **Step 1: Write the failing test.**

Create the fixture:

~~~systemverilog
module q0(input logic p0, input logic p1, output logic p2);
  assign p2 = p0 & p1;
endmodule

module q1(input logic p0, input logic p1, output logic p2);
  q0 x0(.p0(p0), .p1(p1), .p2(p2));
endmodule
~~~

Create the test:

~~~python
import os
import unittest
from pathlib import Path

from myfuzz.frontend.python_api import FrontendLibrary


class HdlFactsV2Test(unittest.TestCase):
    def test_frontend_emits_stable_id_skeleton(self):
        root = Path(__file__).resolve().parents[2]
        library = Path(os.environ["MYFUZZ_FRONTEND_LIBRARY"])
        fixture = Path(__file__).parent / "fixtures" / "opaque_cpu_ip.sv"
        args = ["--lint-only", "-Wno-fatal", str(fixture), "--top-module", "q1"]
        facts = FrontendLibrary(library).hdl_facts(args, root)
        self.assertEqual(facts["schema_version"], "hdl_facts.v2")
        self.assertTrue(all(isinstance(m["id"], int) for m in facts["modules"]))
        self.assertEqual(len({m["id"] for m in facts["modules"]}), 2)
        self.assertTrue(all("ports" in m for m in facts["modules"]))
        self.assertTrue(all("instances" in m for m in facts["modules"]))
        for key in ("parameters", "ports", "instances", "pin_bindings",
                    "expressions", "dataflow_edges", "clock_reset_checks",
                    "local_address_facts", "source_locations", "diagnostics"):
            self.assertIn(key, facts)


if __name__ == "__main__":
    unittest.main()
~~~

- [ ] **Step 2: Run the test to verify it fails.**

Run:

~~~bash
PYTHONPATH=src python3 -m unittest tests/frontend/test_hdl_facts_v2.py -v
~~~

Expected: FAIL with ModuleNotFoundError for myfuzz.frontend.python_api or, after creating the wrapper, missing myfuzz_frontend_hdl_facts_json.

- [ ] **Step 3: Write the minimal implementation.**

Create the native wrapper:

~~~python
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path


class FrontendLibrary:
    def __init__(self, path: Path):
        self.path = path
        self.lib = ctypes.CDLL(path.as_posix())
        self.lib.myfuzz_frontend_hdl_facts_json.argtypes = [
            ctypes.c_int, ctypes.POINTER(ctypes.c_char_p)
        ]
        self.lib.myfuzz_frontend_hdl_facts_json.restype = ctypes.c_void_p
        self.lib.myfuzz_frontend_free.argtypes = [ctypes.c_void_p]
        self.lib.myfuzz_frontend_free.restype = None
        self.lib.myfuzz_frontend_last_error.restype = ctypes.c_char_p

    def hdl_facts(self, args: list[str], cwd: Path) -> dict:
        encoded = [item.encode() for item in args]
        argv = (ctypes.c_char_p * len(encoded))(*encoded)
        old = Path.cwd()
        ptr = None
        try:
            os.chdir(cwd)
            ptr = self.lib.myfuzz_frontend_hdl_facts_json(len(encoded), argv)
            if not ptr:
                raw = self.lib.myfuzz_frontend_last_error()
                raise RuntimeError(raw.decode() if raw else "frontend facts failed")
            return json.loads(ctypes.string_at(ptr).decode("utf-8"))
        finally:
            if ptr:
                self.lib.myfuzz_frontend_free(ptr)
            os.chdir(old)


def run_hdl_facts(library: Path, args: list[str], cwd: Path) -> dict:
    return FrontendLibrary(library).hdl_facts(args, cwd)
~~~

The C++ API follows frontendManifestJson lifecycle and calls V3VIFrontend::factsJson(v3Global.rootp()) after parse/link/width. It preserves the v1 manifest method and emits at least this complete skeleton:

~~~json
{
  "schema_version": "hdl_facts.v2",
  "frontend": {"name": "myfuzz-verilator-frontend"},
  "input_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "modules": [], "parameters": [], "ports": [], "instances": [],
  "pin_bindings": [], "expressions": [], "dataflow_edges": [],
  "control_edges": [], "clock_reset_checks": [], "local_address_facts": [],
  "source_symbols": [], "source_locations": [],
  "diagnostics": {"errors": [], "warnings": [], "unsupported": []}
}
~~~

Add the extern C function beside the existing manifest function, reuse copyCString, and clear/delete/shutdown global state on success and exception.

- [ ] **Step 4: Run focused and regression tests.**

~~~bash
env JOBS=1 src/myfuzz/frontend/scripts/build_frontend.sh
PYTHONPATH=src MYFUZZ_FRONTEND_LIBRARY=src/myfuzz/frontend/build/libmyfuzz_frontend.so \
  python3 -m unittest tests/frontend/test_hdl_facts_v2.py -v
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py' -v
~~~

Expected: A1 test and existing tests pass; JSON parses and every listed section exists.

- [ ] **Step 5: Commit and push the node.**

~~~bash
git diff --check
git add src/myfuzz/frontend/vendor/verilator/src/V3VIFrontend.h \
  src/myfuzz/frontend/vendor/verilator/src/V3VIFrontend.cpp \
  src/myfuzz/frontend/src/MyFuzzFrontend.h \
  src/myfuzz/frontend/src/MyFuzzFrontend.cpp \
  src/myfuzz/frontend/src/MyFuzzFrontendApi.cpp \
  src/myfuzz/frontend/python_api.py \
  tests/frontend/fixtures/opaque_cpu_ip.sv tests/frontend/test_hdl_facts_v2.py
git diff --cached --check
git commit -m "feat(frontend): [A1] emit stable hdl facts skeleton" \
  -m "Node: A1" \
  -m "Tests: env JOBS=1 src/myfuzz/frontend/scripts/build_frontend.sh; PYTHONPATH=src MYFUZZ_FRONTEND_LIBRARY=src/myfuzz/frontend/build/libmyfuzz_frontend.so python3 -m unittest tests/frontend/test_hdl_facts_v2.py -v"
git push -u origin feature/composition-core
~~~

Expected: the A1 commit is visible on GitHub. If push fails, retain the local commit and report pending-push; do not start A2.

