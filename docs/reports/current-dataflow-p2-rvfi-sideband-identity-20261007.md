# P2 RVFI IRQ serial sideband 的源码身份与构建输入门禁

日期：2026-10-07。上一轮（同日 10:10–10:11）为固定官方 RVFI Ibex 增加了**被动 IRQ serial sideband**，用于补齐"RVFI 退休缺少硬件来源 token"这一 P2 缺口：

- 新 RTL：`src/myfuzz/composition/rtl/ibex_irq_serial_sideband.sv`（`decision_serial_o`/`retirement_serial_o`，`0` 表示"没有可证明的来源 lineage"，序列号饱和不回绕）。
- wrapper：`src/myfuzz/composition/rtl/soc_ibex_rvfi_local.sv` 新增两个 64 位顶层输出端口 `irq_decision_serial`、`irq_retirement_serial` 并例化该模块。
- profile：`configs/cpus/ibex_rvfi_local/component_profile.json` 新增两条 `observe` `port_actions` 与 sideband 源文件；`configs/soc/closures/ibex_rvfi_local.json` 重新生成（`lint.exit_code = 0`）。

该轮改动**未同步身份钉**，导致工作区 `tests/scenario` 出现 48 failed + 16 errors（全部为 `ComponentProfileError: elaboration-failed:ibex_rvfi_local:content-hash-mismatch`），并连带 2 项 RVFI 相关失败。本报告记录把这份在建改动收口为可复算身份的过程与门禁。

## 身份重录（可复算，非猜测）

1. **elaborated 内容哈希重算**：用 `SourceCrawler` 的同一算法（`myfuzz-source-tree-v2`）连续两次捕获，结果稳定且一致：`sha256:7fe2fcdbd5cccfafe0e774426c7417f1bf209c995918ac0ca0ea152d7d1a0cea`，覆盖 elaborat 闭包 242 个文件（含 45 个声明文件与 4 个 include root 下的文件）。检查确认无 `.myfuzz-elaboration-*` 或 `/tmp` 路径混入文件集。
2. **profile revision 重录**：`configs/cpus/ibex_rvfi_local/component_profile.json` 的 `source.revision` 由 `sha256:2f8963f6…` 更新为上述 `sha256:7fe2fcdb…`（单点文本替换，文件其余字节未动）。
3. **contract 三钉更新**（`src/myfuzz/local_harness/ibex_rvfi_contract.py`）：

| 常量 | 旧值（失效） | 新值（当前实际） |
|---|---|---|
| `_PROFILE_SHA256` | `d6bef700…` | `aa73e0a5dd6052a50368eb8078199f3ec9f8f50e2de1ae27fc1ce04423e8d514` |
| `_WRAPPER_SHA256` | `844cd288…` | `e9bfa7595201a4205204afc23eff2b904428d2fb53f7f8200743ce4932cbf6c3` |
| `_CLOSURE_SHA256` | `e26200e3…` | `d52dfecda5ac3d0e5fafec95822f68c8f69d5daaa3adf9840621e6666dce065e` |

4. **新增显式 sideband 身份**：`_SIDEBAND_PATH = 'src/myfuzz/composition/rtl/ibex_irq_serial_sideband.sv'`、`_SIDEBAND_SHA256 = '516c51bce5a9434e7ea018fe437dc36570677d80c3e3c89b669387e144b65120'`，并在 `verify_ibex_rvfi_source_contract` 中：文件实体哈希必须等于该钉；closure 记录中非 `third_party/` 的 `files` 列表必须同时给出 wrapper 与 sideband 的相同摘要（`ibex-rvfi-local-rtl-record-changed`），否则拒绝。两个独立来源互相交叉核对，任一不符即 fail-closed。

## 修复的真实构建缺陷

重录身份后 RVFI harness 仍无法构建，Verilator 报 `%Error: Cannot find file containing module: '<cache>/inputs/./src/myfuzz/composition/rtl/ibex_irq_serial_sideband.sv'`，其 "Looked in" 列表显示它把该路径当成模块名搜索。

根因：本地 harness 的构建输入快照由 `authenticated_inputs` 逐条物化，wrapper 在其中、**sideband 不在其中**，因此 build argv 引用了该源文件但 `inputs/` 下并不存在（`build.py::_prepare`）。修复：把 sideband 加入 contract 返回的 `authenticated_inputs`。实测修复后构建输入目录同时含两者：

```
RTL DIR FILES: ['ibex_irq_serial_sideband.sv', 'soc_ibex_rvfi_local.sv']
```

## 门禁

```bash
# 记录在 closure 内的 lint 命令原样重跑
python3 -c "import json;print(' '.join(json.load(open('configs/soc/closures/ibex_rvfi_local.json'))['command']))" | bash
# 退出码 0；Verilator 5.051 devel，Walltime 0.497 s，0 error

PYTHONPATH=src python3 -m pytest tests/local_harness/test_ibex_rvfi_probe.py \
  tests/scenario/test_pin8_native_irq_optin.py -q -p no:randomly
# 13 passed, 1 skipped in 23.42s

PYTHONPATH=src python3 -m pytest tests/local_harness/test_ibex_rvfi_probe.py \
  tests/scenario/test_chain_certificates.py tests/integration/test_first_step_acceptance.py \
  tests/scenario/test_rv32i_rejection_codes.py tests/test_doc_link_check.py \
  tests/scenario/test_pin8_native_irq_optin.py tests/scenario/test_pin8_consumption_certificates.py \
  tests/scenario/test_pin8_cpu_irq_certificates.py tests/scenario/test_pin8_trap_retirement_certificates.py \
  tests/scenario/test_rv32i_mmio_permissions.py -q -p no:randomly
# 224 passed, 1 skipped in 44.92s
```

同轮真实 RTL 侧证：见 [P5 首步端到端验收入口](current-dataflow-p5-chain-acceptance-20261007.md)。该运行以 `--cpu-retirement --native-irq-receipts` 使用这份新 wrapper 与 sideband，24/24 例 complete，RVFI 退休与原生 IRQ 回执正常，完整 fresh replay 一致——**证明新 wrapper＋sideband 能构建、能运行且不干扰既有 RVFI 观测**。

## 限制

- host 侧**尚未消费**这两个 serial 端口：本报告只重录身份并修好构建输入，不授权"精确硬件来源 token"结论。serial 的实际推进语义需要 (a) Python 采集进事件/回执，(b) 真实 RTL 门禁证明 decision→retirement 序列按预期对齐，两者都未完成。
- 322 项软件门禁覆盖 RVFI 端口/宽度/包装与既有证书；它们不替代真实 RTL 的 serial 行为验证。
- 重录只对**当前**工作区源码成立；上一轮修改之前的 RVFI 证据仍绑定其自身冻结源码，不得用本报告新身份回填或升级。
- 本轮未发现自然 RTL 缺陷，也没有改变任何既有证书的适用范围。
