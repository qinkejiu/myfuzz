# 共享 F1/F3/F4/F5 runtime 接线

本增量把真实 GPIO 外部 pin 和实际 IRQ delivery 接到现有 CompiledF4Runtime 的同一个 runner/session/memory，保留原精确 GeneratedCve2Session、GeneratedPulpGpioSession 与版本 authority。CPU 组件新增验证过的 irq_input_port 物理名到既有 irq 控制的映射；默认 irq 行为保留，未知端口拒绝。没有新增 CPU 子类或放宽 issuer 类型。

新配置：configs/scenarios/compiled-f1-f5-ibex-gpio-shared/，复用 causal GPIO 与 Ibex 请求、已有 GPIOEN capability。F4 在显式唯一环境段与 IRQ delivery 同时存在时和 F5 共享 source identity/bit domain，避免整32bit F4 source 与 pin8 F5 source 的ownership冲突。其余 F4 source 行为保持原状。实际静态 F5 declaration 检查、实际 binding/ABI/ownership、PreparedRuntimePathContract.bind 和每次 _stable current 重验共同约束执行。

原 CompiledF4Runtime 通过 f5_preparation opt-in 配置实际物理 interrupt→irq_external_i Binding 与4 tick IrqPulseDelivery；F5 path 在 begin 前和 memory/F4 path 一起装配。F5 raw8 使用与独立 decoder 相同的 payload 位 raw[3]&1，提交时检查真实 waiting instruction transaction、请求证据、epoch、当前共享 cursor 和未物化指令槽，固定4字NOP support。成功后才追加 F5 record 并推进共享 cursor；无消费 provider 时 irq_consumption=unknown。

现 GPIO F2 consumer 实际仅支持另一种 generic APB ABI，不能在 causal GPIO 上复用。因此本 opt-in 按实际能力启用 F1/F3/F4/F5，F2/F6明确unsupported；旧无F5配置的F2/F4 mixed行为保留。MixedStorage backend/channel能按此实际flow集合接收F5，但默认公共campaign kernel/descriptor尚未扩展F5，当前用下面的直接runtime入口验收，不能宣称全F1–F6通用入口完成。

完整prefix保留F5记录，fresh用同一live preparation重新构造实际组件并执行全部顺序；比较器逐字段比较F5证书，不尝试读取storage专用prerequisite。脚本只有真实replay matches=true、verification_scope=full且语义哈希相同才通过；先保留fresh诊断再检查，失败非0。host_source_discovery_scope、harness_validation_scope、execution_validation_scope退出校验通过后才发布最终summary。

软件：`PYTHONPATH=src:. pytest -q tests/integration/test_shared_f5_replay.py tests/integration/test_shared_f5_runtime.py tests/runtime/test_mixed_requirements_union.py tests/runtime/test_generic_mixed_entry.py tests/runtime/test_storage_kernel.py`，80 passed / 17.16s。测试使用真实preparation/artifacts/session/runner/path绑定；完整constructor软件门替换native构建与authority，故不代表原生issuer/进程已经通过。没有运行native。CLI --help exit0。

主代理原生验收命令（输出目录必须不存在）：

```
PYTHONPATH=src:. python3 scripts/run_shared_f5_campaign.py --case /tmp/shared-f5-f4-native --sequence F4-F5-F4 --fresh
PYTHONPATH=src:. python3 scripts/run_shared_f5_campaign.py --case /tmp/shared-f5-f1-native --sequence F1-F5 --fresh
```

可指定 --cache 复用既有build缓存。默认F4输入由声明的layout.encode生成（GPIOEN=0x100、pin=0），F5输入0000000100000000；该序列没有凭宿主写INTEN、mstatus、mtvec或伪造ISR。它验证真实提交/拓扑/重放，不能预先声称CPU接受中断或新消费关系。F2 native序列需先完成其causal GPIO consumer适配。
