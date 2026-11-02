# 配置驱动的独立组件数据流搜索

系统分别运行 CPU/IP 的真实 RTL harness，由现有运行时模拟组件间数据流动。组合入口读取 descriptor 与组件适配器，不生成或连接 SoC。已适配组件的兼容组合通过配置选择；新协议或新组件仍需适配。

统一入口为 `python3 scripts/run_dependency_search.py --scenario CONFIG`。先使用 `--preflight` 检查 schema、descriptor 和能力；预检不编译或执行 RTL，也不声称已经得到实际 compiled catalog 身份。

示例（original 完成后使用同一参数执行 fresh）：

```bash
python3 scripts/run_dependency_search.py --scenario configs/search/timer-ibex.json --mode original --policy state --cases 3 --seed 7 --output /tmp/timer-search --cache /tmp/myfuzz-cache
python3 scripts/run_dependency_search.py --scenario configs/search/timer-ibex.json --mode fresh --policy state --cases 3 --seed 7 --output /tmp/timer-search --cache /tmp/myfuzz-cache
```

`--output` 是 campaign 根目录，结果分别写入 original/fresh；已有输出拒绝覆盖。`--record-local-commands` 额外保存完整命令和响应，默认只保留重放身份观察，避免无必要的 wire 日志。`--seconds` 控制搜索 case 边界，构建、在途 case 和清理可能超时；fresh 重放已经执行的实际 prefix，不再施加第二个搜索时限。F5/F6 至少接纳首个 case。

| 配置 | 执行范围 | 搜索反馈 |
| --- | --- | --- |
| configs/search/wishbone-current.json | 已注册 Wishbone 单 F4 写及同例 readback | live 当前版本；F2/跨例消费不支持 |
| configs/search/memory-consumption-ibex.json | F3 写入与受限 F1 RAM-read | live 当前四字节版本与实际 DUT OBI 消费 |
| configs/search/timer-ibex.json | Timer + Ibex，F2/F4 mixed | 已注册 provider 的实际状态和认证反馈 |
| configs/search/spi-cv32e40p.json | SPI + CV32E40P，F2/F4 mixed | 已注册 provider 的实际状态和认证反馈 |
| configs/search/memory-f1-ibex.json | F1 指令输入，复用 mixed 执行器 | 有限 record catalog；反馈为 unknown |
| configs/search/memory-f3-ibex.json | F3 内存输入，复用 mixed 执行器 | 有限 record catalog；反馈为 unknown |
| configs/search/memory-mixed-ibex.json | 声明的 F1/F3/F4/F2 records | 有限 record catalog；未观测反馈为 unknown |
| configs/search/gpio-f5.json | GPIO F5，最多 16 cases | 有限 record catalog；未观测反馈为 unknown |
| configs/search/dma-f6.json | DMA F6，最多 16 cases | 有限 record catalog；未观测反馈为 unknown |

F1/F3、mixed、F5 和 F6 的有限目录在持续会话中逐例选择；预算截断的 fresh 使用实际执行前缀。未接入版本消费 provider 的路径保留 unknown。GPIO 与 storage live 复用逐例适配接口。

所有路径复用已有执行器。有限 catalog 的 state 模式并不等价于具有 live provider 的自适应反馈；不把未知 reward、关系数或覆盖率写成零。场景中的 goal 描述也不自动生成新的检测器。

严格 fresh 校验请求、原始 summary/source/prefix 绑定、实际新进程 nonce、构建与 binary 身份、语义输入和 plan；进程必须实际回收并正常退出。部分 prefix 仍保留完整原计划的 preparation 与请求容量。历史运行证据不自动成为修改后版本的原生验收证据。

比较入口 `scripts/run_search_comparison.py --scenario CONFIG` 使用相同配置；非 GPIO 场景须显式选择其支持的 variants。具体参数见 `--help`。缺失认证关系反馈时，关系比较保持 unavailable；只有带有效测量证明且同一覆盖点全集的覆盖率才可独立比较。不把软件通过、预检通过或单个样本称作完整性能实验。

用户指定的后续优先级：功能和端到端验收完成后，主要任务转为提高速度。先测量启动/编译、case 吞吐、反馈、日志和重放耗时，再优化实际瓶颈，同时保持覆盖率口径与重放结果一致。

## 执行流程（2026-10-28）

CLI 默认 `--execution-mode search`，与 `--mode original|fresh` 分开：

| execution-mode | 用途 | 重放策略 |
| --- | --- | --- |
| develop | 单 case 调试，cases 只能为 1 | original 不自动完整重放 |
| search | 日常搜索 | 新认证消费关系触发重放；普通 original 跳过无条件重放 |
| acceptance | 正式验收 | 完整重放；显式 fresh 始终做严格跨运行校验 |

日常 search/develop original 假设本地代码、工具链与缓存运行期间不变，静态依赖只在首次使用时检查一次，不做结束重扫；summary 标记 static_validation_policy=entry-only。acceptance 和 fresh 在结束时绕过缓存重新验证，标记 entry-and-exit。session_boundary=verified 表示对应策略已通过，不代表 entry-only 检测了运行期间的源码变化。输入、协议、生产者与消费者关系、版本及真实进程身份仍随执行检查。Python API 未指定 execution_mode 时保留原严格行为。

普通 native search 使用精简 prefix；新关系、验收、fresh 或 `--record-local-commands` 保留完整记录。GPIO 新关系自动在独立控制进程重放；original/fresh 固定相同 elaboration 模式，配置绑定仍逐字段验证。

搜索失败时尝试导出实际尝试前缀，材料完整且静态边界通过才启动有超时的独立复现进程。材料缺失、源文件变化或基础设施错误明确 refused；复现成功仍不是搜索成功，也不自动判定 DUT bug。

实测与限制见 [执行流程验证报告](reports/execution-workflows-20261028.md)。搜索时间不包含全部启动、清理和结束认证成本，吞吐比较须同时读取 command_wall_seconds。
