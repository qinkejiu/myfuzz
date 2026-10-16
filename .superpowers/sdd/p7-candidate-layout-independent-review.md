# P7 candidate layout 独立源审查 — 07f2da6

范围：`compiled_candidate_layout.py`、`test_compiled_candidate_layout.py`、真实 D3 F4 source/source_constraints 生成处和现有 executor 接缝。读取源码，并执行两个最小纯软件 declaration probes；没有重跑实现者的 12-test suite，没有构造 D2/D3 fixture、编译、RTL/native 或远端操作。实现者报告的 12 passed / 16.50s 没有独立日志，本报告不将其记作本轮复测。

## 中严重性问题

### M1：声明域无任何合法值时仍编译出布局

位置：`compile_candidate_layout` 的 external_pin 分支及 `CandidateLayout._validate`。

当前分别检查 mask、range、alignment 的形状，但不验证三者交集非空。最小纯 probe 使用普通合法 image/MMIO declaration，再添加以下 pin（source_constraints 同步逐字镜像）：

```python
kind='external_pin', width=2, bit_offset=0,
mask=1, range=[2, 3], alignment=1
```

`compile_candidate_layout` 成功返回 5-byte layout；枚举这个 pin 的四个值，0/1 因 value-range 无效，2/3 因 value-mask 无效。另一个 probe `mask=3, range=[1,1], alignment=2` 同样编译成功，但唯一范围值不满足 alignment。两者均没有可 encode 的合法 candidate。

这不会把非法 candidate 放行；它会把自相矛盾的输入域留到逐 candidate 分类，导致后续合法生成/搜索只能耗尽 invalid budget，也无法给出可用 seed。建议编译期用有界整数域的可满足性检查拒绝，给出具体 source pointer 和 `source-domain-empty`。不要用枚举 2^32 值实现该检查。真实当前 compiler 默认 external pin range=None/alignment=1，通常不会触发；但本模块已经主动支持更一般的 pin 约束，接入生产前应补此守卫。

## 低严重性问题

- **缺少总 source 数/总 raw bit budget。** 每个 pin 至多 32 bits，但可以添加任意多个独立 source/component/port，编译阶段两处逐项搜索/重叠检查随数量平方增长，byte_length 也没有上限。“bounded”目前只落实到单 slice。建议由代码或明确参数限制总 sources/bits/record bytes，并计入布局 digest/合同。
- **非法 JSON 值的拒绝不总是 CandidateLayoutError。** 最终 `json.dumps(path, allow_nan=False)` 可能因未知顶层 metadata 的 NaN、非 JSON 对象等抛原生 ValueError/TypeError。模块不接受这些值是正确的，但可统一为布局诊断 code/pointer，避免调用者把它当成环境错误。真实已认证 D3 JSON 路径风险较小。
- **覆盖尚窄。** 现有测试确认新增 pin 的独立 slices、pin range/padding、overlap、镜像冲突与部分 malformed；未覆盖非零 bit_offset、非平凡 alignment、稀疏 MMIO mask、空合法域和总预算。可补有意义的纯软件边界，毋须为此重复 native gate。

## 已确认的实现性质

真实 D3 `_evaluate_f4` 的 image、cpu_mmio_stream 和 external_pin 字段与本模块的预期相符；source_constraints 使用同一批 source 约束字段。通过 source_id 匹配镜像，source 和 mirror 数量一致且 source_id 唯一，可拒绝漏项、重复镜像和不一致约束。CPU MMIO 的 range/alignment 被解释为真实访问地址与 4-byte access 对齐，不会错误地要求寄存器写入值按 4 对齐；候选值的 mask 使用 target-word lanes。MMIO field 的 lsb/width/mask 检查和 32-bit raw word 容器分开。

每个 external pin 按自身 width 获得连续、独立 raw slice；little-endian packing、固定长度、尾部零 padding、严格 int（拒 bool）及 encode 的精确 source-set 检查存在。pin bit_offset 保留物理目的位段，mask 为局部候选位段，避免将物理 bit_offset 误当 raw offset。相同 component/port 的重叠位段被拒绝；不同逻辑 port 是否 alias 同一 physical pin，不在本模块的知识范围。

unknown source kind、unknown source/constraint 顶层字段、非 fuzzable source、seed、register_field_constraints 和不支持 register access shape 均有拒绝路径。runtime rule 语义、physical ownership、原始 request→D3 真实性、内存权限/实际 writer arena 容量明确由外层负责；本模块没有静默宣称执行 reachable_window rules。它接受镜像 source 内声明的 component/endpoint 标识，而不是建立其物理真实性，这是文档明确的分层边界。

返回对象为 frozen dataclass，包含 tuple 和标量，不引用可变原始 path；digest 对整个传入 path canonical JSON 取 SHA-256，绑定源、约束和其他 path 内容。该摘要是输入身份，不是签名/authority，也不会使直接构造的 CandidateLayout 对象获得执行资格。

## 接入与验收边界

该模块尚未接入 `CompiledF4Runtime.submit` 或 `run_compiled_execution_files` 的生产候选路径；旧 executor 仍消费固定 8 bytes，seed/通用 register-field semantics 仍未实现。当前 layout 只描述 bounded F4 候选容器及其局部合法性，不生成任意指令、不落实实际 ownership/runtime rules、不创建 register authority，也没有证明 native writer/checker 消费了这些 slices。

结论：独立 slices 和真实 D3 字段绑定基本合理；发现一个需修复的中严重性空域检查缺口及上述低项。不能据此授予 P7-D/E、无适配新 CPU/IP、coverage-guided search 或任何新增 native pass。
