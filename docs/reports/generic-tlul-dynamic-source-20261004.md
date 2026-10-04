# 通用 TL-UL 模板的动态环境输入：范围与验收

通用 `tlul_register_observe` 模板支持在 v2 请求的 `environment_bindings` 中，把真实 RTL 的外部物理输入字段声明为动态 Fuzzable Source。例如 `gpio.pins.in` 绑定 `gpio_external`。同一物理字段不能同时出现在 `fixed_inputs`；所有非 TL-UL 输入必须恰好有一个固定或动态归属，位宽来自完整顶层的物理端口事实。仅 `external_pins` 输入可声明为动态环境源，peer/输出/TL-UL 协议字段均拒绝。

动态字段在 testcase 开始时为 0。`ScenarioGenome` 的 Action 只能变异 ownership map 中标为 `source` 且 `producer_ref` 与请求 `source_id` 一致的位。`ScenarioRunner` 在 DUT 启动前校验字段、位宽、每一位的归属和源身份；把动态输入重新标为 Bound、把固定输入标为 Source 或遗漏动态输入都会拒绝。运行时，session 只接受已声明动态字段的输入值；省略字段会保持上次值，重复相同值不再注入。每次实际变化由通用 `SOURCE_TLUL_REG` 命令写入对应物理输入并推进真实 RTL 一个局部周期，随后 `STEP_TLUL_REG` 正常推进；固定输入在 reset 前赋值，不能由这个命令选择。

动态源声明、物理字段、位宽及 `source_id` 均进入生成 artifact 与 session 身份。一次 testcase 内不重复 reset；源变化、寄存器写入、中断状态和引脚输出均在同一 RTL 进程中持续演化。驱动的命令序列仍使用有界重放缓存，已执行的源命令不会因重试重复施加。

验收使用同一个 GPIO profile，将 `gpio.pins.in` 声明为动态源，`gpio.pins.strap_en` 声明为固定 0。先通过真实 TL-UL 写 INTR_ENABLE 和上升沿触发使能，再把输入从 0 变成 1；OpenTitan GPIO RTL 同步后产生真实 `intr_gpio_o`，`DATA_IN` 和 `INTR_STATE` 寄存器读到真实状态。另一段有状态 Genome 生成同一输入事件，保存证据并在全新进程 fresh replay。原先 RV Timer 与固定输入 GPIO 的两个 profile-only 用例继续回归。

```bash
PYTHONPATH=src MYFUZZ_SCENARIO_REAL=1 python3 -m unittest \
  tests.local_harness.test_generic_tlul_dynamic_source_real \
  tests.local_harness.test_generic_tlul_register_real -v
```

这是单个外部物理字段的寄存器和引脚观察路径。它尚不模拟串行对端、不生成跨组件绑定、不自动派发 CPU 中断，也不声称任意 TL-UL IP 的完整功能验收。新组件仍需源码锁、完整 profile、局部时序和实际行为的独立证据。
