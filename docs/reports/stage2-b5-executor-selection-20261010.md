# Stage 2 B5：通用 executor 选择

日期：2026-10-10。状态：B5 已完成；M1 的基础事件和协议检查仍待实施。本项核对并锁定基础 harness 的 executor 选择边界，没有改动生产选择器，因为当前 `local_harness.v2` 已按 schema 与受信协议契约进入通用 executor。

## 结果

APB3、TL-UL 和 Wishbone 的 v2 MMIO 请求分别进入通用 register-observe executor。TL-UL 选择器先判断 request schema；v2 不读取旧 `local_runtime_variant`。APB3 与 Wishbone 的 v2 分支也直接进入通用模板。三条通用路径继续由协议契约、端口角色／方向／宽度、寄存器窗口和输入 ownership 校验决定能否执行，组件或 endpoint 的 GPIO、UART、SPI 等标签不决定基础 executor。

旧 v1 入口仍使用原先已注册的专用变体。已验证的 PULP GPIO 因果探针和 OpenTitan UART FIFO 源观察仍要求各自冻结 profile、source contract 与匹配的运行时模板；这两条功能路径不参与 v2 的基础 executor 选择。

## 回归与验证

- `tests/local_harness/test_runtime_renderer.py` 增加匿名 endpoint ID 的 APB 角色选择回归，并覆盖 6 种 TL-UL profile、6 种旧／未知变体值，确认 v2 一律选择 `tlul_register_observe`。完整文件结果：**15 passed，47 subtests passed**；包含实际 Verilator runtime lint。
- 通用 APB3、TL-UL、Wishbone 契约测试：**8 passed，2 subtests passed，5 skipped**。跳过项是显式启用真实场景的 RTL 测试，本轮未运行真实 DUT。
- PULP GPIO 因果探针、OpenTitan UART FIFO 探针及 runtime identity 回归：**18 passed，57 subtests passed**，确认旧功能合同和身份检查仍有效。
- 三组测试在独立 pytest 子进程中并行执行；`git diff --check` 通过。

命令均使用 `PYTHONPATH=src:. pytest -q`。真实 APB3／TL-UL／Wishbone DUT 测试、未知 OpenTitan HMAC 接入以及 Stage 2 L1/L2/L3 生产运行结果不在本项证明范围内；目前仍无 Stage 2 CPU/IP 生产 runner，也未给 DUT 矩阵授级。
