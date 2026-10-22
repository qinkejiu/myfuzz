# PULP APB3 GPIO DMA Target

**状态：** 本地真实 RTL 门、fresh replay 和一个 native refusal 门通过；远程门仍开放。独立只读代码审查没有发现 Blocker 或 Important。该结果只覆盖 ZipCPU `wbdmac` 的单字 RAM → PULP GPIO PADOUT 路由。

## 实现

- `GeneratedWishboneDmaSession` 通过版本化 `dma_master_target_access.v1` provider 接口交付已接受的 DMA 写事务。共用校验要求 request、target access、target request、target response 和 target effect 绑定同一个 `TransactionKey`；四个 target witness 还必须共享同一个 `access_id`。错误回执不会生成成功 DMA response。
- `GeneratedPulpGpioSession` 只接受带原生观察合同的 PADOUT `0x0c` 全字写。它把一次 APB request/access/response 和 `gpio_probe_out` 后值绑定到 DMA 事务。
- 新的 `PulpGpioDmaRuntimePaths` 声明 `memory_image → DMA read → DMA write → PADOUT effect`，并绑定正在运行的 DMA、共享 `PersistentMemory`、`MasterTargetWindow` 和 PULP provider identity。route admission 配置及身份快照在 case、step 和 target 副作用前复核。
- `MasterTargetWindow` 的允许值校验不再枚举 `range`，因此完整 32 位值域可常量时间表示。地址绑定的 decoder 新文档使用 v4；历史 v1–v3 shape 和混合模板重放保持兼容。

## 能力门

- **declared：** 图声明单个 32 位 RAM 字读取及按原值写入 PADOUT，包含 read/write endpoint、权限、窗口、偏移和 byte enable。
- **topology_bound：** 编译绑定精确的共享内存对象、RAM 区域、DMA target window、PULP endpoint 和 provider observation profile；路由身份变化在 provider 调用前拒绝。
- **runtime_observed：** 本地 Verilator 门观察到真实 ZipCPU DMA Wishbone read/write，RAM read `0x00010100 → 0x5aa55aa5`，并观察到 PULP APB 写 `0x4000100c`、完整请求/响应以及 PADOUT 后值 `0x5aa55aa5`。两笔 DMA response 的 error 均为 0。
- **replay_verified：** 独立 fresh 进程重跑后，typed route/effect prefix 在仅归一化 `execution_id` 后完全相等。
- **native refusal：** DMA 对未选中的 `0x40001010` 发起 Wishbone 写请求。admission 在 PULP provider 前拒绝；provider call 计数为 0，APB access/request/response 均为 0。拒绝后额外采样 `gpio_out`，实测 PADOUT 为 0。

## 验证与证据

环境为 Python 3.12.3、Verilator 5.051-devel (`e413e67`)。冻结运行输出与独立 join audit 位于 [attempt6 证据目录](evidence/pulp-apb3-dma-20261020-local-attempt6/)；审核摘要为 [independent-audit.json](evidence/pulp-apb3-dma-20261020-local-attempt6/independent-audit.json)。正向 run、fresh run、比较摘要、profile/build identity、事务 key、APB witness 和拒绝用例都保留在该目录。

复跑正向/fresh 与 native refusal 的命令：

```bash
PYTHONPATH=src \
MYFUZZ_DMA_PULP_REAL=1 \
MYFUZZ_DMA_PULP_CACHE=/tmp/codex-pulp-apb3-dma-20261020-attempt6/cache \
MYFUZZ_DMA_PULP_EVIDENCE=/home/qinkejiu/myfuzz/docs/reports/evidence/pulp-apb3-dma-20261020-local-attempt6 \
timeout 1800 python3 -m pytest -xq tests/integration/test_dma_pulp_gpio_real.py
```

关键身份与摘要：

- ZipCPU profile SHA-256：`eabcac10f041131f3759ad194d1e6554fe07160d6f68633c65d52643b6e384bd`；DMA artifact/build：`4e791b6c9d581e15df3b4349ad4b3aa2bb635e4f751659fb69a1ef251298ecd4` / `f11d8cb15e478c6573fe823c2da1a4f2b5715d38486d8cf66135fe5c71b64904`。
- PULP GPIO profile SHA-256：`ebda4798cc5e3874957e3b4aad8aa3fe3131c94f01537e90759fbd2f1bbfead0`；RTL `apb_gpio.sv` SHA-256：`1e271914da4d25c87acd12121dde60a6ed955033870fd7a6730b2c9bafcbcaef`；GPIO artifact/build：`abf9cc1e9280e659809edb2d1dbb65e74f7dd88d9a8907f1ffb9263c2df5d381` / `f8b7ea0e1a69433bdf51e4e31f296553b247ad5893f5edaf1b0a09cd2e5760bc`。
- Route graph SHA-256：`bc551b3b14fcc15be49a0aae68190784f7a0e96efe63352640582c3e172db7c3`；route contract：`40331295edb82a03f5afeaacaa0da70b3376840b33c7b3d4630f9ac1a0bf73e8`；prepared contract：`358e1b7553e367db204ae9802c3efebf9d70b8dcee115c1fd6591bde53ff993e`；fresh typed prefix：`a4b99eeb2800b5b7f0c24cec54e51910305361b27a566034f20cb942c73e093c`。
- Route builder 本地 SHA-256：`b5fd7f3bc1e4d31dee782eadd7a8fdc8f22495b4015fc77dac42a45f12d0609b`；真实门测试 SHA-256：`90c3d6c18843937709963de1f084f3ded856506f2eead0c17c1d261570687d2e`。生成 artifact 的 source manifest 对 334 个 host/source 文件做了固定；核心 session 和 decoder pins 收录在独立 audit 中。

Scoped regression 命令覆盖 decoder legacy replay、source bindings、DMA provider、OpenTitan UART S4、GPIO provider 和 runtime path：**334 passed、1 skipped、168 subtests passed（3.17 秒）**。Opt-in real integration 命令覆盖正向/fresh 与 native 未选地址负例：**2 passed（46.25 秒）**。`git diff --check` 通过。

## 边界与剩余工作

DMA 与 GPIO 是分别运行的 native RTL session，由 transaction-level provider 在进程间交付事务；共享 RAM 是 `PersistentMemory`/`MemoryService`，不代表物理 SRAM RTL。结果不证明 Wishbone-to-APB 物理桥、共同硬件时钟、CPU 发起/观察/退休该数据、持续 DMA fuzz，或 ZipCPU/UART、OpenTitan、Caliptra 等其他 provider 完成。

部分 byte enable 由 provider API 的单测在 APB 调用前拒绝；ZipCPU 该路径本身只生成 full-word DMA beat。被改坏的 provider receipt 会被 common dispatcher 拒绝且不会得到成功 DMA response，但 receipt 在 provider callback 返回后才可验证，不能据此声称撤销已经发生的外设副作用。

远程门尚未运行。遵照 [agent.md](../../agent.md)，本轮尝试连接 `jumpserver` 时 SSH 在 `166.111.80.238:2249` 超时；未连接目标机，也没有在远程写入任何文件。P6/P7/P8、P7 F6、六颗 CPU 整体适配和其余 DMA provider 仍保持原状态。
