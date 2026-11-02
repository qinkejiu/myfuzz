# AHB-Lite CPU 接入单进程循环：身份与真实 CVW 探针

2026-11-01。状态：组件探索；**尚未接入统一入口，也没有验证退休、外设 MMIO、F1–F6 或 IRQ**。

## 复用与实现

现有 `src/myfuzz/protocols/rtl/ahb_lite_memory_target.sv` 已将 CPU 的 AHB-Lite 请求转换为统一 `m_req_*` / `m_rsp_*` beat；host 不必再实现一份 AHB 时序。CVW 地址是 34 位，host 必须保留完整物理地址。CPU 独立暴露 `HREADY` 和 `HRESETn`：前者是 aggregate manager ready，不能拿外设侧 `HREADYEXT` 代替；后者是实际同步 reset，不能拿外部 reset 推断。

新增 `scripts/inprocess_ahb_identity.h` 的 `AhbIdentity` 在实际 manager address phase 保存地址、写方向和 HPROT。后续 `m` beat 的地址与方向匹配时，用保存的 `HPROT[0]` 区分 instruction/data；不匹配时返回 Unknown。每个上升沿在 `edge()` 之前读取当拍 beat 的 `classify()`，因为 completion 与下一笔 address 可以在同一沿出现。它不实现总线握手，也不能单靠地址推断退休。

## 已运行的验证

1. `tests/native/inprocess_ahb_identity_test.cpp`：验证地址相位 HPROT 保留、stalled 地址不替换、同沿 completion 与新地址、reset 和 34 位地址身份。普通 g++ 构建运行退出 0。
2. `tests/native/inprocess_ahb_protocol_test.cpp`：Verilator 构建现有 `ahb_lite_memory_target.sv`，将分类器接到实际 adapter 的 request/response；连续 instruction read → data write 通过，退出 0。这里 CPU 端由定向激励驱动，并非真实 CPU。
3. `tests/native/inprocess_ahb_cvw_smoke.cpp`：使用已有真实 CVW archive，宿主 RAM 预置 5 条 RV32 指令，完成真实 store/load。输出：

```text
unknown request tick=18 addr=c0000000 write=0
instruction_reads=15 unknown=1 data_reads=1 data_writes=1 store=1 reload=1
```

首个启动请求在实际总线同步 reset 释放前已被 backend 捕获，按当时的 manager-domain 观察无法建立原始 address phase，故如实计为 Unknown；随后 15 个取指 beat 和实际 RAM 写入、读取由捕获的 HPROT 分类。该探索没有退休信号或 DUT 正确性检查。

实际 CVW archive 为 `runs/cvw-dma-ram-cache-20261022/422b60dcdcde2b9b723134950d5bba48e89a3666c065f55b140847844b42987b/obj/Vlocal_runtime_cpu__ALL.a`，本次 SHA-256 `e0a927c1859b3198808e65dc30fc153aad5e48d74e9de57a0960e0b32dacaa7d`。其旧 manifest 的构建工具是 Verilator 5.051 `e413e67`；本次复用已有 archive，尚未重新验证它与当前工作树的缓存身份。不得将它当作当前源码的独立构建认证。

## 复现

以下命令只创建各自的临时输出；若现有 archive 或对应 Verilator 版本不存在，须先用当前 source-locked profile 构建，不能直接沿用该结果。

```bash
g++ -std=c++17 -Wall -Wextra -Werror tests/native/inprocess_ahb_identity_test.cpp \
  -o /tmp/myfuzz-ahb-identity-test
/tmp/myfuzz-ahb-identity-test

verilator --cc --exe --build -j 2 --top-module ahb_lite_memory_target \
  --Mdir /tmp/myfuzz-ahb-adapter-check -Wno-fatal \
  src/myfuzz/protocols/rtl/ahb_lite_memory_target.sv \
  "$PWD/tests/native/inprocess_ahb_protocol_test.cpp"
/tmp/myfuzz-ahb-adapter-check/Vahb_lite_memory_target

obj=runs/cvw-dma-ram-cache-20261022/422b60dcdcde2b9b723134950d5bba48e89a3666c065f55b140847844b42987b/obj
vinclude=/home/qinkejiu/.local/verilator-5.051-e413e67/share/verilator/include
g++ -std=c++17 -O2 -I "$obj" -I "$vinclude" -I "$vinclude/vltstd" \
  tests/native/inprocess_ahb_cvw_smoke.cpp "$obj/Vlocal_runtime_cpu__ALL.a" \
  "$vinclude/verilated.cpp" "$vinclude/verilated_threads.cpp" -pthread -latomic \
  -o /tmp/myfuzz-ahb-cvw-smoke
/tmp/myfuzz-ahb-cvw-smoke
```

## 统一入口的剩余工作

- 入口从 artifact 读取 `ahb_lite_cpu` 的 `m` beat、`base_protocol_traces` 和 `manager_domain.roles`，而不是将 CVW 物理别名写死在通用 host。`m` response 和 RAM/MMIO 路由可复用现有 host；未知身份不能计入取指。
- 现有 CVW wrapper 无 RVFI/IRQ 导出，统一入口目前要求 RVFI；需要真实 CPU 退休观察，或明确支持无退休观察的较弱范围，不能把 bus fetch 宣称为退休。上游 `src/rvvi/rvvisynth.sv` 提供真实流水线有效位/PC/指令推导参考，必须核实实际顶层接线。
- 已配置 CVW 开启 64 字节 I-cache；持续会话中宿主修改相同 trampoline 槽后，不能假设 CPU 会重取。配置支持 Zifencei，可探索由 CPU 执行 `fence.i` 或选择无 I-cache 的独立配置，必须实际验证缓存失效和连续两条不同输入。
- 首个请求的同步 reset 窗口须按 Unknown 安全处理，或调整启动时序并验证；总线地址仍需真实服务，不能因缺身份而丢弃。
- 最后用真实 CVW + IP 跑通所支持的 F1–F4 和连续 case，才可以声明该 CPU 协议已接入统一循环。
