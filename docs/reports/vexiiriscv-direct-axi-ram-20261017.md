# VexiiRiscv 双 AXI 端口定向 RAM 实测（2026-10-17）

源码为 `configs/cpus/vexiiriscv/generated/VexiiRiscv.v`，SHA256 `2453680b40e427ad51a29a84cd9138b4b608e206fbec5349e67480147806d0a0`；生成命令、上游源码与依赖钉定见同目录 `manifest.json`。运行程序为 [vexii_axi_directed.cpp](../../tests/integration/vexii_axi_directed.cpp)，直接驱动实际生成顶层的两套独立、裁剪的 AXI4 端口，响应不由 CPU 内部伪造。

远端 `/root/fanzehui/system-20261016/project` 使用 `environment.sh` 的 Verilator 5.051，在 `heavy-worker.lock` 下执行：

```sh
verilator --cc --exe --build -j 4 -Wno-fatal --top-module VexiiRiscv \
  --Mdir /root/fanzehui/system-20261016/evidence/vexii-smoke-obj \
  -o vexii_axi_directed \
  configs/cpus/vexiiriscv/generated/VexiiRiscv.v \
  tests/integration/vexii_axi_directed.cpp
```

构建 exit 0，日志 `/root/fanzehui/system-20261016/evidence/vexii-smoke-build.log`。分别启动二次普通运行及一次 `--fault-read` 对照，三次均 exit 0：

```text
fault_read=0 ticks=75 fetch=13 read=1 write=2 b=2 ram=[53,54]
fault_read=0 ticks=75 fetch=13 read=1 write=2 b=2 ram=[53,54]
fault_read=1 ticks=75 fetch=13 read=1 write=2 b=2 ram=[53,1]
```

CPU 从复位地址 `0x80000000` 经 fetch AXI 读取真实指令，写 `53` 到 `0x80000100`，从 LSU AXI 读回、加一后写到 `0x80000104`。控制运行仅将那笔 LSU 读响应替换为 0，第二次写随之变为 1，说明实际 CPU load 值传播到后续 store。测试维护 AXI AR/R、AW/W/B 的独立握手和响应队列，要求两次写为对齐全字，且观察到完整两个 B 响应。

当前等级仅为**固定生成 RTL 的定向 CPU/RAM 运行**。没有本仓 `component_profile.json`、受信生成式 local harness、CPU/IP 组合、IRQ、持续 testcase、在线变异或完整证据前缀 fresh replay。VexiiRiscv 的 Spinal 配置显式 `useLen=false`、`useBurst=false`、`useLock=false`、`useQos=false`，其真实顶层缺少本仓现有完整 AXI4 模板的这些必需引脚；不能直接套用该模板并宣称通用接入。
