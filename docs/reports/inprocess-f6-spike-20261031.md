# 单进程 F6 探索记录

这是固定 Ibex OBI + ZipDMA Wishbone 的探索，不是通用执行器或 RTL SoC。宿主 C++ 分别推进已有的两个 Verilator 模型，并模拟 RAM、MMIO 路由和 DMA 实际输出的 level IRQ。初版源码保存在目标机工作目录；仓库中的 `scripts/inprocess_obi_wb_dma_spike.cpp` 和 `scripts/inprocess_f6_firmware.py` 随后已更新为从现有 artifact 生成绑定。固件脚本读取已有 F6 compiled contract，移除 GPIO companion 后通过现有 `build_f6_firmware` 和 candidate layout 生成 boot、ISR 和指令 slot。该简化固件不是完整共享 GPIO 场景。

目标机的工作目录为 `/root/fanzehui/myfuzz-inprocess-f6-20261031`；`run.log` 和 `run.time` 保存在该目录。观测到 CPU 写入 DMA 源、目标、长度、启动寄存器；DMA 读取并写入 4 字 `[1,2,3,4]`；DMA IRQ 高电平、CPU IRQ take、软件清除后实际低电平、ISR 结果写入、MRET 和后继指令退休。完成为 176 个宿主 tick，保存的一次运行自计 0.00846 秒，外层进程 wall 0.02 秒。时间包含程序内部加载固件、模型构造、复位、运行和标准输出，不包含构建；计时器精度和系统负载限制这个单次数字。链接时复用了现成 Verilator 模型 archive，链接时间本次没有记录。

输入与产物 SHA256：

| 文件 | SHA256 |
|---|---|
| spike C++ | `eec32f2aa88106279d1820d07b9bace3339d1732f3b0c73fa5e1e34b352b2acc` |
| 固件脚本 | `7039fd08312cb6115ed2b9a5f6f223dbf95f3f966c684b7bdd9b04ec95d9042c` |
| 渲染固件 | `771402bdf884a3a35b4794f60f68accb689c5bbd9b45c784d3ff8c0f2a5a7028` |
| spike 可执行文件 | `832314877bbb24d5e7beba2a29ed6677217d6904aea5cda6fe259e1322035fb0` |
| 已有 CPU archive | `4b8a70fbfb992e6a1d3904884e83f3eed0f77f154826288818f57e734d8e8d88` |
| 已有 DMA archive | `95cca267153508ccf2abb24f01de43baab274a895f48485d20a6dcf9e7b402ba` |
| 来源 compiled_paths.json | `71e440e6e54f6fc522edd7570b2ec3f37f14f46f0272cf2322de5d241406a83f` |

archive 来自目标机 `/root/fanzehui/myfuzz-stage2-prototype-20261031/runs/cache-f6/` 的已有生成构建。上列 archive 哈希是本次额外记录，不代表已有构建 manifest 独立认证了 archive。此探索没有原系统的完整 F6 collector、跨用例状态消费证书或独立 replay；不证明其他 CPU、DMA、IRQ、复位或部分 SEL，亦不可与多进程完整验收直接计算严格加速比。

后续 profile 绑定版保存在同目录的 `profile-bound-v2/`：准备脚本从 CPU 和 DMA artifact 的 backend roles、physical exports 和 F6 合同生成 `f6_binding.h`，固件仍由同一生成器产生。目标机真实 Ibex＋ZipDMA 在四次读写后观测 IRQ take、清除、MRET 和后继退休，176 tick；`run.log` 自计 0.0078975 秒，`run.time` 外层 wall 0.02 秒。两份 profile 的声明频率分别为 CPU 50 MHz、DMA 1 Hz；后者描述为 nominal simulation scheduling value。因此此次明确指定 `--assume-lockstep`，仅按等周期推进仿真，不宣称真实硬件同频。该版本检查时钟形状和 backend 角色，分别执行各组件声明的 reset 时长；不支持 Verilator timing 模型。目标机本次没有找到可直接复用的 wbdmac 模型，尚未验证更换 DMA。

进一步的直接 profile 准备不再构建 GPIO 或完整 D3。目标机 `/root/fanzehui/myfuzz-stage2-batch-20261031/runs/f6-batch-two/` 一次启动 CPU、DMA 和 RAM，按顺序运行预装的 `[1,2,3,4]`、`[5,6,7,8]` 两例，分别观察四读四写、IRQ 接收与清除及 MRET/后继；日志记录 `cases 2`、`ticks 332`，程序自身计时 0.0514 秒、进程 wall 0.218 秒。外层 wall 60.43 秒，包含 Python 启动、准备和链接；不是单例稳态耗时或严格性能对比。该批次未请求完整 F6 证书或 fresh replay，也不是在线生成新输入。

在线版本的目标机结果在 `/root/fanzehui/myfuzz-stage2-online-20261031/runs/f6-online-two/`，摘要和日志也取回到 [本地目录](../../runs/stage2-oneclick-20261031/f6-online-two/summary.json)。真实 CPU 取指在 slot 0 和 slot 1 等待后分别接收输入；两例均观察到四读四写、IRQ 接收/清除与 MRET 后继，CPU/DMA/RAM 仅初始化一次。输入预先写入管道，不代表已与反馈生成器集成；仍限定八槽及支持实际 RVFI 的 OBI CPU。wall 38.76 秒包含准备/链接，模型进程 0.036 秒；未请求完整 F6 证书或 fresh replay。

同一入口只更换 DMA profile 和 capability，目标机 `/root/fanzehui/myfuzz-inprocess-wbdmac-20261031/run/` 的 Ibex + wbdmac 单例观察到四读四写、1 tick IRQ、CPU take 和 MRET 后继；与 ZipDMA 不同，这次无需软件清 IRQ。结果仍是 observation、未 replay，不外推其他 DMA。

该版本当前文件的 SHA256：

| 文件 | SHA256 |
|---|---|
| spike C++ | `286039fe57dbc4a04f33af76f683070e4032bda82f4d46342142f4269e838fee` |
| 固件和绑定脚本 | `3487f30d444343d15ae321feb4c655e1542280e60f0a9bd570b7d1f9c4c0f447` |
| 生成的绑定头 | `740c222b7401921fa766538db7209009e9545fe86b339d25b24c75ab0744df63` |
| 渲染固件 | `771402bdf884a3a35b4794f60f68accb689c5bbd9b45c784d3ff8c0f2a5a7028` |
| spike 可执行文件 | `8b4ee83949825e51b62503bd62e4611e22ba813910c9faa4e78f257487f9eb37` |

目标机复现 profile 绑定版（假设已有上述缓存及版本匹配的 Verilator include）：

```sh
work=/root/fanzehui/myfuzz-inprocess-f6-20261031/profile-bound-v2
project=/root/fanzehui/myfuzz-stage2-prototype-20261031
include=/root/fanzehui/myfuzz-inprocess-irq-20261031/include
cpu="$project/runs/cache-f6/dbf6c0c982420d0aaf2832dd4ecc68716b9beabd8b4bf4ac679c73211ad3af8c/obj"
dma="$project/runs/cache-f6/869e986e78099b59192ad8cd429ce8226dc3efb6a8f18428cf07772cd30817c5/obj"
generated="$project/runs/f6-standard-search/original/generated"
PYTHONPATH="$project/src" python3 "$work/inprocess_f6_firmware.py" \
  --compiled-paths "$project/runs/f6-standard-search/original/compiled_paths.json" \
  --cpu-artifact "$generated/cpu/artifact.json" --dma-artifact "$generated/dma/artifact.json" \
  --profile-base "$project" --assume-lockstep --binding-header "$work/f6_binding.h" \
  --output "$work/firmware.txt"
g++ -std=c++17 -O2 -I"$work" -I"$cpu" -I"$dma" -I"$include" -I"$include/vltstd" \
  "$work/inprocess_obi_wb_dma_spike.cpp" "$cpu/Vlocal_runtime_cpu__ALL.a" \
  "$dma/Vlocal_runtime_dma__ALL.a" "$include/verilated.cpp" \
  "$include/verilated_threads.cpp" -pthread -latomic -o "$work/f6-spike"
/usr/bin/time -p "$work/f6-spike" "$work/firmware.txt"
```
