# ZipCPU wbdmac 真实 RAM→RAM 定向传输（2026-10-17）

提交 `0093b7c` 建立独立的 pipelined Wishbone target/master 单边沿 transport；`8b3f38a` 增加真实 DMA session、账本支持的 RAM 服务与定向运行。固定上游 RTL 为 `third_party/soc-zipcpu/rtl/peripherals/wbdmac.v`，相关源码钉定见 `configs/peripherals/zipcpu_wbdmac`。本轮本地用 Verilator 5.051 构建生成 driver 并连接实际 DMA RTL；没有使用合成 DUT。

最终命令：`MYFUZZ_DMA_REAL=1 MYFUZZ_DMA_CACHE=/tmp/myfuzz-dma-c-real-cache MYFUZZ_DMA_EVIDENCE=/tmp/myfuzz-dma-c-evidence PYTHONPATH=src python3 -m pytest -q tests/local_harness/test_wishbone_dma_session.py`，结果 **4 passed in 15.79s**，日志 `/tmp/myfuzz-dma-slice-c-real.log`。两份完整原始收据在 `/tmp/myfuzz-dma-c-evidence/run-{0,1}.json`；仓库内的紧凑身份和收据哈希在 [DMA 证据](../../configs/peripherals/zipcpu_wbdmac/evidence/dma-session-real-20261017.json)。软件/源锁聚焦检查另为 13 passed、1 skipped；没有重写上游 RTL 或源钉定。

每次新进程均观察到 34 个 DMA 边沿、从 `0x1000/04/08/0c` 四次真实 master 读、向 `0x2000/04/08/0c` 四次真实 master 写，写载荷依次为 `0x12345678`、`0x89abcdef`、`0x0badcafe`、`0xf00dba5e`。目的 RAM 有四笔账本提交并能读回对应字。真实 IRQ 在第 34 边沿与末次写 ACK 同时出现，ERR=0，未决响应=0。两次完整边沿轨迹只归一化新进程 transaction UUID 后一致。

时序边界：这个上游 RTL 的末次写 ACK 预测对响应延迟敏感。所有请求统一下一边沿应答，四字数据正确却没有 IRQ；统一延迟两边沿会提前结束写 burst。通过的受限环境依据**实际 master 引脚**判断写 burst 尾，在普通下一边沿应答策略上额外等待一个边沿；这一策略写入 session 身份。任意合法延迟下的稳健性尚未证明。

当前配置由主机写入实际 DMA target。尚未证明六目标 CPU 的真实 MMIO 配置、DMA IRQ→CPU ISR、受控旧键/零长度/错误/reset 负例、IP/FIFO 方向、持续 testcase 或 P8 全门。启动键按 RTL 为 `0xfed`，长度单位为 word；不能沿用旧文档中的 `0x3db`。
