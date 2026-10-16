# CVW 与 PULP GPIO 定向双向数据链（2026-10-17）

运行范围：远端 `/root/fanzehui/system-20261016/project` 的隔离快照，使用该目录的 `environment.sh`、Verilator 5.051 和 `heavy-worker.lock`。测试代码对应提交 `3dbbbb8`；这是定向静态启动镜像，不是逐例在线 fuzz campaign。远端共享生成器快照早于 DMA Slice B 的 `0093b7c`，因此本报告不对该后续提交的生成器身份授级。

正例命令：设置 `MYFUZZ_SCENARIO_REAL=1`、`MYFUZZ_CVW_GPIO_CACHE=/root/fanzehui/system-20261016/evidence/cvw-gpio-cache`、`MYFUZZ_CVW_GPIO_EVIDENCE=/root/fanzehui/system-20261016/evidence/cvw-gpio-run-padin` 后，在项目目录执行 `flock -w 120 .superpowers/heavy-worker.lock python3 -m pytest tests/integration/test_cvw_cpu_pulp_gpio_chain_real.py::test_real_cpu_gpio_readback_branch_and_fresh_isolated_replay -q`。日志 `evidence/cvw-gpio-padin-positive.log`：`1 passed in 127.52s`。两次独立 CPU/GPIO 进程的完整观测保存在 `evidence/cvw-gpio-run-padin/{first,fresh}.json`，测试逐项比较实际采样、请求、路由交付、RAM 事件、身份和结果。

CPU 实际先写 PADDIR/GPIOEN，再写 PADOUT `0x35`、读回并写入 RAM，然后写 PADOUT `0x6a`、读回并写入 RAM。测试直接把 `0xa5` 驱动到生成 GPIO harness 的物理 `gpio_in`，推进四个 GPIO 本地边沿等待同步；物理输入采样必须出现 `0xa5`。CPU 随后经 GPIO PADIN 读取 `0xa5` 并写入 RAM；三次比较均相等才写成功标记。两份实测 RAM 结果均为 `[0x35,0x6a,1,0xa5]`。实测 APB 顺序恰为 PADDIR 写、GPIOEN 写、PADOUT 写/读、PADOUT 写/读、PADIN 读，共七笔；对应七次唯一路由交付、CPU 接受请求与 CPU 响应，所有 MMIO beat 为 32 位、BE=15，无相邻地址溢出。两个 PADOUT 值还出现在 GPIO 的真实输出引脚采样。

旧零地址窗口负例在同一快照执行 `test_old_zero_window_cannot_reach_external_gpio`：`1 passed in 64.46s`，日志 `evidence/cvw-gpio-padin-negative.log`；没有 GPIO 路由交付或 APB 访问，也没有成功标记。

边界：`gpio_in=0xa5` 是测试直接驱动的固定外部引脚值，当前 GPIO 生成物未启用来源上下文，因此没有 `gpio_input_applied` 的绑定来源收据或变异反馈。CVW v1 产物没有被动导出适配后 AHB 原始引脚，不能声称独立 AHB 地址相位的物理 trace。没有 FIFO、IRQ、DMA、普通 testcase 持续会话、在线变异、完整前缀 replay 或 P6 整行验收。
