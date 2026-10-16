# 无 error 引脚 OBI：真实 fail-stop 边界

## 两项独立实测

| 门 | 冻结范围 | 实际结果 |
|---|---|---|
| 相同适配器 RTL/testbench 的 Verilator 变体 | 测试源码 `434a4e8`；控制 `abf4ec1`，隔离 pytest 配置 | **1 passed / 8.03 秒**；pytest、worker、后置源检查均 exit0；真实模型 returncode **1**，精确命中 `OBI backend error cannot be represented` |
| 真实生成式 CV32E40P 首取指 backend ERR | `b370e3d` 文件列表修复的独立副本，37,528 文件及符号链接预检 | Python 控制与审计 exit0；实际 native PID 214926 exit1，首请求地址 `0x10000`/sequence1 的 req/gnt 均为1；sequence2 注入 ERR 后命中指定 fatal，无成功 STEP 回执 |

前一项是独立适配器 RTL，后一项是生成式 CPU 的实际边界；均不代替连续 F4 的成功数据链验证。最初 Icarus 门缺少工具而跳过，及早期 CV32 `filelist` 枚举失败仍保留各自历史结果，未改记为通过。

## 同一 testbench 的身份与判据

原 Icarus stimulus 逐字节抽出为共享常量，SHA256 为 `83b46a7a6fb8dacc15dfe19a8b04926215877ce867003944670648d11153dc39`，711 字节。两工具使用同一 RTL 与同一 stimulus；Verilator 显式启用 `--binary --timing --assert -j 1`。编译必须 exit0，模型必须非零且包含适配器指定 fatal；testbench 末尾“错误被静默接受”的备用 fatal 无法通过。

软件控制 6 passed / 0.03 秒，使用模拟 subprocess 验证编译失败、零退出、错误 fatal、缺工具和两工具 stimulus 相同。独立源码审查通过。独立控制审查发现环境 pytest 配置可引入额外代码，随后固定最小配置、关闭 conftest 与插件自动加载，并清除额外 pytest 参数；再次审查通过。实际门只选一个原生测试，TMPDIR 与全部远端写入均位于 `/root/fanzehui`，持有 canonical 非阻塞锁。

## 归档与限制

[Verilator 原始运行归档](evidence/obi-no-error-fail-stop-20261017/verilator-native.tar)及[逐文件清单](evidence/obi-no-error-fail-stop-20261017/verilator-native.manifest.json)包含冻结 source/config、控制脚本、前后源摘要、实际等待的退出状态、完整编译命令/输出和模型 stdout/stderr。测试临时编译目录按原测试生命周期释放；本归档不包含可执行模型。实际报错输出为时间25的 `tb.dut` 适配器 fatal。根代理重新读取归档确认 build0、native1、pytest0、sourceafter0。

CV32 boundary 原始记录由对应冻结 F4 门的独立归档保存；未与上述 unit 源码合并为联合 HEAD 证据。无 error 物理端口的成功协议观察仍表示 error 未观测（null），不能因 fail-stop 通过就补造成功 error=0。此报告不授予新 CPU/IP 通用接入、覆盖驱动搜索或 P6/P7/P8 完成。
