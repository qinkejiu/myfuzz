# Stage 2 C7：关闭功能插件的基础路径验收

日期：2026-10-11。C7 已完成；B/C 的软件门禁通过，下一工作包为 D。软件回执 fixture 不构成真实 DUT 验收或 CPU/IP 矩阵授级。

`test_ip_plugin_free_fixtures.py` 使用仅提供原始信号回执的 session，实际调用生产 Runner、基础事件投影、协议 Checker、事件 journal、来源登记和基础覆盖消费者。三种协议 APB3、TL-UL、Wishbone 分别覆盖合法交易及 stall、非法握手、真实协议 error 与 checker violation 分离、reset 取消、跨例请求／响应。TL-UL 另验证重复 source、timeout 后 source 保留和迟到响应：原请求引用保留，迟到响应不恢复成功状态。APB3／Wishbone 不捏造原生事务 ID。

跨例绑定测试从 source case 的源动作、实际输出回执、精确 delivery，一直关联到 consumer case 的实测 pre-edge input sample；起始 action/case 与消费 case 分开保留。它只证明运输与采样关联，不将 EVENT_ORDER 声明变成因果认证。

追加的功能事件注释不改变同一 raw trace 的基础覆盖计数、诊断和 pending。独立新解释器使用 import finder 禁止 GPIO/UART 功能消费者导入，完整 C7 fixture suite 仍通过；因此基础运行不以功能消费者可安装／可导入为前提。尚未实现的 E3–E7 功能插件启停实测不在本报告范围内。

验证命令与结果：

```bash
PYTHONPATH=.:src python3 -m pytest -q \
  tests/scenario/test_ip_plugin_free_fixtures.py \
  tests/scenario/test_ip_plugin_import_boundary.py \
  tests/scenario/test_ip_base_events.py \
  tests/scenario/test_ip_protocol_events.py \
  tests/scenario/test_ip_protocol_checker.py \
  tests/scenario/test_ip_base_coverage.py --tb=short
```

79 passed，67 subtests passed。`git diff --check` 通过。

扩大回归发现 direct elaboration 源锁校验缺陷：受限宿主走 direct 路径时未检查 Git revision 和工作区文件内容，原 `CV32E20SourceProfileTests.test_wrong_source_revision_is_rejected` 失败。新增错误 revision、已跟踪文件被改写、未跟踪源文件三类负例，修复前均未在启动前拒绝。direct 与 supervised 路径现共用 `_pinned_source_reader`，复用 Git HEAD／commit、子仓库 gitlink、文件 blob 与安全路径校验。

```bash
PYTHONPATH=.:src python3 -m pytest -q \
  tests/composition/test_direct_source_pins.py \
  tests/composition/test_cv32e20_source_profile.py \
  tests/composition/test_source_crawler.py -k 'not real_elaboration' --tb=short
```

首轮 56 passed，1 deselected，47 subtests passed。复审另发现 include 认证和编译后缓存复核缺口；新增 Git 脏／未跟踪 header、SHA 显式源列表引用未锁定 include、Git/SHA 编译期间源码改写负例。direct 路径复用有界 `_closure`、真实 metadata read-set 检查及 fresh 磁盘复核，保留受信工具内建文件白名单。最终同组加上 `tests/composition/test_opentitan_uart_direct_fallback.py` 为 63 passed、1 deselected、47 subtests passed；其中真实 UART/CV32E20 的 Verilator 端口提取通过，仅证明前端事实，非 DUT 交易。复审确认两个 finding 均修复。受监督的单项 Verilator 参数化端口回归在沙箱内因进程组不可用而 `startup-error`；获准在沙箱外重跑后 1 passed。首次未设置 PYTHONPATH 的收集错误、初次扩大回归的失败及被中止的长回归均不计为通过；完整 composition/scenario 回归仍待另行验证。

实现／测试入口：[C7 fixture](../../tests/scenario/test_ip_plugin_free_fixtures.py)、[导入边界](../../tests/scenario/test_ip_plugin_import_boundary.py)、[源锁负例](../../tests/composition/test_direct_source_pins.py)。计划：[Stage 2](../superpowers/plans/2026-10-09-stage2-declarative-cpu-ip-adaptation.md)。未运行 HMAC、四核或 20 行功能矩阵；未知 IP 强制门禁 G1–G8 仍未完成。
