# P6 native online：两个启动前失败的实际证据

本归档只记录失败与前置检查，不是RTL失败或P6通过。经jumpserver只读tar流获取旧operation的`control`、`gate-attempt2-control`、`run-attempt2`，未复制project、修改旧记录或重跑。

- 第一轮controller在工具集合前置检查报`verilator-share-set-drift`，`gate_returncode=null`、Git metadata为空。实际扫描根包含原inventory子树外的share/man四项和pkgconfig一项；root后续只读比对报告missing/changed为空，不把它描述为工具修改。该轮after-layout子进程exit0。
- 第二轮真实门进程PID3893459，terminal receipt实际exit1，stdout/stderr均为空。positive/result.json.gz记录`ValueError: host source is missing: scripts/record_scenario.py`；cases/processes均为空，boundary_failure=null。未形成任何DUT执行用例或原生通过证据；工厂可能已做前端查询，不能声称本轮完全无frontend。controlled/fresh门未进入。
- 第二轮四个Git元数据子进程均exit0：root HEAD、closure tracked、Pico/GPIO connectivity。before/after layout分别PID3891154/3916926均exit0，实际8,777文件/599目录的freeze与directory SHA相同。工具before/after两份成功记录均在原归档。父controller结果status=failed、gate_returncode=1，即使其error字段null也不能记为成功。

`remote-records.tar.gz`包含46个普通文件、原始7,932,271字节，压缩2,431,928字节，SHA256 `30a5f4627a379cfd879a0354fb44142456835b2c4a68dbbd4a4bdaca5b2095cd`；`remote-members.json`逐文件绑定长度/SHA。独立离线核对8份子进程终态的16份stdout/stderr哈希全匹配、两份layout映射摘要相等，见`independent-summary.json`。

`local-controls-and-inputs.tar.gz`保留当时`/tmp/p6-native-copy-control-20261018`及`/tmp/p6-native-online-inputs-20261018`的已有控制脚本、复制回执、冻结map、Pico小归档和独立核对文件，不执行其中脚本。所有归档SHA见`archive-receipt.json`。

该选集漏了host_identity的实际脚本闭包。后续须在新source operation选完整scripts及其依赖，重新freeze、准备和root批准；旧失败副本不可就地补文件重跑。此归档本身没有测试、构建、模型或front-end调用，只有SSH只读下载和本地stdlib解读已有证据。整体P6/P7/P8保持开放。
