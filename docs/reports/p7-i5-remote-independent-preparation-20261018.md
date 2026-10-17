# P7 I5 独立远程工作集准备终态（2026-10-18）

状态：**首次独立验收已启动，但在Git前置检查失败；N1–N8和原生门均未执行，不授P7完成。工具元数据查询已实际通过，详情见文末最新实际结果。**

## 实际远程副本

`/root/fanzehui/myfuzz/operations/p7-i5-independent-6b40ef4-20261018-attempt1/project/`

远程 `.copy-ready` 与 `control/copy-ready.json` 记录 `source_copy_verified_only`。15,333个普通文件、798,103,129字节的内容、文件权限及单链接属性逐项通过，且没有多余项目文件。解包后恢复清单中的原始文件模式，避免安全解包器将只读Git pack权限规范化后误认相同。

- 全文件freeze SHA256：`b6372fcdb7ca1e93c289f850b0d53bc421c571204a65b86bd828815eb1f13dd2`。
- 传输包615,937,717字节，SHA256：`a3b5ba65700049ad73e47ccf239ddb6626d1c4777cb4b5018abbe91be9032b1f`；原包保留在operation目录。
- 独立client SHA256：`16434544a4a0712fa7716f6f3e3ff8e0dd949139f6a047780f4d08694ff31dcc`，在operation的`client/kfuzz`；复制准备时未执行，首轮验收也未到达client启动阶段。
- Git基线完整ID：`6b40ef4a5c13f01d50a1103dabbdffd2dd4c8941`。目录名是准备谱系，不能声称每个文件等于该提交：另有审查后的runner缓存修复4b6fc42、native边界守卫52de02c覆盖，以及两份独立Git元数据材料化。最终freeze覆盖实际组合字节，原Git基线和差异均显式记录。

此次仅创建新operation目录；没有覆盖原myfuzz/project源码、旧myfuzz或system-20261016。SSH始终经jumpserver转发，跳转机未落项目文件。

## 失败与材料化均保留

第一次清单规划因原Git索引硬链接拒绝，尚未复制目标；第二次在独立staging发现GPIO partial clone元数据而拒绝。两次均保留stderr和失败回执，没有当作通过。

原选定文件先独立复制为新普通文件，窗口前后内容/模式映射一致，目标不共享硬链接。Ibex与GPIO的原Git元数据使用本地file传输浅层材料化：禁止上游网络协议，`--no-local --no-hardlinks --depth1`，保留原提交对象，声明shallow边界；read-tree及connectivity检查实际exit0。原仓库各自操作前后文件哈希相同。

Ibex提交`34b0705760ef3dfa00e99637432473d2be8f22f3`；GPIO提交`f82caeb7f7d89427f05e9af5ed31e0675efe0d83`。这些是元数据闭包准备，不是RTL运行或来源权威。材料化后从staging重新规划、审批清单、独立复制；最终完整清单及远程副本均校验。

## 工具环境（历史：environment attempt1仅准备、未执行）

新增 `/root/fanzehui/myfuzz/operations/environment-20261018-attempt1/`，独立TMPDIR、source-first PYTHONPATH、空全局Git配置和编译器包装器；原environment.sh未改。Verilator安装内容在tools/verilator-5.051/share/verilator/include，wrapper/backend路径已显式记录，尚未调用版本查询、前端或构建。环境文件的MYFUZZ_SOURCE_ROOT必须指向operations下独立project。该环境仍是prepared_not_executed；工具传递依赖、make/backend、Python依赖和实际选择尚待核验，不因wrapper哈希而自动批准原生运行。

## 独立审查及后续

[静态选定闭包审计](p7-i5-independent-snapshot-closure-20261018.md)独立核对478个源/include/lock/proof文件与8个负例selector，未发现该范围实际缺项；不替代全工具依赖或真实门。[准备脚本审查](p7-i5-snapshot-preparation-review-20261018.md)关闭M1。[native源码审查](p6-native-online-independent-review-20261018.md)关闭因果与边界守卫缺口，但没有新native结果。

历史下一步已推进至工具查询通过、首轮独立验收Git前置失败，详见下方最新结果。后续须在保留失败attempt的基础上准备修正目录结构的新副本，重新核验工具/Python闭包并协调唯一canonical worker锁，再运行具名N1–N8和CV32E20+timer独立门，保留实际退出、完整fresh、证书和逐回执独立审计。P6持久native门与四类反馈、P8性能5×及整个系统均仍开放。

## 原始记录

[准备证据](evidence/p7-i5-independent-preparation-20261018/archive-receipt.json)定位51项原始命令、清单、失败、stderr、材料化、覆盖及复制回执；归档SHA256为`791cab0b534d5f7112e6be2fe36f0e617fe0f98727e6fa197e0773acc24719e8`。完整source传输包在远程operation中，不将大包重复提交到Git。

## 最新实际结果：工具查询通过，I5 attempt1 在负例前失败

本节覆盖上文“尚未调用版本查询”的准备阶段状态；保留原失败副本，不代表目录修复后的第二次操作已运行。

- **工具元数据查询实际terminal0：** controller PID2936380，canonical锁内9个具名子进程均exit0：Verilator `--version`/`-V`、verilator_bin版本、c++/make/ar/git/perl/Python版本。实测Verilator5.051 devel、GCC13.3.0、Make4.3、ar2.42、Git2.43.0、Perl5.38.2、Python3.12.3，runtime root为 `/root/fanzehui/myfuzz/tools/verilator-5.051/share/verilator`。独立核对归档18份stdout/stderr均与operation中的SHA一致；operation记录tools/source unchanged。仅元数据查询，不是frontend、build、测试或native门。
- **I5 attempt1 已失败，N1尚未开始：** 归档 `result.json status=failed`、`negative_results={}`、`formal_p7_complete=false`；before/after Git rev-parse子进程分别PID3115908/3121937均exit0，Git status分别PID3115913/3121942均exit128，均报Ibex `.git` not recognized。原始error=`git-receipt-failed:before-git-dirty`，采集阶段另记after-git-dirty失败，未隐藏首个错误。根代理报告外层运行terminal1；本次归档未包含独立外层父进程exit回执，因此不补造其PID/退出证明。
- **失败原因及边界：** 只读目录诊断显示Ibex `.git/HEAD`与`objects/`存在、空`refs/`缺失。之前15,333文件哈希/权限一致不能证明空目录完整；此次独立重算source-before/source-after两份15,333文件映射全等，仍不能替代目录结构证明。该问题发生于Git身份/脏状态前置检查，不是N1失败或DUT错误，不能计为任何负例/原生通过。
- **修正仅源码通过审查：** preparer601964f的v2 manifest记录空目录/祖先权限，要求Git objects+refs，源与目标目录清单双向检查；独立2cfc8d8审查通过。传输必须显式携带目录条目及权限，并核对新解包目录manifest；未禁用Git status、未忽略submodule错误、未改旧attempt1。新操作仍需独立copy/工具/GO及真实门。

### 独立原始归档

[本轮归档回执](evidence/p7-i5-attempt1-terminal-20261018/archive-receipt.json)包含：

- `remote-records.tar.gz`：只读打流获取整个remote `run-attempt1`和`control/tool-query-attempt1`，44个普通文件、原始6,038,161字节，压缩1,836,224字节，SHA256 `3cfe517b4f262fdabda080ecbebc6dba339b90d9b7bb3bbe47f4eb931ee71e99`。
- `remote-members.json`：逐文件长度/SHA清单；原Git子进程回执、stdout/stderr、完整before/after文件map、query原始日志均保留。
- `local-control-records.tar.gz`：保存 `/tmp/myfuzz-tool-inventory-20261018`现有本地inventory、环境准备、launch、观察、query、目录诊断等原始记录，未重新执行其中脚本。
- `independent-summary.json`：离线JSON/哈希核对结果及外层exit回执缺口。初次离线核对误用python3.12 executable basename定位stdout，已改为实际编号前缀匹配；未改变原归档或运行项目代码。

归档齐全范围是上述两个remote目录及当前本地control目录；不是整个远程operation/source/tools包，外层I5退出记录仍需root控制器另行补齐。采集仅经jumpserver只读tar流下载，没有修改远程run、测试、构建或重跑。P7 I5、P6/P8与整个系统继续开放。

## 第二份工作集：实际 staging/规划进行中

601964f 的 v2 准备器及两份外围控制脚本经独立源码审查后，root 已启动新 operation `p7-i5-independent-601964f-20261018-attempt2` 的纯文件 staging/规划。源是保留的首轮 project；先核旧15,333文件 freeze，仅在新 staging 恢复原材料化中实际存在的 Ibex `refs`、`refs/heads`、`refs/tags` 三个0755目录，并覆盖精确601964f准备器。原 source 的文件/目录清单前后均需一致。

截至本次检查，复制仍运行（SSH session19867，最近观察1,470个 staging 文件），**尚无已审核 v2 selection、最终 project 或 ready 标记**；尚未执行第二次 N1–N8/原生门。控制脚本不会自动从 plan 进入 prepare；root 必须审查实际 manifest 后单独调用 v2 prepare，再核最终文件及目录清单。新验收父进程控制器增加实际 PID/退出和 stdout/stderr SHA 回执、运行前后独立目录核验，但仍未启动。

[第二轮控制输入与活动操作记录](evidence/p7-i5-attempt2-preparation-20261018/operation.json)保存已审查控制脚本、精确目录 recipe 和上传结果。复制耗时不触发重启；继续观察同一进程。此记录不是复制完成或 P7 通过。
