# P7 I5 独立远程工作集准备终态（2026-10-18）

状态：**副本已校验，尚未执行 N1–N8 或原生重跑，不授 P7 完成。**

## 实际远程副本

`/root/fanzehui/myfuzz/operations/p7-i5-independent-6b40ef4-20261018-attempt1/project/`

远程 `.copy-ready` 与 `control/copy-ready.json` 记录 `source_copy_verified_only`。15,333个普通文件、798,103,129字节的内容、文件权限及单链接属性逐项通过，且没有多余项目文件。解包后恢复清单中的原始文件模式，避免安全解包器将只读Git pack权限规范化后误认相同。

- 全文件freeze SHA256：`b6372fcdb7ca1e93c289f850b0d53bc421c571204a65b86bd828815eb1f13dd2`。
- 传输包615,937,717字节，SHA256：`a3b5ba65700049ad73e47ccf239ddb6626d1c4777cb4b5018abbe91be9032b1f`；原包保留在operation目录。
- 独立client SHA256：`16434544a4a0712fa7716f6f3e3ff8e0dd949139f6a047780f4d08694ff31dcc`，在operation的`client/kfuzz`；未执行。
- Git基线完整ID：`6b40ef4a5c13f01d50a1103dabbdffd2dd4c8941`。目录名是准备谱系，不能声称每个文件等于该提交：另有审查后的runner缓存修复4b6fc42、native边界守卫52de02c覆盖，以及两份独立Git元数据材料化。最终freeze覆盖实际组合字节，原Git基线和差异均显式记录。

此次仅创建新operation目录；没有覆盖原myfuzz/project源码、旧myfuzz或system-20261016。SSH始终经jumpserver转发，跳转机未落项目文件。

## 失败与材料化均保留

第一次清单规划因原Git索引硬链接拒绝，尚未复制目标；第二次在独立staging发现GPIO partial clone元数据而拒绝。两次均保留stderr和失败回执，没有当作通过。

原选定文件先独立复制为新普通文件，窗口前后内容/模式映射一致，目标不共享硬链接。Ibex与GPIO的原Git元数据使用本地file传输浅层材料化：禁止上游网络协议，`--no-local --no-hardlinks --depth1`，保留原提交对象，声明shallow边界；read-tree及connectivity检查实际exit0。原仓库各自操作前后文件哈希相同。

Ibex提交`34b0705760ef3dfa00e99637432473d2be8f22f3`；GPIO提交`f82caeb7f7d89427f05e9af5ed31e0675efe0d83`。这些是元数据闭包准备，不是RTL运行或来源权威。材料化后从staging重新规划、审批清单、独立复制；最终完整清单及远程副本均校验。

## 工具环境

新增 `/root/fanzehui/myfuzz/operations/environment-20261018-attempt1/`，独立TMPDIR、source-first PYTHONPATH、空全局Git配置和编译器包装器；原environment.sh未改。Verilator安装内容在tools/verilator-5.051/share/verilator/include，wrapper/backend路径已显式记录，尚未调用版本查询、前端或构建。环境文件的MYFUZZ_SOURCE_ROOT必须指向operations下独立project。该环境仍是prepared_not_executed；工具传递依赖、make/backend、Python依赖和实际选择尚待核验，不因wrapper哈希而自动批准原生运行。

## 独立审查及后续

[静态选定闭包审计](p7-i5-independent-snapshot-closure-20261018.md)独立核对478个源/include/lock/proof文件与8个负例selector，未发现该范围实际缺项；不替代全工具依赖或真实门。[准备脚本审查](p7-i5-snapshot-preparation-review-20261018.md)关闭M1。[native源码审查](p6-native-online-independent-review-20261018.md)关闭因果与边界守卫缺口，但没有新native结果。

下一步：冻结并核验实际工具/Python闭包，协调唯一canonical worker锁，再运行具名N1–N8和CV32E20+timer独立门，保留实际退出、完整fresh、证书和逐回执独立审计。P6持久native门与四类反馈、P8性能5×及整个系统均仍开放。

## 原始记录

[准备证据](evidence/p7-i5-independent-preparation-20261018/archive-receipt.json)定位51项原始命令、清单、失败、stderr、材料化、覆盖及复制回执；归档SHA256为`791cab0b534d5f7112e6be2fe36f0e617fe0f98727e6fa197e0773acc24719e8`。完整source传输包在远程operation中，不将大包重复提交到Git。
