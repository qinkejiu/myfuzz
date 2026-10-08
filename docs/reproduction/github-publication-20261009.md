# 当前实现发布准备（2026-10-09）

目标远端：`git@github.com:qinkejiu/myfuzz.git`，目标分支 `main`。发布的是当前已实现系统的源码快照，不是“全部问题已修复”的版本；未修复问题和未完成的逐文件审阅见[审阅记录](first-step-individual-review-20261008.md)。

## 当前环境限制

GitHub SSH 连接返回 `Could not resolve hostname github.com: Temporary failure in name resolution`。原仓库 `.git` 及家目录外部备份只读。因此本轮不能更新原仓库分支／索引，也不能完成远端发布或外部备份迁移。

发布准备使用 `archive/releases/20261009/git/` 中独立 Git 元数据，父提交取原仓库当前 HEAD，复用原仓库只读对象。`latest-system.bundle` 保存这一父提交以上的新提交，可在包含父提交的仓库中导入。详细提交号、文件清单、验证结果与 SHA 见同目录发布记录。

## 发布内容

- 当前源码、配置、schema、测试、阶段报告与整理文档。
- 小型逐文件审阅证据 `runs/individual-review-20261008/` 和复现目录说明；其余完整 RTL trace、运行、构建缓存及大型备份仍保留本机。
- 第三方使用既有 submodule 指针和源码锁。两个显示 dirty 的子模块已核查：属于临时 elaboration 目录，无需要额外提交的 tracked 源码修改。
- 临时 `.scratch` 已移到本机归档；Windows `Zone.Identifier` 元数据及额外 BOOM reference checkout 排除。既有归档和凭据目录不进入提交。

## 验证范围

轻量 CLI、能力查询和文档链接单测 42 项通过；1117 个 Python 源码／测试文件完成语法解析，无语法错误。P1–P5 已有归档校验通过。没有启动 RTL、完整阶段验收或长时间 fuzz。

暂存内容的 whitespace 检查发现既有 Markdown 行尾双空格、文件结尾空行及两个测试中的行尾空格。为保存原实现字节和冻结源码身份，没有为了消除这些提示改写源码；完整输出保存在本机发布目录。已知代码缺陷随审阅文档一起交付，不能用本轮轻量检查宣布整套系统验收通过。

## 网络恢复后的发布

从仓库根目录，使用已准备的提交执行正常推送：

```bash
git --git-dir=archive/releases/20261009/git push origin main
```

如果远端已经前进，正常推送会拒绝，需要先检查并整合远端更新，不能强推。推送不会更新原仓库 `.git` 中仍指向旧提交的本地分支；本轮发布记录明确保留这个差异。

跨机器时复制 `latest-system.bundle` 与 `SHA256SUMS`，在包含发布记录所列父提交的仓库中验证和导入：

```bash
git bundle verify /path/to/latest-system.bundle
git fetch /path/to/latest-system.bundle refs/heads/main
git switch -c import-current-system FETCH_HEAD
```

之后按实际远端状态合入 `main` 并正常推送。完整原始运行和其他本机备份不随 Git bundle 传输，见[备份分类清单](backup-management-20261009.md)。
