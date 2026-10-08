# 第一步 P1–P5 代码与文档归档

归档目录：[`archive/development/first-step-p1-p5/20261008/`](../../archive/development/first-step-p1-p5/20261008/)。内容和校验方法见归档内的 [`README.md`](../../archive/development/first-step-p1-p5/20261008/README.md)，逐文件路径、分类、大小、权限和 SHA-256 见 `manifest.json`。

## 内容分类

| 分包 | 内容 | 原路径处理 |
|---|---|---|
| `code.tar.gz` | `src/`、`scripts/` 中的源文件，包括当前数据流代码及共享、历史代码 | 保存当前字节快照，运行入口继续使用原文件 |
| `documents.tar.gz` | `docs/` 全部文档和随附证据、`.superpowers/sdd/` 开发审查记录、根目录说明及原始设计文档 | 保留相对路径；当前与历史报告由 manifest 的类别及目录导航区分 |
| `support.tar.gz` | `configs/`、`schemas/`、`tests/`、`examples/`、`patches/`、`.gitignore`、`.gitmodules` | 保存配置、测试夹具、源码锁与第三方来源声明 |
| `review-evidence.tar.gz` | 本次复核输出和历史 P4 阶段汇总 | 历史结果与本次复核仍分别记录 |
| `git-state.json` | Git HEAD、分支、相关文件的修改／新增／删除状态 | 未提交内容以归档文件实际字节为准，Git HEAD 不等于本次工作区快照 |
| `external-dependencies.json` | 第三方源码、原始 RTL 运行、工具链和完整 replay 材料的位置与来源入口 | 大型产物保留原位，重建环境时按源码锁和阶段报告准备 |

为覆盖 P1–P5 的传递依赖，包内同时保存仓库自有的共享与历史代码；这些文件不因此成为 P1–P5 的验收证据。`manifest.json` 记录每个文件所属分包和职责类别。

`__pycache__`、构建目录和二进制中间产物由明确规则排除；第三方 checkout、工具链下载、整个 `runs/` 和用户其他归档不批量复制。`.superpowers/sdd/fixtures/` 中的大型原始事件流保留在活动 checkout。排除项与原因记入 `manifest.json`。原始设计 `.docx` 作为不透明文件按字节保存，不修改正文。

## 核验与恢复

先在归档目录检查：

```bash
sha256sum -c SHA256SUMS
python3 verify_archive.py
```

需要核对本机活动文件是否仍与归档一致时：

```bash
python3 verify_archive.py --source-root /home/qinkejiu/myfuzz
```

解包到新建空目录，依次解开四个 `.tar.gz` 即可恢复原相对路径。归档 README 给出完整命令。直接使用包内历史 RTL 证据前，仍须按各报告核对源码和工具链身份；本归档没有生成新的 RTL 验收。

`archive/` 和 `runs/` 被 Git 忽略；跨机器保存时需要复制整个归档目录，不能仅推送文档索引。
