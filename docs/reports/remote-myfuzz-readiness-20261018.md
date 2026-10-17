# 新远程工作集核对（2026-10-18）

通过 `ssh jumpserver` → `root@192.168.5.70` 只读核对 `/root/fanzehui/myfuzz`，README 与 `.copy-done` 已确认。未启动测试、模型、构建、工具版本查询或编译器；未修改原 `system-20261016`。

## 已确认的差异

- `project` 的 Git HEAD 是 `42a9ce99cc7d1b11d37f44b90e4753563691c44b`，但 `git status --short -uno` 有多项生产源码、配置和测试修改。因此只能把42a9ce9记为HEAD，不能称整个工作树与该提交字节相等，也不能视为本地5051054验收快照。
- `environment.sh` 的 TMPDIR、PYTHONPATH、PATH 首项仍引用 `/root/fanzehui/system-20261016`。直接source会导入旧工作树。
- `bin/c++` 包装器也将 TMPDIR 强制设为旧工作集；仅改外层 TMPDIR 不足以隔离。
- 环境所列 `/root/fanzehui/myfuzz/.tools/verilator-5.051-e413e67/bin` 未找到，实际副本有 `tools/verilator-5.051/`；工具能否直接重定位尚未验证。
- `pythonlib`、`tools`、`bin` 和项目heavy lock文件存在；未因锁文件存在而推断当前有/无运行中的worker。

原始只读输出保存在 `.superpowers/remote-myfuzz-20261018/readiness-observation.txt`。这里只记录观察，不授构建/执行可用性。

## 下一次真实门的准备要求

1. 保留现有副本和历史证据，以已审查本地源码的独立完整快照建立新operation目录；源码/配置/第三方闭包逐文件哈希，不依赖HEAD字符串。
2. 新operation专用环境显式设置新工作集内的TMPDIR/PYTHONPATH和工具路径；核验包装器/可执行文件/运行依赖，不继承旧source或缓存的身份。原environment.sh保持历史。
3. P7 I5保留完整N1–N8 stdout/stderr、实际退出/skip和新CPU/IP RFuzz完整fresh；记录源提交、脏状态、测试文件、实际工具与子进程身份。不能用旧产物复制来冒充独立重跑。
4. 确认当前共享worker锁位置；锁非阻塞，失败即退出，不排队。运行超时只观察同一个PID，不重启。

文档增量可以同步到新工作集的独立evidence目录，不能把新增文档改写为42a9ce9的历史证据。P6/P7/P8开放项不变。

## 文档增量同步完成

11份具名文档/审计报告已复制到 `/root/fanzehui/myfuzz/evidence/docs-followup-dd9684a-20261018/contents/`。独立bundle的SHA256为 `7745cdc45429f5a99593a7e52c4b2a8e0558d0596c7069e9e9a2d5d5c7f3bd40`；远程解包前逐文件验证大小/哈希、拒绝链接及越界路径。`copy-receipt.json`记录实际manifest本地HEAD46d2798。目录名dd9684a只是此次操作标签，不代表整个bundle绑定该提交。project与旧system原件未覆盖。此次同步是文档副本，不是独立native重跑。后续新增报告仍以本地为准。
