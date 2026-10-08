# 远端测试访问规则

本轮 Ibex + PULP GPIO/SPI fuzz 的目标、验收证据和当前状态见 [工作要求](docs/IBEX_PULP_FUZZ_REQUIREMENTS_20260926.md)。

## SSH 跳转

1. 从当前工作机使用 `~/.ssh/config` 中的别名：`ssh jumpserver`。
2. 在跳转机上执行 `ssh root@192.168.5.70`，进入测试目标机。
3. 单条命令可按相同路径执行，例如 `ssh jumpserver 'ssh root@192.168.5.70 hostname'`。

## 文件范围

- 当前本地项目目录是 `/home/qinkejiu/myfuzz`。
- 目标机上的文件操作只限 `/root/fanzehui` 及其子目录；传输测试文件也必须放在该目录内。
- 跳转机仅用于连接，不在其上改动项目文件。
- 对目标机目录执行清理前，先确认目标路径确为 `/root/fanzehui`，且不会跟随符号链接删除目录外的内容。
