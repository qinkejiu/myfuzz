# CVA6 full AXI 有界原生观察门 — 2026-10-17

## 实际结果

在遵循 `agent.md` 的远程独立副本运行，wrapper259215、controller259229 已终态，controller/worker 均 exit0。两个实际 CPU 进程263888、264049 均正常关闭并 reaped/exit0，执行 UUID 不同。末端独立进程检查确认这些 PID 已不存在，canonical heavy-worker lock 非阻塞探测 exit0。

两次各650个实际边沿样本完全相同；各826条 runtime 观察记录、2923条 Runner 事件及650份 DriverReceipt 在仅归一声明的 typed execution identity 后全前缀相同。原始 payload 未归一。两次真实 store/load/store 的 RAM0x400/0x404 均为0x600dcafe；实际接受 AR84、R84、AW2、W2、B2，末端无观察到的未完成请求。

根代理独立读取完整归档，核对每份 receipt 的 execution/sequence/tick/sample、Runner 一次导入、退出码、二进制和原始 build manifest 哈希交叉引用；另从保存的实际650样本重新投影，逐条复现两份826记录。离线复投影不另算一次原生运行。

## 冻结与运行

实现893d255，门脚本822afb8，准备8bae382，根控制87d5fda；控制独立审查8eea1e6。远程路径 `/root/fanzehui/cva6-full-axi-observer-20261017-attempt1`，通过 jumpserver 转发，实际执行 `bash control/root-runner.sh`，内部 `control/run-native.sh` 持有 canonical lock。源冻结 SHA256 `9f2c0510e7430b8f4f11f3ef5ff058f329d586004359d88521e55557b025c130`。

实际 binary SHA256 `42fa1846b113dde4392094c3ba7453ce429e2b03288465c961535f57f5a665e9`，原始 build manifest SHA256 `10d2109b7e2a1f91fa345776bc1f14e2f3e8d9e7f34c113b43ab6f5ecc87c80f`。完整归档含实际 cache/build、生成源码、程序、first/fresh 原始记录和控制日志。

## 证据与边界

- [完整实际归档](evidence/cva6-full-axi-native-20261017/evidence.tar.gz)，SHA256 `88d0b0c3af09c94481ecbaf805d79691ea600658fe805de97f64a107e59ce4c2`。
- [独立保存数据审计](evidence/cva6-full-axi-native-20261017/independent-audit.json)。
- [原始采样离线复投影](evidence/cva6-full-axi-native-20261017/raw-reprojection.json)。

这是固定650步 CPU/RAM 的 bounded_full_axi_observation.v1 原生门。source_authority、retirement_verified、protocol_completion_certified 均为 false；`no_pending_observed` 只描述该有界前缀。未授予任意同协议 IP 接入、覆盖引导反馈搜索或 P6/P7/P8 整阶段验收。随后源码944a888已修复观察器在可清空 EventJournal 中跨 drain 的全局引用编号问题，独立审查aaf4134通过，113项纯软件控制通过；从本归档两份真实样本离线重放各826记录保持完全一致。该修复未另跑新的原生门，本门原始冻结源码与普通 list 路径证据保持原样。
