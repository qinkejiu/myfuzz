# BOOM 工厂修复后的独立元数据恢复 — 2026-10-17

## 实际结果及范围

一次性 metadata controller267241已实际终态exit0，且PID已不存在。运行只做独立复制、来源验证、规范生成、实际Verilator版本查询和新元数据最终化；没有实例化会话、执行模型、重新编译BOOM或测量IRQ。因此它修复的是新工厂身份，不能记成原生IRQ通过。

[此前运行入口失败](boom-irq-native-attempt1-20261017.md)发生在原生会话启动前。修复仅将bound producer从gpio_irq改为实际绑定gpio.irq；程序、pulse64、6000+512上限、12项实际C++输入和8项原生实现源码均未变。旧失败、旧源与旧产物保留原样。

新产物位置为 /root/fanzehui/boom-irq-factory-fix-20261017/artifact-finalized。新manifest SHA256为3f405a57322a697f0dfee4004ef15e9c3c5c849bf1fc360b0dd0d087f2bbf89d；二进制SHA256仍为6367b592b743f935cb2de04bc6dfc4ac54c9ec8cf5dce4eb6545b140971e6c90。新host factory SHA0af5037e8282c232c672a0251e2c8f579d4f1f6edde793bc51e20854f8f1e77e单独记录；不能说全部host Python未变。

## 独立审计

根代理核对源2567文件before/after/copy完全一致、原构建84文件前后相同、工具身份前后相同、无共享inode。受保护的旧metadata88文件、旧finalized source2564文件、失败runtime source2566文件及其first原始gzip均未变。原三份历史归档哈希、binary原始字节、全部12个effective inputs、16项实际历史probe inventory及原build0/probe0/最终化失败1均重新核对，没有把历史状态改为新运行成功。

另从远端直接读取新manifest、新binary、新factory哈希，确认worker.exit0且incomplete/pending标记不存在。完整38文件的byte size/SHA与归档清单匹配。版本查询由受审查的实际调用流程及manifest版本输出支撑；没有单独版本子进程PID或syscall记录，不补造这种证据。

runtime_verified、source_authority、new_cpp_build、native_model_executed均false。下一原生门须独立复制新finalized source，复用新artifact原路径并重新冻结控制；不能在这个已使用的目录重启。

## 冻结与证据

source fix15bc4cb，准备4feb5b2，控制审查98e9da1/7b3ec71，根准备审查5230e71。实际运行前root另核ready20ad6eb738b67db8640f7e21299259fbc04f017f948960eddfa306e1dee0d211及完整source/protected/build maps。

- [完整元数据操作证据](evidence/boom-irq-factory-metadata-recovery-20261017/metadata-recovery-evidence.tar.gz)，SHA256 b8562f7f5dcd7945d0cb53d21230d3349734b485092647eb4b1e54aa25da42e0。
- [逐文件清单](evidence/boom-irq-factory-metadata-recovery-20261017/archive-file-manifest.json)。
- [根代理独立归档审计](evidence/boom-irq-factory-metadata-recovery-20261017/independent-audit.json)及[实际远端哈希](evidence/boom-irq-factory-metadata-recovery-20261017/remote-actual-hashes.json)。

整个系统、P6/P7/P8保持未验收。
