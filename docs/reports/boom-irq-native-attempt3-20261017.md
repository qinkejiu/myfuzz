# BOOM：真实 GPIO→MEIP→ISR→MRET 有界门通过

实际 controller269878／gate269888 均终态exit0。首轮、完整fresh前缀及一次IRQ抑制负例通过；根代理独立复核全部403文件、原始传输流、GPIO／CPU因果链与完整首轮/fresh文档。仅规范化具名运行身份与实际PID，其余字段逐项相等。

[完整原始归档](evidence/boom-irq-native-attempt3-20261017/evidence.tar.gz) SHA `df3ad507ca27e1f07e1493eeae6bdb87ec02e697f4e53b398027ba7b1f25583b`；[独立审计](evidence/boom-irq-native-attempt3-20261017/independent-audit.json)及[逐文件清单](evidence/boom-irq-native-attempt3-20261017/file-manifest.json)包含完整校验与实际引用。

| 运行 | CPU/GPIO样本 | Runner事件 | 实际总步数 | 请求/交付IRQ tick |
|---|---:|---:|---:|---:|
| 首轮 |3000/3024|54669|6024|64/64|
| fresh |3000/3024|54669|6024|64/64|
| 抑制交付 |3000/3016|55133|6016|64/0|

主调度均6000步，Router间接步数分别24/24/16，quiesce均实际0步；共享总上限6512、quiesce最多512、墙钟300秒及IRQ64 tick保持。前两次失败未改写，见[attempt1](boom-irq-native-attempt1-20261017.md)、[attempt2](boom-irq-native-attempt2-20261017.md)。

## 实际链路

真实GPIO上升触发CPU tick221..284的MEIP输入。ROB/CSR实际中断原因分别在281post、282post出现；ISR读真实状态、清除、读回0并写RAM。真实cause／MEPC接受存储在339／346，status／clear在403／407，done在412，qualified CSR cmd4/address0x302的MRET在429，返回前景后的接受存储在475。RAM保留cause0x800000000000000b、MEPC0x8000005c、status1、clear0、done1、resumed1。完整源、原生A/D、目标访问与时间引用见独立审计。

抑制负例保留真实GPIO事件和64 tick交付请求，实际CPU输入为0；未观察到IRQ trap、qualified MRET或ISR/恢复存储。这是受控环境故障，不作为DUT缺陷。抑制运行没有额外fresh配对结论。

三轮共9个实际模型进程（每轮CPU启动检查、CPU测量、GPIO）PID和nonce均不同，全部关闭/reaped/exit0。原BOOM二进制SHA6367b592b743f935cb2de04bc6dfc4ac54c9ec8cf5dce4eb6545b140971e6c90及manifest3f405a57322a697f0dfee4004ef15e9c3c5c849bf1fc360b0dd0d087f2bbf89d未变；2567运行源码、2567原来源文件、88原产物和工具映射前后相等。未重建BOOM或重写元数据。

此结果接受固定GPIO→MEIP→trap/ISR→MRET→RAM诊断链，属于接受事务及被动CSR观察；不授源权威、退休认证、通用IRQ覆盖或完整P6/P7/P8。整个系统仍有通用接入、事件/反馈搜索及联合验收工作。
