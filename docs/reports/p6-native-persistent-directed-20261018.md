# P6 native：固定实例持久定向门实际通过

状态：**PicoRV32 native＋PULP GPIO 的有界三例持久会话通过，完整 fresh 与受控响应扰动经两份独立保存数据审计通过；P6 整阶段仍开放。**

## 实际执行

远程源码副本：`/root/fanzehui/myfuzz/operations/p6-native-online-c924aac-20261018-attempt2/project`。输出为同 operation 的 `run-attempt3`，控制回执为 `gate-attempt3-control`。gate 父进程 PID4046776 实际 exit0；运行前后文件、目录和具名工具检查均通过。8,887文件／600目录，文件 freeze `50145c2408804a76c6ff651cefbb143aae17cd1be18559f79ea6386b510e2cc4`；不是当前联合 HEAD 的全系统验收。

| 例 | 实际选择源 | 目标读回 A / B | 实际 RAM / GPIO 结果 | 下一个实测等待取指地址 |
| --- | --- | --- | --- | --- |
| 1 | CPU 指令 | 62 / 0 | 62 / 62 | `0x220` |
| 2 | GPIO 8位输入 | 62 / 167 | 153 / 153 | `0x240` |
| 3 | CPU 指令 | 62 / 167 | 153 / 153 | `0x260` |

三例沿用同一 CPU／GPIO PID、nonce、epoch、RAM和Router；每例实际 CPU128 tick、GPIO144 tick，未逐例重建或复位。独立审计重建实际 accept/consume 序号，检查边界处无已接受的未完成响应；原始指令读回分别为 ADDI62、NOP、ADDI62。每例四笔排队交付、四笔目标 backend 请求/响应及两笔 CPU session 后端读响应握手均逐键关联，联合结果来自真实 RAM 写和 GPIO 物理采样。

受控门保留真实目标读回62，仅在实际 Router 返回回调将交付值异或1为63；CPU session 后端实际接受交付63；CPU随后真实写RAM/GPIO为63。独立复算与原 checker 的 `routed_read_response_mismatch`、`joint_ram_mismatch`、`joint_gpio_mismatch` 三项一致。这是声明的宿主响应扰动，不是自然发现的 DUT 错误。

正向原执行与 fresh 各2,246事件、受控各982事件；两组完整 trace document 分别精确相同。8个真实DUT进程均 terminal0，fresh PID/nonce 独立、artifact相同。CPU原/fresh为4108968/4130126，GPIO为4109109/4130280；受控CPU为4149882/4169962、GPIO为4150010/4170091。

## 证据与独立复核

- [原始归档、进程及完整fresh审计](p6-native-online-directed-independent-audit-20261018.md)：44份远程记录，原包SHA256 `dc399360c1b72d5754effad7ba0563b823ce2cffa396bef85b93cbb81937d784`，逐成员哈希与独立审计程序保留。
- [独立数据流审计及准备谱系](p6-native-online-remote-preparation-20261018.md)：从原始PRE/POST、CPU事件、排队交付与物理GPIO复算；对应脚本及JSON在同证据目录。
- [两轮先前失败](evidence/p6-native-online-attempts-20261018/README.md)：工具扫描范围错误、第一次P6选集缺host脚本，均完整保留。完整scripts闭包在新副本补齐，未改运行时或放宽验收条件。

## 尚未证明

native CPU artifact 未导出原生 `mem_ready`；记录中的 `data_rsp_consumed` 是 adapter/backend 握手，不是直接采样的原生 CPU 总线完成或退休。取指接受也须联合物理 `mem_instr`、PRE 握手、完整事务键和逐字节 writer，不能仅因 `channel_id=memory` 就认为是取指。

该 GPIO artifact 没有独立PSEL/PENABLE抽头，保存日志也不是完整DriverReceipt日志；此门证明钉定APB目标backend及物理GPIO的实际响应，不授独立APB相位证据。来源关联仍有 `unknown`／`transport_candidates_only`，RAM为 `observation_only`；不授通用来源权威、退休、IRQ、闭环证书或四类反馈命中。

本门不是RFuzz持续搜索、18格campaign或性能验收。行2–4持久多例会话、行5真实反馈搜索及逐边来源认证、P7通用接入、P8性能5×和当前联合版本验收仍需继续完成。
