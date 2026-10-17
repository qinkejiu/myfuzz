# P6 native在线定向门：独立实际证据审计

结论：**第三轮有界定向门的保存证据独立审计通过；不授P6整行、闭环证书或搜索性能完成。** 远程operation为 `/root/fanzehui/myfuzz/operations/p6-native-online-c924aac-20261018-attempt2`，实际gate进程PID4046776、终态exit0。前两次启动前失败保留在[旧失败归档](evidence/p6-native-online-attempts-20261018/README.md)。

## 审计方式与原始归档

仅经jumpserver只读tar流下载`gate-attempt3-control`与`run-attempt3`，未复制project、改远程记录或运行项目代码/测试/模型。随后直接用标准库逐项读取原始gzip/JSON和子进程回执，未依赖summary的pass字段，也未导入原门禁checker。

[证据目录](evidence/p6-native-online-directed-20261018/archive-receipt.json)包含44个原始文件，解压普通文件总588,382字节；原包466,775字节，SHA256 `dc399360c1b72d5754effad7ba0563b823ce2cffa396bef85b93cbb81937d784`。逐成员长度/SHA见`remote-members.json`；可复核的纯保存数据审计为`audit.py`，结果为`independent-summary.json`。首次离线审计把进程表额外component列与按component分组的identity map混比，已按实际schema修正联结；原证据未变，过程说明保留在`audit-execution-note.json`。

## 实际运行、完整fresh与进程

| 项目 | 独立核对结果 |
| --- | --- |
| 父gate、元数据、layout子进程 | 共7份actual terminal均exit0；14份stdout/stderr SHA全部重算匹配 |
| Git前置 | root HEAD、closure tracked、Pico/GPIO connectivity四项exit0 |
| source前后layout | 8,887文件/600目录；file freeze `50145c24…e2cc4`、directory SHA `7cf80b4c…417ad`前后相同 |
| 工具前后 | 两份完整receipt全文相同；绑定115个Verilator runtime文件、581个pythonlib文件与具名入口清单；不是任意系统依赖闭包证明 |
| 正向 | CPU/IP/CPU三例；原执行与fresh各2,246事件，**整个trace document精确相同** |
| 受控响应 | 一例；原执行与fresh各982事件，整个trace document精确相同 |
| digest | 两组原plan SHA、trace semantic SHA及gzip/JSON bundle SHA独立重算匹配 |
| 进程身份 | 共8个实际DUT Popen回执，PID/nonce全局不同，均terminal0、epoch0；每component跨原/fresh/正向/受控artifact相同 |

正向三个case记录的actual PID/nonce/epoch与原始process identity逐格相同；每个保存case receipt的完整事件切片与首轮trace原对应范围一致，独立case文件也与result中的case完全相同。实际next-slot按32字节推进。fresh的`matches=true/full`、first_difference/difference_context均None，与独立全文比较结果一致；未删除事件、时钟、回执或任意身份字段来制造相等。

CPU原/fresh PID为4108968/4130126，GPIO原/fresh为4109109/4130280；受控CPU为4149882/4169962、GPIO为4150010/4170091。进程回执来自已审查门禁保留的真实Popen对象，非进程名称推断；本审计核对这些保存回执及逐case身份，不伪称另行探测已退出的OS进程。

## 受控响应实际关联

原/fresh各一份故障记录完全相同：实际PADOUT读回62、返回错误位0，回调仅将交付值改为63。原始mmio_delivery仍保存62，单一CPU session的backend response_consumed事件按source sequence14/epoch0精确关联到交付63，二者未混成“真实目标读回63”。这是已声明的宿主响应扰动，不是自然发现的DUT错误。正向无扰动记录。

详细CPU/IP数据因果与三个独立checker差异由另一代理对同一原包独立复算，本报告不以本身的PID或fresh审计代替该数据流审计。正向/受控的声明来源、实际MMIO/CPU消费证据仍只覆盖固定Pico/PULP GPIO实例；不授退休、通用来源权威、IRQ、四类反馈命中、18格campaign、通用无适配接入或吞吐目标。

本报告未修改CURRENT_PROGRESS等共享总表，由root在汇总实际因果审计后更新。整体P6/P7/P8保持开放。

## 原生完成信号测量边界补记

进一步原始轨迹审计确认该native artifact没有导出原生`mem_ready`。本报告及审计结果中的`data_rsp_consumed`、raw `m_rsp_ready`与“CPU response consumed”均指**CPU session/adapter backend响应握手**，不是直接测得的原生CPU总线完成或退休。受控62→63关联授予的是实际backend响应交付及后续真实CPU RAM/GPIO结果；不得用事件字段名字代替未导出的原生端口测量。完整fresh全文相等、真实进程终态和实际RAM/GPIO结果结论不变；未修改原归档/checker，也没有重新运行测试或模型。
