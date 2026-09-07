# 通用组合生成与真实 RTL 长测记录（2026-09-07）

工作区：`/home/qinkejiu/myfuzz/.worktrees/ibex-protocol-longrun`。

## 实现与验证范围

本次新增原生 APB3、APB4、Wishbone Classic 点对点组合路由，修复多端点共享时钟/复位、模块内 reset 证据定位、filelist 顺序/宏定义与源码证据一致性。协议编译保留能力及通道关系，等待约束取最严格上限；未在 sample projection 中实现的通道关系显式记录为适配器义务。

CVA6 接口模板包含完整 AXI4 字段及明确的源码入口；CPU profile 可执行状态必须通过接口、locator、源码 pin 和注释校验。BOOM 保持 reference-only。实际 CVA6/BOOM RTL 执行、AXI 多通道通用组合、完整 TileLink 及 RFuzz coverage-guided execution **尚未完成**。

## 本次运行对象

这是生产通用 planner 生成顶层后的真实 Icarus RTL 仿真。激励模块是合成总线事务发生器，外设是验证用寄存器模块，**不是 Ibex/CVA6/BOOM 实核或生产级外设**。

合法候选池包含 APB3/APB4/Wishbone 三种接口的三个两组件组合及一个三组件组合。用随机取得并保存的种子 `1723573746` 抽取三个不同组合，再按顺序执行。

每个组件独立完成交替写入/读回检查；每 4096 时钟批次必须新增超过 100 次事务且无读回/协议错误。常驻仿真保持状态，种子驱动连续 xorshift 写数据。计数提交前确认仿真进程仍存活且已经暂停。每批暂停 50 ms，运行使用 nice=15、一个 worker、一个 simulator、无波形，监督器监测进程组 RSS（soft 512 MiB / hard 768 MiB）。

## 运行命令

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 nice -n 15 \
  python3 scripts/run_generic_rtl_campaign.py \
  --output runs/generic_random3_300s_20260907_verified \
  --seconds 300 --count 3 --seed 1723573746
```

运行耗时从构建和短预检成功后计算。达到预算时监督器的 `timed-out` 是预期停止；受暂停的 simulator 可能在终止宽限期后被 SIGKILL 清理。只有完整时长、正事务计数、零错误、无监督错误并成功写入 checkpoint 才判定通过。

## 结果

最终全量回归：`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 nice -n 15 python3 -m unittest discover -s tests -p 'test_*.py'`，823 项测试、17.510 秒、OK。运行指标/逐组件记分板/退出状态修复经过独立复审。

三个组合均完成完整的 300 秒预算，合计 **18,751,780 次事务，0 错误**。总表、逐组结果与 checkpoint 的计数一致；每组生成 31 个 checkpoint。

| 组合（均含合成激励模块） | 实际时间 | 事务 | 错误 | 进程组峰值 RSS | 状态 |
| --- | ---: | ---: | ---: | ---: | --- |
| APB4 register + Wishbone register | 300.508 s | 5,746,980 | 0 | 37,933,056 B | 通过 |
| APB3 register + APB4 register | 300.510 s | 5,300,224 | 0 | 37,982,208 B | 通过 |
| APB3 register + APB4 register + Wishbone register | 300.509 s | 7,704,576 | 0 | 38,121,472 B | 通过 |

结果目录：`runs/generic_random3_300s_20260907_verified`。总表是 `campaign.json`；各组合保留源文件、pin 描述、生成 IR/layout/top/filelist、build.log、preflight.log、runtime/checkpoint.json 和 runtime/result.json。

- [总表](../../runs/generic_random3_300s_20260907_verified/campaign.json)
- [第一组结果](../../runs/generic_random3_300s_20260907_verified/combination_1/runtime/result.json)
- [第二组结果](../../runs/generic_random3_300s_20260907_verified/combination_2/runtime/result.json)
- [第三组结果](../../runs/generic_random3_300s_20260907_verified/combination_3/runtime/result.json)

上述峰值是 worker + simulator 所在进程组的 RSS，约 36.2–36.4 MiB，不包含父级编排进程和其他应用。运行中单个 simulator 采样 CPU 约为一个逻辑核的 22%，nice=15；这不是严格 CPU 配额。所有正式组的停止均为预算到期后的进程组清理，不是 DUT 崩溃。

原始指标历史有界，达到上限后截断历史而继续累计事务。继承监督器的 `iterations` 字段等于事务数，不等于独立 fuzz cases。本次不统计代码/结构覆盖率，也不宣称 RFuzz 执行。

## 预检中发现并修复的问题

- 源码是否安装影响五个旧测试：改用临时空 root 验证依赖缺失。
- 短寿命子进程在 stat/status 采样间退出：复查 zombie/退出状态；当前长测改为常驻仿真。
- 组合总事务数可能掩盖单个组件停滞：新增逐组件进度及读回检查。
- checkpoint 发布错误未纳入成功判断：纳入监督器 error 和 checkpoint 存在性校验。
- 已退出仿真进程的积压正常输出可能被计为成功：读取前检查退出状态，暂停后确认子进程状态。
- 仅 nice 和缓冲管道无法充分降低 CPU：增加每批 SIGSTOP/SIGCONT 节流。

被中止的预检目录保留用于审计，不计入三个完整五分钟结果。用户原有 `third_party/` 和 `.superpowers/sdd/task-2-report.md` 未修改或暂存。
