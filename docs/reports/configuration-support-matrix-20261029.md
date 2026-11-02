# 公共 OBI/APB 适配支持矩阵

前六组 storage 关系测试均复用 `configs/search/*.json` → `scripts/run_dependency_search.py` → 公共 CPU OBI / peripheral APB adapter、F2/F4 lowerer 与 live storage provider。组合只改变 profile/request、compose 与已声明寄存器能力，没有新增 CPU×IP 专用执行器。

| CPU | IP / 已声明字段 | 配置 | 原生证据目录（runs 下） | original / strict fresh | 当前前缀离线 DUT line/block 覆盖 |
|---|---|---|---|---|---|
| Ibex | Timer / TIMER0_CTRL，offset 4 | `configs/search/timer-ibex.json` | `adapter-matrix-20261029/timer-ibex-v1` | 各4例，通过 | 22/30 |
| CV32E40P | SPI / SPICMD，offset 8 | `configs/search/spi-cv32e40p.json` | `adapter-matrix-20261029/spi-cv32-v1` | 各4例，通过 | 72/271 |
| Ibex | SPI / SPICMD，offset 8 | `configs/search/spi-ibex.json` | `reverse-pairs-20261028/spi-ibex-v1` | 各4例，通过 | 72/271 |
| CV32E40P | Timer / TIMER0_CTRL，offset 4 | `configs/search/timer-cv32e40p.json` | `reverse-pairs-20261028/timer-cv32-v1` | 各4例，通过 | 22/30 |
| CV32E20 | SPI / SPICMD，offset 8 | `configs/search/spi-cv32e20.json` | `adapter-matrix-20261029/spi-cv32e20-v1` | 各4例，通过 | 72/271 |
| CV32E20 | Timer / TIMER0_CTRL，offset 4 | `configs/search/timer-cv32e20.json` | `adapter-matrix-20261029/timer-cv32e20-v1` | 各4例，通过 | 22/30 |
| CV32E40P | causal GPIO / GPIOEN offset4、PADIN offset8；F1/F3 RAM | `configs/scenarios/compiled-f1-f4-cv32e40p-gpio-shared/generic_scenario.json` | `adapter-matrix-20261029/cv32-gpio-v1` | 各8例；within 双通过，独立 cross 报告通过 | 未测 |

证据根目录为 `research/input-strategy-audit-20261027/runs/`。前六行的 `comparison.json`、`seed-7-state-none/{original,fresh}/search-summary.json`、`state-transitions.json` 是对应记录。前六行实际序列均为 F4→F4→F2→F4；F2 获得已认证同版本 `write-read:12345678`，writer 与 reader 各分配1，总关系奖励2。fresh 的 within-invocation、cross-invocation 与 session-boundary 均 verified，重新执行真实输入与消费；并非仅导入旧结果。

前两行 CLI `source_sha` 为 `a9c965e8e0fd8b06223d9238f70b82485caa399824b2a161772a92d24588be6c`，第3、4行为 `59b8a733e380d2c9b97dae5d0c61f3d00966f1d51480269e932b19a935bb84b3`，新增 CV32E20 两行为 `8cdf425662731a5833a6893fc567e5329b8daf634de28b65ac7b8c0b66b00c65`。这是三个源码版本族的 3 CPU × 2 IP 适配证据矩阵，**不能合并为同一次策略或性能比较**，也不证明后续源码修订已重新原生验收。

覆盖测量针对 peripheral 录制的完整实际前缀：六行均136条结果、157 ticks，plain / instrumented 输出相同且匹配原录制回复。Timer 分母身份为 `d92ac3dee4acc6b1b0ddf091b0ffb455d1340d9013299115b0d4dbcbc7dbbdbb`，SPI 为 `140995efd9705ee1b525d120f23c49366934edaac9576e2dcfd749be153e9e5a`。它是预算外离线 RTL 覆盖，不是关系计数、搜索期在线覆盖或性能提升证据。

## GPIO 复用的独立核验

GPIO 行复用原 CV32E40P OBI CPU adapter、causal GPIO session/authority、F2/F4 lowerer 与公共 memory flows，没有新增 CPU×IP 执行器。公共修复按明确环境声明解释 pin8/width1，不依赖 IRQ；F4 辅助 pin 使用独立 source-only prepared path，零因果边，CPU MMIO 主路径保持独立，不把 pin 驱动伪装为 GPIOEN 写入原因。

实际八例为 F3:55→F1 read→F4 GPIOEN256/pin0→F2→F4 GPIOEN256/pin1→F2→F4 GPIOEN257/pin0→F2，original 与独立 CLI fresh 均执行11个 Session case（含三次真实辅助 pin）。PADIN 为0/256/0，dependent RAM 为1445/1189/1445；三次 GPIOEN 读回256/256/257。F3 实际写85至262136，F1 经真实 DUT OBI 读回85，四字节版本均[0,2]，来源为该次提交。RAM 是 host modeled persistent memory；CPU retirement、instruction→store 因果及 live 搜索奖励均不据此推断。

独立核验记录位于证据目录的 `independent-cross-verification.json`：逐项比较实际序列、online plan、PADIN/RAM 证据、进程分离和相同 artifact/build/binary，绑定原始文件 SHA256。两份 prefix semantic hash 为 `cc85072ab62b4469e4f53c977ea7d4303a9de13b35c222d2b34a25879e627bb6`，两次 within replay 均匹配。原 generic fresh summary 的 cross 状态仍为 `pending`，未改写为自动验证；cross 结论来自这份独立报告。

此行为另一个源码快照、另一种显式输入目录的复用验收，不与前六行合并策略或性能比较；未测 GPIO 离线 RTL 覆盖，未声明 CV32E40P 的 IRQ/F5/F6 支持。

## 同一入口重跑

前六行 storage 配置：替换 `NAME` 为表中配置名，并为每次运行选择未存在的输出目录：

```sh
PYTHONPATH=src python3 scripts/run_dependency_search.py --scenario configs/search/NAME.json --preflight
PYTHONPATH=src python3 scripts/run_search_comparison.py --scenario configs/search/NAME.json --variants state --seeds 7 --cases 4 --seconds 90 --output NEW_OUTPUT --cache CACHE --fresh --measure-coverage peripheral --coverage-max-commands 4096
```

第二条通过相同公共 CLI 启动真实 original / fresh，并附着该 original 前缀的覆盖测量。仅需检查运行时，可省略覆盖参数；需要显式分别调用时：

```sh
PYTHONPATH=src python3 scripts/run_dependency_search.py --scenario configs/search/NAME.json --mode original --execution-mode acceptance --policy state --seed 7 --cases 4 --output NEW_OUTPUT --cache CACHE
PYTHONPATH=src python3 scripts/run_dependency_search.py --scenario configs/search/NAME.json --mode fresh --execution-mode acceptance --policy state --seed 7 --cases 4 --output NEW_OUTPUT --cache CACHE
```

GPIO 行使用独立 descriptor 入口，原生执行时逐次调用（第二次复用同一输出目录）：

```sh
python3 scripts/run_generic_scenario.py --descriptor configs/scenarios/compiled-f1-f4-cv32e40p-gpio-shared/generic_scenario.json --flow mixed --mode original --case NEW_OUTPUT --cache CACHE --records-file configs/scenarios/compiled-f1-f4-cv32e40p-gpio-shared/directed_records.json --record-local-commands
python3 scripts/run_generic_scenario.py --descriptor configs/scenarios/compiled-f1-f4-cv32e40p-gpio-shared/generic_scenario.json --flow mixed --mode fresh --case NEW_OUTPUT --cache CACHE --records-file configs/scenarios/compiled-f1-f4-cv32e40p-gpio-shared/directed_records.json --record-local-commands
```

该入口的自动 cross 状态仍应与独立核验区分；不得仅运行第二条就将 pending 写成 verified。

## 能力与拒绝范围

- 前六行仅覆盖声明字段的合法读写、当前版本与同版本 F4→F2 消费；GPIO 行分别核 GPIOEN 写读回、动态只读 PADIN 及 F3/F1 host RAM 版本。其他寄存器、只读字段写入、协议/宽度或实际 artifact 能力不匹配必须经过 typed admission 拒绝；preflight 本身不等于真实 native admission。
- CV32E40P 保持 `read-write-no-error-pins` 合同，不能从没有的错误引脚生成总线错误证据。不能因同为 OBI 就推断所有 CPU 的 IRQ、retirement 或 error 行为相同。
- CV32E20 新增两行仅证明公共 OBI/APB F2/F4 复用，不证明该 CPU 的 F5/F6、GPIO IRQ、ISR 或 DMA 支持。
- 本矩阵不授予 F5/F6、IRQ acceptance/ISR、任意 CPU/IP 或跨组件消费能力；未安装实际 provider 的反馈仍为 unknown。
