# 流式 pinned JSON 写出（2026-10-31）

只改宿主证据写出，不运行 native。`compiled_f6_saved_outputs.write_pinned_json` 保持默认 `sort_keys=True, indent=2, allow_nan=False`、ASCII escaping 和末尾换行；64Ki 字符批次编码、写出并增量 SHA256，atomic replace 后分块读回校验同一 SHA256。目标文件仍只在编码完全成功后替换；失败不登记 pins，临时文件始终清理。

实现函数由28行变为47行，另增加1行 import；净增20行产品代码。新测试覆盖精确旧字节和 hash、禁止整文档 dumps、编码中途失败保留旧文件及清临时、replace 后篡改拒绝。既有测试一起运行：18 passed（7.37s）。

## 同数据宿主 A/B

可复现脚本：[benchmark.py](evidence/stream-pinned-json-20261031/benchmark.py)。从仓库根执行 `PYTHONPATH=src python3 docs/reports/evidence/stream-pinned-json-20261031/benchmark.py legacy` 或 `stream`；末尾加 `memory` 单独记录 tracemalloc。脚本在每次独立进程构造同一38,421条事件大样本，临时目录退出自动清理；包含写入、atomic replace 和初始读回校验，不包含输入构造。不是实际 DUT trace，不外推端到端收益。

所有8次运行输出均为46,326,369字节，SHA256全部一致：`b7dd75355f79de5ebce394b705c1b115d2260d48cb2e6e67300b1d2aaa35b0e2`。

|顺序|模式|耗时(s)|
|---|---|---:|
|1|legacy|0.519906|
|2|stream|0.512687|
|3|stream|0.824742|
|4|legacy|0.587663|
|5|legacy|0.388474|
|6|stream|0.316755|

中位数 legacy 0.519906s，stream 0.512687s，波动显著，不声称提速。

单独启用 tracemalloc 的两次测量：legacy 峰值新增 Python 分配131,443,382字节，stream 341,083字节（约少99.74%）；耗时分别1.593/1.894s，追踪开销下的时间不用于性能结论。未追踪运行前两次 stream 额外峰值RSS约512KiB，legacy各约133,120KiB；后续进程的 `ru_maxrss` 起始值异常偏高，未采用该组RSS差值作内存结论，以 tracemalloc 结果为主。

边界：默认格式完全兼容且不缩减证据；大单字符串仍可能产生单个大 encoder chunk。读回校验由原来的整文件直接比较改为流式 SHA256比较，保留相同篡改拒绝错误码；没有 fsync 或新的持久化保证。
