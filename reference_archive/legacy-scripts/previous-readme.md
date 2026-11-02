# 历史 scheme 对照工具

这里保留早期 Ibex/CVA6 的固定方案和时长对照工具，用于复现历史实验。当前独立 CPU/IP harness、场景和 compiled 数据流入口见[脚本首页](../README.md)。

| 工具族 | 入口 |
|---|---|
| CVA6 resumable scheme1/scheme4 | `run_cva6_scheme1_vs_scheme4_10h_resume.py` 及 plus4/plus5 变体 |
| Ibex 四方案 | `run_four_schemes_1000s.py`、`run_four_schemes_10h_hourly_common.py` |
| Ibex baseline/lightweight 与 bit 约束对照 | `run_ibex_baseline_vs_lightweight_plus_1000s.py` 及 plus3、scheme5/6、ablation 变体 |
| Ibex 可续跑长测 | `run_ibex_scheme1_vs_scheme4_plus2_10h_resume.py` 及 plus3 变体 |
| Ibex bit constraints pre/post | `run_ibex_all_bit_constraint_variants_pre_post_6h_resume.py` |

从项目根运行，例如：

```bash
python3 scripts/legacy/run_four_schemes_1000s.py --help
```

14 个脚本于 2026-10-26 从 `scripts/runs/` 成组迁入；文件字节、权限、同目录依赖和项目根目录深度保持一致。历史方案配置仍在 `configs/designs/`，原始结果见[实验资料](../../docs/history/README.md)。

冻结归档中的旧命令仍按原始路径解释；重放这些归档应使用其保存的原输入，不能用当前路径替换后声称旧哈希不变。迁移映射和原文见 `runs/repository-organization/20261026/`。
