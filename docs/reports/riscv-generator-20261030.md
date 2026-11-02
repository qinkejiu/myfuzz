# RISC-V 指令扩展模块与 F1 真实执行（2026-10-30）

范围：给 CPU profile 驱动的 F1 输入提供一个独立、声明式的 RISC-V 编码/生成模块；不依赖旧的证书/溯源层，不改现有 runtime 语义。RV64 和 A/CSR/FENCE 只做编码器，未在真实 CPU 上验证。

## 新增

| 文件 | 行数 | 内容 |
|---|---:|---|
| `src/myfuzz/riscv/profile.py` | 91 | 读取 `cpu.xlen`、extensions（归一）、instruction alignment、reset_vector；RV32E→16 个寄存器；C 要求 alignment=2 |
| `src/myfuzz/riscv/catalog.py` | 265 | 105 条声明式指令事实：RV32I 52、M 13、A 11、C 22、Zicsr 6、Zifencei 1；含 fixed bits、操作数类、立即数范围、是否写 rd、min_xlen |
| `src/myfuzz/riscv/encoding.py` | 331 | 纯函数编码器；非法操作数/立即数/对齐/压缩寄存器类一律 `EncodingError`，不截断；`pack_compressed_pair` 把两条 16 位指令打包进 4 字节槽 |
| `src/myfuzz/riscv/program.py` | 341 | 种子化直线生成器；寄存器读写依赖、x0 保护、RV32E 限 x0–x15、RAM 窗口与对齐约束、输出 `records`/`f1_records` 和逐条元数据 |
| `scripts/generate_riscv_program.py` | 105 | CLI：`--profile/--seed/--count/--ram-base/--ram-size/--output`，写 `program.json`、`records.json`、`program.S` |
| `tests/riscv/test_encoding.py` | 257 | 用 clang RISC-V 集成汇编器实际汇编出的参考词 + 独立字段解码 + 仓库内解码器二次核对 |
| `tests/riscv/test_profile_program.py` | 227 | profile 门控、确定性、RV32E、窗口/对齐、与 F1 validator 互操作、CLI |

编码参考不是凭记忆：用 `clang --target=riscv32/riscv64 -march=...` 汇编 100+ 条指令并读取 `.text` 字节；I/M/C 词另由仓库现有指令 provider 交叉核对。vendored riscv-dv 只提供格式/扩展表，不含原始 opcode 位，已在代码注释说明。

## 支持与限制

- 已实现：RV32I 全 R/I/S/B/U/J + FENCE/ECALL/EBREAK、RV32M、RV32A（含 aqrl）、Zicsr、Zifencei、RV32C 全部 22 条、RV64 12 条 + M 的 5 个 W 形式。
- 默认生成池只包含现有 F1 validator 接受的子集（LUI、ADDI/SLTI/SLTIU/XORI/ORI/ANDI/SLLI/SRLI/SRAI、I/M OP、LW/SW/SB、13 条安全 C），保证每条记录可直接作为 F1 输入；`--include-non-f1` 才生成 A/RV64/FENCE 等尚未被旧 validator 接受的记录。
- RV64 只与汇编器核对，未在真实 CPU/RTL 执行；C 打包固定两条合法 16 位指令；CSR/SYSTEM 不生成（可能 trap）；F/D 声明被忽略。
- RAM 窗口须 4 字节对齐且 ≥4 字节；12 位立即数使单窗口最多约 2 KiB 可达。

## 真实执行（F1）

新增 `configs/scenarios/mmio-profile-examples/riscv-f1-cv32e20.json`（CV32E20 RV32IMC × APB I2C，RAM 0x10000–0x3FFFF，`memory_flows: true`）。用生成器产出 4 条 F1 记录（seed 20261030），再与场景自带 F3/F4/F2 在同一会话执行：

```sh
python3 scripts/generate_riscv_program.py \
  --profile configs/cpus/cv32e20/component_profile.json \
  --seed 20261030 --count 4 --ram-base 65536 --ram-size 196608 \
  --output runs/_riscv-f1-program
python3 scripts/generate_mmio_scenario.py \
  --config configs/scenarios/mmio-profile-examples/riscv-f1-cv32e20.json \
  --output runs/_riscv-f1-scenario
python3 scripts/run_generic_scenario.py \
  --descriptor runs/_riscv-f1-scenario/generic_scenario.json \
  --flow mixed --mode original --case runs/riscv-f1-cv32e20-20261030 \
  --cache runs/riscv-f1-cv32e20-20261030/cache --execution-mode search \
  --rounds 128 \
  --record F1:b70f0100 --record F1:93d52f00 --record F1:93991501 \
  --record F1:b6979986 --record F3:55000000 \
  --record F4:55000000 --record F2:00100040
```

结果（`runs/riscv-f1-cv32e20-20261030/`，本机 Verilator 5.051）：7 例全部 `observed`，CPU/IP 退出码 0；4 条生成指令的真实取指边界分别命中 `0x10014/0x10034/0x10054/0x10074`，F3 真实 RAM 写 observed、F4 joins=2、F2 joins=1；同目录独立进程 replay `replay_matches=true`（26.57 s）。`evidence-summary.json` 保存了生成器命令、seed、记录与逐条 assembly。

不再声称：退休/RVFI、RV64、C.NOP 槽内填充、A/CSR/FENCE 的 F1 执行、DUT 内部正确性。

## 测试

```sh
cd /home/qinkejiu/myfuzz && PYTHONPATH=src:. python3 -m pytest tests/riscv -q
# 127 passed
```

另外对 `configs/cpus` 下 24 个可识别 RISC-V profile 做了 20 seed × 两种压缩模式的 smoke：记录均被现有 F1 validator 接受；`zipaxi` 非 RISC-V，按预期拒绝。
