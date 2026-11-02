# TL-UL IP 目标在通用 F2/F4 的真实运行（Ibex OBI → OpenTitan GPIO）

- 日期：2026-10-31
- 场景：`configs/scenarios/compiled-f2-f4-obi-tlul-gpio`（Ibex OBI CPU → OpenTitan GPIO TL-UL target，
  INTR_ENABLE rw，base `0x40000000`，128 B）
- 结论：**F2 + F4 各 1 例已在本机真实 RTL 跑通**（`cases: 2`，两个进程 `returncode: 0`）。
  本文写就时 full（3×F4 + 3×F2）与 `--mode fresh` 尚未执行，其后已补跑完成，见下方状态说明。

> **状态说明（2026-10-31 后续）：** 本文是 2 例 F2/F4 最小验证的记录，证据目录已改名为 `runs/ibex-obi-tlul-gpio-f2f4-20261031`（只有 `original/`，无 `fresh/`）。完整 6 例 F4/F2 + 独立进程 fresh（本机 48.5 s / 48.6 s，`replay_matches=true`）在 `runs/ibex-obi-tlul-gpio-20261031`，远程镜像 `runs/remote-batch22-20261031b/tlul-gpio-run`、`tlul-gpio-target`；引用 TL-UL 结论时以 6 例目录为准，见[验收矩阵](stage1-acceptance-matrix-20261031.md) §3。本文其余内容（根因、修改文件、单例细节）仍然有效。

## 1. 根因

D3 `compiled_paths` 把 target 的 MMIO endpoint 上**所有已声明 input field** 都生成为
`origin=fuzzable` 的 `external_pin` source。TL-UL target 的 10 个总线输入
（`a_valid_i/a_opcode_i/a_param_i/a_size_i/a_source_i/a_address_i/a_mask_i/a_data_i/a_user_i/d_ready_i`）
因此出现在 F4 path 里。但它们在 local harness 运行时**不是 host 可见的 pin**：

1. `runtime_renderer.py` 对 `tlul_register_observe`：`consumed = endpoint_id in adapted`，总线端口被渲染成
   wrapper 内部 `link_lh_p_*` wire，由 `beat_to_tlul.sv` 从 `reg_req_*` 驱动；顶层只有 `trace_a_*` /
   `trace_d_*` 被动观察端口（当时在 `runs/_local-tlul-timer/work/generated/peripheral/runtime.sv` 可复现；该 `work/` 已在 2026-10-31 清理中删除，仅保留 `original/failure.json`）。
2. ownership 只包含真实环境输入（`gpio.pins.in` / `strap_en`，fixed）；`a_*_i` 没有任何 owner，
   `runner.inject_source` 必然在 `ownership.field_width/mutation_source` 拒绝。
3. `tlul_register_template.register_observe_policy` 明确拒绝把 target 总线 endpoint 的字段作为
   dynamic/bound 输入；session 唯一的驱动入口是 `ACCESS_TLUL_REG` → `beat_to_tlul`。
4. `compiled_f4_runtime_path.py` 旧实现只接受“0 个 pin”或“与 F5 共享的 1 个 pin”，且要求 pin 是
   dependency graph 的 source（该 graph 只有 4 个 `program_image`），因此
   `runs/_local-tlul-gpio/original/failure.json` 报 `compiled-F4-runtime-path-unmapped-source`。

**机制结论**：A/D 通道由 target session 内部驱动（`write_register/read_register` → `beat_to_tlul`），
`external_pin` 只是声明/观察别名；host 每个 tick 从 `mmio_delivery` 生成 A 通道是错误方向，且有上述三重
拒绝。运行时已有的“host 驱动 TL-UL”路径就是 session 的 register access 命令，本次直接复用，未重写协议。

## 2. 修改文件

| 文件 | 改动 |
| --- | --- |
| `src/myfuzz/scenario/target_bus_pins.py`（新增） | “已声明 target 总线输入”的唯一声明权威：严格识别 TL-UL target 模板的 10 个输入 role/width（`a_valid 1, a_opcode 3, a_param 3, a_size 2, a_source 8, a_address 32, a_mask 4, a_data 32, a_user 23, d_ready 1`），生成 `target_bus_pin_declaration.v1` 文档，身份 = `sha256(canonical{component,port,bit_offset,width,direction})`；从真实 artifact（`kind=tlul_register_observe` + `base_protocol_trace.protocol=tl-ul` + `adapted_endpoint_ids` + plan ports）自证 pin，输出 `by_identity/by_field` 注册表 |
| `src/myfuzz/integration/compiled_f4_runtime_path.py` | 在 admission 中把 target mmio endpoint 上的 pin 集合识别为“已声明 target 总线输入”：校验 component/endpoint/port 唯一/`bit_offset=0`/`mask` 全宽/`origin=fuzzable`/`range=None`/width 多重集精确等于 TL-UL 模板输入集，然后为每个 pin 写 `external_pin_paths{source_id,direction,declaration,path_id}`；不把这些 path 塞进 `prepared` graph/contract（避免 mixed-flow F2 graph 相等检查与 ownership 检查被打穿）；共享 F5 的单 pin 仍走原 F5 binding（`external_pin_delivery=shared_f5`）；其它 host pin 保持原 graph-source 路径；无 pin 的 document 缺省为空列表 |
| `src/myfuzz/scenario/session_runtime.py` | `configure_runtime_paths` 后从真实 artifact 安装 declared pin 注册表（`_install_declared_bus_pins`）；`submit_case` 对“path_id = 声明身份”的 `BatchSourceEvent` 走 declaration-only 分支：按 artifact 重新校验 component/port/bit/width/direction/value，不写 ownership/inputs、不注册 provenance source admission，只记录 `declared_target_bus_pin` 观察事件后执行其声明的 advance；普通 case 路径完全不变（legacy `_execute_case` override 仍不收空关键字） |
| `src/myfuzz/scenario/runner.py` | 新增 `declare_target_bus_pin(...)`：只追加 `declared_target_bus_pin` 事件（含 `declaration_id`、`delivery=target_adapter_internal_observed_only`），绝不写 `_inputs`、不产生 local command |
| `tests/integration/test_tlul_runtime_delivery.py`（新增） | 8 个合成事件测试（不跑 RTL）：pin 映射/身份、pin 集合拒绝（子集/超集/宽度/端点/组件/mask/offset/origin/range/重复 port）、artifact role 集拒绝、注册表重复拒绝、session 仅接受声明 case、runner 声明不改 inputs、admission `external_pin_path`/文档漂移拒绝、artifact 驱动注册表安装 |

`compiled_mmio.py` / `mmio_cpu_adapter.py` / `extension_plugins.py` / `scripts/*` 未改动；
`tests/integration/test_target_tlul.py` 的 adapter/observer 接口未变；只把 descriptor 的
`f4_records` 断言同步为 18 字节记录（协调方已更新 `generic_scenario.json`）。

## 3. 真实运行结果

命令（本机，唯一一次真实 RTL）：

```sh
TMPDIR=/tmp/myfuzz-tmp PYTHONPATH=src python3 scripts/run_generic_scenario.py \
  --descriptor configs/scenarios/compiled-f2-f4-obi-tlul-gpio/generic_scenario.json \
  --flow mixed --mode original --case runs/ibex-obi-tlul-gpio-f2f4-20261031 \
  --cache runs/ibex-obi-tlul-gpio-f2f4-20261031/cache --execution-mode search --rounds 128 \
  --record F4:000000550000000000000000000000000000 --record F2:04000040
```

> 注意：F4 候选 layout 含 10 个已声明 pin 切片（32 stream bit + 109 pin bit = 141 bit = **18 字节**），
> 因此 `F4:55000000`（4 字节）会被 `storage.py` 以
> `generic-case-shape at /case/raw_records_hex/0`（expected 18 / actual 4）拒绝。F2 仍为 4 字节。
> 0x55 的 18 字节记录为 `550000000000000000000000000000000000`（pin 全 0）。

结果（证据：`runs/ibex-obi-tlul-gpio-f2f4-20261031/original/`）：

- `summary.json`：`status=observed`，`case_count=2`，`wall_seconds=51.54`，`execution_seconds=1.586`，
  `plan_identity_sha256=0b8c029d94f95b99d301e5d50b3646e68e8cf8f2c70b99d27c46f1d44be52c37`，
  d2=`f19fdfef…a94b`，d3=`cced24ea…9d7e`；两个进程 `returncode=0`（pid 4367/4399）。
- 内存：`mem-before` used 2082 MB，`mem-after` used 1952 MB，采样峰值 **3751 MB**（< 5.5 GB 限额），
  14 个 3 秒采样在 `runs/ibex-obi-tlul-gpio-f2f4-20261031/mem.log`。
- `replay.json`：`execution-mode search` 下 within-invocation replay 为 not-requested。

### 例 0（F4，raw `000000550000000000000000000000000000`，写入 `0x55000000`）

- case_id `obi-tlul-gpio-mmio-mixed:0`，certificate `compiled_mmio_case.v1`，status `observed`，
  path `F4:ram.image`；`internal_storage_version=unknown`、`cross_case_origin=unknown`、`reward_eligible=false`。
- joins：
  - write：acceptance 212 → delivery 226 → TL-UL `a_valid&a_ready` 事件 239
    （`a_opcode=0` PUT_FULL，`a_address=4`，`a_mask=0xf`）→ `d_valid&d_ready` 事件 253（`d_opcode=0` ACK），
    value `0x55000000`
  - readback：acceptance 325 → delivery 339 → A 事件 352（`a_opcode=4` GET）→ D 事件 366
    （`d_opcode=1` ACK_DATA），value `0x55000000`
  - 依赖 RAM 写：`memory_write` 事件 452，地址 `0x3fffc`，值 `0x55000000`
- exact hops：data hop `source_sequence` 1（write）、2（read）
- instruction boundary park：`address=65712 (0x100b0)`，`expected_address=65712`，
  `reason=fragment_end_instruction_fetch`，`settle_advances=12`，`stopped_after_advance=34`，`tick=36`

### 例 1（F2，raw `04000040`，读 `0x40000004`）

- case_id `obi-tlul-gpio-mmio-mixed:1`，status `observed`，path `F2:ram.image`。
- joins：acceptance 845 → delivery 859 → TL-UL A 872（`a_opcode=4` GET，`a_address=4`）→
  D 886（`d_opcode=1` ACK_DATA），`read_value=0x55000000`（等于例 0 写入值，证明寄存器真实保存）；
  `result_value=0x55000045`（F2 xor 常量），依赖 RAM 写事件 1046（地址 `0x3fffc`）。
- exact hops：data hop `source_sequence` 4
- park：`address=65756 (0x100bc)`，`settle_advances=12`，`stopped_after_advance=32`，`tick=69`
- trace 末态：`local_ticks={processor:69, peripheral:81}`，prefix semantic
  `8fdd61c6b4cac3754c2276b7acaee5e708d674723d9726e3b0ad8161384d495f`

说明：本场景 descriptor 的 executor 是 `compiled_mmio`，它的 `submit` 只使用 admission 的
`runtime_path_id` / `instruction_binding`，**从不提交 pin case**，所以 events 中没有
`declared_target_bus_pin`（`events.json` 计数为 0）；pin 的“按声明交付”由 admission 的
`external_pin_paths` 记录，RTL 上 A 通道由 target 自己的 `beat_to_tlul` 驱动。18 字节记录里的 10 个
pin 值被 `compiled_mmio` 忽略（仅占 layout 位），不影响 RTL。`declared_target_bus_pin` 路径仅在
`CompiledF4Runtime`（F4 executor）遇到已声明 target 总线 pin 时启用，已由 8 个合成测试覆盖。

## 4. 回归与测试

- `pytest tests/integration/test_tlul_runtime_delivery.py -q` → **8 passed**
- `pytest tests/integration/test_target_tlul.py -q` → **31 passed**（descriptor 在 01:31 被协调方更新为
  18 字节 `f4_records` 后，该文件中唯一的记录断言已同步为 18 字节；`test_target_tlul.py` + 新测试共
  39 passed）
- `pytest tests/integration/test_compiled_f4_runtime_path.py tests/integration/test_target_ahb_lite.py
  tests/integration/test_target_axi4lite.py tests/integration/test_wishbone_mmio_target.py
  tests/integration/test_compiled_mmio_wishbone_target.py tests/integration/test_target_tlul.py -q`
  → **97 passed**（无 pin 的 APB / WB / AXI4-Lite / AHB-Lite 目标不受影响）
- `pytest tests/scenario/test_session_runtime_paths.py tests/scenario/test_online_source_provenance.py
  tests/integration/test_tlul_runtime_delivery.py -q` → **41 passed, 36 subtests passed**
- `pytest tests/integration/test_cv32e40p_causal_gpio.py -k "prepared_pin_case or four_flow_plan"` →
  2 passed（原有“单 pin graph path”路径保持可用）
- 已知环境噪声（与本次改动无关）：`tests/integration/test_compiled_f4_runtime_path_wiring.py` 报
  `host-source-content-drift:src/myfuzz/runtime/registry.py`。该文件是同一共享工作区里另一个 agent
  在 01:22 新建的未跟踪文件，不在本次改动范围内。

## 5. 复现命令（full 与 fresh）

F4 三条记录的 18 字节形式（pin 全 0）：`0x55 → 550000000000000000000000000000000000`，
`0xaa → aa0000000000000000000000000000000000`，`0x1234 → 341200000000000000000000000000000000`。

```sh
# full：3×F4 + 3×F2（交替写/读）
TMPDIR=/tmp/myfuzz-tmp PYTHONPATH=src python3 scripts/run_generic_scenario.py \
  --descriptor configs/scenarios/compiled-f2-f4-obi-tlul-gpio/generic_scenario.json \
  --flow mixed --mode original --case runs/ibex-obi-tlul-gpio-20261031 --cache runs/ibex-obi-tlul-gpio-20261031/cache \
  --execution-mode search --rounds 128 \
  --record F4:550000000000000000000000000000000000 --record F2:04000040 \
  --record F4:aa0000000000000000000000000000000000 --record F2:04000040 \
  --record F4:341200000000000000000000000000000000 --record F2:04000040

# fresh：同一 case 目录、同一记录，重放原始前缀
TMPDIR=/tmp/myfuzz-tmp PYTHONPATH=src python3 scripts/run_generic_scenario.py \
  --descriptor configs/scenarios/compiled-f2-f4-obi-tlul-gpio/generic_scenario.json \
  --flow mixed --mode fresh --case runs/ibex-obi-tlul-gpio-20261031 --cache runs/ibex-obi-tlul-gpio-20261031/cache \
  --rounds 128 \
  --record F4:550000000000000000000000000000000000 --record F2:04000040 \
  --record F4:aa0000000000000000000000000000000000 --record F2:04000040 \
  --record F4:341200000000000000000000000000000000 --record F2:04000040
```

（跑前跑后看 `free -m`；本次峰值 3.7 GB。）

## 6. 追加：full + fresh（主代理，2026-10-31）

- 本机 6 例（F4/F2 ×3）：original 48.5 s、fresh 48.6 s，`replay_matches=true`；证据 `runs/ibex-obi-tlul-gpio-20261031/original|fresh`。
- 远程同一快照：original 90.4 s、fresh 95.4 s，`replay_matches=true`；证据 `runs/tlul-gpio-run/original|fresh`。
- F4/F2 记录为 18 字节（4 字节寄存器流 + 14 字节零 pin 切片）；`acceptance_sequence.json` 已同步。

## 7. unknown

- TL-UL target 内部寄存器存储的版本号、跨 case 来源仍未证明：证书固定
  `internal_storage_version=unknown`、`cross_case_origin=unknown`、`reward_eligible=false`。
- 原 2 例运行之外的 full/fresh 已由主代理补跑并通过；仍不声称跨调用 replay 或内部版本。
- `d_user/d_param/d_sink` 等 optional trace role 未参与本 join（adapter 只要求 `_REQUIRED` 角色）。
- `compiled_mmio` 忽略 F4 记录中的 10 个 pin 字节；D3 仍把它们当 fuzzable entropy（候选空间浪费），
  长期应由 D3 `compiled_paths`/layout 更正（本任务不允许改该共享文件）。
