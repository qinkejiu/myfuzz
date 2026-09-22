# SoC Fuzz PPT Two-Slide Update Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在原 5 页 PPT 的第 2 页加入现有协议与 IP 系列对应关系，并把第 4 页改成 CPU 驱动与绕过 CPU 的双路径数据流。

**Architecture:** 以原生 PPTX 为源，复制到独立项目，保留 5 页顺序。先用 PPT Master 的 Fill Native PPTX 路线复制页面与替换既有文字，再用 OfficeCLI 对第 2、4 页补充可编辑形状与连线；所有改动在副本完成，原文件不覆盖。

**Tech Stack:** PPTX OOXML、PPT Master `template_fill_pptx.py`、OfficeCLI。

## Global Constraints

- 源文件：`/home/qinkejiu/myfuzz/范泽辉-2026.9.9.pptx`；输出保留原文件。
- 只改变第 2、4 页；页数与顺序保持 5 页；其他页的可见内容不变。
- 第 2 页映射：OBI—Ibex；AXI4—CVA6；APB3—PULP GPIO/SPI；TL-UL—OpenTitan UART/GPIO；Wishbone—ZipCPU UART/Timer。
- 第 4 页 CPU 路径标为“目标”，因为随机指令初始化尚未投入当前 SoC 运行构建；外设直驱路径标为“已实现”。
- 外设反馈到其他外设仅在有声明且接通的连接时成立；`mmio_only` 模式 CPU 持续复位。
- 采用原 PPT 的颜色、字体和卡片语言；新增内容用 PowerPoint 原生文本框、形状与连线。

---

### Task 1: 建立可编辑副本与第 2 页协议区

**Files:**
- Read: `/home/qinkejiu/myfuzz/范泽辉-2026.9.9.pptx`
- Create: `/home/qinkejiu/myfuzz/projects/soc_fuzz_ppt_update_ppt169_20260915/sources/范泽辉-2026.9.9.pptx`
- Create: `/home/qinkejiu/myfuzz/projects/soc_fuzz_ppt_update_ppt169_20260915/analysis/fill_plan.json`
- Create: `/home/qinkejiu/myfuzz/projects/soc_fuzz_ppt_update_ppt169_20260915/exports/范泽辉-2026.9.9-修改版_20260915_000000.pptx`

**Interfaces:**
- Consumes: 已审批设计说明 `docs/superpowers/specs/2026-09-15-soc-fuzz-ppt-two-slide-update-design.md`。
- Produces: 5 页、顺序不变的原生 PPTX 副本，第 2 页右侧协议区完成。

- [x] **Step 1: 创建项目并复制源文件。** 使用 `project_manager.py init "soc_fuzz_ppt_update_ppt169_20260915" --format ppt169`，再用 `import-sources` 导入根目录 PPTX；核对 `slide_library.json` 显示 5 页。
- [x] **Step 2: 制作与核查填充计划。** 运行 `python3 /home/qinkejiu/.codex/skills/ppt-master/scripts/template_fill_pptx.py scaffold /home/qinkejiu/myfuzz/projects/soc_fuzz_ppt_update_ppt169_20260915/analysis/范泽辉-2026.9.9.slide_library.json -o /home/qinkejiu/myfuzz/projects/soc_fuzz_ppt_update_ppt169_20260915/analysis/fill_plan.json --slides "1,2,3,4,5"`。填入五页各自的 `layout_rationale` 和第 4 页新的文案，运行同一脚本的 `check-plan` 子命令；报告不得有 errors。
- [x] **Step 3: 经 PPT Master 的确认门后应用计划。** `fill_plan.json` 设为 `confirmed`，运行 `template_fill_pptx.py apply` 写入 `exports/`；不要使用 `--force` 绕过确认门。
- [x] **Step 4: 新增第 2 页右侧协议区。** 对 `exports/范泽辉-2026.9.9-修改版_20260915_000000.pptx` 使用 OfficeCLI `add`，在 `'/slide[2]'` 创建名为 `ProtocolPanel` 的容器、`ProtocolTitle` 标题、`ProtocolOBI`／`ProtocolAXI4`／`ProtocolAPB3`／`ProtocolTLUL`／`ProtocolWishbone` 五个文本形状。五行准确采用 Global Constraints 中的映射；不改左侧组件 A/B。开始前运行 `officecli help pptx add shape` 核对参数。
- [x] **Step 5: 读取核查。** 运行 `officecli view /home/qinkejiu/myfuzz/projects/soc_fuzz_ppt_update_ppt169_20260915/exports/范泽辉-2026.9.9-修改版_20260915_000000.pptx text --start 2 --end 2` 与 `officecli get /home/qinkejiu/myfuzz/projects/soc_fuzz_ppt_update_ppt169_20260915/exports/范泽辉-2026.9.9-修改版_20260915_000000.pptx '/slide[2]' --depth 1`；应读出五组映射及七个新增原生形状。

### Task 2: 第 4 页双路径图与交付验证

**Files:**
- Modify: Task 1 的 `exports/范泽辉-2026.9.9-修改版_20260915_000000.pptx`
- Create: `/home/qinkejiu/myfuzz/projects/soc_fuzz_ppt_update_ppt169_20260915/validation/readback.md`
- Create: `/home/qinkejiu/myfuzz/projects/soc_fuzz_ppt_update_ppt169_20260915/validation/validate_report.json`
- Create: `/home/qinkejiu/myfuzz/范泽辉-2026.9.9-修改版.pptx`（经验证的交付副本）

**Interfaces:**
- Consumes: Task 1 输出的原生 PPTX。
- Produces: 第 4 页两条标注状态的数据流图和通过检查的最终 PPTX。

- [x] **Step 1: 核对第 4 页旧对象。** 对 `/home/qinkejiu/myfuzz/projects/soc_fuzz_ppt_update_ppt169_20260915/exports/范泽辉-2026.9.9-修改版_20260915_000000.pptx` 运行 `officecli get` 的 `'/slide[4]' --depth 1` 与 `officecli view annotated`，确认旧文字、图块、连线 ID；仅移除会与新双路径冲突的第 4 页对象。
- [x] **Step 2: 画共同起点和两条路径。** 用原生形状写入“随机 bit”、上路径“CPU 驱动（目标）→真实 CPU→仲裁/路由→ROM/RAM/外设→响应/中断”、下路径“外设直驱（已实现）→fuzz MMIO/环境引脚→真实外设→响应/输出/中断”；每个连接用带箭头的 OfficeCLI connector。
- [x] **Step 3: 加注边界。** 第 4 页脚注写“外设间反馈仅限已声明连接；mmio_only 中 CPU 保持复位”，不暗示任意外设互连或固定 stub 已实现随机指令执行。
- [x] **Step 4: 检查 PPTX 结构与文字。** 运行 `template_fill_pptx.py validate`、`officecli validate`、`officecli view issues` 与 `officecli view text`；确认 5 页、五组映射、两条路径及脚注均存在。
- [x] **Step 5: 检查视觉。** 对 1–5 页生成截图并逐页检查文字裁切、重叠、对比度、间距、箭头；如截图不可用，使用 HTML 预览并如实记录未验证项目。最多修订三轮，最后 `officecli close` 刷盘。
- [x] **Step 6: 交付副本。** 把经验证的 `exports/` 最终文件复制为根目录 `范泽辉-2026.9.9-修改版.pptx`，核对两份 SHA-256 相同；保留原文件。
