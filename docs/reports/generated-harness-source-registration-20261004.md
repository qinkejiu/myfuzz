# CVE2 与 PicoRV32 源码获取门禁

日期：2026-10-04。对应[实施计划](../superpowers/plans/2026-10-04-cve2-pico-source-registration.md)与[五协议设计](../superpowers/specs/2026-10-04-generated-local-harness-five-protocol-design.md)的源码获取前提。

| 源码 | 上游 URL | 父仓库 gitlink | 全新检出得到的 HEAD |
|---|---|---|---|
| CV32E20/CVE2 | `https://github.com/openhwgroup/cve2.git` | `d079e8c8e6a08b330940ae123876ba0612bec18d` | 相同 |
| PicoRV32 | `https://github.com/YosysHQ/picorv32.git` | `ef203c2b0a3fb793280f5114941416c425c5b461` | 相同 |

父仓库提交 `e84102301abe7034bb9dc221b7f4cd6836cc1389` 只修改 `.gitmodules` 并加入两个 mode `160000` gitlink。提交前两个已有 checkout 的 `git status --porcelain` 均为空、HEAD 与 origin URL 均匹配；提交后的差异经独立代理审查，无发现问题。

在隔离目录执行 `git clone --no-local --no-checkout . <tmp>`、`git checkout HEAD`、`git submodule update --init third_party/cv32e20_upstream_reference third_party/picorv32_upstream_reference`，首次拉取成功。两个子模块的 HEAD 等于上表 pin，`status --porcelain` 均为空，其余子模块未初始化；临时目录已清理。原工作树的 BOOM、Ibex 状态及用户未跟踪文件未改变。

**本门禁只证明源码可获取和 revision 可重复。** 组件 profile、选定文件与传递 elaboration closure、生成 harness、真实 RTL 运行及跨组件场景均须另行验收。当前 PicoRV32 的旧 `official_core_interface_description.json` 仍有零 revision 占位值，不能作为通过证据。
