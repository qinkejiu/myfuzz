# 通用 APB 会话严格身份重建 — 2026-10-17

`GeneratedApb3RegisterSession` 已有组件无关的总线 transport，但其真实 `identity_document()` 被统一 preflight 的闭合字段集拒绝。另一个相反缺口是删除 service 专属字段后，generic artifact 曾可退化成 bare session 身份而通过；这会漏掉实际 setup/probe/初始化策略。

本增量为 `apb3_register_observe` 增加精确字段集、v1服务版本、两项既有初始化策略、最多16项全字对齐 setup writes/probe offsets、32位值范围，以及严格 JSON build identity 比较。统一 preflight 仍重建精确 profile/请求/绑定/ABI/runtime/driver 与 source/build identity，不接受未知字段或删除 service 字段的降级。没有组件名字分支，没有默认寄存器写入、隐式 probe 或结果生产者。

## 软件证据

实际 identity 重建先2项 RED；删除字段的降级漏洞另2项 RED。修复后38项纯软件控制通过5.74秒，覆盖 timer/GPIO 的真实 profile、绑定、source lock、渲染器、constructor 和严格重建，以及 JSON 往返/错版本/未知字段/错误初值策略/布尔代整数/超界和错位写入或 probe/篡改 runtime 与 build。

软件 fixture 明确替代 physical port facts 与 build-tool identity。GPIO 全端口宽度来自保存的真实产物，timer facts 按 pinned RTL 顶层参数形状构造；这些均不算本次 elaboration 或新原生证据。测试对外部 subprocess 加守卫，仅允许 source verifier 的 git 读取；未运行模型、elaboration 或硬件构建。

## 仍需完成

该入口只允许对实际 generic transport 的严格身份与配置复核，不授予 live register version、reset/source authority、编译F4完整执行或 P7 正式验收。后续真正新 IP 路径仍需受信的内部存储 producer、版本令牌与实际 CPU→IP 原生/fresh 门。
