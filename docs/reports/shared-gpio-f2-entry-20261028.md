# 显式 GPIO F2 共享入口

新增 `generic_scenario_f2.json` 与 `configs/search/gpio-shared-f2.json`，声明 F1/F2/F3/F4/F5；原无 F2 descriptor 文件不变。F2 输入 `08100040` 对应真实 PADIN 地址0x40001008。runtime 只有实际 preparation.flow_ids 含 F2 才启用 GPIO F2；backend 按实际能力保留/排除 F2。

CompiledF4Runtime 的 F2 使用独立 register_f2=PADIN，F4 仍是 GPIOEN。capture、issue、consumer check 和 exact-hop scope 全部取 register_f2。证书前置条件及 version_before 使用 consumer 返回的实际 APB read PRE 版本（版本0合法），不使用较早捕获的快照版本；stable_f2_read_version 只做已定义的稳定投影，原始 actual_read 另存 certificate.native_read。CPU native OBI read 与依赖结果 RAM store 的 check_f2_exact_hops 保留。

GPIO 组件现在由 code-owned gpio.register-bank.v1 说明两种不同子合同：GPIOEN 稳定 RW，PADIN 动态 RO。compiler 通过真实 bank.supports(register,operation,offset) 验证路径；StorageFlowKernel 仅接受因果 GPIO 模板下 F4 GPIOEN offset4 write、F2 PADIN offset8 read 或已声明的 GPIOEN read，拒绝把 PADIN 当 stable RW。组件 bank/adapter 实现和其8项专项验证由反馈适配代理提供。

软件验证：共享 F2 装配、两套有/无 F2 的真实 preparation→component verifier/registry→plan→实际 authority/bound runtime→kernel lower、已有共享/runtime/storage 门104 passed /75.87s；search/search_comparison 211 passed /9.54s。actual-read装配测试用mock native build/consumer回执，验证实际读版本0覆盖旧快照版本88，不能替代原生证明。本代理没有运行native。

直接 runtime 脚本新增显式 `--enable-f2`；默认关闭。主代理可运行以下真实序列并完整fresh，检验PADIN消费0→256→0：

```
PYTHONPATH=src:. python3 scripts/run_shared_f5_campaign.py --case /tmp/shared-gpio-f2-native --enable-f2 --fresh --record F2:08100040 --record F4:0001000000 --record F5:0000000100000000 --record F2:08100040 --record F5:0000000000000000 --record F2:08100040
```

统一 generic CLI 也可用显式 generic_scenario_f2.json 与同一组 mixed --record。F6尚未接入此共享runtime；本增量不声称全系统完成或搜索效率提升。
