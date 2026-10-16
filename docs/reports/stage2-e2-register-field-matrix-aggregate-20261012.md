# E2 64窄字段单valuepoint聚合证据（2026-10-12）

状态：scoped PASS。Root确认最后reviewer11089实际exit0后，轻量sequential聚合核对16个已独立审计bundle全部通过。exact64个(register,field,lsb,width)覆盖当前sidecar所有32个2bit INTTYPE字段及32个4bit PADCFG字段，无漏项或重复；每字段仅一个指定合法CPU RMW＋READ valuepoint。不是每字段0..3／0..15穷举，不证明全部permission／width／reset／effect边界，也不是完整E1／E2或Stage2完成。

读取每bundle preparation、summary、fresh wrapper、independent audit、source-and-command及resource小文件，逐bundlediscard；没有读取大型trace／manifest、执行native／fullaudit或恢复saved authority。核对全部trace count／semantic／ordinary／verifier／preflight fresh相等、9认证产物／8原request重编译／282pins／18关联／54APB／12selectedMMIO／4RAM已由每bundle独立audit证明，聚合再检查小证据一致；current code-owned源／sidecar冻结身份跨16bundle一致。每次generation及fresh是独立singleworker／≤180秒／RSS限额内：总16gen＋16fresh，不能称一个combined180运行。

每bundle只有8个current证书（4RMW＋4READ），历史各自保留；这不是global active128，聚合JSON明确global_active_certificate_count=null。证据JSON只comparison，不授跨Session权威或完整L2／functional／RFuzz／BFM。[聚合JSON](stage2-e2-register-field-matrix-aggregate-20261012.json)及[exact字段inventory](stage2-e2-register-field-matrix-execution-20261012.md)。

| Chunk | Register field=value | Events | Gen秒 | Fresh秒 | current cert／bundle | 独立审计 |
|---:|---|---:|---:|---:|---:|---|
| 1 | INTTYPE_LOW pin0=1, pin1=2, pin14=3, pin15=1 | 18218 | 133.036 | 117.503 | 8 | [PASS](../../runs/stage2-e2-register-field-inttype-low-20261012-v1/independent-audit.json) |
| 2 | INTTYPE_LOW pin2=2, pin3=3, pin4=1, pin5=2 | 18227 | 132.412 | 117.866 | 8 | [PASS](../../runs/stage2-e2-register-field-inttype-low-pins2-5-20261012-v1/independent-audit.json) |
| 3 | INTTYPE_LOW pin6=3, pin7=1, pin8=2, pin9=3 | 18227 | 132.386 | 118.395 | 8 | [PASS](../../runs/stage2-e2-register-field-inttype-low-pins6-9-20261012-v1/independent-audit.json) |
| 4 | INTTYPE_LOW pin10=1, pin11=2, pin12=3, pin13=1 | 18227 | 132.044 | 119.363 | 8 | [PASS](../../runs/stage2-e2-register-field-inttype-low-pins10-13-20261012-v1/independent-audit.json) |
| 5 | INTTYPE_HIGH pin16=1, pin17=2, pin30=3, pin31=2 | 18218 | 132.307 | 116.242 | 8 | [PASS](../../runs/stage2-e2-register-field-inttype-high-20261012-v1/independent-audit.json) |
| 6 | INTTYPE_HIGH pin18=2, pin19=3, pin20=1, pin21=2 | 18227 | 131.006 | 117.598 | 8 | [PASS](../../runs/stage2-e2-register-field-inttype-high-pins18-21-20261012-v1/independent-audit.json) |
| 7 | INTTYPE_HIGH pin22=3, pin23=1, pin24=2, pin25=3 | 18227 | 131.442 | 116.561 | 8 | [PASS](../../runs/stage2-e2-register-field-inttype-high-pins22-25-20261012-v1/independent-audit.json) |
| 8 | INTTYPE_HIGH pin26=1, pin27=2, pin28=3, pin29=1 | 18227 | 132.648 | 118.064 | 8 | [PASS](../../runs/stage2-e2-register-field-inttype-high-pins26-29-20261012-v1/independent-audit.json) |
| 9 | PADCFG_0 pin0=1, pin1=5, pin6=10, pin7=15 | 18222 | 132.430 | 119.738 | 8 | [PASS](../../runs/stage2-e2-register-field-padcfg0-20261012-v1/independent-audit.json) |
| 10 | PADCFG_0 pin2=2, pin3=6, pin4=9, pin5=14 | 18231 | 133.457 | 118.203 | 8 | [PASS](../../runs/stage2-e2-register-field-padcfg0-pins2-5-20261012-v1/independent-audit.json) |
| 11 | PADCFG_1 pin8=1, pin9=5, pin14=10, pin15=15 | 18222 | 132.285 | 118.604 | 8 | [PASS](../../runs/stage2-e2-register-field-padcfg1-20261012-v1/independent-audit.json) |
| 12 | PADCFG_1 pin10=2, pin11=6, pin12=9, pin13=14 | 18231 | 133.124 | 118.806 | 8 | [PASS](../../runs/stage2-e2-register-field-padcfg1-pins10-13-20261012-v1/independent-audit.json) |
| 13 | PADCFG_2 pin16=1, pin17=5, pin22=10, pin23=15 | 18222 | 132.999 | 119.251 | 8 | [PASS](../../runs/stage2-e2-register-field-padcfg2-20261012-v1/independent-audit.json) |
| 14 | PADCFG_2 pin18=2, pin19=6, pin20=9, pin21=14 | 18231 | 132.319 | 118.924 | 8 | [PASS](../../runs/stage2-e2-register-field-padcfg2-pins18-21-20261012-v1/independent-audit.json) |
| 15 | PADCFG_3 pin24=1, pin25=5, pin30=10, pin31=15 | 18222 | 134.160 | 120.053 | 8 | [PASS](../../runs/stage2-e2-register-field-padcfg3-20261012-v1/independent-audit.json) |
| 16 | PADCFG_3 pin26=2, pin27=6, pin28=9, pin29=14 | 18231 | 131.967 | 118.520 | 8 | [PASS](../../runs/stage2-e2-register-field-padcfg3-pins26-29-20261012-v1/independent-audit.json) |

当前source freeze关键身份：

- src/myfuzz/scenario/session_runtime.py: `f7da03f4b74d21e36736fbe50e3891937108c1a78a9d9d52c3a870398c4bafa0`
- src/myfuzz/integration/ibex_pulp_register_replay.py: `bfbb72a8bc79e7f37150e125670ceb8dd78ee1fc39497e397a5c15d4809510bf`
- src/myfuzz/scenario/register_program_verifier.py: `0375ed3ffcd9a4ec012ab8873f5874212d2c9d9dfd0878fcb1b9ab5554ca0470`
- src/myfuzz/local_harness/build.py: `06334fedf08cacd861806362dc216026af3b426cd80be2ceb10929ff2197056c`
- configs/peripherals/pulp_gpio/test_capability.json: `0cefc52e9300d9c0630642fa70ce7cce021035b218dfb64eea01045a618efc1d`

后续仍包括word字段plain／RO／conditionalread-clear、真实reset-default观察、权限／width／mask／副作用完整矩阵与等级证据；D5／D6／D8、完整E1／E2及E3–I继续OPEN。DIR_OUT word generation48145正在运行、尚未通过，本报告不将其计入64窄字段或word验收。
