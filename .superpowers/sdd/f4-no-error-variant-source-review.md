# F4 no-error ABI 增量独立源审查

只读复核owner冻结WIP（HEAD `9125484e07d2536982c9e4888812a8223c72179b`）的compiled_f4、renderer最小分支、no-error tests、generated-boundary诊断脚本、原CV32fixture和设计文档。未运行测试、构造、build/native或远端任务，未修改实现。八文件SHA与owner source-files.sha256逐项核对一致。

## 中严重性问题

**Generic OBI事件仍把不存在的error角色写为false。** 新 `check_f4_exact_hops` 正确给no-error hop写error:null，但已有 `scenario/ip_protocol_events.py:_consume_obi` 对导出transaction_response仍用 `bool(signals.get('error',0))`。因此缺physical error pin也产生error:false，违背本设计“无角色不伪造error=0证据”的统一边界。该旧缺口因新增合法no-error执行现在会进入正式exported runtime event。

Owner已独立发现并请求root授权最小扩展；本轮源码确认该行仍未修复。建议缺role=>None，真实role样本0/1保留原语义，并核对协议checker、schema/evidence consumers和已有error注入拒绝，不把None当已观测zero。应补缺角色/真实0/真实1软件控制后冻结新identity。本项解决前，不宜声称新事件流已完全符合no-error证据合同。

## 其余源行为裁决

`_cpu_error_policy`从exact admitted profile显式bool、真实endpoint模板pair、selected executor facts、adapter_sources、native ABI tap认证和生成HAS_ERROR计数推导；不按CPU名字或“缺tap”降级。no-error pair为read-only-no-error-pins/read-write-no-error-pins，native pair保持原variant。`verify_cpu_obi_protocol_traces`按ABI真实role/width/wiring重建全部trace/tap metadata，伪造constant_zero error tap被拒绝。

fail-stop adapter固定SHA `59730c6742a85351d6e2cbf284d88185c874080274f323f2364268f2da3440df`，代码拥有pin并重读实际源bytes。真实adapter在HAS_ERROR=0且backend rsp_valid&&rsp_ready&&rsp_error时同步$fatal；runtime要求恰好两个adapter、两个对应HAS_ERROR。仅修改artifact digest不能授权另一份fail-stop实现。该硬pin需要任何后续adapter变更单独review，不是动态信任任意哈希。

精确hop消费者默认省略policy仍strict native_error_role，每个consumed response必须真实error整数0；no-error须显式policy并输出null，不声称error/trap能力。policy进入checker identity、exact_hops和prefix，_stable重推比较。明确native_error_response断言在no-error上unsupported，原三个success-only assertions及其exact instruction/version/nativeOBI/router/APB/GPIOEN joins未减少。一般未知assertion仍由现有闭集拒绝，不因无error而当passed。

renderer改动只为显式bool的OBI选择现有对应模板pair，补齐此前False variant未记录contracts的问题；不新增CPU物理error端口、不改CPU profile、不换factory。其为共用renderer身份变化，后续native gates需要新冻结源码，不借历史Ibex/CV32的binary通过。

## Boundary诊断脚本

脚本只有显式调用才build/run。它生成/admit当前exact D2/D3，要求fail_stop_no_error_pin，保留source hashes并在过程中复验，观察真实backend instruction request acceptance与native req/gnt/address一致后才在下一命令注入i_rsp_valid=1/i_rsp_error=1。命令字段顺序与STEP_CPU driver一致。任意初始化/通信异常都会保留.incomplete并抛错，不会充作通过；没有实际acceptance则预算失败。

注入后成功RESULT立即拒绝；只有保存的actual非零child exit加指定原生fatal文字“OBI backend error cannot be represented”才判fail-stop完成。stdout尾部/stderr/raw commands/actual close returncode均保存；不能靠host捕获任意异常或自行kill所造成-9记正例。finally kill仅清理失败/未退出进程，正例returncode在此前proc.wait得到。此项是backend ERR边界诊断，不是CPU错误trap或完整F4成功门。

heavy-lock参数为必填，_worker_lock实际互斥；脚本不自动证明传入路径是远端canonical共享锁，调用必须用既定canonical路径。脚本没有网络操作；后续远端执行仍须遵守agent.md jumpserver及/root/fanzehui范围，不能因脚本存在绕过授权/锁/RSS预算。

## 软件记录与身份

当前冻结core SHA：`3ef5cd65b05ef81b00c8504e4b6324cc581177e8b9ad327be4fedb39cf5d0f53`；renderer：`521956a288c60c36816137c080659871f51bcac95640ca65c76af8a14666686f`；new tests：`8ac6e42e7df1497542f279d94d029580ecf2ad77cd9f13cae1e319e634977b51`；boundary script：`d51dc09ac1e17626947bd27ec29fafc63fc0d53659ca8646ca3ef539cf8344fc`。其余fixture/README摘要见owner八文件manifest；本轮验证全部匹配。

Owner记录RED9fail、first focused GREEN9passed/10.81s、补adapter bytes控制后的focused/broader正在收尾；本轮不提前宣布未收到的最终结果，也不将syntax/help或software fixtures视为native执行。new tests覆盖wrong template/fact/tap/adapter/HAS_ERROR、required nativeerror assertion、null exact-hop及strict default。

结论：新policy和boundary诊断源级设计基本符合合同；generic OBI exported error:false缺口是当前实质阻断。修复后仍需单独授权的adapter/generated-boundary native ERR门及Ibex/CV32三例两fresh门。当前无新native/P7/D4通过，原CV32仅恢复为合法success-only候选，不等于已验收运行。

## 最小通用观察修复后的只读复核

Root授权后owner扩展四个文件；本轮已只读复核diff和新测试，12文件manifest重新核对全部一致。上述中项已解决：OBI无error role的transaction_response.error现在为None；实际role0/1保留原值。evidence outcome明确为completed_error_unobserved，不授ok；coverage单独计error_unobserved，且不计ok/error，有限feature词表已包含该项。normalizer拒绝signals/widths集合矛盾及error宽度非1。新软件测试串联normalizer/checker/evidence/coverage，对None/0/1及错误宽度检查，未把verified completion等同已观测success。

剩低项：新宽度检查使用`widths.get('error') != 1`，Python True也等于1；若要严格JSON类型一致，应再要求type为int。admitted artifact真实trace认证仍阻止将该bool作为合法物理宽度，故不构成本次F4 policy绕过。

Owner报告broader ABI69passed2skipped/175.32s、extended协议238passed+67subtests/11.21s；本轮没有重跑。这些是软件结果，两个native skip不能算native pass。当前无剩余已确认高/中阻断；先前结论中的阻断已由本段取代。新native错误边界门及Ibex/CV32完整fresh门仍未运行，P7/D4不授级。

## 最终helper与类型防御freeze

只读复核owner最后两项防御：显式no-error policy遇任一trace仍暴露error角色，helper在消费事件前拒绝policy-trace-contradiction；generic normalizer的error width要求精确int1，True不再通过。对应两个pure negative已在源码，前述bool低项亦已解决。12文件manifest再次逐项核对全OK。

最终core SHA `a915395075e84e00b6f9c7a2da7617308dcdd03a2ecf71aef09898eebc519842`；normalizer `ccf702bc9d8a0ed676ec1ea363f430bcc6507670973f445aab441bbf112f48fb`；no-error tests `157dc1d3a2c233fe339c09639e414a9ba84a7355087a7cf74857314af72ec0a6`；observation tests `bc085cd4d42b4b10ffdcb28033081b0cda4299fa9f625accf9e537d660cd1332`。此前broad软件结果属于这两项最后防御前的版本，最后GREEN由owner另行保存，本轮未重跑或提前认定结果。当前无剩余已确认高/中源阻断；native/P7边界不变。
