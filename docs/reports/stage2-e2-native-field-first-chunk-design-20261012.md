# 首个剩余窄字段 native chunk（只读提案，未执行）

选 GPIO A `INTTYPE_LOW.pin0/pin1/pin14/pin15`，当前真实v3 sidecar字段名与source refs已读取核对；不是历史 `INTTYPE_HIGH.pin16/pin31` 的复用覆盖。四字段均 rw、side_effect none、width2、read_mask/write_mask3，lsb分别0/2/28/30，对应bus masks `0x00000003/0x0000000c/0x30000000/0xc0000000`。生产compiler必须从当前profile+sidecar重算，不以本表作为权限。备选是 `PADCFG_1.pin8/pin9/pin14/pin15`（确切名称有下划线），width4、lsb0/4/24/28、mask15；首轮不混两bank，便于精确限定覆盖。

建议8原请求，按字段顺序各一次显式RMW write随后一次独立READ：pin0→1、pin1→2、pin14→3、pin15→1；值均严格uint且≤3，无bool/自动截断。RMW请求read_modify_write=True、allow_side_effect=False，36byte程序、max_program_bytes64。READ结果使用safeRAM `0x10004/0x10008/0x1000c/0x10010`，必须actualRuntime检查真实memoryregions、initial/source-owned cells、全部声明slots与MMIO重叠，并保留实际privateissuedcommit，不由host填值。每READ实际CPU extraction `(busword>>lsb)&3` 与actualRAM enabled-bytecells对应，不以reset_value预设oracle。

每次RMW保存实际beforeLW/afterSW delivery、unique command-local raw/base APB refs、actualsource/targetepoch与完整CPUcontext；按 `(old & (~mask & 0xffffffff)) | ((value<<lsb)&mask)` 核对full32SW，并断言 `((old^new)&~mask)==0`。下一selectedREAD观察同word；code-owned verifier必须按完整chronology/nointerveningwrite/reset资格核对RMW→laterreadback，不能仅编译hash或同值RAM授证。四RMW与四窄READ期望8 exactfieldop行为证书，仅当前这4field，不授其余12lowfield、highbank或整个register/wholeL2。

建议沿用当前actualassembly advance_rounds48/max_program_bytes64/max_records14、L1 preflight、ordinary256/verifier256，template512。初始53三组件commands的159steps只是历史启动测量；本轮真实warming只通过recordedSession.advance_initial至actualdeclaredwaiting。每case144componentsteps≤512，完整8cases不裁剪；预计selected12MMIO／36APB／4RAM，加固定bootstrap6关联约18association／54APB，必须保留并解释真实额外stream，不把预计计数强制成不可偏离oracle。

本轮不reset、不alias、不fullmask、不disable IRQ host input、不改bootstrap/ISR。A.INTTYPE只改A中断类型配置，不写A.OUT，因此没有宣称low8pads改变或B输入被隔离；实际接线CPU IRQ源B须持续记录CPU commanded IRQ、A/B actualphysical IRQ、rawsamples、pulsepolicy与全部IRQevent。如果观察额外ISR/事务，完整保存并严格判断是否影响该word区间，不能丢额外event以凑8selected。若需要隔离，应另提真实CPU B.INTEN write/read请求及相应case/resource范围，而不是偷偷增加未记录命令或声称reset值。

准备新的独立chunk目录，generation与trusted fullfresh分别singleworker／180秒/RSS预算；旧current缓存至多是新candidatecache，所有current source/build/input/binary认证仍必需。先generation完整预算成功再fresh，最后串行大JSON独立audit，避免并发内存改变budget。保留原request/currenttypedprofile+sidecar/sourceSHA、实际fullword与field extraction、untouchedbits、raw/base/callback/issuedRAM、fullfinalwrappers和complete trace/plan。当前未建新worker、未编译/运行或改production/config；后续执行由Root审查安排。
