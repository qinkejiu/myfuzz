# Native reset Task2 Runner私有consumer准备（只读，未实现）

Task1已获Root GO；producer可变源码阶段，本报告只准备接口和测试，不修改Runner、不运行test/native。前baseline20文件原始bytes归档已经验证，既有f7da／bfbb native门禁只保留其历史源码资格，不能以Task1新SHA改写旧pins或重授reset-default。

Task1／2独立contract review三条件必须实施：全operation错误范围含ACK／parse／abort／GPIO _take／directwrite payload／callback failures；native资格只来自pinned实际build issuance而非ambient方法／path／自洽hash；public detached exports和private facts registry／issuer必须分开。Task1成功parsed command应先immutable sealed，随后consumer错误以独立permanent-incomplete事实记录，不删除已实际作用的write。

## 最小私有接口（已向renderer提出；最终实现契约待其确认）

Runner beforebegin `install_native_reset_evidence(max_records,max_commands)` 应构造exact NativeResetEvidence并绑定actual runner、CPU service／ledger／router／windows／memory对象、每个实际native GPIO及其installed NativeResetObservation。针对每个target登记一次仅当前actual evidence拥有的private issuer，建议producer接口 `_register_private_issuer(evidence, *, runner)`；禁止 arbitrary caller provider、foreignsameprofiletarget、ducktype class／重复冲突issuer。名称待renderer最终确定，不将建议当已实现。

renderer已有提议 `_private_facts_since(cursor, *, issuer)` 与 `_resolve_fact(token, *, issuer)`。consumer要求单调fact cursor涵盖lifecycle、command完成／pending／fail、END close和postparse终止记录；建议返回immutable tokens与nextcursor，严格连续序号而非扫描全journal。Token只由actual private registry持有，resolve逐次检查exact owner／registry／producer class method及code／source pin、实际process／execution nonce绑定；equal JSON／deepcopy／foreign token不能注册事实。public logical processordinal／epoch／sequence可stable export，PID／nonce／issuer/token不进fresh comparison。

事实消费后才分配实际Runner journal IDs，index只记新fact并用 `_event_ref_by_id` 绑定实际ref。现有ordinary completed_accesses提供selected READ与实际queued CPU delivery关联，不能证明command interval完整；direct WRITE即便无ordinary row仍必须进入observer command coverage。未知／缺失／pending／callback failure／method drift使interval永久incomplete，不用最后readvalue或全resetbarrier治愈。

Runner global reset须在reset_all前drain事实、finalize oldinterval并pin当前actualCPU source execution／epoch及memory object／generation；每target end/reap／newREADY seal和Runner barrier仅在全component实际成功后关联。target reset_epoch、logical process、Runner command_epoch、CPU source_epoch、memory generation分别按自身真实领域核对，不断言整数彼此相等。独立target.reset_local不是global reset-all证明；partial全局reset保留history／incomplete。warm memory generation保持与cold增加由actual memory政策证明。

前effect模块pinned guard覆盖STEP／reset／source admission（new_operation容量），不能经instance／class方法替换绕过；执行后callback与terminal export再静态核current pins／registry／identity，不重造capacity或heal incomplete。Task3 actual issued MemoryCommitAuthority consumer必须在ack之前consume；Task2仅提供真实reset／continuouscommand事实，不自行授reset_value或semantic等级。

## Meaningful TDD清单（待Task1冻结后）

- current actualfactory＋真实READY／END进程／strictparser安装producer后，actualRunner warm／cold reset比较独立领域；软件worker机械事实native_eligible=False，不能伪造native正例。若安装严格拒绝ineligible，可测试拒绝＋真实base lifecycle control，实际native资格只能后续监督门禁证明。
- duplicate／foreign issuer/token、public detached lifecycle／command、deepcopy token、sameprofileforeigntarget／memory/serviceledger替换、method/code／registry/source drift，均在effect／journal qualification之前拒绝。
- parsed实际WRITE后 `_take` 或direct payload error、callbackfail、无ordinary rows的directwrite、pending／unknown command、ACK failure、END／READY失败完整保留并永久incomplete；不将parser成功当CPU ack或语义成功。
- command／lifecycle／Runner记录容量耗尽前无ACK／CMD／STEP；last合法case正常剩余ticks与export不因new-operation计数误拒。迟到duplicate command／ordinal gap不能通过cursor补证。
- actualreset-all部分失败与independent target reset不拼globalbarrier；actualacceptedsourcekey、CPU domain与memory generation错位不相互抵销。reset后旧seal／旧issuedRAM绝不授权。
- defaultoff existingRunner layouts完全不变；新增optin stable configuration／sourceclosure／journal／snapshot只用于comparison，fresh原请求／当前私有provider重建，不saved setter。

本阶段仅Task2接口准备。Task1实际producer契约仍待renderer最终发布，Task2及Task3／reset-default语义未实现、未验证；完整E1／E2／Stage2保持OPEN。

## Task1已承诺接口与one-use消费审查（只读）

renderer承诺 `_register_private_issuer(actual_evidence, *, runner)` once，要求exact未来NativeResetEvidence class及actualRunner.sessions[target] owner；`_private_facts_since(cursor, *, issuer) -> (opaque tokens, nextcursor)` 为pending／parse／close／lifecycle／failure全域单调cursor；`_resolve_fact(token, *, issuer) -> detached dict` 每issuer／token只解析一次，检查token identity／registry／owner／process／nonce并拒JSON。snapshot为schema／config／status／reason／lifecycles／commands／counts，complete或永久incomplete，mechanical native_eligible=False。此处仅承诺，尚非已实现或软件native资格证明。

one-use解析本身合理，但 `validate()`、`completed_intervals()`、snapshot／terminal export若再次resolve历史token，会把正常重复验证当replay攻击；reset后若将历史token绑定错为当前process，也会误拒合法closed lifecycle。Task2应将resolve限制在单一actual ingestion路径：私有cursor先拿新tokens，逐token一次resolve，完成producer前后guard后存入Runner-owned私有已消费事实缓存，分配actual journal refs。缓存每记录保留private issuer/token identity、原factordinal、canonical fact digest及actualref identity；detached exports从此缓存生成，而不是再次从token解析或接受调用者返回JSON。public report内容不是cache authority。

后续validate只检查actual provider／issuer／registry对象与module-pinned方法code／source绑定、当前snapshot permanent status和连续coverage状态；已消费历史事实验证缓存identity／digest与actual `_event_ref_by_id`，不耗尽token或全journal扫描。最好Task1另提供只读私有issuer静态guard／registry high-watermark与immutable resolved-proof handle（不输出token权限），供consumer核对原registry、当前cursor与事实不能被替换；若没有新接口，至少fixed `NativeResetObservation.validate(allow_incomplete=...)`及known snapshot/code-pins必须足以验证provider不漂移。不能使用public detachedfacts相等来替代这些检查，也不能为了重复export允许第二次resolve。

需要明确producer历史process语义：resolve checks的是token原始私有process／nonce／factrecord绑定及真实END close链，而不是无条件要求其等于owner当前 `_process`。close token可能在END/reap后、newREADY前产生；old command解析与end close的合法历史必须能被增量drain。正常reset前主动drain旧commands、reset后consumeclose/newREADY；independentreset或partialreset仍保留原process链、不能凭当前新process复活失败interval。

消费原子性：不能在存证前推进cursor到nextcursor；逐token已consume但日志append或后置guard失败必须保留已sealed prefix并永久incomplete，后续不可重试resolve同token治愈。批次中间失败保留明确最后committed factordinal及未完成pending，export可保存incomplete历史但拒任何新command／semantic资格。private `_resolve_fact`拒重复／foreigntoken是负例，不应触发正常validate／export路径。

新增测试至少包括：consume一次后连续两次validate／snapshot／completed_intervals／terminal export均成功且resolve callcount不再增长；opaque duplicate手动重解失败；oldprocess END→newREADY历史正常导出；缓存publiccopy mutation不污染authority；privatecache／registry／issuer/methodcode替换使后置guard拒；resolve成功后append failure或midbatch错误永久incomplete、不重新consume或授interval。所有mechanical Pythonworker仍False，不把consumer class exact检查本身当native eligible positive。

## 当前Task1落盘候选只读交接审查（未执行测试）

读取当前observer／session／GPIO代码，尚不能直接视为Task2安全交接完成：

1. `native_reset_observation.py` 的 `_resolve_fact` 仅按token identity找tuple、标consumed、返回JSON；保存的process／execution两项没有校验，未兑现original private process／nonce绑定。`_fact`可被直接调用追加caller dict并生成有效opaque token，没有actual origin guard；`_ready`／`_closed`同样缺actual producer frame约束，`_closed`还未要求传入process对应当前已知process记录。Task2不能靠equalJSON补验证或将其当native资格。
2. `validate`只pin四个registry容器对象，未pinregistry_token／issuer_token／consumed对象，也未校验same-length `_facts` tuple内容、JSON和private process table没有被替换。`_private_state`只给token＋len＋status，现状不足以区分同长度内容篡改；需producer不可替代的immutable seal/digest与实际authority mapping、或严格连续私有注册证明。consumer仍仅一次resolve后私有缓存，重复export不重新consume。
3. completeness路径已覆盖ACK前reserve、ACK／parse失败abort、parse seal后GPIO `_take`／direct read/write error独立incomplete，且parsed command保留，这是正确方向。但`validate`的pinned producer-method检查抛出与source/binary读OSError不走 `_fail`；恢复方法或文件后可能回complete。`_command_impl`的process.dead／poll异常在observer attempt前抛出，未标activeinterval incomplete。实施需对已启动provider的这些错误留永久failure事实，不为纯argument拒绝或容量preflight造effect claim。

这些为静态源码发现，未运行测试、未构造NativeResetEvidence实际issuer或伪造native-positive。具体RED应由Task1 owner／独立reviewer使用真实wire／lifecycle边界复现并修复，再冻结final契约；Task2源码仍未修改，不减少原计划privateauthority／completecommand需求。
