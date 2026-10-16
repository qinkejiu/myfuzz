# Declarative Register Alias Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Verify observed ordinary register SET/CLR behavior through versioned declarative relationships and private actual CPU before/write/after plus RAM evidence, including authenticated saved-file fresh replay.

**Architecture:** Extend the sidecar through an explicit versioned closed schema, preserving v1/v2 behavior. Generic verifier logic resolves the current declaration against actual target/profile/runtime bindings; no PULP/CPU names select core behavior. Saved documents are comparison data; fresh execution reconstructs current authority.

**Tech Stack:** Python dataclasses/closed JSON schemas, existing RV32I compiler, native passive APB observations, ScenarioSession, private ordinary-access and memory-commit registries, existing run identity and resource supervisor.

## Global Constraints

- Historical verifier-v3 actual gate terminated at the unchanged 180-second budget during authenticated save; its partial artifacts and frozen source identities remain preserved. Subsequent v5 export/cache gate passed generation, fresh replay and independent audit. This alias package has scoped software evidence; native alias generation Root74397 passed exit0/resourcecomplete164.01385019000736s. Separate fresh Root11283 passed exit0/resourcecomplete153.30511558598664s; final independent audit reviewer42535 passed terminal0 for the scoped four-bracket package.
- E1/E2/G8 requirements remain: declarative generic adaptation, complete mask/width/permission/reset scope eventually, no CPU/IP-name special cases and no claimed whole-stage completion.
- Keep absent/default-off assembly, Session schema16/17 and legacy v1/v2 sidecar behavior unchanged. Opt-in new sidecar version/channel content is explicitly authenticated.
- Keep proof scope `observed_cpu_register_readback_consistency`; no storage/version/prerequisite/functional grants. Scoped observed certificates do not grant whole-matrix verified L2.
- No commits/reset/worktrees or extra RTL during software implementation. Actual native gate follows production freeze and one supervised worker; preserve failures in separate directories. No repeated permission ceremony is required for the already-authorized work.

## Task 1: Versioned generic relationship declaration

**Owner:** Root (composition/data). **Files:** modify `src/myfuzz/composition/test_capability.py`; new `tests/composition/test_register_alias_capability.py`; update `configs/peripherals/pulp_gpio/test_capability.json` only after generic parser tests; extend existing GPIO reference tests.

**Interface:** Add an immutable `RegisterAliasRelation` to an explicitly new sidecar schema `ip_test_capability.v3`. Proposed closed row keys: `endpoint_id`, `source_register`, `source_field`, `destination_register`, `destination_field`, `operation`, `bus_width`, `evidence_ref`. `operation` is exactly `set_bits` or `clear_bits`; bus_width exactly32 for the initial production rule. v1/v2 construct an empty relationship tuple. Existing v2 requires its original feature_contract; v3 requires the v1 root fields plus register_aliases and permits an optional feature_contract, parsed through the unchanged strict feature rules when present. Absent feature_contract remains None, without inventing a plugin declaration. Loader continues `load_ip_test_capability(..., profile=profile)`; normalized capability exposes `.register_aliases` and includes the extension in its fingerprint.

- [x] Write RED: a differently named valid profile/sidecar with a closed declared relationship loads; current loader rejects unsupported v3. Actual 33 RED/2 compatibility PASS before implementation; first candidate relevant software 70 PASS, independent boundary review pending.
- [x] Write negative tests before implementation: unknown keys/version/operation; bool width; missing/foreign endpoint; duplicate source; conflicting relationship; identical/cyclic destination; source WO/effect mismatch; destination unreadable/effectful/incomplete/overlapping; mask or alignment/aperture mismatch. No silently clipped masks or unrequested alias RMW.
- [x] Implement generic resolution against current profile and full field semantics. Initial relation requires full32 source and full32 plain readable destination; do not invent narrow real alias declarations to widen scope.
- [x] Preserve v1/v2 old behavior/bytes and existing loader reference tests. Document that evidence_ref is declarative source provenance, never a callable/provider choice.
- [x] Add actual PULP v3 data: PADOUTSET.bits→PADOUT.value set_bits and PADOUTCLR.bits→PADOUT.value clear_bits using the pinned RTL revision/SHA and exact297–302/311–316/570–578 lines. Validate every SHA against actual source. No compiler/core PULP mapping.

Deliverable: source-bound generic typed relationship; missing relation remains unsupported.

## Task 2: Private bracket semantic verification

**Owner:** Renderer (verifier/actual evidence). **Files:** modify `src/myfuzz/scenario/register_program_verifier.py`; new `tests/scenario/test_register_alias_verifier.py`; extend private ordinary-access tests only if a demonstrable missing primitive requires it. Do not weaken causal providers.

**Interfaces:** Consume typed relationships from the current target-bound loaded sidecar; consume `OrdinaryApbAccessEvidence.completed_accesses()` and existing private `_issued_result` memory authority. Produce certificate rule `ordinary_register_alias_readback.v1`; the actual alias write is its association/observed_accesses. Closed result keys are alias_relation, before_readback_access, after_readback_access, before_result_commit, after_result_commit and expected_value. Selected READ/private RAM crosslinks are required; no saved authority restoration.

- [x] Meaningful RED: real software factory/CPU._serve/router/strict parsed native target generates before PADOUT read, alias write and after PADOUT read, actual issued RAM stores; current verifier reports unsupported_effect_rule. A generic renamed profile must produce the same rule without PULP checks.
- [x] Select exact ordered bracket on same target/endpoint/reset epoch/memory generation/CPU source epoch, increasing transaction sequence and actual requested register offset. Require the observed before response and after result; use actual write bus value. Compute OR or AND_NOT with explicit32-bit arithmetic and declaration mask.
- [x] Require actual source request/compiled bytes/admitted action plus private completed callback and raw/base refs. Require before and after READ case RAM evidence via actual private issuance/commit; saved/caller copies cannot fill missing proof.
- [ ] Complete original negative/behavior matrix (scoped software negatives passed as detailed below; full native reset/permission/mask scope still open): reject/leave honest gaps for missing before/after, wrong value, unrelated bits corruption, unknown declaration, foreign instance, different offset/endpoint, intervening same-target write (including aliases), reset/generation/source epoch change, unissued/wrong-address/wrong-value RAM commit, manipulated public ledger/sample/journal or detached authority replacement.
- [ ] Keep existing plain-write conservative invalidation. Bound bracket indexes/history; do not scan/copy full journal or entire configuration on every STEP. Add deterministic cost/callcount tests without caching saved authority.
- [x] Derive verified scoped field operation only from the actual certificate. Runtime support still describes executable declarations; whole72-field grade remains unverified/incomplete.

Deliverable: an actual observed alias certificate, not a host arithmetic oracle.

## Task 3: Closed saved certificate and snapshot validation

**Owner:** Root (pure validator), Renderer (Session export hook). **Files:** extend pure validator in `register_program_verifier.py` in coordinated nonoverlapping turns; new `tests/scenario/test_register_alias_saved_boundaries.py`; Session changes only if the existing wrapper cannot carry the new rule.

- [x] RED: valid actual new rule wrapper is rejected by the old closed schema; then accept it with exact fields.
- [x] Recompute relationship compatibility, before/write/after arithmetic, context equality, evidence ID and derived normalized per-target verified snapshots. Verify exact mask/width/types; bool/int substitutions must not compare equal.
- [x] Test self-consistently rehashed wrong relation/destination/effect, altered before or after values, foreign source key, forged result commit, altered grants and unsupported verified operation. Shape-valid saved claims never satisfy live permission.
- [x] Preserve wrapper schema `register_program_verifier_session.v1` where a closed new rule is sufficient; version the certificate/relationship explicitly if an incompatible structure is required. Preserve schema17 incomplete export and historical-only reset semantics.

Deliverable: saved comparison parsing is closed and self-consistent, without authority restoration.

## Task 4: Production authenticated save and fresh file replay

**Owner:** Runner agent (integration/CLI). **Files:** `src/myfuzz/integration/ibex_pulp_register_replay.py`, new `tests/integration/test_register_alias_replay.py`; `scripts/run_ibex_pulp_online.py` only if the existing full wrapper output needs explicit adaptation.

- [x] RED nonempty software production fixture: before/write/after original requests compile and execute through actual private objects, save authenticated schema16 bundle, then trusted selector fresh-recompiles the original requests and compares full trace/ordinary/verifier wrappers and field metadata.
- [x] Authenticated source closure includes loader/typed relationship/verifier/pure parser dependencies. No saved path selects code or provider. Default38/40 modes remain exact; current enabled closure reflects current source hashes.
- [x] Rehashed relationship/sidecar identity/report/certificate and RAM tampering fail before factory where structurally invalid, or fresh mismatch where valid comparison facts differ. Writer and selector must use the same closed checks before mkdir/factory.
- [x] Retain actual private READ+RAM nonempty assertions and no-DUT-oracle disclosure for software fixtures; include default-off compatibility and schema17 regression.

Deliverable: production saved-file replay proves current-source reconstruction rather than saved permission restoration.

## Task 5: Native directed gate and independent evidence

**Owner:** Root supervisor/gate; Runner independent artifact audit; Renderer independent interface review. **Files:** new `runs/stage2-e2-register-alias-verifier-20261012-v1/{check.py,supervise.py,fresh_cli.py}` and audit script; do not overwrite historical gates.

- [x] Freeze all production/data sources after software RED→GREEN and independent G8 review. Pin new sidecar/compiler/runtime/verifier/Session/integration/CLI/full source closure and scripts.
- [x] Native generation completed four brackets: SET0x80010000, repeat SET, CLR0x80000000, repeat CLR. Each bracket is READ PADOUT→safe RAM, explicitly permitted alias SW, READ PADOUT→different safe RAM. This is12cases/12CPU MMIO/36APB boundaries/8RAM commits, plus fixed bootstrap6associations/18APB:18total associations/54total APB. Values derive from actual before response, not assumed reset.
- [x] First repeat brackets preservedlow8; later zero/fullmask brackets used actualB.INTEN0 isolation withoutmaskclipping and passed generation/fresh/audit. Explicitreset/permission/full14/72coverage remains separatelyopen.
- [x] Scoped generation and production fresh CLI completed separate unchanged180second wall/RSS budgets under the one-worker lock. The recent14case verifier generation consumed all139s before export and timed out in save; estimate cost from measured final software/source snapshot, not a promise of combined180 success. Record phases so semantic failure and resource timeout are distinct.
- [x] Scoped four-bracket audit verified source pins and exact source SHA,9authenticated artifacts/envelope, all original manifests/source bytes, private association raw/base/source refs, actual before/write/after arithmetic,8RAM commits, actual scoped certificates/gaps,3cache input sets/binaries, full fresh wrappers/events/semantic, separate resource receipts. Fresh fulltrace storage limitation is disclosed if CLI only emits semantic/count/full state.

Deliverable: actual directed consistency evidence with explicit scope; no claim RFuzz/BFM/wholeE2/functional/complete verified L2.

## Task 6: Progress reconciliation

**Owner:** Root docs coordinator. Update E2/source audit/plan/progress and scripts README only after final audit. Record historical v1/v2 and new v3 sidecar SHA drift and historical gate scopes without rewriting old source pins. E1/E2 checkbox remains open for actual reset/permission/mask/width/effect completeness and capability-grade requirements. Link the generic alias relation and G8 software/actual evidence, along with failures and resource limits.

Interface correction after inspecting current code: v2 is already the strict feature-contract schema. Alias declarations use v3; widening old v2 or inventing a feature plugin merely to express an L2 relationship is prohibited. The existing v1 and v2 normalized bytes/fingerprints stay unchanged. Operation labels remain set_bits/clear_bits; their code-owned arithmetic is OR/AND_NOT. This is a plan/test correction only; current verifier-v3 gate production is frozen.

Current Task1 checkpoint: generic parser/assessment first candidate implemented; production sidecar remains v1. Exact selected source-field evidence equality is declaration consistency, not current-source authority. Independent endpoint/provenance/typed-drift boundaries are under review; Tasks2–5 remain unimplemented/unverified. v5 prior export/cache generation, fresh and independent audit passed; historical frozen pins remain historical after alias source edits.

Independent Task1 scoped review closed: 52 alias cases PASS (0.34s), no remaining scoped P1/P2; root broader relevant103 PASS/2 subtests (0.51s). Parser SHA d568fa1926af62896e3d186428d65f865eaf56b34f984eb09e9bf8a08a244b77. Production data migration, remaining negative/reset/permission matrix and actual verifier/save/native tasks remain open.

Task1 production data migrated and independently reviewed: parser8d325472...198e0, sidecar0cefc52e...efc1d, unchangedRTL1e271914...caef;114 software cases+2subtests PASS, independent79PASS. Declaration edges10 cover source permissions, overlap/cycle/alignment/aperture and physical conflict; full runtime/reset/permission scope remains open. Task2 initialsetup path failure not semanticRED; fixture corrected without factory relaxation.

Task2 fixture scope correction: initial actual render attempts rejected absolute temporary profile and unknown source-lock component ID; setup errors are not semantic RED. Current actual renamed fixture retains authenticated component ID and renames register/endpoint; a fully different actual component ID with a genuine temporary source-lock root remains required generic coverage. Task4 real software SET/CLR tests returned2actual RED in66.30s for unsupported_effect_rule after3private associations and2RAM commits passed; save/fresh branches not yet executed.


## Scoped software and native-running checklist (2026-10-12)

- [x] Actual SET/CLR before/write/after+private RAM software positives and scoped gaps: genuine73459 RED, earlier637 candidate positives/negatives; no host/saved authority.
- [x] Final037 closed pure24 and legacy2, production save/fullfresh2 software receipts:51.97s/49.21s/165.70s respectively.
- [x] Actual fully renamed generic CPU/private chain2 PASS35.07s on earlier637 candidate; final037 onlylegacy missingrelationship reason delta statically reviewed, NOT a finalgeneric rerun. Standalone real sourceartifact2 PASS.61s has separate parser scope.
- [x] Genuine actualSession warm/cold software lifecycle reset negative:35.08s/35.68s on037, realREADY/END/start/end/reap/epoch transitions and memorypolicy; no hand-built epochs or RTL-default claim.
- [x] Final source/data/gate freeze and supervised native launch Root74397 in new alias-v1 directory.
- [x] Native generation terminal0+resourcecomplete+authenticated full artifacts: Root74397,164.01385019000736s,1worker,RSS2355449856<3176628224;12cases/18confirmed/8RAM/25237events,4alias+8READcerts,gaps[].
- [x] Native separate fresh CLI full comparison and resourcecomplete: Root11283 exit0,153.30511558598664s,workers1,RSS2359955456<3156848640; separate180-second policy unchanged.
- [x] Independent final source/artifact/binary/raw/base/CPU/RAM/fullfresh audit: reviewer42535 terminal0/PASS, enriched audit saved; both generation/fresh resourcecomplete.
- [x] Remaining zero/fullmask native brackets completed with actualB.INTEN0 isolation; both native budgets and independentmask audit passed.
- [ ] Original native observable reset-default and permission/full register-field/effect completeness; entireStage2 remainsopen.


### Alias native generation 真实通过；fresh 运行中

Root74397监督器真实terminal0，resource status=complete：elapsed164.01385019000736秒，workers1，peak tree RSS2355449856 bytes < limit3176628224 bytes；原180秒wall/RSS policy保持。新alias-v1实际12selected cases、18confirmed ordinary associations（包含固定bootstrap）、8实际RAM commits、完整25237events；4alias+8READ certificates，gaps=[]。实际PADOUT前读与后读观察轨迹为0→0x80010000→同值→0x00010000→同值；按actualbefore值计算，不能将首次0解释为已认证reset default。

完整trace semantic `e744874aa3c1660c455f081713c9c77d406734156db92717a1136911420d1ae0`；authenticated run identity `8019be229437fb9b1784f7a0d6cca2d1aa8705246374fb7ed486fe62262c6c81`。generation成功已建立本次四SET/repeat/CLR/repeat区间的scoped实际证据与完整认证保存；全部source/scripts继续冻结至fresh/audit终态。Root11283正在运行独立fresh CLI（单独原180秒预算），最终独立artifact/fresh audit仍pending，当前不得记录fresh/audit通过。

完整Stage2/E1/E2仍开放，zero/fullmask的nativebrackets、native observable reset-default/permission及完整14register/72field/effect/等级矩阵未因此完成。证书仍为observed_cpu_register_readback_consistency，四类storage/version_dependency/prerequisites/functional grants=False；不授aggregate wholeL2、RFuzz或BFM执行资格。


### Alias separate native fresh 通过；最终独立审计待终态

Root11283真实terminal0，fresh resource status=complete：elapsed153.30511558598664秒，peak tree RSS2359955456 bytes < limit3156848640 bytes，workers1。generation164.01385019000736秒与本次独立fresh均在不变180秒wall/RSS policy内通过；不同available-derived limit是同一policy每次资源采样结果，不是放宽预算。通过范围仍是四SET/repeat/CLR/repeat brackets及对应12selected cases；fresh通过不新增zero/fullmask/reset-default/permission或wholematrix验证。

Reviewer现在执行完整JSON/artifact/source/raw/base/CPU/RAM/fresh独立审计，终态尚pending；本包最终completedcheckbox保持开放。生产与gate scripts冻结，不启动并发heavy audit/测试或生产编辑。完整原Stage2/E1/E2及zero/fullmask/native observable reset-default/permission/14register72field完整矩阵仍开放，不授storage/version_dependency/prerequisites/functional或wholeL2。


### Alias 四 bracket scoped package 最终独立审计通过

Reviewer42535完整native alias audit真实terminal0/PASS，补充审查报告已保存；generation164.01385019000736秒与fresh153.30511558598664秒两份resource均complete。独立审计确认本scope当前源/认证产物及实际CPU/raw/base/RAM/readback与fullfresh闭环；此前saved数据只比较，没有恢复authority。Task5四SET/repeat/CLR/repeat brackets及对应12cases包已完成，生产四Bracket来源仍由冻结identity8019be229437fb9b1784f7a0d6cca2d1aa8705246374fb7ed486fe62262c6c81标识。

完成只限已观察四bracket；完整Stage2/E1/E2及SET0/CLR0/SETffffffff/CLRffffffff的zero/fullmask原要求、native observable reset-default、permission/完整14register72field/effect与wholelevel矩阵继续开放。后续fullmask不得裁剪低8位冒通过，需核实际wiring/dir/IRQ/CPU状态并在独立新session/fresh门禁保留完整mask原请求。当前不授storage/version_dependency/prerequisites/functional或wholeL2，未执行下一scope。

## 下一 zero/fullmask scope：只读设计，尚未执行

实际wiring A=0x40001000、B=0x40000000。当前stream bootstrap先向B写GPIOEN/INTEN0x101、INTTYPE_LOW0x10001；再向A写DIR/GPIOEN0xff、PADOUT0。A.gpio_out低8直接绑定B.gpio_in，RTL gpio_out=r_gpio_out不受DIR门控，不能以DIR0假设隔离。CPU bootstrap显式mie.MEIE0x800/mstatus.MIE8，Bpin0 rising可能触发IRQ/ISR；ISR可写A.PADOUT，破坏bracket。现stock配置不能无证据宣称fullmask安全。

最小既有API方案是独立fresh新session先真实CPU向gpio_b.INTEN.value WRITE0并READ→实际safe RAM确认0。该字段当前sidecar full32/rw/none/ffffffff masks，走原compiler/runtime/source-gate/Session授权，不新增CSR ISA或provider。隔离后确认唯一actual B.irq→CPU.irq policy width4、state_document statusactive/source_level0/两source IDs None/两pulse bounds None、pendingFalse；Runner _pending_irq_pulses()=={}及_effective_inputs('cpu').irq0。每bracket期间实际CPU step inputs.irq和按artifact physical_observation_parameters解析的CPU external IRQ input、B interrupt output的pre/post raw samples均非空且0；对应raw refs/base projector绑定，禁source_start/pulse_start/irq_overrun/cpu_irq_input/cpu_irq_taken，不私自清pulse状态或用无ISR当mask证据。

然后A执行完整SET0、CLR0、SETffffffff、CLRffffffff四个READ→aliasWRITE→READ brackets，值由actualbefore响应计算，不clip低8，不假设reset值。计划14cases（2B隔离+12A）、9RAM（1BREAD+8AREAD）、20ordinary associations（A15/B5含bootstrap）、case42APB/total60APB、9READ+4alias+1plain-write certificates；这些都是预计断言，须未来实际receipt确认。保持分别180秒单worker/RSS policy，资源margin需真实测，不预授通过。当前只设计，Root审查后才新执行；native reset-default、permission与完整matrix仍分别开放。


### 下一 zero/fullmask native generation：running，尚未验收

Root50928在四脚本审查/冻结与hash核对后启动新mask generation，source verifier037不变、原180秒wall/RSS与singleworker policy保持。前三份已审计且匹配currentbuild的cache复制到本次独立cache目录，binaries核对；旧cache/产物不改，production仍严格验证所有current source/build inputs，不把复制cache当作跳验授权。本次不是empty-cache冷构建，不与先前冷构建耗时混称。

计划14cases：B.INTEN实际WRITE0/READ0/privateRAM与真实IRQ quiet/pulse drained，然后A完整SET0、CLR0、SETffffffff、CLRffffffff四brackets。预计20ordinary associations、9实际RAM commits、total60APB；这些数字目前仅expected，尚不作为已观察结果。完整mask不裁剪低8，隔离不依赖DIR或reset默认假设。当前仅native generation running；zero/fullmask原验收仍pending，须真正generation→separatefresh→independentaudit receipts闭合，不根据启动/软件/缓存复用提前勾选。

所有source/scripts持续冻结，不执行并发测试/大JSON审计，不更改生产或预算。native observable reset-default/permission/full14register72field/effect/wholelevel矩阵及完整Stage2仍开放；四个先前SET/repeat/CLR/repeat审计通过的范围保持历史，不代替本次新mask范围。

- [x] New zero/fullmask native generation actual terminal0/resourcecomplete/authenticated artifacts: Root50928 complete152.13179933300125s,1worker,RSS2590924800<3251445760;actual14cases20confirmed9RAM28995events/4alias9READ1plaincert/gaps[].
- [x] New zero/fullmask separate fresh: Root85373 terminal0/resourcecomplete166.55756382399704s,1worker,RSS2641014784<3242532864;independent180-secondpolicy unchanged.
- [x] New zero/fullmask independent complete audit: reviewer55204+enrichment terminal0/PASS,283pins9artifacts14exact28995events20associations60APB9RAM14seals14certs13IRQquietsnapshots/CPU+B1152raweach/3currentcaches/fullfresh; new receipts establish this scope.


### Zero/fullmask native generation 真实通过；fresh 运行中

Root50928真实terminal0，resource complete：elapsed152.13179933300125秒、workers1、peak tree RSS2590924800 bytes < limit3251445760 bytes，原180秒policy保持。本次实际14cases、20confirmed associations、9RAM commits、完整28995events；4alias+9READ+1plain-write certificates，gaps=[]。B.INTEN实际WRITE0/READ0隔离确认，13次IRQ quiet snapshots的实际CPU/B physical值均0，无裁剪mask或DIR/reset默认假设。

实际四bracket观察：SET0为0→0；CLR0为0→0；SETffffffff为0→ffffffff；CLRffffffff为ffffffff→0。输入fullword及untouched/noop关系由actual CPU/APB/issuedRAM链确认，不由host预置result值代替。trace semantic `7f1ea66fd9c05f9592ed49be66c7bf03e2f519b91ad35c9d6c5242b6730664c1`；authenticated identity `974ffd0d7967cdb04cdee6e4acc03f47834cf93e362258347dcb04687097ad18`。

本次zero/fullmask generation成功，separatefresh Root85373正在原独立180秒budget执行；最终independentaudit尚pending，因此zero/fullmask完整验收未关闭。生产/source/scripts保持冻结，不执行heavyJSON/并发测试，不改历史receipt。native observable reset-default、permission/full14register72field/effect/wholelevel矩阵及完整Stage2仍开放；无storage/version_dependency/prerequisites/functional或wholeL2授证。


### Zero/fullmask separate native fresh 真实通过；最终审计运行中

Root85373真实terminal0，resource complete：elapsed166.55756382399704秒，workers1，peak tree RSS2641014784 bytes < limit3242532864 bytes；generation152.13179933300125秒与本次fresh均在不变180秒wall/RSS policy内通过。范围仍为真实B.INTEN隔离后SET0/CLR0/SETffffffff/CLRffffffff完整四brackets及14cases，没有clipping低8。Reviewer独占执行完整大型JSON/artifact/fresh审计，终态pending；本mask package completedcheckbox仍开放。

源码/scripts继续冻结，无并发heavy任务或生产修改。Native observable reset-default、permission/完整register-field/effect矩阵与整个Stage2仍开放，原grant边界不变。


## 下一 native observable reset：只读接线结论与版本化设计

现Session.reset保存reset_operations的{after_cases,policy}，register fresh每case提交后重放reset，下一项立即adapter.prepare。GeneratedCve2Session.reset_local实际清_pending_instr/_waiting_instr/_request_evidence/_sequences并通过真实end/begin回bootstrap；Runtime._context要求当前真实waiting transaction在declared未materialized online slot。Session.advance_initial仅_cases为空可用；case.advances位于sourceadmission之后，不能先推进到compile-required waiting。没有合法记录/回放post-reset scheduler前缀的生产API；直接runner.step_batch或手造waiting/epoch不满足savedfresh。软件RESETfixture的真实_serve(nextslot)仅机械source/qualification边界，不能当nativebootstrap/resume接线已完成。

Warm memory保留旧SOURCE program，真实bootstrap后会重执行旧片段至下一缺word；必须观察全部旧GPIO/APB/IRQ/RAM副作用，不能跳过旧程序。Cold仅reapply INITIAL_IMAGE，firstonline重新unmaterialized；LiveMemoryEffectTracker在actualresetbarrier清slots/提升epoch与retirefloor，新unique action可通过原register_instruction_slot将reservation绑定currentgeneration，不是复活旧proof。现API支持末case后reset再finish/fullfresh，能验证机械reset和history/current隔离，但没有postreset READ/default证据。

下一方案明确采用版本化closed complete18/incomplete19，仅实际使用新的recorded resume commands时选用；旧16/17布局/字节及resetrow双keys默认不变，不通过unversioned optionalkey暗中放宽。拟Session.advance_after_reset(schedule)只允许最后actualrecordedreset后的非terminal阶段、无active/prepared submission，执行现source/observer/verifier守卫与真实runner.step_batch，记录有限commandtimeline与epoch/caseboundary，再fresh同序reset→resume→actualprepare/recompile。具体18/19字段/容量/命令引用与sourceclosure待实现前定稿。失败必须halt并拒export，除非另有明确closedterminal codec；不能把scheduler failure强写runtime.uncertain或伪成完整计划，不发明原计划未要求的actualfault验收。

Reset语义资格还需独立actual SourceCryptoReset/startup descriptor：当前driver_renderer822–835在reset assert/release tick(dut,nullptr)后READY携actualartifact digest及assert/release ticks；GeneratedLocalSession.begin_case严格parse_driver_ready却未保存私有startup receipt。reset_barrier/保存epoch整数不自动成为native观察证明。新seal必须从真实current build/source/binary与actualparse/lifecycle原对象产生、私有immutable记录，fresh重新生成；saved descriptor仅比较，不注册authority。CPU sourceMetadata、artifact/resetroles/context与后续CPU/APB/privateRAM链需精确绑定，软件READY/END worker不能冒native crypto reset proof。

最小稳定字段候选是A.INTEN.value：实际bootstrapA写DIR/GPIOEN/PADOUT、B写GPIOEN/INTEN/INTTYPE_LOW；ISR只读B.PADIN/INTSTATUS并写A.PADOUT，不写A.INTEN。A.PADDIR/PADOUT/GPIOEN及B已配置字段的postboot值不能自动授reset-default；需read-before-write新固定selector或严格不同观察窗口才能覆盖。现ordinaryREAD certificate只证明raw→CPU→RAM一致，不比较reset_value；新reset-default rule还需actualresetseal、nointervening target/alias/internal/environment write区间及actualREAD/privateissuedRAM==source-bound declaredreset_value。Conditionalreadclear/PADIN保持保守gaps，不授storage/version/prereq/functional或wholeL2。

本节仅下一原E2实施细化，未实现/未测试/未执行native。当前mask source/scripts冻结保持，mask最终审计及完整Stage2范围不被此设计提前关闭。


### Zero/fullmask scoped native 包：最终独立审计通过

Reviewer55204及enrichment真实terminal0/PASS，完整独立mask报告已保存。审计核对283 current source pins、9 authenticated artifacts、14 exact requests/cases、完整28995events、20ordinary associations、60APB boundaries、9RAM commits、14completed seals/14certificates、13IRQ quiet snapshots，以及隔离后CPU与B各1152条actual raw zero samples、3current cache/binaries、完整phases/budgets/fullfresh。generation152.13179933300125秒与fresh166.55756382399704秒resource均complete，原180秒singleworker/RSS policy未改。

真实B.INTEN0隔离后的SET0/CLR0/SETffffffff/CLRffffffff四bracket scoped generation→authenticated save→trusted fullfresh→independent audit已闭合；完整mask不裁剪，IRQquiet由实际输入/输出/脉冲state及raw关联验证，不据无ISR推断。当前source verifier037与sidecar/RTL源身份保持本包冻结证据；后续源码改动须形成新scope，历史产物不改。

原Stage2/E1/E2未完成：native observable reset-default、permission/完整14register72field/effect/wholelevel矩阵仍开放，不授storage/version_dependency/prerequisites/functional或aggregate wholeL2。下一reset-resume由Root另写dedicated实施计划；只有使用resume flag/commands才新complete18/incomplete19，旧16/17不放宽。recorded真实scheduler前缀及fresh重算与actual resetseal/defaultcertificate分阶段，后者不能借本mask包提前授证。此时未实现/未执行下一resetnative范围。
