# Compiled F6 CPU-programmed RAM Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. The user approved the specification and parallel execution; do not ask for another execution choice or approval.

**Goal:** Execute the approved four-word CPU-programmed RAM→RAM F6 contract through persistent native DMA, IRQ/ISR, full fresh verification and the explicit unified RFuzz entry.

**Architecture:** Add independent versioned F6 contract, firmware/layout, consumer, runtime and transport/report modules. Reuse exact generated artifacts, shared persistent RAM, per-initiator services, existing live route binding and transport; add only a sealed pre-effect response fault seam and narrowly authenticated fixed-ISR MRET issuer to low-level sessions.

**Tech Stack:** Python, existing ScenarioSession/Runner/Router, RV32I OBI Ibex native RVFI/IRQ provider, registered ZipCPU Wishbone DMA, MemoryService, RFuzz and Verilator.

## Global Constraints

- Authority: the user's approved original `docs/superpowers/specs/2026-10-24-compiled-f6-cpu-programmed-ram-design.md` SHA is `d8b0d1666d548f7c70eff7416e559d5124412a252661b310a703d45cbcd172db`. Current full spec revision SHA `05fdde2ed930eeef42979ff512beb2a0bc1a46e7c97b8aa945e030a771ac7e41` includes the independently source-reviewed registered Ibex IRQ-entry/MRET/successor evidence chain and the Task8 implementation note that the fixed ISR waits for the real `mip.MEIP[11]` input to fall before terminal store/MRET. This preserves the approved workload, 16-tick pulse, and capability scope; the changed fixed-image manifest and native behavior remain subject to code review and a new frozen gate. Do not restore the unverified `pc_wdata` target assumption.
- F2 final frozen gates and documentation closure passed. Preserve their historical immutable inputs/attempts. New F6 work stays in the shared dirty predecessor workspace rooted at commit4186ff5; no HEAD-only worktree,stage,commit,reset or clean. Replace each skill commit step with scoped diff,baseline/current hashes,RED/GREEN logs and independent Spec/Quality review.
- Wire8 little-endian: four11-bit values in bits0..43,reserved bits44..63 zero,values0..0x7ff,pairwise distinct. One record/test;2..200 refuse wholly;common parser retains200 bound. No normalization or clipping. Legal declared seed is required;zero seed is invalid.
- Only four CPU ADDI source operands vary. Addresses,count4,block4,BE15,key0xfed,increment modes,CSR offsets0/4/8/12,IRQ wiring and fixed code remain bound. CPU performs source writes and DMA programming;host never supplies source data,PRDATA,successful IRQ or native output.
- Fixed256B slots,128B online whitelist prefix,1..16 slots;mutable ADDI indices10/12/14/16. Boot/ISR/control islands are immutable preloads. BNE/JAL/CSR/MRET never widen the online RV32I whitelist. x1/x2/x4/x5/x11 preserved;x10 success1/error2;ISR may clobber x3/x6..x9.
- Exact shared PersistentMemory;existing CPU.service and DMA.memory_service retain distinct actual services/ledgers/seals. Complete owner/execution/case/epoch/channel/sequence identity is mandatory;local event IDs are not globally unique.
- Native take uses registered `verify_ibex_irq_receipt_artifact` and its source/profile guard. Fixed16 target-local-tick IrqPulseDelivery expires independently of take. No universal OBI IRQ/RVFI claim or new component-name selector branch.
- Exactly five expectations: protocol_checker.receipt_violations,cross_component.declared_edge_hops,dma.cpu_configuration,dma.word_transfer_join,dma.irq_isr_completion. Admitted cases preserve passed/failed/missing;preflight refusal creates no case. Failed/partial test feedback is zero.
- Sealed expected ERR selector is(case_index,operation,word_index),one shot,after native route admission/before target callback;target_effect=false. Continue bounded native error IRQ/ISR/MRET/current-island observation before stopping. Separate failed_prefix_full fresh;never certify it as successful full.
- Original/fresh actual raw,build/exe/READY/PID/nonce/reap,typed inventory and first-byte pins must join same-call D2/D3/artifact identities. No authority from saved JSON. Native work uses one heavy lock;no native/build jobs during source edits.
- Development evidence: `.superpowers/sdd/compiled-f6-20261024/`; final evidence: `docs/reports/evidence/compiled-f6-cpu-programmed-ram-20261024/`. New attempts only. No RAM→IP/FIFO/general CPU/P6/P7-E/P8/system-completion claims.

## Ownership, execution order and actual reuse

Task1 owns compiler/contract;Task2 owns pure layout/firmware;Task3 owns DMA ERR low-level changes;Task4 owns CPU MRET low-level changes. Task1 andTask3 can start in parallel. Task2 andTask4 have disjoint files and can proceed after their contract inputs are clear. Task5 follows1–4;Task6 integrates them;Task7 owns shared entry/finalizer wiring;Task8 freezes and accepts the complete candidate. Each task ends with independent source/evidence review;resolve concrete findings before dependents consume it.

Existing APIs (not new promises): `compile_paths(request)`, `load_path_compile_request(...)`; `prepare_dma_intent_binding(wiring,prepared,*,route_links)`; `bind_dma_intent_topology(declaration,runner,*,artifact_links,path_ids=None)`; `DmaMasterRouteAdmission(policy,bound,*,path_id,read_route,write_route)`; `ScenarioSession.configure_runtime_paths(...)`,declare_instruction_slots,begin,submit_case,encode_plan,finish; `GeneratedWishboneDmaScenarioSession`; CPU native parsed POST RVFI capture at cpu_session.py:328–390. All F6 APIs below are NEW unless named in this paragraph.

## Task 1: Versioned static contract, compiler marker and source admission

**Files:** create `src/myfuzz/scenario/f6_execution_contract.py`, `src/myfuzz/local_harness/wbdmac_source_contract.py`, `tests/integration/test_compiled_f6_contract.py`; modify `src/myfuzz/scenario/compiled_paths.py`, `src/myfuzz/local_harness/generated_execution_admission.py`. Do not modify layout,CPU or DMA session files.

**Interfaces:** new `F6ContractRefused(code,pointer,detail=None)`; `compile_f6_execution_contract(request,*,base_dir)->dict`; `validate_f6_execution_contract(document,*,request,base_dir)->dict`; `assess_compiled_f6_support(*,artifacts,compiled_inputs,base_dir)->dict`. The closed D3 marker is `f6_execution={schema_version:'compiled_F6_cpu_dma_contract.v1',seed,program}`; `program` contains exactly `boot_address,isr_address,park_address,slot_base,slot_count,source_address,destination_address,result_base`, with all windows checked against actual wiring resources and pairwise nonoverlap/capacity. `seed` is the one D3-declared four-value legal candidate seed and is the only origin used for raw8 and four operand source declarations. Output schema is compiled_F6_cpu_dma_contract.v1 with exactly the approved spec§4 top-level fields. `candidate_layout` closes `wire_bytes=8`, `record_limit=1`, reserved-zero mask, distinctness, seed raw/words and exactly four source entries `{source_id,bit_offset,width,mask,register,instruction_offset}`. `program_contract` closes the eight program fields, `slot_bytes=256`, `online_prefix_bytes=128`, `result_stride=24`, `operand_instruction_offsets=[40,48,56,64]`, `instruction_source_id`, and the `initial_image` canonical sparse segment manifest plus `initial_image_sha256`. Only Task2's pure firmware builder may issue that manifest/hash; the compiler may consume its result but not duplicate the encoder. Any in-memory placeholder used during manifest construction must be resolved before output; the final contract validator rejects an empty manifest or missing digest. Add the marker only as an explicit versioned request field;it selects this contract,never an import/factory. No marker preserves existing unsupported F6 behavior.

- [ ] **RED:** source-backed existing Ibex RVFI/ZipCPU profiles,real generated D2 and explicit wiring;tests never construct a native session. Require four distinct operand sources derived from the marker's one D3-declared seed,exact registered IRQ/provider and CSR RTL digests,permissions,nonoverlap,route/physical endpoint mappings and firmware-builder image manifest/hash. Mutate each marker/seed/source/IRQ/template/route/profile field;assert code/pointer refusal. Old Caliptra static result remains unchanged.

```python
def test_no_marker_does_not_admit_f6(source_inputs):
    request, compiled, artifacts = source_inputs
    assert next(p for p in compiled['paths'] if p['flow_id']=='F6')['status']=='unsupported'
    bad = dict(request, f6_execution={'schema_version':'wrong'})
    with pytest.raises(F6ContractRefused) as caught:
        compile_f6_execution_contract(bad, base_dir=ROOT)
    assert caught.value.pointer == '/f6_execution/schema_version'
```

- [ ] **Run RED:** `PYTHONPATH=src:. python3 -m pytest -q -ra tests/integration/test_compiled_f6_contract.py`;retain missing-module/contract failures before implementation.
- [ ] **Implement:** closed-key validation;source-contract provider pins actual wbdmac RTL/parameters,CSR write/readback semantics,key/count/block encoding,word-address conversion and native IRQ. Match registered source/template shapes,not logical names. Recompile full D3 equality before admission. `_evaluate_f6` calls the new pure builder only for the explicit marker;emit the new graph/sources/expectation IDs while unmarked paths retain static refusal. Public factory adds explicit `compiled_f6_cpu_dma_ram` only after Task6 supplies its runtime.

```python
def require_exact(recomputed, supplied, *, pointer):
    if json.dumps(recomputed,sort_keys=True,allow_nan=False) != json.dumps(supplied,sort_keys=True,allow_nan=False):
        raise F6ContractRefused('contract-drift', pointer)
    return deepcopy(recomputed)
```

- [ ] **GREEN:** `PYTHONPATH=src:. python3 -m pytest -q -ra tests/integration/test_compiled_f6_contract.py tests/scenario/test_compiled_paths.py tests/scenario/test_dma_intent_topology_binding.py`. Include actual source-backed rename and incompatible same-protocol source/IRQ negatives. No native authority claim.
- [ ] Archive task1 baseline/diff/hashes/logs and independent review. Task1 reviewer verifies unchanged old F2/F4/Caliptra behavior and deterministic closed marker selection.

## Task 2: Raw44 layout, canonical whitelist prefix and immutable firmware

**Files:** create `src/myfuzz/integration/compiled_f6_layout.py`, `src/myfuzz/integration/compiled_f6_firmware.py`, `tests/integration/test_compiled_f6_layout.py`, `tests/integration/test_compiled_f6_firmware.py`. No shared compiler/session changes.

**Interfaces:** frozen `F6Candidate(raw:bytes,words:tuple[int,int,int,int])`; `compile_f6_candidate_layout(path)->F6Layout`;layout.decode(raw)->F6Candidate,layout.document()->dict; `f6_seed_record(path)->bytes`; `build_f6_firmware(contract)->F6Firmware`;firmware.initial_images->dict[int,bytes] containing only exact sparse immutable segments, `initial_segment_manifest` as a canonical address/length/hash sequence, `manifest_sha256`, `instruction_slots->tuple[(address,count)]`, `prefix(candidate,*,case_index)->bytes`,document()->dict. Contract owns all addresses/slot counts;no factory constants become hidden defaults. Hash the sorted segment manifest without synthesizing zero-filled gaps.

- [ ] **RED:** round-trip bit boundaries,high20 refusal,duplicate refusal,wrong widths/bools,seed source;prefix length128,only four ADDI imm[10:0] differ;exact fixed opcodes/registers/addresses/config order. Immutable images do not overlap reserved prefixes. Instantiate the actual `PersistentMemory`, preload only manifest segments, reserve prefixes, and assert each byte of the first online prefix remains unmaterialized (`initialized_bytes` equals the exact segment-byte sum). Software emulator covers successful MRET/control-island nextslot and error x10=2 current-island behavior without claiming RTL evidence.

```python
def test_only_four_declared_immediates_change(layout, firmware):
    a = layout.decode(sum(v << (11*i) for i,v in enumerate((1,2,3,4))).to_bytes(8,'little'))
    b = layout.decode(sum(v << (11*i) for i,v in enumerate((5,6,7,8))).to_bytes(8,'little'))
    x,y=firmware.prefix(a,case_index=0),firmware.prefix(b,case_index=0)
    assert len(x)==len(y)==128
    changed=[i for i in range(32) if x[4*i:4*i+4]!=y[4*i:4*i+4]]
    assert changed==[10,12,14,16]
```

- [ ] **Run RED:** `PYTHONPATH=src:. python3 -m pytest -q -ra tests/integration/test_compiled_f6_layout.py tests/integration/test_compiled_f6_firmware.py`.
- [ ] **Implement core encoding:** `words=tuple((int.from_bytes(raw,'little')>>(11*i))&0x7ff for i in range(4))`;reject `len(raw)!=8`,integer>>44 nonzero or len(set(words))!=4. Build exact32-word prefix:8 pointer words,clearx10/setx11,8 operand/store words,fixed DMA CSR programming sequence,NOP padding. Initial images contain fixed boot,ISR,each control island and park only as separate sparse segments;never preload a flat image across an online prefix. Use signed-low adjusted LUI/ADDI for arbitrary admitted32-bit addresses. Call existing online instruction validator on every prefix. ISR preserves pointer/comparison registers;normal and error branches implement the approved distinct terminal stores/MRET.
- [ ] **GREEN:** rerun both new modules;archive actual selection and refusal outcomes. Negative controls include altered fixed branch/MRET/preload hash,slot overlap/exhaustion,attempted overwrite and mutated nonoperand byte. Tests call the actual existing `validate_instruction_bytes` on every generated prefix.
- [ ] Archive task2 receipts and independent review;do not claim continuous native execution from emulator tests.

## Task 3: Sealed one-shot pre-effect native DMA ERR seam

**Files:** create `src/myfuzz/local_harness/f6_dma_response_fault.py`, `tests/integration/test_compiled_f6_response_fault.py`; modify ONLY `src/myfuzz/local_harness/wishbone_dma_session.py` for the hook. This task can run parallel to Task1.

**Interfaces:** frozen `F6ResponseFaultDeclaration(case_index:int,operation:str,word_index:int)` with document();new `install_f6_response_fault(session,*,declaration,execution_binding_sha256)->F6ResponseFault`;fault.begin_case(index),fault.select(key,*,operation,word_index)->bool,fault.document()->dict. Installation is prestartup/once-only and validates original generated DMA methods and closed declaration;no arbitrary callback or mutable factory. Ordinary runtime passes no declaration and has no fault authority.

- [ ] **RED:** feed explicitly synthetic parsed DMA receipts into actual step path with software service spy. Assert route admission occurs before selected ERR;selected callback never runs,no ReadSnapshot/commit,one typed ledger error receipt,target_effect=false,one-shot key record. Unselected beat unchanged;wrong key/case/op/index/reinstall/poststartup/method drift refuses. Fresh logical selector hits a different actual execution key.

```python
def test_fault_precedes_target_effect(native_dma_double):
    dma, service, admission = native_dma_double
    install_f6_response_fault(dma, declaration=F6ResponseFaultDeclaration(0,'write',2),
                             execution_binding_sha256='a'*64)
    dma.step_local()
    assert admission.accepted_keys
    assert service.write_calls == []
    assert dma.events[-1]['environment_error_receipt']['target_effect'] is False
```

- [ ] **Run RED:** `PYTHONPATH=src:. python3 -m pytest -q -ra tests/integration/test_compiled_f6_response_fault.py`.
- [ ] **Implement order:** actual native accepted PRE→full key→existing route admission→sealed selector→ledger.execute_once(error payload)→skip service callback→native pending ERR. Unselected path retains existing callback/admission completion behavior. Selected error completion is delivered to the new F6 policy as error1;do not silently invoke its successful completed(error0) branch. Retain all prior effects and raw response chronology.
- [ ] **GREEN:** `PYTHONPATH=src:. python3 -m pytest -q -ra tests/integration/test_compiled_f6_response_fault.py tests/local_harness/test_wishbone_dma_session.py tests/local_harness/test_wishbone_dma_error_recovery.py tests/local_harness/test_wishbone_dma_target_provider.py`. Check old invalid-resource ERR and normal native response timing unchanged;no native launch.
- [ ] Archive task3 baseline/diff/hash/RED/GREEN and independent review of the actual before-effect ordering.

## Task 4: Source-authenticated narrow fixed-ISR MRET issuer

**Files:** create `src/myfuzz/scenario/native_f6_isr_return.py`, `tests/integration/test_compiled_f6_isr_return.py`; modify ONLY `src/myfuzz/local_harness/cpu_session.py` to invoke the issuer from actual native RVFI receipt capture. No DMA/session-runtime edits.

**Interfaces:** `install_f6_isr_return(session,*,contract,execution_binding_sha256)->F6IsrReturnIssuer` takes the complete validated `compiled_F6_cpu_dma_contract.v1`,not a caller-selected nested program fragment; it rebuilds the canonical `F6Firmware` and verifies its fixed ISR bytes, exactly the two approved success/error MRET sites, and manifest against the contract before installing. `issuer.begin_case(case_id,*,case_index,irq_take_key)`, `issuer.document()`, `issuer.events`. Issuance is invoked privately from the original `_retire` parsed actual POST-RVFI path,not a public method accepting arbitrary event dicts. Emitted schema native_f6_isr_return.v1 binds take→first ISR-entry retirement→fixed MRET→immediate architectural successor through original parsed receipts, process/epoch/order, ISR hash and current case. The entry retirement's nonzero serial joins the take decision; MRET's own sideband retirement serial must be the observed zero.

- [ ] **RED:** actual source-backed registered Ibex artifact contract plus synthetic parsed DriverReceipt harness. Refuse wrong provider/ISR bytes/PC/insn/epoch/receipt order/duplicate take/cross-case/forged issuer, missing/mismatched first handler entry, stale invalid-cycle fields, missing or nonconsecutive MRET successor, debug/trap/intr diversion, and mismatched/error instruction response. A generic cpu_retire dict cannot issue authority. Require actual MRET0x30200073 at either canonical site, then first subsequent valid retirement at exactly MRET order+1 with aligned `pc_rdata` inside the current case's allowed prefix/control-island region. Preserve raw MRET `pc_wdata` without treating it as the ERET target; record return target from the source-verified successor `pc_rdata`, with both receipts/orders and explicit inference label. Match the successor to an actual error-free native instruction response; the runtime binding later verifies its bytes against the canonical prefix/preload.

```python
def test_saved_retire_json_cannot_issue_return(issuer):
    assert not callable(getattr(issuer,'observe_saved_event',None))
    with pytest.raises(ValueError):
        issuer.begin_case('run:1',case_index=1,irq_take_key=('wrong',0,1))
```

- [ ] **Run RED:** `PYTHONPATH=src:. python3 -m pytest -q -ra tests/integration/test_compiled_f6_isr_return.py`.
- [ ] **Implement:** preserve existing `_native_retirement_receipt` actual DriverReceipt/POST44-field/last-native-IRQ verification. New issuer consumes that original callback only,validates registered source and rebuilt fixed ISR,joins the actual take decision serial to the first valid `rvfi_intr` retirement at ISR entry, retains the fixed MRET pending, then consumes only the immediately next valid retirement (`order == MRET order + 1`) as actual resumed-PC evidence. Check original receipt sequence/tick continuity across the chain, no new take/trap/handler entry/debug diversion/scope change, and source-matched error-free native instruction response for the successor. Record MRET retirement serial as the observed zero; preserve raw MRET `pc_wdata` and derive the returned PC from successor `pc_rdata` only. Current CPU type/profile guard stays inside registered provider;F6 selects provider contract,not component name. No broad RVFI retirement permission is added.
- [ ] **GREEN:** `PYTHONPATH=src:. python3 -m pytest -q -ra tests/integration/test_compiled_f6_isr_return.py tests/local_harness/test_cpu_native_irq_receipt.py tests/local_harness/test_cpu_native_retirement_receipt.py tests/scenario/test_retirement_delivery.py`. Verify installer absent leaves existing CPU output/identity unchanged.
- [ ] Archive task4 source/synthetic boundary and review. Only later frozen native MRET evidence accepts real ISR return.

## Task 5: Multiword route policy, actual consumer and five typed outcomes

**Files:** create `src/myfuzz/scenario/f6_ram_dma_policy.py`, `src/myfuzz/scenario/f6_assertion_evidence.py`, `src/myfuzz/integration/compiled_f6_consumer.py`, `tests/integration/test_compiled_f6_consumer.py`, `tests/integration/test_compiled_f6_assertion_evidence.py`, `tests/integration/f6_compiled_support.py`. Modify `src/myfuzz/scenario/memory_service.py` and `src/myfuzz/local_harness/wishbone_dma_session.py` ONLY if the new actual-issued DMA read bridge is necessary;Task3 owner hands off first. Never treat ordinary unarmed snapshots as already issued native authority.

**Interfaces:** `F6RamDmaPolicy(contract)` implements identity_document/state/begin_case/accepted/completed required by existing DmaMasterRouteAdmission;`begin_transfer(*,case_id,source_versions,fault=None)`;`capture_f6_case(runtime,attempt)->dict`;`build_f6_assertion_material(runtime)->dict` returns independent assertions/assertion_evidence;`validate_f6_assertion_evidence(document,*,execution_binding,case_inventory)->dict` enforces the exact five expectation rows and complete compiled/binding/path/run/case scope without upgrading saved JSON into live authority;`f6_case_feedback(material,*,case_ids)->bytes` yields five conjunction targets,all zero unless complete. Evidence snapshot issuer is NEW: original native DMA accepted-read callback arms actual MemoryService issuance and retains an opaque service-owned handle;consumer validates handle identity,not reconstructed JSON.

- [x] **RED:** real contract/firmware fixture with marked synthetic native journal;four-read/four-write source-version/transaction/BE/order associations. Corrupt one of every configuration write,snapshot owner/key/version,route,response,commit,IRQ,take,MRET/return/result edge. Missing becomes missing,contradiction failed,no borrowed reference passes;partial case vector zero. Duplicate commit/read response refuses;expected ERR retains prior effects without four-word certificate.

```python
def test_missing_word_never_credits_other_words(consumer_case):
    runtime, attempt = consumer_case
    runtime.observer_view = [e for e in runtime.observer_view
                             if e.get('event_id') != attempt['word_commits'][2]]
    material=capture_f6_case(runtime,attempt)
    assert material['observations']['dma.word_transfer_join']['status']=='missing'
    assert f6_case_feedback(material,case_ids=(attempt['case_id'],))==bytes(5)
```

- [x] **Run RED:** `PYTHONPATH=src:. python3 -m pytest -q -ra tests/integration/test_compiled_f6_consumer.py tests/integration/test_compiled_f6_assertion_evidence.py`.
- [x] **Implement:** index composite owner/key/raw references;join installed candidate operands→actual CPU source/config writes→actual route admissions→issued per-byte read snapshots→ordered destination writes/commits→native responses→IRQ delivery/take→sealed MRET→CPU ISR status/readback/result stores→next fetch or error-current-island. Preserve immutable independent inventory and all five expected rows for every admitted attempt. Under expected ERR,allow error state to reach native terminal;never recast unknown checker/host exceptions as clean input refusal.
- [x] **GREEN:** `PYTHONPATH=src:. python3 -m pytest -q -ra tests/integration/test_compiled_f6_consumer.py tests/integration/test_compiled_f6_assertion_evidence.py tests/integration/test_compiled_f6_contract.py tests/integration/test_compiled_f6_layout.py tests/integration/test_compiled_f6_firmware.py tests/integration/test_compiled_f6_response_fault.py tests/integration/test_compiled_f6_isr_return.py tests/scenario/test_compiled_assertion_results.py`. Reviewer examines all word joins/issuer boundaries,not only matching data values.
- [x] Archive task5 diff/hashes/examples/review,including a real-shaped multiword saved example explicitly labeled synthetic.

## Task 6: Same-call persistent F6 runtime and complete fresh/error replay

**Files:** create `src/myfuzz/integration/compiled_f6.py`, `src/myfuzz/integration/compiled_f6_runtime_path.py`, `src/myfuzz/integration/compiled_f6_build_join.py`, `src/myfuzz/scenario/f6_execution_binding.py`, `tests/integration/test_compiled_f6_runtime.py`, `tests/integration/test_compiled_f6_execution_binding.py`;modify `src/myfuzz/scenario/session_runtime.py` and `src/myfuzz/scenario/runner.py` only for explicit F6 setup/replay/issuer forwarding not available through existing APIs. **Task6 scope amendment:** add a controlled DMA-only logical testcase transition on the original running DMA session, plus a Runner/runtime coordinator that validates the registered CPU and DMA and the authenticated F6 boundary before mutation. CPU testcase identity/sequences, IRQ serial, RVFI order and pending authenticated next fetch remain unchanged; Task5 verifies CPU and DMA keys against their respective session case IDs and does not require ID equality. `ScenarioSession.submit_case()` has no per-step observer; F6 must read actual CPU-issued source versions after the deferred start-register request is queued and before the immediately following DMA step drains it. Add an optional F6-used step observer forwarded to the existing Runner batch callback; calls omitting it preserve existing behavior. Modify `src/myfuzz/local_harness/wishbone_dma_session.py` for the scoped DMA case transition. Modify `src/myfuzz/scenario/dma_intent_topology_binding.py`, `src/myfuzz/scenario/runtime_path_contract.py`, and `src/myfuzz/scenario/runtime_edge_index.py` only for the proven operation-scoped permission consistency needed by F6's read-only and write-only route intents over one read/write RAM. Each RAM route permissions tuple must be a subset of actual resource permissions and include its operation, while resource window/identity remains exact and static intent/live route tuples remain equal. Task1's route declarations remain unchanged. Do not relax peripheral permission checks or edit Task3/Task4/Task5 issuer/fault owners.

**Interfaces:** `build_f6_execution_binding(*,contract,artifacts,compiled_inputs,base_dir,run_id,program,runner,bound_topology)->dict` and `validate_f6_execution_binding(document,*,contract,artifacts,compiled_inputs,run_id,program,runner,bound_topology)->dict` implement the independent closed `compiled_F6_execution_binding.v1` schema. It pins the static contract, same-call D2/D3 source/build identities, sparse program manifest, actual live read/write route and endpoint aliases, shared RAM plus distinct service owners, registered IRQ-take/MRET issuers, run/expectation scope; live object identity is checked in-process and serialized fields alone issue no authority. `CompiledF6Runtime(*,artifacts,compiled_inputs,base_dir,cache_dir,run_id,rounds_per_case=4096,max_cases=16,build_audit_sink=None,response_fault=None)`;properties path,execution_binding,session,runner,attempts,records,cursor,trace,finished;`preflight(raw)->F6Candidate`, `submit(raw:bytes)->dict`, `finish()->dict`, `replay(prefix,*,audit_sink=None)->dict`, `execution_audit()->dict`. `admit_compiled_f6_runtime_path(*,artifacts,compiled_inputs,base_dir)->dict` is pure;runtime binds actual topology once after constructing sessions before begin. Build join wrappers use generic compiled_build_join flow='F6' with explicit F6 schema validation,not F2 binding relabeling.

- [ ] **RED:** source-backed software session doubles prove exact artifact object/request/D3 ownership,one boot,case0/1 same session/PID identity,distinct slots/source operands,preflight zero effects,slot/result/tick/event/idle/pending/IRQ budget refusal. Add an F6-owned no-process-reset DMA-only logical scope transition test: CPU testcase ID, sequences, IRQ serial, RVFI order, pending authenticated next fetch and all CPU state remain unchanged; DMA process/PID/execution/reset epoch/absolute ticks/RAM/service/ledger/cumulative events/transport sequence/parser state/route history remain unchanged, while DMA testcase ID and source sequence advance. Before mutation require terminal/MRET/fetch-or-park, immutable Task5 inventory, fixed IRQ expiry, idle, resolved DMA responses/ledger, no selected/active fault; allow only the authenticated next CPU instruction fetch to remain outstanding. Atomic preflight rejects duplicate/reused IDs, backward/skipped indices and invalid route/policy/fault transitions without partial mutation. Include operation-scoped read/write route permission subset positives and disabled/missing-operation/static-live drift negatives in both D4 declaration and runtime path binding. Finish idempotently returns cached pair material;constructor/submit/finish/fresh/cleanup failures retain first object/notes and independently export available partial evidence. Fixed pulse expiry and next pending fetch are separate conditions.

```python
def test_two_cases_reuse_boot_and_require_return_boundary(runtime_double, legal_records):
    rt=runtime_double
    rt.submit(legal_records[0]);rt.submit(legal_records[1])
    assert rt.runner.begin_count==1
    assert len(rt.records)==2
    assert rt.records[0]['certificate']['next_fetch']['address'] == rt.records[1]['instruction_address']
```

- [ ] **Run RED:** `PYTHONPATH=src:. python3 -m pytest -q -ra tests/integration/test_compiled_f6_runtime.py`.
- [ ] **Implement:** recompile same-call contract→construct actual registered artifacts/shared RAM/separate services→immutable preload/online reservations→prepare/bind routes/ownership→install policy/snapshot/MRET issuers/optional sealed fault→begin once. Add the narrow F6 DMA logical-scope transition on the original DMA session and a Runner/runtime coordinator. The coordinator verifies the exact registered CPU/DMA, preserves CPU transaction scope and the intentional next pending instruction fetch, requires frozen prior Task5 inventory plus terminal/MRET/fetch-or-park/IRQ-expiry/idle and settled DMA response/ledger state, and atomically preflights duplicate/order/fault/route/policy transition conditions before mutation. It changes only DMA testcase ID/source sequence and per-case route/policy/fault cursors; it preserves both native executions/processes/PIDs/reset epochs/ticks/RAM/services/ledgers, cumulative raw event streams, DMA command/ACK sequence/parser, issued receipts, and global commit/event/IRQ/RVFI serials. The route admission retains prior route-match history. Start next DMA route/policy/fault case scope only after the transition. Submit admits actual case before effects;executes canonical prefix until complete terminal,MRET and authenticated next-fetch/park plus old pulse expiry/idle/settlement. Fault path completes bounded error ISR/current-island then stops campaign. Max_cases cannot exceed declared slots16. Never host-reset/recreate/jump PC between cases. Update only generic persistent-memory permission consumers so each operation-scoped route permission tuple is a subset of the exact resource permissions and includes the selected operation; static intent/live route tuples remain exactly equal and peripheral semantics do not change.
- [ ] **Fresh:** factory reconstructs same declarations/source/configuration and fresh processes,remaps declared fault selector to new keys,and compares full raw-normalized prefix. Envelope contains matches,first_difference,scope,actual_prefix,actual_events,original_execution_audit,execution_audit,original_build,fresh_build. Successful scope='full';expected failure scope='failed_prefix_full',completed=false. Missing envelope/material/nonzero exit cannot pass. Independent export callbacks attempt all fields before raising the original primary.
- [ ] **GREEN:** `PYTHONPATH=src:. python3 -m pytest -q -ra tests/integration/test_compiled_f6_contract.py tests/integration/test_compiled_f6_layout.py tests/integration/test_compiled_f6_firmware.py tests/integration/test_compiled_f6_response_fault.py tests/integration/test_compiled_f6_isr_return.py tests/integration/test_compiled_f6_assertion_evidence.py tests/integration/test_compiled_f6_execution_binding.py tests/integration/test_compiled_f6_consumer.py tests/integration/test_compiled_f6_runtime.py tests/integration/test_dma_bound_online_session.py tests/integration/test_dma_intent_binding_replay.py tests/scenario/test_online_session_partial_replay.py`. Review actual-source finalizer/replay interfaces and original-byte ownership before transport wiring.
- [ ] Archive task6 baseline/diff/hashes/RED/GREEN/Spec+Quality review. No native acceptance from doubles.

## Task 7: Explicit decoder/RFuzz/file dispatch, saved joins and typed report

**Files:** create `src/myfuzz/scenario/compiled_f6_decoder.py`, `src/myfuzz/integration/compiled_f6_rfuzz.py`, `compiled_f6_rfuzz_session.py`, `compiled_f6_receipts.py`, `compiled_f6_saved_outputs.py` under that integration directory;create `tests/integration/test_compiled_f6_rfuzz.py`, `test_compiled_f6_saved_outputs.py`, `test_compiled_f6_entry.py`;modify `src/myfuzz/integration/compiled_execution_files.py`, `scenario_rfuzz_live.py`, `src/myfuzz/local_harness/auto_harness_test.py`, `src/myfuzz/scenario/capability_report.py`, `scripts/auto_harness_test.py`, and `configs/peripherals/zipcpu_wbdmac/component_profile.json` only to add the source-reviewed native IRQ form required by D1. The F6 support assessor must join that declared IRQ form to `verify_wbdmac_source_contract`; do not suppress or override D1 findings. Add default-off exact registered DMA-linked artifact provider opt-in to `src/myfuzz/local_harness/harness_set.py` and an explicit `flow='F6'` reconstruction branch to `src/myfuzz/local_harness/generated_artifact_admission.py`; default loading/generation continues to reject route-bearing sets. Extend `tests/integration/test_generated_artifact_admission.py` and `tests/local_harness/test_harness_set.py` for the F6 opt-in and unchanged default/F2/F4 behavior. In `src/myfuzz/scenario/compiled_paths.py`, only for marked F6 requests, normalize the post-supplement typed wiring into a full `path_wiring.v2` `wiring.document` view containing the merged IRQ deliveries/routes/bindings; preserve the original `PathCompileRequest.document` unchanged as the frozen user input and hash source. Extend `tests/scenario/test_compiled_paths.py` for F6 delivery normalization and unchanged F2/F4 behavior. One Task7 owner coordinates all shared wiring;do not concurrently edit these files.

**Interfaces:** `CompiledF6Decoder.from_runtime(runtime)`,max_input_bytes=8,decode_sequence(records,*,cursor,case_index)->tuple;`CompiledF6RfuzzExecutor(ScenarioRfuzzExecutor)` with explicit live surface and `(trace,plan_hex)` cached finalizer;`run_compiled_f6_rfuzz_session` keyword signature matches F2 wrapper;`join_compiled_f6_receipts(*,runtime,executor,receipts_path,replay)->dict`;`verify_saved_compiled_f6_build_outputs(output_dir,*,outcome,harness_set,manifest)->dict`. Outcome keys match F2 plus independent assertion_material and transport_files;failed outcome never enters success verifier. Five-counter feedback is F6-owned. The explicit closed D3 marker is carried by optional `--f6-execution <json-path>` / `run_auto_harness_test(..., f6_execution=path)` input and injected into `path_compile_request.v1.f6_execution`; optional `--f6-deliveries <json-path>` / `f6_deliveries=path` supplies the typed `PathDelivery` array through the existing generic `path_compile_request.v1.deliveries` supplement. Both are pinned inputs; absent marker preserves current unsupported F6 behavior and absent/invalid IRQ delivery refuses before construction. Do not extend `harness_compose.v1/v2` or change F2/F4 defaults. Task8 freezes and passes both files explicitly.

- [ ] **RED:** raw2..200 record preflight,duplicate slot/cache/drift,source operands not F2 address/F4 commit semantics;real source-backed driver principal records exact loaded artifact/request/D3 identities. Patch only actual runtime/client/bundle boundary,not verifier or inventory reconstruction. Missing/malformed/wrong marker,client,IRQ,layout or support refuses before constructor. D1's former `interrupt-form-undeclared` on WBDMAC is repaired by adding its source-reviewed IRQ form to the component profile; the F6 support assessor must reject declaration/source drift against the pinned RTL contract instead of suppressing D1. The CLI/API marker is exact-key checked and injected only as `path_compile_request.v1.f6_execution`; the IRQ file is validated as a typed `PathDelivery` list and injected only as the generic `path_compile_request.v1.deliveries` supplement. Both are independently pinned; compose v1/v2 remain closed. F6 D2 generation may opt in only to the exact registered DMA linked-artifact provider for the unique route initiator; persist the provider sidecar and identity. Only `flow='F6'` loading may reconstruct route-bearing v2 artifacts, by rebuilding from the saved requests with the registered provider and comparing every ordinary artifact and endpoint-link sidecar byte before returning any same-call credential. Default loader still refuses route-bearing v2; missing/mutated/wrong-provider sidecars and stale source/artifact drift refuse. For marked F6 only, typed wiring after merging explicit request supplements must expose the exact complete `path_wiring.v2` view consumed by the F6 replayer while the original `PathCompileRequest.document` stays unchanged and remains the request hash source. Missing/contradictory deliveries refuse; F2/F4 and unmarked projections remain byte-identical. Typed report gets independent pair and no extra tier. Late raw/typed/fresh/build/capability formatting or coherent rehash replacement fails initial pins;first primary/notes survive exports.

```python
def test_entry_has_no_family_fallback():
    from myfuzz.local_harness.auto_harness_test import COMPILED_EXECUTORS
    row=COMPILED_EXECUTORS['compiled-f6-rfuzz']
    assert row['flow']=='F6' and row['family_fallback'] is False
    assert row['entry']=='myfuzz.integration.compiled_f6_rfuzz:run_compiled_f6_rfuzz_session'
```

- [ ] **Run RED:** `PYTHONPATH=src:. python3 -m pytest -q -ra tests/integration/test_compiled_f6_rfuzz.py tests/integration/test_compiled_f6_saved_outputs.py tests/integration/test_compiled_f6_entry.py`.
- [ ] **Implement:** share only compiled_rfuzz_transport parsing/owned exchange. Closed registry selects F6 loader/support/wrapper/verifier/filenames;preserve F2/F4 defaults/public signatures. Add explicit F6 pure online material validation branch and retain same-call in-memory first-writer byte commitments before later pin scans. Persist raw8/decoded operands/program/case/assertion/original/fresh bijections;preflight refusals redecode with no fabricated case IDs.
- [ ] **Save:** compiled_f6_prefix.json,replay,fresh_prefix,fresh_events,fresh_execution_audit,fresh_verification,build_join.v1,receipt_join.v1 plus compiled_assertion_results.v1.json/compiled_assertion_evidence.v1.json and original raw session files. Error prefixes retain explicit incomplete/fault scope. Prepared initial pins survive final capability/report writes and are republished before final checks;no rebaselining from disk. Capability F6 binding validation explicitly joins the five expectations and inventory.
- [ ] **GREEN:** `PYTHONPATH=src:. python3 -m pytest -q -ra tests/integration/test_compiled_f6_*.py tests/integration/test_generated_artifact_admission.py tests/local_harness/test_harness_set.py tests/scenario/test_compiled_paths.py tests/integration/test_compiled_f2_rfuzz_entry.py tests/integration/test_compiled_f2_rfuzz_saved_outputs.py tests/integration/test_compiled_f4_saved_build_outputs.py tests/integration/test_scenario_rfuzz_terminal_identity.py`. Exact selected files/counts recorded,not guessed. Review full production success principal and failure paths before freeze.
- [ ] Archive task7 diff/hashes/RED/GREEN/reviews;report actual candidate diversity/cost/rates or null with reason,and useful_search_benefit_claimed=false unless independent evidence supports it.

## Task 9: Source-bound native OBI instruction-fetch completion receipt

**Why this continuation exists:** the approved F6 graph requires the fourth edge
to be rebuilt from original Runner/Observer facts. The existing
`native_instruction_bus_completion.v1` producer is for `NativeBusObserver` and
its native-memory backend handshake; F6 uses `GeneratedCve2Session` and native
OBI `i_req`/`i_rsp` signals. Do not route OBI evidence through that other
producer. This task adds an OBI-owned receipt with the same narrow meaning:
actual source-backed instruction bus transfer completed; it grants no source
authority, decode, retirement, or semantic-consumption claim.

**Files:** create `src/myfuzz/scenario/f6_instruction_fetch_receipt.py` and
`tests/scenario/test_f6_instruction_fetch_receipt.py`; modify
`src/myfuzz/local_harness/cpu_session.py`,
`src/myfuzz/scenario/session_runtime.py`,
`src/myfuzz/scenario/runner.py`, `src/myfuzz/integration/compiled_f6.py`,
plus focused tests for each modified live boundary. Do not use
`NativeBusObserver` or weaken its existing owner checks.

**Receipt contract:** `compiled_F6_instruction_fetch_completion.v1` is issued
only by the original generated CPU OBI response-consumption path for a real
four-byte instruction fetch. Bind the original `InstructionAcceptance` object,
the admitted `BoundOnlineInstruction`/`SourceAdmission`, exact F6 run and
execution-binding digest, case/index/path/source/action, CPU execution and
testcase, reset epoch, complete OBI `TransactionKey`, accepted address and
acceptance tick, response tick, actual `ReadSnapshot` byte material (memory,
generation, offset, four versions, writer IDs/kinds), and exact native OBI PRE
request-accept and response-consume samples. Save Runner IDs for the admission,
instruction-source service event, request PRE sample plus step producer,
response-consume PRE sample plus producer, and `instr_response` event. The
first prefix fetch may have been accepted while its declared slot was still
empty; preserve that actual wait→source-admission→read-snapshot→response order
and transaction identity. Issue one receipt for every completed four-byte
fetch inside the admitted 128-byte prefix; unrelated boot, ISR, and control-island
fetches are diagnostic-only. Require eventual coverage of all 32 aligned word
addresses, but allow the same address to be fetched again after a real prefetch
flush under a distinct complete `TransactionKey`; reject duplicate completion
for the same key. The CPU adapter is single-outstanding, so the live unconsumed
receipt queue is at most one object; cumulative receipts are bounded by the
admitted F6 case/step/Runner-event budgets, not assumed to equal `16 × 32`.
Bind and drain the actual `instruction_source` service row at the source-
acceptance boundary before native step scheduling; a later step used to drain
that row is not its source-time producer. Bind `run_id` and the exact
execution-binding digest into both original and fresh issuer owners. Reset,
abort, finish, owner drift, or contradictory bytes revoke/fail the issuer.

- [x] **RED:** source-backed software boundary proves the receipt is absent
  without opt-in; real code-owned `InstructionAcceptance` and `ReadSnapshot`
  identities are required; exact OBI request and response handshakes are
  required; a waiting request may predate source admission but response may
  not; wrong source/case/path/run/key/epoch, modified byte/version/writer,
  missing/tampered raw reference, wrong PRE signal, duplicate completion,
  serialized DTO injection, reset reuse, and cross-fresh reuse refuse.
- [x] **Implement:** capture the actual CPU service acceptance return and retain
  its immutable snapshot object through response consumption only in the
  opt-in F6 path. A code-owned issuer binds it to the current actual F6 source
  admission in `ScenarioSession._execute_case` and immediately logs the real
  source service event before any native step. The OBI CPU issues receipts only
  from its original `_step_local` path in two stages: backend
  `i_rsp_valid && i_rsp_ready` freezes a candidate and its exact PRE/POST;
  the next actual CPU OBI PRE `rvalid/rdata/error` clock sample issues only
  after matching that candidate's original accepted key/snapshot. Preserve the
  existing `instr_response` as explicitly backend-scoped evidence and save
  backend PRE/POST plus native response PRE/step producer references. Complete
  the old response before admitting a same-edge new request, and count the
  candidate in pending_responses. Runner consumes original
  issued objects only after saving the raw OBI PRE sample and `instr_response`,
  verifies all original IDs/transactions/bytes/scopes, and serializes typed
  receipt events. Bound the transient queue to the single outstanding OBI
  response and cumulative storage to the exact F6/Runner budget; no
  caller-created event dict can issue authority.
- [x] **GREEN:** run focused receipt/CPU/session/Runner tests and all existing
  native completion and F6 consumer tests affected by these interfaces.
  Existing F2/F4/packet-native behavior remains unchanged; no native launch in
  this software task.
- [x] Archive the actual red/green commands and output, source hashes, diff,
  and independent Spec/Quality review in `.superpowers/sdd/f6-obi-receipt-20261025/`.
  Do not mark F6 edge 3 or Task8 complete from software fixtures.

## Task 10: F6 edge-3 live and saved projection of native OBI receipts

**Files:** modify `src/myfuzz/integration/compiled_f6_consumer.py`,
`src/myfuzz/integration/compiled_f6_saved_semantics.py`,
`src/myfuzz/integration/compiled_f6_saved_outputs.py`,
`scripts/verify_compiled_f6.py`, and their focused integration tests.

- [ ] **RED:** current source-admission/service-only archive leaves edge 3
  `missing`. An edge passes only when source-bound OBI completion events cover
  all 32 aligned word addresses in the current prefix and every completed
  prefix fetch has an exact original Runner reference. A real prefetch flush
  may refetch an address under a distinct complete `TransactionKey`; repeated
  addresses are allowed, but duplicate keys, absent receipts, wrong-slot,
  cross-case/fresh, altered acceptance/snapshot/version, altered PRE/response
  sample, dangling or borrowed event references fail or remain missing with
  failed-over-missing precedence.
- [ ] **Implement:** live F6 consumer validates original receipt objects through
  the Runner journal and places their IDs in the attempt/cross-edge-owned
  evidence. Detached saved projector reconstructs edge 3 independently from
  raw Runner rows for original and fresh archives, checks the full
  `InstructionAcceptance` byte-version/writer chain and coverage of all 32
  OBI prefix fetch addresses, and closes exact root-reference/evidence
  inventory. No service
  label or matching bytes alone substitutes for the receipt.
- [ ] **GREEN:** run focused live consumer, saved-semantics, saved-output, and
  F6 verifier modules. Results are software projection coverage only until
  complete real F6 original/fresh success and expected-error archives pass
  independent raw audit.
- [ ] Archive task10 diff/hashes/RED/GREEN and independent review. Then return
  to Task8; any source change requires new frozen gates.

## Task 8: Saved auditor, frozen native controls, final acceptance and docs

**Files:** create `scripts/verify_compiled_f6.py`, `tests/integration/test_verify_compiled_f6.py`, `tests/integration/test_compiled_f6_native.py`, `tests/integration/test_compiled_f6_native_helpers.py`, `.superpowers/sdd/compiled-f6-20261024/gates/run_gate.py`,its `inputs/control-matrix.json`,registered renamed/refusal/fault fixtures,and `docs/reports/compiled-f6-cpu-programmed-ram-20261024.md`. Update CURRENT_PROGRESS,report index and exact runtime/component references only after accepted terminal evidence. Never alter prior F2 gate wrappers/attempts.

**Interfaces:** saved CLI `python3 scripts/verify_compiled_f6.py --output docs/reports/evidence/compiled-f6-cpu-programmed-ram-20261024/ibex-ram-attempt1/run --invocation docs/reports/evidence/compiled-f6-cpu-programmed-ram-20261024/ibex-ram-attempt1/invocation`;completed or expected-failure verification selected by closed saved schema and frozen declaration,never a caller “trust” flag. Native tests opt in only with MYFUZZ_RUN_NATIVE_F6=1. Supervisor records child PID/PGID/actual/expected exit/reap/timeout/RSS,external before/after byte/origin/unavailable/output maps,materialized regular tar and executable pins.

- [ ] **RED/GREEN software auditor:** altered raw44/reserved/source/program/snapshot/typed/scope/prefix/events/IRQ/MRET/build/binary/key/formatting/missing file/stale incomplete markers must refuse. Helper software tests prove actual property APIs,attempt-all export/cleanup,first-primary and nested-note preservation. Exact default native skip reason names MYFUZZ_RUN_NATIVE_F6=1;missing/duplicate/unrelated skips fail.

```python
def test_raw_substitution_refuses(saved_outcome):
    output,invocation=saved_outcome
    replace_one_raw_operand(output)
    with pytest.raises(ValueError):
        verify_saved_f6(output,invocation=invocation)
```

The new auditor module exposes `verify_saved_f6(output,*,invocation)->dict`;`replace_one_raw_operand` is a test-only helper in that same test module that rewrites a retained raw8 record without changing the frozen external initial pin.

- [ ] **Run:** `PYTHONPATH=src:. python3 -m pytest -q -ra tests/integration/test_verify_compiled_f6.py tests/integration/test_compiled_f6_native_helpers.py tests/integration/test_compiled_f6_native.py`;inspect actual default skip selection. No native opt-in during edits.
- [ ] **Freeze:** prepare all exact source/tests/configs/generated control inputs,commands/tool/client pins and source symlink provenance before launch. Inventory registered source closure boundedly;exclude only owned scratch directories,never declared files. Record all prior RED/failures. Obtain independent freeze/archive/current-byte/command selection review before any gate.
- [ ] **Frozen software:** supervisor runs every Task1–8 software module plus affected F2/F4/session/DMA/IRQ regressions,with explicit live Rust smoke opt-in and F6 native opt-out. Archive exact pytest argv/JUnit/count/subtests/skips;no planned count is an acceptance fact.
- [ ] **Frozen directed/native controls:** one shared heavy lock,one native job at a time. Require two distinct legal raw candidates in one continuous CPU/DMA boot;all four word source/config/read/write/IRQ/take/ISR-entry/serial/MRET/immediate-successor-PC/result/nextslot joins;MRET `pc_wdata` remains raw and is never treated as the architectural return target. The current-case successor must match an error-free native instruction response and canonical prefix/preload. Distinct full fresh processes. During case 2, capture the native instruction fetch waiting on its still-unfilled prefix, then prove that only the source-bound 128-byte admission resumes that same fetch/process;no host PC change or instruction-byte rewrite is allowed. Require renamed logical instances/same physical profile ABI;unsupported IRQ/source/route/shape refusal before construction;invalid reserved/duplicate operands/2records zero effects;controlled missing snapshot/commit/IRQ/MRET/successor yields actual attempted failed/missing+zero feedback;sealed ERR on a declared middle read/write yields target_effect=false,actual partial effects/native error IRQ/ISR/MRET/current-island return and independent failed_prefix_full replay.
- [ ] **Actual unified RFuzz:** create frozen `gates/inputs/f6-ram/compose.json`, `test_capability.json`, `f6_execution.json` and `f6_deliveries.json` under this plan's new evidence root using Task1's closed marker and source-backed fixture. Preserve CPU physical endpoints and exact registered DMA physical endpoint links;logical names come from fixture requests. Archive literal argv before freeze:

```bash
PYTHONPATH=src:. python3 scripts/auto_harness_test.py \
  --executor compiled-f6-rfuzz \
  --f6-execution .superpowers/sdd/compiled-f6-20261024/gates/inputs/f6-ram/f6_execution.json \
  --f6-deliveries .superpowers/sdd/compiled-f6-20261024/gates/inputs/f6-ram/f6_deliveries.json \
  --cpu configs/cpus/ibex_rvfi_local/component_profile.json \
  --ip configs/peripherals/zipcpu_wbdmac/component_profile.json \
  --compose .superpowers/sdd/compiled-f6-20261024/gates/inputs/f6-ram/compose.json \
  --ip-capability .superpowers/sdd/compiled-f6-20261024/gates/inputs/f6-ram/test_capability.json \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir .superpowers/cache/compiled-f6-20261024 \
  --output docs/reports/evidence/compiled-f6-cpu-programmed-ram-20261024/ibex-ram-attempt1/run \
  --budget-seconds 30 --max-tests 4 --max-runs-per-batch 1 \
  --search-seed 1 --rounds-per-case 4096
```

Require actual receipt/feedback exchange and full fresh;directed two-case diversity is not mislabeled RFuzz search benefit. Only the supervisor launches this literal child after independent freeze review.
- [ ] **Affected compatibility:** actual unified F2 Timer/SPI and F4 Timer/SPI on the same final production snapshot,plus original Caliptra source/software boundary controls. Old F2 freeze3 evidence remains historical and cannot certify changed shared code. Independent raw audits include CPU native error observable vs absent-error limitations.
- [ ] **Final audit/docs:** run saved auditor per positive/expected-failure/refusal outcome as applicable;independent raw/source/build/byte review per gate. Reconcile all terminal facts and source hashes,generated/executed/certified/input-invalid/failed counts,costs and true limitations. Update plan checkboxes/status/report/index only after actual evidence;retain prior failed attempts,controlled fault labels and no arbitrary onboarding/system claims.

## Plan self-review and handoff

Tasks 9 and 10 are a documented continuation required before Task8. Task9 uses
the F6 CPU's actual OBI interface because the existing packet completion
observer has a different native backend; Task10 is the only task that may
remove the current saved edge-3 `missing` result. The user-approved F6 scope is
unchanged, and this continuation does not promote software receipts to native
acceptance.

### Fixture and schema handoff details

Task1 defines a module-local `source_inputs` pytest fixture in its new contract
test module. It returns(serialized_request,compiled_document,exact_artifacts),
using existing load/plan/render/source verification functions before native
construction. `compile_f6_execution_contract` consumes that serialized request
mapping;the compiler passes its equivalent parsed request document,not an
unrelated request reconstructed from saved output. Extend PathCompileRequest
and its closed loader/document serializer consistently for f6_execution.
Later shared fixture code moves into Task5's f6_compiled_support.py only after
Task1 owner hands off;do not import another test module's private fixture.

Task2's layout/firmware fixtures are constructed from the contract fixture.
Task3's native_dma_double fixture supplies the actual parsed PRE read/write
beat selected at(case0,write,index2),an actual generated-session object without
starting its process,a marked synthetic command receipt and admission/service
spies. Task4's issuer fixture uses actual source-backed generated artifacts and
original native receipt parser callbacks with explicit synthetic POST fields;
it cannot grant native evidence. Task5's consumer_case yields a source-backed
runtime-shaped software fixture and an actual attempt inventory plus detached
observer view;its test-only fields are not added to production runtime APIs.
Task6's runtime_double supplies the real F6 runtime with constructor/session
boundaries replaced by those marked software objects;runner.begin_count is a
test spy counter,not an assumed existing ScenarioRunner property.

Prefix source mappings bind instruction image,case slot and individual operand
bit slices. Read/write routes carry actual DmaMasterRouteContract objects and
endpoint link identities. The runtime dependency graph has exactly four
declared dataflow edges: RAM source→DMA reads, DMA reads→DMA writes,
DMA writes→RAM destination, and instruction source→online prefixes. CPU
configuration and IRQ/ISR remain separate typed component evidence in the
five expectations;they are not extra runtime graph edges. Policy
accepted/completed state checks
actual native sequence and response chronology;it cannot impose an invented
read/write alternation. For block4,the registered wbdmac provider defines the
actual four-read/four-write burst order and readback encoding from pinned RTL.

Evidence comparison uses exact raw first-byte commitments plus canonical
semantic checks. Compare process-local fields only through an enumerated
normalization map;record raw values separately. Successful and expected-error
prefixes have distinct completed/status/scope fields;both require actual full
fresh prefix/events/audits/build maps. Expected preconstruction refusals instead
retain exact stage/code/pointer,incomplete marker,source-matched guarded
development proof and unpatched frozen CLI output;they do not fabricate replay.

### 2026-10-25 implementation checkpoint

The live consumer and detached original/fresh saved verifier now reconstruct
the four runtime graph edges from Runner facts and keep cross-edge references
separate from the three component expectations. Edge-local issue routing and
`instruction_source` Observer→Runner authentication are implemented. This is
still a software candidate: edge 3 stays `missing` without an archived original
F6 instruction-acceptance receipt, and no full real original/fresh success or
expected-error archive has passed raw audit. The combined consumer/assertion
regression result of 198 passed predates the final reference-closure changes;
see [the implementation report](../../reports/f6-cross-component-edges-20261025.md)
for the exact validation boundary. Do not mark any Task8 frozen gate complete.

### Final acceptance ledger

Task8 supervisor declares these separate gate modes before freezing:
software,native-controls,f6-positive,f6-renamed,f6-unsupported-irq,
f6-wrong-route,f6-controlled-err-read,f6-controlled-err-write,
f2-timer,f2-spi,f4-timer,f4-spi. The native control suite covers actual two-case
continuity,raw/layout refusal and copied-observation missing evidence separately
from valid-route ERR response controls. Each mode gets a new attempt directory,
literal command,expected exit and explicit exact selected-case/skip policy.
No mode runs twice merely to improve a count;repeat only after a documented
failure,source change or unresolved acceptance gap. Source change invalidates
current-byte attribution and requires fresh affected frozen gates.

Before completing Task8,the independent reviewer checks the ledger against
all prior task reviews,actual source map/archive/generated fixture bytes,
current tool/client pins and terminal gate audits. Costs distinguish compile
from cache hits and application/client from native child time. Native error
observations retain their provider's true scope,including unavailable pins in
affected compatibility runs. The final report links raw evidence and states
what remains open rather than combining old six-CPU/four-IP examples into this
new contract's acceptance.

- [ ] Spec coverage: §§1–5→Tasks1/2/5/6;slot/IRQ/MRET§6→Tasks2/4/6;word sources§7→Tasks3/5;typed/failure§8→Tasks3–7;unified/fresh/pins§9→Tasks6/7;frozen acceptance/docs§10→Task8. Old Caliptra/other protocol boundaries remain unchanged.
- [ ] Interface check: all new API names above are definitions assigned to owning tasks;existing APIs are explicitly named. Task3 handoff precedes Task5 DMA issuance edits;Task4 owns CPU hook;Task7 alone owns shared finalizer/driver. The public factory F6 constructor activation waits for Task6.
- [x] Self-review performed when authoring: checked approved spec,actual source gaps,four resolved design findings,raw/program bit widths,service ownership,fault chronology,MRET trust,parallel file ownership and gate attribution. No further design/user choice is pending.
- [x] Root and independent plan review completed: the root added the distinct `compiled_F6_execution_binding.v1` builder/validator, exact sparse preload manifest/unmaterialized-prefix assertion, and explicit native wait/resume gate. Proceed with authorized independent source tasks using TDD and Spec/Quality review;native work waits for the final frozen candidate.
