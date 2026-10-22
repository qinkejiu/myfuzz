# CV32E40P → ZipCPU DMA → PULP GPIO → CV32E40P ISR

Date: 2026-10-21

## Result

This slice adds a measured CPU-configured, one-word DMA chain for the
CV32E40P profile. The CPU writes the ZipCPU wbdmac registers over native OBI.
The DMA reads 0x5aa55aa5 from the shared host PersistentMemory service at
0x00022000, writes it to PULP GPIO PADOUT at 0x4000100c, then raises its
completion IRQ. CV32E40P acknowledges external IRQ ID 11, enters its direct
ISR at 0x10200, reads the DMA status and GPIO value, and stores the cause,
status, output, source value, and success marker in RAM.

The D3 request uses configs/cpus/cv32e40p/component_profile.json. Its declared
ROM region is 0x10000/0x8000 (readable, executable, not writable); RAM is
0x20000/0x20000 (readable/writable, not executable). The native runtime uses
the same named regions and enforces their read/write policy. PersistentMemory
does not represent execute permission, so this evidence makes no runtime
instruction-execute protection claim. To cover the CV32E40P sequential fetch
after the terminal JAL, the test initializes unused ROM gaps with NOPs before
the CPU starts; the D3 geometry, profile, and ROM read-only policy stay fixed.

PULP GPIO is bound through the existing D4 topology admission. The same
prepared typed path object is bound exactly once in each run; its credential
tier is topology_bound. Only the full-word write to PADOUT offset 0x0c and
the selected value are admitted. Static D3 F6 remains unsupported, has no
runtime path identity, and adds no DMA_MASTER_TRANSFER edge.

The measured D4 topology-binding identity SHA-256 is
e3d9f4fff7e778bde9d8a28294670698ed91a19d3f25defa4190661f9700f4d3. Its
selected RAM-read route SHA-256 is
427e9f0932de07634375de649b1c1250858e1d93f20fc78feaf424a8efe09738; the
PADOUT-write route SHA-256 is
0831db029fc455794855c0231c0b7ab2f712bcb32b6cbf45e09baa001f9f948c. The
runtime path ID is
9ceeb5747bf5cc0d19f6ba196ecad8f1ce47adc4fb2ebf151532bf0f18c0493f.

## Positive and fresh evidence

In both first and fresh runs, native OBI receipts show these accepted CPU
writes in order: source 0x40002008 = 0x22000, destination 0x4000200c =
0x4000100c, length 0x40002004 = 1, and keyed start 0x40002000 =
0x0fed0001. The DMA read key is source sequence 1 and the write key is
sequence 2, both on channel dma-memory and bound to the run's DMA execution
and testcase. The four-byte RAM read returns 0x5aa55aa5 with byte enable 15
and zero error. The separate PADOUT write key joins the D4 edge (2, 0), the
PULP target request, APB access, observed GPIO effect, target response, and
native DMA response. The read route is D4 edge (0, 0).

The DMA IRQ source and Runner binding/input records precede the CPU
acknowledgement. Event 1561 records irq_ack_o=1 and irq_id_o=11; the later
accepted instruction fetch at event 1614 is 0x10200. ISR RAM stores are
mcause=0x8000000b, status=0, GPIO readback=0x5aa55aa5, source readback=
0x5aa55aa5, and marker=1. No RVFI retirement interface is available in this
profile; the report claims native bus and trap/ISR evidence, not retirement.

The first and fresh schedules each have 309 steps (103 dma/cpu/gpio rounds),
2,863 Runner events, completed admission, and one GPIO provider call. All
three native child processes exit 0 in each run. Fresh used new processes and
new CPU/DMA/GPIO/Runner execution IDs, and its semantic comparison is equal
after the declared execution-identity normalization. The normalized SHA-256
is 004b65dd57a12c23d51745f8fc8f1102f7ba3e67595f617d48bfb79dede384f3.

The measured artifact identities are CPU
38348595b2fad93400b72eb22fd9cf94f127fba1875bb9bfc207de094b40fa1a, DMA
05889d83bc7e93367bf1afa078439bde2718f4e88aba88bb114e11a41e01c654, and GPIO
d970d89b7b05055ed8099553dc9106c788bea25594e54dd4cf8f3d7ba0d15622. The
selected CPU profile input SHA-256 is
21d04c8ad75d2e6cc1feff72b22dc1d7656b129cddd70d55bb981973d0db3e45.

| Run | CPU/DMA/GPIO process IDs | CPU/DMA/GPIO/Runner execution IDs |
|---|---|---|
| attempt5 first | 1614091 / 1614123 / 1614155 | e530cf75942e4c3ab6ae7aa4abe0f25f / 9d4cb145ecb2405d8caa103ffdcb3c0f / 9e14547938e44e828a14b827063cce34 / 7c5cee229911457b80cf83c6e55abca7 |
| attempt5 fresh | 1615246 / 1615278 / 1615310 | 40415e28610f48ceb614f54c77ad96a1 / 1b5da316bd074301820743c9382e2200 / ddc697b88aa04928a6596160230ea854 / 5a90b637c30e4be3964386f44d9f4162 |
| attempt6 wrong-offset | 1617114 / 1617146 / 1617178 | b20df65e214746e8a1366d89557b1432 / 9428e5ce73b142afb3f5d92da991f957 / 856654b235c1400fb303978a9dd7271e / 05d948d1d1b745acad5376fcd4fe6800 |

## Strengthened ISR and profile-fingerprint assertions

The follow-up focused software gate adds two boundaries. First, each of the
three accepted CV32 ISR data reads is joined from its OBI request to the typed
router-delivery or RAM receipt and to exactly one consumed response with the
same source epoch/sequence. The reads are DMA status at `0x40002000` (value
zero, sequence 5), PADOUT at `0x4000100c` (value `0x5aa55aa5`, sequence 8),
and the source word at `0x22000` (value `0x5aa55aa5`, sequence 10); each uses
byte enable 15. The source read joins the actual CPU memory-service receipt.
These bus and ISR joins do not establish RVFI retirement.

Second, a same-component profile negative changes only the CV32 profile
fingerprint while retaining component ID `cv32e40p`, compiles D3, and attempts
D4 installation. D4 refuses with
`dma-binding-template-mismatch` at `/route_links/1/endpoint_link/target`;
all native processes remain unstarted and CPU local ticks remain zero.

Attempt7's initial software attempt had one failure because a test mock
replaced provider methods protected by the fixture's identity guard; that log
is preserved. The final five-test software rerun passed (**5 passed / 54.53s**).
Its native first/fresh execution reached the expected results, but pytest
reported `1 failed in 64.52s` (command elapsed 64.75s) because a test-only
assertion compared JSON-normalized list data with the runtime driver's tuple
samples. Preserve it as a failed
assertion attempt; it is not a passing gate. Attempt8 fixes that test comparison
with the existing typed `_plain` normalization while retaining strict value
equality. The five-test software gate passed (**5 passed / 54.96s**) and the
strengthened positive/fresh native gate passed (**1 passed / 69.28s**).
Both runs completed 103 rounds / 309 steps with the established result; all
CPU/DMA/GPIO child processes exited zero, and the final heartbeat has no
pending responses or target requests. First/fresh ISR joins use schema v2,
the normalized comparison has `equal=true` and `difference=null`, and its
matching SHA-256 is
`004b65dd57a12c23d51745f8fc8f1102f7ba3e67595f617d48bfb79dede384f3`. The
attempt8 postflight audit also confirms that attempt7 files stayed unchanged
and the reused binaries/manifests match the previously verified content-addressed
cache. See [attempt8 evidence](evidence/cv32e40p-zipcpu-pulp-dma-isr-20261021/attempt8/).

## Wrong-offset refusal

The independent attempt6 negative run sampled the actual Wishbone pre-backend
write to 0x40001010 (mwb_adr=0x10000404, mwb_dat_w=0x5aa55aa5). D4 route
admission raised ValueError before PULP provider dispatch. The final native
event records harness_failure status uncertain_effect with an empty
uncertain_transactions list. Evidence has zero provider calls, no PULP target
request/APB access/response, no observed GPIO effect, no DMA IRQ or CPU IRQ
input, and all five result words are zero. The three child processes exit 0.
This is an environment-side route refusal; it is not an RTL bus-error response.

The refusal stops at schedule step 160, after 53 full rounds and the DMA step
of the next round. The final heartbeat has one pending CPU response and no
pending target request. The run therefore does not claim that all transactions
were drained. Its heartbeat cpu event counter is zero because that counter
reads the separate cpu_events collection; the same evidence records 53 CPU
bus steps and 53 CPU local ticks, so the counter is not a CPU-execution count.

## Verification commands

The strengthened five-test software gate passed **5 passed / 54.96s**:

    PYTHONPATH=src:. pytest -q \
      tests/integration/test_cv32e40p_dma_pulp_gpio_real.py::test_mutated_cv32_profile_fingerprint_is_rejected_before_native_execution \
      tests/integration/test_cv32e40p_dma_pulp_gpio_real.py::test_cv32_pulp_d3_d4_binds_exact_memory_gpio_and_rejects_mutated_padout \
      tests/integration/test_cv32e40p_dma_pulp_gpio_real.py::test_wrong_cpu_profile_d3_is_rejected_before_cv32_native_runner \
      tests/integration/test_cv32e40p_dma_pulp_gpio_real.py::test_cpu_step_capture_accepts_scenario_runner_mapping_output \
      tests/integration/test_p7b_p7c_dma_route_intent.py::test_pulp_gpio_cv32_route_geometry_and_default_ibex_profile

The strengthened opt-in native positive/fresh gate passed **1 passed / 69.28s**:

    MYFUZZ_CV32_PULP_DMA_REAL=1 \
    MYFUZZ_CV32_PULP_DMA_CACHE=/tmp/cv32e40p-pulp-dma-20261021-a4/cache \
    MYFUZZ_CV32_PULP_DMA_EVIDENCE=$PWD/docs/reports/evidence/cv32e40p-zipcpu-pulp-dma-isr-20261021/attempt8 \
    PYTHONPATH=src:. pytest -q \
      tests/integration/test_cv32e40p_dma_pulp_gpio_real.py::test_real_cv32_dma_pulp_gpio_irq_isr_and_typed_fresh_replay

The native commands reused the content-addressed cache at
/tmp/cv32e40p-pulp-dma-20261021-a4/cache. Before reuse, canonical SHA-256
values for each CPU, DMA, and GPIO build_identity and runtime_artifact were
compared across attempts4-7 and the attempt8 current artifacts; every identity
matched. Attempt8 additionally compared the three cached binary SHA-256 values
to their manifests and the previous preflight; the postflight audit confirms
they stayed unchanged. Evidence outputs are isolated per attempt. The replay
uses new processes and execution IDs, not a new build cache.

The focused software gate passed 3 tests in 23.72 seconds:

    PYTHONPATH=src:. pytest -q \
      tests/integration/test_cv32e40p_dma_pulp_gpio_real.py::test_cpu_step_capture_accepts_scenario_runner_mapping_output \
      tests/integration/test_cv32e40p_dma_pulp_gpio_real.py::test_cv32_pulp_d3_d4_binds_exact_memory_gpio_and_rejects_mutated_padout \
      tests/integration/test_cv32e40p_dma_pulp_gpio_real.py::test_wrong_cpu_profile_d3_is_rejected_before_cv32_native_runner

The opt-in positive/fresh native gate passed 1 test in 65.33 seconds
(pytest exit 0):

    MYFUZZ_CV32_PULP_DMA_REAL=1 \
    MYFUZZ_CV32_PULP_DMA_CACHE=/tmp/cv32e40p-pulp-dma-20261021-a4/cache \
    MYFUZZ_CV32_PULP_DMA_EVIDENCE=/tmp/cv32e40p-pulp-dma-20261021-a5/evidence \
    PYTHONPATH=src:. pytest -q \
      tests/integration/test_cv32e40p_dma_pulp_gpio_real.py::test_real_cv32_dma_pulp_gpio_irq_isr_and_typed_fresh_replay

The independent opt-in wrong-offset gate passed 1 test in 32.44 seconds
(pytest exit 0):

    MYFUZZ_CV32_PULP_DMA_REAL=1 \
    MYFUZZ_CV32_PULP_DMA_CACHE=/tmp/cv32e40p-pulp-dma-20261021-a4/cache \
    MYFUZZ_CV32_PULP_DMA_EVIDENCE=/tmp/cv32e40p-pulp-dma-20261021-a6/evidence \
    PYTHONPATH=src:. pytest -q \
      tests/integration/test_cv32e40p_dma_pulp_gpio_real.py::test_real_cv32_dma_wrong_padout_offset_refuses_before_provider

## Evidence and retained attempts

The original positive/fresh evidence and native pytest log remain archived in
[attempt5](evidence/cv32e40p-zipcpu-pulp-dma-isr-20261021/attempt5/); the
final assertion-strengthened positive/fresh evidence and native log are in
[attempt8](evidence/cv32e40p-zipcpu-pulp-dma-isr-20261021/attempt8/). Attempt7
contains the failed assertion run and its unmodified-file SHA inventory.
Wrong-offset refusal and its log are in
[attempt6](evidence/cv32e40p-zipcpu-pulp-dma-isr-20261021/attempt6/). An
independent read-only audit recomputed the result, transaction joins,
acknowledgement/trap ordering, fresh comparison fields, refusal boundary,
heartbeat state, and SHA-256 equality between the archived files and their
operation-local source files.

Earlier attempts remain preserved in the same evidence directory and do not
count as final passes. Attempt1 exposed an uninitialized sequential ROM fetch
at 0x1005c; attempt2 exposed a test-side Mapping return handling error; and
attempt4 reached the positive/fresh result but failed a test assertion that
looked for an event kind not emitted by the Runner. The final gates reran with
the ROM fill and assertion/capture fixes in place. Attempt3 is the prior
wrong-offset run; attempt6 is the final gate with the request payload and
refusal-side-effect assertions.

## Scope limits

This is one local CV32E40P profile, one ZipCPU wbdmac artifact, one PULP GPIO
PADOUT route, and one 32-bit DMA word. It composes independently generated
native sessions through transaction-level delivery and a host
PersistentMemory service. It does not prove a physical Wishbone-to-APB3
bridge, physically shared SRAM, global cycle-accurate SoC timing, arbitrary
DMA routes, multiword or continuous fuzzing, generic F6 execution, remote
validation, CPU retirement, or general CPU/IP onboarding. It does not close
P6, P7-E, P8, or the six-CPU/four-IP objective.
