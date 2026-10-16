# Actual CVW CPU → Caliptra SHA256 → RAM — 2026-10-17

The fourth peripheral series has a real directed CPU integration: the pinned
CVW executes a static RISC-V boot image, writes the actual pinned Caliptra SHA256
BLOCK/CTRL registers, polls STATUS.valid, loads DIGEST words and stores them into
declared RAM. Both `abc` and `abd` run in one persistent pair of native sessions.
The CPU image contains message padding and instructions; expected digests exist
only in the independent hashlib test oracle.

The pinned CPU configuration is **XLEN=32, AHB data=32, address=34 bits**, with
D-cache disabled. The Caliptra subordinate is AHB-Lite32. No 64-to-32 conversion
is claimed. Source verification uses both profiles' existing D2 locks, including
closure hashes and pinned Git blob checks. Neither upstream RTL nor the generic
AHB session/router was modified.

## Evidence and checks

The final real gate passed **3 tests in 100.00 seconds**: the complete positive
first/fresh process comparison, the old internal zero-window control, and an
actual CPU byte store rejected before any SHA target tick. The compact runtime
index is `configs/peripherals/caliptra_sha256/evidence/cpu-chain-20261017.json`.

Each positive run has 1,248 CPU samples, 336 SHA target samples and **84 actual
register transactions**: 34 writes, 34 STATUS polls and 16 digest reads. The two
hashes finish with 17 actual polls each. The test compares every real accepted
CPU MMIO request to its router delivery, every target AHB address acceptance and
separate data phase to that delivery, and each register response to the actual
CPU response consumption. RAM contains all sixteen actual digest words followed
by the CPU's completion store. Expected digests are:

- abc: `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`
- abd: `a52d159f262b2c6ddb724a61840befc36eb30c88877a4030b65cbe86298449c9`

Fresh native CPU and target processes have different execution IDs. All saved
physical samples, CPU outputs, router deliveries, RAM events, digests and
identities compare exactly. Wrong-window execution reaches no target, leaves
results zero and emits no target samples. Partial/unaligned host access requests
are also rejected without advancing target ticks.

The frozen independent source snapshot and raw evidence live at
`/root/fanzehui/cvw-caliptra-chain-20261017`, under the only permitted remote
root. Its `.superpowers/cvw-caliptra` directory persists job PID, state, logs and
exit code. Native work uses the shared
`/root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock`.

```bash
source /root/fanzehui/system-20261016/environment.sh
flock /root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock \
  env PYTHONPATH=src:/root/fanzehui/system-20261016/pythonlib \
  MYFUZZ_SCENARIO_REAL=1 \
  MYFUZZ_CVW_SHA_CACHE=.superpowers/cvw-caliptra/cache \
  MYFUZZ_CVW_SHA_EVIDENCE=runs/cvw-caliptra-chain-20261017 \
  python3 -m pytest -q tests/integration/test_cvw_cpu_caliptra_chain_real.py --tb=short
```

Both native build identities record 312 host source hashes. Concurrent parent
work changed `src/myfuzz/integration/compiled_f4.py` and
`src/myfuzz/scenario/runner.py` after the frozen snapshot; their recorded hashes
therefore differ from the current shared tree. This evidence is for the frozen
snapshot. The newly added Caliptra scenario and test match the executed source.

## Scope

This proves actual CPU/IP dataflow and deterministic fresh directed execution
for the aligned single-block SHA256 path. Independent local RTL processes are
stepped by the existing synchronous MMIO service; it does not establish a shared
cycle clock. It does not establish IRQ consumption, multi-block/Winternitz,
retirement, an online fuzz campaign, Runner certificate/coverage admission,
saved-prefix replay authentication or complete P6/P7 acceptance. Target wrapper
HRESP remains tied low as described by the separate register-target report;
transport shape rejection is a host refusal, not a DUT fault finding.
