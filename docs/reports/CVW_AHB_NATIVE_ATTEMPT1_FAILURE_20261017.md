# CVW AHB attempt1: preserved native startup failure

## Actual outcome

Root launched the sole authorized controller PID `272511` and gate child PID `272523`. The child exited **1**, poll status1; the controller recorded failure. Two observation timeouts continued the same handle; no restart or owner-issued kill occurred. Source before/after changes were empty, tools were unchanged, and controller/capture collection errors were empty.

Both CPU and Caliptra binaries/cache manifests were built and are archived. Only the CPU model started: actual PID `273974`, READY observed, then session abort closed/reaped it with returncode/poll **-9** after the observer exception. Caliptra's native lifecycle is empty; it was not started. No `STEP_MEMORY` or target ACCESS command occurred. Fresh did not start. This is **not a native gate pass** or a complete protocol prefix.

The single actual `READ_AHB_STARTUP(0)` receipt has status result, zero command ticks and all **16 original measured startup edges**. The observer retained 11 raw startup edges / 22 records before failing. Its projected counters are accepted1/completed0/reads1/writes0/stalls2/errors0; these use the incorrect boundary interpretation described below and are not validated manager transaction counts. Original service/router rows are empty. The measured reset-to-command prefix flag is false. All sixteen raw edges remain in the original page receipt, including five not reached by projection.

## Exact original exception

`ValueError: ahb_address_hold` arose in `recorder.begin → runner.begin_test → CPU.begin_case → _read_ahb_startup → observe_startup → _observe`, at the post-address hold comparison on startup edge11. The failed raw event reference is20; the failure record is21. This precedes a command step and target physical-join/result validation. No shape, bound or timing was relaxed.

## Saved-edge/source diagnosis

The thirteen-role trace correctly exposes its declared ABI input `HREADYEXT` as `hready`. The observer incorrectly interprets that external target return as the manager's aggregate ready. The existing physical observations separately contain genuine `HREADY` (`rt_lh_p_6_0_0`) and bus `HRESETn` (`rt_lh_p_8_0_0`). These original observations were not substituted into the attempt.

| Startup edge | External reset PRE | Bus HRESETn PRE | HREADYEXT PRE | Global HREADY PRE→POST | Address/HTRANS PRE→POST |
| --- | --- | --- | --- | --- | --- |
| 9 | 0 | 0 | 1 | 1→1 | c0000000/2→c0000000/2 |
| 10 | 0 | 0 | 0 | 1→1 | c0000000/2→c0000000/2 |
| 11 | 0 | 1 | 0 | 1→0 | c0000000/2→c0000004/3 |
| 12 | 0 | 1 | 0 | 0→0 | c0000004/3→c0000004/3 |

The CPU's genuine global-ready acceptance at edge11 permits the following address in POST. Applying hold using external-ready0 falsely rejects that measured transition. Additionally, the observer treats external `dut.reset` release at edge9 as bus reset release; actual HRESETn remains0 until POST edge10. Its accepted projection at edge9 is therefore also in the wrong reset domain.

The frozen source confirms both distinctions. `wallypipelinedsoc.sv` synchronizes `reset_ext`, connects the core to aggregate `HREADY/HRESP`, and connects `HREADYEXT/HRESPEXT` to uncore. `uncore.sv` lines195–215 selects external response/ready only when delayed external selection is active, otherwise includes the other selected slaves or HSELNoneD; delayed selects are reset/clock-enabled using the genuine bus reset/ready. The profile explicitly leaves aggregate HREADY as an observed output while binding the protocol hready role to HREADYEXT. These are separate physical signals and semantics.

This evidence establishes an observer boundary/reset-domain error. It does **not** establish a DUT hold violation. Existing hold checks must not simply be ignored or loosened to fit the sample. A subsequent source-only contract must explicitly bind genuine manager-ready and actual bus-reset roles, retain external target return separately, and declare the external-boundary scope. Further context/error semantics must remain explicit rather than inferred from a CPU name.

## Immutable archive

`evidence/cvw-ahb-native-20261017/terminal-originals.tar.gz` is the original terminal tree: **37231073 bytes**, SHA256 `55a1a8943242843d19362abb2de1087f12e54a803b18d60f03b6a3abc7c7674f`, 1132 members. It contains full control/claims/stdout/stderr/maps/tools, first/failure, both complete caches/binaries, temporary artifacts and root's preserved preflight-bytecode bytes/receipt. Both binary SHA values match the first document and archived executable bytes. The unchanged project and its original455MB preparation archive remain at the remote base and are referenced by the exact full source map/host freeze.

Original first gzip SHA256 is `2707e1ddba05ce4c92c159b04de752c2572039e42258cb7979a072b8fbf79849`. Selected original files, full archive catalog, original source-proof files/pins, raw16-edge domain table and a structured saved-failure summary are retained beside it. Root operation receipts are also preserved as a clearly scoped at-archive snapshot. No DUT/native rerun or source fix was performed during this diagnosis.

## Next gate

Root authorized only a source-only domain-contract correction, saved16-edge RED/GREEN and negative controls, strict constructor/admission versioning, then independent review. A subsequent native attempt requires an independent source snapshot and new exact GO. No source/retirement/storage authority or complete CPU prefix is granted by this failed attempt.
