# Generated local C++ driver evidence — 2026-10-04

Based on runtime-top commit `2a02c3d`. This slice adds `driver_renderer.py` and focused driver tests; it does not change runtime tops, builders, or Python sessions. Actual Verilator builds execute original pinned CVE2 and PULP GPIO RTL. Persistent Python-session and cross-component acceptance are separate gates.

## Generation and identity

`render_local_driver(artifact, *, base_dir: Path)` consumes `status=top_only` and refreshes runtime-top/source admission before generation. A different runtime document, SV text, structure, or source snapshot is refused. The returned artifact retains its original structural/runtime SV and source verification, adds deterministic `cpp_text`, and records:

- `driver_schema_version=local_driver_generation.v1`, `status=driver_generated`, `driver_status=generated`.
- `cpp_sha256` and fresh `artifact_digest`.
- `driver_header_sources` path/SHA records for `local_driver_v1.h` and `local_command_replay.h`.
- `driver_field_map`, mapping semantic aliases to actual admitted runtime ports.
- `driver_reset={schema_version:generated_local_reset.v1,reset_assert_ticks,reset_release_ticks}`.
- `driver_limits`, including command/payload/reply/cache bounds and conservative per-command tick/receipt reservation bounds.

C++ includes `V<module_name>.h` and `local_driver_v1.h`. Build with the include root `<base_dir>/src/myfuzz/local_harness/rtl` and bare compiler definition `-DMYFUZZ_ARTIFACT_DIGEST=<final digest>`; C++ stringifies this macro. Injecting the final digest avoids a circular digest in generated C++ bytes. Builder admission must verify current header bytes, generated C++ hash, complete artifact identity, and actual compilation flags.

## Wire and snapshots

Startup performs a genuine asynchronous reset assertion edge, executes declared assertion/release cycles, then sets runtime ticks to zero. READY is `READY local_driver.v1 <digest> <assert_ticks_hex> <release_ticks_hex>`.

Strict command grammar remains `STEP_CPU` with nine fields, `STEP_GPIO` with one, and `ACCESS_GPIO` with five. The bounded C++ input reader drains oversized lines without materializing them. Wrong-runtime commands are rejected before replay admission. The shared bounded header rejects malformed fields/identity/conflicts/order and reserves reply/cache bytes before effects. Historical cached replies are returned unchanged.

RESULT contains execution, command sequence, actual before/after clocks, and lowercase hex-encoded canonical JSON. Its exact keys are `schema_version`, `kind`, `samples`, `observations`, `pre_backend`, `rdata`, `error`. Objects have sorted keys/compact separators; scalar integers use decimal. Physical values wider than 64 bits use zero-padded fixed-width lowercase hex without `0x`.

Each actual clock contributes one `{local_tick,pre,post}` sample. Snapshots contain all `backend` fields and all exported `physical` fields. GPIO adds convenience aliases `gpio_out`, `gpio_dir`, `gpio_in_sync`, `gpio_padcfg`, and native `interrupt`. `pre_backend` captures the actual backend before the first command edge after inputs are applied. CPU request acceptance and backend response completion are measured from those handshake fields; no IRQ masking or internal CPU behavior is invented.

GPIO accesses hold response-ready low until data/error are captured, then consume the response exactly once. All acceptance, APB SETUP/ACCESS, wait, and completion clocks are counted and sampled. Partial-write rejection comes from the actual APB adapter; no synthesized read/modify/write exists. CPU unsolicited responses produce identity-bearing protocol-environment errors without a clock edge. Post-effect driver failure emits an uncertain-effect receipt and terminates the process.

## Verification

TDD first run failed because `driver_renderer.py` did not exist. The first implementation run built both models and passed the CPU test; the GPIO test exposed an incorrect test expectation about status timing. The first status access captures the pending event before its read-clear edge; the next status read returns zero. The assertion was corrected to match the original RTL semantics.

Final command in the isolated worktree:

```bash
MYFUZZ_LOCAL_SOURCE_ROOT=/home/qinkejiu/myfuzz PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_driver_renderer -v
```

Result: **4 tests passed**, **0 skips**, in **26.970 seconds**. Both models were built with actual `verilator --cc --exe --build -j 1`, original source closure, generated structural/runtime tops, and generated C++. Every RESULT passed independent canonical/schema/tick validation using host `wire.py` from commit `70e237f`.

Measured GPIO evidence includes PADOUT write/readback `0xa5`, historical command-1 replay after command-2 with zero new ticks, native interrupt samples during an APB access, INTSTATUS reads `1` then `0`, 128-bit pad configuration encoded as 32 hex digits, partial-write error with unchanged PADOUT, and wrong-runtime rejection without consuming the next valid sequence.

Measured CVE2 evidence includes first instruction request at `0x10000` with one actual runtime clock and an unsolicited data-response error at unchanged runtime tick `1`. Observations include wide physical outputs from the real top. No completed program, ISA correctness, ISR servicing, or cross-component behavior is claimed by these tests.

`git diff --cached --check` passed before commit. The explicit source-root environment variable lets an isolated worktree use the existing pinned source checkout without modifying or copying its vendored RTL.
