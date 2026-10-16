# P7 register-source semantics and strict candidate validation

## Changes

- New `scenario/register_source_access.py` defines `register_source_access.v1` for declared 32-bit target-word accesses. Window base/size/alignment, exact register offset/address, access alignment/width, target-lane byte enables, CPU source component/data endpoint, device/target endpoint, register/field and mask are distinct explicit fields. Write value origin is CPU transaction wdata; read value remains bound target rdata; register state stays bound target commit.
- `compiled_paths.py` F2/F4 now use exact register address singleton range and access alignment4. GPIOEN remains offset4 (never swapped to PADOUT); window alignment remains4096 in the nested contract. F2's selected PADIN is likewise exact offset8. The same access contract is included in source_constraints, so no consumer has to reconstruct offset from names. Unsupported non-word access shapes get a named declaration gap rather than an inferred adapter.
- `validate_register_candidate` recompiles the entire trusted typed declaration and compares all fields before validating a candidate; stale/edited compiled geometry/masks refuse. Requires the exact declared CPU/data endpoint, target component, address, operation and full target-word lanes15. Wrong owner/endpoint/target/register, partial lanes, bool/oversized values, reserved bits and user-driven read response refuse. A masked write without a declared merge policy also refuses. This is PURE declaration validation, not execution authorization; returned runtime_admitted is alwaysfalse, with actual writer receipt/version/checker requirements named.
- Execution feasibility now carries the exact register_access and explicit `compiled-register-writer-checker-binding-missing` reason. The former alignment ambiguity disappears. Existing candidate-window mismatch remains: compiled GPIOEN40001004 versus fixed runtime PADOUT4000100c. No D3 runtime path was enabled.

## Compatibility and limits

Capability-only D3 schema/path identities and F1..F6 capability statuses/counts remain intact for the accepted compositions (four declared executable, two unsupported). Register source geometry is deliberately more precise, so old persisted broad-window D3 documents must be recompiled; they are not silently accepted by the fresh consistency/candidate gates. Full-word target lanes are normalized target-word lanes, not an assertion about wider CPU physical bus lane positions.

No changes to OBI/Runner/renderer/driver/header/build/session, DMA, source pins or source-lock. No CPU instruction encoder or target write is called by the pure candidate validator. Exact GPIOEN writer receipt, authoritative IP-register version and compiled checker joins are not installed in the fixed runtime, so this task does NOT claim a real compiled GPIOEN fuzz candidate executed. The explicit D2-only runtime subset remains available; F1 execution still refuses missing authenticated CV32E40P retirement.

## RED/GREEN focused verification

RED: `PYTHONPATH=src python3 -m pytest -q tests/scenario/test_register_source_access.py` failed collection before the new production module existed.

Final focused:
`PYTHONPATH=src python3 -m pytest -xq tests/scenario/test_register_source_access.py tests/scenario/test_compiled_paths.py`
-> **53 passed in37.39s**; `/tmp/myfuzz-register-access-final-focused.log`.

Includes CPU/data ownership, wrong target/PADOUT address, partial write, edited geometry/mask, bound read response, reserved value bit and missing masked merge negatives. Existing source declarations/read-only/reserved source compiler checks pass. Two prior assertions were updated from broad-window geometry to exact PADIN/GPIOEN geometry; causal/refusal assertions retained.

Integration and prior chain:
`PYTHONPATH=src python3 -m pytest -xq tests/integration/test_compiled_execution_projection.py tests/integration/test_p7b_to_p7c_chain.py`
-> **10 passed in120.16s**; `/tmp/myfuzz-register-access-integration.log`.

## Meaningful actual RTL regression gate

```
MYFUZZ_GENERATED_RUNTIME_REAL=1 MYFUZZ_GENERATED_RUNTIME_CACHE=/tmp/myfuzz-register-access-real-cache MYFUZZ_GENERATED_RUNTIME_EVIDENCE=/tmp/myfuzz-register-access-evidence PYTHONPATH=/tmp/myfuzz-register-access-snapshot/src flock -n /tmp/myfuzz-register-access-snapshot/.superpowers/sdd/stage2-heavy-worker.lock python3 -m pytest -xq /tmp/myfuzz-register-access-snapshot/tests/integration/test_generated_dual_runtime_loaded_real.py
```
**2 passed in92.21s**, `/tmp/myfuzz-register-access-real.log`.

Actual pinned CV32E40P plus two GPIO processes, exact loaded D2 artifacts/nondefault reset2/3, same three processes across eight cases, blocked default _artifact reconstruction and full fresh replay match. New actual projection assertions require access_alignment4/window_alignment4096, absence of the old alignment-unresolved reason and presence of writer/checker binding refusal. The measured GPIOEN producer write (event462/value255) still has observed_case=null and is startup-only; candidate_source_certified remainsfalse. No measured startup transaction is relabeled as a compiled fuzz source.

## Isolated identity/evidence

All real execution LOCAL in frozen `/tmp/myfuzz-register-access-snapshot`, extending the earlier accepted P7 snapshot with exactly the seven owned files. Source manifest `/tmp/myfuzz-register-access-snapshot-hashes.json`. All owned production and test bytes match the successful snapshot. Normal source/artifact/post-build identity gates remain enabled; isolated heavy-worker flock held. Concurrent current-tree OBI/Runner changes are not folded into this evidence or claimed tested.

`/tmp/myfuzz-register-access-evidence/` contains complete execution-projection.json, compiled-paths.json, actual events.json/plan.json, summary.json with actual build/request/artifact identities and fresh verdict, and artifact-hashes.json. No remote action or remote validation claim.

Read-only check `git -C external_designs/cv32e40p status --short` was empty; this slice created no files in that shared submodule. Other user/agent submodule dirt was untouched. `git diff --check` passed.

Next: install exact GPIOEN candidate writer + source identity joins, IP-register version witness issuance and compiled assertion checker mappings, and explicitly declare the topology's physical bound/external sources. Only after those exist can this exact register source acquire execution admission; changing the candidate to PADOUT is not a substitute.

## Committed evidence copy

The full evidence files above are preserved as deterministic gzip under `configs/scenarios/cv32e40p-pulp-dual-gpio/evidence/p7-register-access-20261017/`; `index.json` pins original and compressed SHA256 values. Original `/tmp` files are the direct gate outputs.
