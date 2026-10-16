# P7 continuation: exact execution downgrade with actual producer evidence

## Result

No complete D3 path can honestly be mapped to the fixed CV32E40P dual-GPIO runtime in this bounded slice. No execution authorization was added. Instead the new machine-readable execution-feasibility stage reports **4 capability-declared executable paths, 0 execution-supported paths**. All four execution records are `status=unsupported`, `runtime_admitted=false`. F1 explicitly refuses absent authenticated retirement observation; capability-only D3 is preserved as requested and does not become a runtime license.

The prior explicit D2-only execution subset remains operational: a new isolated real gate ran the same eight continuously hosted CPU/GPIO cases and full fresh replay. Actual producer receipts are attached to the negative projection without being promoted to compiled-candidate authority.

## Concrete F4 alignment, and why no false positive was allowed

D3's chosen CPU MMIO source is `gpio_a.GPIOEN.value.mmio`. The profile's actual register map says GPIOEN offset=4, window base=0x40001000, so exact target address=0x40001004. The loaded GPIO artifact's native bus outputs/source verification/fingerprint/digest identify the real producer. The fixed runtime decoder's only MMIO candidate window is PADOUT at 0x4000100c, size4. Thus the source/constraint mapping is NOT equivalent.

The actual real prefix DOES contain GPIOEN write at event462, value255. Its provenance has observed_case=null (fixed startup), not a fuzz candidate. New real assertions require that distinction and leave candidate_source_certified=false. A matching producer transaction is not sufficient to claim the declared compiled fuzz source executed.

A second precise ambiguity: D3's register source carries alignment4096 (window alignment). The actual GPIOEN address+4 does not satisfy that as an access alignment. The feasibility report names `compiled-register-address-alignment-unresolved`, preserves the original constraint, and requires separate window/access alignment semantics. It does not silently rewrite alignment to4 or discard masks/ranges.

F4 also lacks explicit compiled source id, bound-producer delivery, ip_register_version prerequisite handler and per-assertion checker joins. No seed exists for this F4 path; a default bootstrap is not invented as its seed. F1 has a seed but no mapped seed executor or authenticated retirement observation. F2/F3 have similarly located missing obligations.

## Owned implementation

- NEW `src/myfuzz/local_harness/compiled_execution_projection.py`: recompiles/checks supplied D2/D3 through unchanged strict consistency admission; edited input returns input_refused with no path analysis. Exact request/profile/register/window/ABI resolution, declared runtime candidate-window comparison, source/bound/prerequisite/seed/checker missing mappings and actual diagnostic delivery attachments. Even forged caller handler tables or a caller's claim of retirement cannot install an executor or grant permission. All paths remain unsupported. It never starts RTL.
- Existing Ibex/CV32E40P online modules expose `describe_generated_execution`: facts from their actual fixed decoder, with no implicit optional RVFI selection and no claim of implemented compiled handlers.
- `auto_harness_test.py`: explicit RuntimeFamily execution_declaration pointer (not profile-name inference). Before a requested D4 live attempt, writes `execution_projection.v1.json`, records stage execution_status=unsupported/support-count0, then retains existing strict admission refusal. No D4 default reconstruction or fallback.
- New focused projection/CLI tests; existing gated D2 real test additionally evaluates projection against the just-measured actual prefix and proves matching GPIOEN writes are startup-only.

No raw capability compiler, source pins, renderer, driver, template, header, build, session or DMA files were modified by this slice. generated_execution_admission.py was not modified. This bounded downgrade retains the earlier D2-only gate while reporting why full D3 execution is unavailable.

## Verification

RED before production module: new test failed import with missing compiled_execution_projection. Focused GREEN:
```
PYTHONPATH=src python3 -m pytest -q tests/integration/test_compiled_execution_projection.py tests/integration/test_auto_harness_test.py
```
**20 passed in97.13s**; `/tmp/myfuzz-p7-d3-feasibility-focused.log`.

Additional actual CLI invocation test:
`PYTHONPATH=src python3 -m pytest -xq tests/integration/test_compiled_execution_projection.py -k cli`
**1 passed,2 deselected in15.89s**; `/tmp/myfuzz-p7-d3-projection-cli.log`.
It exercises full D1/D2/D3 against CV32E40P, writes execution_projection.v1.json with4/0 and F1 unsupported, then refuses `compiled-runtime-input-refused` BEFORE creating a session or executing its dummy client. This is not a successful D3 runtime run.

Final isolated actual RTL gate:
```
MYFUZZ_GENERATED_RUNTIME_REAL=1 MYFUZZ_GENERATED_RUNTIME_CACHE=/tmp/myfuzz-p7-d3-projection-real-cache MYFUZZ_GENERATED_RUNTIME_EVIDENCE=/tmp/myfuzz-p7-d3-projection-evidence PYTHONPATH=/tmp/myfuzz-p7-d3-projection-snapshot/src flock -n /tmp/myfuzz-p7-d3-projection-snapshot/.superpowers/sdd/stage2-heavy-worker.lock python3 -m pytest -xq /tmp/myfuzz-p7-d3-projection-snapshot/tests/integration/test_generated_dual_runtime_loaded_real.py
```
**2 passed in90.40s**; `/tmp/myfuzz-p7-d3-projection-real.log`.
It retains exact loaded artifacts/nondefault reset2/3, blocks default _artifact reconstruction, keeps all three actual process PIDs across eight source cases, then full fresh replay matches. Four instruction cases/four external-pin cases; eight no-violation running receipts; 4021 actual events; CPU313/GPIOA345/GPIOB337 final local ticks. No D3 path is certified by this result.

## Source identity and retained evidence

Real execution was LOCAL, not remote. Frozen `/tmp/myfuzz-p7-d3-projection-snapshot` extends the prior already validated isolated snapshot with exactly the owned production/test changes. CV32E40P and GPIO source working files and independent Git metadata are present under that snapshot. All normal D2 loader/source checks, captured build identities and post-build input checks remain intact. Isolated heavy-worker flock was held; no remote action.

Manifest `/tmp/myfuzz-p7-d3-projection-snapshot-hashes.json`; all production files and actual gated real test bytes match successful snapshot. One subsequent software-only CLI unit test was added and verified in current tree; it does not alter real execution code.

Evidence `/tmp/myfuzz-p7-d3-projection-evidence/`:
- execution-projection.json: complete 4→0 downgrade; F1 seven refusals, F2 nine, F3 six, F4 ten, actual register producer ABI/source identities and event462 startup evidence
- summary.json: exact artifact/request/build identities, eight raw inputs/receipts, full fresh=true verdict and local ticks
- events.json/plan.json: entire measured prefix/saved plan
- compiled-paths.json: unchanged capability-only D3 document
- artifact-hashes.json: SHA256 evidence manifest

`git diff --check` passed.

## Next bounded work

First make register-stream address semantics explicit in D3 (exact offset, access vs window alignment, field mask and supported lanes) without replacing the source with the existing PADOUT fixture. Add explicit physical binding/environment declarations to D2/D3 for this topology. Then implement an actual generated candidate/seed adapter for that exact selected register, authoritative ip_register_version witnesses, and exact compiled assertion/checker joins. F1 additionally requires an authenticated CV32E40P retirement observer; physical fetch or OBI acceptance cannot substitute for retirement. Until these exist D3 execution remains refused, while explicitly selected D2-only runtime stays available. No continuous search, generic full D3 execution or P7 completion is claimed.

## Committed evidence copy

The full evidence files above are preserved as deterministic gzip under `configs/scenarios/cv32e40p-pulp-dual-gpio/evidence/p7-d3-execution-20261017/`; `index.json` records original and compressed SHA256 values. Original `/tmp` files are the direct gate outputs.
