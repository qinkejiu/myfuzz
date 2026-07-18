# Frozen AXI-Lite Qualification Dataset

This directory is the offline Slice H qualification input. `oracle.json` is the
frozen denominator. It records qualified and permanently rejected candidates,
the complete CPU x IP compatibility matrix, two multi-IP cases, family-level
80/20 assignments, resource budgets, provenance, licenses, and every source,
wrapper, filelist, and transitive include hash.

Regenerate or verify it without network access:

```sh
PYTHONPATH=src python3 materials/qualification/axi_lite/freeze_oracle.py
PYTHONPATH=src python3 materials/qualification/axi_lite/freeze_oracle.py --check
```

Qualification must use the checked-in `upstream/` mirror. It must never fetch a
floating branch or silently replace a missing file from the network. A separate
cache may contain archives named by the `archive_sha256` values in `oracle.json`,
but cache restoration must reproduce every checked-in content hash before use.
Moving a family between splits, changing a rejection, or updating an upstream
revision creates a new oracle version and a new denominator.

## Run Qualification

Build both real multi-IP SoCs and run a short non-acceptance smoke:

```sh
PYTHONPATH=src python3 -m myfuzz.builder.qualification_pipeline \
  --oracle materials/qualification/axi_lite/oracle.json \
  --materials-root materials \
  --output build/qualification/axi_lite \
  --jobs 2 \
  --smoke
```

Omit `--smoke` to run the frozen acceptance denominator: 10 seeds, 256 cycles,
two cases, and both RAW and CONSTRAINED modes. A valid acceptance report at
`build/qualification/axi_lite/qualification_report.json` has
`full_denominator: true`, 40 runs, and `acceptance.pass_rate: 1.0`. The two
case directories contain the generated SoC RTL, full filelist, analysis and
instrumentation evidence, compiled Verilator target, RawBits v2 testcases,
per-cycle coverage traces, and deterministic replay reports.

The experiment reports whether the measured data supports a plateau-reduction
claim. Qualification success does not imply such an improvement.

## Retention and Distribution

- Preserve upstream notices and the complete license files under `upstream/`.
- Preserve SPDX headers and modification comments in wrappers. Wrapper hashes
  are recorded as provenance patches; changing one invalidates the oracle.
- Generated SoC and Harness files that merely instantiate or connect upstream
  modules remain separate generated files. Distribute them with this NOTICE and
  every license applicable to the included source set.
- Instrumented copies are modified derivatives. Keep the original notice and
  license, retain the instrumentation provenance manifest, and mark each changed
  file as modified when distributing it.
- Compiled simulation targets must retain `NOTICE.md`, the applicable license
  texts, the frozen oracle digest, and the source/instrumentation manifests.
- Rejected local candidates are denominator evidence only and are not eligible
  for qualification target distribution through this dataset.

This policy is an engineering retention rule, not legal advice. Material whose
license hash, provenance, or redistribution approval cannot be verified fails
qualification before elaboration.
