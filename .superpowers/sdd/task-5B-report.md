# Task 5B Implementation Report

## Status

Implementation complete; independent specification and code-quality reviews pending.

## Summary

- Replaced the unavailable private `rfuzz_flow.tools` dependency with a repository-native integration over the vendored original RFuzz `top.cpp`, `fpga_queue.cpp`, `fpga_queue.hpp`, and `kfuzz` artifacts.
- Materialized a validated wrapper, DUT header, augmented TOML, and exactly one raw candidate ABI fragment per harness artifact.
- Bound coverage explicitly through `candidate.dut.__vi_coverage` and used the selected top's propagated coverage width as the logical universe.
- Accepted only exact logical or RFuzz-aligned bitmap widths, validated every byte, and ignored only the physical alignment tail.
- Kept Verilator server compilation at one worker under descendant RSS monitoring and the configured hard memory limit.
- Added `-Wno-fatal` after a real Ibex build proved that 1361 existing RTL/instrumentation warnings otherwise terminate elaboration; genuine Verilator errors remain fatal.

## TDD Record

All commands ran from `/home/qinkejiu/myfuzz/.worktrees/integration` with `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:.`.

### Native original RFuzz boundary

Initial RED cases covered missing fixed original RFuzz files, absent native materialization, invalid candidate ports/inner instance, ambiguous ABI fragments, selected-top coverage binding, aligned bitmap width, and fixed single-worker construction.

GREEN focused suite:

```text
python3 -m unittest tests.test_original_rfuzz_native tests.experiments.test_rfuzz_adapter tests.harness.test_flow_integration tests.integration.test_rfuzz_runner -v

Ran 77 tests in 2.859s
OK
```

### Candidate source inclusion

The first real preflight exposed unresolved candidate hierarchy because the generated candidate source was not present in the Verilator command. The regression test first failed with:

```text
TypeError: build_server_command() got an unexpected keyword argument 'candidate_source'
```

After forwarding the validated raw ABI source, the focused case passed and the real build resolved `candidate.dut.__vi_coverage`.

### Existing warning policy

The second real preflight reached Verilator but failed with:

```text
%Error: Exiting due to 1361 warning(s)
```

The command test was extended first and failed because `-Wno-fatal` was absent. After adding the option, the same test passed and the same real preflight completed successfully.

## Real Preflight Evidence

Command:

```text
python3 src/myfuzz/scripts/run_design_flow.py --config runs/static_projection/smoke_20260727_1137/derived/ibex_opentitan_real_ip/policy-4b42539dd9898e9a/config.json --stage server --jobs 1 --candidate-mode candidate_direct --server-artifact-id sha256:344209b1754fd66658864bfb13e470cf385cbc435ba84aff77f98e4363dec76c --hard-memory-bytes 7000000000 --result-json runs/static_projection/preflight_task5b/ibex_candidate_direct_build.json
```

Observed result:

```text
artifact_id: sha256:344209b1754fd66658864bfb13e470cf385cbc435ba84aff77f98e4363dec76c
server_exists: true
server_size: 1089176 bytes
peak_rss_bytes: 493830144
resource_terminated: false
```

## Verification Note

One full 656-test run had a single timeout-sensitive failure in the unrelated reference FIFO isolation test immediately after the large Verilator build. Its isolated rerun passed in 0.181 seconds. A clean full-suite rerun then passed:

```text
python3 -m unittest discover -v

Ran 656 tests in 10.347s
OK
```
