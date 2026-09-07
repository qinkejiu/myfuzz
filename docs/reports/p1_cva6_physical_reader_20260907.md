# P1 CVA6 Physical Evidence Reader Report

## Scope

This gate reads compiler-produced physical port facts from the actual `cva6`
module at upstream revision
`2e1336dcff3d1a0b49fbe6282b97802f32ea32af`. It does not claim CPU execution or
protocol correctness.

## Bounded artifact

- Verilator tree: 28 MiB, 2,650,008 JSON structure tokens.
- Traversed JSON objects: 1,361,725.
- Frontend peak sampled RSS: 217,231,360 bytes.
- Production limits: 64 MiB JSON bytes, 3,000,000 structure tokens,
  1,500,000 traversed objects, and 768 MiB hard process RSS.

The reader now follows packed enum base types while retaining the compiler
base width and signedness. It recursively validates packed arrays whose element
is a packed structure and exposes such an array only as one aggregate member
when it is nested under a named structure member. It does not invent indexed
member paths. Structured enum bases and unpathed top-level aggregates remain
unsupported.

## Actual CVA6 result

The retained production parse completed in about two seconds and returned all
13 top-level ports. The structured outputs and inputs include:

- `rvfi_probes_o`: 6974 bits, 88 member facts.
- `cvxif_req_o`: 449 bits, 17 member facts.
- `cvxif_resp_i`: 178 bits, 14 member facts.
- `noc_req_o`: 470 bits, 32 member facts.
- `noc_resp_i`: 210 bits, 13 member facts.

The measured structured-array case `rvfi_probes_o.csr.pmpcfg_q` is represented
as one 512-bit aggregate at raw bits `[5171:4660]`.

## Verification

- Reader RED/GREEN logs:
  `runs/p1_elaboration_probe_20260907/task6a-red.log`,
  `task6a-green.log`, `task6a-array-red.log`, and
  `task6a-array-green.log`.
- Real artifact result:
  `runs/p1_cva6_module_20260907/reader-production.log`.
- Reader, runner and crawler regression: 77 tests passed in 5.598 seconds;
  `runs/p1_cva6_module_20260907/task6a-regression.log`.

The remaining frontend gate keeps strict warning behavior by default. The
actual upstream configuration emits 464 warnings, so a later explicit policy
must record the complete warning stream before accepting the generated JSON.
