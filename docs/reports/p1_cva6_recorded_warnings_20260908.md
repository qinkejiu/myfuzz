# P1 CVA6 Recorded Warning Frontend Report

## Result

The bounded Verilator frontend now has an explicit `recorded-nonfatal` warning
policy. Its default remains fatal. The opt-in mode adds `-Wno-fatal` and accepts
physical evidence only after validating a complete machine-readable summary of
the full merged diagnostic stream.

For the fixed CVA6 revision
`2e1336dcff3d1a0b49fbe6282b97802f32ea32af`, the production runner completed in
about five seconds with return code 0 and extracted all 13 top-level ports.
Sampled peak RSS was 234,721,280 bytes over 29 samples.

The full diagnostic stream was 288,861 bytes. Human-readable retention was
truncated at 64 KiB, while streaming evidence recorded 464 warnings and zero
errors:

| Class | Count |
| --- | ---: |
| ASCRANGE | 101 |
| CMPCONST | 2 |
| IMPLICITSTATIC | 1 |
| SELRANGE | 61 |
| UNSIGNED | 3 |
| WIDTHEXPAND | 219 |
| WIDTHTRUNC | 77 |

The run manifest retains the raw-stream SHA-256 and byte count for audit. Those
path-sensitive values do not enter stable source identity; identity retains the
explicit policy and sorted warning class counts.

## Failure boundaries

The runner rejects nonzero exit, any `%Error` record, incomplete line parsing,
malformed or oversized summary JSON, invalid warning class names, more than
1024 warning classes, inconsistent counts, source/tool changes and malformed
compiler evidence. Warning names are bounded to 128 uppercase alphanumeric or
underscore characters. The producer applies the same bounds before writing the
summary.

## Verification

- Interface description, reader, runner and crawler: 92 tests passed in 7.078
  seconds. Log: `runs/p1_cva6_module_20260908/task6b-final-regression.log`.
- Actual CVA6 summary:
  `runs/p1_cva6_module_20260908/recorded-result.json`.
- Full retained run manifest:
  `runs/p1_cva6_module_20260908/recorded-manifest.json`.
- Independent review: PASS after closing path-independent identity, overlong
  line and nonzero error-count findings.

This gate proves auditable frontend physical evidence. It does not establish
CVA6 protocol behavior, execution correctness or RFuzz feedback.
