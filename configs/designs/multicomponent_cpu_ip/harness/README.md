# Harness Files

Planned files:

```text
multicomponent_cpu_ip_baseline_direct_slice_harness.sv
multicomponent_cpu_ip_depaware_projection_harness.sv
```

The baseline harness must fixed-slice `rfuzz_input_bits` directly into target
inputs. The dependency-aware harness must use the same raw input width and the
same target, but can project fields according to the manifest rules.

Both harnesses currently use:

```text
rfuzz_input_bits width: 256
__vi_coverage width: 102
```

The coverage width comes from a source-branch instrumentation probe over the toy
RTL. If the RTL changes, rerun instrumentation and update both harness output
ranges before building RFuzz servers on the remote machine.
