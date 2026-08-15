# RFuzz Verilator Compatibility Design

## Context

The Task 5B native RFuzz campaign failed before the first fuzz result was
published. The current environment selected Verilator 5.051 devel. The
generated native server aborts while constructing/evaluating the model because
the vendored RFuzz `sc_time_stamp()` hook assumes that an active test already
exists. The same RTL, TOML, fuzzer, and FIFO protocol run continuously with the
repository's preserved Verilator 5.020 server artifact.

The repository already contains the RFuzz-compatible Verilator 5.020 toolchain
at `third_party/rfuzz/upstream/.tools/apt-root/usr/bin/verilator`. Existing
native RFuzz identity records already include the selected binary and exact
version, but the default resolver still points at a stale 5.042 location and
then silently falls back to the process `PATH`.

## Decision

Native RFuzz builds and campaign identity generation will use the bundled RFuzz
toolchain as the default:

`third_party/rfuzz/upstream/.tools/apt-root/usr/bin/verilator`

An explicit `MYFUZZ_SERVER_VERILATOR_BIN` environment override and existing
command/configuration overrides remain supported. Every selected executable is
probed before identity calculation or server construction, and the exact
reported version is recorded in the derived config and build sidecar. A
declared version or identity mismatch remains a hard error.

The default resolver will no longer silently select an unrelated `PATH`
Verilator when the RFuzz-compatible bundled toolchain is absent. It will fail
with an actionable message explaining the required bundled executable or the
explicit override. This keeps a missing dependency distinct from an
incompatible compiler and prevents invalid campaign data from being produced.

The vendored RFuzz C++ runtime will not be changed. Its timing limitation is
the compatibility boundary being protected by this change, not behavior to
paper over in the runtime.

## Components and Data Flow

1. `run_design_flow.py` resolves the native RFuzz compiler using the explicit
   override first, then the bundled 5.020 path. It validates the executable and
   probes its version before building or validating a server artifact.
2. `run_static_projection_campaign.py` uses the same resolver policy when
   computing each derived config's native input identity. The resulting config
   contains the bundled path and exact version, so later server and fuzz stages
   cannot drift to another compiler.
3. Existing `native_input_identity()` hashing continues to include the compiler
   path, compiler digest, and version. No campaign result is accepted when the
   selected native inputs differ from the planned identity.
4. The compatibility server build command remains single-worker and otherwise
   unchanged.

## Error Handling

- An explicit override is authoritative, but its executable must be usable and
  its observed version must match any declared version.
- If no override is provided and the bundled executable is missing, resolution
  raises a clear dependency error instead of returning `verilator` from `PATH`.
- Existing artifact identity/version checks remain fail-closed.
- A server crash or FIFO failure is still classified as infrastructure failure;
  it is never interpreted as a DUT crash or policy result.

## Testing

Tests will cover:

- default resolution of the bundled RFuzz 5.020 path;
- explicit environment override precedence;
- failure when the bundled executable is missing and no override is given;
- campaign identity/config recording of the resolved path and version;
- preservation of existing artifact version mismatch rejection.

After the tests pass, verification will rebuild one native artifact with the
bundled compiler, run a bounded native smoke using the real kfuzz binary, and
confirm FIFO cleanup, zero server/fuzzer return codes, and the expected
5.020 version in the artifact sidecar before restarting the Task 5B campaign.

## Scope

This change is limited to native RFuzz compiler resolution and its tests. It
does not alter projection policies, candidate manifests, RTL, RFuzz protocol
semantics, or campaign promotion thresholds.
