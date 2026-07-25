# Ibex + OpenTitan Real Common-IP Coverage Target

## Objective

Replace the local `ibex_mcip_uart`, `ibex_mcip_gpio`, and
`ibex_mcip_timer` proxy models in the coverage experiment with the real
OpenTitan UART, GPIO, and RV timer RTL. The resulting target must run Ibex and
the three OpenTitan IP blocks as one system and support a fair baseline versus
dependency-aware RFuzz comparison.

The existing proxy experiment and its results remain historical artifacts, but
must be labelled as proxy-only and must not be reported as OpenTitan coverage.

## Source Provenance

Use the repository's existing OpenTitan submodule at commit
`13a8919bceac625dbd1b6ad804e62f9bdeadee86`. The target must instantiate the
official `uart`, `gpio`, and `rv_timer` top modules and include the official
dependency closure required by their core descriptions, including generated
register packages/tops and required `prim` and `tlul` RTL.

Do not copy or rewrite the IP behavior into local stand-ins. Local RTL is
limited to system integration components that OpenTitan does not provide for
the Ibex OBI-facing experiment: an OBI-to-TL-UL adapter, address routing,
memory endpoint, reset/clock plumbing, and the RFuzz harness.

## System Architecture

The target contains:

- one upstream Ibex core;
- one OpenTitan UART;
- one OpenTitan GPIO;
- one OpenTitan RV timer;
- a deterministic instruction/data memory containing a small MMIO exerciser;
- a generic OBI-to-TL-UL adapter and one-to-three address router;
- baseline and dependency-aware RFuzz harnesses around the same system top.

Ibex boots from the local memory and repeatedly reads and writes the three MMIO
regions. Peripheral interrupts feed the Ibex interrupt inputs. External UART,
GPIO, timer, memory-response, and error stimuli come only from the RFuzz raw
input vector or deterministic reset defaults.

SPI is outside this target. Adding SPI would expand the first implementation's
dependency and behavioral surface without helping establish that real
OpenTitan common IP can run in the comparison framework.

## Bus and Data Flow

Instruction fetches terminate at local memory. Data accesses to the RAM region
also terminate locally. Peripheral MMIO accesses pass through the generic
OBI-to-TL-UL adapter and are routed by non-overlapping, word-aligned address
regions to exactly one OpenTitan IP.

The adapter holds request fields stable until TL-UL acceptance and converts the
TL-UL response into Ibex grant/read-valid/error semantics. The router permits
one outstanding transaction, routes the response back to the adapter, and
returns a deterministic error response for unmapped addresses. These bounded
rules avoid hidden queues and keep memory use predictable.

The target exposes observation outputs for architectural progress, selected
MMIO activity, interrupt state, and IP response activity. Coverage is still
collected solely from the instrumented RTL; observation outputs do not replace
coverage points.

## Comparison Contract

Baseline and dependency-aware runs must share:

- the exact same OpenTitan and Ibex source revisions;
- the exact same system top and instrumented coverage vector;
- the same raw input width, campaign seeds, RFuzz build, and run duration;
- the same MMIO exerciser image and reset sequence;
- the same server and process-memory limits.

Only the raw-input projection differs. Baseline maps fixed raw slices directly
to exposed environment fields. Dependency-aware projection may enforce declared
protocol relations, such as valid/ready transaction coherence, aligned MMIO
addresses, bounded response latency, and mutually consistent error/response
signals. It must not inspect DUT outputs to choose future fuzz input and must
not use directed instruction templates that differ from the baseline.

Coverage percentages may be compared only after both runs prove an identical
coverage width and instrumentation identity. Reports include covered points,
coverage percentage, direct-only/depaware-only/overlap sets, throughput,
duration, and peak process-tree RSS.

## Dependency and Build Strategy

Resolve the minimal synthesizable source closure from the pinned OpenTitan core
metadata and store a deterministic repository-relative file list for the
target. Use Verilator with bounded build parallelism (`-j 1` for the heavy
server build). Missing generated packages, duplicate modules, unsupported
assertion constructs, or unresolved parameters are build failures; they must
not be bypassed by substituting local behavioral modules.

The OpenTitan submodule is an external dependency. Preflight reports a clear
dependency-unavailable result when it is absent or at the wrong revision.

## Failure Handling

The build stops on source-provenance mismatch, missing dependency files,
Verilator lint/elaboration failure, mismatched coverage universes, or a server
smoke failure. Runtime reporting distinguishes clean completion, fuzzer/server
failure, timeout, and memory termination. A failed or partial campaign is not
presented as a valid coverage comparison.

The integration shall keep the previous proxy target separately named. New
artifact names use an explicit real-OpenTitan target identifier so that proxy
and official-IP results cannot be confused.

## Verification and Acceptance

Acceptance requires:

1. Tests proving the target source list resolves to the pinned OpenTitan tree
   and contains official UART, GPIO, RV timer, `prim`, and `tlul` RTL.
2. Tests proving none of the three local `ibex_mcip_*` peripheral proxy modules
   appears in the real-OpenTitan target source list or hierarchy.
3. Verilator lint/elaboration of the complete system top.
4. Successful RFuzz-compatible server build and bounded smoke campaign for both
   harnesses.
5. Identical coverage width and instrumentation identity across baseline and
   dependency-aware variants.
6. A short coverage run that records nonzero execution, coverage, and process
   memory for both variants before any longer campaign is launched.
7. Existing project tests and formatting checks remain passing.

The implementation is complete when these checks pass and the produced report
unambiguously identifies the OpenTitan commit and official IP modules used.
