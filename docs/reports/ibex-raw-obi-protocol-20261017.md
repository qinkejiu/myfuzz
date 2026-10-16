# Ibex CPU-side passive OBI protocol evidence — 2026-10-17

## Boundary and implementation

The generated OBI CPU runtime now exports passive observations of each actual
CPU-side bound ABI wire, before obi_processor_memory_adapter. These are15
outputs across instruction/data endpoints, separate from the existing20 beat
backend fields. Adapter req_valid/ready and rsp_valid/ready are not relabeled.

The artifact's base_protocol_traces declares ip_protocol_trace_set.v1 with two
ip_protocol_trace.v1 members, CPU physical boundary, actual endpoint/clock,
per-role names/widths, max_outstanding1 and request-specific wait bound. Its
protocol_tap_ports retain exact source_wire linkage. Generated C++ saves the
independent protocol_taps group in both pre/post snapshots; only pre-edge
samples feed protocol projection/checking. Reply capacity includes the new
sample group. The taps never drive a CPU or adapter input.

Ordinary render_local_driver admission recomputes the runtime and compares all
bytes/metadata. Build admission independently regenerates the baseline and
driver, rejecting changed tap metadata even if its artifact hash is recomputed.
A focused negative test confirms this through local_build_identity. The native
observation verifier also authenticates the trace set against actual ABI wire
bindings while preserving its previous refusal API order.

## Directed real gate

The real program executes from Ibex's observed boot fetch0x10080, stores53 at
0x20100, loads it, increments and stores54 at0x20104, then loops. The existing
CPU Session requires a router: an unreachable0x40000000 guard raises on every
call; the test asserts zero router acceptances and deliveries. It supplies no
IP response or claimed CPU/IP dataflow.

Two fresh real processes retain full original pre/post snapshots, native
execution IDs and complete artifact/build/source identities. An offline adapter
views each protocol_taps group through the two explicit endpoint configurations;
it retains native tap names and original local_tick. Generic normalizer/checker
and IpProtocolEvidenceConsumer process these views. This is separate from
Runner's still singular protocol-trace integration; it does not promote Runner
multi-endpoint execution, online mutation or dependency/dataflow certification.

A projected response-value tamper is compared against the same saved original
CPU-side raw taps and cannot certify that endpoint. Genuine certificates remain
historical protocol-boundary evidence without invented OBI transaction IDs.

Final command uses the repository's **unified** remote lock:

```sh
cd /root/fanzehui/system-20261016/project
. /root/fanzehui/system-20261016/environment.sh
flock -n /root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock env \
 MYFUZZ_OBI_TAPS_REAL=1 \
 MYFUZZ_OBI_TAPS_CACHE=/root/fanzehui/system-20261016/cache/obi-taps \
 MYFUZZ_OBI_TAPS_EVIDENCE=/root/fanzehui/system-20261016/evidence/ibex-obi-taps-20261017 \
 python3 -m pytest -q tests/local_harness/test_obi_cpu_protocol_taps.py --tb=short
```

Final result: **2 passed in68.50s**, real Verilator RTL under the unified lock.
Each fresh process retained100 original edge snapshots and produced52 verified
protocol certificates:49 instruction and3 data. The100-edge cutoff leaves2
instruction requests pending (one granted and one offered); the trace is not
claimed to be drained. Checker violations and normal-proof diagnostics are
empty. A tampered instruction response causes projection_mismatch and leaves
only the3 unaffected data certificates; it does not invalidate unrelated
endpoint history. Fresh complete snapshots/projections/build identities match,
while execution IDs differ.

Original artifact/first/fresh JSON is committed as deterministic gzip in
`docs/reports/evidence/ibex-raw-obi-20261017/`; summary.json pins compressed and
uncompressed SHA256s. Independently rerunning the current generic consumers on
the original saved protocol_taps reproduces the complete normal and tampered
reports, including all3 data certificates. All304 host-source SHA256s matched
the current local tree when these results were checked (zero stale files).
Artifact digest:758f53bfa6cdc5296cf2f7aaa71bdac8d4cb491b3a09f99ca9585565dc19f55f.
Build digest:845b89a0e7dae1c74d0d33d078bc51a510f0a09ee58f3766acb273c4eaa7ba46.
Remote original files/log remain in the path from the command above.

Two preliminary attempts failed before build/RTL on fixture constructor
requirements (router mandatory and non-None); they used the wrong workspace
lock path and are not acceptance evidence. No concurrent heavy workload ran;
the final command above uses the agreed project/.superpowers lock.

## Local checks and remaining work

Final CPU Session/raw stream/native observation/tap-generation and ordinary
build-admission rehashed-metadata regression: **57 passed,2 skipped in42.36s**.
The two skips are existing and new explicit real gates; the new Ibex real gate
was separately enabled above. Renamed-instance protocol reuse and existing Wishbone CPU execution regression:
**2 passed,5 subtests passed in21.47s**. The raw OBI event semantics themselves
were previously tested in d4f9d20 (224 passed,67 subtests).

Real source/build evidence is scoped to the saved input identity. Subsequent
shared-host changes do not inherit it. Full Runner multi-endpoint integration,
CPU/IP transaction join, interrupt causality, continuous search, fault
confirmation and authenticated scenario-prefix replay remain pending.
