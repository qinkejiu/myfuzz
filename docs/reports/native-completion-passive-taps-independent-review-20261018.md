# Native completion passive taps: independent source review

Reviewed freeze: `a57f4d2cc8e16495d3840b3d30103db580374559`.
Verdict: **no Critical or Important source defect found in generation/admission
stages①–③**. This does not approve live native session consumption or execution.

The reviewer read the three changed modules, their public admission/render
callers, existing driver snapshot/bounds generation, wire parsing, Runner raw
sampling and trace-set dispatch. No project import, test, probe, frontend,
build, native process or remote command was executed.

## Checks supporting the scoped verdict

- Opt-in requires canonical v2 `raw_tick_stream` alone. Native protocol shape
  and typed completion capabilities select the path, without CPU-name matching.
- `_shape` binds six exact endpoint roles/directions/widths/spans to real ABI
  `link_*` wires. Added ports are passive outputs; ready/rdata come from CPU
  native boundary wires, never substituted backend response signals.
- Instruction identity is the declared unique full one-bit observed output in
  unchanged non-adapted exports. A native bus role or backend alias cannot
  satisfy that marker selection. Native physical mapping adds no IRQ aliases.
- Verifier re-renders the structural wrapper and the complete admitted runtime
  projection, comparing full SV/hash and the relevant port, clock, template,
  bound and observation metadata. This catches extra drivers or matching assigns
  alongside incorrect wiring. The pure renderer calls the binding helper, not
  this verifier, so there is no verifier recursion or repeated frontend call.
- Existing driver generation includes every protocol_tap_ports entry in PRE/POST
  snapshot and conservative maximum payload sizing. Taps are not backend drive
  fields. This is emission/admission wiring, not a typed live sample validator.
- Disabled opt-in adds no new ports or changed drive/tick/reset semantics.
  Renderer/source identity changes still require fresh artifact/build admission;
  no historical binary or whole-artifact/CPP equality is inherited.
- Observation contracts explicitly decline generic checker, source and
  retirement authority. The preserved template version describes unchanged
  bus behavior; the passive observation itself has its own versioned contract.

## Explicit remaining integration blocker

Runner's `_protocol_trace_set` creates `ProtocolTraceSetObserver` when a session
with `base_protocol_traces` enables physical tick sampling. Its constructor
currently calls `verify_cpu_obi_protocol_traces` unconditionally, so this native
artifact would be refused through that route. Current native session also has
no native drain/tick-stream consumer implemented in this increment.

Stages④–⑤ must therefore provide an explicitly admitted native raw/receipt
consumer and dispatch, preserve all new group fields and exact values, and
avoid the OBI-only trace-set observer. Do not suppress verification or pretend
the generic IpProtocolNormalizer/Checker supports ready-valid-memory. This is
an unimplemented next-stage requirement, not a demonstrated live pass or a
reason to weaken the scoped metadata contract.

## Reviewed source pins

- native_contract.py: `ce526eb59042db3b993d06f08a68928f071c2321b93b315dca50f063d4caa4c2`
- runtime_renderer.py: `c429f55995d254352e382c07d996f3184e10ca1e4723084a7aa19f0e9d225d99`
- native_physical_observation.py: `edead883652a4dbdcb2cefceff589838a7868a0fcc951b404e8613f0810d9478`

Next evidence must come from the actual verified receipt hook and source
snapshot join, actual PRE native valid&&ready, new source/build identities,
negative controls and whole cold/warm fresh replay. Saved backend-only raw data
cannot mint a live CPU-consumption or retirement authority. P6 remains open.
