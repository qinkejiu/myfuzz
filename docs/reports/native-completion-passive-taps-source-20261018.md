# Native completion passive taps: source increment

Status: source implementation only for plan248c833 stages①–③. No tests were added/run; no project import, frontend, build, model or remote operation was performed. Native session consumption/events (④–⑤), actual completion observations and fresh validation remain future gates. The historical c924aac directed run cannot inherit these new taps.

## Explicit selection and actual wires

Only canonical LocalHarnessRequestV2 tuning with the existing single raw_tick_stream record enables this increment. The native completion executor remains selected by typed protocol/capabilities, with no CPU-name branch. Native default requests gain no passive ports or changed operations/response/tick behavior.

`native_contract.py:native_completion_observation_binding` requires one declared ready-valid-memory/1 memory-master endpoint, the existing completion-no-error typed contract, exact integer widths and the actual structural ABI projection. Its six passive output taps are:

| Endpoint role (DUT direction) | Passive runtime output |
|---|---|
| valid (out1) | cpu_native_trace_valid |
| addr (out32) | cpu_native_trace_addr |
| wdata (out32) | cpu_native_trace_wdata |
| wstrb (out4) | cpu_native_trace_wstrb |
| ready (in1) | cpu_native_trace_ready |
| rdata (in32) | cpu_native_trace_rdata |

Every assignment copies `_shape`'s admitted `link_*` wire directly. No alias is guessed from port spelling and no m_rsp backend signal substitutes for native ready/rdata. Taps are outputs in protocol_tap_ports, never backend drive fields, physical inputs or fuzzable ownership. Existing physical_exports are projected unchanged from the non-adapted ABI. The instruction sideband must be the profile's declared instruction_identity_port and a unique full1bit observed output; the contract retains that exact runtime signal. No IRQ alias is added.

## Version and closed projection

The new `native_completion_observation.v1` records endpoint/clock, PRE completion predicate valid&&ready, read-zero-strobe semantics, actual instruction sideband mapping and false source-authority/retirement/generic-checker flags. Existing ip_protocol_trace_set.v1/ip_protocol_trace.v1 containers carry ready-valid-memory with protocol_taps/pre_post/cpu_physical_abi. Existing driver generation automatically includes this group in complete snapshots and conservative size bounds. Wire commands, driver tick ordering, reset, response/error paths and local_driver.v1 framing are unchanged.

`verify_native_completion_observation` requires explicit opt-in and closed metadata equality, re-renders the actual structural wrapper and the **entire** source-owned runtime without frontend admission, compares complete runtime SV and its hash, and compares runtime/backend/physical ports, selected template, wait bound and physical-observation mapping/contracts. A matching assign alongside a second assignment, a wrong m_rsp connection, duplicate/renamed port, wrong role/direction/width/clock/endpoint or bool-as-width cannot satisfy that projection. A native completion observation marker on another runtime or an unrequested native trace is refused. The native physical mapping uses aliases=[] rather than borrowing OBI IRQ facts.

Bus template cpu.native-memory@1 completion-no-error is retained because bus behavior is unchanged; this is a separately versioned observation contract. runtime_renderer and the new native_contract source are bound into implementation inputs. Changing renderer source legitimately changes artifact/CPP digest and build identity even with opt-in disabled, so this report does **not** promise whole default artifact byte equality or reuse of old binaries.

## Remaining evidence boundary

This generation/verification layer does not parse a live native completion or issue a consumed-source token. Generic IpProtocolNormalizer/Checker still has no ready-valid-memory implementation; reusing its trace container does not grant checker coverage. The next consumer must observe actual PRE native valid&&ready (distinct from earlier backend response consumption), retain real parsed receipt scope, and separately bind source snapshots; no retirement assertion follows. New frozen source, independent review, new build and actual directed/fresh gates are required before runtime success.

Source SHA256 at this freeze:

- native_contract.py: `ce526eb59042db3b993d06f08a68928f071c2321b93b315dca50f063d4caa4c2`
- runtime_renderer.py: `c429f55995d254352e382c07d996f3184e10ca1e4723084a7aa19f0e9d225d99`
- native_physical_observation.py: `edead883652a4dbdcb2cefceff589838a7868a0fcc951b404e8613f0810d9478`
