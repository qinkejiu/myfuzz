# Generated CPU protocol reuse audit (2026-10-04)

The generated runtime selector uses endpoint protocol, function, field shape, and typed capabilities. It does not select a CPU by component ID or source path. The five paths below each planned a pinned source, verified its source lock, rendered a structural wrapper, rendered the runtime top, and generated a driver using an instance name different from the existing acceptance tests. A renamed Wishbone instance also built and ran real RTL, fetched instructions, and stored `0x12345678` in persistent RAM.

| Protocol path | Current pinned top | Admitted variant | Renamed instance evidence | Other RTL with same protocol |
| --- | --- | --- | --- | --- |
| OBI | `cve2_top` | Two 32-bit masters: read-only instruction and read/write data; grant then response; error pins; one external IRQ input | `reuse_obi` driver artifact | No second pinned OBI CPU profile tested |
| Native completion memory | `picorv32` | One 32-bit byte-addressed completion port; one outstanding; no error pin; RAM/ROM service; optional typed instruction observation | `reuse_native` driver artifact | No second pinned native CPU profile tested |
| Wishbone classic | `picorv32_wb` | One 32-bit byte-addressed master; no `ERR` or `STALL`; one outstanding; observed one-bit instruction marker required to classify fetches | `reuse_wishbone` driver artifact and real fetch/store | No second pinned Wishbone CPU profile tested |
| AXI4-Lite | `picorv32_axi` | One 32-bit master; no physical response-code pins; one outstanding; RAM/ROM completion adapter | `reuse_axi_lite` driver artifact | No second pinned AXI4-Lite CPU profile tested |
| Full AXI4 | `zipaxi` | Separate 32-bit instruction/data masters; 1-bit IDs; five independent channels; FIXED/INCR/legal WRAP bursts; RAM service; exclusive accesses rejected | `reuse_axi4` driver artifact | No second pinned full AXI4 CPU profile tested |

The Wishbone service previously read an output named `mem_instr` directly and silently treated a missing output as a data transfer. The profile now declares `instruction_identity_port`, the runtime artifact resolves it to a verified observed one-bit output, and the service uses that artifact field. A Wishbone profile without a valid marker is rejected at rendering. The physical pin name remains in the pinned PicoRV32 profile, where its meaning can be reviewed alongside source evidence.

The OBI session class retains the historical name `GeneratedCve2Session`; its admission checks `obi_cpu` artifact kind and operates on generated `i_`/`d_` backend ports. The other services likewise use runtime kind and instance identity. The current generated shapes and service policies are finite variants. This audit does not claim that any unprofiled CPU with the same protocol is supported. A new RTL top must be source locked, have every physical port classified, and satisfy the row's admitted shape and typed semantics before reuse can be claimed.

Focused acceptance:

```sh
PYTHONPATH=src python3 -m unittest tests.local_harness.test_cpu_protocol_reuse -v
```
