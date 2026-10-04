# Versioned Local Protocol Template Contracts

Based on main `2a02c3d4b9237171562a76e09a27a443fa8c0862`. The immutable registry selects contracts from declared protocol, endpoint function, resolved semantic roles/directions/physical spans/widths, and typed profile facts. It does not inspect component names or infer semantics from port names or evidence prose.

## Registered Variants

| Versioned variant | Finite contract |
|---|---|
| cpu.obi@1/read-only | Request/grant/response/error; read-only, single outstanding per endpoint |
| cpu.obi@1/read-write | Adds WE/WDATA/BE; byte lanes, single outstanding per endpoint |
| cpu.axi4@1/single-beat-id | 32/64-bit data; LEN=0 only, FIXED/INCR only, ID roundtrip, independent channels; no bursts, exclusive or atomic operations |
| cpu.axi4-lite@1/no-response-code | 32-bit, independent channels, byte enables; BRESP/RRESP physically absent; backend errors must terminate without invented success |
| cpu.wishbone@1/no-err-stall | 32-bit, byte-address contract, CYC/STB held to ACK; zero SEL reads mean full-word read; no ERR/STALL |
| cpu.native-memory@1/completion-no-error | 32-bit; VALID/READY is completion, never early request acceptance; no physical error response |
| target.tl-ul@1/user-integrity | 32-bit Get/PutFull/PutPartial; source roundtrip; actual user/integrity fields required; encoding remains source-defined |
| target.apb3@1/full-word | 32-bit setup/access/response/error; no PSTRB or partial writes |
| target.wishbone@1/word-addressed-registered-ack | Word addressing and implemented SEL; one-cycle STB pulse, CYC held through registered ACK |
| target.wishbone@1/addressless-select-ignored | No ADR; SEL ignored/full-word; one-cycle STB pulse; DUT ignores CYC |

All contracts are version 1, with scalar/fixed/derived role widths, required and optional roles, optional groups, finite data/address/field/wait limits and typed semantic predicates in their canonical document/hash. Target Wishbone's optional STALL is an observed-zero-only future runtime constraint, not a proven constant inferred from its name.

Native completion is explicit-only. CPU Wishbone auto selection requires typed `address_units=byte`; without that fact, explicit policy selects a configuration contract but does not prove DUT adherence. Explicit selection cannot contradict a present typed semantic fact. Target Wishbone always requires typed address units, address/select implementation, error support, CYC/ACK and registered-ACK flavour facts.

## V2 Boundary

`endpoint_policies` now validates exact template/version/variant IDs, endpoint compatibility and `max_outstanding=1`. The result includes selected contract evidence in its configuration identity. Both contract and selection documents set `runtime_effective=false` and `dut_semantics_verified=false`.

Optional signal overrides, boot and peer tuning remain refused. Existing v1 requests, runtime rendering, driver/build/session files are unchanged. No registry consumer runs DUT cycles or generates a driver. Source-lock verification and actual RTL evidence remain separate gates.

## Verification

- Plan committed before implementation: `af14857`.
- TDD observed missing-registry failures, then refusal of a positive registered endpoint policy, and missing capability/shape checks before their implementation.
- `PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_template_contracts tests.local_harness.test_tuning tests.local_harness.test_request -q`: 47 passed, including 18 new registry/policy tests.
- Full local_harness discovery: 102 passed, no exclusions. Worktree code/tests used the existing checked-out sources through explicit test ROOT/SCRIPT overrides to `/home/qinkejiu/myfuzz`, not symlinks or network fetching.
- Real profile elaboration/binding checks selected CVE2 OBI read/write and read-only; CVA6 AXI4 finite contract; Pico AXI-Lite; PULP APB3; ZipCPU UART and Timer target variants. Pico native and Wishbone automatic selection correctly refused, then explicit configuration selection passed.
- Ibex OBI and OpenTitan GPIO TL-UL endpoint contracts match, but those current profiles request `selection=declared`. This does not prove complete top-port ownership; the separate v2 tuning validator continues refusing non-full physical facts.

No new Generated or RTL operational evidence exists for any variant. In particular, CVA6's actual multi-beat fetch traffic is not covered by a single-beat contract match; Pico native/AXI/Wishbone execution and replay have not been run through this registry; and no generated TL-UL/ZipCPU target runtime is implemented here. Existing OBI/APB driver work and legacy adapter/SoC sessions are separate evidence, not promoted by this change.
