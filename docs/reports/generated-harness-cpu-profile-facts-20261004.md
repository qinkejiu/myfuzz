# CPU profile source facts audit — 2026-10-04

This audit covers the four component profiles present at base commit `7d5ea9e`.
All four results are **source/profile facts only**. Full top elaboration,
protocol binding and complete port dispositions do not establish Generated,
RTL operational or Cross-component accepted status. No generated harness or
real scenario/program execution was exercised by this audit.

## Source identity and frontend

- CVE2 source root: `third_party/cv32e20_upstream_reference`, revision
  `git:d079e8c8e6a08b330940ae123876ba0612bec18d`, top `cve2_top`.
- All Pico variants use `third_party/picorv32_upstream_reference`, revision
  `git:ef203c2b0a3fb793280f5114941416c425c5b461`, source `picorv32.v`.
- Actual frontend: `verilator-json`; installed binary reported
  `Verilator 5.051 devel rev vUNKNOWN-built20260806-e413e67`.
  `elaborate_profile` returned physical facts successfully for all four profiles
  with `selection="all"`. No selected-only top was accepted as full coverage.
- CVE2 uses 28 source files, `RVFI=1`, and overrides `MHPMCounterNum=10`,
  `MHPMCounterWidth=40`, `RV32E=0`, `RV32M=2`, `XInterface=0`.
  All five overrides were accepted by the current frontend. Each Pico profile
  uses one source file, `ENABLE_PCPI=0`, `ENABLE_IRQ=0`, and no
  `RISCV_FORMAL` define.

## Measured physical coverage

Counts below come from actual returned `facts.ports` and the resulting
`build_port_dispositions` ledger. Bits are the sum of physical port widths;
ledger bits are the sum of classified spans. Successful ledger construction
also checks that every physical bit has exactly one disposition and every
input has a driver.

| Profile | Top | Ports (input/output) | Physical bits | Ledger entries/bits | Recorded frontend warnings | Constant/functional/observe entries |
| --- | --- | --- | --- | --- | --- | --- |
| CVE2 | `cve2_top` | 70 (27/43) | 1308 | 70/1308 | 90 | 16/18/36 |
| Pico native | `picorv32` | 27 (9/18) | 409 | 27/409 | 0 | 5/8/14 |
| Pico AXI | `picorv32_axi` | 32 (13/19) | 384 | 32/384 | 0 | 5/19/8 |
| Pico Wishbone | `picorv32_wb` | 24 (9/15) | 341 | 24/341 | 0 | 5/10/9 |

CVE2 warnings are recorded under the profile's `recorded-nonfatal` policy;
this is a successful elaboration with warnings, not a warning-free claim.
CVE2 packed RAM, XIF and crash ports and RVFI outputs are included in these
counts. Pico RVFI ports are absent under the tested defines.

## Rejection evidence

Each mutation starts from a newly parsed source profile; files on disk and
source pins are untouched. Tests assert exception type and diagnostic text,
so an unrelated refusal cannot satisfy the intended check.

| Mutation | CVE2 | Each of the three Pico tops |
| --- | --- | --- |
| Replace source revision with forty zeroes | `ComponentProfileError`: `git-revision-mismatch` | Same refusal |
| Remove an input's constant action | `PortDispositionError`: `undisposed-port-bits:cv32e20_0:fetch_enable_i:0:0` | `undisposed-port-bits:<name>_0:pcpi_ready:0:0` |
| Assign two output roles the same physical alias | `ComponentProfileError`: `duplicate-port-binding:data_req_o:` (`req`/`we`) | `duplicate-port-binding:mem_addr:` (`addr`/`wdata`), `duplicate-port-binding:mem_axi_awaddr:` (`awaddr`/`araddr`), `duplicate-port-binding:wbm_adr_o:` (`adr`/`dat_w`) |

The duplicate mutations deliberately use equal direction and width, isolating
physical ownership from width/direction conflicts. The loader rejects them
before elaboration or binding. This is earlier than the plan's illustrative
`addr=req` mutation anticipated; the assertions encompass loading and verify
the actual duplicate diagnostic.

## Capabilities and remaining execution limits

- CVE2 exposes split OBI instruction/data request, grant and response roles;
  `gnt` accepts the request, while `rvalid/rdata/error` complete the response.
  The profile records RV32IMC and aligned reset fetch at `0x10000`.
  IRQ external maps to `irq_external_i`; other interrupt inputs are inactive.
- Pico native exposes `valid/ready/addr/wdata/wstrb/rdata`. `mem_ready` is
  completion with valid read data, not early acceptance. In the pinned RTL,
  `mem_xfer` uses `mem_valid && mem_ready` (`picorv32.v:373`). `mem_instr`
  and native look-ahead outputs are observed rather than invented protocol roles.
- Pico AXI exposes the physical AXI4-Lite channels but has no `mem_axi_bresp`
  or `mem_axi_rresp` ports. The positive test verifies their absence. Later
  transactors must account for the lack of physical response status; this
  profile supports a no-error boundary and cannot invent error aliases.
- Pico Wishbone has no `wbm_err_i` or `wbm_stall_i`; the positive test verifies
  their absence. It is a no-error/no-stall classic boundary. RTL assigns
  `wbm_adr_o <= mem_addr` (`picorv32.v:3011`), preserving a byte address, and
  `wbm_sel_o <= mem_wstrb` (`:3014`). Read `sel` handling still requires a
  later protocol transactor test.
- All three Pico CPU contracts are RV32I at reset vector zero. Their custom
  IRQ mechanism is disabled and does not establish standard machine-external
  IRQ delivery. PCPI inputs and IRQ are tied inactive with the corresponding
  disable parameter evidence.
- Memory address/data widths are 32 bits with four byte lanes. The profile
  `max_outstanding=1` is a planned environment limit, not a measurement of
  native core concurrency. Simulation, reset/boot delivery, protocol timing,
  error behavior, independent ISA validation and cross-component execution
  remain untested here.

## Validation

```bash
PYTHONPATH=src:. python3 -m unittest tests.composition.test_cv32e20_source_profile tests.composition.test_picorv32_source_profiles -q
git diff --check
```

The focused suite passes 8 test methods: two positive methods cover four tops
and six negative methods cover twelve independently restored mutations.
The first audit run exposed four duplicate cases rejected during loading,
outside the initial exception context; moving loading into that context and
asserting `duplicate-port-binding` made the tests match the actual refusal.
No production changes were needed. The final suite and whitespace check pass.
