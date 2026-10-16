# Caliptra SHA256 static source/profile slice

Official Caliptra v2.1.2, git
`49370266d12cb0c4a8f71b3a0ff7e54ba7d4866e`, resides in the pinned
`third_party/caliptra_upstream_reference` submodule. Upstream files are unchanged.

The scope is sha256_ctrl with AHB_ADDR_WIDTH=32 and AHB_DATA_WIDTH=32, not the
whole Caliptra SoC. Eleven explicit files were retained from the upstream
src/sha256/config/sha256_ctrl.vf: ten synthesizable modules/packages plus
src/libs/rtl/caliptra_sva.svh, which defines CALIPTRA_ASSERT_KNOWN used by the
generated register block. No UVM, testbench, formal models, SRAM/ROM, clock-gate
or other unrelated library modules are compiled. The actual Verilator dependency
report equals this exact eleven-file closure. Include roots are retained in the
upstream order; no extra included file was observed. CLP_ASSERT_ON is not defined.

Actual local Verilator 5.051 lint and JSON-only elaboration succeeded with
16 physical top ports. Lint has **21 upstream warnings**: 13 WIDTHEXPAND,
3 ASCRANGE and 5 CMPCONST, recorded in evidence/lint.log. No warning suppression
was added beyond -Wno-fatal. Diagnostic line endings/trailing whitespace are
normalized in the committed text logs. The closure and source lock record exact source
hashes, parameters, tool identity and portable relative commands. These prove
static source/elaboration only; no register transaction or SHA256 result was run.

## Reset and input ownership

Both reset_n and cptra_pwrgood are declared active-low asynchronous reset ports.
sha256.sv connects reset_n to hwif.reset_b and cptra_pwrgood to the separate
hwif.error_reset_b. Generated error registers use posedge clk/negedge
error_reset_b; merely fixing cptra_pwrgood high from time zero would not prove
reset initialization. reset_policy.json specifies both low for initial clocked
initialization then both high. Eight asserted/released edges are a proposed host
sequence, not an executed reset test. Independent warm/power reset sequencing
is not supported in this slice. The debug/scan input is explicitly constant zero.
Bus request inputs belong to a future manager/session; read data, bus response
and error/notif outputs remain DUT observations. No IRQ trigger/capture or
clear semantics are granted by these passive pins.

## Register-target limits

Only naturally aligned full-word, single-outstanding accesses in a 4 KiB window
are in scope. The profile lists the basic name/version/control/status, block and
digest registers. Winternitz and interrupt register semantics are not modeled.
The generated address is truncated to 12 bits; host routing must reject addresses
outside the window. There is no byte-enable port, and sha256.sv supplies all-one
write bit enables; partial writes must be rejected before issuing a transfer.

sha256_ctrl ties ahb_slv_sif err and hld to zero. Internal sha256_err is not
forwarded to HRESP; invalid register offsets need not raise a bus error.
Address and data phases must be serviced separately. The existing CVW CPU AHB
subordinate has the opposite role and cannot drive this target.

The profile loads structurally and uses the normal strict source-lock verifier.
The identity-bound test_capability sidecar declares potential bus/passive sample
operations only; register semantics, aliases and certified observations are
empty. Runtime remains unsupported until a dedicated AHB-Lite register-target
contract, manager transport, session and actual dual-reset sequence are built.
Next acceptance is real padded-abc single-block SHA256 with bounded status polls,
actual digest response comparison, payload negative control and fresh replay.
CPU consumption, IRQ delivery and persistent RFuzz remain separate tasks.
