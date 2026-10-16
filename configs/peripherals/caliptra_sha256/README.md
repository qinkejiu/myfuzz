# Caliptra SHA256 AHB-Lite target

Official Caliptra v2.1.2 is pinned at
`49370266d12cb0c4a8f71b3a0ff7e54ba7d4866e` in
`third_party/caliptra_upstream_reference`; upstream files are unchanged.
The eleven-file closure contains the SHA256 modules/packages, AHB slave and
`caliptra_sva.svh`. Static lint/JSON elaboration records 16 ports and 21 upstream
warnings, retained in the source closure. The source lock remains a source and
elaboration record; local runtime evidence is reported separately.

The generated `target.ahb-lite@1/full-word-single` manager now drives real
`sha256_ctrl` through separate address/data phases. It admits aligned 32-bit
full-word accesses in the 4 KiB window, one outstanding, with native HREADYOUT,
HRDATA and HRESP observations. HREADYIN is the single-target fabric ready signal.
Partial/unaligned/out-of-window accesses are rejected before bus effects.
The generic session uses `ahb_lite_register_observe`; no component name selects
runtime behavior. Debug/scan is fixed zero. There is no peer or mutable input
model in this initial target variant.

Both `reset_n` and `cptra_pwrgood` are active-low asynchronous resets. The generated
initialization drives both low for eight edges, then high for eight edges.
`cptra_pwrgood` resets the separate error-register bank and is not fixed high.
Independent warm/power reset sequencing remains unsupported. Native error/notif
pins are passive observations, with no CPU interrupt delivery contract.

CTRL and BLOCK are **software write-only**, as specified by `sha256_reg.rdl`
and the generated register readback mux; reads return zero. The profile's initial
`rw` declarations were corrected after real access exposed the mismatch.
Name/version/status/digest are read-only. Internal register errors do not reach
HRESP: `sha256_ctrl` ties the AHB wrapper's err/hld inputs zero.

Local real acceptance reads NAME/STATUS, writes both padded `abc` and `abd`
blocks in one session, pulses INIT/MODE, polls VALID and checks all eight actual
digest words against an independent reference. Every access has one actual AHB
address acceptance, distinct data phase, matching payload/response, and three
normalized protocol events with zero checker violations. A fresh process repeats
the complete directed sequence and matches its receipts/events/digests.
See [the runtime report](../../../docs/reports/caliptra-sha256-ahb-target-20261017.md).

This establishes local register/hash operation. It does not establish CPU
consumption, IRQ delivery, Winternitz, full Caliptra SoC, persistent RFuzz,
coverage-guided search or authenticated saved-prefix replay. The capability
sidecar deliberately contains no certified register semantics/observation mappings.
