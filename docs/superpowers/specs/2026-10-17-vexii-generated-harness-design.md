# Vexii generated dual AXI RAM harness

Approved scope: pinned generated VexiiRiscv.v, 48 physical ports (LSU29,
fetch13, privileged4, clock/reset2). Two explicit AXI contracts select only the
actual reduced roles: fetch AR/R, LSU AW/W/B/AR/R. LEN/BURST/LOCK/QOS are absent;
single-beat semantics are an explicit required capability, not inferred by name.
The existing complete AXI template remains unchanged.

A generated runtime exports the actual reduced wires. The driver accepts one
response bundle and records one pre-edge sample per command. A dedicated RAM
session admits one outstanding read per endpoint and one LSU write, buffering
AW and W independently, holding ID/data/last stable through backpressure. It
rejects misalignment, oversized transfers, illegal WLAST/strobes and unmatched
responses. Reset cancels local pending responses. Fixed rdtime/IRQ inputs are
zero; MMIO/IRQ delivery and general bursts are outside this slice.

A source contract pins the profile, generated RTL, generation manifest and port
inventory, using actual elaboration evidence. The acceptance program independently
checks instruction fetch, store53, load, store54 and both B completions in two
fresh generated processes, plus a controlled data-read replacement producing1.
Raw physical samples and identities accompany the report. Direct C++ smoke
bench results remain separate from generated-harness evidence.
