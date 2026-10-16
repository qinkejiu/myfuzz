# Pinned VexiiRiscv generated CPU

`generated/manifest.json` pins generator/dependency revisions, exact command and
single generated RTL. `generated/ports.json` contains 48 physical ports:
LSU AXI29, fetch AXI13, privileged inputs4 and clock/reset2. `closure.json` and
`vexii_source_contract.py` authenticate the profile and generated evidence.
The generation manifest retains its original generation/lint-only status;
subsequent generated runtime evidence is separate.

The profile selects an explicit reduced single-beat AXI contract: fetch AR/R,
LSU AW/W/B/AR/R, address/data32, ID1. LEN/BURST/LOCK/QOS do not exist. There are
no fabricated physical exports. Runtime selection requires the actual role
sets plus `bursts=false` and `single_beat_reduced_axi=true`, independent of name.
CACHE/PROT are observed and accepted as metadata without cache/protection
simulation. IRQ and rdtime are fixed0 in this RAM slice.

`GeneratedReducedAxiCpuSession` uses the generated structural/runtime/driver
pipeline and native process, serves PersistentMemory, preserves response IDs
and data until handshake, buffers AW/W independently, and permits the missing
half of a partially accepted write to drain during quiesce. Unsupported size,
alignment, WLAST and strobe patterns fail closed. This is one outstanding
transaction per endpoint, separate fetch/LSU, no MMIO target routing.

For actual commands, physical evidence and boundaries see
[generated harness report](../../../docs/reports/vexiiriscv-generated-harness-20261017.md).
The existing direct C++ AXI smoke evidence is independent and is not used as
proof of this generated harness. CPU/IP composition, interrupt delivery,
continuous search and authenticated evidence-prefix replay remain pending.
