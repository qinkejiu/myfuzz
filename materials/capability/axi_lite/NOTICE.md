# Third-Party Notices

The main capability manifest includes frozen source from PicoRV32 (ISC),
UltraEmbedded RISC-V (BSD-3-Clause), verilog-axi (MIT), and PULP `axi` plus
`common_cells` (Solderpad Hardware License 0.51). Complete license text and
source coverage are recorded by `manifest.json`.

Auxiliary WB2AXIP source and license material is stored under `upstream/` in
this directory but is not referenced by the main scale-comparison manifest.
Reused CPU, verilog-axi, and PULP material remains in the formal qualification
mirror; its immutable source, dependency, license, and provenance records are
copied from that frozen oracle into this capability manifest.

The local wrappers retain the upstream SPDX identifiers. The WB2AXIP repository
declares Apache-2.0 in its README and source headers; the included `LICENSE` is
the complete Apache License 2.0 text distributed by the host operating system.
