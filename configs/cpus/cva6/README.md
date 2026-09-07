# CVA6 semantic interface profile

This directory contains a source-independent semantic description for a CVA6
RV64 IMAFDC configuration. The description names instruction/data memory,
interrupt, optional debug, clock, and reset roles; it intentionally leaves
physical directions, widths, signedness, hierarchy, and timing to the generic
HDL crawler.

The profile is reference-only. Before runtime publication, materialize the
upstream checkout below `third_party/cva6`, replace the reserved all-zero
`sha256:` placeholder with the verified source-tree digest (or a full verified
Git commit), and rerun annotation validation. The catalog must continue to
report the profile as unavailable until that succeeds.

The expected architectural memory boundary is AXI4. A source-backed candidate
must prove the actual channel set and widths; the profile does not authorize a
silent AXI4-to-AXI4-Lite or TileLink reduction.
