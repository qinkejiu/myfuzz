# BOOM semantic interface profile

This directory contains a source-independent semantic description for a BOOM
RV64 IMAFDC configuration. The description names instruction/data memory,
interrupt, optional debug, clock, and reset roles; it intentionally leaves
physical directions, widths, signedness, hierarchy, and timing to the generic
HDL crawler.

The profile is reference-only. BOOM is normally materialized together with a
generated Rocket Chip/Chipyard design below `third_party/boom`; replace the
reserved all-zero `sha256:` placeholder with the verified generated-source
digest (or a full verified Git commit) before runtime publication. The catalog
must continue to report the profile as unavailable until annotation and the
selected integration boundary both validate.

The expected memory boundary is a generated Tile-facing interface, represented
here as the reference `tilelink@1` expectation. It must be structurally
validated before a candidate can select a concrete TileLink runtime adapter;
the profile is not a CPU-name shortcut or a claim that every BOOM wrapper is
TL-UL.
