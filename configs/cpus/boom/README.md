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

There is an additional unavailable dependency: `tilelink@1` is not implemented
in the protocol catalog. Downloading or generating BOOM sources alone cannot
make this profile executable. The abstract instruction/data aliases are role
placeholders, not a complete TileLink channel mapping. TL-UL support does not
provide BOOM TileLink/coherence support.

The explicit materialization entry is `third_party/boom/sources.f`. It must
list generated RTL and its dependencies, including an exported `boom_tile`
boundary. Use actual port aliases/module/hierarchy in the description; there
is no supported `source_anchor` field. Update the profile and description
locators identically and include filelists in the verified source pin.

Runtime enablement additionally requires a supported, validated boundary:
implement the applicable TileLink protocol, full channel mapping and adapter
capabilities, or supply a separately verified boundary converter and describe
its supported protocol honestly. Keep `implemented=false` and
`available=false` until those dependencies exist. A regression test provides
pinned synthetic RTL and verifies that annotation still rejects the missing
`tilelink@1` dependency. This iteration does not download Chipyard or claim
BOOM runtime support.
