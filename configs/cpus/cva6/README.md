# CVA6 semantic interface profile

This is a reference template for an explicitly exported CVA6 RV64 IMAFDC
boundary, not a manifest that can analyze an untouched upstream checkout.
It describes one shared AXI4 memory master, interrupts, optional debug, clock
and reset. Physical directions, widths and timing come from HDL analysis.

The profile is reference-only. Before runtime publication, materialize the
source and a flattened `cva6_axi_boundary` wrapper below `third_party/cva6`, replace the reserved all-zero
`sha256:` placeholder with the verified source-tree digest (or a full verified
Git commit), and rerun annotation validation. The catalog must continue to
report the profile as unavailable until that succeeds.

Materialization steps:

1. Export the selected configuration's AXI record/interface into scalar ports
   on `cva6_axi_boundary`. The `mem_*` aliases are wrapper port names to supply
   or rename to match that export, not assertions about upstream port names.
   The template lists all 29 fields required by the current AXI4 catalog across
   AW/W/B/AR/R. Additional upstream sidebands need explicit treatment in the
   export; the wrapper must not silently discard required behavior.
2. Create `third_party/cva6/sources.f` listing the wrapper and required HDL
   dependencies, relative to that source root. Include any nested filelists,
   include directories and defines needed by the selected configuration.
3. Update both the CPU profile's `source_locator` and this description's
   `source` identically: root, revision, top_module, files/filelist and include
   roots. For SHA256 use `source_tree_hash` over all crawler-read inputs,
   including filelists and include-root files. A Git pin must match HEAD and
   the content of each consumed file.
4. Only then declare `available=true`, `source_status=implemented` and
   `implemented=true` in the CPU profile. The catalog still requires real
   schema loading, verified source crawling and protocol annotation to succeed.

The synthetic integration test verifies this complete template with two
independently renamed port sets. It is not a CVA6 execution test. Successful
annotation does not establish adapter compatibility with bursts, IDs, atomics,
coherence or other capabilities; composition must separately validate these
before runtime publication. No AXI4-to-AXI4-Lite reduction is implied.
