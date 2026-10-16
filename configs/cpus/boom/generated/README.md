# Pinned derived BoomTile RTL

`rtl.tar.gz` contains exactly the four emitted Verilog inputs used by the
successful direct runtime probe. `source_manifest.json` binds the archive,
each uncompressed file, the content-framed source union, and physical port
capture. `python3 materialize.py` authenticates every member before writing
these files locally. No download or Scala build is needed for this step.

This is derived `chipyard.SmallBoomConfig` source. Its provenance is
`../derived_source_manifest.json`: Chipyard/BOOM pins, published dependency
changes and the minimal explicit Rocket metadata IO patch. It is not a claim
that unmodified upstream compiled. The 47-port `BoomTile` exposes one shared
coherent TileLink A/B/C/D/E bus with 39 signals, plus clock, reset, hart ID and
five local interrupts.

Generate or execute the physical local CPU/RAM driver from the repository:

```sh
PYTHONPATH=src python3 -m myfuzz.local_harness.tilelink_coherent_cpu_session \
  --output .superpowers/boom-generated/run
```

Add `--build-and-run --heavy-lock <shared-heavy-worker.lock>` on the authorized
build host to build from these authenticated RTL inputs, run two fresh CPU
instances, require byte-identical traces and exercise the corrupted reload
control. The generated `artifact.json` binds the profile, source manifest,
manager, driver and exact Verilator command; `gate.json` binds the executable
and three run outputs. This entry point is an isolated coherent CPU/RAM
session. It is not admission to the generic CPU/peripheral MMIO router.

The CPU boots at 0x10040, executes RV64 code in RAM at 0x80000000, performs
cached store/load and dirty release/writeback, fences earlier stores before
the final load, then reports first and reloaded
values at legal uncached addresses 0x4000/0x4008. B.valid remains zero because
there are no other clients; external probe handling is not exercised.
