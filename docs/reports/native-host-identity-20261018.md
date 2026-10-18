# Native host source identity static audit

Added five explicit HARNESS v2 paths in `scenario/host_identity.py`:

- `scenario/native_packet_session.py`: physical packet guards and terminal failure handling.
- `scenario/picorv32_native_online.py`: bootstrap, source decoding and runner assembly.
- `integration/picorv32_native_online.py`: bounded runtime execution and fresh replay entry.
- `scenario/picorv32_native_cpu_example.py`: deferred native memory/MMIO service execution.
- `scenario/native_cpu_events.py`: verified live bus receipt observation.

Paths above are relative to `src/myfuzz/`. Independent standard-library AST
traversal reproduced `local_harness/build.py::_discover_host_sources` seeds,
relative import resolution and module/package traversal: 329 files. The first
four paths were absent; `native_cpu_events.py` was already reachable through
the runner import. It remains explicit because it directly interprets live
native execution evidence. All five are now explicit in HARNESS v2; none of
these five live sources is missing from that closure. Build discovery was
read only and is unchanged.

Static self-review parsed the changed module, compared the HOST v1 tuple AST
against HEAD, confirmed its unchanged 34 ordered paths, and confirmed all 68
HARNESS v2 explicit paths exist without duplicates. Existing missing-source,
saved identity equality and build input digest checks are unchanged. The v2
identity legitimately changes; previous actual passes do not certify this
new identity or establish native completion, source grants or P6 acceptance.

Changed `host_identity.py` SHA256:
`4a7379c6f33216cb4d46e3d8683bfe651879683f400d82e4c33b9e8e7c178f58`.

Only source reads, AST parsing, file hashing and Git inspection were used.
No project imports, tests, frontend/build/model invocation, native process,
tool version query or remote operation was performed. The initial `python`
command was unavailable; the static audit used system `python3`.
