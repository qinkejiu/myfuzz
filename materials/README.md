# Materials

This is the single material library for protocol/IP/CPU experiments.

```text
catalog/                  Source material metadata
protocol/                 Materialized protocol cases, split by protocol
generated_protocol_cases/ Legacy generated case materials
protocol_cpus/            CPU master filelists
simple_ips/               Simple IP filelists
rtl/                      Local RTL models, wrappers, stubs, and vendor RTL
cases/                    Small smoke and local development cases
qualification/            Frozen offline qualification datasets and notices
```

Source code belongs under `src/`. Generated run output should stay outside the
repository or under a temporary build directory.

The old automatic top-level generator code has been removed, but the materials
are intentionally kept as source data for the next protocol-profile-based
builder.

The AXI-Lite qualification denominator and its no-network verification command
are documented in `qualification/axi_lite/README.md`.
