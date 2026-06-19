# Multi-Component CPU + IP Experiment

This directory is the local scaffold for the next scheme5-style experiment:
compare a direct-slice baseline against a dependency-aware projection harness on
the same CPU + multi-IP target.

## Layout

```text
baseline_direct_slice/  baseline config: raw RFuzz bits are fixed-sliced
depaware_projection/    scheme config: raw bits are projected through dependencies
harness/                shared or variant-specific harness files
manifests/              dependency schemas and target-specific manifests
rtl/                    toy/smoke wrappers or custom composite target RTL
scripts/                local smoke and future remote launch helpers
```

## Current Status

This is a first-stage scaffold plus toy RTL/harness implementation. It
intentionally contains no claimed fuzz result.

The planned first target is a small CPU-like component plus RAM/timer/GPIO and
UART/SPI-style IP. The first real-design target should use the RVX component
set documented in `docs/CANDIDATE_COMPONENT_PROJECTS_RVX_COREV_PULP_20260617.md`.

Local execution is limited to structural checks. Run RFuzz instrument/server/fuzz
steps on `inner70:/root/fanzehui/myfuzz`.
