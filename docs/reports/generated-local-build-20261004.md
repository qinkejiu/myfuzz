# Generated local build evidence — 2026-10-04

## Scope

Runtime plan Task 2 builder only. Implementation commit: `d3b73bb` (base `fc14476`). No session or runtime-renderer changes.

`build_local_harness(artifact, *, base_dir, cache_dir)` admits only generated drivers authenticated by fresh source-lock verification, structural/runtime regeneration and actual `render_local_driver` regeneration. It checks complete C++/SV bytes, mutable document digest, required headers, profile, elaboration closure, adapter bytes and executing Python import closure. `top_only` and empty C++ are rejected.

Canonical build identity includes snapshots, generator/host bytes, tool paths/version/executable hashes, Verilator runtime includes, build argv, C++ standard and digest macro. Compilation uses `--cc --exe --build -j 1`, a 300-second timeout, process-group termination and atomic cache publication. Cache reuse reauthenticates live inputs and validates archived bytes and binary SHA. Failed or timed-out builds publish nothing.

## Verification

Tests were written first; initial import failed because `build.py` did not exist. Final command:

```sh
PYTHONPATH=src python3 -m pytest -q tests/local_harness/test_build_identity.py
```

Result: **9 passed in 35.05s**. Coverage: real GPIO fixture and genuine generated-driver compilation/READY, cache reuse, corrupt cached input/binary refusal, mutable artifact/text tampering, malformed header/schema refusal, header-set/compiler flag identity changes, generator regeneration mismatch, build failure and timeout cleanup. Fixture tests mock only driver-generation admission; the genuine generated-driver test does not mock it.

Separate retained real builds used actual `render_local_driver` and `build_local_harness`, then ran each executable with `END` and a ten-second host timeout. Both exited zero and emitted the exact artifact digest:

### configs/peripherals/pulp_gpio/component_profile.json

- READY: `READY local_driver.v1 3f9aae47ae58dfe29eced0a92102c4ad56cce84431a0010f024f7511d43de447 8 8`
- Artifact digest: `3f9aae47ae58dfe29eced0a92102c4ad56cce84431a0010f024f7511d43de447`
- Build digest: `81cb45985d7ce4c37124d8f9964fafba9207fcc3adbeafbe5eab10343afb9e40`
- Binary SHA-256: `e21ebd76de197d57f9bd2f543807eb2798d83e8e493b355b316322b5c7325586`
- Retained executable: `/tmp/local-build-evidence/81cb45985d7ce4c37124d8f9964fafba9207fcc3adbeafbe5eab10343afb9e40/harness`
- Verilator: `Verilator 5.051 devel rev vUNKNOWN-built20260806-e413e67`
- Snapshot inputs: 160; Python closure files: 149.

### configs/cpus/cv32e20/component_profile.json

- READY: `READY local_driver.v1 9bdc4fd35739831b5e2b491e13dcbae801f3578de7a999f623637f6f3371238c 8 8`
- Artifact digest: `9bdc4fd35739831b5e2b491e13dcbae801f3578de7a999f623637f6f3371238c`
- Build digest: `2a7286a78446cb94e77e342922a7acd51401247cc4eea0361d8a9bfa85e79e88`
- Binary SHA-256: `bc09f44b0a6716eac3b14082b043f470e9a3847f51ec90f11b1edeb4ef9850f7`
- Retained executable: `/tmp/local-build-evidence/2a7286a78446cb94e77e342922a7acd51401247cc4eea0361d8a9bfa85e79e88/harness`
- Verilator: `Verilator 5.051 devel rev vUNKNOWN-built20260806-e413e67`
- Snapshot inputs: 192; Python closure files: 149.

Full manifests, actual argv, generated SV/C++, snapshots and logs reside beside each retained executable. `/tmp/local-build-evidence/results.json` records both manifests.

## Limits

This proves authentic generated CPU/GPIO executables build and READY succeeds; higher-level scenario/session acceptance remains separate. No waveform flag is enabled. Builds support the locked ordered source closure rather than arbitrary filelist execution. System C++ library/header contents and compiler shared-library dependencies are not exhaustively captured; compiler executable/version, C++ standard, linker/archiver and Verilator runtime includes are captured. Cache storage is local trusted storage: manifest/binary SHA detects isolated tampering, not an attacker rewriting both manifest and binary. Corrupt entries fail closed and require explicit removal.
