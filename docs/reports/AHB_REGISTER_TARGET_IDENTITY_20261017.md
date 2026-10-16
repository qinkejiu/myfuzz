# AHB register target strict identity

Source-only increment following reviewed AHB startup capture. No DUT build, elaboration, model execution or native result is claimed.

The existing generated AHB register session was missing strict Runner reconstruction support. Its genuine identity failed closed; removing its service fields could previously downgrade to the generic identity branch. The RED receipt records both failures (2 failed, 18 passed).

`contracts.py` now selects an explicit runtime-kind to service-key/schema mapping for APB3 and AHB-Lite register services. Both share existing bounded setup-write/probe/policy validation. Keys remain protocol-specific, unknown/missing/mixed fields reject, and AHB build JSON uses strict bool-versus-int comparison. The actual Runner class registry already contains the AHB session; no new class alias or source authority was added.

Tests use the actual Caliptra profile, generated renderer/driver/session constructor, reconstruction and Runner manifest. Physical facts are explicitly saved historical ABI facts; frontend/tool identity are software fixtures. A subprocess guard allows git source authentication only. The archived old target artifact is provenance for those facts, not evidence of new startup taps or native execution.

Software evidence:

- Target controls: 21 passed in 12.23s.
- Combined target/APB/startup/AHB observer/parser controls: 162 passed in 23.26s.
- Receipts and exact source SHA256: `evidence/ahb-register-identity-20261017/`.

No new storage/reset/source authority is granted. New CVW-to-Caliptra startup/13-role native evidence remains a separate pending gate.
