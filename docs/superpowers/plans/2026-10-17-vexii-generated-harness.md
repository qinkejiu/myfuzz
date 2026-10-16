# Vexii generated harness implementation

Approved design: ../specs/2026-10-17-vexii-generated-harness-design.md.

1. Pin the generated RTL/manifest/48-port inventory, create actual CPU profile.
2. Add exact reduced fetch/data shapes and single-beat semantic contracts.
3. Register generated runtime, driver command, wire maxima and authenticated
   host session source. Keep complete AXI behavior unchanged.
4. Implement one-edge persistent RAM session with independent AW/W and bounded
   response state; reject invalid size/alignment/last/strobes.
5. Validate generation and semantic refusal locally; freeze shared host files.
6. Under the remote heavy-worker.lock, run generated CPU RAM twice fresh and
   a read substitution control; save physical samples and build identities.
7. Report actual runtime level, evidence and remaining CPU/IP/IRQ/replay gaps.
