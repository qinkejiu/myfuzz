# Codex system progress status — 2026-10-23

This is the stop-point status requested for 09:00 local. It separates what has
real first/fresh evidence from what is still open. It is **not** a claim that
the full six-CPU/four-IP, P6/P7/P8 system is complete.

## Real gates landed today

### 1. Native exact-source completion Task 5 (local, three branches)

- Gate script SHA-256 `1422dc3f595eb97f181a6a875d271af238031d7fbd7d5f9a2914c54ab4cc7124`
  (byte-identical to the frozen r11 gate script).
- Clean-HEAD rerun evidence: `docs/reports/evidence/native-completion-task5-final-20261023/`
  (summary SHA-256 `e2a1f4e7b4a4f24b386397f72f4c9d1aa549fbafb406fd3afbfccb908fb75579`).
- Positive, controlled-response and native-source-refusal branches all pass;
  every branch has four real processes, all `terminal_returncode=0`; refusal
  retains the exact contradiction and replays the full prefix.
- Source closure: `9573e7c` integrated the seven modified plus one untracked
  module; clean checkpoint `5634abb`; report `docs/reports/native-completion-task5-local-20261023.md`.
- Independent audit: `docs/reports/native-task5-local-independent-audit-20261023.md`.
- **Boundary:** local gate only. No remote `/root/fanzehui/myfuzz` r11 Stage2
  upload/claim/controller/independent auditor, no source-tree/tool closure or
  executable identity. Proof scope is `native_instruction_bus_transfer_completed`.

### 2. Compiled F2 CPU-load / IP-read-response (Timer and SPI, native)

- Clean-HEAD evidence: `docs/reports/evidence/compiled-f2-native-gate-final-20261023/{timer,spi}/`.
- Timer (`ibex_obi_local` OBI + PULP APB `TIMER0_CTRL`):
  semantic `9e90366a2194501ad14ad46516f566e21720366afdc9863c2e53a1841a36c9df`,
  build join `complete` `8ef6a67e…`, fresh `matches=true/full`.
- SPI (`cv32e40p` OBI + PULP APB `SPICMD`):
  semantic `da0e5e46034ba27b9cbd8ca734a16fb7d9b76d3feb8f4184925761838cc92323`,
  build join `complete` `4d22e476…`, fresh `matches=true/full`.
- Both certificates carry a real `ip_register_version` prerequisite and the
  three edges persistent CPU→CPU, CPU→IP `read_request`, IP→CPU `read_return`;
  PRDATA `0` is consumed by a dependent `XOR 0x5a5` store at `0x0003fffc`.
- Report: `docs/reports/compiled-f2-native-gate-20261023.md`; independent audit:
  `docs/reports/f2-native-independent-audit-20261023.md` (F-1 resolved by
  `5634abb`; report text corrected).
- **Boundary:** one candidate per instance, reset-zero PRDATA, no mutation
  diversity/throughput, no renamed-instance native control, no F1/F3/F5/F6,
  no P6/P7/P8 completion.

### 3. CVW directed D4 session

- Commit `3d86c19`/`5051054`; evidence `docs/reports/evidence/cvw-session-20261018/`.
- Real CVW + PULP GPIO session: 7 APB deliveries, RAM `[0x35,0x6a,1,0xa5]`,
  first fetch `0xC0000000` held 1 tick, F4 RTL operational + cross-component
  accepted, fresh `matches=true/full`, exit 0.
- Report: `docs/reports/cvw-directed-session-20261018.md`.
- **Boundary:** directed fixed image, not RFuzz online, no F5/F6, not P6.
  Independent audit found process-independence wording/records gaps; report was
  corrected.

### 4. Vexii CPU+IP+IRQ fixed row

- Commits `f454962`/`ad4eb9e`/`69556d3`/`9287e47`/`2c99a00`; evidence
  `docs/reports/evidence/vexi-irq-fixed-20261018/`.
- 8 repeated cases in one boot, real CPU→PULP GPIO APB→GPIO IRQ→CPU trap→ISR→RAM;
  1567 CPU / 1711 GPIO ticks, 8 IRQ rises/falls, 36 APB deliveries, RAM result
  `[17,35,51,91,165,291,1023,127]`, status 1, check 0, done `0x600d`; two fresh
  processes with distinct UUIDs; 77/77 checks.
- Report: `docs/reports/vexiiriscv-cpu-ip-irq-20261018.md`.
- **Boundary:** declared host pulse-to-level and GPIO loopback, one IP, fixed
  program/table, no online mutation/coverage/prefix certificates, not P6.
  Independent audit found gate-exit/selection records and comparator-scope gaps;
  report wording was corrected.

## Earlier slices still relevant

- P7 I3 timer F4 and P7 I4 CV32E20+timer RFuzz, P8 S2/S3/S4 DMA gates have real
  evidence at their frozen commits; see
  `docs/reports/p7-p8-real-gates-20261018.md` and
  `docs/reports/p7-i5-candidate-20261018.md`.
- P6 remains fixed-instance `fresh_genomes`, not persistent single-harness;
  rows 2–5 still lack per-edge `RuntimePathContract` and closed-loop four hits.
- P8 S1c schedule thinning measured 1.37×, not 5×.



## R11 Stage 2 (Task 5 remote) — prepared, not passed

- Local package: `/home/qinkejiu/.native-gate/r11-stage2-5a6bfbeb4188`,
  4,690 members, 127,054,293 bytes; Stage 2 manifest SHA-256
  `54c61ce9ad87e1064c048114f98d8c90371cf8584d2b63f05e19b463f4fa4706`.
  Source is committed HEAD `8485893` via `git archive` plus the pinned PicoRV32
  gitlink; tool closure is a local CPython copy with a frozen environment.
- Local admission preflight passed with the unmodified frozen controller
  (claimed_run stubbed); 25/25 package verification checks passed; two
  independent pre-upload reviewers accepted the same exact digest.
- The operation tree was uploaded to
  `/root/fanzehui/myfuzz/operations/r11-native-completion-20261023-5a6bfbeb4188`
  and the manifest SHA matched on target. The one-shot controller then refused
  at `file:type-or-links:control/protected-baselines-preflight.v1.json` (the
  controller's own preflight map), before any claim, launch, cache or evidence;
  a retry with `umask 077` could not run because the SSH target became
  unreachable (`Connection timed out`). No gate, post-gate runner, independent
  auditor or upload reviews were produced; the remote operation path is
  consumed/unfinished.
- **Verdict:** R11 Task 5 remains OPEN. The local package is reproducible and
  reviewed, but neither the controller one-shot gate nor the independent remote
  auditor passed.

## Open items at the 09:00 stop

1. **Remote r11 Task 5:** no Stage2 source/tool package, upload, claim,
   one-shot controller run, or independent post-gate auditor on
   `/root/fanzehui/myfuzz`; the local gate is not a substitute.
2. **P6 literal completion:** persistent single-harness multi-case sessions,
   per-edge source provenance and closed-loop four-hit feedback for rows 2–5.
3. **P7 I5 formal:** consolidated negative group (N3 has no dedicated
   current-source test), independent rerun, and full P7 gate.
4. **P8 S1c 5×:** measured 1.37×; multi-tick harness batching design not
   implemented.
5. **Six CPU / four IP full matrix:** BOOM has no generated profile/RTL/toolchain;
   CVW/Vexii are directed/fixed rows, not P6 campaigns; no full matrix.
6. Audit gaps in CVW/Vexii process records and F2 renamed-instance native
   control remain.

## Remote working set

`/root/fanzehui/myfuzz/` (≈20G) contains `project/`, `tools/`, `pythonlib/`,
caches, Chipyard sources, `evidence/`, DMA work trees and `README.md`.
The previous `/root/fanzehui/myfuzz-20260927-legacy/` is preserved; the original
`/root/fanzehui/system-20261016/` was not modified.
