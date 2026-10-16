# New persistent BOOM cached-RAM supplement — prepared, not run

`src/myfuzz/scenario/boom_coherent_verification.py` is frozen separately from
passed primary GPIO gate8a3fed3. Only CLI import/--help has run (exit0). No
supplement native process, clock edge, build, lock acquisition or gate has run.
Wait for the root's reserved short window after the F4 terminal state.

The probe loads the fenced reference cached-RAM eviction/reload instructions
through GeneratedBoomCpuSession into the SAME already-built persistent binary.
Two fresh processes must produce actual A/C/D/E, CPU result words0x123 and
backing RAM0x123, drained manager/closed healthy coherent checker, exact complete
measured-edge receipt equality (including idle/reset edges), exact raw bus-row
equality and scope-only full runtime-stream equality. All raw traces, scopes,
process PIDs/exits and failed prefixes are retained. A separate optional old
one-shot comparison excludes only its additional D address/fault diagnostic
metadata; it does not replace either new complete-fresh comparison.

Remote ready script:
`/root/fanzehui/boom-verification-20261017/coherent-probe.sh`.
Local durable copy: `.superpowers/boom-verification-20261017/coherent-probe.sh`.
Ready state: `.superpowers/boom-verification-20261017/coherent-ready.json`.
The script uses the canonical heavy lock, environment.sh/pythonlib and source
snapshot, and writes state/coherent.exit and log output when actually launched.
The launcher must persist state/coherent-PID before polling, inspect any prior
PID before retry, and never restart a live job. No coherent-PID currently exists.

Matching local/remote ready module SHA-256:
`0a7fb00b015588e68383febb2a17836be310c0b9612c3094ef52bee1b2fd0bcd`.
Matching local/remote script SHA-256:
`d1e560336bfd9e4f3cefa425def218500f11fb3813f6f0929a1d185d8b58928f`.
Expected existing native executable SHA-256 from primary native artifact:
`6f47a6166bb5ef5b515ed256adc721ee5ff6ae43e913883b4bce93ccb15bd44a`.
No C++ or passed primary source/evidence was changed. No C/E runtime or full P6
claim follows from this prepared source. Actual results/evidence remain pending.
