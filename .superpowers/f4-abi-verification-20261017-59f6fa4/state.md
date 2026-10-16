# F4 ABI gate state

## Adapter attempt: terminal, NOT ACCEPTED

Only the prepared adapter gate was authorized and launched. Exact command:
`env PYTHONOPTIMIZE=0 bash /root/fanzehui/f4-abi-verification-20261017-59f6fa4/run_gate.sh adapter`, via `ssh jumpserver` then `ssh root@192.168.5.70`.

- Actual remote wrapper PID211500 (terminal/gone); actual pytest child PID211683.
- True pytest exit0; collected1 / **1 skipped in0.02s**. No adapter simulation pass occurred.
- Independent post-exit audit true exit1: `adapter gate must actually pass, not skip`.
- Source pre/post match all37,527 files and symlink identities; source-after true exit0.
- Lock-acquired timestamp saved; terminal canonical `flock -n ... true` probe true exit0 confirmed release.
- Environment tool lookup: iverilog=null, vvp=null; Verilator exists. The existing test explicitly skips without Icarus+vvp. No installation, source change, retry or alternative gate was performed.

Exact remote receipts: `/root/fanzehui/f4-abi-verification-20261017-59f6fa4/logs/adapter.*`; copied into this local `logs/` directory, including raw pytest output, actual PID/exit files, source audits, lock receipt and tool availability. Preparation snapshot/archive remain frozen.

Boundary, Ibex and CV32 continuous/fresh gates remain **UNRUN**. No full D4/P7/native ABI acceptance or search throughput claim. Future gates/retry require a new exact root GO; preserve this skipped attempt/output identity rather than overwrite it.
