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

## Boundary attempt: terminal before native startup, NOT ACCEPTED

After separate exact root GO and free canonical prelaunch probe, only boundary gate launched: wrapper212039, actual Python212053. True command exit1 at `_source_paths` source['files'] KeyError because original CV32 has filelist. Source pre/post37527files+symlinks match; source-after trueexit0. Terminal canonical nonblocking release probe exit0. Independent post-exit acceptance audit is not run when controlling command already failed. No generated CPU process or actual backend ERR/fatal proof exists for this attempt. Output `.incomplete` and raw traceback are preserved, including missing report caused by failure before diagnostic try guard. No retry/othergate launched; original snapshot remains frozen. Software root-cause fix is reviewed separately, not overlaid into this attempt.
