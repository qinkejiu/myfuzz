# Current compiled F4 Ibex native verification — 2026-10-17

## Result and scope

Actual controller exit **0**; independent post-exit audit **0**; source-after verification **0**. Three continuous directed candidates were certified, and both full fresh replays returned `matches=true`, `first_difference=null`. This covers the current experimental CPU→GPIOEN F4 executor with native error pins. It does not establish arbitrary APB IP support, general instruction search, full D4, or P7 acceptance. CV32 continuous execution was not launched by this authorization.

## Exact command and frozen source

Executed through `ssh jumpserver` then `ssh root@192.168.5.70`:

```sh
env PYTHONOPTIMIZE=0 bash /root/fanzehui/f4-filelist-verification-20261017-b370e3d/run_gate.sh ibex
```

Independent project snapshot is reviewed no-error source `59f6fa4` plus filelist fix `b370e3d`; controls prepared in `cd055fc`. Full manifest SHA256 `ce083b1ecee2a66bb9b40f789fc9f01c6f8c6db32a5f99322c0e3def58a5622a` pins 37,528 files plus 124 symlink identities. Launcher SHA256 `834b44f98c642847277129f02083a898ea73e4c9c286330d4a2821312fe19917`. Copied Git metadata HEAD is `f9bd70e5319866a59bbc148bcb12c6863cebe2ce`; the manifest and reviewed overlay define the actual source, rather than a clean-checkout claim. Before/after source checks passed. Native processes use the frozen private inputs, declared candidate slices, exact error policy and strict fresh comparison.

Canonical lock: `/root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock`. Wrapper PID216271, controller PID216282. Controller was absent after completion; terminal nonblocking lock probe returned0. No other native gate was started.

## Actual process receipts

| Execution | Role | PID | Execution nonce | Reaped exit |
|---|---|---:|---|---:|
| Primary | peripheral |220793|f07d8f1b3d0c470696bd336a8ba9052d|0|
| Primary | processor |220932|11880ec2522a41fcb5e82d8482084afb|0|
| Fresh1 | peripheral |226997|afdfc06a070d4bd0afd7bbfa1a607a6b|0|
| Fresh1 | processor |227136|628ccad6fdd640d5aa3390e1e0f80eaa|0|
| Fresh2 | peripheral |232872|55d757890f6d4723be660635e8dd753f|0|
| Fresh2 | processor |233011|59206561e13f4e7e8873724fb14a28fb|0|

All six PIDs and nonces differ. Each fresh directory includes its actual complete `prefix.json` (including online plan), `events.json`, `execution_audit.json`, artifact hashes and comparison. Both fresh comparisons preserve all semantic fields except the existing narrowly scoped process identity normalization.

Semantic hash for primary and both fresh runs: `7246394851dcf02ed02b513f560a20b807e80e50793c83db8820995f051564b9`.

## Measured cost

Generation37.610s; startup60.341s; individual cases66.071/64.608/68.330s; case total199.009s; total765.133s. Useful directed case throughput0.0150747 cases/s. These measurements do not establish practical coverage-guided search throughput.

## Preserved evidence

[Complete primary/fresh outputs and raw command logs](evidence/compiled-f4-ibex-current-20261017/evidence.tar.gz), SHA256 `a42beafbac16488931935bc4037c920f33496f6d1f6ee4b4b424b4cf78cd0a05`.

Remote immutable preparation/output base: `/root/fanzehui/f4-filelist-verification-20261017-b370e3d`; actual exit files are `logs/ibex.exit`, `logs/ibex.source-after.exit`, and `logs/ibex.audit.exit`. Local copied outputs/logs and source manifest remain under `.superpowers/f4-filelist-verification-20261017-b370e3d`. Historical snapshots and prior failures remain preserved separately.
