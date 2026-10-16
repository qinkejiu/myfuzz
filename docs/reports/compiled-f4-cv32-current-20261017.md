# Current compiled F4 CV32E40P native verification — 2026-10-17

## Result and capability boundary

Actual controller exit **0**, post-source verification **0**, independent post-exit audit **0**. The original CV32E40P fixture completed three continuous directed candidates and two full fresh replays through the same compiled executor as Ibex. Both replays returned `matches=true`, `first_difference=null`. All actual primary/fresh subprocesses closed and reaped with returncode0.

This is the legal **success-only no-error-pin ABI**, not a substituted CPU or fabricated error0. The exact prefix policy is `mode=fail_stop_no_error_pin`, `native_error_observation=false`, `backend_error_policy=fail_stop_no_error_pin_to_raise`, derived from selected read-only/read-write-no-error-pins contracts and actual absent physical roles. Exact-hop consumed instruction/data error fields are JSON null (20 such fields in the first certificate), not observed successful error-pin values. CPU native-error/trap capability remains unsupported. The actual generated backend-ERR fail-stop gate is separately documented in [the boundary report](compiled-f4-cv32-no-error-boundary-20261017.md).

Scope remains the current experimental CPU→GPIOEN F4 path. No arbitrary APB IP support, full D4/P7, general instruction search or coverage-guided throughput claim.

## Exact command and source pins

Executed through `ssh jumpserver` then `ssh root@192.168.5.70`:

```sh
env PYTHONOPTIMIZE=0 bash /root/fanzehui/f4-filelist-verification-20261017-b370e3d/run_gate.sh cv32
```

Same reviewed independently copied project as [the current Ibex gate](compiled-f4-ibex-current-20261017.md): no-error implementation `59f6fa4`, filelist fix `b370e3d`, controls `cd055fc`. Full manifest SHA256 `ce083b1ecee2a66bb9b40f789fc9f01c6f8c6db32a5f99322c0e3def58a5622a` pins37,528 files and124 symlink identities. Launcher SHA256 `834b44f98c642847277129f02083a898ea73e4c9c286330d4a2821312fe19917`. Copied Git metadata HEAD `f9bd70e5319866a59bbc148bcb12c6863cebe2ce` is provenance metadata; actual source is pinned by manifest and reviewed overlay. Before/after source checks passed.

CPU artifact `46671cd291ce1eb33aaf589b4a7048e25ec2a89537d5169ab290af6f2e7f3274`; target artifact `9e09611ef3ed8eb9009f388ee154c782b15c4be16d6c88fd800c39ec0785b82e`. Adapter source SHA256 `59730c6742a85351d6e2cbf284d88185c874080274f323f2364268f2da3440df` is part of the exact no-error policy.

Declared32+32-bit candidate layout length8, digest `b4fcdb0d00a1b8402ddab0b3655c4095db549e64decf8a80c14dc45650f12552`. Actual records: `5500000078563412`, `aa00000078563412`, `7856341278563412`. This preserves independent MMIO-word/pin slices. Observed first instruction fetch address0x10000/event17, inside admitted image. No implicit seed or expected-output producer.

## Actual process receipts

Wrapper238483, controller238665. Canonical lock `/root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock`; terminal controller absent and nonblocking release probe0.

| Execution | Role | PID | Execution nonce | Reaped exit |
|---|---|---:|---|---:|
| Primary | peripheral |240888|b561ce29bef748bfa3cc31deb7b5e734|0|
| Primary | processor |241027|4228e15bd6174a5a867962d595cba405|0|
| Fresh1 | peripheral |246454|c5c95075b06c418b81c9ed22c906b2d3|0|
| Fresh1 | processor |246593|61c7d9e3eb8644128e799ebdf953e34b|0|
| Fresh2 | peripheral |253049|416241e5b7e44b7ca2a25db6a4972d06|0|
| Fresh2 | processor |253188|4ff1a661441544ea9e078e352d9b1dfe|0|

All six PIDs/nonces differ. Each fresh contains its own actual complete prefix/online plan, events, execution audit, artifact hashes and comparison. Semantic hash for primary and both fresh executions: `552a8dc903a89424e22a150e260588ac92a42f0fb929aaec28e24250ecc3d25c`.

## Measured cost and preserved evidence

Generation27.379s; startup38.190s; cases66.499/67.025/67.894s (201.418s total); total723.684s. Useful directed case throughput0.0148944 cases/s, without a practical search-throughput claim.

[Complete actual primary/fresh outputs and command logs](evidence/compiled-f4-cv32-current-20261017/evidence.tar.gz), SHA256 `1b18b4774cb380a89098279dcf63d2393a4e000df7273bcf9bc605a9c8499267`.

Remote evidence base `/root/fanzehui/f4-filelist-verification-20261017-b370e3d`; true exits `logs/cv32.exit`, `logs/cv32.source-after.exit`, `logs/cv32.audit.exit`. Local copied source manifest/output/logs remain under `.superpowers/f4-filelist-verification-20261017-b370e3d`. Historical failures and snapshots remain preserved.

## Root independent saved-prefix audit

[Independent archive audit](evidence/compiled-f4-cv32-current-20261017/independent-audit.json) confirms all three entire7,351-event arrays exactly equal without further normalization, whole prefixes equal except declared certificate process_scope, all candidate slices match actual raw bytes, six distinct reaped exit0 subprocesses, and all20 error fields in the first certificate remain null.
