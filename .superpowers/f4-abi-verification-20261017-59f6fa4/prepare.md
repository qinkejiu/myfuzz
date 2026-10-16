# Prepared native ABI gates — NOT LAUNCHED

Prepared source base commit: `59f6fa4ff74841ae48fffab84112d852cc4adb7d`.
Independent local snapshot: `.superpowers/f4-abi-verification-20261017-59f6fa4/project`.
Independent remote snapshot: `/root/fanzehui/f4-abi-verification-20261017-59f6fa4/project`.
The full manifest identifies actual frozen working-tree bytes, including preserved user dirt; the base commit alone does not claim a clean tree. All12 F4 implementation/config/test/script bytes match the reviewed 59f6fa4 pins. Copied root Git metadata HEAD is `f9bd70e5319866a59bbc148bcb12c6863cebe2ce` because metadata was copied later while the live shared tree advanced; this metadata commit is recorded separately, not substituted for the F4 implementation or full manifest identity.
Transfer used only `ssh jumpserver` → `ssh root@192.168.5.70`; target operations remain within `/root/fanzehui`.
No hardlink copy was used: source copied with rsync -a, archived and extracted with --no-same-owner into a new project directory. Runtime source was not changed.

## Pins and preparation receipts

- 37,527 hashed files, including independently copied required Git metadata/objects; 124 symlink identities, all resolving within snapshot (pre-existing unrelated broken links are recorded).
- `source_manifest.json` SHA256 `76b897916308f3ce6847ae64abf156ccea15d5c077dd30f143685ef1307259b4`; compressed manifest is committed as `source_manifest.json.gz`.
- Full archive SHA256 `aa5e8af3cc7aea56922d70c243a8754f9fdefa39ab2a1d2cd6d6e5f3cfbead72`, remote `source-snapshot.tar.gz`. Large project/archive remain external evidence, not Git objects.
- `run_gate.sh`: `5017afa6e6990d464949d1610a128dc4f04ef747376cd952b0038af5cf56dbf0`.
- `verify_snapshot.py`: `e5b33ae21e29214004dade957c28916ee3ae8911380c00b9f719fba5c25547bd`.
- `validate_gate.py`: `26e8f02c4975386a3b3082ef864e33f2545ca3e01f3480d6351744d0a04416f7`.
- Canonical environment.sh SHA256 `a713c0de882e7a59813d49f5a756d9fa122a05acf5363c48669c009033056ca8`; Python path snapshot/src:snapshot:/root/fanzehui/system-20261016/pythonlib.
- Local and remote full source/symlink verification match; remote archive hash matches; both declared CV32E40P and Ibex Git revision objects exist. These were read-only provenance probes, no frontend/elaboration/build/simulation.
- `logs/remote-final-prepare.log` and `.exit` preserve true preparation exit0 and exact hashes.

Initial preparation omitted Git objects; source-only inspection detected the verifier's git cat-file requirement before any gate launch. That archive/manifest/project remain separately named `*-initial-no-git*` locally/remotely as rejected preparation evidence. They must never be used for gates. Final extraction created a fresh root-owned project to avoid dubious ownership, rather than rewriting linked source.

## Exact future commands (one gate per explicit GO)

All commands below are **provided, not executed**. The fixed launcher arguments select exact compose/capability/supplement/records files and fixed NEW output directories. No caller dirname selects artifact/profile/seed; no implicit executor default or synthetic records exist. Run each command only after the root coordinator confirms the canonical lock window is reserved.

```bash
ssh jumpserver 'ssh root@192.168.5.70 "env PYTHONOPTIMIZE=0 bash /root/fanzehui/f4-abi-verification-20261017-59f6fa4/run_gate.sh adapter"'
ssh jumpserver 'ssh root@192.168.5.70 "env PYTHONOPTIMIZE=0 bash /root/fanzehui/f4-abi-verification-20261017-59f6fa4/run_gate.sh boundary"'
ssh jumpserver 'ssh root@192.168.5.70 "env PYTHONOPTIMIZE=0 bash /root/fanzehui/f4-abi-verification-20261017-59f6fa4/run_gate.sh ibex"'
ssh jumpserver 'ssh root@192.168.5.70 "env PYTHONOPTIMIZE=0 bash /root/fanzehui/f4-abi-verification-20261017-59f6fa4/run_gate.sh cv32"'
```

The launcher contains exact underlying commands:

1. Existing adapter RTL test `tests/protocols/test_obi_processor_memory_adapter_rtl.py::ObiProcessorMemoryAdapterRtlTests::test_backend_error_fail_stops_when_cpu_has_no_obi_error_channel` under one outer canonical lock. A skipped test does not pass the independent post-exit audit.
2. `scripts/check_compiled_obi_no_error_boundary.py` with original CV32 compose, capability and supplement; max-rounds256, command-timeout30; one actual accepted instruction backend ERR. Command internally holds canonical lock. Requires actual native fatal and nonzero native process exit.
3. `scripts/run_compiled_dataflow.py`, explicit compiled_f4_obi_apb, Ibex fixture, three declared original8-byte records, max-cases3, rounds128, replays2. Internal lock covers primary and both fresh runs.
4. The identical entry/executor/record count/budgets with original CV32 fixture and distinct new output directory. Expected success-only no-error policy; actual first native fetch must be observed, no Ibex boot-offset assumption reused.

## Lock, PID and exit conventions

Canonical only: `/root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock`.
Launcher first verifies source, performs a nonblocking immediate-release lock probe, then launches only the chosen gate. Lock-held failure is exit75, never a queued waiter. Adapter uses an outer lock because pytest has none; boundary and file entry use their internal lock, avoiding double lock deadlock. No lock probe/lock acquisition/waiter was created during preparation.

For gate G, exact paths beneath the remote base:

- `logs/G.wrapper.pid`: actual wrapper shell PID.
- `logs/G.pid`: actual python/pytest child PID, written immediately after launch.
- `logs/G.log`: complete command output.
- `logs/G.exit`: actual waited child process exit (never inferred from last output).
- `logs/G.lock-probe.exit`, and adapter `logs/adapter.lock-acquired`.
- `logs/G.source-before.json`, `logs/G.source-after.json`, `logs/G.source-after.exit`.
- `logs/G.audit.json`, `logs/G.audit.exit`: independent post-exit artifact checks. Command exit0 alone is not acceptance.
- `logs/G.started`/`finished`: UTC timestamps.

A repeat refuses existing PID/exit/output, preserving failures. To retry, create/review a new preparation/output identity; do not delete evidence or reuse output. The launcher's own SSH exit reflects command/source/audit failure while the child exit remains separately recorded.

## Evidence acceptance still required

Outputs are `outputs/boundary`, `outputs/ibex`, `outputs/cv32`. Both continuous gates must contain three certified cases, complete primary and two complete fresh prefixes/online plans/events, actual role→PID/nonce maps, actual post-close zero returncodes, exact source/artifact/layout/policy identity, and exact matches. Post-exit audit rechecks strict comparison with the existing narrow normalization only, six unique PID/nonce pairs, exact input records and no `.incomplete` marker. Native first_difference/failures remain evidence and cannot be normalized away.

Native generated-boundary backend fatal has its own real nonzero native close receipt; the controlling diagnostic command must exit0 only when the expected fail-stop was actually observed. This controlled fault is not an F4 success certificate.

Status: PREPARED ONLY. No native gate, build, elaboration, adapter simulation, throughput claim, full D4 or P7 acceptance has occurred for this prepared snapshot. Root DMA/BOOM queue remains authoritative; wait for exact GO.
