# Reviewed filelist fix: prepared boundary retry, UNRUN

Filelist fix commit b370e3d, independent source review `.superpowers/sdd/f4-filelist-fix-source-review.md`, pure final39passed0.51s. No runtime/CPU/IP source changes.

New independent local project `.superpowers/f4-filelist-verification-20261017-b370e3d/project`; remote `/root/fanzehui/f4-filelist-verification-20261017-b370e3d/project`. Both cp-a from the prior frozen37527-file source, then atomically replaced only reviewed four files. No old snapshot/archive/output was modified. Full proof:37528hashedfiles, unchanged124symlink identities, zero shared old/new file inodes, exactly four reviewed source/test changes. Old source manifest76b897... is the base, new source manifest SHA256 **ce083b1ecee2a66bb9b40f789fc9f01c6f8c6db32a5f99322c0e3def58a5622a**. Copied Git metadata retains old f9bd70e; the byte manifest plus reviewed overlay identify this working tree, not a clean checkout claim.

Reviewed overlay archive SHA256 **595c5b43e89ad9ef675f61859492013d2e2e6074c3dac82dee59cab60e672186**. Installation checked exact members, used atomic temporary-file replacement and verified no shared inodes. Large base archive/project remain separately preserved; compressed full manifest is committed here.

Launcher run_gate.sh SHA256 **834b44f98c642847277129f02083a898ea73e4c9c286330d4a2821312fe19917**; verifier e5b33ae21e29214004dade957c28916ee3ae8911380c00b9f719fba5c25547bd; post-exit validator26e8f02c4975386a3b3082ef864e33f2545ca3e01f3480d6351744d0a04416f7. Launcher changed only fixed base path/output identity from the previous prepared controls. Canonical environment/Pythonlib/lock remain unchanged.

Read-only remote full manifest verification matches and new logs have no gatePID/output. Source-input preflight explicitly forbids subprocess.Popen and passed original CV32 declarations (870pinnedinputs) plus Ibex (1068), native_executedfalse. It does not generate, elaborate, build or simulate. Preparation/helper script bytes and raw receipts are saved here.

## Exact future boundary command — requires separate root GO

```bash
ssh jumpserver 'ssh root@192.168.5.70 "env PYTHONOPTIMIZE=0 bash /root/fanzehui/f4-filelist-verification-20261017-b370e3d/run_gate.sh boundary"'
```

Only boundary is proposed next. No launch/lock probe/waiter was created during this preparation. Canonical `/root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock`; command internally locks, wrapper only probes/releases before launch, no double lock. PID/exit/source/audit conventions unchanged under newbase/logs/boundary.*. Actual command child exit remains separate from source-after and acceptance audit exits. New output is newbase/outputs/boundary; reuse refuses. Native fatal+actual nonzero child receipt remain required for diagnostic command success. Timeout/startup/source failures are not DUT fail-stop evidence.

Original skipped adapter and failed pre-native boundary receipts remain oldbase. No retry occurred during software fix or preparation. Parent owns separate Verilator equivalent test; it is not part of this frozen snapshot. Ibex/CV32 fullcontinuous/fresh gates remain unrun for this source, no fullP7/D4/native pass claim.
