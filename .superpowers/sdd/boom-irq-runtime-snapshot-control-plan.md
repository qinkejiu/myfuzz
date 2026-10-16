# BOOM IRQ runtime snapshot/control plan (not executed)

Read-only planning after c6e7994. No constructor, model, generator, version query, build, probe-describe or native gate invoked. Existing recovery project/artifact and its2564-source/84-original receipt evidence remain unchanged. Gate source is awaiting independent review; any resulting fix requires a new gate SHA/freeze.

## Reuse the existing finalized artifact path

Use CPU output `/root/fanzehui/boom-irq-metadata-recovery-20261017/artifact-finalized` exactly where finalized. Its actual manifest SHA is `ec4431b9aa2b75932d9a689d5e5bc1041f6bd25158919bd16e240a428bbd5737`, binary SHA `6367b592b743f935cb2de04bc6dfc4ac54c9ec8cf5dce4eb6545b140971e6c90`. Do not move, regenerate, edit, relabel or re-sign metadata. Keep the historical command paths and original project path in trace_verifier verbatim. Existing manifest runtime_verified/source_authority/new_cpp_build remain false.

Actual source inspection:

- `boom_irq_cpu_session.py:49` creates the authentication temp directory beside the output and generates expected effective inputs using the caller's repo. Lines56–60 compare identity values including trace_verifier SHA and scenario_factory SHA, not repo or trace_verifier string paths. Lines61–83 require exact implementation/aux hashes, actual probe inventory, exact registry layout, strict recovery origin and exact session file set. `_start` verifies every artifact byte before Popen.
- `boom_irq_recovery.py:113` validates physical/declarative origin against the three fixed historical archives. Lines126–137 preserve captured binary/input/registry bytes, archive pins, original effective command `build_argv(OLD_OUTPUT)`, actual version and probe inventory. Current Python helper identity is compared by bytes. There is no requirement that the runtime repo string equal the metadata-finalization source path.
- `boom_irq_generation.py:56` records the factory byte SHA. The two new verification/test files are not silently added to or substituted for the authenticated implementation_source_hashes; the gate independently freezes them and the host/config closure.
- `tilelink_coherent_cpu_session.py:85` retains trace_verifier path plus SHA. The persistent session compares SHA only and does not execute that trace verifier. Its retained path still exists in original project-finalized. This plan does not change that field.
- `configs/cpus/boom/generated/materialize.py:35` writes authenticated RTL bytes into the supplied repo during expected generation. Therefore using original project-finalized as runtime repo would perform writes there even when identical. The runtime repo must be an independent copy. Canonical validation's temporary directory is a new sibling under permitted recovery parent, never inside finalized artifact.

Thus source reading supports **new independent repo + unchanged original artifact path** without bypassing any constructor check. This is a source conclusion, not an executed constructor acceptance result; actual native gate must still prove it later.

## Independent preparation

Proposed new base `/root/fanzehui/boom-irq-runtime-gate-20261017`; new project `project`, GPIO-only cache `gpio-cache`, gate output `gate-output`, state/log directories. All remote file operations remain under fanzehui and use the prescribed nested SSH transit. No canonical lock is needed for copying/hashing, but the future native command requires root scheduling and acquires the canonical lock nonblocking inside the gate.

Prepare with independent copy2/cp-a (never cp-al) from recovered project-finalized. Reject nonempty/existing new project and all ancestor symlinks, stage in `project.preparing`, then atomic rename only after byte and inode validation. Copy all original2564 files including scripts and standalone PULP `.git`39-file object closure; exclude no Git objects, add no external gitdir link. Overlay only reviewed `src/myfuzz/scenario/boom_gpio_irq_verification.py` and `tests/local_harness/test_boom_irq_verification.py` (currently c6e7994, subject to review). Assert no existing baseline file differs; expected added file set exactly these two. Measure actual final count rather than assuming it. Preserve source before/after/destination per-file manifests, link counts1 and zero shared source inodes.

Read-only preparation audit must validate all original finalized source and artifact files before/after, exact original manifest/binary/three archives and current helper/implementation pins, actual standalone PULP Git closure, tool paths/hashes within fanzehui, and every new imported BOOM module `__file__`/hash under new project. Import gate and prepare source freeze only; these paths are software-proven tool-free and must not call factory/constructor/generate. Record actual effective dependency set and check every dependency belongs to copied source. Do not claim clean checkout/reviewed whole HEAD: baseline is the explicitly pinned frozen working tree.

## Future one-shot operation controller

Controller/launcher get independent source-only controls and readonly review before launch. They must exclusively claim `state/operation.claim` before any PID/state write, and refuse all old PID/exit/claim/output/cache/launcher state without modification. Launcher has read-only same-state guard and source-first PYTHONPATH `project/src:project:pythonlib`. Controller verifies ready/control/source/artifact/tool hashes and imported module origins again in its actual process before executing the gate. PID is durable before waiting; operation never auto-retries or overwrites failed output.

Record exact argv/environment paths, source freeze and reviewed gate SHA, original recovery source/artifact complete before inventory, tool before identity and ready hash. Runtime command (prediction only, NOT executed):

```
python3 -u -m myfuzz.scenario.boom_gpio_irq_verification --run-native \
  --repo /root/fanzehui/boom-irq-runtime-gate-20261017/project \
  --cpu-output /root/fanzehui/boom-irq-metadata-recovery-20261017/artifact-finalized \
  --cache-dir /root/fanzehui/boom-irq-runtime-gate-20261017/gpio-cache \
  --output /root/fanzehui/boom-irq-runtime-gate-20261017/gate-output \
  --freeze-path /root/fanzehui/boom-irq-runtime-gate-20261017/source-freeze.json \
  --freeze-sha256 <actual-frozen-sha> \
  --artifact-sha256 ec4431b9aa2b75932d9a689d5e5bc1041f6bd25158919bd16e240a428bbd5737 \
  --heavy-lock /root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock
```

No BOOM compile or describe step. The real GPIO generated driver may compile only during this explicitly authorized future native entry; that is heavy work and remains queued. Preserve every build/driver/cache source receipt and actual command exit. Controller finally audits original finalized source/artifact byte inventories unchanged, new source unchanged (materialize identical bytes allowed only in independent repo), tools unchanged, exact actual worker exit and lock holder lifecycle; do not infer terminal success from PID disappearance. Archive complete first/fresh/suppression raw/runtime/GPIO/Runner/RAM/lifecycle traces and their unabridged UUIDs, metadata origin and freeze. Record first full prefix difference if comparison fails. Failed/unknown/partial runs remain failed; no automatic timing/pulse/bound extension or alternate directory restart.

## Boundaries

Current implementation fixed6000+512 and64-tick policy stays unchanged pending actual evidence. Final artifact/source authority, new C++ build and retirement authority remain false. Operational preparation and gate execution are separate; this document authorizes neither. Independent source review precedes controller freeze; exact root GO precedes any native entry.
