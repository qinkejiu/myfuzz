# CV32 no-error OBI: actual generated boundary ERR gate

The generated CV32E40P CPU boundary passed the controlled backend ERR fail-stop gate. This proves the legal no-error ABI terminates on a real backend error; it does not provide CPU error-pin observation or establish full F4/P7 acceptance.

## Actual result

| Evidence | Observed |
| --- | --- |
| Actual first instruction acceptance | `0x10000`, request/grant both1; physical ABI has no error role |
| Injected backend response | Instruction ERR1, commandsequence2, after actual sequence1 acceptance |
| Native result | Exact `OBI backend error cannot be represented by this CPU interface` fatal in `u_adapter_i`; actual process exit1 |
| Controller / postsource / independent audit | 0 / 0 / 0 |
| Source identity | All37528files and symlink identities match before/after |
| Process identity | Wrapper213211, controller213275, actualCPU214926; execution nonce d76fd053ea67435cae85d4502e18954b |
| Lock | Canonical shared lock held during build/run, terminal nonblocking release probe0 |

No success reply was accepted for the injected ERR. Native error observation remains absent; the backend error is never relabeled a physical error=0 sample.

## Reproducibility

F4 ABI implementation59f6fa4 plus independently reviewed filelist closure fixb370e3d; controls cd055fc. Independent remote project `/root/fanzehui/f4-filelist-verification-20261017-b370e3d/project`, formed by cp-a plus exactly4reviewed atomic replacements, zero shared old/new inodes. Full working-tree manifest SHA256 `ce083b1ecee2a66bb9b40f789fc9f01c6f8c6db32a5f99322c0e3def58a5622a`; copied Git metadata f9bd70e is recorded separately and is not a clean source checkout claim.

Exact command via jumpserver:
`env PYTHONOPTIMIZE=0 bash /root/fanzehui/f4-filelist-verification-20261017-b370e3d/run_gate.sh boundary`.

The wrapper fixes original CV32 compose/capability/supplement, explicit canonical heavy lock, max-rounds256 and command-timeout30. Artifactdigest `46671cd291ce1eb33aaf589b4a7048e25ec2a89537d5169ab290af6f2e7f3274`; actual built binary SHA256 `7505bc4dbb1ecd96d5f9d747035d0753961e8e4146dc9e738cf3a427281bb018`. UTCwindow2026-10-16T21:25:56Z..21:26:59Z. [Evidence archive](evidence/compiled-f4-cv32-no-error-boundary-20261017/evidence.tar.gz) and [SHA256](evidence/compiled-f4-cv32-no-error-boundary-20261017/evidence.sha256) preserve raw commands/READY/replies/fatal/stderr, generated artifact bytes, source-input hashes, source/PID/exit/audit receipts, build log/manifest and actualbinaryhash.

Prior skipped Icarus gate and pre-native filelist failure remain preserved and unaccepted in their original snapshot. This result does not convert them into passes. Continuous3-candidate/two-fresh production gates and arbitrary instruction search remain separate requirements.

## Independent saved-data review

The root agent independently verified the archive SHA, decoded the raw RESULT payload, checked actual pre-edge instruction req/grant/address and absence of a physical error tap, checked the exact second CMD backend ERR fields, and confirmed only the first command has a RESULT reply before the actual adapter fatal. READY artifact identity crosslinks to the build receipt and recorded actual binary SHA; source-before/after and all three controlling/source/audit exit files agree. [Machine-readable audit](evidence/compiled-f4-cv32-no-error-boundary-20261017/independent-audit.json). This audit only reads saved data and invoked no compiler/model.
