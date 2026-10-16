# IRQ native build preparation only — 2026-10-17

Frozen owned source:5bb888f. No source change since that source review.
Remote base: `/root/fanzehui/boom-irq-verification-20261017`.
Prepared through prescribed SSH transit; no native/build/elaboration or probe
execution, no canonical lock, no new job PID. Root's DMA window was not used.

`project` is an independent `cp -a` of the prior BOOM project, followed only by
an overlay of the13 frozen IRQ files and their existing build/pins files.
No `cp -al`; no writes to the prior BOOM project/native/evidence. The source
identity of inherited dependencies is the actual2426-file manifest, not a claim
that the whole snapshot equals current workspace HEAD. Scope:src/configs/tests
and third_party/soc-pulp-apb-gpio; Python bytecode excluded. Actual inode audit
found zero file inode sharing with old snapshot across those source scopes.

Actual Python-only import audit loaded all five new modules from the new
project. Source pins13/13 match. Static firmware bytes1280, SHA256
`acecf7cb717ea5fee1791e14313a8b66d94b96ac2c4b63a6c53645892f28ae39`.
No factory/session constructor or build generator was called in that audit.
`artifact` is a fresh empty directory; final check confirms no build.log or
state/PID. Preparation state remains `prepared_not_launched`.

## Frozen preparation receipts

Local durable directory: `.superpowers/boom-irq-verification-20261017/`.
Remote `ready.json` SHA256:
`98042cbc92c23abab04408de9f612a773665bf96be75bee0a32a952209caad20`.
Remote launch script: `/root/fanzehui/boom-irq-verification-20261017/launch.sh`
SHA256 `e4e506d137d9abd998f2a6edb9a5679a7869ff0b8c64a27df8c52f7de9723a16`.
Full source manifest SHA256:
`f7ab4b657052afc5e594c56529337a6401f81691bf2edb395877335f75d035ec`.
Owned pins SHA256:
`ba886f175961b8d42d0cd8834ed3ed4a1129dbade09a2028c242d4051c179d52`.
Build script SHA256:
`c7b0743c6672b49a3301cc1990892b1ada02cf8771edc703bfba8eea364d9ca4`.
Other audit and preparation hashes plus predicted full Verilator argv are in
ready.json. Local and remote final launch/ready hashes match.

## Next stage, not run

Only after exact parent GO, launch the prepared launch.sh (nohup command is in
ready.json). It records actual PID before checking the complete source file set
and hashes, verifies empty output, then invokes the existing build.sh. That
script uses prescribed environment/Python library and nonblocking canonical
heavy lock. Native builder records actual build exit and then invokes exactly:

`/root/fanzehui/boom-irq-verification-20261017/artifact/obj/VBoomTile --describe-probes`

This confirms actual generated VPI inventory/full names/widths with no measured
clock edge. It must fail on any mismatch; no fallback0 or guessed symbols.
Actual generated-probes.json, Syms source and executable join the final IRQ
artifact closure. No inventory/executable currently exists. Terminal status
files and probe stdout/stderr are listed in ready.json; root must check real
exits and worker termination before releasing the heavy slot.

This first stage establishes build and probe inventory only. It is not an IRQ
runtime gate. Runtime gate assembly, actual ISR/return/RAM evidence, fresh full
prefix comparison and missing/changed IRQ/status controls remain subsequent
work against actual confirmed generated symbols.

## Authorized first launch and corrected attempt2

After exact parent GO, attempt1 launcher200310 completed source precheck2426
without mismatch, then exited127 before the builder: prescribed environment
has /usr/bin/python3 but no `python` alias. No RTL build/probe/native process
started. Actual launch/build-and-probes exits127, worker absent, artifact empty
and canonical flock probe exit0 confirmed. Complete state/log/original scripts
and ready were copied independently into remote attempt1 and local attempt1.tar.

Root authorized one corrected attempt after these checks. Two launcher commands
now use python3; no environment alias or profile/driver/runtime source changed.
Focused interpreter regression actual RED1→GREEN1 (1 passed0.02s), without
executing launcher commands. Owned pins now additionally include build.sh14/14;
full source manifest remains unchanged2426 files. Python import/empty-output
audit repeated successfully. Corrected ready and launch hashes are in the
current ready.json. Independent attempt2 log/state paths avoid overwriting
attempt1. Parent received actual PID200937 and live builder200950/Verilator200958
with source precheck pass; first native build is now running, not yet a result.
