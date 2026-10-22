# P6 Attempt10 r10 Controller Repair — 2026-10-19

## Status

The r10 frozen package is reviewed and uploaded. The controller and P6 gate have **not** been started. P6 remains open; this report records preparation and a pending execution-scope decision, not a runtime result.

## r9 failure and repair

The r9 controller failed before claim creation at its tool-freeze JSON read. `read_regular()` returns bytes and `strict_json()` already decodes bytes as UTF-8, but the caller applied `.decode("utf-8")` first, passing a `str` into the bytes decoder and raising `AttributeError: 'str' object has no attribute 'decode'`. The r10 repair passes the bytes directly to `strict_json()`.

Read-only inspection after the r9 failure found no claim, preflight or controller receipt, launch intent, gate start/process-started/end receipt, gate log, or evidence output. The r9 artifacts remain preserved.

## Reviewed frozen identities

| Package | Canonical digest | Manifest raw SHA-256 | Review |
|---|---|---|---|
| Stage1 r10 | `ed7f53aa183e06a2341770805ddf1eecdc8d5a6e6ac22a7692096047e477f84b` | `ad44d0ab9a7116fbfdf09f50f93cb0a4001ff58116e36f89dbbeee9a3fb29c99` | Two independent exact-digest ACCEPTs |
| Stage2 r10 | `2fb5f718368042fac5e665184f8966269badff7a17903036d86f8db9fb2f1646` | `1e8242df2ede2d7a3be44472c453fa064ace2f7279bd86a27637fed7a477cc41` | Two independent exact-digest ACCEPTs |

All 11 r10 files were uploaded under `/root/fanzehui/myfuzz/operations/p6-native-instruction-bus-completion-v1-20261019-attempt10/` with exclusive no-follow creation, readback, and metadata checks. Controller and runner are mode `0700`; the other nine files are `0600`; every file is root-owned with one hard link. Two independent read-only post-upload reviews ACCEPTed the same Stage2 digest. All 11 r9 predecessors retain their expected identities. The one-shot and runtime receipt paths and the evidence directory remain absent.

The local review records are [Stage1 review A](../../.superpowers/sdd/r10-review-a.md), [Stage1 review B](../../.superpowers/sdd/r10-review-b.md), [Stage2 review A](../../.superpowers/sdd/r10-stage2-review-a.md), [Stage2 review B](../../.superpowers/sdd/r10-stage2-review-b.md), [post-upload review A](../../.superpowers/sdd/r10-postupload-review-a.md), and [post-upload review B](../../.superpowers/sdd/r10-postupload-review-b.md).

## Execution scope conflict

The frozen controller hashes its configured tool paths before creating the claim. The r10 tool freeze includes `/usr/bin/python3.12`, `/usr/bin/git`, and `/usr/bin/perl`; these reads are outside the remote file-operation scope in [agent.md](../../agent.md), which limits target-machine file operations to `/root/fanzehui/**`. Therefore no r10 controller or gate process has been invoked. The user directed us to continue; work is proceeding within the existing boundary, with r10 left untouched while we check for a workspace-local tool route.

A metadata-only executable-basename inventory covered `/root/fanzehui` while pruning the read-only `/root/fanzehui/system-20261016` subtree. It found no regular executable files named `python`, `python3`, `python3.12`, `git`, or `perl`; the separate inspection of the new and legacy myfuzz tool/cache locations reached the same result. This establishes that the checked worksets do not already contain obvious same-named copies, but does not rule out renamed binaries.

## Acceptance boundary and next step

The repair has only cleared static package review, upload integrity, and preservation checks. It has not shown that a gate ran, and grants no source-consumption, decode, retirement, semantic-consumption, feedback, or formal-completion authority. Keep the frozen packages and r9 history unchanged. Once the path-scope choice is resolved, either launch only through the reviewed r10 contract, or create a new revision with all required identities/reviews/upload checks repeated. Append the eventual controller, gate, runner, and independent-auditor terminal result here; do not mark P6 complete unless that audit satisfies the frozen acceptance criteria.
