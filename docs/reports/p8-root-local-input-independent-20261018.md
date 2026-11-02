# P8 regular root local input: independent audit

Scope: the local regular root selection and prepared copy only. This is not a remote transfer, source adapter, whole project, P7, P8, runtime, or model pass.

## Selection

The first plan (`attempt1`, selection SHA256 `1a782c32bf49befeb3a0cf55e6f83d3f21f04d0efb1b9ad49c4b722dcff455e6`) was planned, not copied; it is not a failed copy. Review found 518 cache leaves (15,283,356 bytes). Attempt2 explicitly excluded those leaves without deleting original files.

Attempt2 selection SHA256 is `11e1e298379b54973836de4ec57d4383ab84f9302081e688db0edf1cb7a908f8`: 10,346 regular files, 493,088,962 bytes, 522 directories. The repeat independent source review actually ran at 09:39:03.226250–09:39:04.313031 UTC on 2026-10-18; its timestamp is not a backdated timestamp of the earlier inline review. All selected bytes and modes were read, with complete noncache src/scripts (1,112 files) and configs (509 files), no remaining cache leaves, `.gitmodules` retained and `.git/modules` excluded. Root HEAD was `269717b7e9cc7c92da5e427ac950bc82446b3ac6`.

## Actual copy and independent stage audit

The original strict preparer SHA256 `89a7c42963aac5c7761d76c9e0f80776209645cc2876e56743f96a0df0e83e02` ran as PID 43547 at 09:38:08.801736–09:38:24.732119 UTC, actual return code 0, stderr empty. The independent audit then ran at 09:39:58.542457–09:40:00.066972 UTC. It verified exact complete file/directory sets, modes, nlink=1 and file SHA256 against selection, generated entry, freeze, and receipt. Actual stage: 10,347 files (10,346 selected plus one generated empty private lock), 524 directories, 493,088,962 bytes.

Freeze SHA256: `27ec3b8a97d22b3272acf3dd90bf44f05a20f7ffd8c984be9b6b49054a2a6ba5`. Prepare receipt SHA256: `07fbab00a65dd862afd794fd2d5254707a55ad90b8170cea099eebf63c6ce920`. Source and stage HEAD matched the frozen HEAD. All 387 frontend files, including 58 ELF files, retained bytes/modes. A final complete selected source file/directory recheck was unchanged.

The audit used only standard library saved/file reads; it did not execute the preparer, Git, project imports, tests, models, or remote operations. Existing source and immutable outside controls/stage were not modified.

## Evidence

Small receipts, audit scripts/results and SHA/byte pins are in [evidence/p8-root-local-input-20261018](evidence/p8-root-local-input-20261018/). Full selection/freeze/maps remain at `archive/p8-source-metadata-20261018/root-control-attempt2/`（2026-10-26 由家目录 `/home/qinkejiu/myfuzz-p8-root-control-20261018-attempt2/` 整体移入，字节与 pin 未变）; stage remains at `archive/p8-source-metadata-20261018/root-input-attempt2/`. Neither the 493 MB stage nor large map/archive payloads are included in this commit. The preparer receipt remains `copied_pending_closure_and_tool_review`.
