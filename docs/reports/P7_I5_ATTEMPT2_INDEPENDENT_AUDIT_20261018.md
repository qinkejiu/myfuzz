# P7 I5 attempt2 independent evidence audit

2026-10-18 08:01 UTC read-only collection. Operation: `/root/fanzehui/myfuzz/operations/p7-i5-independent-601964f-20261018-attempt2`.

I5 local acceptance evidence is internally consistent. This audit does not close P7; P6, P7 and P8 remain OPEN. No tests, probes, builds, models or gates were started during this audit.

- Controller PID 3340261 terminated with return code 0; real gate PID 3783383 return code 0.
- Independent JUnit parsing: N1–N8 executed 2/1/1/5/2/1/2/6 cases (20 total); every group has zero failure/error/skip and process return code 0.
- Actual gate argv selected CV32E20/CVE2 and PULP timer, `compiled-f4-rfuzz`, 32 rounds per case. Session records 2 certified receipts, 5 completed feedback exchanges, client return code 0, and 91.51387357000203 effective search seconds.
- Receipt bytes independently hash to the compiled receipt join SHA; both rows refer to `F4:ram.image` and `peripheral.TIMER0_CTRL.value.mmio`. Receipt compiled digest joins the recorded digest `567cf4200a9f07f3daa80bb4efc2471064d3cb1bedb99709ac6b4388b39c3f99`.
- Full fresh replay reports 536 events / 2 records, matching prefix and semantic hashes with no difference. Fresh peripheral PID 4034503 and processor PID 4035411 differ from original 3894782/3895649; fresh execution audit records both reaped with return code 0 and closed=true.
- Source-before/source-after, client-before/client-after, and tool-freeze/tools-after dictionaries compare equal independently. Before and after layout receipts each report 15333 files / 1330 directories, file freeze SHA `e3d2eaa2937fd665ad816250e976e7745cefe220a71e51a5815a892bd35a13fa`, directory SHA `9e055be358785fdd196c3be6e35dd0e61fb4d986643430cc77c9d766577c750c`.
- Read-only `ps` observation found no listed controller/N1/gate/original/fresh DUT PID and no operation-path process. This is a terminal observation, not a claim that original DUT exit return codes are independently available; explicit reaping receipts are retained for the fresh DUT pair.

Evidence: [independent-audit.json](evidence/p7-i5-attempt2-independent-20261018/independent-audit.json), `acceptance-evidence.tar.gz`, `archive.sha256`, and member hash manifest in the same directory. Archive retains control and run-attempt2 except native-cache, including JUnit, process receipts, session/bundle receipts, generated source and replay artifacts. Initial transfer included native-cache; it was removed from the retained archive without executing it. Original transfer SHA/member hashes are retained for provenance. No project tree or client binary was transferred.
