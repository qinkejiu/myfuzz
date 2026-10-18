# Native source-binding preparation: independent source/data review

Conclusion: scoped clean after the explicit directory-selection revision. This is source/data review only; it grants no actual copy, gate, runtime, C2 consumption, retirement, feedback or P6 result.

Report recorded at 2026-10-18T10:14:09.243012+00:00 UTC. The review used only file reads, standard-library JSON/AST/tar parsing and hashes. No controller or project code was executed/imported; no tests, Git queries, compiler, models, upload or remote operations were run by this review.

## Selected closure and correction

Reviewed directory: `.superpowers/sdd/native-source-binding-20261018/attempt1-control/`. Immutable source is remote native-completion attempt2/project; target is the new `p6-native-source-binding-20261018-attempt1/project`. Baseline files SHA256 is `3c287137bfa7e98c6b28444b20b26fa2e6ab25d6a01c2262594408fa380e44be`, directories `861e192518e1d809231b676b91b17c149466000f83138969eac6cbfaff68fb36`.

The first draft retained four current empty directories and advertised605 directories. The author revised the selection before execution: scripts/maintenance, frontend CompilerIdCXX/tmp, frontend pkgRedirects and protocols/rtl/.myfuzz-elaboration-pac5y844 are explicitly excluded residue. Final directories now exactly equal the baseline601 directory map, preserving existing baseline empty directories. Final files total8892. No actual failed copy or gate is implied by this draft correction.

Independently reread all1112 noncache current src/scripts regular files and checked nlink1, size, mode and SHA256 against the complete current map. The twelve overlays exactly equal all current-versus-baseline differences, with no old extra source files or deletion. The new binding producer is included. All configurations, third-party files, frontend/build/ELF/shared-library files and root/component Git metadata remain baseline bytes/modes. Full expected file map equals baseline merged with the twelve overlay files; full expected directory map equals baseline.

Every payload/control member of the revised tar was read and compared with its selected local file/reference, with regular/directory types, modes and duplicate rejection. All twelve input-pins entries matched actual size/SHA. Static host declarations remain HOST v1=34, HARNESS v2=70; historical69-path evidence does not certify this payload.

## Twelve reviewed source paths

- `scripts/verifier/native_completion_gate_checks.py`
- `scripts/verify_picorv32_native_online.py`
- `src/myfuzz/integration/picorv32_native_online.py`
- `src/myfuzz/local_harness/native_session.py`
- `src/myfuzz/scenario/host_identity.py`
- `src/myfuzz/scenario/memory.py`
- `src/myfuzz/scenario/memory_service.py`
- `src/myfuzz/scenario/native_instruction_source_binding.py`
- `src/myfuzz/scenario/native_packet_session.py`
- `src/myfuzz/scenario/native_replay_identity.py`
- `src/myfuzz/scenario/runner.py`
- `src/myfuzz/scenario/session_runtime.py`

These are the connected opt-in source scope in9b5e190; the separate integration review covered actual service return/event-index binding, one-shot ownership anchors, defaultFalse, saved plan20/21, typed nonce projection and lifecycle. This preparation review does not replace a new actual gate.

## Controller boundaries

`prepare_copy.py` fixes old source/new destination under fanzehui, verifies complete baseline before and after, refuses symlinks/specials/hardlinked regular files, checks the overlay map, copies full files/directories into an exclusive stage, verifies the complete result and host70, and atomically publishes. It launches no Git/tool/model and cannot write the old attempt2 source.

Parent and launcher retain frozen env3 identities (environment9141, tool manifest6591, inventory9672), actual executable and115-share/581-pythonlib full-map checks before/after, four actual Git preflights, canonical `/root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock` with nonblocking acquisition and handoff to the child. Child wait stays with the same Popen after interruption, preserving primary errors and actual stream/terminal receipts without killing/restarting. The directed child carries both `--native-completion-observation` and `--native-source-binding`, fixed new cache/output, and gate source SHA `00401f20c9ec4ea098086557969b9e610a9b7268b67118978da06bfe803c3bb7`.

New actual deployment/copy, independent complete source/output map review, actual copy-receipt pins, root scheduling of the heavy gate and independent saved-data auditing remain required. Expected directed counts in the draft are acceptance criteria, not measured results.

## Exact reviewed pins

`input-pins.json` SHA256: `9454db97a9b3d7a230b031bac10246e3adf39067dd917d20cbbeb782585aa96d`.

| Artifact | Bytes | SHA256 |
| --- | ---: | --- |
| `baseline-directories.json` | 35081 | `861e192518e1d809231b676b91b17c149466000f83138969eac6cbfaff68fb36` |
| `baseline-files.json` | 1632255 | `3c287137bfa7e98c6b28444b20b26fa2e6ab25d6a01c2262594408fa380e44be` |
| `copy-inputs.tar.gz` | 1319795 | `272a3b0cd8713aa7cc3b0b27fbf7ae05aa9be0e8f0e588509ba50601c37e56c7` |
| `expected-final-directories.json` | 35081 | `861e192518e1d809231b676b91b17c149466000f83138969eac6cbfaff68fb36` |
| `expected-final-files.json` | 1632443 | `d5ce57a590fc3f1668f9e1606c187818fffc66a78c7367f268e54884267c3024` |
| `launch-native-gate.sh` | 811 | `dbc7b7fe1ff78461fe79ca4b1925401e9ab28cde05bcbeb3d9c91faca89027ac` |
| `local-current-src-scripts.json` | 201375 | `3ca53e65a9efe939f0c4eb46249eb745587081b4d6fc2660cad0ebddaaa1a9a8` |
| `overlay-map.json` | 2573 | `3f0404498e11a4d1e9e5dadca72df9973e9778c4e4bcb4f097c6be4042429f24` |
| `overlay-paths.json` | 568 | `551491be43df4fbdb540cb204bdb67428b7e4456dba25649ebf7934ca1700860` |
| `prepare_copy.py` | 11115 | `9a2f9efd8ce6331eb396625a9cfc83e3ca0d8be82838330be425efc4b22d13b3` |
| `run_native_gate.py` | 13292 | `04d32a34b9795a32d19f1628acfdb1bf595467dada4bc0fc7a07b4957cea5717` |
| `selection.json` | 656 | `1df0ac1db3ce4c0d081a4f810fe96fbfc46fd0ed9aada658f0e546fff77c5ac8` |
