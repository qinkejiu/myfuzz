# F4 verification report — in progress

Verification is explicitly authorized by the latest user continuation. No prior pending option response is assumed. The current scope is the experimental directed F4 writer; full P7 and general search remain unaccepted.

## Completed software gates

`PYTHONPATH=src python3 -m pytest -q tests/integration/test_compiled_f4.py`: **7 passed, 1 skipped in 113.44s**, true pytest exit 0. This uses the current Ibex configuration. The skipped opt-in native case is not reported as passed.

`PYTHONPATH=src python3 -m pytest -q tests/integration/test_compiled_execution_files.py`: **32 passed in 0.29s**, true pytest exit 0. Controls cover lexical symlink retargets, changed declared dependency sets, unsupported executor/refusal evidence/explicit lock, exact native instruction and data hop acceptance/response/value/error/version/route changes, missing/mismatched native target commits, and post-start mutation of caller/private ownership, physical mapping, request, compiled document and artifact content. Native-hop events and selected authority dependencies are synthetic or mocked in these software controls; they establish fail-closed code behavior, not actual hardware execution.

## Source and environment

An ordinary independent rsync copy, without hardlink-based source sharing, is retained under `snapshot/` and remotely at `/root/fanzehui/f4-verification-20261017/project`. `source_manifest.json` pins 32605 non-Git files. Remote verification found no mismatches. Additive software control tests were committed after the snapshot; production runtime sources in the frozen snapshot are unchanged by those test additions. Raw remote environment information is in `logs/remote-environment.txt`.

## Native attempt 1

`remote_gate.sh` is the exact command script: explicit Ibex compose/capability/supplement/records, `compiled_f4_obi_apb`, three record submissions, 128 rounds per case, two fresh prefix replays, and canonical `--heavy-lock /root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock`.

The entry completed D2 generation and pure support admission, then refused because the canonical heavy lock was held by a DMA peer that had acquired it during a coordination race. **True entry exit 2**, `compiled-files-heavy-worker-lock-held`, `runtime_admitted=false`, total 34.56 seconds. No F4 native runtime object was constructed. The report and `.incomplete` are preserved in local `attempt1/` and the remote original `evidence/`; logs are under `logs/remote-attempt1/`. This is a scheduling refusal, not a hardware assertion failure or a passing RTL gate.

## Pending native gate

`remote_gate_attempt2.sh` uses the same frozen production sources and declarations with a new `evidence-attempt2/` output and separate log/true-exit/PID files. It is idle pending DMA terminal confirmation and root launch clearance. No native F4 result or fresh replay match is claimed yet.

## Native attempt 2 and constructor fix

After explicit launch clearance and confirmed prior lock release, attempt 2 exited **2** before native session construction: `TypeError: cannot pickle 'mappingproxy' object`. Its report accurately retains `startup_partial_trace_available=false` and `runtime_admitted=false`; this is a constructor implementation failure, not a semantic DUT failure. Source artifacts and raw failure evidence are preserved under local `attempt2/` and remote `evidence-attempt2/`.

The admitted Ibex fixture object graph contains immutable MappingProxyType metadata. The constructor's generic deepcopy could not copy these. The fix traverses admitted dataclasses/containers, seeds deepcopy's private memo with new immutable proxies over privately copied dictionaries, then copies the complete graph. The resulting private input/artifact identity must equal the exact issued identity and is re-admitted before native process startup. Caller/private ownership and metadata mutation refusal checks remain intact.

A source-reconstruction draft was rejected during development because the no-process regression exposed frontend elaboration subprocesses; its failure log is retained. The final fix copies exact already-admitted bytes without source rereads/frontends. The real-Ibex regression allows no Popen during private copying: **1 passed, 8 deselected in 16.27s**, exit 0. The 32 software refusal controls also pass on the fixed source, exit 0. A new independent frozen source snapshot and newly named native output are required before the next gate; no native retry result is claimed yet.

## Native attempt 3 — completed

True exit file `/root/fanzehui/f4-verification-20261017/logs/entry-attempt3.exit` is 0. Python159074 is gone and canonical lock has no holder. Three actual cases certified; two actual fresh replays return matches=true with identical complete semantic hash `568802e698c6fa86675b67e0cc8610af78b09d3c0253d54efd92b197dd09d7fa`; replay walls234.42/237.13s, total795.37s. Current post-fix focused suites report40passed/1skipped127.66s, exit0. Full source manifest32608files verified before/after. Final evidence is mirrored under attempt3/ with no .incomplete marker and archived with SHA256 under docs/reports/evidence/compiled-f4-ibex-20261017/. Public report: docs/reports/compiled-f4-ibex-verification-20261017.md. No-error variant design is documented separately, not implemented. Full P7/D4 remains unaccepted; subsequent candidate-layout source changes need new pins/gates.
