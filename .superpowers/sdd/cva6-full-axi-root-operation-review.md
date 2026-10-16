# CVA6 root-operation wrapper independent source review

2026-10-17; read-only review, no native/build/test/upload performed. Scope: `.superpowers/cva6-full-axi-root-operation/{run.sh,preflight.py,audit.py}` and the pinned inner gate's successful-path source verification in `scripts/verify_cva6_full_axi_observer.py:343`.

## Frozen bytes

- run.sh: `c854b5edf63169848b8ba19c0ce82f00d4c11f24809739ce68b7ef61fae58efa`
- preflight.py: `6ca99769e636b9525b95dd3324ece657a876ebc538d56fd24171aef40b5577a6`
- audit.py: `472f52a599bfb8b8d9224d171f25a8ce2e85370c9d58f9d8d2d316f9447767e9`

## Verdict

No high/medium source blockers found for this bounded operating wrapper. This is not an execution receipt or P7/source-authority acceptance.

The wrapper confines paths to the named fanzehui preparation, rejects reused operation/run output (including symlinks), probes canonical flock nonblocking, and delegates actual nonblocking lock ownership to the reviewed inner script. The probe is not treated as a lock reservation; a racing owner makes inner acquisition fail, which is preserved rather than queued/retried. It saves the actual spawned controller PID and exact wait status before audit, and preserves preflight/controller/audit failures in worker.exit. No outer heavy lock creates nested-lock deadlock.

Preflight pins inner script, source-freeze receipt and verifier; rejects symlink path components, root escape and changed source bytes across the freeze. PYTHONPATH selects the frozen source first; PYTHONOPTIMIZE=0 keeps assertion checks effective. Successful inner execution revalidates source after strict complete-prefix comparison before issuing summary pass; root audit does not itself repeat source hashing, but its required pass derives from that pinned inner verification.

Post-exit audit requires actual controller exit0, native_run true, both complete 650-sample/receipt runs, actual lifecycle closed/return0/poll0, different native execution identities/PIDs, two write beats and exact observed RAM values. It checks full-prefix equality flags plus raw samples/accepted/pending equality and rejects incomplete markers. Whole observer/runner/driver comparison and lifecycle validation remain the reviewed inner verifier's responsibility, rather than a new normalization in the wrapper.

The public scope remains bounded CPU RAM AXI observation: source_authority=false and retirement_verified=false. Actual remote source pre/post receipts, runtime PID/nonce identity and canonical release must still be checked after the eventual authorized execution; this review does not assert they already exist.
