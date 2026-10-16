# F4 verification — 2026-10-17

Authorized current-state verification. Independent source snapshot is `snapshot/`; `source_manifest.json` pins its non-Git bytes. Local current-Ibex pure pytest is active. Remote snapshot transfer is active. No native gate result yet.

Local existing pure gate completed: `7 passed, 1 skipped in 113.44s`, process exit 0. Its real RTL case is intentionally skipped without the opt-in environment variable. Gate stdout/command/exit are saved under logs/. Remote production gate is queued behind DMA's canonical heavy lock; no native F4 process has started.

Remote gate started after DMA released the canonical lock. Shell PID 141854; Python entry PID 141855. The entry acquires `/root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock` itself. Frozen remote source verification matched all 32605 pinned files. Software entry/hop regression controls now report 18 passed in 0.38s, exit 0; these model contracts and are not native RTL evidence.

Attempt 1 terminated before native startup: true entry exit 2, `compiled-files-heavy-worker-lock-held` after generation. DMA held the canonical lock due a coordination race. Refusal report and `.incomplete` retained under remote evidence/ and local attempt1/. No assertions were weakened; attempt2 is prepared with a new output path and awaits explicit root launch clearance.

Attempt 2 terminal: entry exit 2 before native construction, `cannot pickle 'mappingproxy' object`. Private admitted graph copying now supports independent immutable proxies and exact identity/readmission (commit bdeee0b). Actual-profile no-Popen copy regression: 1 passed / 8 deselected, 16.27s; all 32 software refusal controls pass. New independent `snapshot-attempt3/` and remote `project-attempt3/` freeze current source; remote source verification matched 32608 files, zero mismatches. Attempt3 command is ready with NEW evidence path and separate raw logs/PID/exit, awaiting root clearance after DMA3/BOOM. No native F4 pass/replay claimed.

TERMINAL attempt3: actual /root/fanzehui/f4-verification-20261017/logs/entry-attempt3.exit=0; PID159074 gone; canonical lock released.3actualcases certified, both actualfreshreplays matches=true, semantic hash568802e698c6fa86675b67e0cc8610af78b09d3c0253d54efd92b197dd09d7fa. Public report and SHA256-pinned evidence archive saved under docs/reports/. No-error design only; candidate integration deferred until independent review/root reactivation. This freezes the completed experimental Ibex F4 scope, not full P7.
