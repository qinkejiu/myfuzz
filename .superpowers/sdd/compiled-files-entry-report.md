# Public compiled execution file entry — 2026-10-17

Added `myfuzz.integration.compiled_execution_files` and `scripts/run_compiled_dataflow.py`. The public setup creates D2 artifacts from an explicit composition, builds the actual path compile request with explicitly selected IP capability files, applies only supported request supplement sections, compiles D3, reloads exact generated artifacts and compiles caller-declared ownership/physical mappings before support admission. It imports no test modules and has no component/profile-name dispatch. `compiled_f4_obi_apb` is an explicit executor choice; other names refuse and retain a report.

Added `configs/scenarios/compiled-f4-obi-apb-ibex/execution_supplement.json`. Its environment link names the actual GPIO pin endpoint; its 32-bit `gpio_in` ownership cites the compiled `peripheral.in.external` source; its physical map names actual `gpio_in`. These names are explicit fixture declarations, not runtime inference. Native GPIOEN and MMIO producers remain generated RTL/live authority; no supplemental producer or expected target result is manufactured.

The run entry requires a new output directory and an explicit JSON list of eight-byte hex records. It bounds records, case count, rounds and fresh replay count. It pins input composition/request/profile/capability/supplement/record bytes, explicitly referenced native source files, implementation/adapter files and the launch script; changed pinned inputs refuse before native startup, every source submission and each fresh replay. Saved declarations and hashes are review artifacts, not authority objects.

Native startup, continuous submissions, finish, all fresh replays and error cleanup hold `.superpowers/heavy-worker.lock`. The replay invokes the code-owned runtime's exact live-prefix comparison followed by fresh construction/re-admission of private trusted source declarations and new process-local GPIOEN tokens. This entry does not deserialize saved JSON into live tokens or execute persisted generated binaries as trusted authority. It has no network path or remote launch behavior.

Outputs include D2 sources, D3 request/compiled paths, capability-selection/support reports, exact input declarations/hashes, per-case wall times, completed prefix/events, fresh replay results, startup/generation/total times and useful cases per case-execution second. Failures retain `.incomplete`, a reasoned report and available partial native events. Successful reports explicitly scope execution as experimental directed candidates; coverage-guided search, general instruction search and full D4 acceptance remain false.

No tests were added or run. No code generation, builds, simulation, command execution gate or fresh replay was performed. This implementation is source-reviewed only and unverified. An authorized future invocation, using a caller-created records JSON file, is:

```bash
python3 scripts/run_compiled_dataflow.py \
  --compose configs/scenarios/compiled-f4-obi-apb-ibex/compose.json \
  --ip-capability configs/scenarios/compiled-f4-obi-apb-ibex/test_capability.json \
  --supplement configs/scenarios/compiled-f4-obi-apb-ibex/execution_supplement.json \
  --records /absolute/path/to/records.json \
  --executor compiled_f4_obi_apb \
  --output /absolute/path/to/new-evidence-directory \
  --cache-dir /absolute/path/to/build-cache \
  --run-id compiled-f4-ibex --max-cases 64 --rounds-per-case 128 --replays 2
```

The launch consumes only the explicitly provided records. Historical CV32 evidence and its frozen source snapshot are untouched. The entry does not by itself establish that the Ibex fixture passes current runtime admission or exact-hop checks.
