#!/bin/bash
set -u
base=/root/fanzehui/f4-filelist-verification-20261017-b370e3d
project="$base/project"
lock=/root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock
case "${1:-}" in adapter|boundary|ibex|cv32) gate=$1;; *) echo 'usage: run_gate.sh adapter|boundary|ibex|cv32' >&2; exit 64;; esac
source /root/fanzehui/system-20261016/environment.sh
export PYTHONPATH="$project/src:$project:/root/fanzehui/system-20261016/pythonlib"
cd "$project" || exit 97
if test -e "$base/logs/$gate.pid" || test -e "$base/logs/$gate.exit" || test -e "$base/outputs/$gate"; then
  echo 'new gate output required; refusing overwrite' >&2; exit 73
fi
printf '%s\n' "$$" > "$base/logs/$gate.wrapper.pid"
python3 "$base/verify_snapshot.py" > "$base/logs/$gate.source-before.json" 2>&1
preflight=$?
if test "$preflight" -ne 0; then printf '%s\n' "$preflight" > "$base/logs/$gate.exit"; exit "$preflight"; fi
# Probe only: release immediately. The exact GO coordinator must reserve this window.
flock -n "$lock" true
probe=$?
printf '%s\n' "$probe" > "$base/logs/$gate.lock-probe.exit"
if test "$probe" -ne 0; then printf '%s\n' 75 > "$base/logs/$gate.exit"; exit 75; fi
printf '%s\n' "$(date -u +%FT%TZ)" > "$base/logs/$gate.started"
if test "$gate" = adapter; then
  # Pytest itself has no lock; retain one outer canonical lock around the whole test.
  exec 9>"$lock"
  if ! flock -n 9; then printf '%s\n' 75 > "$base/logs/$gate.exit"; exit 75; fi
  printf '%s\n' "$(date -u +%FT%TZ)" > "$base/logs/$gate.lock-acquired"
  python3 -m pytest -vv -s tests/protocols/test_obi_processor_memory_adapter_rtl.py::ObiProcessorMemoryAdapterRtlTests::test_backend_error_fail_stops_when_cpu_has_no_obi_error_channel > "$base/logs/$gate.log" 2>&1 &
elif test "$gate" = boundary; then
  python3 scripts/check_compiled_obi_no_error_boundary.py --base-dir "$project" \
    --compose configs/scenarios/compiled-f4-obi-apb/compose.json \
    --ip-capability configs/scenarios/compiled-f4-obi-apb/test_capability.json \
    --supplement configs/scenarios/compiled-f4-obi-apb/execution_supplement.json \
    --output-dir "$base/outputs/boundary" --cache-dir /root/fanzehui/system-20261016/f4-cv32-cache \
    --heavy-lock "$lock" --max-rounds 256 --command-timeout 30 > "$base/logs/$gate.log" 2>&1 &
else
  if test "$gate" = ibex; then config=compiled-f4-obi-apb-ibex; cache=f4-ibex-cache; else config=compiled-f4-obi-apb; cache=f4-cv32-cache; fi
  # CLI takes its own canonical lock for live + all fresh replays: no outer lock.
  python3 scripts/run_compiled_dataflow.py --compose "configs/scenarios/$config/compose.json" \
    --ip-capability "configs/scenarios/$config/test_capability.json" \
    --supplement "configs/scenarios/$config/execution_supplement.json" \
    --records "configs/scenarios/$config/example_records.json" --executor compiled_f4_obi_apb \
    --output "$base/outputs/$gate" --cache-dir "/root/fanzehui/system-20261016/$cache" \
    --heavy-lock "$lock" --run-id "compiled-f4-$gate-abi" --max-cases 3 --rounds-per-case 128 --replays 2 > "$base/logs/$gate.log" 2>&1 &
fi
child=$!
printf '%s\n' "$child" > "$base/logs/$gate.pid"
wait "$child"
actual_exit=$?
printf '%s\n' "$actual_exit" > "$base/logs/$gate.exit"
python3 "$base/verify_snapshot.py" > "$base/logs/$gate.source-after.json" 2>&1
source_exit=$?
printf '%s\n' "$source_exit" > "$base/logs/$gate.source-after.exit"
printf '%s\n' "$(date -u +%FT%TZ)" > "$base/logs/$gate.finished"
if test "$actual_exit" -ne 0; then exit "$actual_exit"; fi
if test "$source_exit" -ne 0; then exit "$source_exit"; fi
python3 "$base/validate_gate.py" "$gate" > "$base/logs/$gate.audit.json" 2>&1
audit_exit=$?
printf '%s\n' "$audit_exit" > "$base/logs/$gate.audit.exit"
exit "$audit_exit"
