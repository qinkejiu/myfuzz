#!/bin/bash
set -u
base=/root/fanzehui/obi-fail-stop-verilator-20261017-434a4e8
lock=/root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock
source /root/fanzehui/system-20261016/environment.sh
export TMPDIR="$base/tmp"
export PYTHONPATH="/root/fanzehui/system-20261016/pythonlib"
export PYTHONOPTIMIZE=0
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
unset PYTEST_ADDOPTS PYTEST_PLUGINS
ulimit -c 0
cd "$base/project" || exit 97
if test -e "$base/launched"; then exit 73; fi
( set -o noclobber; printf '%s\n' "$$" > "$base/launched" ) || exit 73
python3 "$base/verify.py" > "$base/source-before.json" 2>&1
preflight=$?
if test "$preflight" -ne 0; then printf '%s\n' "$preflight" > "$base/worker.exit"; exit "$preflight"; fi
exec 9>"$lock"
if ! flock -n 9; then printf '%s\n' 75 > "$base/worker.exit"; exit 75; fi
python3 -m pytest -c "$base/project/pytest.ini" --noconftest --rootdir "$base/project" -vv -s tests/protocols/test_obi_processor_memory_adapter_rtl.py::ObiProcessorMemoryAdapterRtlTests::test_backend_error_fail_stops_when_cpu_has_no_obi_error_channel_verilator > "$base/native.log" 2>&1 &
child=$!
printf '%s\n' "$child" > "$base/native.pid"
wait "$child"
result=$?
printf '%s\n' "$result" > "$base/native.exit"
python3 "$base/verify.py" > "$base/source-after.json" 2>&1
source_result=$?
printf '%s\n' "$source_result" > "$base/source-after.exit"
if test "$result" -ne 0; then printf '%s\n' "$result" > "$base/worker.exit"; exit "$result"; fi
if test "$source_result" -ne 0; then printf '%s\n' "$source_result" > "$base/worker.exit"; exit "$source_result"; fi
python3 "$base/audit.py" > "$base/audit.json" 2>&1
result=$?
printf '%s\n' "$result" > "$base/worker.exit"
exit "$result"
