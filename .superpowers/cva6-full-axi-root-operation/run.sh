#!/bin/bash
set -u
base=/root/fanzehui/cva6-full-axi-observer-20261017-attempt1
operation=$base/control/root-operation
lock=/root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock
source /root/fanzehui/system-20261016/environment.sh || exit 97
export PYTHONPATH=$base/project/src:$base/project:/root/fanzehui/system-20261016/pythonlib
export PYTHONDONTWRITEBYTECODE=1 PYTHONOPTIMIZE=0 TMPDIR=$base/tmp
if test -e "$operation" || test -L "$operation" || test -e "$base/run" || test -L "$base/run"; then exit 73; fi
# Probe, never queue. The inner reviewed script owns the actual lock lifecycle.
flock -n "$lock" true || exit 75
mkdir "$operation" || exit 73
printf '%s\n' "$$" > "$operation/wrapper.pid"
python3 "$base/control/root-preflight.py" > "$operation/preflight.json" 2>&1
status=$?
if test "$status" -ne 0; then printf '%s\n' "$status" > "$operation/worker.exit"; exit "$status"; fi
bash "$base/control/run-native.sh" > "$operation/native.log" 2>&1 &
child=$!
printf '%s\n' "$child" > "$operation/controller.pid"
wait "$child"
status=$?
printf '%s\n' "$status" > "$operation/controller.exit"
if test "$status" -ne 0; then printf '%s\n' "$status" > "$operation/worker.exit"; exit "$status"; fi
python3 "$base/control/root-audit.py" > "$operation/audit.json" 2>&1
status=$?
printf '%s\n' "$status" > "$operation/worker.exit"
exit "$status"
