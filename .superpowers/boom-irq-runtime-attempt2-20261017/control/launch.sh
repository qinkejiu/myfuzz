#!/usr/bin/env bash
set -uo pipefail
base=/root/fanzehui/boom-irq-runtime-attempt2-20261017
for path in "$base/state/PID" "$base/state/launcher-PID" "$base/state/worker.exit" "$base/state/operation.claim" "$base/state/native-PID" "$base/state/native.exit" "$base/gate-output" "$base/gpio-cache"; do
  if test -e "$path" || test -L "$path"; then
    echo "runtime operation already used; no state changed" >&2
    exit 125
  fi
done
source /root/fanzehui/system-20261016/environment.sh || exit
export PYTHONPATH=$base/project/src:$base/project:/root/fanzehui/system-20261016/pythonlib
export PYTHONDONTWRITEBYTECODE=1
export TMPDIR=$base/temp
cd "$base/project" || exit
exec python3 -u "$base/control/controller.py" --run-native-once
