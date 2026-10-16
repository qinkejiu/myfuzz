#!/bin/bash
set -euo pipefail
base=/root/fanzehui/boom-irq-runtime-attempt2-20261017
expected=2c2ffdd7d21252bf323a9b866a01d1e16d68b1c727664ab9a657760ff4089116
actual=$(sha256sum "$base/ready.json")
test "${actual%% *}" = "$expected"
for path in "$base/state/PID" "$base/state/launcher-PID" "$base/state/worker.exit" "$base/state/operation.claim" "$base/state/native-PID" "$base/state/native.exit" "$base/gate-output" "$base/gpio-cache" "$base/logs/controller.log"; do
 if test -e "$path" || test -L "$path"; then exit 125; fi
done
flock -n /root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock true
set -C
nohup env PYTHONOPTIMIZE=0 bash "$base/control/launch.sh" > "$base/logs/controller.log" 2>&1 </dev/null &
printf '%s\n' "$!"
