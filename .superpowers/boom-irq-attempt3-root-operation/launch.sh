#!/bin/bash
set -euo pipefail
base=/root/fanzehui/boom-irq-runtime-attempt3-20261017
expected=96f5e22f37ccc574f5b8ba55b46a132afb4d0f845949d394ff76fedce0d39685
actual=$(sha256sum "$base/ready.json")
test "${actual%% *}" = "$expected"
for path in "$base/state/PID" "$base/state/launcher-PID" "$base/state/worker.exit" "$base/state/operation.claim" "$base/state/native-PID" "$base/state/native.exit" "$base/gate-output" "$base/gpio-cache" "$base/logs/controller.log"; do
 if test -e "$path" || test -L "$path"; then exit 125; fi
done
flock -n /root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock true
set -C
nohup env PYTHONOPTIMIZE=0 bash "$base/control/launch.sh" > "$base/logs/controller.log" 2>&1 </dev/null &
printf '%s\n' "$!"
