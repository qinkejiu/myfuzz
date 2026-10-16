#!/bin/bash
set -euo pipefail
base=/root/fanzehui/boom-irq-factory-fix-20261017
actual=$(sha256sum "$base/ready.json")
test "${actual%% *}" = 20ad6eb738b67db8640f7e21299259fbc04f017f948960eddfa306e1dee0d211
for path in "$base/state/PID" "$base/state/launcher-PID" "$base/state/worker.exit" "$base/state/operation.claim" "$base/state/stage" "$base/state/result.json" "$base/state/failure.json" "$base/state/imports.json" "$base/project-finalized" "$base/artifact-finalized" "$base/logs/controller.log"; do
 if test -e "$path" || test -L "$path"; then exit 125; fi
done
set -C
nohup env PYTHONOPTIMIZE=0 bash "$base/run-control.sh" > "$base/logs/controller.log" 2>&1 </dev/null &
printf '%s\n' "$!"
