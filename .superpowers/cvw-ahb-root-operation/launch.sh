#!/usr/bin/env bash
set -euo pipefail
base=/root/fanzehui/cvw-ahb-observer-20261017-attempt1
printf '%s  %s\n' 5cff1fcf5c9ea37821e273c25aa6857eb3dad18db6ec26c097b931b95d04b105 "$base/control/ready.json" ce931d7ba7ffe2391b3fc155056402d95178349078a764d5168e873801867a1f "$base/control/run-controlled.sh" | sha256sum --check -
for path in "$base/run" "$base/control/operation.claim.json" "$base/control/operation.terminal.json" "$base/control/controller.claim.json" "$base/control/child.started.json" "$base/control/controller.terminal.json" "$base/control/child.stdout" "$base/control/child.stderr" "$base/control/launcher.log"; do
 if test -e "$path" || test -L "$path"; then exit 125; fi
done
flock -n /root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock true
set -C
nohup env GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL="$base/control/empty.gitconfig" GIT_OPTIONAL_LOCKS=0 bash "$base/control/run-controlled.sh" > "$base/control/launcher.log" 2>&1 </dev/null &
printf 'controller_launch_pid=%s\n' "$!"
