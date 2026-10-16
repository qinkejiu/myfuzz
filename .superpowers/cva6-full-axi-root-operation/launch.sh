#!/bin/bash
set -u
base=/root/fanzehui/cva6-full-axi-observer-20261017-attempt1
if test -e "$base/control/root-operation" || test -L "$base/control/root-operation" || test -e "$base/run" || test -L "$base/run"; then exit 73; fi
nohup bash "$base/control/root-runner.sh" > "$base/control/root-launcher.log" 2>&1 < /dev/null &
printf '%s\n' "$!"
