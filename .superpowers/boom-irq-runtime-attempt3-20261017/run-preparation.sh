#!/bin/bash
set -eu
base=/root/fanzehui/boom-irq-runtime-attempt3-20261017
source /root/fanzehui/system-20261016/environment.sh
export PYTHONDONTWRITEBYTECODE=1 PYTHONOPTIMIZE=0
export PYTHONPATH=/root/fanzehui/boom-irq-factory-fix-20261017/project-finalized/src:/root/fanzehui/boom-irq-factory-fix-20261017/project-finalized:/root/fanzehui/system-20261016/pythonlib
export TMPDIR="$base/tmp"
set -o noclobber
printf '%s\n' "$$" > "$base/state/preparation-launcher-PID"
set +e
python3 -u "$base/control/prepare.py" > "$base/logs/preparation.log" 2>&1
code=$?
printf '%s\n' "$code" > "$base/state/preparation.exit"
exit "$code"
