#!/usr/bin/env bash
set -uo pipefail
base=/root/fanzehui/boom-irq-factory-fix-20261017
# Read-only preflight; the controller's exclusive claim covers direct and shell entries.
for path in "$base/state/PID" "$base/state/launcher-PID" "$base/state/worker.exit" "$base/state/operation.claim" "$base/project-finalized" "$base/artifact-finalized"; do
  if test -e "$path" || test -L "$path"; then
    echo "metadata operation already used; no state changed" >&2
    exit 125
  fi
done
source /root/fanzehui/system-20261016/environment.sh || exit
export PYTHONPATH=$base/source/src:$base/source:/root/fanzehui/system-20261016/pythonlib
export PYTHONDONTWRITEBYTECODE=1
export TMPDIR=$base/temp
cd "$base/source" || exit
exec python3 -u "$base/control.py" --metadata-only-once
