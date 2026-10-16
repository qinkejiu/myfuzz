#!/bin/bash
set -u
TASK=/root/fanzehui/system-20261016/dma-continuous-verification-20261017/attempt4-replay-diagnostic
trap 'task_exit=$?; printf "%s\n" "$task_exit" > "$TASK/worker.exit"' EXIT
printf '%s\n' "$$" > "$TASK/worker.pid"
exec 9>/root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock
flock -n 9 || exit 2
source /root/fanzehui/system-20261016/environment.sh
cd /root/fanzehui/system-20261016/dma-continuous-verification-20261017/attempt4-project
export PYTHONPATH="/root/fanzehui/system-20261016/pythonlib:$PWD/src:$PWD"
python3 -u "$TASK/capture_replay.py" > "$TASK/replay.log" 2>&1
