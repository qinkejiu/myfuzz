#!/bin/bash
set -uo pipefail
cd /root/fanzehui/boom-verification-20261017/project
source /root/fanzehui/system-20261016/environment.sh
export PYTHONPATH=/root/fanzehui/system-20261016/pythonlib:$PWD/src:$PWD
printf '%s\n' waiting-or-running-coherent-supplement > /root/fanzehui/boom-verification-20261017/state/coherent-stage
flock /root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock python3 -u -m myfuzz.scenario.boom_coherent_verification --repo "$PWD" --cpu-output /root/fanzehui/boom-verification-20261017/native --output /root/fanzehui/boom-verification-20261017/coherent --one-shot-trace /root/fanzehui/boom-verification-20261017/one-shot/fresh1.jsonl
probe_status=$?
printf '%s\n' "$probe_status" > /root/fanzehui/boom-verification-20261017/state/coherent.exit
printf '%s\n' coherent-supplement-finished > /root/fanzehui/boom-verification-20261017/state/coherent-stage
exit "$probe_status"
