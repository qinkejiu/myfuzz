#!/usr/bin/env bash
# Prepared source only. Root exact GO is still required before execution.
set -euo pipefail
source /root/fanzehui/system-20261016/environment.sh
base=/root/fanzehui/cvw-ahb-observer-20261017-attempt1
project=$base/project
export PYTHONPATH=$project/src:$project:/root/fanzehui/system-20261016/pythonlib
export TMPDIR=$base/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONOPTIMIZE=0
cd "$project"
printf '%s  %s\n' bb1b121327b52ae26e4b64d57d5b5cd5676c7ae3f1a208d891a3009e622f9ebd "$base/control/cvw_ahb_gate_control.py" | sha256sum --check -
exec python3 "$base/control/cvw_ahb_gate_control.py" --execute --base "$base" --freeze-sha256 c02134412a742eccde99746af5487f81c2f77f09a7cf20250ce37f2077762e8f --source-map-sha256 75244d6c7b7e6490ece1c70c20d3e143f9791804dd8f2a247f6e4d088af0dce9
