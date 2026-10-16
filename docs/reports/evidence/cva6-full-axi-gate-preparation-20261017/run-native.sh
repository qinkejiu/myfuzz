#!/usr/bin/env bash
set -euo pipefail
source /root/fanzehui/system-20261016/environment.sh
base=/root/fanzehui/cva6-full-axi-observer-20261017-attempt1
project=$base/project
export PYTHONPATH=$project/src:$project:/root/fanzehui/system-20261016/pythonlib
export TMPDIR=$base/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONOPTIMIZE=0
cd "$project"
exec python3 scripts/verify_cva6_full_axi_observer.py --run-native --repo "$project" --output "$base/run" --heavy-lock /root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock --freeze "$base/control/source-freeze.json" --freeze-sha256 9f2c0510e7430b8f4f11f3ef5ff058f329d586004359d88521e55557b025c130
