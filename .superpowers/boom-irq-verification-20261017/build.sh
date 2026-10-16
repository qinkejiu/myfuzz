#!/usr/bin/env bash
set -euo pipefail
cd /root/fanzehui/boom-irq-verification-20261017/project
source /root/fanzehui/system-20261016/environment.sh
export PYTHONPATH=/root/fanzehui/system-20261016/pythonlib:$PWD/src:$PWD
python - <<'PY'
import hashlib,json
from pathlib import Path
pins=json.loads(Path('.superpowers/boom-irq-verification-20261017/source-pins.json').read_text())
for name,digest in pins.items():
    if hashlib.sha256(Path(name).read_bytes()).hexdigest()!=digest:
        raise SystemExit('IRQ prepared source mismatch: '+name)
PY
python -m myfuzz.local_harness.boom_irq_generation --repo "$PWD" \
  --output /root/fanzehui/boom-irq-verification-20261017/artifact \
  --heavy-lock /root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock
