#!/usr/bin/env bash
set -uo pipefail
base=/root/fanzehui/boom-irq-verification-20261017
printf '%s\n' "$$" > "$base/state/PID"
printf '%s\n' 'live-source-check-before-build' > "$base/state/stage"
trap 'status=$?; printf "%s\n" "$status" > "$base/state/launch.exit"; printf "%s\n" terminal > "$base/state/stage"' EXIT
cd "$base/project" || exit
source /root/fanzehui/system-20261016/environment.sh || exit
export PYTHONPATH=/root/fanzehui/system-20261016/pythonlib:$PWD/src:$PWD
export PYTHONDONTWRITEBYTECODE=1
python3 -u - <<'PY'
import hashlib,json
from pathlib import Path
base=Path('/root/fanzehui/boom-irq-verification-20261017')
manifest=json.loads((base/'source-manifest.json').read_text())
errors=[name for name,expected in manifest['files'].items() if hashlib.sha256((base/'project'/name).read_bytes()).hexdigest()!=expected]
actual={str(file.relative_to(base/'project')) for scope in manifest['scope']
        for file in (base/'project'/scope).rglob('*')
        if file.is_file() and '__pycache__' not in file.parts and file.suffix!='.pyc'}
errors += sorted(actual ^ set(manifest['files']))
report={'checked_files':len(manifest['files']),'mismatches':errors,'pass':not errors}
(base/'state/source-check-before-build.json').write_text(json.dumps(report,indent=2)+'\n')
assert not errors,errors
assert not any((base/'artifact').iterdir()),'artifact output no longer empty'
PY
status=$?
if [ "$status" -ne 0 ]; then exit "$status"; fi
printf '%s\n' 'build-and-actual-probe-inventory' > "$base/state/stage"
bash .superpowers/boom-irq-verification-20261017/build.sh
status=$?
printf '%s\n' "$status" > "$base/state/build-and-probes.exit"
exit "$status"
