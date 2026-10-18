#!/bin/bash
set -euo pipefail
set -C
if [ "$#" -ne 3 ]; then
  echo 'usage: launch-native-gate.sh FILE_FREEZE_SHA COPY_RECEIPT_SHA DIRECTORIES_FILE_SHA' >&2
  exit 2
fi
export MYFUZZ_SOURCE_ROOT=/root/fanzehui/myfuzz/operations/p6-native-completion-20261018-attempt1/project
export PYTHONDONTWRITEBYTECODE=1
. /root/fanzehui/myfuzz/operations/environment-20261018-attempt3/environment.sh
cd "$MYFUZZ_SOURCE_ROOT"
exec python3 /root/fanzehui/myfuzz/operations/p6-native-completion-inputs-20261018-attempt1/run_native_gate.py \
  --freeze-sha256 "$1" --receipt-sha256 "$2" --directories-file-sha256 "$3" \
  >/root/fanzehui/myfuzz/operations/p6-native-completion-20261018-attempt1/gate-parent.stdout \
  2>/root/fanzehui/myfuzz/operations/p6-native-completion-20261018-attempt1/gate-parent.stderr
