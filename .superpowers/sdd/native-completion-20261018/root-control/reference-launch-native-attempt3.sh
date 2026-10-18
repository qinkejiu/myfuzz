#!/bin/bash
set -euo pipefail
export MYFUZZ_SOURCE_ROOT=/root/fanzehui/myfuzz/operations/p6-native-online-c924aac-20261018-attempt2/project
. /root/fanzehui/myfuzz/operations/environment-20261018-attempt3/environment.sh
cd "$MYFUZZ_SOURCE_ROOT"
exec python3 /root/fanzehui/myfuzz/operations/p6-native-inputs-20261018/run_p6_attempt3.py --freeze-sha256 50145c2408804a76c6ff651cefbb143aae17cd1be18559f79ea6386b510e2cc4 --receipt-sha256 c6f570ae39acfd44aec14c2391cfe5c4e1f686707db0bd07f7f926d920b9a017
