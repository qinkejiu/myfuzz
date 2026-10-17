#!/usr/bin/env bash
set -u
cd /home/qinkejiu/myfuzz
flock -w 14400 .superpowers/heavy-worker.lock bash -c '
set -u
cd /home/qinkejiu/myfuzz
export PYTHONPATH=src
export MYFUZZ_SCENARIO_REAL=1
export MYFUZZ_CVW_GPIO_CACHE=/home/qinkejiu/myfuzz/.superpowers/cache/cvw-session-gate
export MYFUZZ_CVW_GPIO_EVIDENCE=/home/qinkejiu/myfuzz/docs/reports/evidence/cvw-session-20261018/static-chain
setsid python3 -m pytest tests/local_harness/test_ahb_lite_session.py -q \
  > docs/reports/evidence/cvw-session-20261018/ahb-session-tests.log 2>&1
echo "ahb_session_exit=$?" >> docs/reports/evidence/cvw-session-20261018/ahb-session-tests.log
setsid python3 -m pytest tests/integration/test_cvw_cpu_pulp_gpio_chain_real.py -q \
  > docs/reports/evidence/cvw-session-20261018/static-chain-tests.log 2>&1
echo "static_chain_exit=$?" >> docs/reports/evidence/cvw-session-20261018/static-chain-tests.log
setsid python3 -m pytest tests/integration/test_cvw_ahb_runtime_generation.py -q \
  > docs/reports/evidence/cvw-session-20261018/ahb-runtime-generation-tests.log 2>&1
echo "ahb_runtime_generation_exit=$?" >> docs/reports/evidence/cvw-session-20261018/ahb-runtime-generation-tests.log
'
