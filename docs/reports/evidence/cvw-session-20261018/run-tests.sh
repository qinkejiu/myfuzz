#!/usr/bin/env bash
# Reproduce the CVW directed-session gate's focused tests and negative control.
set -u
cd /home/qinkejiu/myfuzz
export PYTHONPATH=src
export MYFUZZ_SCENARIO_REAL=1
export MYFUZZ_CVW_SESSION_CACHE="$PWD/.superpowers/cache/cvw-session-gate"
flock -w 14400 .superpowers/heavy-worker.lock bash -c '
set -u
cd /home/qinkejiu/myfuzz
export PYTHONPATH=src MYFUZZ_SCENARIO_REAL=1
export MYFUZZ_CVW_SESSION_CACHE=/home/qinkejiu/myfuzz/.superpowers/cache/cvw-session-gate
python3 -m pytest tests/integration/test_cvw_runtime_family.py::test_the_family_cli_starts_a_real_directed_session_and_grades_f4 -q \
  > docs/reports/evidence/cvw-session-20261018/pytest-gate.log 2>&1
echo "pytest_exit=$?" >> docs/reports/evidence/cvw-session-20261018/pytest-gate.log
rm -rf docs/reports/evidence/cvw-session-20261018/client-binary-refusal
python3 scripts/auto_harness_test.py \
  --cpu configs/cpus/cvw/component_profile.json \
  --ip configs/peripherals/pulp_gpio/component_profile.json \
  --compose configs/scenarios/cvw-pulp-gpio/compose.json \
  --output docs/reports/evidence/cvw-session-20261018/client-binary-refusal \
  --runtime cvw-ahb-pulp-gpio \
  --cache-dir .superpowers/cache/cvw-session-gate \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --budget-seconds 60 --label cvw-client-binary-refusal \
  > docs/reports/evidence/cvw-session-20261018/client-binary-refusal.stdout.log \
  2> docs/reports/evidence/cvw-session-20261018/client-binary-refusal.stderr.log
echo "client_binary_refusal_exit=$?" >> docs/reports/evidence/cvw-session-20261018/client-binary-refusal.stdout.log
'
