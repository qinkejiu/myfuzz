#!/usr/bin/env bash
set -euo pipefail
ROOT=/home/qinkejiu/myfuzz
BASE=$ROOT/runs/p6-controlled-error-non-ibex-non-gpio-20261017
RUN=$BASE/attempt-12-head-snapshot
SNAP=$RUN/source
rm -rf "$RUN"
mkdir -p "$SNAP"
git -C "$ROOT" archive HEAD src configs tests scripts schemas | tar -x -C "$SNAP"
mkdir -p "$SNAP/external_designs"
git clone --quiet "$ROOT/external_designs/cv32e40p" "$SNAP/external_designs/cv32e40p"
git -C "$SNAP/external_designs/cv32e40p" checkout --quiet --detach 6033d2b1be3295ec774d17ac4cf226faacfdeb08
mkdir -p "$SNAP/third_party"
rsync -a --exclude '.git' "$ROOT/third_party/soc-opentitan/" "$SNAP/third_party/soc-opentitan/"
cp "$ROOT/tests/integration/non_ibex_non_gpio_controlled_error_process.py" "$SNAP/tests/integration/"
cp "$ROOT/tests/integration/test_non_ibex_non_gpio_controlled_error_real.py" "$SNAP/tests/integration/"
cd "$SNAP"
export MYFUZZ_SCENARIO_REAL=1
export MYFUZZ_CONTROLLED_ERROR_OUTPUT=$RUN/evidence
export PYTHONPATH=src
python3 -m pytest -q \
  tests/integration/test_cv32e40p_opentitan_uart_controlled_error_real.py \
  tests/integration/test_non_ibex_non_gpio_controlled_error_real.py
