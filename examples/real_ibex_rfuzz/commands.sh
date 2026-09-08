#!/usr/bin/env bash
set -euo pipefail

EXAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$EXAMPLE_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="src:."
export JOBS=1

INPUT="examples/real_ibex_rfuzz/input/ibex-scratch.json"
CLIENT="runs/task14_client_cancel_build/debug/kfuzz"

case "${1:-help}" in
  check)
    verilator --version
    test -f third_party/rfuzz/upstream/ibex/rtl/ibex_core.sv
    test -x "$CLIENT"
    ;;
  compose)
    nice -n15 python3 examples/real_ibex_rfuzz/run_example.py compose \
      --input "$INPUT" --output "${2:-runs/examples/real-ibex-compose}"
    ;;
  test)
    nice -n15 python3 examples/real_ibex_rfuzz/run_example.py test \
      --input "$INPUT" --client "$CLIENT" \
      --output "${2:-runs/examples/real-ibex-rfuzz-5s}" --seconds "${3:-5}"
    ;;
  inspect)
    python3 examples/real_ibex_rfuzz/run_example.py inspect \
      --output "${2:-runs/examples/real-ibex-rfuzz-5s}"
    ;;
  focused-tests)
    nice -n15 python3 -m unittest -v tests.examples.test_real_ibex_rfuzz_example
    ;;
  full-tests)
    nice -n15 python3 -m unittest discover -s tests -p 'test_*.py'
    ;;
  formal-3x300)
    nice -n15 python3 scripts/run_real_cpu_campaigns.py \
      --config configs/campaigns/ibex-real-rfuzz.json \
      --client "$CLIENT" --output "${2:-runs/task15-real-cpu-3x300}" \
      --seconds 300 --seed 20260908
    ;;
  help|*)
    echo "usage: $0 {check|compose|test|inspect|focused-tests|full-tests|formal-3x300} [output] [seconds]"
    ;;
esac
