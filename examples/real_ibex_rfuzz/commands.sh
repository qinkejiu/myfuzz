#!/usr/bin/env bash
set -euo pipefail

EXAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$EXAMPLE_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="src:."
export JOBS=1

INPUT="examples/real_ibex_rfuzz/input/ibex-scratch.json"
CLIENT="runs/rfuzz_client_native_build/target/debug/kfuzz"

case "${1:-help}" in
  check)
    verilator --version
    test -f third_party/rfuzz/upstream/ibex/rtl/ibex_core.sv
    test -x "$CLIENT"
    ;;
  compose)
    nice -n15 python3 examples/real_ibex_rfuzz/run_example.py compose \
      --input "$INPUT" --output "${2:-runs/examples/contract-rfuzz-compose}"
    ;;
  test)
    nice -n15 python3 examples/real_ibex_rfuzz/run_example.py test \
      --input "$INPUT" --client "$CLIENT" \
      --output "${2:-runs/examples/contract-rfuzz-5s}" --seconds "${3:-5}"
    ;;
  inspect)
    python3 examples/real_ibex_rfuzz/run_example.py inspect \
      --output "${2:-runs/examples/contract-rfuzz-5s}"
    ;;
  replay)
    nice -n15 python3 examples/real_ibex_rfuzz/run_example.py replay \
      --input "$INPUT" --output "${2:-runs/examples/contract-rfuzz-5s}" \
      --build-output "${3:-runs/examples/contract-rfuzz-replay}"
    ;;
  focused-tests)
    nice -n15 python3 -m pytest tests/examples/test_real_ibex_rfuzz_example.py -q
    ;;
  full-tests)
    nice -n15 python3 -m pytest tests -q
    ;;
  help)
    echo "usage: $0 {check|compose|test|inspect|focused-tests|full-tests} [output] [seconds]"
    echo "       $0 replay [existing-test-output] [new-build-output]"
    ;;
  *)
    echo "unknown command: $1" >&2
    exit 2
    ;;
esac
