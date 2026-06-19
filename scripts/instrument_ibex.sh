#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/.." && pwd)"

rfuzz_root="${RFUZZ_ROOT:-${project_dir}/third_party/rfuzz/upstream}"
ibex_root="${IBEX_ROOT:-${rfuzz_root}/ibex}"
flist="${FLIST:-${ibex_root}/sources.f}"
out_dir="${OUT_DIR:-${project_dir}/runs/designs/ibex_direct/instrumented}"
top_module="${TOP_MODULE:-ibex_core}"
coverage_port="${COVERAGE_PORT:-__vi_coverage}"

force_args=()
if [[ "${FORCE:-1}" != "0" ]]; then
  force_args+=(--force)
fi

python3 "${project_dir}/scripts/source_branch_instrumenter.py" \
  --project-root "${ibex_root}" \
  --out-dir "${out_dir}" \
  --flist "${flist}" \
  --top-module "${top_module}" \
  --coverage-port "${coverage_port}" \
  "${force_args[@]}" \
  "$@"
