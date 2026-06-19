#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/.." && pwd)"

rfuzz_root="${RFUZZ_ROOT:-${project_dir}/third_party/rfuzz/upstream}"
cva6_root="${CVA6_ROOT:-${rfuzz_root}/cva6}"
flist="${FLIST:-${cva6_root}/sources.f}"
out_dir="${OUT_DIR:-${project_dir}/runs/designs/cva6_direct/instrumented}"
top_module="${TOP_MODULE:-cva6}"
coverage_port="${COVERAGE_PORT:-__vi_coverage}"

force_args=()
if [[ "${FORCE:-1}" != "0" ]]; then
  force_args+=(--force)
fi

python3 "${project_dir}/scripts/source_branch_instrumenter.py" \
  --project-root "${cva6_root}" \
  --out-dir "${out_dir}" \
  --flist "${flist}" \
  --top-module "${top_module}" \
  --coverage-port "${coverage_port}" \
  "${force_args[@]}" \
  "$@"
