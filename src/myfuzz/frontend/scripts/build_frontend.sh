#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
frontend_dir="$(cd "${script_dir}/.." && pwd)"
build_dir="${MYFUZZ_FRONTEND_BUILD_DIR:-${frontend_dir}/build}"
jobs="${JOBS:-1}"

cmake -S "${frontend_dir}" -B "${build_dir}" -DCMAKE_BUILD_TYPE=Release
cmake --build "${build_dir}" --target myfuzz_frontend -j "${jobs}"

cat <<EOF
myfuzz frontend component build complete.
Source:  ${frontend_dir}
Build:   ${build_dir}
Library: ${build_dir}/libmyfuzz_frontend.so
EOF
