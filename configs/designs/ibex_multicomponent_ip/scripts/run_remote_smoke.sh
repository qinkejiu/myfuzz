#!/usr/bin/env bash
set -euo pipefail

cd /root/fanzehui/myfuzz

python3 configs/designs/ibex_multicomponent_ip/scripts/prepare_remote_sources.py

for cfg in \
  configs/designs/ibex_multicomponent_ip/baseline_direct_slice/config.json \
  configs/designs/ibex_multicomponent_ip/depaware_projection/config.json
do
  python3 src/myfuzz/scripts/run_design_flow.py --config "$cfg" --stage frontend --force
  python3 src/myfuzz/scripts/run_design_flow.py --config "$cfg" --stage instrument
  python3 configs/designs/ibex_multicomponent_ip/scripts/prepare_remote_sources.py --write-width-config "$cfg"
  width_cfg="$(dirname "$cfg")/config.coverage_width.json"
  python3 src/myfuzz/scripts/run_design_flow.py --config "$width_cfg" --stage toml
  python3 src/myfuzz/scripts/run_design_flow.py --config "$width_cfg" --stage harness
done

echo "Remote smoke completed through frontend/instrument/toml/harness."
echo "Build server/fuzz next only after checking the generated coverage denominator is identical."
