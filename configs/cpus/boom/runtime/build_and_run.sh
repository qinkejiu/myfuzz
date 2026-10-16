#!/usr/bin/env bash
set -euo pipefail
TASK_ROOT=/root/fanzehui/system-20261016
GEN_ROOT=$TASK_ROOT/chipyard-release-deps/sims/verilator/generated-src/chipyard.TestHarness.SmallBoomConfig
RUNTIME_ROOT=$TASK_ROOT/evidence/boom-tile-ram
cd "$RUNTIME_ROOT"
flock "$TASK_ROOT/project/.superpowers/heavy-worker.lock" bash -c '
set -euo pipefail
verilator --cc --exe --build --top-module BoomTile --Mdir obj -Wno-fatal --output-split 20000 --output-split-cfuncs 20000 -j 2 -CFLAGS "-std=c++17 -O1" "$1/chipyard.TestHarness.SmallBoomConfig.top.v" "$1/chipyard.TestHarness.SmallBoomConfig.top.mems.v" "$1/plusarg_reader.v" "$1/EICG_wrapper.v" "$PWD/boom_tile_ram.cpp" > build.log 2>&1
./obj/VBoomTile > runtime.jsonl 2> runtime.stderr
' _ "$GEN_ROOT"
