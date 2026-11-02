#!/bin/sh
# Remote-side half of scripts/run_remote_stage1.sh.
#
# Runs on the test server under /root/fanzehui only.  It is copied there by the
# local driver and executed as a file (not through a stdin heredoc) so the
# Verilator frontend inherits the same stdin/stdout it gets from an interactive
# command.
#
# Required environment: SNAPSHOT, VERILATOR_BIN, COMBO, KIND, PATH_IN.
set -eu

cd "$SNAPSHOT"
PATH="$VERILATOR_BIN:$PATH"
export PATH
PYTHONPATH=src
export PYTHONPATH
TMPDIR="/root/fanzehui/tmp-stage1/$COMBO"
export TMPDIR
mkdir -p "$TMPDIR" runs

rm -rf "runs/$COMBO" "runs/$COMBO-scenario"
if [ "$KIND" = generate ]; then
    python3 scripts/generate_mmio_scenario.py --config "$PATH_IN" --output "runs/$COMBO-scenario"
    DESCRIPTOR="runs/$COMBO-scenario/generic_scenario.json"
    EXTRA="--records-file runs/$COMBO-scenario/acceptance_sequence.json"
else
    DESCRIPTOR="$PATH_IN/generic_scenario.json"
    EXTRA="--records-file $PATH_IN/acceptance_sequence.json"
fi

run_one() {
    mode=$1
    python3 scripts/run_generic_scenario.py \
        --descriptor "$DESCRIPTOR" --flow mixed --mode "$mode" \
        --case "runs/$COMBO" --cache "runs/$COMBO/cache" \
        --execution-mode search --rounds 256 $EXTRA
}

# Warm the page cache over the RTL tree first.  `run_verilator_elaboration`
# supervises the frontend with a 30 s limit (source_elaboration.py
# _ELABORATION_TIMEOUT_SECONDS); on this host a cold read of the whole tree
# after an rsync exceeds it and the frontend is reported as "crashed", while the
# same elaboration finishes in a couple of seconds once the files are cached.
warm_sources() {
    find third_party configs -type f \
        \( -name '*.sv' -o -name '*.svh' -o -name '*.v' -o -name '*.vh' \
           -o -name '*.svp' -o -name '*.vhd' \) -print0 2>/dev/null \
        | xargs -0 -r cat > /dev/null 2>&1 || true
}

run_with_warmup() {
    mode=$1
    if ! run_one "$mode"; then
        echo "!! $COMBO/$mode failed; warming the source cache and retrying once" >&2
        warm_sources
        rm -rf "runs/$COMBO/cache"
        run_one "$mode"
    fi
}

warm_sources
run_with_warmup original
run_with_warmup fresh
rm -rf "runs/$COMBO/cache" "runs/$COMBO/work"
