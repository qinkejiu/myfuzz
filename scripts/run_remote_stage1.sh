#!/bin/sh
# Push the stage-1 tree to the test server under /root/fanzehui, run the
# representative F1-F4 combos there with an independent TMPDIR/cache per combo,
# then mirror the small JSON evidence (summary/replay/case_sequence/failure)
# back into the local repository.
#
# Access rule (agent.md): the server is only reachable through the jump host and
# only /root/fanzehui may be written.
#
# Usage:
#   scripts/run_remote_stage1.sh [combo ...]
#   COMBOS="vexii-f1f4 vexii-f2f4" scripts/run_remote_stage1.sh
#
# Environment:
#   SNAPSHOT       remote snapshot dir (default /root/fanzehui/myfuzz-stage1-20261031)
#   LOCAL_MIRROR   local evidence dir  (default runs/remote-stage1-20261031)
#   VERILATOR_BIN  remote Verilator bin dir
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

SNAPSHOT=${SNAPSHOT:-/root/fanzehui/myfuzz-stage1-20261031}
LOCAL_MIRROR=${LOCAL_MIRROR:-runs/remote-stage1-20261031}
VERILATOR_BIN=${VERILATOR_BIN:-/root/fanzehui/myfuzz-20260927-legacy/.tools/verilator-5.051-e413e67/bin}
REMOTE_HOST=root@192.168.5.70
SSH="ssh -o BatchMode=yes -o ServerAliveInterval=15 -J jumpserver $REMOTE_HOST"
RSYNC_SSH="ssh -o BatchMode=yes -J jumpserver"

if [ $# -gt 0 ]; then
    COMBOS=$*
else
    COMBOS=${COMBOS:-"vexii-f1f4 vexii-f2f4 ibex-obi-apb-i2c"}
fi

# kind|path : "descriptor" combos already carry generic_scenario.json and
# acceptance_sequence.json; "generate" combos are generator configs that must be
# expanded on the server first.
combo_kind() {
    case "$1" in
    vexii-f1f4|vexii-f2f4|picorv32-axil-axi4lite-uart|cvw-ahb-ahb-sha|ibex-obi-tlul-gpio)
        echo descriptor ;;
    ibex-obi-apb-i2c|picorv32-wb-apb-i2c|picorv32-wb-apb-spi|cvw-ahb-apb-spi|picorv32-axil-apb-spi)
        echo generate ;;
    *) return 1 ;;
    esac
}

combo_path() {
    case "$1" in
    vexii-f1f4) echo "configs/scenarios/compiled-f1-f4-axi4-apb-i2c-vexii" ;;
    vexii-f2f4) echo "configs/scenarios/compiled-f2-f4-axi4-apb-i2c-vexii" ;;
    picorv32-axil-axi4lite-uart) echo "configs/scenarios/compiled-f2-f4-axil-axiluart-picorv32" ;;
    cvw-ahb-ahb-sha) echo "configs/scenarios/compiled-f2-ahb-sha256-mmio" ;;
    ibex-obi-tlul-gpio) echo "configs/scenarios/compiled-f2-f4-obi-tlul-gpio" ;;
    ibex-obi-apb-i2c) echo "configs/scenarios/mmio-profile-examples/i2c-ibex-obi-profile.json" ;;
    picorv32-wb-apb-i2c) echo "configs/scenarios/mmio-profile-examples/i2c-picorv32-wb-profile.json" ;;
    picorv32-wb-apb-spi) echo "configs/scenarios/mmio-profile-examples/spi-picorv32-wb-memory.json" ;;
    cvw-ahb-apb-spi) echo "configs/scenarios/mmio-profile-examples/spi-cvw-ahb-memory.json" ;;
    picorv32-axil-apb-spi) echo "configs/scenarios/mmio-profile-examples/spi-picorv32-axi-memory.json" ;;
    *) return 1 ;;
    esac
}

sync_tree() {
    echo "== rsync tree -> $SNAPSHOT"
    $SSH "mkdir -p $SNAPSHOT"
    rsync -a --exclude='__pycache__/' --exclude='*.pyc' -e "$RSYNC_SSH" \
        src scripts configs schemas examples "$REMOTE_HOST:$SNAPSHOT/"
}

run_remote() {
    combo=$1
    kind=$(combo_kind "$combo") || { echo "!! unknown combo $combo"; return 1; }
    path=$(combo_path "$combo")
    echo "== remote run $combo ($kind)"
    # One ordinary command line per step (no stdin script, no executed script
    # file): on this host the Verilator frontend reports "crashed" inside
    # preparation whenever the same steps arrive through a stdin heredoc or an
    # executed script file, while the identical plain command line succeeds.
    env_prefix="cd $SNAPSHOT && PATH=$VERILATOR_BIN:\$PATH && export PATH && PYTHONPATH=src && export PYTHONPATH && TMPDIR=/root/fanzehui/tmp-stage1/$combo && export TMPDIR && mkdir -p \$TMPDIR runs"
    if [ "$kind" = generate ]; then
        prep="python3 scripts/generate_mmio_scenario.py --config $path --output runs/$combo-scenario"
        descriptor="runs/$combo-scenario/generic_scenario.json"
        records="runs/$combo-scenario/acceptance_sequence.json"
    else
        prep="true"
        descriptor="$path/generic_scenario.json"
        records="$path/acceptance_sequence.json"
    fi
    # Clear the case once, then run both modes into the same case root.
    $SSH "$env_prefix && rm -rf runs/$combo runs/$combo-scenario && $prep"
    for mode in original fresh; do
        $SSH "$env_prefix && python3 scripts/run_generic_scenario.py --descriptor $descriptor --flow mixed --mode $mode --case runs/$combo --cache runs/$combo/cache --execution-mode search --rounds 256 --records-file $records"
    done
    $SSH "cd $SNAPSHOT && rm -rf runs/$combo/cache runs/$combo/work"
}

mirror_back() {
    combo=$1
    dest="$LOCAL_MIRROR/$combo"
    mkdir -p "$dest"
    for mode in original fresh; do
        mkdir -p "$dest/$mode"
        rsync -a -e "$RSYNC_SSH" \
            --include='*/' --include='summary.json' --include='replay.json' \
            --include='case_sequence.requested.json' --include='failure.json' --exclude='*' \
            "$REMOTE_HOST:$SNAPSHOT/runs/$combo/$mode/" "$dest/$mode/" || true
    done
    echo "== mirrored $combo -> $dest"
}

sync_tree
for combo in $COMBOS; do
    run_remote "$combo"
    mirror_back "$combo" || echo "!! mirror of $combo failed" >&2
done
echo "== done"
