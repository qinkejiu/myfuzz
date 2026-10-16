#!/bin/bash
set -u
TASK=/root/fanzehui/system-20261016/dma-continuous-verification-20261017/attempt6
PROJECT=/root/fanzehui/system-20261016/dma-continuous-verification-20261017/attempt6-project
trap 'job_exit=$?; printf "%s\n" "$job_exit" > "$TASK/worker.exit"' EXIT
printf '%s\n' "$$" > "$TASK/worker.pid"
printf '%s\n' waiting > "$TASK/state"
exec 9>/root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock
flock -n 9 || { printf '%s\n' lock-refused > "$TASK/state"; exit 2; }
printf '%s\n' running > "$TASK/state"
source /root/fanzehui/system-20261016/environment.sh
export PYTHONPATH="/root/fanzehui/system-20261016/pythonlib:$PROJECT/src:$PROJECT"
cd "$PROJECT"
python3 -m pytest -q tests/integration/test_dma_uart_rx_failure_document.py tests/integration/test_dma_uart_rx_replay_state_edges.py tests/integration/test_dma_uart_rx_cursor.py tests/integration/test_dma_uart_rx_discovery_scope.py tests/integration/test_dma_uart_rx_boot_contract.py tests/integration/test_dma_uart_rx_runtime.py::test_identity_normalization_is_scoped_to_actual_ledger_fields tests/local_harness/test_host_source_discovery_scope.py tests/local_harness/test_wishbone_dma_scenario_session.py tests/scenario/test_stateful_batch.py tests/scenario/test_irq_delivery.py > "$TASK/focused.log" 2>&1
FOCUSED_EXIT=$?
printf '%s\n' "$FOCUSED_EXIT" > "$TASK/focused.exit"
if test "$FOCUSED_EXIT" -ne 0; then printf '%s\n' failed-focused > "$TASK/state"; exit "$FOCUSED_EXIT"; fi
export MYFUZZ_DMA_CONTINUOUS_REAL=1
export MYFUZZ_DMA_CONTINUOUS_CACHE=/root/fanzehui/system-20261016/dma-continuous-verification-20261017/cache
export MYFUZZ_DMA_CONTINUOUS_EVIDENCE="$TASK/evidence"
timeout 900 python3 -m pytest -x -vv -s tests/integration/test_dma_uart_rx_runtime.py::test_continuous_native_uart_dma_prefix_and_failure > "$TASK/native.log" 2>&1
NATIVE_EXIT=$?
printf '%s\n' "$NATIVE_EXIT" > "$TASK/native.exit"
printf '%s\n' finished > "$TASK/state"
exit "$NATIVE_EXIT"
