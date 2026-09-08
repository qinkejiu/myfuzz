#!/usr/bin/env bash
set -u
mode=$1
shift
root=$(cd "$(dirname "$0")" && pwd)
metrics="$root/${mode}-process-group-rss.txt"
: > "$metrics"
setsid "$@" &
pid=$!
peak=0
while kill -0 "$pid" 2>/dev/null; do
  total=$(ps -o rss= --sid "$pid" 2>/dev/null | awk '{s+=$1} END {print s+0}')
  if (( total > peak )); then peak=$total; fi
  sleep 0.1
done
wait "$pid"
status=$?
printf 'peak_process_group_rss_kib=%s\nexit_status=%s\n' "$peak" "$status" > "$metrics"
exit "$status"
