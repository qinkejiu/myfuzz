# Low-resource smoke run

Run from the repository root:

~~~bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_low_resource_smoke.py
~~~

The command is opt-in and uses temporary output. To retain the report:

~~~bash
python3 scripts/run_low_resource_smoke.py --report /tmp/myfuzz-low-resource/report.json
~~~

The conservative profile selects one candidate, the first sorted seed, and the
declared smoke budget. It forces one build slot, disables waveforms, bounds
the replay/event/field queues to 32/512/16, and caps the planner memory policy
at 512 MiB soft, 768 MiB hard, and 64 MiB per token. Already smaller input
limits remain unchanged. Optional --soft-memory-mib and --hard-memory-mib
values are positive integer MiB overrides: smaller values are preserved, while
values above the conservative ceilings are clamped to 512 MiB soft and 768 MiB
hard. The requested soft limit must be below the requested hard limit, and the
effective limits must remain ordered after clamping; malformed or invalid
values stop with an argparse usage error before the smoke starts. A lower soft
limit also reduces the token size when necessary so it never exceeds that
effective soft limit.

The smoke invokes the existing protocol catalog, harness compiler, dependency
graph, candidate-pipeline join, memory gate, and report publisher. Its matrix
runner is deterministic and in-process, so it does not launch Verilator, RFuzz,
or a long fuzz campaign. A successful smoke proves the integration contracts
are wired together; it is not evidence of RTL functional correctness or
production-scale performance.

Normal experiment callers and checked-in configurations are unchanged. Real
experiments continue to use their existing shared memory-gate policy.
