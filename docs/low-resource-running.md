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
values must remain positive and ordered.

The smoke invokes the existing protocol catalog, harness compiler, dependency
graph, candidate-pipeline join, memory gate, and report publisher. Its matrix
runner is deterministic and in-process, so it does not launch Verilator, RFuzz,
or a long fuzz campaign. A successful smoke proves the integration contracts
are wired together; it is not evidence of RTL functional correctness or
production-scale performance.

Normal experiment callers and checked-in configurations are unchanged. Real
experiments continue to use their existing shared memory-gate policy.
