# Native raw observation planner admission correction

The actual first frozen directed launch reached gate PID3130216 and exited1.
It failed at `plan_local_harness` with
`native-physical-observation-protocol-unsupported`: the raw V2 request branch
admitted only OBI/APB even though the renderer, driver, contract verifier and
session already implemented the selected native-memory observation path.
The positive directory is empty; no model execution/build result is granted.
Profile elaboration precedes this refusal, so frontend work is not ruled out.
Parent3107064 exited1; its four Git checks passed and before/after source,
directory and tool checks completed without drift. Failure evidence is retained.

The source correction allows `ready-valid-memory/1` only in the explicitly
requested raw observation branch. It requires exactly one protocol endpoint,
a memory-master function and the existing strict `native_completion_contract`
capability/template admission. The native renderer still checks the exact ABI,
passive role wiring, instruction marker and observation metadata. No-raw V2
register templates remain unchanged and continue refusing this protocol.

Independent source tracing confirmed this missing admission and found the
corresponding downstream native branches already present. Static AST and
whitespace checks passed. No new tests, project import, frontend, build or
model were run for the correction. It requires a new frozen operation; the
failed first operation is not modified, and no successful gate is claimed.
P6/P7/P8 remain OPEN.
