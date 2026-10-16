# Independent OBI same-TB Verilator source review — 2026-10-17

Read-only review of root's uncommitted test increment. No pytest, simulator,
compiler, elaboration or remote operation was run. Only source/AST inspection
and byte hashing were performed. Reviewed file hashes:

- test_obi_processor_memory_adapter_rtl.py:
  `3c8aa3aa243edcb8e28754635ca76342c2c75c52232bc3430c29ced54b48f1ff`
- test_obi_fail_stop_verilator_control.py:
  `74f0d06911c91f4b83a9372782f51dcf15ff298aa6fbb993e6d9521962cdf1f3`

## Verdict

No high/medium source finding in this increment. The new test is an explicit
same-stimulus tool variant and does not replace or weaken the original Icarus
case. Native Verilator outcome remains unknown until its separately authorized
run; software controls are not remote acceptance evidence.

## Checks

Independent AST extraction of the old committed method's dedented literal and
the new shared NO_ERROR_TESTBENCH confirms byte-for-byte identity:711 UTF-8 bytes,
SHA256 `83b46a7a6fb8dacc15dfe19a8b04926215877ce867003944670648d11153dc39`.
Both tool paths write this same constant; original scheduling, response error
injection, parameters HAS_ERROR=0 and fallback fatal are preserved. No RTL edit
is included in the reviewed diff.

Verilator invocation explicitly uses --binary --timing --assert, tb as top,
private Mdir and -j1. Build must return0 before executable invocation. Runtime
must return nonzero AND include the exact adapter diagnostic substring
`OBI backend error cannot be represented`. The TB fallback message is different
and cannot independently pass. Signal termination's negative return code is
correctly retained rather than assuming a particular shell134 status.

Returned compile and runtime processes print separate actual command/output/
exit JSON; adapter and TB hashes are included in build JSON. Compile failure
cannot pass, zero native exit cannot pass, and unrelated fallback fatal cannot
pass. Missing Verilator is an explicit skip and invokes no process. Timeouts
raise rather than producing a successful result; future orchestration should
retain timeout traceback and actual worker/children terminal status rather
than infer completion from absence of a result JSON.

The control module imports the target module via alias, not its unittest class,
so it does not accidentally expose imported original Icarus test methods to
pytest collection. It patches tool lookup/subprocess and reads the actual temp
TB bytes to compare both tools and fixed digest. No constructed process result
is labeled a native observation.

## Evidence boundary and run preparation

Root reports6 software controls passed0.03s. Earlier RED imported the unittest
class and accidentally collected three real Icarus tests which passed; that is
not isolated software RED and not a remote gate. Root retained it and a later
isolated4failed RED after alias correction. This review did not rerun either
trace and does not promote the accidental local Icarus results into remote
Verilator acceptance. The new variant has not run natively at review time.

When running remotely, select the exact Verilator test method and retain its
build/result JSON plus outer pytest exit and source hashes. Existing Python
TemporaryDirectory calls use the environment's TMPDIR; the remote launcher must
set TMPDIR beneath /root/fanzehui to honor agent.md. Canonical heavy-window
ownership and actual terminal checks belong to that launcher. This source
review itself neither acquired a lock nor authorized native execution.
