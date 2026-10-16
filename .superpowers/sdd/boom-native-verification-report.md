# BOOM persistent native / standard GPIO verification

Actual verification passed. This covers the new persistent binary and the
standard ScenarioRunner BOOM→actual PULP GPIO→CPU readback/native RAM path,
with two fresh complete prefixes and environment response controls. It does
not establish full P6 or generic runtime admission.

## Native evidence

Committed evidence directory:
`configs/cpus/boom/evidence/persistent-runtime-20261017/`.
Archive `evidence.tar.gz`: 3,046,302 bytes, SHA-256
`be65978ca43a7f4ee5bae761a936094976207d3c695c9ffd9c37e52bc8faf586`.
Internal manifest binds 41 files. All were checked locally against their
hashes after download. Full raw CPU/GPIO/runner streams, native UUIDs and OS
PIDs/exits remain intact; readable gate/artifact/summary copies are alongside it.

Native build exit 0, standard GPIO gate exit 0 and preserved one-shot gate
exit 0 are actual persisted files. The launch script's final exit is its recorded
one-shot status; no independent verify.exit was captured or fabricated.
Launcher155524/build child155525 and later gate processes were confirmed
terminal; canonical lock had no holder before the next agent's heavy window.
Fresh persistent compilation used 23 C++ units, no prior object cache, and
Verilator reported 68.813 seconds.

Two fresh runs: 1,200 CPU edges, 1,208 GPIO edges, 20,597 full events each.
Actual GPIO PADOUT/output/readback=53. CPU stores readback53 and branch marker1
at native uncached 0x3000/0x3004. Actual accepted A→router source key→physical
APB/transport access ID→accepted D→CPU result-store bindings are checked.
Both CPU/GPIO native processes exit0. Both complete event prefixes match after
normalizing only top-level declared process/stream scope, source_transaction
execution scope and native reset acknowledgement scope. Arbitrary payload
fields are unchanged even if their contents equal a nonce. Normalized SHA-256:
`62891182387db436fbc07210c7a6e9a4615d60725d0015861cf6f9afb2da1141`.

Changed-response control: actual GPIO returns53, the environment offers52,
and the real CPU stores52 plus failure marker0xffffffff. Missing-response
control: actual GPIO returns53, the environment withholds D, native result RAM
stays zero and one coherent source remains pending. Both reject the positive
gate with no unrelated transport or coherent-checker error. These deliberately
substituted environment responses are not reported DUT bugs.

The GPIO program records A6/D20 and no C/E. The old one-shot gate passes its
two matching fresh traces and read-corruption control using its authenticated
prior executable, after the current generator reproduces source/driver/manager
identity and prior binary SHA. This is explicitly prior-build provenance.
A separate cached-RAM probe of the NEW persistent C/E path remains pending.

## Source and focused regressions

Independent remote snapshot under `/root/fanzehui/boom-verification-20261017`:
rsync without hardlinks, then atomic replacement of staged src/configs/tests.
Initial transfer mentioned nonexistent optional pyproject.toml; complete staged
replacement and 2,366-file SHA verification superseded it. Both pre/post-gate
checks have zero mismatches; native artifact RTL/manager/driver/executable
closure hashes also match. Exact tested hashes for owned gate/session/helper/
test files were compared with the local files before commit.

Focused command:
`PYTHONPATH=src PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest -q tests/local_harness/test_boom_session_regressions.py`

Latest local result:16 passed in10.74s. Remote earlier 15-test version passed
in1.07s. A source=8 negative case first failed, then both adapter/helper widths
were corrected from16 to the actual physical3 bits. A payload nonce case first
failed broad field-name normalization, then structural-path normalization fixed
it. Other regressions cover manifest omissions/rehashed modified RTL/manager,
duplicate/stale callbacks and malformed size/mask/alignment/opcode/param/epoch
before enqueue/target effect. Actual sys.setprofile discovery counts are2
unscoped versus1 scoped with identical complete bytes; the real four-run native
gate records one AST discovery over158.363s. Source rereads/probes remain active.

A verified waiting-only launcher139670/child139671 was stopped before any
native outputs during shared-queue coordination; its143 is not a compilation
failure. Actual authorized native job155524 was recorded before polling.
Durable state/log/PID files remain in local `.superpowers/boom-verification-20261017`
and the corresponding remote directory. No real hardware was targeted.

Remaining: separate persistent C/E cached-RAM coverage, warm RAM retention,
IRQs/probes, source authority/retirement evidence and full P6 acceptance.
