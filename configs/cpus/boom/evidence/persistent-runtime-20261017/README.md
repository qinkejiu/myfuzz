# Persistent BOOM / actual PULP GPIO verification

Actual remote source snapshot: `/root/fanzehui/boom-verification-20261017/project`.
Build/gates used the shared canonical heavy-worker lock. No real hardware target
was used. Native build, standard GPIO gate and preserved one-shot gate each
recorded exit 0. The launch script's final exit is its recorded one-shot status;
there was no separate `verify.exit` file, and none has been fabricated.

Two fresh standard ScenarioRunner prefixes each contain 20,597 events after
1,200 CPU edges and 1,208 GPIO edges, including its two actual routed accesses.
The CPU writes GPIO PADOUT=53, actual GPIO output/readback equals 53, then the
CPU writes native RAM readback=53 and branch success=1 at 0x3000/0x3004. Both
native processes exit 0. Raw CPU and GPIO nonces, OS PIDs and exits are retained.
The complete event prefixes match after replacing only declared execution and
stream scope fields. Payloads and arbitrary nested identity-like data remain
unchanged. Both normalized prefixes hash to
`62891182387db436fbc07210c7a6e9a4615d60725d0015861cf6f9afb2da1141`.

The changed-response environment control preserves real GPIO readback 53 and
offers 52 to BOOM. The real CPU stores 52 and failure marker 0xffffffff. The
missing-response control preserves real GPIO readback 53, withholds D, and
leaves result RAM zero with one coherent source pending. Both fail the positive
functional gate without protocol/checker errors. These are injected environment
controls, not reported DUT defects.

This GPIO program observes A=6/D=20 and no C/E. The preserved one-shot benchmark
separately passes its two fresh matching traces and read-corruption control;
it uses its prior authenticated binary after the current generator reproduces
its source/driver/manager identities. Coverage of C/E in the new persistent
transport requires its separate cached-RAM supplement. No full P6, generic
runtime admission, ISA retirement or persistent-memory authority is granted.

`evidence.tar.gz` is 3,046,302 bytes, SHA-256
`be65978ca43a7f4ee5bae761a936094976207d3c695c9ffd9c37e52bc8faf586`.
Its internal manifest binds 41 files: full raw prefix/CPU/GPIO events for four
runs, native artifact/build log, source hashes, actual stage exits, launch
scripts, process identities and one-shot provenance/gates. All archive members
were verified locally against that manifest. Pre/post-run checks match all
2,366 snapshot file hashes; copied native RTL/manager/driver/executable closure
also matches its artifact. The native build took 68.813 seconds. Four-run gate
took 158.363 seconds and performed one actual host AST-discovery call under its
code-owned scope; per-use source bytes/probes remain validated.
