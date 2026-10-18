# ZipCPU offline metadata attempt1: independent failure capture

Actual parent PID3940481 returned1; outer SSH launch also returned1 at
08:56:31UTC. Parent start/terminal and selected-launch records agree on the
PID and controller SHA
`f8c4f32f58629864133db59eceadf1b66452931b8896c3657e00e637ff45a1fe`.
The captured controller bytes match that SHA. The operation was
`/root/fanzehui/myfuzz/operations/p8-source-zipcpu-metadata-20261018-attempt1`.

Initial source mapping refused
`/root/fanzehui/myfuzz/project/third_party/soc-zipcpu/sim/verilator/zipelf.h`
with `file-not-regular`; source-after collection failed with exactly the same
error. Only parent-start and parent-terminal files exist in operation control.
Neither complete before nor complete after file/directory maps was formed.
Therefore this failure provides **no proof that a whole-source freeze remained
unchanged**. The read-only source traversal in the captured controller is a
code property, distinct from an observed complete before/after equality.

The terminal records zero child commands. The captured control flow fails
before any Git subprocess invocation: zero Git children, zero models and no
repository network fallback ran. Hashing the selected Git executable for the
parent metadata is not a Git invocation. No snapshot/runtime admission or
prepared-source success was established. The recorded requested ZipCPU
revision42606d2d6ef55df313772232977621b2d72f0159 is not a newly verified
revision result from this failed attempt.

Authorized two-hop read-only collection ran08:59:35–08:59:38UTC. At
08:59:37UTC `/proc/3940481` was absent. Only `lstat` and `readlink` were used
on the known source entry itself; it was a symlink with text `../cpp/zipelf.h`,
mode0777 and15 link bytes. Its target was not opened, resolved or followed.
The collector used Python standard-library reads and streamed a control-only
tar archive; source/tmp trees were excluded. It invoked no Git, project import,
tool query, tests, frontend, model or retry. It did not modify the source
controller being revised separately.

Evidence directory:
`docs/reports/evidence/p8-zipcpu-metadata-attempt1-20261018/`.
It retains both actual parent receipts, selected launch, exact controller,
parent stdout/stderr, outer SSH terminal/stream records, read-only observation,
archive member hashes and the independent failure review JSON. Archive SHA:
`77b4b51c2b5f4bc261129559c70311febdff8a22354ff9304be66cf34ae813ce`.
No P8 source-closure, runtime or model pass is claimed.
