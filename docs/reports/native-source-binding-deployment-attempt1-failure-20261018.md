# Native host-binding deployment attempt1: actual failure

Root executed the reviewed deployment wrapper SHA256
`62dcafe36ce9930cc3d580062f38151dcfc656893b66df0b224d499809764bf2`.
The local terminal receipt records actual SSH child55701 returncode1,
local inputs unchanged, and empty stdout. stderr records ValueError: tar-parent
and the jump SSH child's actual terminal receipt. These are failure evidence,
not a successful source copy or native gate.

## Root cause and boundary

The pinned outer archive272a3b0c omitted directory member `overlay`, although
it contained overlay/scripts and overlay/src descendants. Independent local
stdlib tar-member/parent census confirmed `overlay` is the sole missing parent.
The collector did not extract the archive or execute its contents. The strict
parser correctly rejected this shape; its parent-membership check must remain.

In the executed wrapper, archive parsing precedes STAGE.mkdir and all file
publication and prepare_copy Popen. This observed tar-parent refusal therefore
did not reach source copying or create a DUT/model child. No source tree was
produced by this path. This report does not claim an independently observed
remote path absence: no remote read was performed for it. Root may collect
later path-absence evidence separately, labelled with its observation time.

## Retained evidence and remedy

Small immutable evidence is under
`evidence/native-source-binding-deployment-attempt1-20261018/`: original local
start/terminal/stdout/stderr, executed wrapper and original input-pins, plus
SHA/length references to the unchanged archive and controllers and independent
missing-parent census. The wrapper's exact executed SHA is recorded separately
from the original input-pins inventory, which predates the final wrapper fixes.
All original attempt1-control artifacts remain untouched.

The new attempt2-control archive adds explicit outer overlay/0755; its relative
overlay map intentionally does not add a root entry. It uses a fresh attempt2
inputs path while the project operation remains attempt1. Independent review
and root authorization apply separately. No retry, collector, auditor, Git,
project import, tests, model or remote operation was run in preparing this
report. The old69-path native pass does not certify new70-path integration;
C2 source-consumption authority remains ungranted.
