# Native completion attempt1 independent preparation audit

Independent read-only audit passed on2026-10-18 at08:28:00–08:28:11UTC
through `ssh jumpserver` then `ssh root@192.168.5.70`. The remote audit used
only Python standard-library reads, AST parsing and hashing. It imported no
project modules and invoked no Git, tool query, frontend, tests, compiler,
model or gate. All remote paths stayed under `/root/fanzehui`.

New operation:
`/root/fanzehui/myfuzz/operations/p6-native-completion-20261018-attempt1`.
Source revision recorded in its frozen selection:
`acc47fe9a2b169e56e873821e27968a47e80ed08`.

The audit independently rehashed every final project file and read every
directory mode:8891 files,601 directories. Both complete maps exactly equal
the frozen baseline plus reviewed17-file overlay, and the saved final maps.
There are no unmanifested outputs or caches. Existing387 frontend files,
including baseline build artifacts, and7255 Git metadata files remain equal
to baseline. The complete1111 current src/scripts file rows match the frozen
local file map, with zero old extra src/scripts files. All69 explicit HARNESS
host paths are present with correct hashes/modes, and HOST v1 count remains34.
The full scripts record also matches exactly.

The old source tree was rehashed independently after preparation. It exactly
matches the original baseline and both source-before/source-after file and
directory records. Baseline file-map file SHA remains
`50145c2408804a76c6ff651cefbb143aae17cd1be18559f79ea6386b510e2cc4`;
baseline directory-map file SHA remains
`b16e9bd3b7cabcd0e75ebf051af9a2045ce6dfe600fd7f0cc8035f21389c7393`.

The actual copy parent PID2877701 and child PID2877799 agree in start and
terminal records. Child return code is0, copy stdout equals the operation copy
receipt, and stdout/stderr hashes match the terminal record. The archived
local upload terminal reports rc0. The independent audit and subsequent
read-only control download also returned0. These are preparation/control
results only; no native hardware execution or gate pass is established.

## Pins for a separately reviewed gate parent

| Control file | File SHA256 |
| --- | --- |
| `control/final-file-freeze.json` | `94de100ab2ab50f3674f179378c9138d73cec873c68ae401bc43f9cb63e76cd1` |
| `control/final-directories.json` | `861e192518e1d809231b676b91b17c149466000f83138969eac6cbfaff68fb36` |
| `control/copy-receipt.json` | `3efbfeb6c6e84169e9230d360478ca6a7d9613c39f76a38652013cc8b6293003` |
| `control/explicit-host-files.json` | `f8965b59f20195cf3f7fd1f55bb8df8d958757cbedc20795b2184a5a2fdbfeb9` |
| `control/full-scripts.json` | `c53ce4d5f890369aa132ff0902bc27b548573b838db41a45de0f69ced4bd05eb` |

The final directory map's canonical JSON content SHA256 is separately
`b1c26f2541eb0a46a616a657c1ec02b1c46da5073260a4b8a24585991a63a009`.
It must not be confused with that JSON file's raw byte SHA above.

## Captured evidence

`docs/reports/evidence/native-completion-preparation-20261018/` retains the
exact audit source, its JSON report, remote stderr, audit parent terminal,
local upload terminal, control archive receipt and archive member hashes.
`remote-controls.tar.gz` contains24 regular control/input evidence files and
no project tree; each operation control member was checked against the audit
report pins, and its frozen1111 local file map was byte-compared with the
original local input. Archive SHA256:
`5943f70a3627d9708af0f08736d7a6282dca3c031af4cea3154f4abe09787c76`.
Download completed08:28:40UTC. Original root-control inputs were not modified.

This review accepts preparation integrity only. It does not establish native
completion behavior, fresh replay, feedback, source consumption or P6 completion.
