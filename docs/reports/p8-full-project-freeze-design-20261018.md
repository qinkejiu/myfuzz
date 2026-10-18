# P8 complete project freeze design

Source/document inspection only. No preparer implementation, project import, tests, Git subprocess, remote operation or execution occurred for this design. Component metadata materialization is an input to a later project freeze; it does not make the full P8 project ready. P6/P7/P8 remain OPEN.

## New P8 preparation boundary

Keep `scripts/prepare_p7_i5_snapshot.py` and its strict P7 policy unchanged. Its `file_entry` requires regular files/nlink1; selected directory links reject; the separate directory census preserves empty directories; `validate_git` rejects promisor/partialclone keys and `.promisor` packs, nonempty alternates/commondir and escaping metadata pointers. Its map schema cannot represent tracked link bytes. Do not send a symlink-containing P8 full tree through it and reinterpret the resulting failure as a successful freeze.

Prepare a separately named/versioned P8 planner/copier with explicit typed leaves and independent review. Separate plan from explicit prepare; pin the exact reviewed selection manifest and every input overlay/archive hash. No model/frontend/tool query or Git subprocess is part of the pure copier. Actual Git object/blob/index qualification is a separately authorized input/audit operation, with durable receipts; the pure copy phase must verify those pinned receipts and bytes rather than minting fresh Git authority.

New staging/project/control/output/cache paths must be under `/root/fanzehui`, separate from all old sources, component materialization operations and current native operation. Require new absent destinations, no symlink ancestors and independent regular-file copies. Never mutate a previous component materialization stage or its recorded metadata. Output/cache/TMPDIR and locks are outside the frozen project.

## Minimum complete selection

Take a new coherent current source snapshot; do not combine a historical root tree with whatever files happen to be latest during copying. Record exact commit plus dirty-file bytes/maps. Current full `src/`, `scripts/` and `configs/` are mandatory, including package files, every host identity dependency, `scripts/verify_soc_sources.py`, `scripts/measure_dma_uart_transport.py`, all profile/closure/lock/proof inputs and source-pinned driver/runtime/RTL files. Preserve needed project instructions/provenance/docs and root package/configuration files. Preserve independently copied root `.git`/`.gitmodules` and required evidence artifacts that source-lock tracking checks expect. Do not copy caches/build outputs/active evidence or broad hidden workspaces merely to avoid an explicit closure.

The three full component working trees and independently qualified metadata are:

| Component root | Official revision | Metadata prerequisite |
| --- | --- | --- |
| `third_party/rfuzz/upstream/ibex` | `34b0705760ef3dfa00e99637432473d2be8f22f3` | Still needs its own selected independent-store preparation/receipt for this P8 source freeze |
| `third_party/soc-opentitan` | `fca045df919a26c47e71616b9dac917b1ea4fd07` | New offline batch operation requires actual terminal and independent object/path audit |
| `third_party/soc-zipcpu` | `42606d2d6ef55df313772232977621b2d72f0159` | Actual attempt2 exit0 reported; independent closure/path receipts must be accepted and pinned |

The [existing-store inventory](p8-existing-remote-metadata-inventory-20261018.md) found all original available component stores promisor=true. Do not copy the original Ibex metadata unchanged or assume a P7 materialized store's mere existence is P8 qualification. A previously qualified exact Ibex store may be reused only with its actual object/source/metadata receipt and a new independent copy/map; otherwise materialize it separately. Retain both Ibex vendor trees. No store may borrow outside alternates, worktree/commondir state or lazy network acquisition. Declared shallow ancestry is legitimate only with an unchanged exact official commit and complete selected tree/blob closure proof.

The [scalar dependency report](p8-scalar-remote-dependency-20261018.md) supplies the exact recursive profiles and union-hash include boundaries. Include **whole recursive roots**, not only elaborated RTL or observed header filenames:

- Ibex: `vendor/lowrisc_ip/ip/prim/rtl`, `vendor/lowrisc_ip/ip/prim_generic/rtl`, `vendor/lowrisc_ip/dv/sv/dv_utils`, `vendor/pulp_common_cells/rtl`.
- OpenTitan: `hw/ip/prim/rtl`, `hw/ip/prim_generic/rtl`, `hw/ip/tlul/rtl`, `hw/top_earlgrey/rtl`, `hw/top_earlgrey/rtl/autogen`.
- ZipCPU: whole pinned component, including `rtl/peripherals/wbdmac.v` and `doc/src/gpl-3.0.tex`; retain OpenTitan LICENSE/UART HJSON/core and Ibex LICENSE too.

A complete `configs` lock contains other components. Preserve its exact bytes and required referenced evidence; do not invent a component-filter CLI for `verify_soc_sources.py`. Full-lock verification against a deliberately bounded three-component source set may report unrelated absent roots. Qualification of the scalar-selected transitive dependencies must explicitly identify that scope; it is not whole-lock success. If existing source/build logic actually demands another root, expand the selection deliberately before freezing rather than silently importing from an old external project.

## Typed tracked-link copying

The P8 leaf schema must distinguish regular files and symlinks. Regular rows carry kind, content bytes/SHA256, actual mode and independent-file constraint; link rows carry kind, lstat mode, raw `readlink` byte length, raw-link hex and its SHA256. Treat directory symlinks as typed leaves and remove them from os.walk traversal. Do not use exists/is_file/resolve through a link to decide what bytes to copy. No metadata `.git` entry/subtree accepts links; special files are rejected.

A source link is admissible only if the exact official Git tree path has mode120000 and its actual Git blob bytes equal the raw link bytes. Normal regular paths must match their real Git blob and executable mode semantics; gitlink160000 remains an explicit separate repository boundary, never a blob or a followed directory. No skipped link/path can be called a full snapshot.

Require a nonempty relative link target whose lexical normalization from the link's parent remains within its own component, with no NUL. Preserve the exact relative text; do not rewrite it to an absolute path or dereference/copy its target. Create regular directories/files before typed links, with no admissible child path under a symlink leaf; use os.symlink and never chmod/follow a created link. Any consumer that later resolves paths must additionally check the full link chain for escape/cycles and admitted target type; lexical containment of one link alone is not a general runtime path-safety proof. A dangling internal link must be retained as such in metadata but cannot satisfy a required compiled input.

Example retained failure and correction: ZipCPU `sim/verilator/zipelf.h` is an actual tracked link, mode0777, target `../cpp/zipelf.h` (raw hex `2e2e2f6370702f7a6970656c662e68`), lexically `sim/cpp/zipelf.h`. Original attempt1 rejected it before any Git child; that failure remains immutable. The later component copier's typed support is not a change to strict P7 preparation.

## Metadata and canonical full maps

Component working-tree bytes and final `.git` must originate from the same qualified revision and path map. Explicitly exclude the old component metadata before independently overlaying the new clean store; do not accidentally retain both old module objects and new metadata. Prefer in-component standalone `.git` directories with clean nonbare config/index. Do not edit old `.git` pointer files in place. If any pointer is deliberately retained, its normalized target, complete metadata and every ancestor must be inside the new project and selected manifest; reject absolute/escaping pointers and shared commondir/alternates. Root `.git/modules` remnants must be explicitly inventoried: either exclude obsolete unselected stores from the new root metadata under a reviewed transformation, or include/qualify them; stale promisor stores cannot silently survive a strict metadata scan. Preserve root HEAD/ref/gitlink identity and document every new-only config/pointer/index transformation. Root trackedness and component blob checks are separate.

Canonical plan/freeze has three disjoint sorted maps: directories (including every empty directory and parent mode), regular leaves, typed links. Reject duplicate/prefix collisions, path traversal/normalization ambiguity, regular hard links, symlink ancestors and undeclared overlays. Metadata directories must retain objects, refs, refs/heads and refs/tags even if empty; preserve other actual empty directories too. File-only archives are insufficient, as the historical Ibex empty-refs failure demonstrated.

Pin exact serialized manifest bytes and their SHA256, counts/bytes per leaf kind and directory count. Source-before/source-after typed maps must agree for each source selection and metadata-overlay input. Destination independently recensed maps must exactly equal the final **post-overlay** expected maps, including raw link bytes, modes and all empty directories; do not reuse a pre-overlay freeze. Any temporary path/state must be outside the selected tree. Publish only by final rename after validation and durable copy receipt. Failure retains its own source/plan/copy diagnostics and cannot set ready.

## Required later acceptance receipts

Before any scalar measurement, independently validate all three component official HEAD/shallow/objects/refs and complete required path blobs, stage nonbare status/index and root tracking, source-lock/profile/include/probe hashes, source-first paths and full before/after file/directory/link maps. No copied metadata can independently grant source authority merely because its config is nonpromisor. Review exact Python/Git/compiler/Verilator/share/pythonlib/tool/transitive runtime inputs for this new operation; component success does not freeze them.

The eventual project receipt must say only source prepared and independently audited, with a separate scalar measurement prerequisite list. Scalar original four-case timing, process closure, output metrics and later ordinary/failure fresh have their own actual command/lock and evidence. This document grants no current projectready, timing improvement, RFuzz, source-consumption or P8 acceptance claim.
