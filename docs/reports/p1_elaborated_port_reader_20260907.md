# P1 elaborated physical-port reader evidence

Status: Task 1 implemented, independently reviewed and verified. This is a
physical compiler-evidence reader, not CPU elaboration or execution acceptance.

Starting point: `281f977`. Plan:
`docs/superpowers/plans/2026-09-07-elaborated-physical-port-evidence.md`.

## Delivered boundary

`extract_physical_ports(tree, metadata, top_module=..., source_files=...)`
reads one Verilator JSON top module and emits deterministic `elaborated_ports.v1`
facts. Supported physical types are explicit integral BASICDTYPE, REFDTYPE,
PARAMTYPEDTYPE, packed STRUCTDTYPE and packed arrays of integral leaves.

The result retains source-owned port/member locations, resolved widths,
signedness, nested member paths and packed offsets. First-declared packed struct
members occupy the most significant bits. It never assigns protocol roles or
functional meaning.

The reader rejects unresolved/cyclic references, unapproved source locations,
unpacked arrays/structs, unions, interfaces, expression ranges, malformed flags,
duplicate modules/ports/types/members and unsupported physical nodes. Limits
bound AST nodes, recursion, width, ports, per-structure leaves and total emitted
leaves.

## TDD and review

Initial RED: `reader-red.log` failed because the module did not exist. The first
GREEN passed 6 tests. Independent review found missing range proof, incomplete
source-closure checking, duplicate member ambiguity, loose signed parsing, a
non-global output limit and a test dependency on ignored run files. The
review-fix RED/GREEN logs show these corrections.

A final review found that a nested outer MEMBERDTYPE could evade the source
allowlist. `reader-final-red.log` reproduces that case; the final implementation
validates every traversed member. A clean-checkout-compatible test now writes a
small parameterized package/module in a TemporaryDirectory and runs the
installed Verilator under `nice -n15`, `JOBS=1`, and a 20-second timeout.

Final independent review: PASS, limited to this reader.

Main verification command:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 nice -n15 \
python3 -m unittest tests.composition.test_source_elaboration \
  tests.composition.test_source_crawler -v
```

Result: **45 tests / 0.303 seconds / OK**. Log:
`runs/p1_elaboration_probe_20260907/main-reader-after-review.log`.
`git diff --check` returned zero.

## CVA6 probe boundary

The retained source-bound wrapper uses the fixed upstream pin
`2e1336dcff3d1a0b49fbe6282b97802f32ea32af`, config_pkg, the selected
cv64a6_imafdc_sv39 config, build_config_pkg, the fixed-tree AXI package, and the
default AXI/NOC parameter type declarations extracted from core/cva6.sv.

Strict Verilator JSON generation stopped on 14 upstream width warnings. An
explicit exploratory `-Wno-fatal` run retained every warning and produced JSON;
the reader resolved request_o to 470 bits/32 leaves and response_i to 210
bits/13 leaves. Peak frontend RSS was about 42 MiB. Files, commands, hashes and
scope are retained in `runs/p1_elaboration_probe_20260907/cva6-types*/`.

The AXI blob was initially absent from the sparse worktree. A reviewer read it
from the promisor Git object without disabling lazy fetch, so that first read
may have fetched the fixed blob. Later object access used `GIT_NO_LAZY_FETCH=1`.
No moving revision was used.

This wrapper proves only the module's selected default type declarations. The
NOC types are overrideable at an actual parent instance, and the complete CVA6
module/source closure has not been elaborated. Protocol semantics, interface
annotation integration, CPU execution, RFuzz against a core, and BOOM-generated
RTL remain open.
