# A5 Deterministic Top-K and Composition IR Report

## Scope

Implemented deterministic bounded composition search and serialization:

- `compose_topk` builds the A3 constraint graph, rejects hard-conflict graphs, consumes A4 address regions, enumerates one-to-one endpoint matchings with bounded depth-first state, and retains only K candidates in a heap.
- Candidate edges are normalized before enumeration, graph hashes exclude candidate edge IDs and emitter/runtime metadata, and the final ordering uses the eight-tier lexicographic score vector with the normalized graph hash as the final deterministic tier.
- `composition_ir` emits numeric component, endpoint, net, adapter, address, domain, and external-port relations while retaining RTL evidence, inferred/assumed decisions, and rejected legal alternatives.
- `candidate_manifest` joins deterministic emitter metadata, strips directories from emitted source paths, and derives semantic hashes only from IR and emitted content.

The implementation never reads RTL identifier text. Search ordering is based on typed semantic fields, opaque numeric IDs, and canonical content hashes. The frontier retains only the current matching path plus a heap of at most `limit` candidates; rejected candidate objects are released immediately.

## TDD Evidence

The initial A5 tests failed with `ModuleNotFoundError` for the missing `myfuzz.composition.search` and `myfuzz.composition.ir` modules. After the initial implementation, an address provenance test failed because the internal A4 marker `fixed` leaked into IR. The implementation preserves contributing `local_address_facts` RTL evidence while emitting each allocated absolute base as `inferred`.

## Verification

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests/composition -p 'test_*.py' -v
Ran 40 tests in 0.008s
OK

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests/contracts -p 'test_*.py' -v
Ran 9 tests in 0.002s
OK

PYTHONDONTWRITEBYTECODE=1 python3 -m compileall -q src/myfuzz/composition tests/composition
exit 0

git diff --check
exit 0
```

## A5 Re-review Fixes

- The metadata gate now rejects POSIX absolute paths wherever they occur in a semantic metadata string, including delimiter-embedded values such as `debug_path=/private/build/top.sv` and `cache:/tmp/output`.
- Score tier four accepts a verified clock/reset association only from a `clock_reset_checks` record with exact `structurally_validated: true` and explicit matching `component_id`, `port_id`, `kind`, and `domain_id`. Generic `validated: true` claims do not affect the score.

## Re-review TDD Evidence

RED command and observed results:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest tests.composition.test_ir.CompositionIrTests.test_manifest_rejects_embedded_absolute_host_paths tests.composition.test_search.CompositionSearchTests.test_score_tier_four_counts_only_unvalidated_declared_clock_reset_associations -v
Ran 2 tests in 0.001s
FAILED (2 failures): embedded absolute host paths were accepted; generic `validated: true` reduced score tier four from 2 to 0.
```

GREEN commands and observed results:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest tests.composition.test_ir.CompositionIrTests.test_manifest_rejects_embedded_absolute_host_paths tests.composition.test_search.CompositionSearchTests.test_score_tier_four_counts_only_unvalidated_declared_clock_reset_associations -v
Ran 2 tests in 0.001s
OK

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest tests.composition.test_ir tests.composition.test_search -v
Ran 14 tests in 0.006s
OK

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests/composition -p 'test_*.py' -v
Ran 46 tests in 0.011s
OK

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests/contracts -p 'test_*.py' -v
Ran 9 tests in 0.002s
OK

PYTHONDONTWRITEBYTECODE=1 python3 -m compileall -q src/myfuzz/composition tests/composition
exit 0

git diff --check
exit 0
```

Coverage includes limit and fewer-than-K behavior, invalid limits, hard-conflict rejection, graph-hash deduplication, repeated-run ordering, RTL and address evidence, inferred/assumed provenance, rejected alternatives, manifest contract validation, semantic IR hashing, and source-path sanitization.

## A5 Review Fixes

- Absolute allocated address bases now emit `inferred` provenance and a matching `address_base` inference, while the local RTL address fact remains evidence. No absolute allocated base is emitted as `rtl`.
- A shared recursive metadata gate rejects absolute paths, ISO timestamps, object/process pointer strings, and PID strings from composition IR and all manifest metadata, including top ABI, diagnostics, and validation. The generated source filename remains reduced to its basename.
- Score tier four now counts only explicit clock/reset declarations without a matching structurally validated `clock_reset_checks` fact.
- Field, edge, region, endpoint, emitted IR relation, assumption, and rejected-alternative ordering is canonical. The bounded retained candidate set ignores duplicate normalized graph hashes.
- Composition IR now includes one concrete stable-ID instance record per declared component.

## Review TDD Evidence

RED commands and observed results:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest tests.composition.test_ir tests.composition.test_search -v
Ran 12 tests in 0.005s
FAILED (3 failures, 1 error): allocated base emitted `rtl`; instances were empty; host-specific ABI/diagnostic/validation metadata was accepted; the initial one-sided clock fixture had no legal candidate.

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest tests.composition.test_search.CompositionSearchTests.test_normalized_graph_hash_ignores_field_permutation -v
Ran 1 test in 0.000s
FAILED: equivalent field permutations produced distinct normalized graph hashes.
```

GREEN commands and observed results:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest tests.composition.test_ir tests.composition.test_search -v
Ran 13 tests in 0.006s
OK

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest tests.composition.test_search.CompositionSearchTests.test_normalized_graph_hash_ignores_field_permutation -v
Ran 1 test in 0.000s
OK

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests/composition -p 'test_*.py' -v
Ran 45 tests in 0.010s
OK

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests/contracts -p 'test_*.py' -v
Ran 9 tests in 0.002s
OK

PYTHONDONTWRITEBYTECODE=1 python3 -m compileall -q src/myfuzz/composition tests/composition
exit 0

git diff --check
exit 0
```
