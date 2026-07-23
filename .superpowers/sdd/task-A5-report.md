# A5 Deterministic Top-K and Composition IR Report

## Scope

Implemented deterministic bounded composition search and serialization:

- `compose_topk` builds the A3 constraint graph, rejects hard-conflict graphs, consumes A4 address regions, enumerates one-to-one endpoint matchings with bounded depth-first state, and retains only K candidates in a heap.
- Candidate edges are normalized before enumeration, graph hashes exclude candidate edge IDs and emitter/runtime metadata, and the final ordering uses the eight-tier lexicographic score vector with the normalized graph hash as the final deterministic tier.
- `composition_ir` emits numeric component, endpoint, net, adapter, address, domain, and external-port relations while retaining RTL evidence, inferred/assumed decisions, and rejected legal alternatives.
- `candidate_manifest` joins deterministic emitter metadata, strips directories from emitted source paths, and derives semantic hashes only from IR and emitted content.

The implementation never reads RTL identifier text. Search ordering is based on typed semantic fields, opaque numeric IDs, and canonical content hashes. The frontier retains only the current matching path plus a heap of at most `limit` candidates; rejected candidate objects are released immediately.

## TDD Evidence

The initial A5 tests failed with `ModuleNotFoundError` for the missing `myfuzz.composition.search` and `myfuzz.composition.ir` modules. After the initial implementation, an address provenance test failed because the internal A4 marker `fixed` leaked into IR. The implementation now maps fixed RTL address facts to `rtl`, inferred placements to `inferred`, and preserves contributing `local_address_facts` evidence.

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

Coverage includes limit and fewer-than-K behavior, invalid limits, hard-conflict rejection, graph-hash deduplication, repeated-run ordering, RTL and address evidence, inferred/assumed provenance, rejected alternatives, manifest contract validation, semantic IR hashing, and source-path sanitization.
