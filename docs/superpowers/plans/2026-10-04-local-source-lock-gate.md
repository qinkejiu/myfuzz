# Local Harness Source Lock Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Independently reject local harness profile sources that do not match a verified pinned source-lock entry.

**Architecture:** Add an explicit gate taking a ComponentProfile and repository base directory. Compare its normalized source identity fields with the matching component record in configs/soc/sources.lock.json, require selected/source_verified/elaboration_verified status, and invoke the existing single-record verifier with full document ownership and allowed-root context. Return evidence including lock SHA without modifying planning or rendering and without compiler replay.

**Tech Stack:** Python 3.12, unittest, existing scripts/verify_soc_sources.py.

## Global Constraints

- Do not modify renderer.py, port_rendering.py or plan_local_harness.
- Verify only the matching record; preserve dependency ownership context.
- Reject missing/duplicate entries, mismatched source settings, dirty pinned bytes and invalid closure evidence.
- No full lock replay, runtime claims, or network use.

### Task 1: Independent verification API

**Files:**
- Create: src/myfuzz/local_harness/source_lock.py
- Create: tests/local_harness/test_source_lock.py
- Modify: src/myfuzz/local_harness/__init__.py

**Interfaces:**
- Consumes: ComponentProfile.source_document, ComponentProfile.component_id, base_dir: Path.
- Produces: verify_local_source_lock(profile: ComponentProfile, *, base_dir: Path) -> dict[str, object].

- [ ] Write tests using temporary pinned Git source and real closure evidence. Start with `self.assertTrue(callable(getattr(source_lock, 'verify_local_source_lock', None)))`; test clean evidence, source document drift, missing record, unverified closure, dirty Git content, corrupt closure bytes, and changed closure-owned file.
- [ ] Run `PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_source_lock -q`; expect failure due to missing gate.
- [ ] Implement the gate with these explicit checks:

```python
validate_document(document)
record = next(r for r in document['components'] if r['id'] == profile.component_id)
# Compare root/revision/top, ordered source files, filelist and normalized
# optional lists; match effective parameters/defines to typed lock and
# authenticated closure evidence, and require verilator-json frontend.
if (record['closure_status'], record['source_status'], record['elaboration_status']) != (
        'selected', 'source_verified', 'elaboration_verified'):
    raise ValueError('local-source-lock-unverified')
result = verify_record(record, root, owners=document_owners(document, root),
                       allowed_roots=document_roots(document)[record['id']], replay=False)
```

Use the existing repository verifier module through an explicit importlib file loader; missing record raises `local-source-lock-missing-component`. Return verifier result plus `schema_version: local_source_lock_verification.v1` and `lock_sha256` of the actual document bytes.
- [ ] Run new tests and `tests.integration.test_soc_source_locks` plus existing local_harness tests. Confirm no planner mutations fail.
- [ ] Commit only gate, tests, exports and this plan using `git commit -m 'feat: add independent local harness source lock gate'`.

Execution refinement: defaults for include_roots/repositories/filelist_variables normalize to empty lists. Profile parameters and defines must exactly match both typed lock values and authenticated closure values. This permits the existing PULP GPIO representation while rejecting undeclared overrides. The API requires a repository checkout with the verifier script; artifact builder integration is outside this milestone.

Review amendment: compare actual ComponentProfile.source against the canonical _source_locator(source_document) result before lock verification. Test direct dataclasses.replace mutations of revision/root/files/top/elaboration; reject the retained-document/actual-locator divergence.
