# Full AXI raw-reference drain fix independent review

2026-10-17. Frozen source `944a888`; independent read-only diff/source review. No model, native, build, elaboration or remote action. No test rerun by this reviewer.

- `src/myfuzz/scenario/full_axi_events.py` SHA256 `6121ea7da01f1266bb3cf5e4506fa45d390a2ed0a3c2100b6463b0087356354a`
- `tests/scenario/test_full_axi_events.py` SHA256 `efcda0e3bd2dacd9e0d1aa65ef4ec67fa088c446c578dbaaabdb4edd1c44075b`

Verdict: no high/medium source blocker found for this bounded fix.

The lifetime `_record_count` is initialized only at observer construction and incremented once for every `_emit`, including diagnostic/scope events. It replaces `len(events)+1` only when allocating the next raw reference. Scope begin/end do not reset it. Consequently the undrained path retains exactly its former event-slot numbering, while a Runner EventJournal drain clearing the list no longer reuses reference1. No new event fields, payload rewrite or normalization was introduced. Existing request/write-data/completion references continue naming their original raw record.

The new control runs the actual Runner import and EventJournal drain with software records: old AR drained, later R joins old request/new raw references, duplicate drain imports nothing, and a subsequent scope keeps unique raw references. This addresses the real integration seam rather than testing list.clear alone.

Inspected author receipts: initial RED shows rawref reuse; an intermediate GREEN attempt failed because its own assertion used singular raw_event_ref for a read-beat event that correctly uses plural raw_event_refs, and that failure remains retained. Final `.superpowers/full-axi-drain-fix/green-final.log` reports113 passed7.00s. `archived-prefix-compatibility.json` records actual saved first/fresh826 event arrays unchanged under offline reprojection. These receipts were read, not independently regenerated in this review.

The existing frozen CVA6 native execution retains its original source identity. This source fix and offline compatibility check do not retrospectively change that native pin or confer source/retirement/P7 authority. Any future native run uses a new frozen source identity.
