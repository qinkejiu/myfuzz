# Full AXI lifetime raw references

Root cause: `observe` assigned `len(self.events)+1`, but ScenarioRunner deliberately clears the same list in place after importing it into EventJournal. A later response reused raw reference1 and could collide with its own request.

Actual pure Runner/EventJournal regression first failed `1 > 1` (red.log). Minimal fix keeps a lifetime emitted-record counter, never resets it with scope or list drains, and uses its next index. No schema/payload field added, no native execution. Initial GREEN run112passed/1failed because the new test incorrectly assumed singular raw_event_ref on read completion; corrected to the existing raw_event_refs list, preserving that log. Final113pure controls passed7.00s. Archived actual CVA6 first/fresh650samples each still reproduce every826 record byte-for-JSON-value unchanged (offline comparison, not new native evidence).

Runtime/source scope intentionally unchanged; no authority escalation. Independent review requested from fix_f4_executor.
