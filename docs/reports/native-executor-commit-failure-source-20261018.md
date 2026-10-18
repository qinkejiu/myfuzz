# Native executor post-submit commit failure

Source-only implementation of the failure notification seam in the approved
[P6 native plan](../superpowers/plans/2026-10-18-p6-native-persistent-search.md).

## Cause and correction

The executor submits the real case before committing its decoder. A decoder
exception or non-admitted result previously reached general executor cleanup
without poisoning the guarded native session itself. A later direct submission
could therefore bypass the executor's stopped state.

Both failure forms now set `commit_refused`, notify only the code-owned
`NativePacketSession.abort_packet_submission(primary)`, then re-raise the
original failure. That existing failure-only method poisons the packet session,
collects the actual attempted boundary, finalizes once and preserves cleanup
errors as notes. It cannot assert successful decoder commit or grant feedback.
The decoder still has exactly one commit owner and one actual commit call.
The default session receives no native abort notification.

## Review and limits

Independent source review found no new Important issue: terminal checking
precedes cached receipt reuse, the original exception remains primary, and
the lazy failure-path import has no static reverse import to the executor.
Static AST parsing and scoped whitespace checks passed. No project import,
test, frontend, build, model or remote command was run. The old real gate
does not validate this change. Guarded fresh reconstruction, typed nonce
comparison, exact admitted source joins and the new actual gate remain open;
this change grants no RFuzz support or P6 completion.
