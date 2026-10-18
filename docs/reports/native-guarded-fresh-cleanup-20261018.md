# Guarded native fresh cleanup correction

Independent review found that malformed packet validation may raise before
NativePacketSession.submit_case enters its physical-operation try block.
Fresh replay had already begun real sessions, so that refusal could leave
their processes running. Warmup/begin failures also lacked an outer native
cleanup scope.

The explicit native replay branch now encloses begin, every saved warmup,
trusted admission, every guarded case and finish in one try. BaseException
calls the code-owned NativePacketSession.abort_packet_submission method and
uses bare raise to preserve the original exception. The existing abort method
marks terminal state and finalizes the runner at most once, retaining original
failure information and attaching cleanup failure notes. No case is retried
or executed in both branches. The generic replay execution remains in its
original branch; default behavior and exact trace comparison are preserved.

Static review parsed the changed source and compared ASTs of the complete
generic begin-through-finish statement sequence against HEAD: unchanged.
`git diff --check` passed. Source SHA256 at review:
`b073888e30373d044a2122c4f25203ab0e8d26df1037dd329e397887874b9964`.

This is source-only correction. No project imports, tests, frontend/build/model,
native process or remote operation ran. No new pass is claimed. Packet plan
max_cases binding, native terminal-failure serialization and opt-in fresh
nonce comparison remain separate work. Original raw trace comparison and
retention were not changed.
