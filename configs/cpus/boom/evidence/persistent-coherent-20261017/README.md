# New persistent BOOM cached coherence verification

Actual supplement gate exits0 using the SAME persistent native executable as
the standard GPIO gate, SHA-256
`6f47a6166bb5ef5b515ed256adc721ee5ff6ae43e913883b4bce93ccb15bd44a`.
No rebuild or C++ changes occurred. Launcher180701 completed and released the
canonical heavy lock. Fresh native PIDs180842/181102 both exit0.

Each fresh run takes599 measured edges and accepts A21/C80/D164/E14,279 total
beats. Both CPU result words and dirty backing RAM equal0x123. The coherent
checker is healthy and closed with no pending source/sink. All measured edge
receipts—including idle/reset edges—match exactly between these NEW runs.
Raw accepted bus rows also match exactly, and full runtime streams match after
the declared execution/stream scope comparison. Unabridged raw identities,
599-edge receipt streams, accepted rows and558-record runtime streams are kept.

A separate old one-shot comparison also matches every recorded bus field.
Only that diagnostic's additional D address/fault flag are projected out.
This separate comparison does not replace either new full-fresh comparison.
The program includes initial/final memory fences and RV64 zero extension and
is retained as program.hex, SHA-256
`4ee3acfc3f4f64af93b37a0eaac1e43fe104ffb27c4181fd5580f703ae0f2adf`.

`evidence.tar.gz`:45,006bytes, SHA-256
`3f95e0e98a7ae991d71f16aee56a9d90ee5c0f5cb3b096c73483c8296deb2b56`.
Its16-file manifest binds source/script, native artifact, baseline trace, raw
new fresh edge/bus/runtime traces, actual PID/stage/exit/log and gate result.
All files were independently hashed locally after download; source bytes match
the committed prepared source. The exact reused native binary hash was checked
both immediately before launch and after completion.

This verifies new persistent C/E handling and real cache eviction/writeback.
External B/probes, native reset retention and general admission remain outside
scope. No full P6 or source/ISA authority is granted. Changed/missing response
controls belong to the separately recorded actual GPIO gate; none is silently
claimed as a fault control of this cached supplement.
