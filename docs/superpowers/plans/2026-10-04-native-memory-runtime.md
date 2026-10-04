# Native completion memory generated runtime

## Source facts and contract

Pinned PicoRV32 source (`ef203c2b0a3fb793280f5114941416c425c5b461`) computes `mem_xfer = mem_valid && mem_ready`, consumes `mem_rdata` on that transfer and clears `mem_valid` on completion. A write is identified by nonzero `mem_wstrb`; addresses are byte addresses with aligned word transactions. IRQ/PCPI remain disabled. No physical error response exists.

The existing `ready_valid_processor_memory_adapter` asserts ready while IDLE and converts backend error/timeout to zero-data success. It is unsuitable for completion semantics. Preserve it for its existing callers; add an independently named, strict completion adapter with no early ready, single outstanding request, held request checks, bounded wait, and sticky terminal fault without asserting ready on error/timeout.

Explicit typed capabilities `completion_semantics=completion` and `address_units=byte` are required at runtime. No inference from a component/module name. Select the registry's cpu.native-memory/completion-no-error template explicitly, retaining its contract identity in runtime identity. Registry contract-only claims remain unchanged; separate runtime evidence gates apply.

## Steps and tests

1. Add typed native profile facts and strict runtime admission tests (missing/wrong completion/address semantics refuse).
2. Write completion adapter tests for no early completion, request stability, response data, backend error and timeout refusal. Add source-backed native runtime top with one memory backend and physical output observations; Verilator lint.
3. Generate STEP_MEMORY transport using the same bounded replay envelope, exact source/header/build identity and reset READY verification. Preserve OBI/APB operation behavior.
4. Add generic GeneratedNativeMemorySession servicing accepted memory beats through PersistentMemory/MemoryService; errors terminate rather than synthesize completion. Capture actual pre/post/native physical observations and transaction identities.
5. Run actual PicoRV32 program fetch/store/load twice in one process, retained memory state and fresh scenario replay. Report actual program bytes, tool/build identity, accepted transactions, reset counts and replay evidence separately. Operational support requires this gate; otherwise report only the implemented stage.

## Isolation

Use branch local-pico-runtime. Parallel agents do not edit the core runtime/driver/session files. Shared template changes remain protocol-driven; no Pico-specific renderer condition.
