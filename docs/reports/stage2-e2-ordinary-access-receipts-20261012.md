# E2 ordinary APB target receipts — implementation progress

2026-10-12. This continues the original Stage2 E1/E2 plan. The first package adds actual target command observations and actual Router handoff; the full stage remains open.

Three parallel agents investigated the [target path](stage2-e2-ordinary-access-renderer-design-20261012.md), [Runner/replay path](stage2-e2-ordinary-access-runner-design-20261012.md) and [independent trust boundaries](stage2-e2-ordinary-access-review-design-20261012.md). Renderer owns the new local-harness receipt helper and native GPIO Session, runner owns Router, and the reviewer owns independent boundary tests. Root owns integration verification and progress documents. No commit, cleanup or RTL simulation has been performed in this increment.

The default remains disabled. Explicit before-begin configuration enables a separate ordinary receipt API, without enabling the internal-probe causal GPIO mode. The target captures the actual parsed DriverReceipt execution, sequence, reset epoch and lifetime sample span, checks one complete error-free APB request/accept/response, then tags only samples produced by that command. Its finite live registry returns detached observations; saved receipt JSON does not register as authority.

Router supplies the actual TransactionKey and DeviceWindow context. It validates the closed returned receipt against the target's live registry and preserves detached nested data. Queued delivery is published only after the real CPU response callback succeeds. Callback failure records a target-only uncertainty, preserves the original exception, and cannot reexecute the ledger-cached target command. Synchronous return explicitly has `source_delivery_confirmed=false`; it cannot be interpreted as CPU callback confirmation. The old causal path retains priority and the disabled path retains its old field layout.

The evidence scope is `actual_target_command_observation_only`. All receipts keep `grants_verified`, `grants_storage` and `grants_functional` false. Native APB's null transaction key and explicit identity gap remain unchanged. This package does not yet join raw/base journal IDs, add a production Session/assembly selector, or certify register readback/storage/effects.

Initial baseline: four final capability/native APB modules passed 44 tests in 97.26 seconds (root handle 7518, exit0). Root's actual generated CPU `_serve` → service ledger/Router → generated target test used strict parsed software transport: missing-API RED (9.04 seconds), then initial GREEN (8.88 seconds). This is software transport evidence, not an RTL CPU execution gate.

Independent RED findings included three incomplete/conflicting APB boundary cases, four boolean/nonstring identity type cases, and a command tick-base change that misaligned retained sample coordinates. These were directed to the target implementer for repair before acceptance. Final verification and review results will be recorded below after production freeze.

Remaining work follows the same original plan: bounded Runner journal association to actual acceptance/delivery and command-tagged raw/base IDs; production opt-in configuration/source closure and fresh file replay; code-owned per-operation verifier using actual readback/reset observations; permission/mask/width and supported effect behavior gates; honest complete declared/effective/verified matrices. A target receipt or a successful replay is not aggregate L2 or functional completion.

## Freeze and independent review

Target and Router production files are frozen for root verification. Renderer joint verification: 57 passed in 38.61 seconds (handle 82249, exit0). Independent final boundary verification: 19 passed in 5.25 seconds, plus the two capacity/identity cases passed in 6.69 seconds; no remaining P1/P2 findings in this package. Root's ten-module broader regression completed as handle 98275, exit0: **166 passed, 34 subtests passed in 128.51 seconds**. It covers the four new receipt/Router/boundary/CPU handoff modules, legacy GPIO and Router, native APB projection, register runtime and capabilities, and the production register replay integration module. The three changed production source SHAs matched the frozen pins after verification.

Additional RED→GREEN fixes preserve nonzero source write-data on a read request without turning it into an APB write, pin startup capacity in target identity/configuration, and prevent receipt IDs from being overwritten by a new driver process with the same reset epoch and reset command sequence. Access IDs now use a lifetime monotonic counter; private actual execution nonces map to stable process ordinals for comparison, while physical command identity remains privately deduplicated. Capacity includes retained history and refuses before a new command.

Frozen changed production sources:

- `local_harness/ordinary_apb_access_receipts.py`: `82da871f5dbb3f6a3a32e1c64426465cd970807e694dea49c1b8014560e9edd7`.
- `local_harness/gpio_session.py`: `942c93c368dec1f966b42d1c793b30c0472901ba86710722c056dda8284bc620`.
- `scenario/router.py`: `e7149f3415d09f18c46a8248c832f7db18b5e9122f5fd65f6006d13cbb69c9d0`.

The prior actual capability gate remains historical evidence for its own frozen source identity. There is no new actual RTL or file CLI gate for the receipt increment. The direct target opt-in has its own identity fields; it is not yet exposed as an ordinary-receipt option in the production register assembly.

The production selector's existing 38/40-file closures already cover protocol normalizer/checker and core routing. The new receipt helper and a future collector need explicit opt-in closure entries. Driver build closure recursively observes new imports, which is a separate identity mechanism and does not replace the selector or Session source pins. Next configuration order is target receipt configuration, Runner collector installation, register adapter installation, capability preflight, then begin/fresh manifest comparison.
