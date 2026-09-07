# Generic AXI4-Lite routing follow-up implementer report

Status: DONE

Requirements: `.superpowers/sdd/axi-lite-followup-brief.md`. Executed the approved
Tasks 5/6 follow-up in the existing isolated worktree, without reopening design
approval. This is the implementer/self-review handoff, not an independent review.

## Implementation

- Added focused `generic_axi_lite.py`, selected through `native_contract` only
  for the semantic protocol key `axi4-lite@1`. No CPU-name selection or wrapper
  dependency. Existing `auto.py` already calls that contract boundary and needed
  no changes.
- Native catalog validation rejects unknown/missing fields, incompatible field
  directions/width expressions, unsupported channel relations, capability keys
  or values (including bursts, IDs and multiple outstanding requests), malformed
  temporal/projection channel shapes, and invalid wait bounds. The effective
  bound is the minimum of the catalog capability, gate and temporal bounds.
- Rendering validates unsigned physical channel shapes, equal AW/AR address
  widths, 32/64-bit equal write/read data widths, byte strobes, protection and
  response widths, address flags, region bounds and reset semantics.
- AW and W capture independently in either order. Either channel reserves the
  sole outstanding transaction slot. A simultaneous write/read request gives
  priority to the write; an outstanding partial write prevents read admission.
  AR otherwise accepts independently. No additional source transaction is
  accepted while a source response is pending, even under prolonged backpressure.
- AWADDR and ARADDR are independently decoded and translated at capture. The
  comparison uses one extra address bit to handle a region ending at the top
  of the address space. Invalid AW/AR addresses produce local DECERR, with zero
  read data for invalid reads, without any downstream transaction or quarantine.
- Downstream AW/W/AR payload and VALID are registered and held until each
  channel's handshake. B/R responses and read payload are latched and held until
  the source consumes them. Normal target response codes propagate unchanged.
- The wait counter starts when a downstream request is asserted. The strictest
  catalog bound is a conservative *total target transaction* budget, including
  request acceptance and response waiting; it is not restarted per channel.
  Source AW/W collection and source response backpressure do not consume it.
  A response handshake on the deadline wins over timeout.
- A timeout returns SLVERR (zero read data), then permanently quarantines the
  route until reset. Pending downstream VALID/payload are **not withdrawn** on
  timeout. They can still handshake in quarantine, but late B/R responses cannot
  reach the source or contaminate another transaction. Reset clears the route;
  the source and target must share that reset. This is documented in the module
  docstring and generated RTL comments.
- Generic top publication permits this independent dual-address route and
  retains the existing adapter boundary. `component_select` is tied high for
  AXI4-Lite because the adapter does its own two independent address checks.
  The old single-address routes and APIs remain unchanged.

## TDD evidence

All commands ran from `/home/qinkejiu/myfuzz/.worktrees/ibex-protocol-longrun`.
Python/build work was sequential, under `nice -n 15`, using local Icarus/vvp,
with no waveforms or network fetches. Test subprocesses inherit that priority.

Initial RED, before production edits:

```text
nice -n 15 env PYTHONPATH=src python3 -m unittest tests.integration.test_axi_lite_native_composition -v
Ran 6 tests in 0.065s
FAILED (errors=13)
AutoCompositionError: generic:adapter:axi4-lite@1:native-protocol-unsupported
```

All scenarios reached the expected missing native protocol guard, rather than
failing imports or simulator setup. The first command used unavailable `python`;
it was corrected to `python3` before recording this RED result.

Initial GREEN after native implementation:

```text
nice -n 15 env PYTHONPATH=src python3 -m unittest tests.integration.test_axi_lite_native_composition -v
Ran 6 tests in 0.367s
OK
```

During RED-to-GREEN, fixed the frozen-plan tuple/list contract comparison,
replaced a test deepcopy of immutable mappingproxy metadata with field-only
copies, and used explicit enum branches instead of ternary enum assignment for
Icarus compatibility. These failures were observed before their respective fixes.

Second RED: explicit unsupported temporal/projection metadata tests:

```text
nice -n 15 env PYTHONPATH=src python3 -m unittest tests.integration.test_axi_lite_native_composition.AxiLiteNativeCompositionTests.test_rejects_unsupported_temporal_and_projection_shapes -v
Ran 1 test in 0.003s
FAILED (failures=6)
AssertionError: AutoCompositionError not raised
```

Added strict temporal/projection shapes, then GREEN: the AXI file and focused
native/generic regressions passed 33 tests in 0.942s. Additional self-review
regressions subsequently passed without further production changes.

## Final verification

```text
nice -n 15 env PYTHONPATH=src python3 -m unittest tests.integration.test_axi_lite_native_composition -v
Ran 10 tests in 0.529s
OK

nice -n 15 env PYTHONPATH=src python3 -m unittest tests.integration.test_axi_lite_native_composition tests.integration.test_native_protocol_composition tests.composition.test_generic_auto tests.composition.test_protocol_composer tests.protocols.test_axi4_lite_rtl -q
Ran 36 tests in 1.036s
OK

nice -n 15 env PYTHONPATH=src python3 -m unittest discover -s tests -t . -q
Ran 849 tests in 18.813s
OK

git diff --check
# exit 0, no output
```

The full suite was run once before committing, after the main agent confirmed
its earlier full suite had finished. Its count includes the main agent's
independent source-type/transport work present during discovery. Expected CLI
diagnostic/output tests emitted their normal text; focused test output was clean.

The AXI test file executes 16 real Icarus/vvp benches (including parameterized
subcases) plus a source-backed generated top compilation. Tests exercise both
source AW/W orders, both target AW/W handshake orders, write/read arbitration,
independent addresses, stable payload under request and response backpressure,
DECERR without target traffic, exact timeout bounds 1 and 4, fully/partially
accepted and unaccepted target requests, late responses, quarantined handshake,
deadline completion precedence, post-reset successful traffic, all four reset
semantics, 64-bit payloads and a region ending at 2**address_width.

## Changed paths (only these are owned/committed)

- `src/myfuzz/composition/generic_axi_lite.py`
- `src/myfuzz/composition/generic_protocol_routes.py`
- `src/myfuzz/composition/protocol_composer.py`
- `tests/integration/test_axi_lite_native_composition.py`
- `.superpowers/sdd/axi-lite-followup-report.md`

## Self-review and limits

Reviewed requirements against the state transitions, admission/handshake signals,
counter start/deadline behavior, reset and quarantine behavior, immutable plan
boundary, generated module port wiring and old native route dispatch.
Self-review identified incomplete temporal/projection rejection; reproduced it
with six RED cases and fixed it. Added boundary/reset/partial-handshake regressions.
No known remaining correctness concern within this task's contract.

Intentionally unsupported: AXI4 bursts/IDs, full TileLink, CDC, shared multi-target
buses, extra outstanding transactions, and AXI4-Lite widths outside 32/64-bit data.
Waiting for a missing source AW or W is unbounded: that is source-side collection,
not a target timeout. Reset recovery assumes the connected target is reset too;
a timed-out request might still take effect downstream before reset, so callers
must not treat SLVERR as proof that no write occurred.

The source-backed publication fixture is synthetic HDL with physical ports and
source hashing; it is not evidence of real CVA6/BOOM CPU integration. Independent
real-source dependency assessment, general docs, and RFuzz transport/publication
changes remain the main agent's work. Preserved `.superpowers/sdd/task-2-report.md`,
`third_party/`, and all independent transport/source-crawler changes untouched.

`protocol_composer.py` ownership returns to the main agent after this commit for
its RFuzz publication integration. Independent review is left to the controller.

## Independent review P2 fix: publication at the address-space end

The independent reviewer found an Important/P2 omission in top publication:
`_render_generic_top` constructed single-address select literals before replacing
them with the AXI constant select. Thus an exclusive upper address of `0x10000`
for a 16-bit endpoint failed `_sv_literal`, even though the AXI adapter's extended
address comparison supported it. The earlier adapter-level boundary simulation
did not cover this outer publication path. The original no-known-concerns statement
above describes the pre-review self-assessment, not evidence that this gap was absent.

Reproduced with two new tests before the production fix:

```text
nice -n 15 env PYTHONPATH=src python3 -m unittest tests.integration.test_axi_lite_native_composition.AxiLiteNativeCompositionTests.test_generated_top_with_last_page_region tests.integration.test_axi_lite_native_composition.AxiLiteNativeCompositionTests.test_source_backed_publication_at_address_space_end -v
Ran 2 tests in 0.066s
FAILED (errors=2)
ValueError: generic composition address literal is invalid
```

The first test exercises the generated top with the exact reported region
`base=0xff00,size=0x100`. The second creates a legitimate source-backed plan with
a catalog region covering `0..0x10000`, passes freshness reconstruction and full
publication, then compiles the published top with real Icarus. No publication
validation is mocked or bypassed in the latter test.

Fix: branch on native AXI4-Lite before constructing any single-address literals;
only non-AXI routes execute the previous comprehension. No adapter state machine,
timeout logic, or writer/publication-bottom code was changed.

GREEN, including all existing AXI simulations and APB/Wishbone native regressions:

```text
nice -n 15 env PYTHONPATH=src python3 -m unittest tests.integration.test_axi_lite_native_composition tests.integration.test_native_protocol_composition -q
Ran 19 tests in 1.033s
OK
```

No full suite run for this fix, as requested while the main agent runs its suite.
Only the AXI test and this report are committed by the implementer. The renderer
fix in `protocol_composer.py` is deliberately left unstaged for the main agent to
commit alongside its separately owned writer-bottom changes. Main transport,
docs, smoke tests, task-2 report and third-party files remain untouched. This fix
is ready for independent re-review; the production fix still needs the main
agent's commit.
