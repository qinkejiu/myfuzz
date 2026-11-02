# BOOM (TileLink coherent, RV64) on the generic F2/F4 executor: refused, with evidence

This descriptor is real: it declares a CPU, a target IP, a capability sidecar,
flow ids, executors and fuzz records exactly like the six working CPU rows. It
exists so the shared pipeline answers for BOOM **by name** instead of by a dead
mapping, and so the answer is reproducible.

## Result: refused before any runtime, past elaboration

```sh
TMPDIR=/tmp/myfuzz-tmp PYTHONPATH=src python3 scripts/run_generic_scenario.py \
  --descriptor configs/scenarios/compiled-f2-f4-apb-i2c-boom/generic_scenario.json \
  --flow F4 --mode original --case runs/boom-refusal-20261031/case \
  --cache runs/boom-refusal-20261031/cache --execution-mode search --rounds 128
```

Exit status `1`, empty stdout (no summary, no `status: observed`), stderr:

```
myfuzz.runtime.contracts.GenericRuntimeRefused: generic-source-unverified at /preparation
<- myfuzz.local_harness.harness_set.HarnessSetRefused:
   protocol-shape-not-admitted at /cpu/data_endpoint
   {"protocol": ["tilelink-coherent","1"],
    "error": "template-selection-refused:no_unique_compatible_contract"}
```

Two blockers used to be reported here. The first one is **resolved**:

1. *Elaboration* (17.96 MB `chipyard.TestHarness.SmallBoomConfig.top.v` vs
   `source_elaboration._MAX_AST_NODES = 1_500_000`, refused at
   `source_elaboration.py:183`) no longer runs. D2 authenticates and reuses the
   port artifact the derivation already publishes
   (`generated/source_manifest.json` -> `physical_ports` +
   `physical_ports_sha256`, `configs/cpus/boom/evidence/derived-20261017/
   physical_ports.json`), and cross-checks it against the ANSI port list re-read
   from the pinned source bytes: see `src/myfuzz/composition/
   stored_elaboration.py`. 47 ports, 3.6 s, no frontend walk, no change to the
   node limit.

2. *Protocol admission* is the remaining one, and it is now named:
   `src/myfuzz/local_harness/template_contracts.py` has `('tilelink','1')` CPU
   contracts only (the abstract four/five-role pair at `:224`), so nothing
   matches `('tilelink-coherent','1')` for a 39-role A/B/C/D/E client. No
   `tilelink_coherent_cpu` runtime kind exists either
   (`src/myfuzz/local_harness/runtime_renderer.py:352` kind inference,
   `src/myfuzz/runtime/registry.py:174` registrations), so no
   `LocalRuntimeArtifact` (`runtime_document` + `plan`) can be rendered.

`requests/processor.json` is now `local_harness.v1`, the shape every working CPU
row uses: the previous `local_harness.v2` + `raw_tick_stream` tuning is admitted
only for OBI/APB/native-memory observation (`local_harness/plan.py:210-220`) and
is not needed by the generic F2/F4 executor, which observes the rendered
protocol taps instead.

## Address window: why the IP cannot sit at 0x40000000

The pinned harness is not a Chipyard SoC. Its C++ manager serves every address
from one byte-addressed map and intercepts **only** a host-declared page:

* `src/myfuzz/local_harness/boom_cpu_driver.cpp:56` accepts
  `EXTERNAL <lo> <hi>` only for `0x4000 <= lo < hi <= 0x5000`;
* `src/myfuzz/local_harness/boom_scenario_session.py:46-47` enforces the same
  page, and `:232-234` requires the routed window to own the whole 4-byte word;
* `configs/cpus/boom/README.md` records `0x4000/0x4008` as "legal uncached
  locations in the emitted map, supplied by this isolated RAM manager instead
  of the full SoC boot register".

So `compose.json` places `pulp_i2c` at `base = 16384` (`0x4000`, size 4096) and
the register of interest is `PRESCALER` at offset `0` (addr `0x4000`, 32-bit,
`rw`, write/read mask `0xffff`). The register itself is the real one from
`configs/peripherals/pulp_i2c/component_profile.json`; only the window address
is the harness's, not the SoC's. Mapping `0x40000000` would require the CPU to
reach that address, which this harness answers from RAM instead of the router.

## What is delivered instead

The F2/F4 **dataflow** on this exact CPU/IP pair is delivered and run on real
RTL through the standard `ScenarioRunner` + `DataflowRouter` +
`GeneratedApb3RegisterSession`, by
`src/myfuzz/scenario/boom_tl_apb_f2f4.py`:

* F4, six cases: `runs/boom-f4-20261031/{original,fresh}` (6/6 pass, fresh
  `replay_matches=true`)
* F2, six cases: `runs/boom-f2-20261031/{original,fresh}` (6/6 pass, fresh
  `replay_matches=true`)

Those runs are explicitly **not** `compiled_mmio` admission: each case boots its
own native process, because the pinned harness accepts instruction words only
while `cycle == 0`. The generic executor supplies instruction words *after* the
core left reset (`integration/compiled_mmio.py:207` `declare_instruction_slots`,
`:252` `BoundOnlineInstruction`) and reads RAM back through the host
`PersistentMemory`, so it needs a rendered harness whose memory stalls an
undetermined fetch (`local_harness/native_session.py:81-113` is the reference
shape).

## Files

| file | meaning |
| --- | --- |
| `generic_scenario.json` | the refused descriptor (`executors: compiled_mmio`) |
| `compose.json` | BOOM CPU + `pulp_i2c` at `0x4000`, RAM `0x80000000 + 1 MiB` |
| `requests/processor.json` | `local_harness.v1` request for the BOOM profile |
| `requests/peripheral.json` | `local_harness.v2` request for `pulp_i2c` |
| `execution_supplement.json` | no host pins (the target's inputs are profile constants) |
| `test_capability.json` | the real `pulp_i2c` `PRESCALER` declaration (copied, fingerprint-checked) |

