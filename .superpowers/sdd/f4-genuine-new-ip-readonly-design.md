# Read-only design: a genuinely different APB IP in compiled F4

Scope: source inspection/design only while the frozen Ibex gate runs. No generic core, source authority, fixture or runtime changed; no additional native/test/build was run for this audit. Current dual-CPU/GPIO success cannot authorize arbitrary same-protocol IP.

## Current supported boundary

| Layer | Existing support | Actual missing boundary |
| --- | --- | --- |
| D3 | `compiled_paths.py:1480,1614` and `register_source_access.py` derive exact aligned32-bit target-word address, masks, byte lanes, source/target components/endpoints and CPU transaction origin. F4 emits ip_register_version prerequisite and bound target commit. | Sidecar writable/readable claims do not prove a live storage value or its update rule. `_preferred` deterministically picks side-effect-free/name ordering; selection must be deliberately unambiguous. |
| Generic APB transport | `apb3_register_template.py` authenticates target.apb3/full-word selection:12-bit APB address,32-bit word,4096-byte window, no partial writes, native PSLVERR. Every nonbus physical input is fixed/source/bound with exact ownership. `GeneratedApb3RegisterSession` supports actual read/write/source/bind and pre/post tick samples. | Transport completion and readback are not a registered internal prestate/version authority. No peer/serial behavior is supplied by this template. |
| F4 executor | `compiled_f4.py:376,380,448` requires kind apb_gpio, GPIOEN, GPIO probe contract and exact GPIO prerequisite; directly constructs GeneratedPulpGpioSession/GpioRegisterVersionAuthority. | New APB artifact is refused; renaming an instance cannot change that capability. |
| Native joins | `generated_register_writer.py:113` requires verify_native_physical_observation; existing verifier only admits obi_cpu/apb_gpio. | Generic APB passive trace exists, but the current physical authority verifier is not generic. Preserve reconstruction of actual wires, not merely protocol labels. |
| Live authority/reset | `gpio_register_version.py` requires exact GPIO class/probe source and actual command frame/build. `native_reset_observation.py:40` requires GeneratedPulpGpioSession; `native_reset_evidence.py:82` registers only GPIO targets. | Both reset/build/command producer eligibility and storage observation need a source-verified generic interface. Removing type checks alone would weaken authority. |

`tests/local_harness/test_generic_apb3_register_real.py` contains GPIO+timer transport tests and opt-in real replay cases. Their existence is source evidence only; none was run in this audit, and they do not establish compiled F4 version authority.

## Recommended real new-to-F4 target: pinned PULP timer

Use the existing, genuinely different `apb_timer` RTL, not a GPIO alias/profile rename:

- profile `configs/peripherals/pulp_timer/component_profile.json`, source revision03eba2e6965f5363df12621882bc70498c551a73, APB_ADDR_WIDTH12/TIMER_CNT2;
- `src/apb_timer.sv` SHA22dce4e3ff8328bdd6e1621c20e2877e7f44cfecccc07203d09e994632cc1778;
- `src/timer.sv` SHAd352fc4476da83658d361e8f500b5a73f857f0a11e9436ab47d5bf0ba0bc7fce;
- selected storage TIMER0_CTRL, offset4,32-bit full-word read/write, reset0. Actual `timer.sv:71,89,96,120,134,139` preserves CTRL except reset or selected APB write, writes PWDATA and reads regs_q[REG_TIMER_CTRL]. Counting/IRQ can change other state; it is not proof that every register is stable.

Prefer CTRL over COUNT (autonomous when enabled) or CMP (write resets count). Sidecar declares only the chosen supported CTRL field, with full masks and actual source evidence; this avoids `_preferred` accidentally selecting COUNT. No invented setup writes, expected rdata or IRQ behavior. Generic target uses setup_writes=()/probe_offsets=(): CPU/router remains the only candidate register writer.

This is a genuinely different source/module/register machine and a new IP in the compiled F4 supported set, even though the repository already contains timer RTL/transport support. It is **not** a newly imported repository IP. If the plan literally requires a previously absent upstream IP, timer alone does not satisfy that stronger requirement. Renaming GPIO would satisfy neither interpretation.

Timer has no external data input beyond bus/clock/reset, so its declared candidate layout should be4bytes (MMIO word), not the current GPIO fixtures'8bytes. Derive this from D3; never append a dummy pin source to keep old record length.

## Minimum declaration and trusted implementation design

1. Declarative composition selects the generic APB register template, exact timer source/profile/capability and CPU resource/window. Own every real nonbus input; timer needs no fabricated external pin producer. D3 selects TIMER0_CTRL, exact target word and ip_register_version subject. Preserve all three required F4 assertions and instruction→native CPU→router→native APB→register commit→CPU readback/RAM joins.
2. Introduce one restricted code-owned storage-observation contract class/validator, not a component-name runtime branch or arbitrary JSON callback. A descriptor binds source digest/revision, elaborated parameters/top/hierarchy, register/offset/mask/width/reset, exact native APB decode, actual storage probe expression and allowed update equation. For this source, the prospective expression is the real generated-wrapper hierarchy ending `TIMER_GEN[0].timer_i.regs_q[1]`; verify the complete generated hierarchy rather than assuming its prefix.
3. Contract verification must prove the selected expression is actual source-owned storage; enumerate reset/write/autonomous writers and exact alias/decode behavior. A source hash plus a caller statement about semantics is insufficient. Use a closed source-shape verifier for the supported APB storage dialect or an explicitly code-reviewed/source-pinned registered producer contract. Unknown shapes/changed writers/mismatched parameters refuse. A human JSON evidence_ref by itself never mints authority.
4. Generated renderer exposes read-only pre/post storage and native APB probes only after that contract is admitted. Do not let a user choose an arbitrary hierarchy string, redirect the probe to PWDATA/host expected value, fuzz the probe input or trust stored reports. Generic APB trace verification must reconstruct exact RTL wires/ports/assignments and real driver sample group.
5. Factor reset/build/command eligibility into a closed producer interface shared by GPIO and the admitted generic session. Retain actual built binary/source closure, actual Popen/process/nonce, reset epoch and trusted `_command_impl` frame/receipt identity. Preserve current GPIO guarantees. Merely permitting another Python type in NativeResetObservation is not equivalent evidence.
6. Generic version authority consumes every actual native tick sample, checks storage continuity and transition equation, counts real accepted writes and issues process-local single-use tokens. Revoke on any command/reset/process/source/uncertain receipt. Before/after tokens and commit must bind exact register, epoch, native tick, artifact/contract/source digest and actual routed CPU transaction. Readback-only diagnostics cannot stand in for this prerequisite.
7. F4 admission selects the target's admitted storage observation contract and register from D3; construction selects protocol/template, not named timer/GPIO classes. No unregistered generic fallback. Include contract/producer/layout digests in stability checks, checker/prefix and fresh identity. Generic session reports and serialized JSON remain evidence, never authority.

Native PSLVERR is a real timer output even though this RTL drives it0; that authorizes observing successful APB completion, not claiming error-generation behavior. CPU native-error/no-error policy remains separately selected by the CPU's exact contract. Timer IRQs are pulses and no CPU IRQ route is declared here; this design grants F4 consumption only, not F5 interrupt delivery or serial functionality.

## Verifiable acceptance sequence for future authorization

- Pure RED→GREEN: wrong source/probe expression, unsupported writer/autonomous changes, mismatched register/decode/parameters, fake native samples, stale/foreign/serialized tokens, missing ownership/producer/reset eligibility, altered layout/source and partial/seed semantics refuse before ticks.
- Source/codegen review: GPIO behavior unchanged; timer contract witnesses actual different RTL/storage; no name-based runtime branches, no implicit setup/expected-output producer.
- Standalone native storage probe: reset baseline, real accepted APB CTRL write and read, actual pre/post internal value, real PSLVERR; controlled mismatch/foreign-producer refusal.
- Actual CPU→timer continuous3 records and2 full fresh prefixes through the same compiled entry, all actual primary/fresh plan/events/PID/nonce/close/source identities. Mutated source/probe/route controls must refuse and preserve failures.
- Keep current GPIO gates and both CPU ABI gates as regressions. No arbitrary-IP/fullP7 claim from a timer-only registered storage dialect.
