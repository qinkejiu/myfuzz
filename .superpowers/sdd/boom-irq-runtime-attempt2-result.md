# BOOM IRQ runtime attempt2: failed global scheduler budget

Root launched the sole authorized operation. Actual controllerPID268173 / gate childPID268183 reached terminal; state/native.exit=1 and worker.exit=1, child.poll=1. Both PIDs were absent at terminal read. No owner restart or concurrent model operation occurred.

## Immutable full evidence

`.superpowers/boom-irq-runtime-attempt2-20261017/native-attempt2-evidence.tar.gz` contains396 regular files, including complete gate-output, GPIO generated cache/build products, raw CPU/GPIO streams, source/target/runtime/Runner events, lifecycle/exit receipts, all controls/maps and logs. SHA `8e0a8f1e85e2e122ef052a83cd9d86fe46baea3f6c36926aa5a0ce3f6f671393`. Per-file lengths/SHA are in native-file-manifest.json. Exact first.json.gz is also retained as native-first.json.gz. Existing remote attempt/source/artifact remain unchanged.

Only first ran: fresh and suppression were not reached after validation rejected first.status. Summary status=failed, error ValueError `run did not complete`. Captured first.status=`budget_exhausted`, error=null. This is neither setup failure nor proven DUT failure.

## Actual saved observations

Measured CPU execution5f8e226b-ac3b-41d5-b8cd-d53b5a9f482c PID268732; constructor setup executionacb3ae9b-6609-4524-9341-8c1b72c00cb3 PID268604. Both true CPU processes closed exit0 using binary6367b592...c90. ActualGPIO PID268860 execution969f6138addd42b2b2a8d4dd38b28e10 closed exit0.

19299 CPU commands,19301 CPU transport reads,2988 CPU samples;2994 GPIO commands,3182 GPIO transport reads,3012 GPIO samples;54452 Runner events;6 real router deliveries;81 coherent raw accepted events (162 raw+projection records). Coherent report structural_error=false and normalization_poisoned=false; no pending sources/sinks or uncertain keys.

Saved physical delivery entries have requested=delivered=1 at CPU cycles221..284 inclusive, exactly64 samples. ROB actual interrupt cause0x800000000000000b occurs281post/282pre; CSR exception occurs282post/283pre. Actual preprobe cmd4/address0x302 qualifies MRET at429. Accepted RAM stores: cause3010 tick339, mepc3018 tick346, status3020 tick403, clear3024 tick407, done3028 tick412, resumed302c tick475. Final physical RAM reads:3000=1,3010=0x800000000000000b,3018=0x8000005c,3020=1 (upper clear0),3028=0x100000001 (done1/resumed1). These observations alone do not grant the full gate or fresh-prefix claim.

Actual GPIO deliveries are writes offsets4/24/28 followed by status offset36 reads0/highlane1/0. Full original lane values are retained (middle64-bit response4294967296).

## Root cause and smallest proposed correction (not applied)

Last actual event54452 is budget_exhausted, limit=max_scheduler_steps, phase=before_step, effect_may_have_occurred=false, local_ticks CPU2988/GPIO3012. Sum=6000. The gate ResourceBudget sets max_scheduler_steps=STEPS=6000, while DependencyScheduler is requested to execute6000 outer schedule calls and then at most512 quiesce calls. Generic router steps the GPIO to complete actual APB transactions; those24 extra GPIO steps also count in Runner's global resource budget, so main scheduling terminates12 CPU iterations before its requested3000CPU/3000GPIO outer schedule finishes.

Source pointers: boom_gpio_irq_verification.py _run_one ResourceBudget and genome creation; scheduler.py main range(genome.max_steps); runner.py step global local-tick capacity and budget exhaustion. No need to change generic runner/RTL/firmware, IRQ width or infer completion from RAM.

Proposed source-only correction: explicitly budget existing requested main+quiesce allowance (STEPS+QUIESCE), retaining genome6000 and quiesce512, fixed64 pulse and strict validation. Add a pure realRunner/scheduler contract regression with nested target steps to show outer bound versus global local-step accounting, and assert no allowance extension based on ISR progress. Parent must approve accounting interpretation and source review before a new isolated metadata/control/runtime attempt. This report changes no implementation and launches nothing.
