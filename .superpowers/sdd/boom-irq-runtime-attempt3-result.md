# BOOM IRQ runtime attempt3 actual bounded gate PASS

Root independently preflighted actualready96f5e22f...9685 and launched the sole operation. Actualcontroller269878/nativegatechild269888 reachedterminal; native.exit=0/worker.exit=0/child.poll=0. Both controller/child absent at terminal observation. No restart or additional operation was launched by owner.

## Full preserved evidence

`.superpowers/boom-irq-runtime-attempt3-20261017/native-attempt3-evidence.tar.gz` SHA `df3ad507ca27e1f07e1493eeae6bdb87ec02e697f4e53b398027ba7b1f25583b`,403 regularfiles. Includes complete first/fresh/suppressed gzip documents and checks, all actual CPU/GPIO command/raw streams, runtime/source/Runner samples/events/routerdeliveries, actual lifecycle/PID/closeexit receipts, complete generatedGPIOcache/build products, controls/overlay/maps/proof/toolsbeforeafter/sourcebeforeafter/summary/inputaudit. native-file-manifest.json records each regularfile length/SHA. No full source tree or old BOOM artifact is moved or changed.

actual-run-audit.json retains all processready descriptors/actualargs/binaryhashes/nonces/counters. Exactsummary and child receipt retained separately. local-native-evidence-audit.json records re-execution of validate_run on each savedactual document and complete compare_fresh on first/fresh; allpassed without model execution. Fullprefix bytes/documents retained, not replaced with hashes.

## Actual counters and lifecycle

| Run | CPUticks | GPIOticks | Main direct | Indirect | Quiesce direct | Total | Requested/delivered IRQ |
|---|---:|---:|---:|---:|---:|---:|---:|
| first |3000|3024|6000|24|0|6024|64/64|
| fresh |3000|3024|6000|24|0|6024|64/64|
| suppressed |3000|3016|6000|16|0|6016|64/0|

All actual localsteps remain within shared6512cap; mainouter6000, maxquiesce512, fixedpulse64, wall300000ms unchanged. No unconditional512 reservation. Quiesce genuinely requiredzero additional localsteps in each run.

| Run | Role | ActualPID | Execution nonce | Closeexit |
|---|---|---:|---|---:|
|first|CPU setup|270138|00f977a8-58e4-4d2f-8e35-06cf86283208|0|
|first|CPU measured|270266|951e5db0-49f9-427b-ba01-349e5ef35245|0|
|first|GPIO|270394|53190e0382c542d4a02cf7eb0e18e741|0|
|fresh|CPU setup|270782|b43902f8-e3de-48d4-8bdc-a365e34c93b0|0|
|fresh|CPU measured|270910|78a5be65-e7b6-4cd0-aad6-a1956fb6a982|0|
|fresh|GPIO|271038|fb449ceebcc34342aea5833113ae3201|0|
|suppressed|CPU setup|271316|22dfdb60-e86d-4eee-a0cf-3045a72c3206|0|
|suppressed|CPU measured|271444|f8e3b5a6-c75b-427e-a075-7993822e13f3|0|
|suppressed|GPIO|271572|80347151b1e1481981ae6fa770a83154|0|

Every process closed=true/reaped0; fresh has distinctactual setup/measured/native/Runner/stream identities. First/fresh completeprefix equality compares actual CPU samples/commands/rawlines, targetphysicalsamples/transport, runtime/source/router/Runner events and lifecycle under declaredidentity normalization, preserving arbitrarypayload.

## Actual IRQ result / negative control

Positive actualGPIO rise produces fixedMEIP input64 CPUticks221..284. ROB actualcause0x800000000000000b at281post/282pre, CSRexception282post/283pre. RealGPIO statusclear sequence0,1,0 with actualsource/nativeA/D/targetrefs joins. Cause/MEPC RAMaccepted stores339/346; status/clear403/407; done412; qualifiedCSRcmd4/address0x302 MRET429; foregroundresumed acceptedstore475. FinalRAMcause0x800000000000000b/MEPC0x8000005c/status1/clear0/done1/resumed1. PhysicalforegroundPC afterreturn is observed. These are acceptedtransaction/passiveCSR observations, not retirementauthority.

Suppressed run retains actualGPIO sourceedge and requested64, delivers0 toCPU/nativeMEIP; noIRQtrap/qualifiedMRET/ISRresultstores/done/resumed, allresultRAMzero. This is a controlled environment delivery fault, not a DUTbug. Gate records suppressed_delivery_rejected=true. It is one suppression run, not an additional suppressedfresh-pair claim.

Allthree coherent reports structural_error=false/normalization_poisoned=false, closed/no pendingsinks/sources/uncertaintransactions. First/fresh162 runtime records (81raw accepted), suppressed770 runtime records (385raw accepted); no errorssilenced.

## Identity and limits

Actualready96f5e22f37ccc574f5b8ba55b46a132afb4d0f845949d394ff76fedce0d39685; sourcefreezeSHA d0eb71f1cfaa7a6db158f3c9211249c03e7703b89519a94db42cfd8317f0803e; originalartifactSHA3f405a57322a697f0dfee4004ef15e9c3c5c849bf1fc360b0dd0d087f2bbf89d; BOOMbinary6367b592b743f935cb2de04bc6dfc4ac54c9ec8cf5dce4eb6545b140971e6c90. Exact source/overlay/control pins, historical buildorigin/metadataorigin/tool receipts remain in archive. No BOOM C++ rebuild or metadata rewrite. Allbefore/after immutableinput/tool audits passed.

Summary statuspass/full_fresh_prefix_equal=true/suppressed_delivery_rejected=true. source_authority=false/isa_retirement_authority=false/new_cpp_build=false/full_P6=false. This closes this bounded realGPIO→MEIP→CPUtrap/ISR/MRET/foreground diagnostic gate; it does not grant fullP6, genericIRQcoverage or retirementauthority. Existing failedattempt2 remains failed/immutable.
