# CV32E40P OBI → PULP timer APB3 compiled F4 sibling

This sibling composition reuses the registered `TIMER0_CTRL` source contract and the APB3 full-word target template with the CV32E40P RV32I split-OBI profile. The CPU request and CLI must both name `configs/cpus/cv32e40p/component_profile.json`; its reset synchronizer uses an 8/8 tick window.

The executor is selected through `--executor compiled-f4-rfuzz`, with no `--runtime` family. This checks CPU-instance reuse of the existing compiled F4 route. The PULP timer storage source remains the sole generic APB storage contract in this slice; this configuration does not claim arbitrary APB3 register semantics or a second APB storage source.
