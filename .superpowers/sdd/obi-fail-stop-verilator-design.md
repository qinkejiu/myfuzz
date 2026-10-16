# Same-testbench OBI fail-stop tool variant

The remote Icarus gate skipped because iverilog/vvp are absent; its audit remains failed. The available Verilator can compile the exact same adapter RTL and timing testbench with --binary --timing --assert, one build worker. Keep two explicit test selectors so a fallback cannot disguise a skipped tool as success. Extract the existing stimulus into one shared constant without changing any byte; preserve both nonzero-exit and exact-fatal assertions. Log build argv/source digests and subprocess return/stdout/stderr in the native pytest output. Missing tool remains an explicit skip and must fail the independent native gate audit.

Software controls mock subprocesses, verify both tools receive identical original stimulus, compile failure/zero native exit/wrong fatal all refuse, and missing tool invokes no process. A separately frozen remote gate must actually compile/run before native acceptance. No DUT or production executor changes.
