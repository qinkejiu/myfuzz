# OBI fail-stop Verilator variant: source/software increment

Root implementation; independent source review requested. The earlier remote Icarus skip remains unaccepted. New explicit selector:
`tests/protocols/test_obi_processor_memory_adapter_rtl.py::ObiProcessorMemoryAdapterRtlTests::test_backend_error_fail_stops_when_cpu_has_no_obi_error_channel_verilator`.

Both tools compile the identical original TB and adapter. Original frozen b370e3d stimulus SHA256 equals shared constant83b46a7a6fb8dacc15dfe19a8b04926215877ce867003944670648d11153dc39; independent identity receipt stored. Exact nonzero exit and adapter-specific fatal remain required, so the TB's final fallback fatal cannot pass. Verilator uses --binary/--timing/--assert, -j1; build180s/run20s bounded. Native build/result lines preserve actual command/sourcehash/return/stdout/stderr. Test uses a temporary working directory.

TDD evidence: initial RED4failed/3passed0.12s unintentionally collected the imported original unittest class; those three local existing Icarus tests actually executed and passed. This is not remote acceptance or a new Verilator run. Corrected module-alias collection then isolated4failed0.04s due missing new method. GREEN4passed0.03s; final6passed0.03s after additional same-stimulus/missing-tool controls, all subprocesses mocked. Tests assert failed compilation, nativezero and wrongfatal cannot pass. Raw logs stored separately; no history overwritten. New variant native has NOT run.

Source SHA pins and RED/GREEN/testbench identity are in .superpowers/obi-fail-stop-verilator/. Native execution requires a new identity/output, canonical lock and actual audit rejecting skip. No production Python/RTL changed by this increment.
