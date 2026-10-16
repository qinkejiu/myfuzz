# CV32 declaration filelist source pin fix

Actual frozen boundary command failed before native startup: wrapper212039/Python212053, actual child exit1, KeyError source['files'] in compiled_execution_files._source_paths. Actual source before/after all37527file/symlink checks match and source-after.exit0; terminal canonical release probe exit0. No backend ERR/fatal/DUT pass evidence; original snapshot/output remains unchanged.

Root cause: outer file entry enumerated only explicit source.files although original CV32 legitimately declares source.filelist with pinned variable/include roots. This was independent of successful no-error ABI admission tests, which generated source artifacts through the existing frontend and did not traverse public file enumeration.

Fix reuses existing _source_locator + source_crawler._declared_files for exactly the production supported filelist grammar, without calling crawl/elaboration/compiler. The read callback pins top/nested filelists and expanded HDL. Declared include directories are enumerated and every member pinned; re-enumeration detects added headers, changed filelists/headers and symlink substitutions before startup or replay. Root escape and existing lexical symlink refusals remain mandatory. Existing synthetic source fixtures now declare revision/top_module to match the real schema rather than bypass source validation.

Boundary diagnostic source enumeration now occurs inside its failure-report guard. A source discovery failure records native_executed=false/error and preserves .incomplete; it never claims a startup trace or native failure. This is proven by a separate RED regression.

Software receipts in .superpowers/f4-filelist-fix/: initial filelist RED5fail (missingfiles), first GREEN36pass/1fail (lexical direct-source symlink error code ordering), corrected37pass, boundary-report RED1fail (no report before guard), final **39 passed0.51s trueexit0**. Tests mock subprocess.Popen to refuse all frontend/native launches; actual original CV32 declaration enumerates with that guard. No native simulation/build/elaboration/retry was run for this source fix. Verilator equivalent test is a separate increment and does not block this freeze.

Review files: src/myfuzz/integration/compiled_execution_files.py, scripts/check_compiled_obi_no_error_boundary.py, tests/integration/test_compiled_execution_files.py, tests/integration/test_compiled_filelist_sources.py. Source SHA manifest .superpowers/f4-filelist-fix/source-files.sha256.
