# Independent source review: standalone Verilator adapter native controls

Reviewed read-only, no tests/build/native/remote preparation executed by reviewer. Source controls under `.superpowers/obi-fail-stop-verilator/native-preparation/`: run.sh b75fbfa919ae5e0272f9a6e82e1085c2dcbfaa0b6074ebe8b53fc012e7dddd0f; verify.py068df8c8f217b7b8978e762ab58f277688b40d7ca9359b2981a1904acaa6de14; audit.py879c3c4bc2388c1cb5275cfe0691978907a219f95e97e36075bef6f0da53436e; manifest3da3b60b4fe01c411dafb77531dc125869dd8317e18b829415cfd6003419902f.

Two declared source bytes match current reviewed adapter/test. The selected test uses identical NO_ERROR_TESTBENCH as Icarus, explicit --timing/--assert Verilator command, compile-success requirement, actual completed native run returncode nonzero and actual fatal string. Build/result JSON preserve raw outputs and adapter/TB hashes; audit rejects skipped/zero/wrong-fatal evidence. Runner holds only canonical nonblocking lock, fixes TMPDIR under fanzehui, disables core dumps and retains actual pytest PID/exit/source/audit receipts. Source verifier rejects symlink components and hardlinks; selected test imports only Python stdlib besides pytest runner infrastructure. No native P7/F4 semantic claim follows this unit gate.

## Medium: isolate ambient pytest configuration for claimed two-file closure

The current exact selector/--rootdir do not disable conftest discovery, plugin autoload or PYTEST_ADDOPTS/PYTEST_PLUGINS. Those can load extra Python outside the two authenticated project files and can alter subprocess behavior/assertions. This is a source-closure gap for the explicit standalone two-file gate, not evidence that such a plugin is present. Read installed pytest source confirms initial _confcutdir defaultsNone and upward conftests are allowed. Recommended minimal control: export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1, unset PYTEST_ADDOPTS/PYTEST_PLUGINS and run `-c /dev/null --noconftest --rootdir "$base/project"` with the exact selector. Trusted pytest/toolchain remains an environment dependency; project extension discovery must be explicitly closed.

## Low: preflight failure exit receipt

verify failure currently exits74 before writing worker.exit. Save source-before.exit and worker.exit on this path so failure observation need not infer wrapper exit from PID disappearance. Existing failed-reuse marker remains preserved.

Other than the above closure control, no high/medium findings in actual native fatal/nonzero logic or source/TB identity. Final approval awaits minimal runner control re-freeze. Reviewer did not modify implementation.

## Final v2 re-review: findings resolved

Root provided minimal isolated runner: PYTEST_DISABLE_PLUGIN_AUTOLOAD=1, clears PYTEST_ADDOPTS/PYTEST_PLUGINS, explicit pinned minimal pytest.ini via -c, --noconftest plus fixed rootdir and exact selector. Manifest now authenticates two code files plus minimal config. This closes project/ancestor conftest and ambient pytest configuration/plugin discovery; trusted Python/pytest/compiler remain explicit host toolchain dependencies. Medium resolved.

Source-preflight failure now saves its actual verifier status to worker.exit before returning. Low resolved. Fatal/nonzero/TB hash/actual waited pytest exit/postsource/audit checks remain unchanged.

Final SHA256: run.sh **ba2b25b4694a7b522343d6430ba488b3f4a0fa69d281af84a98653c209df07b3**; verifier unchanged068df8...; audit unchanged879c3c...; source-manifest.json **7fc87a28bbd1e4264be7750627719651303e37e02934b54ecf42951eaf8566aa**; pytest.ini **8250d20f42b419af40706490ead78aabab9feba93eab09a3f626e3de5256e1f4**. Read-only comparison matches root freeze. No remaining high/medium blocker for this standalone adapter gate. Reviewer did not run native/build/tests or remotely prepare these controls; v2 native acceptance remains unrun and cannot be inferred from this source review.
