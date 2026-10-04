# CVE2 RV32E profile-only OBI reuse

This acceptance uses the pinned CVE2 RTL with `RV32E=1` as a new parameter
configuration. It adds a component profile, a source-lock record and closure,
and an acceptance test. The local harness generator, OBI protocol template,
driver, and CPU session have no variant-specific changes.

The profile changes the elaboration parameter and CPU extension declaration;
all physical top ports still come from Verilator elaboration, and the existing
OBI field aliases drive the same template. The source lock keeps the changed
parameter and closure separate from the existing `RV32E=0` identity. The
recorded Verilator lint command for `RV32E=1` exits zero with 94 warnings and
the same 33-file authenticated closure. A replayed elaboration confirms that
the observed read set matches that closure.

`tests/local_harness/test_cve2_rv32e_profile_reuse.py` generates and builds
the harness, runs a real RV32E program through persistent RAM, checks a
write/read sequence and byte write outcome, saves evidence, then replays it
through fresh RTL processes. The focused test passed (1/1, 69 seconds on this
host). This proves that a parameter variant of the existing CPU can reuse the
OBI template with declarative profile/source facts.

It does **not** prove onboarding of a different CPU implementation. The
existing Ibex runtime already proves a second OBI implementation, but its
onboarding preceded this profile-only gate. Stage D's strongest claim still
needs an unintegrated, locally available CPU model whose interface fits an
existing protocol template, with no generator source change.
