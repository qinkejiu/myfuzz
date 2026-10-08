#!/usr/bin/env python3
"""Prepared real-RTL gate: make part of the CPU-side branch quota observable.

The P4 instrumented-branch window ends with 0/64 CPU points lit in every one of
the 28 instrumented runs, while 18-50 of the 64 IP points light in the same
runs.  ``scripts/rtl_cpu_side_observation_diagnosis.py`` shows why: the whole
CPU quota is bound to ``u_cpu0/i_ibex_trvk`` (``if (BaseIsa ==
BaseIsaRV32IorCHERIoT)``, ``ibex_top.sv:1275``) and ``u_cpu0/u_ibex_lockstep``
(``if (Lockstep)`` with ``localparam Lockstep = SecureIbex`` = 0,
``ibex_top.sv:212``/``:873``), both generate branches the compiled model does not
elaborate, so their counters are structural zeros that no search can move.

This script is the *gate* for fixing that.  It never decides the fix is present
by trusting a flag: it re-derives the verdict from the run's own compiled model
and the shipped coverage counter path.

Modes
-----

``plan`` (default, read-only)
    Print the production change the fix needs, the exact commands to run, and
    the exact success/failure criteria.  With ``--reference-run`` it also runs
    the read-only verdict against a saved run so the gate reports whether it is
    currently BLOCKED or READY.

``verify --run <dir>`` (read-only)
    Run every criterion against one instrumented run and print PASS/FAIL per
    criterion.  This is the arm the root runs after the campaign.

``execute --campaign-command <shell> --output <dir>``
    Run the campaign (this DOES start Verilator and the RFuzz client) and then
    verify the produced run.  Refuses without ``--i-understand-this-runs-rtl``.

Exit codes
----------

``0``  PASS - every criterion held, at least one observed CPU point is lit.
``1``  FAIL - a criterion did not hold (the run is readable; the fix is not
       effective or the identity did not verify).
``3``  BLOCKED - the CPU quota is still bound to unelaborated instances.
``4``  INCONCLUSIVE - the run cannot answer the question (no compiled model, or
       the CPU never retired in it, so a zero proves nothing about the mapping).
``2``  usage error.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shlex
import subprocess
import sys


SCRIPT = Path(__file__).resolve()
ROOT = SCRIPT.parents[1]
SRC = ROOT / "src"
# The repository root is needed for ``scripts.*`` (the diagnosis module) and
# ``src`` for the myfuzz package, exactly as the neighbouring campaign CLIs set
# both up.
for entry in (SRC.as_posix(), ROOT.as_posix()):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from scripts.rtl_cpu_side_observation_diagnosis import (  # noqa: E402
    CLASS_LIT,
    CLASS_UNELABORATED,
    CLASS_UNKNOWN,
    CLASS_UNREADABLE,
    ArtifactUnavailable,
    diagnose_run,
    summarise,
)

REPORT_CLI = ROOT / "scripts" / "report_rtl_branch_coverage.py"
DIAGNOSIS_CLI = ROOT / "scripts" / "rtl_cpu_side_observation_diagnosis.py"

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_USAGE = 2
EXIT_BLOCKED = 3
EXIT_INCONCLUSIVE = 4

#: The production change this gate exists to verify.  It IS implemented now, and
#: stated with exact locations so a reviewer can check the claim against the
#: source instead of trusting a flag.
REMEDIATION = (
    "IMPLEMENTED. src/myfuzz/integration/soc_builder.py compiles the planned "
    "observation set first, then probes the produced Verilator model "
    "(build/obj_dir/*___024root.h) for every observed point's instance scope via "
    "the shared probe in src/myfuzz/elaboration_probe.py. Points bound to a "
    "scope the model does not contain are classified `unelaborated_scope` with a "
    "reason, points that cannot be probed at all are classified "
    "`elaboration_unknown`, both are dropped from the observed set, the same "
    "128-slot quota is re-planned without those instances (iterating against the "
    "same model, because which counters the harness reads does not change what "
    "the design elaborates), and the harness is rebuilt exactly once when the "
    "plan changed. The rebuild is re-probed and the build refuses "
    "(profile-coverage-elaboration-probe-failed / "
    "rebuild-still-binds-unelaborated-scope) rather than publish counters it "
    "cannot prove are armed. The exclusions, their classifications and reasons, "
    "and the probe record are written to build/soc_coverage_plan.json "
    "(`elaboration`) and to the build document (`observation_elaboration`). "
    "Nothing in the instrumented tree, the coverage port or the positional "
    "counter readback path changed. Background: the selector takes the CPU quota "
    "by ascending raw coverage-bit index while the instrumenter puts the first "
    "declared child at the most significant end, so the lowest CPU bits were the "
    "generate-disabled `i_ibex_trvk` (ibex_top.sv:1275) and `u_ibex_lockstep` "
    "(ibex_top.sv:873, Lockstep = SecureIbex = 0) subtrees."
)

DEFAULT_CAMPAIGN_COMMAND = (
    "MYFUZZ_SOC_REAL=1 PYTHONPATH=src:. python3 -m myfuzz compat soc run "
    "--matrix configs/soc/matrix.json --output runs/<new-run> "
    "--seconds 600 --seed 20260926 --client <kfuzz>"
)

CRITERIA = (
    ("run-artifact",
     "report.json parses and carries client_result with branch_coverage_ports"),
    ("coverage-identity",
     "scripts/report_rtl_branch_coverage.py --run <dir> exits 0 with "
     "status=verified and external_binding.passed=true"),
    ("cpu-stimulus (precondition)",
     "at least one RVFI opcode counter is non-zero, i.e. the CPU really "
     "retired instructions in this run"),
    ("elaboration-attested",
     "the saved plan records the build-time elaboration probe (status "
     "verified|replanned, every reported point classified elaborated, the "
     "recorded model digest equal to the model header on disk)"),
    ("exclusions-reported",
     "every point the probe refused to observe is reported with a "
     "classification and a reason, the excluded-instance candidate counts "
     "match the instrumentation manifest, and no such instance is still "
     "observed"),
    ("no-dead-counters",
     "zero observed points classified unelaborated-bound"),
    ("cpu-side-observable",
     "at least --min-cpu-points observed CPU points classified elaborated-lit"),
    ("readback-integrity",
     "zero probe-unreadable, zero elaboration-unknown, zero contradictions"),
)


def _load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _run_cli(argv: list[str]) -> tuple[int, str, str]:
    result = subprocess.run([sys.executable, *argv], capture_output=True, text=True,
                            cwd=ROOT.as_posix(), check=False)
    return result.returncode, result.stdout, result.stderr


def _coverage_identity(run: Path) -> tuple[bool, str]:
    code, out, err = _run_cli([REPORT_CLI.as_posix(), "--run", run.as_posix(),
                               "--json", "--quiet"])
    if code != 0:
        return False, f"report CLI exit {code}: {(err or out).strip()[:400]}"
    try:
        document = json.loads(out)
    except json.JSONDecodeError:
        return False, "report CLI did not emit JSON"
    status = document.get("status")
    binding = document.get("external_binding") or {}
    if status != "verified":
        reasons = [item.get("reason") for item in document.get("rejections", [])]
        return False, f"status={status} reasons={reasons[:4]}"
    if not binding.get("passed"):
        return False, f"external binding findings={binding.get('findings')}"
    observed = document.get("observed_branches") or {}
    return True, (f"verified branch_points={observed.get('observed_points')}"
                  f"/{observed.get('total_points')}")


def _cpu_stimulus(run: Path) -> tuple[bool, str]:
    report = _load_json(run / "report.json")
    client = report.get("client_result") if isinstance(report, dict) else None
    if not isinstance(client, dict):
        return False, "no client_result"
    provenance = client.get("artifact_provenance") or {}
    checker = provenance.get("checker_feedback") or {}
    window = checker.get("rvfi_opcode_coverage_counter_range")
    maxima = client.get("coverage_maxima")
    if not window or not isinstance(maxima, list) or len(maxima) <= int(window[1]):
        return False, "run declares no RVFI opcode counter window"
    values = [int(maxima[index]) for index in range(int(window[0]),
                                                    int(window[1]) + 1)]
    if not any(values):
        return False, ("no RVFI opcode bin lit: the CPU did not retire in this "
                       "run, so a zero CPU branch count is not evidence")
    return True, (f"RVFI opcode counters {window} maxima={values} "
                  f"(sum={sum(values)})")


def _diagnosis(run: Path) -> dict:
    return diagnose_run(run)


def _manifest_bits(run: Path) -> list[dict] | None:
    """The instrumenter's own per-bit map of the run, when it is saved."""
    path = (run / "build" / "instrumentation" / "instrumented"
            / "instrumentation.json")
    if not path.is_file():
        return None
    try:
        manifest = _load_json(path)
    except (OSError, json.JSONDecodeError):
        return None
    bits = manifest.get("coverage_bits") if isinstance(manifest, dict) else None
    return [entry for entry in bits if isinstance(entry, dict)] \
        if isinstance(bits, list) else None


def _elaboration_checks(run: Path, document: dict) -> tuple[bool, bool, str]:
    """Re-derive the two criteria that describe the run's own probe record.

    The gate never trusts the record: it re-reads the plan, the model header on
    disk and the instrumentation manifest, and requires them to agree with each
    other and with the saved record.
    """
    recorded = document.get("recorded_elaboration")
    if not isinstance(recorded, dict):
        return (False, False,
                "the saved plan records no elaboration probe: this run predates "
                "the build-side fix, so its observed set was never proven armed")
    counts = recorded.get("counts") if isinstance(recorded.get("counts"), dict) else {}
    observations = recorded.get("observations")
    excluded = recorded.get("excluded")
    excluded_instances = recorded.get("excluded_instances") \
        if isinstance(recorded.get("excluded_instances"), dict) else {}

    # --- elaboration-attested -------------------------------------------
    findings: list[str] = []
    status = recorded.get("status")
    if status not in ("verified", "replanned"):
        findings.append(f"status={status!r}")
    if not isinstance(observations, list) or not observations:
        findings.append("no per-point observation classification")
    elif any(str(row.get("classification")) != "elaborated" for row in observations):
        findings.append("an observed point is not classified elaborated")
    elif int(counts.get("observed_points", -1)) != len(observations):
        findings.append(
            f"observed_points={counts.get('observed_points')} but "
            f"{len(observations)} observations recorded")
    elif int(counts.get("elaborated", -1)) != len(observations):
        findings.append(
            f"elaborated={counts.get('elaborated')} but "
            f"{len(observations)} observations recorded")
    re_derived = document.get("compiled_model") or {}
    probed = recorded.get("model") if isinstance(recorded.get("model"), dict) else {}
    if not re_derived.get("present"):
        findings.append("the compiled model header is no longer readable")
    elif not probed.get("sha256"):
        findings.append("the record names no probed model digest")
    elif probed.get("sha256") != re_derived.get("sha256"):
        findings.append("the recorded model digest is not the model on disk")
    if document["counts"].get("points") != len(observations):
        findings.append(
            f"the run observed {document['counts'].get('points')} points but the "
            f"record attests {len(observations)}")
    attested = not findings
    attested_detail = (f"status={status} model={str(probed.get('sha256'))[:12]} "
                       f"observed={len(observations) if isinstance(observations, list) else '?'}"
                       if attested else "; ".join(findings))

    # --- exclusions-reported --------------------------------------------
    report_findings: list[str] = []
    if not isinstance(excluded, list):
        report_findings.append("no excluded list")
        excluded = []
    if int(counts.get("refused_planned_points", -1)) != len(excluded):
        report_findings.append(
            f"refused_planned_points={counts.get('refused_planned_points')} but "
            f"{len(excluded)} rows recorded")
    by_class: dict[str, int] = {}
    for row in excluded:
        classification = str(row.get("classification", ""))
        if classification not in ("unelaborated_scope", "elaboration_unknown"):
            if len(report_findings) < 8:
                report_findings.append(
                    f"unclassified exclusion at bit {row.get('bit')}")
            continue
        if not str(row.get("reason", "")).strip() and len(report_findings) < 8:
            report_findings.append(f"unreasoned exclusion at bit {row.get('bit')}")
        by_class[classification] = by_class.get(classification, 0) + 1
    if int(counts.get("unelaborated_scope", -1)) != by_class.get("unelaborated_scope", 0):
        report_findings.append("the unelaborated_scope count does not add up")
    if int(counts.get("elaboration_unknown", -1)) != by_class.get("elaboration_unknown", 0):
        report_findings.append("the elaboration_unknown count does not add up")
    if status == "verified" and excluded:
        report_findings.append("a verified plan must exclude nothing")
    bits = _manifest_bits(run)
    if bits is None:
        report_findings.append("the instrumentation manifest is not readable")
    else:
        per_instance: dict[str, int] = {}
        for entry in bits:
            instance = str(entry.get("instance_path", ""))
            per_instance[instance] = per_instance.get(instance, 0) + 1
        for instance, entry in excluded_instances.items():
            if int(entry.get("candidate_bits", -1)) != per_instance.get(instance, 0) \
                    and len(report_findings) < 8:
                report_findings.append(f"candidate count wrong for {instance}")
        if int(counts.get("excluded_candidate_bits", -1)) != sum(
                per_instance.get(instance, 0) for instance in excluded_instances):
            report_findings.append("excluded_candidate_bits does not match the manifest")
        still_observed = [row for row in (observations or [])
                          if str(row.get("instance_id", "")) in excluded_instances]
        if still_observed:
            report_findings.append("an excluded instance is still observed")
    reported = not report_findings
    reported_detail = (f"excluded={len(excluded)} "
                       f"instances={len(excluded_instances)} "
                       f"candidate_bits={counts.get('excluded_candidate_bits')}"
                       if reported else "; ".join(report_findings[:4]))
    return attested, reported, attested_detail + " | " + reported_detail


def _verdict(run: Path, minimum_cpu_points: int) -> tuple[int, list[dict], dict]:
    checks: list[dict] = []

    def add(name: str, ok: bool, detail: str) -> bool:
        checks.append({"criterion": name, "passed": bool(ok), "detail": detail})
        return ok

    if not (run / "report.json").is_file():
        add("run-artifact", False, f"missing {run / 'report.json'}")
        return EXIT_FAIL, checks, {}

    try:
        document = _diagnosis(run)
    except ArtifactUnavailable as error:
        add("run-artifact", False, str(error))
        return EXIT_FAIL, checks, {}
    counts = document["counts"]
    cpu = counts["by_category"].get(
        "cpu", {CLASS_LIT: 0, "points": 0})
    add("run-artifact", True,
        f"{counts['points']} observed points, cpu={cpu['points']}")

    ok, detail = _coverage_identity(run)
    add("coverage-identity", ok, detail)

    stimulus_ok, stimulus_detail = _cpu_stimulus(run)
    add("cpu-stimulus (precondition)", stimulus_ok, stimulus_detail)

    attested, reported, elaboration_detail = _elaboration_checks(run, document)
    add("elaboration-attested", attested, elaboration_detail)
    add("exclusions-reported", reported, elaboration_detail)

    dead = counts[CLASS_UNELABORATED]
    add("no-dead-counters", dead == 0,
        f"{CLASS_UNELABORATED}={dead} instances="
        f"{list(document['unelaborated_instances'])[:2]}")

    lit = cpu[CLASS_LIT]
    add("cpu-side-observable", lit >= minimum_cpu_points,
        f"cpu {CLASS_LIT}={lit} (minimum {minimum_cpu_points}) of "
        f"{cpu['points']}")

    integrity = (counts[CLASS_UNREADABLE] == 0 and counts[CLASS_UNKNOWN] == 0
                 and counts["contradictions"] == 0)
    add("readback-integrity", integrity,
        f"{CLASS_UNREADABLE}={counts[CLASS_UNREADABLE]} "
        f"{CLASS_UNKNOWN}={counts[CLASS_UNKNOWN]} "
        f"contradictions={counts['contradictions']}")

    if not document["compiled_model"]["present"] or not stimulus_ok:
        return EXIT_INCONCLUSIVE, checks, document
    if not all(check["passed"] for check in checks):
        if dead:
            return EXIT_BLOCKED, checks, document
        return EXIT_FAIL, checks, document
    return EXIT_PASS, checks, document


def _print_criteria() -> None:
    print("Success criteria (all must hold):")
    for name, detail in CRITERIA:
        print(f"  - {name}: {detail}")
    print("Failure: any criterion above does not hold, or the coverage identity "
          "is rejected.")
    print("Inconclusive (exit 4): the run has no compiled model, or the CPU "
          "never retired in it - a zero CPU count then proves nothing.")


def _print_plan(minimum_cpu_points: int, campaign_command: str) -> None:
    print("=== P4 CPU-side branch observation gate ===")
    print()
    print("Step 1 - the production change (implemented; review it, do not "
          "re-apply it):")
    print("  " + REMEDIATION)
    print()
    print("Step 2 - one CPU-executing instrumented cell (this DOES start "
          "Verilator and the RFuzz client; the build now compiles twice when "
          "the probe drops points, so allow more than the usual build time):")
    print("  " + campaign_command)
    print("  # reuse whatever command produced "
          "runs/ibex-pulp-gpio-spi-cpu-gpio-write-600s-160c-20260926;")
    print("  # mode must be cpu_only so the CPU actually retires.")
    print("  # if the build refuses with "
          "profile-coverage-elaboration-probe-failed, that is a FAILURE of the "
          "fix, not a retry: the probe could not prove the counters are armed.")
    print()
    print("Step 3 - verify (read-only, no RTL):")
    print(f"  PYTHONPATH=src python3 {DIAGNOSIS_CLI.as_posix()} \\")
    print("      --run <new-run>")
    print(f"  PYTHONPATH=src python3 {REPORT_CLI.as_posix()} --run <new-run>")
    print(f"  PYTHONPATH=src python3 {SCRIPT.as_posix()} verify --run <new-run> "
          f"--min-cpu-points {minimum_cpu_points}")
    print()
    print("Step 4 - read the fix's own record (read-only):")
    print("  PYTHONPATH=src python3 -c \"import json;"
          "d=json.load(open('<new-run>/build/soc_coverage_plan.json'));"
          "e=d['elaboration'];print(e['status'],e['counts'],"
          "[r['instance_id'] for r in e['excluded'][:3]])\"")
    print("  # status must be verified or replanned; every excluded row must "
          "carry a classification and a reason, and no excluded instance may "
          "appear in d['observed'].")
    print()
    _print_criteria()
    print()
    print("Failure modes, stated exactly:")
    print("  - build refuses with *-coverage-elaboration-probe-failed: the probe "
          "could not read the compiled model, nothing was published (the fix is "
          "fail-closed; treat as FAIL, not as 'no coverage').")
    print("  - verify exit 1 (FAIL): the run published a point the probe did not "
          "attest, or the coverage identity did not verify.")
    print("  - verify exit 3 (BLOCKED): the CPU quota is still bound to "
          "unelaborated instances.")
    print("  - verify exit 4 (INCONCLUSIVE): the CPU never retired, or the run "
          "has no compiled model; a zero CPU count then proves nothing.")


def _report_verdict(code: int, checks: list[dict], document: dict,
                    minimum_cpu_points: int) -> None:
    if document:
        print(summarise(document))
    for check in checks:
        print(f"  [{'PASS' if check['passed'] else 'FAIL'}] "
              f"{check['criterion']}: {check['detail']}")
    verdict = {EXIT_PASS: "PASS", EXIT_FAIL: "FAIL", EXIT_BLOCKED: "BLOCKED",
               EXIT_INCONCLUSIVE: "INCONCLUSIVE"}.get(code, str(code))
    print(f"verdict={verdict}")
    if code == EXIT_BLOCKED:
        print("  the observed set is still bound to instances the compiled model "
              "does not elaborate.  On a run produced after the fix that means "
              "the fix is not effective (see Step 1); on a run saved before it, "
              "the verdict is expected and only a new run can decide.")
    elif code == EXIT_INCONCLUSIVE:
        print("  rerun with mode=cpu_only (and enough seconds for the CPU to "
              "fetch and execute) so the CPU arm is decidable.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command")
    plan = commands.add_parser("plan", help="print the plan and criteria (read-only)")
    plan.add_argument("--reference-run", type=Path, default=None,
                      help="also run the read-only verdict against this saved run")
    plan.add_argument("--min-cpu-points", type=int, default=1)
    verify = commands.add_parser("verify", help="verify one saved run (read-only)")
    verify.add_argument("--run", type=Path, required=True)
    verify.add_argument("--min-cpu-points", type=int, default=1)
    execute = commands.add_parser("execute", help="run the campaign, then verify")
    execute.add_argument("--campaign-command", required=True,
                         help="shell command that produces --output")
    execute.add_argument("--output", type=Path, required=True)
    execute.add_argument("--min-cpu-points", type=int, default=1)
    execute.add_argument("--i-understand-this-runs-rtl", action="store_true")
    args = parser.parse_args(argv)
    if args.command in (None, "plan"):
        _print_plan(getattr(args, "min_cpu_points", 1), DEFAULT_CAMPAIGN_COMMAND)
        reference = getattr(args, "reference_run", None)
        if reference is None:
            print()
            print("no --reference-run given; the plan above was not evaluated "
                  "against a saved run")
            return EXIT_PASS
        code, checks, document = _verdict(reference, args.min_cpu_points)
        print()
        _report_verdict(code, checks, document, args.min_cpu_points)
        return code
    if args.command == "verify":
        code, checks, document = _verdict(args.run, args.min_cpu_points)
        _report_verdict(code, checks, document, args.min_cpu_points)
        return code
    if not args.i_understand_this_runs_rtl:
        print("execute refuses to start Verilator without "
              "--i-understand-this-runs-rtl", file=sys.stderr)
        return EXIT_USAGE
    if args.output.exists():
        print(f"output must be new: {args.output}", file=sys.stderr)
        return EXIT_USAGE
    command = shlex.split(args.campaign_command)
    if not command:
        print("empty campaign command", file=sys.stderr)
        return EXIT_USAGE
    print(f"running: {args.campaign_command}")
    result = subprocess.run(command, cwd=ROOT.as_posix(), check=False)
    if result.returncode != 0:
        print(f"campaign failed with exit {result.returncode}", file=sys.stderr)
        return EXIT_FAIL
    code, checks, document = _verdict(args.output, args.min_cpu_points)
    _report_verdict(code, checks, document, args.min_cpu_points)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
