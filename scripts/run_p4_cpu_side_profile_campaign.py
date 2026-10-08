#!/usr/bin/env python3
"""Drive ONE profile-path ibex campaign whose provenance declares the RVFI window.

Why this exists
---------------

``scripts/run_p4_cpu_side_branch_gate.py verify`` cannot decide the CPU-side
mapping question on the **legacy** single-cell campaign path.  That path renders
``build/soc_top.sv`` and exposes no ``rvfi_*`` port at all (measured: 0
occurrences), and its ``client_result.artifact_provenance`` document has no
``checker_feedback`` key, so the gate's ``cpu-stimulus`` precondition reads
"run declares no RVFI opcode counter window" and the whole verdict falls back to
INCONCLUSIVE even when every other criterion passes.

The **profile** path (any campaign config carrying ``composition_request``) is
different, and the difference is in the shipped builder, not in a flag.  All
citations below are ``src/myfuzz/integration/soc_builder.py`` unless stated
otherwise (line numbers as of the current working tree):

* ``_build_profile_campaign_artifact`` loads the shipped checker map
  ``configs/soc/checkers/ibex_pulp_gpio_spi.json`` when the composition request
  id is ``ibex-pulp-gpio-spi`` (the ``if plan.request_id == CHECKER_REQUEST_ID``
  branch);
* the ``opcode_coverage_ports`` block turns an **active property with
  ``bit == 16``** into all 12 bits of ``rvfi_opcode_coverage_o``, and refuses the
  build (``profile-rvfi-opcode-coverage-port-invalid``) if the rendered top does
  not declare that 12-bit output;
* the ``checker_feedback`` block publishes
  ``rvfi_opcode_coverage_counter_range`` =
  ``[len(branch_ports) + 100, len(branch_ports) + 100 + 12 - 1]``;
* the same document publishes
  ``coverage_ports = branch_ports + checker_ports + opcode_coverage_ports``, so
  the RVFI window is exactly the last 12 counters of ``coverage_maxima``, and
  ``branch_coverage_ports`` is the flat list the diagnosis CLI reads;
* ``build_soc_campaign_artifact`` branches on ``"composition_request" in
  config``; without that key nothing renders ``rvfi_opcode_coverage_o`` at all.

This driver therefore builds the *same ibex cell* through the profile path.  It
re-implements no campaign logic: it loads the shipped composition request with
the shipped loader, checks the RVFI prerequisite with the builder's own
rendering/parsing helpers, builds the campaign config, and calls the shipped
``run_soc_campaign`` with the shipped artifact rebuilder.

Fail closed
-----------

Before anything expensive happens, the driver proves in software that the
fixture really activates the RVFI property:

* the composition request id must be ``ibex-pulp-gpio-spi`` (otherwise the
  builder loads no checker profile and emits ``checker_feedback: null``);
* the loaded checker profile must contain an **active** property with
  ``bit == 16`` (otherwise ``opcode_coverage_ports`` stays empty and the window
  is published as ``null``);
* the rendered top must declare ``rvfi_opcode_coverage_o`` as a 12-bit output
  (otherwise the builder would refuse the build).

Any of these failing exits ``3`` with a named reason and starts no campaign.

Usage
-----

::

    MYFUZZ_SOC_REAL=1 PYTHONPATH=src:. python3 \\
        scripts/run_p4_cpu_side_profile_campaign.py \\
        --output runs/<new-run> --seconds 600 --seed 20260926 \\
        --client runs/rfuzz_client_bounded_build/target/debug/kfuzz

``--check-only`` prints the same machine-readable prediction without building
anything (no Verilator, no RFuzz client).

Exit codes: ``0`` the campaign ran (or ``--check-only`` passed), ``1`` the
campaign failed, ``2`` usage error, ``3`` the profile fixture cannot produce a
checker profile with bit 16.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from dataclasses import dataclass
import json
import os
from pathlib import Path
import sys


SCRIPT = Path(__file__).resolve()
ROOT = SCRIPT.parents[1]
SRC = ROOT / "src"
for entry in (SRC.as_posix(), ROOT.as_posix()):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from myfuzz.composition.soc_checker_profile import (  # noqa: E402
    MANIFEST_PATH as SHIPPED_CHECKER_MANIFEST,
    load_checker_profile,
)
from myfuzz.composition.soc_composition import (  # noqa: E402
    STIMULUS_ADDRESS_STRATEGY,
    build_composition,
)
from myfuzz.composition.soc_profile_renderer import render_composition  # noqa: E402
from myfuzz.integration.rfuzz_simulator import (  # noqa: E402
    checker_feedback_observations,
)
from myfuzz.integration.soc_builder import (  # noqa: E402
    COUNTER_LIMIT,
    _parse_ports,
    build_soc_campaign_artifact,
    load_profile_campaign_request,
)
from myfuzz.integration.soc_campaign import run_soc_campaign  # noqa: E402


SCHEMA = "p4_cpu_side_profile_campaign.v1"

#: The profile fixture that composes the real pinned Ibex OBI master with the
#: real pinned PULP GPIO/SPI targets.  Its ``request_id`` is the only one for
#: which the builder loads the shipped checker map.
COMPOSITION_REQUEST = "examples/soc_generation/request-ibex-pulp-gpio-spi.json"
COMPONENT_PROFILES = (
    "configs/cpus/ibex/component_profile.json",
    "configs/peripherals/pulp_gpio/component_profile.json",
    "configs/peripherals/pulp_spi/component_profile.json",
)
#: The shipped checker map, read from the same constant the builder imports.
CHECKER_MANIFEST = SHIPPED_CHECKER_MANIFEST
CHECKER_REQUEST_ID = "ibex-pulp-gpio-spi"

#: The property whose ``active`` status is what makes the builder bind the RVFI
#: opcode counters (the ``opcode_coverage_ports`` block in
#: ``_build_profile_campaign_artifact``), and the port it must find.
RVFI_PROPERTY_BIT = 16
OPCODE_COVERAGE_PORT = "rvfi_opcode_coverage_o"
OPCODE_COVERAGE_WIDTH = 12

#: The profile branch quota is the shipped ``COUNTER_LIMIT``; the selector
#: refills exactly this many points after the elaboration probe drops whole
#: instance subtrees (proved by the saved plan of
#: ``runs/p4-cpu-side-coverage-20261008-online``: 696 refused, 128 observed).
BRANCH_COUNTER_QUOTA = COUNTER_LIMIT
TOP_NAME = "myfuzz_soc_top.sv"

DRIVE_PROFILE = "cpu_execute"
MODE = "cpu_only"
CELL_ID = "ibex-pulp"

DEFAULT_SECONDS = 300
DEFAULT_SEED = 20260926
DEFAULT_CLIENT = "runs/rfuzz_client_bounded_build/target/debug/kfuzz"
#: Pinned to the only profile-path run in the workspace whose CPU really retired
#: instructions in the RFuzz search (12 bins declared, 5 lit, sum 20):
#: ``runs/ibex-pulp-gpio-spi-cpu-gpio-write-600s-160c-20260926``.
DEFAULT_SEED_CYCLES = 160
DEFAULT_INSTRUCTION_CANDIDATES = 5
PROVEN_PROFILE_RUN = "runs/ibex-pulp-gpio-spi-cpu-gpio-write-600s-160c-20260926"
RESET_CONTRACT = {"driver": True, "memory": True, "cpu": True,
                  "peripherals": True, "irq": True, "coverage": True}

MINIMUM_SECONDS = 300
EXIT_OK = 0
EXIT_CAMPAIGN_FAILED = 1
EXIT_USAGE = 2
EXIT_PROFILE_FIXTURE = 3

GATE_CLI = ROOT / "scripts" / "run_p4_cpu_side_branch_gate.py"


class ProfileFixtureError(RuntimeError):
    """The profile fixture cannot declare the RVFI opcode counter window."""


@dataclass(frozen=True)
class ProfileFixture:
    config: dict
    request: object
    plan: object
    checker_manifest: dict
    checker_profile: object
    external_input_defaults: dict
    opcode_coverage: dict


def fixture_config(*, root: Path = ROOT) -> dict:
    """The minimal profile config the shipped request loader needs."""
    return {
        "root": str(root),
        "composition_request": COMPOSITION_REQUEST,
        "component_profiles": list(COMPONENT_PROFILES),
        "drive_profile": DRIVE_PROFILE,
        "mode": MODE,
    }


def _external_input_defaults(plan) -> dict:
    """Exactly the ports the builder will demand defaults for.

    The builder requires ``set(external_input_defaults)`` to equal the rendered
    top's undriven input set, so the driver derives them from the plan's own
    dispositions instead of guessing.
    """
    defaults: dict[str, int] = {}
    for instance in plan.instances:
        for entry in instance.dispositions:
            if entry.disposition == "external" and entry.direction == "input":
                suffix = "" if (entry.bit_lo, entry.bit_hi) == (0, entry.width - 1) \
                    else f"_{entry.bit_hi}_{entry.bit_lo}"
                defaults[f"{instance.instance_id}__{entry.port}{suffix}"] = 0
    return defaults


def _opcode_coverage_facts(request, plan, checker_profile, ports) -> dict:
    """Re-derive the builder's ``opcode_coverage_ports`` condition, in order."""
    bit16 = [item for item in checker_profile.properties
             if item.status == "active" and item.bit == RVFI_PROPERTY_BIT]
    if not bit16:
        raise ProfileFixtureError(
            "profile-checker-bit16-inactive: %s declares no active property with "
            "bit %d, so the builder's opcode_coverage_ports block would leave it empty "
            "and checker_feedback.rvfi_opcode_coverage_counter_range would be "
            "published as null"
            % (CHECKER_MANIFEST, RVFI_PROPERTY_BIT))
    port = next((item for item in ports
                 if item.get("name") == OPCODE_COVERAGE_PORT), None)
    if (port is None or port.get("direction") != "output"
            or port.get("width") != OPCODE_COVERAGE_WIDTH):
        raise ProfileFixtureError(
            "profile-rvfi-opcode-coverage-port-invalid: %s does not declare "
            "`output logic [%d:0] %s` (found %r); the builder would refuse this "
            "build (profile-rvfi-opcode-coverage-port-invalid)"
            % (TOP_NAME, OPCODE_COVERAGE_WIDTH - 1, OPCODE_COVERAGE_PORT, port))
    try:
        checker_ports = checker_feedback_observations(ports)
    except ValueError as error:
        raise ProfileFixtureError(
            "profile-checker-feedback-bus-invalid: %s" % error) from error
    return {
        "property_bit": int(bit16[0].bit),
        "property_id": str(bit16[0].property_id),
        "property_owner": bit16[0].owner,
        "property_binding": bit16[0].binding,
        "port": {"name": str(port["name"]), "direction": str(port["direction"]),
                 "width": int(port["width"])},
        "checker_ports": tuple((str(name), int(bit)) for name, bit in checker_ports),
        "request_id": str(request.request_id),
        "plan_hash": str(getattr(plan, "plan_hash", "")),
    }


def load_profile_fixture(*, root: Path = ROOT, checker_manifest: str | None = None,
                         config: Mapping[str, object] | None = None) -> ProfileFixture:
    """Load and check the shipped profile fixture (pure software, no RTL).

    Raises :class:`ProfileFixtureError` when the fixture cannot make the builder
    emit a non-null ``rvfi_opcode_coverage_counter_range``.
    """
    manifest_reference = CHECKER_MANIFEST if checker_manifest is None else checker_manifest
    root = Path(root).resolve()
    config = dict(fixture_config(root=root) if config is None else config)
    request = load_profile_campaign_request(config, root)
    if request.request_id != CHECKER_REQUEST_ID:
        raise ProfileFixtureError(
            "profile-checker-request-mismatch: %s declares request_id %r but the "
            "builder only loads the checker map for %r; no "
            "checker_feedback would be published"
            % (COMPOSITION_REQUEST, request.request_id, CHECKER_REQUEST_ID))
    plan = build_composition(request, base_dir=root, drive_profile=DRIVE_PROFILE,
                             address_strategy=STIMULUS_ADDRESS_STRATEGY)
    manifest_path = Path(manifest_reference)
    manifest_path = manifest_path if manifest_path.is_absolute() else root / manifest_path
    if not manifest_path.is_file():
        raise ProfileFixtureError(
            "profile-checker-manifest-missing: %s" % manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    checker_profile = load_checker_profile(manifest, plan)
    rendered = render_composition(plan, checker_profile=checker_profile)
    # The builder needs the legacy parameter document to parse symbolic widths
    # (the builder writes it before parsing the same way); the generated profile
    # header itself is numeric.
    rendered["soc_parameters.json"] = json.dumps(
        plan.plan["fabric"]["rtl"]["parameters"])
    ports = _parse_ports(rendered[TOP_NAME], rendered, request.request_id)
    opcode = _opcode_coverage_facts(request, plan, checker_profile, ports)
    return ProfileFixture(config=config, request=request, plan=plan,
                          checker_manifest=manifest,
                          checker_profile=checker_profile,
                          external_input_defaults=_external_input_defaults(plan),
                          opcode_coverage=opcode)


def gate_provenance_expectation(fixture: ProfileFixture) -> dict:
    """The exact provenance the gate's ``cpu-stimulus`` precondition will read.

    ``scripts/run_p4_cpu_side_branch_gate.py:_cpu_stimulus`` touches exactly four
    places in ``report.json``; they are named here so a reviewer can diff the
    prediction against the produced run instead of trusting a summary.
    """
    checker_count = len(fixture.opcode_coverage["checker_ports"])
    low = BRANCH_COUNTER_QUOTA + checker_count
    high = low + OPCODE_COVERAGE_WIDTH - 1
    return {
        "keys": [
            "client_result.artifact_provenance.checker_feedback."
            "rvfi_opcode_coverage_counter_range",
            "client_result.coverage_maxima",
            "client_result.artifact_provenance.coverage_ports",
            "client_result.artifact_provenance.branch_coverage_ports",
        ],
        "request_id": fixture.opcode_coverage["request_id"],
        "checker_profile_hash": fixture.checker_profile.profile_hash,
        "checker_property_bit": fixture.opcode_coverage["property_bit"],
        "checker_property_id": fixture.opcode_coverage["property_id"],
        "opcode_coverage_port": fixture.opcode_coverage["port"],
        "branch_counter_quota": BRANCH_COUNTER_QUOTA,
        "checker_counter_count": checker_count,
        "opcode_counter_count": OPCODE_COVERAGE_WIDTH,
        "coverage_counter_count": BRANCH_COUNTER_QUOTA + checker_count + OPCODE_COVERAGE_WIDTH,
        "rvfi_opcode_coverage_counter_range": [low, high],
        "coverage_maxima_length": BRANCH_COUNTER_QUOTA + checker_count + OPCODE_COVERAGE_WIDTH,
    }


def base_config(*, fixture: ProfileFixture, output: Path, seconds: int, seed: int,
                client: str, root: Path = ROOT, seed_cycles: int = DEFAULT_SEED_CYCLES,
                instruction_candidates: int = DEFAULT_INSTRUCTION_CANDIDATES) -> dict:
    """The campaign config handed to the shipped ``run_soc_campaign``.

    ``composition_request`` is what selects the profile build path
    (``build_soc_campaign_artifact``) and therefore the checker profile and the RVFI
    opcode counters.  ``instruction_candidates > 1`` makes the builder generate
    the declared candidate program and its boot image, exactly as the proven
    profile run ``%s`` did, so no external boot image is needed.
    """ % PROVEN_PROFILE_RUN
    return {
        "root": str(Path(root).resolve()),
        "config_id": "ibex-pulp-profile-rvfi-%ds-%dc-%d"
                      % (seconds, seed_cycles, seed),
        "cell_id": CELL_ID,
        "composition_request": str(fixture.config["composition_request"]),
        "component_profiles": list(fixture.config["component_profiles"]),
        "drive_profile": DRIVE_PROFILE,
        "mode": MODE,
        "seed": seed,
        "duration_seconds": seconds,
        "seed_cycles": seed_cycles,
        "instruction_candidates": instruction_candidates,
        "external_input_defaults": dict(fixture.external_input_defaults),
        "client_binary": client,
        "verilator": "bundled",
        "simulator": "verilator",
        "reset_contract": dict(RESET_CONTRACT),
    }


def _identity_document(*, fixture: ProfileFixture, config: dict, output: Path,
                       client: str, expectation: dict) -> dict:
    return {
        "schema_version": SCHEMA,
        "plan_hash": fixture.opcode_coverage["plan_hash"],
        "output": str(output),
        "cell_id": CELL_ID,
        "config_id": config["config_id"],
        "request_id": expectation["request_id"],
        "composition_request": config["composition_request"],
        "component_profiles": list(config["component_profiles"]),
        "drive_profile": DRIVE_PROFILE,
        "mode": MODE,
        "seed": config["seed"],
        "duration_seconds": config["duration_seconds"],
        "seed_cycles": config["seed_cycles"],
        "instruction_candidates": config["instruction_candidates"],
        "client": client,
        "external_input_defaults": dict(config["external_input_defaults"]),
        "checker_profile_hash": expectation["checker_profile_hash"],
        "checker_property_bit": expectation["checker_property_bit"],
        "checker_property_id": expectation["checker_property_id"],
        "opcode_coverage_port": expectation["opcode_coverage_port"],
        "rvfi_opcode_coverage_counter_range":
            expectation["rvfi_opcode_coverage_counter_range"],
        "coverage_counter_count": expectation["coverage_counter_count"],
        "gate_provenance_keys": list(expectation["keys"]),
        "proven_profile_run": PROVEN_PROFILE_RUN,
        "gate_cli": str(GATE_CLI),
    }


def _rvfi_precondition(output: Path) -> dict:
    """Read the produced run's own precondition verdict (read-only)."""
    if not (output / "report.json").is_file():
        return {"status": "run-artifact-missing"}
    from scripts.run_p4_cpu_side_branch_gate import _cpu_stimulus

    try:
        passed, detail = _cpu_stimulus(output)
    except (OSError, ValueError, KeyError, TypeError) as error:
        return {"status": "unreadable", "error": str(error)[:400]}
    return {"status": "passed" if passed else "failed", "detail": detail}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", type=Path, required=True,
                        help="new output directory for the campaign run")
    parser.add_argument("--seconds", type=int, default=DEFAULT_SECONDS)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--client", default=DEFAULT_CLIENT)
    parser.add_argument("--seed-cycles", type=int, default=DEFAULT_SEED_CYCLES,
                        help="cycles per fuzz test; 160 is the proven "
                             "CPU-retiring value (default %(default)s)")
    parser.add_argument("--instruction-candidates", type=int,
                        default=DEFAULT_INSTRUCTION_CANDIDATES,
                        help="declared instruction slots of the generated "
                             "candidate program (default %(default)s)")
    parser.add_argument("--check-only", action="store_true",
                        help="prove the RVFI precondition in software and exit "
                             "without building anything")
    args = parser.parse_args(argv)

    output = args.output if args.output.is_absolute() else ROOT / args.output
    if output.exists() or output.is_symlink():
        print(f"output must be new: {output}", file=sys.stderr)
        return EXIT_USAGE
    if args.seconds < MINIMUM_SECONDS:
        print(f"a real profile campaign needs at least {MINIMUM_SECONDS} "
              f"seconds for the CPU to fetch and execute", file=sys.stderr)
        return EXIT_USAGE
    if args.seed < 0:
        print("--seed must be a nonnegative integer", file=sys.stderr)
        return EXIT_USAGE
    if not 1 <= args.seed_cycles <= 200:
        print("--seed-cycles must be within 1..200 (the client's own bound)",
              file=sys.stderr)
        return EXIT_USAGE
    if args.instruction_candidates < 1:
        print("--instruction-candidates must be at least 1", file=sys.stderr)
        return EXIT_USAGE

    try:
        fixture = load_profile_fixture()
    except ProfileFixtureError as error:
        print(str(error), file=sys.stderr)
        return EXIT_PROFILE_FIXTURE
    expectation = gate_provenance_expectation(fixture)

    if args.check_only:
        print(json.dumps({"schema_version": SCHEMA, "mode": "check-only",
                          "composition_request": COMPOSITION_REQUEST,
                          "proven_profile_run": PROVEN_PROFILE_RUN,
                          **expectation}, sort_keys=True, ensure_ascii=False))
        return EXIT_OK

    client = args.client if Path(args.client).is_absolute() else str(ROOT / args.client)
    config = base_config(fixture=fixture, output=output, seconds=args.seconds,
                         seed=args.seed, client=client,
                         seed_cycles=args.seed_cycles,
                         instruction_candidates=args.instruction_candidates)
    # ``run_soc_campaign`` requires a not-yet-existing output directory and
    # creates it itself, so the audit copy of the task identity lands beside it.
    output.parent.mkdir(parents=True, exist_ok=True)
    identity = _identity_document(fixture=fixture, config=config, output=output,
                                  client=client, expectation=expectation)
    (output.parent / f"{output.name}.task.json").write_text(
        json.dumps(identity, indent=1, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8")

    result = run_soc_campaign(config, output, root=ROOT, environment=os.environ,
                              preflight_only=False,
                              rebuilder=build_soc_campaign_artifact)
    summary = {key: result.get(key) for key in
               ("status", "final_status", "effective_fuzz_seconds",
                "requested_duration_seconds", "replay", "errors",
                "evidence_missing")}
    summary.update({
        "schema_version": SCHEMA,
        "mode": "campaign",
        "output": str(output),
        "request_id": expectation["request_id"],
        "checker_property_bit": expectation["checker_property_bit"],
        "rvfi_opcode_coverage_counter_range":
            expectation["rvfi_opcode_coverage_counter_range"],
        "expected_coverage_counter_count": expectation["coverage_counter_count"],
        "rvfi_precondition": _rvfi_precondition(output),
        "verify_command": "PYTHONPATH=src python3 %s verify --run %s "
                          "--min-cpu-points 1" % (GATE_CLI, output),
    })
    print(json.dumps(summary, sort_keys=True, default=str)[:4000])
    return EXIT_OK if result.get("status") in (
        "completed", "completed_with_client_termination") else EXIT_CAMPAIGN_FAILED


if __name__ == "__main__":
    raise SystemExit(main())
