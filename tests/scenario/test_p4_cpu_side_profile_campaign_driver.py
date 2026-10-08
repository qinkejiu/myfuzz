"""The P4 CPU-side gate needs a run whose provenance declares the RVFI window.

The shipped gate ``scripts/run_p4_cpu_side_branch_gate.py`` cannot decide the
CPU-side mapping question on the legacy single-cell campaign path, because that
path renders ``soc_top.sv`` with no ``rvfi_*`` port at all (measured: 0
occurrences) and publishes an ``artifact_provenance`` document with no
``checker_feedback`` key, so its ``cpu-stimulus`` precondition reads "run
declares no RVFI opcode counter window".

``scripts/run_p4_cpu_side_profile_campaign.py`` drives the *profile* path for the
same ibex cell instead, where ``src/myfuzz/integration/soc_builder.py`` renders
``rvfi_opcode_coverage_o`` (12 bits) whenever the checker profile declares an
active property with ``bit == 16`` and emits
``checker_feedback.rvfi_opcode_coverage_counter_range``.

These tests are software-only: no Verilator, no RFuzz client, no campaign is
started.  They pin three separate things:

1. the fixture really produces a checker profile with an active bit-16 property
   and a rendered 12-bit RVFI opcode output port, i.e. the builder's own
   condition at ``soc_builder.py:1576`` will hold (``opcode_coverage_ports``
   non-empty) and ``checker_feedback`` will be non-null;
2. the driver fails closed - with a distinct exit code and before any campaign
   is started - when that condition cannot be met;
3. the exact provenance key path the gate consumes is the one a *saved*
   profile-path run really carries, and the window arithmetic the driver
   predicts is the window that run really published.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

from scripts.run_p4_cpu_side_branch_gate import _cpu_stimulus  # noqa: E402
from scripts import run_p4_cpu_side_profile_campaign as driver  # noqa: E402
from myfuzz.composition.soc_checker_profile import MANIFEST_PATH  # noqa: E402
from myfuzz.integration.soc_campaign import _normalise_config  # noqa: E402

#: The pre-fix profile-path run whose CPU really retires: it publishes the RVFI
#: window and lit opcode bins, and its checker profile hash is the one the
#: current shipped manifest still produces.
RETIRING_PROFILE_RUN = ROOT / driver.PROVEN_PROFILE_RUN
#: Every saved profile-path run that declares the window publishes the same one,
#: whatever its duration or seed-cycle count: the window is a pure function of
#: the branch quota and the checker bus width.
OTHER_RETIRING_PROFILE_RUNS = (
    "runs/ibex-pulp-gpio-spi-cpu-600s-20260926",
    "runs/ibex-pulp-gpio-spi-cpu-spi-tx-seed-smoke-200c-20260926",
    "runs/ibex-pulp-gpio-spi-cpu-retry4",
)
#: The post-fix legacy run: its saved plan proves the observation selector
#: refills the same 128-slot quota after the probe dropped 696 points.
POST_FIX_LEGACY_RUN = ROOT / "runs" / "p4-cpu-side-coverage-20261008-online"

#: The one provenance path the gate's ``_cpu_stimulus`` precondition reads.
RVFI_WINDOW_PATH = ("artifact_provenance", "checker_feedback",
                    "rvfi_opcode_coverage_counter_range")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _dig(document: object, path: tuple[str, ...]) -> object:
    current = document
    for key in path:
        assert isinstance(current, dict), f"{path}: {key} missing"
        assert key in current, f"{path}: {key} missing"
        current = current[key]
    return current


def _require_profile_run() -> Path:
    if not (RETIRING_PROFILE_RUN / "report.json").is_file():
        pytest.skip(f"saved profile run absent: {RETIRING_PROFILE_RUN}")
    return RETIRING_PROFILE_RUN


@pytest.fixture(scope="module")
def fixture():
    return driver.load_profile_fixture()


# ---------------------------------------------------------------------------
# 1. the fixture really satisfies the builder's bit-16 condition
# ---------------------------------------------------------------------------

def test_driver_pins_the_shipped_ibex_profile_fixture() -> None:
    assert driver.COMPOSITION_REQUEST == \
        "examples/soc_generation/request-ibex-pulp-gpio-spi.json"
    assert driver.CHECKER_MANIFEST == MANIFEST_PATH
    assert driver.CHECKER_REQUEST_ID == "ibex-pulp-gpio-spi"
    assert driver.RVFI_PROPERTY_BIT == 16
    assert driver.OPCODE_COVERAGE_PORT == "rvfi_opcode_coverage_o"
    assert driver.OPCODE_COVERAGE_WIDTH == 12
    # Starting from the legacy path is what made the gate undecidable; the
    # driver must never fall back to it.
    assert "composition_request" in driver.fixture_config()


def test_fixture_request_id_selects_the_shipped_checker_profile(fixture) -> None:
    assert fixture.request.request_id == driver.CHECKER_REQUEST_ID
    assert [item.instance_id for item in fixture.plan.instances] == \
        ["cpu0", "gpio0", "spi0"]
    assert fixture.checker_profile.request_id == driver.CHECKER_REQUEST_ID


def test_shipped_checker_profile_activates_property_bit_16(fixture) -> None:
    active = [item for item in fixture.checker_profile.properties
              if item.status == "active" and item.bit == driver.RVFI_PROPERTY_BIT]
    assert len(active) == 1
    assert active[0].property_id == "RVFI.ORDER"
    assert active[0].owner == "cpu0"


def test_fixture_renders_a_twelve_bit_rvfi_opcode_coverage_output(fixture) -> None:
    """The renderer's port must match the builder's 12-bit output check."""
    port = fixture.opcode_coverage["port"]
    assert port == {"name": "rvfi_opcode_coverage_o", "direction": "output",
                    "width": 12}
    assert fixture.opcode_coverage["property_bit"] == 16
    assert fixture.opcode_coverage["property_id"] == "RVFI.ORDER"


def test_gate_precondition_key_path_and_window_arithmetic(fixture) -> None:
    """Pin the keys the gate reads and the window the builder will publish.

    ``soc_builder.py:2030`` builds the window as
    ``[len(branch_ports) + 100, len(branch_ports) + 100 + 12 - 1]`` and
    ``soc_builder.py:2075`` makes the published vector
    ``branch_ports + checker_ports + opcode_coverage_ports``, so the window is
    always the last 12 slots of that vector.  The profile branch quota is the
    shipped ``COUNTER_LIMIT`` (128).
    """
    expectation = driver.gate_provenance_expectation(fixture)
    assert expectation["rvfi_opcode_coverage_counter_range"] == [228, 239]
    assert expectation["branch_counter_quota"] == 128
    assert expectation["checker_counter_count"] == 100
    assert expectation["opcode_counter_count"] == 12
    assert expectation["coverage_counter_count"] == 240
    assert expectation["keys"] == [
        "client_result.artifact_provenance.checker_feedback."
        "rvfi_opcode_coverage_counter_range",
        "client_result.coverage_maxima",
        "client_result.artifact_provenance.coverage_ports",
        "client_result.artifact_provenance.branch_coverage_ports",
    ]


def test_external_input_defaults_match_the_shipped_profile_campaign_shape(fixture) -> None:
    # The builder requires ``set(external_input_defaults)`` to equal its own
    # computed required-input set exactly, so the driver must derive them from
    # the plan's dispositions rather than guess.
    assert fixture.external_input_defaults == {"gpio0__gpio_in": 0}


# ---------------------------------------------------------------------------
# 2. the exact provenance keys, pinned against a saved profile-path run
# ---------------------------------------------------------------------------

def test_saved_profile_run_carries_every_key_the_gate_reads() -> None:
    run = _require_profile_run()
    report = json.loads((run / "report.json").read_text(encoding="utf-8"))
    client = report["client_result"]
    window = _dig(client, RVFI_WINDOW_PATH)
    maxima = client["coverage_maxima"]
    provenance = client["artifact_provenance"]

    assert isinstance(window, list) and len(window) == 2
    assert [int(value) for value in window] == [228, 239]
    assert len(maxima) == 240 == len(provenance["coverage_ports"])
    assert len(provenance["branch_coverage_ports"]) == 128
    assert provenance["coverage_ports"][-12:] == [
        ["rvfi_opcode_coverage_o", bit] for bit in range(12)]
    assert provenance["ibex_instruction_coverage"]["bins"][0] == "LUI"
    assert provenance["checker_feedback"]["properties"][16]["property_id"] == \
        "RVFI.ORDER"
    assert provenance["checker_feedback"]["properties"][16]["status"] == "active"
    # The gate indexes ``coverage_maxima`` with the declared window, so the
    # window must stay inside the vector the run actually published.
    assert len(maxima) > int(window[1])


def test_gate_cpu_stimulus_precondition_passes_on_the_saved_profile_run() -> None:
    """Re-derive the precondition with the shipped gate itself, read-only."""
    run = _require_profile_run()
    ok, detail = _cpu_stimulus(run)
    assert ok is True, detail
    assert "RVFI opcode counters [228, 239]" in detail
    assert "sum=20" in detail


def test_saved_profile_run_checker_hash_is_reproducible_from_the_shipped_manifest(fixture) -> None:
    """The fixture must be the same configuration the proven run used."""
    run = _require_profile_run()
    report = json.loads((run / "report.json").read_text(encoding="utf-8"))
    provenance = report["client_result"]["artifact_provenance"]
    assert provenance["checker_profile_hash"] == fixture.checker_profile.profile_hash
    assert provenance["checker_feedback"]["profile_hash"] == \
        fixture.checker_profile.profile_hash


def test_the_window_is_stable_across_other_saved_profile_runs(fixture) -> None:
    """Different durations and seed-cycle counts, one and the same window.

    The window is ``[COUNTER_LIMIT + 2*50, +11]`` for every profile-path run, so
    the driver's prediction does not depend on the search length.
    """
    predicted = driver.gate_provenance_expectation(
        fixture)["rvfi_opcode_coverage_counter_range"]
    seen = 0
    for relative in OTHER_RETIRING_PROFILE_RUNS:
        report_path = ROOT / relative / "report.json"
        if not report_path.is_file():
            continue
        client = json.loads(report_path.read_text(encoding="utf-8"))["client_result"]
        window = _dig(client, RVFI_WINDOW_PATH)
        assert [int(value) for value in window] == predicted == [228, 239], relative
        maxima = client["coverage_maxima"]
        assert len(maxima) == len(client["artifact_provenance"]["coverage_ports"]), relative
        assert any(int(value) for value in maxima[int(window[0]):int(window[1]) + 1]), relative
        seen += 1
    assert seen >= 2, "expected at least two other saved profile runs"


def test_post_fix_legacy_plan_proves_the_quota_is_refilled_after_exclusion() -> None:
    """The driver's 128-slot prediction must hold after the elaboration probe.

    The probe drops whole instance subtrees; the selector then refills the same
    128-slot quota from the eligible candidates.  The saved post-fix legacy plan
    is the evidence: 696 refused points, still 128 observed.
    """
    plan_path = POST_FIX_LEGACY_RUN / "build" / "soc_coverage_plan.json"
    if not plan_path.is_file():
        pytest.skip(f"saved plan absent: {plan_path}")
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    assert plan["limit"] == 128
    assert len(plan["observed"]) == 128
    assert plan["elaboration"]["counts"]["refused_planned_points"] == 696
    assert plan["elaboration"]["status"] in ("verified", "replanned")


# ---------------------------------------------------------------------------
# 3. the campaign config the driver hands to the shipped runner
# ---------------------------------------------------------------------------

def test_campaign_config_enters_the_profile_branch_and_normalises(tmp_path, fixture) -> None:
    config = driver.base_config(
        fixture=fixture, output=tmp_path / "run", seconds=300, seed=7,
        client="/nonexistent/kfuzz", root=ROOT)
    # The builder branches on this exact key (``soc_builder.py:2108``); without
    # it nothing renders ``rvfi_opcode_coverage_o``.
    assert "composition_request" in config
    assert config["component_profiles"] == list(driver.COMPONENT_PROFILES)
    normal = _normalise_config(config)
    assert normal["cpu"] == "cpu0"
    assert normal["peripherals"] == ["gpio0", "spi0"]
    assert normal["mode"] == "cpu_only"
    assert normal["peer_spacing_policy"] == "drop_later"
    assert normal["duration_seconds"] == 300.0


def test_campaign_config_declares_rvfi_prerequisites(tmp_path, fixture) -> None:
    config = driver.base_config(
        fixture=fixture, output=tmp_path / "run", seconds=300, seed=7,
        client="/nonexistent/kfuzz", root=ROOT)
    assert config["instruction_candidates"] == driver.DEFAULT_INSTRUCTION_CANDIDATES > 1
    assert config["seed_cycles"] == driver.DEFAULT_SEED_CYCLES
    assert config["external_input_defaults"] == fixture.external_input_defaults
    assert config["reset_contract"] == {
        "driver": True, "memory": True, "cpu": True,
        "peripherals": True, "irq": True, "coverage": True}
    assert config["verilator"] == "bundled"
    assert config["drive_profile"] == driver.DRIVE_PROFILE


# ---------------------------------------------------------------------------
# 4. argument handling and the fail-closed path
# ---------------------------------------------------------------------------

def test_cli_requires_output() -> None:
    with pytest.raises(SystemExit) as raised:
        driver.main([])
    assert raised.value.code == 2


def test_cli_refuses_an_existing_output(tmp_path, capsys) -> None:
    output = tmp_path / "already-there"
    output.mkdir()
    assert driver.main(["--output", str(output)]) == driver.EXIT_USAGE
    assert "output must be new" in capsys.readouterr().err


def test_cli_refuses_a_short_duration(tmp_path, capsys) -> None:
    assert driver.main(["--output", str(tmp_path / "run"), "--seconds", "60"]) == \
        driver.EXIT_USAGE
    assert "300" in capsys.readouterr().err


def test_cli_check_only_is_software_only_and_prints_the_prediction(
        tmp_path, capsys, monkeypatch) -> None:
    def _forbidden(*args, **kwargs):
        raise AssertionError("--check-only must not start a campaign")

    monkeypatch.setattr(driver, "run_soc_campaign", _forbidden)
    code = driver.main(["--output", str(tmp_path / "run"), "--check-only"])
    assert code == driver.EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == driver.SCHEMA
    assert payload["mode"] == "check-only"
    assert payload["rvfi_opcode_coverage_counter_range"] == [228, 239]
    assert payload["checker_property_bit"] == 16
    assert payload["checker_property_id"] == "RVFI.ORDER"


def _inactive_manifest(tmp_path: Path) -> Path:
    manifest = json.loads((ROOT / MANIFEST_PATH).read_text(encoding="utf-8"))
    for entry in manifest["properties"]:
        if entry["bit"] == 16:
            entry.update(status="not_assessed", binding=None,
                         reason="test-fixture-withdrawn")
    path = tmp_path / "checker_profile_no_bit16.json"
    path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
    return path


def test_cli_fails_closed_when_bit_16_is_not_active(tmp_path, capsys, monkeypatch) -> None:
    monkeypatch.setattr(driver, "CHECKER_MANIFEST",
                        str(_inactive_manifest(tmp_path)))

    def _forbidden(*args, **kwargs):
        raise AssertionError("a fixture without bit 16 must never start a campaign")

    monkeypatch.setattr(driver, "run_soc_campaign", _forbidden)
    code = driver.main(["--output", str(tmp_path / "run"), "--seconds", "300",
                        "--seed", "1", "--client", "/nonexistent/kfuzz"])
    assert code == driver.EXIT_PROFILE_FIXTURE
    assert "profile-checker-bit16-inactive" in capsys.readouterr().err


@pytest.mark.parametrize("replacement,fragment", [
    ("rvfi_opcode_coverage_x", "profile-rvfi-opcode-coverage-port-invalid"),
    ("rvfi_opcode_coverage_o [10:0]", "profile-rvfi-opcode-coverage-port-invalid"),
])
def test_cli_fails_closed_when_the_opcode_port_is_not_12_bit_output(
        tmp_path, capsys, monkeypatch, replacement, fragment) -> None:
    from myfuzz.composition.soc_profile_renderer import render_composition

    needle = "output logic [11:0] rvfi_opcode_coverage_o"
    assert replacement != needle

    def _fake_render(plan, *, checker_profile=None):
        rendered = render_composition(plan, checker_profile=checker_profile)
        text = rendered["myfuzz_soc_top.sv"]
        assert needle in text
        if replacement.endswith("[10:0]"):
            rendered["myfuzz_soc_top.sv"] = text.replace(
                needle, "output logic [10:0] rvfi_opcode_coverage_o")
        else:
            rendered["myfuzz_soc_top.sv"] = text.replace(
                "rvfi_opcode_coverage_o", replacement)
        return rendered

    monkeypatch.setattr(driver, "render_composition", _fake_render)

    def _forbidden(*args, **kwargs):
        raise AssertionError("an unrenderable port must never start a campaign")

    monkeypatch.setattr(driver, "run_soc_campaign", _forbidden)
    code = driver.main(["--output", str(tmp_path / "run"), "--seconds", "300",
                        "--seed", "1", "--client", "/nonexistent/kfuzz"])
    assert code == driver.EXIT_PROFILE_FIXTURE
    assert fragment in capsys.readouterr().err


def test_cli_drives_the_shipped_campaign_runner_once(tmp_path, monkeypatch, capsys) -> None:
    calls: list[dict] = []

    def _fake_run(config, output, **kwargs):
        calls.append({"config": config, "output": Path(output), **kwargs})
        return {"status": "completed", "effective_fuzz_seconds": 300.0,
                "requested_duration_seconds": 300.0, "replay": {"status": "passed"},
                "errors": [], "evidence_missing": []}

    monkeypatch.setattr(driver, "run_soc_campaign", _fake_run)
    output = tmp_path / "run"
    code = driver.main(["--output", str(output), "--seconds", "300",
                        "--seed", "20260926",
                        "--client", "/nonexistent/kfuzz"])
    assert code == driver.EXIT_OK
    assert len(calls) == 1
    assert calls[0]["output"] == output
    # The identity document must be written before the campaign runs, so a
    # failed build still leaves the declared configuration auditable.
    identity = json.loads((tmp_path / "run.task.json").read_text(encoding="utf-8"))
    assert identity["schema_version"] == driver.SCHEMA
    assert identity["request_id"] == "ibex-pulp-gpio-spi"
    assert identity["rvfi_opcode_coverage_counter_range"] == [228, 239]
    assert identity["checker_property_bit"] == 16
    assert identity["checker_property_id"] == "RVFI.ORDER"
    assert identity["client"] == "/nonexistent/kfuzz"
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "completed"
    assert payload["verify_command"].endswith("verify --run %s --min-cpu-points 1"
                                              % output)
