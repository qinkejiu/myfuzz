"""Cross-case chain report over saved runtime chain certificates.

Every synthetic run directory is one ``online_trace_jsonl.v1`` artifact built
from the hand-joined journals of ``test_chain_certificates``: the report is
recomputed by the real frozen producer, and the expectations below are hand
computed from those journals (case indices, event ids, case gaps). A cross-case
chain is produced by rewriting ``provenance.observed_case`` of the declared
tail of one journal, which leaves every event id and every join untouched while
moving the certificate's endpoint case index past its source case index.

The negative cases tamper a real certified certificate (not a hand-built one)
so that a broken schema, hop order or ``cross_case`` flag is refused with
``ValueError`` instead of being silently dropped from the report.
"""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from myfuzz.scenario.chain_certificates import (
    CPU_TO_IP_TO_CPU,
    IP_TO_CPU_TO_IP,
    ChainCertificates,
)
from myfuzz.scenario.cross_case_chains import (
    CERTIFIED,
    DIRECTIONS,
    GAP_STATS_SCOPE,
    REPORT_SCHEMA_VERSION,
    cross_case_chain_report,
    cross_case_chain_row,
)
from tests.scenario.test_chain_certificates import (
    CPU_HOPS,
    IP_HOPS,
    _cpu_journal,
    _ip_journal,
    _merge,
    _pin8_admission,
)

ROOT = Path(__file__).resolve().parents[2]
# First declared hop of each direction that is proven after a case boundary can
# already have been crossed: everything from there on is retagged.
CROSS_CASE_TAIL = {IP_TO_CPU_TO_IP: "isr_padin_mmio_acceptance",
                   CPU_TO_IP_TO_CPU: "instruction_retirement"}
# Events carrying the pin-8 IRQ "source_event_id", which the frozen CPU-IRQ
# auditor requires to increase strictly across admitted sources; a journal that
# merges several pin-8 chains must therefore number them.
IP_SOURCE_EVENT_NAMES = ("ip_source_start", "ip_pulse_start", "cpu_irq_input",
                         "cpu_irq_taken")


# --------------------------------------------------------------- synthetic runs


def _retag_case(journal, names, case_index):
    """Rewrite ``observed_case`` on named events, keeping every other field."""
    for name in names:
        def editor(event, case_index=case_index):
            provenance = dict(event["provenance"])
            provenance["observed_case"] = {"case_id": f"case-{case_index}",
                                           "case_index": case_index}
            return {**event, "provenance": provenance}
        journal.edit(name, editor)
    return journal


def _ip_chain(case_index=1, endpoint_case_index=None, tag="", source_event_id=1):
    """One pin-8 chain; ``endpoint_case_index`` retags its declared tail."""
    journal = _ip_journal(case_index=case_index, tag=tag)
    for name in IP_SOURCE_EVENT_NAMES:
        journal.mutate(name, source_event_id=source_event_id)
    if (endpoint_case_index is not None
            and endpoint_case_index != case_index):
        hops = IP_HOPS[IP_HOPS.index(CROSS_CASE_TAIL[IP_TO_CPU_TO_IP]):]
        _retag_case(journal, hops, endpoint_case_index)
    return journal


def _cross_case_ip_journal(case_index=1, endpoint_case_index=3, tag="",
                           source_event_id=1):
    return _ip_chain(case_index=case_index,
                     endpoint_case_index=endpoint_case_index, tag=tag,
                     source_event_id=source_event_id)


def _cross_case_cpu_journal(case_index=1, endpoint_case_index=3, tag=""):
    journal = _cpu_journal(case_index=case_index, tag=tag)
    hops = CPU_HOPS[CPU_HOPS.index(CROSS_CASE_TAIL[CPU_TO_IP_TO_CPU]):]
    return _retag_case(journal, hops, endpoint_case_index)


def _write_run(directory, journal):
    """Write one streaming-format run directory holding the journal's events."""
    directory.mkdir(parents=True, exist_ok=True)
    events = journal.events
    (directory / "online_events.jsonl").write_text(
        "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
        encoding="utf-8")
    (directory / "online_final_trace.meta.json").write_text(json.dumps({
        "schema_version": "online_trace_jsonl.v1",
        "events_file": "online_events.jsonl",
        "event_count": len(events),
        "status": "complete"}), encoding="utf-8")
    return directory


def _certified_certificate(journal):
    """The one certified certificate of a synthetic journal, from the producer."""
    consumer = ChainCertificates()
    certificates = list(consumer.ingest(journal.events))
    certificates.extend(consumer.flush())
    assert len(certificates) == 1, certificates
    assert certificates[0]["status"] == CERTIFIED
    return certificates[0]


def _certificate_id(direction, admission_id):
    return hashlib.sha256(json.dumps([direction, admission_id],
                                     separators=(",", ":")).encode(
                                         "utf-8")).hexdigest()


# ------------------------------------------------------------- same-case chains


def test_same_case_chains_are_not_cross_case(tmp_path):
    journal = _merge(_ip_journal(), _cpu_journal())
    report = cross_case_chain_report(_write_run(tmp_path / "run", journal))

    assert report["schema_version"] == REPORT_SCHEMA_VERSION
    assert report["certificate_schema_version"] == "runtime_chain_certificate.v1"
    assert report["events_ingested"] == len(journal.events)
    assert report["trace"]["format"] == "jsonl.v1"
    assert report["trace"]["events_file"] == "online_events.jsonl"
    assert report["certified_count"] == 2
    assert report["incomplete_count"] == 0
    assert report["cross_case_count"] == 0
    assert report["same_case_count"] == 2
    assert report["unresolved_case_count"] == 0
    assert report["truncated"] is False
    assert report["truncated_certificate_count"] == 0
    assert report["retained_certificate_count"] == 2
    assert report["max_case_gap_seen"] is None
    assert report["all_directions_have_cross_case"] is False
    assert report["directions_without_cross_case"] == list(DIRECTIONS)

    for direction in DIRECTIONS:
        row = report["by_direction"][direction]
        assert row["certified_count"] == 1, direction
        assert row["cross_case_count"] == 0, direction
        assert row["same_case_count"] == 1, direction
        assert row["has_cross_case"] is False, direction
        assert row["incomplete_count"] == 0, direction
        assert row["first_missing_hop"] is None, direction
        assert row["first_missing_hops"] == {}, direction
        # No cross-case chain: the distribution has no sample and stays null.
        assert row["case_gap"]["scope"] == GAP_STATS_SCOPE, direction
        assert row["case_gap"]["sample_count"] == 0, direction
        assert row["case_gap"]["p50"] is None, direction
        assert row["case_gap"]["max"] is None, direction
        assert row["case_gap"]["min"] is None, direction
        assert row["representative_cross_case_chain"] is None, direction

    chains = {row["direction"]: row for row in report["chains"]}
    assert sorted(chains) == sorted(DIRECTIONS)
    ip = chains[IP_TO_CPU_TO_IP]
    assert ip["cross_case"] is False
    assert ip["case_gap"] == 0
    assert (ip["source_case_id"], ip["source_case_index"]) == ("case-1", 1)
    assert (ip["endpoint_case_id"], ip["endpoint_case_index"]) == ("case-1", 1)
    assert ip["source_admission_id"] == _pin8_admission().admission_id
    assert ip["certificate_id"] == _certificate_id(
        IP_TO_CPU_TO_IP, _pin8_admission().admission_id)
    assert [hop["hop_id"] for hop in ip["hops"]] == list(IP_HOPS)
    assert [hop["event_id"] for hop in ip["hops"]] == [journal.ids[name]
                                                       for name in IP_HOPS]
    assert ip["hop_count"] == len(IP_HOPS)
    assert ip["terminal_hop"] == {"hop_id": "isr_padin_retirement",
                                  "event_id": journal.ids["isr_padin_retirement"]}
    assert ip["completed_event_id"] == journal.ids["isr_padin_retirement"]
    cpu = chains[CPU_TO_IP_TO_CPU]
    assert [hop["event_id"] for hop in cpu["hops"]] == [journal.ids[name]
                                                        for name in CPU_HOPS]
    assert cpu["completed_event_id"] == journal.ids["retired_target_delivery"]


# --------------------------------------------------------------- cross-case runs


def test_cross_case_gap_and_hops_match_hand_computation(tmp_path):
    ip = _cross_case_ip_journal(case_index=1, endpoint_case_index=3)
    cpu = _cross_case_cpu_journal(case_index=1, endpoint_case_index=4)
    journal = _merge(ip, cpu)
    report = cross_case_chain_report(_write_run(tmp_path / "run", journal))

    assert report["cross_case_count"] == 2
    assert report["same_case_count"] == 0
    assert report["all_directions_have_cross_case"] is True
    assert report["directions_without_cross_case"] == []
    assert report["max_case_gap_seen"] == 3

    # Hand-computed: IP case 1 -> case 3 is a gap of 2, CPU case 1 -> case 4 a
    # gap of 3. Each direction keeps exactly one cross-case chain.
    ip_row = report["by_direction"][IP_TO_CPU_TO_IP]
    assert ip_row["cross_case_count"] == 1
    assert ip_row["same_case_count"] == 0
    assert ip_row["has_cross_case"] is True
    assert ip_row["case_gap"] == {"scope": GAP_STATS_SCOPE, "sample_count": 1,
                                  "p50": 2, "max": 2, "min": 2,
                                  "excluded_truncated_count": 0}
    cpu_row = report["by_direction"][CPU_TO_IP_TO_CPU]
    assert cpu_row["case_gap"]["sample_count"] == 1
    assert cpu_row["case_gap"]["p50"] == 3
    assert cpu_row["case_gap"]["max"] == 3

    chains = {row["direction"]: row for row in report["chains"]}
    ip_chain = chains[IP_TO_CPU_TO_IP]
    assert ip_chain["cross_case"] is True
    assert ip_chain["case_gap"] == 2
    assert (ip_chain["source_case_id"], ip_chain["source_case_index"]) == (
        "case-1", 1)
    assert (ip_chain["endpoint_case_id"], ip_chain["endpoint_case_index"]) == (
        "case-3", 3)
    assert [hop["hop_id"] for hop in ip_chain["hops"]] == list(IP_HOPS)
    assert [hop["event_id"] for hop in ip_chain["hops"]] == [
        journal.ids[name] for name in IP_HOPS]
    assert ip_chain["terminal_hop"] == {
        "hop_id": "isr_padin_retirement",
        "event_id": journal.ids["isr_padin_retirement"]}
    assert ip_chain["completed_event_id"] == journal.ids["isr_padin_retirement"]
    assert ip_chain["certificate_id"] == _certificate_id(
        IP_TO_CPU_TO_IP, _pin8_admission().admission_id)

    cpu_chain = chains[CPU_TO_IP_TO_CPU]
    assert cpu_chain["case_gap"] == 3
    assert (cpu_chain["source_case_id"], cpu_chain["source_case_index"]) == (
        "case-1", 1)
    assert (cpu_chain["endpoint_case_id"], cpu_chain["endpoint_case_index"]) == (
        "case-4", 4)
    assert [hop["event_id"] for hop in cpu_chain["hops"]] == [
        journal.ids[name] for name in CPU_HOPS]

    assert ip_row["representative_cross_case_chain"]["certificate_id"] == \
        ip_chain["certificate_id"]
    assert ip_row["representative_cross_case_chain"]["hops"] == ip_chain["hops"]


def test_direction_without_cross_case_reports_same_case_and_first_gap(tmp_path):
    journal = _merge(
        _cross_case_ip_journal(case_index=1, endpoint_case_index=2),
        _cpu_journal(case_index=5, tag="same_"),
        _cpu_journal(case_index=9, tag="gap_").drop("mmio_write_delivery"))
    report = cross_case_chain_report(_write_run(tmp_path / "run", journal))

    assert report["certified_count"] == 2
    assert report["incomplete_count"] == 1
    assert report["cross_case_count"] == 1
    assert report["same_case_count"] == 1
    assert report["all_directions_have_cross_case"] is False
    assert report["directions_without_cross_case"] == [CPU_TO_IP_TO_CPU]

    ip_row = report["by_direction"][IP_TO_CPU_TO_IP]
    assert ip_row["has_cross_case"] is True
    assert ip_row["same_case_count"] == 0
    cpu_row = report["by_direction"][CPU_TO_IP_TO_CPU]
    assert cpu_row["has_cross_case"] is False
    assert cpu_row["cross_case_count"] == 0
    assert cpu_row["same_case_count"] == 1
    assert cpu_row["certified_count"] == 1
    assert cpu_row["incomplete_count"] == 1
    # The first gap of the direction that never crossed a case boundary.
    assert cpu_row["first_missing_hops"] == {"mmio_write_delivery": 1}
    assert cpu_row["first_missing_hop"] == "mmio_write_delivery"


# ------------------------------------------------------------- bounded details


def test_max_gap_cases_truncates_details_but_keeps_counts(tmp_path):
    journal = _merge(
        _ip_chain(case_index=1, tag="a_", source_event_id=11),   # same case
        _cross_case_ip_journal(case_index=4, endpoint_case_index=5, tag="b_",
                               source_event_id=12),
        _cross_case_ip_journal(case_index=7, endpoint_case_index=10, tag="c_",
                               source_event_id=13),
        _cross_case_ip_journal(case_index=13, endpoint_case_index=18, tag="d_",
                               source_event_id=14))
    run = _write_run(tmp_path / "run", journal)

    report = cross_case_chain_report(run, max_gap_cases=2)
    assert report["max_gap_cases"] == 2
    assert report["certified_count"] == 4
    assert report["cross_case_count"] == 3
    assert report["same_case_count"] == 1
    assert report["max_case_gap_seen"] == 5
    assert report["truncated"] is True
    assert report["truncated_certificate_count"] == 2
    assert report["retained_certificate_count"] == 2
    assert sorted(row["case_gap"] for row in report["chains"]) == [0, 1]
    assert all(row["case_gap"] <= 2 for row in report["chains"])

    ip_row = report["by_direction"][IP_TO_CPU_TO_IP]
    assert ip_row["cross_case_count"] == 3
    assert ip_row["cross_case_retained_count"] == 1
    assert ip_row["cross_case_truncated_count"] == 2
    assert ip_row["has_cross_case"] is True
    assert ip_row["case_gap"]["sample_count"] == 1
    assert ip_row["case_gap"]["p50"] == 1
    assert ip_row["case_gap"]["max"] == 1
    assert ip_row["case_gap"]["excluded_truncated_count"] == 2

    # Without a bound the same artifact keeps every certificate detail.
    full = cross_case_chain_report(run)
    assert full["max_gap_cases"] is None
    assert full["truncated"] is False
    assert full["retained_certificate_count"] == 4
    assert full["max_case_gap_seen"] == 5
    # Hand-computed gaps 1, 3 and 5: upper median of the sorted samples.
    full_gaps = full["by_direction"][IP_TO_CPU_TO_IP]["case_gap"]
    assert full_gaps["sample_count"] == 3
    assert full_gaps["p50"] == 3
    assert full_gaps["max"] == 5
    assert full_gaps["min"] == 1


def test_long_sequence_stays_bounded_while_counts_stay_exact(tmp_path):
    journals = []
    for index in range(12):
        case_index = 1 + index * 4
        tag = f"c{index}_"
        if index % 2:
            journals.append(_cross_case_ip_journal(
                case_index=case_index, endpoint_case_index=case_index + 3,
                tag=tag, source_event_id=11 + index))
        else:
            journals.append(_ip_chain(case_index=case_index, tag=tag,
                                      source_event_id=11 + index))
    journal = _merge(*journals)
    report = cross_case_chain_report(_write_run(tmp_path / "run", journal),
                                     max_gap_cases=0)

    assert report["certified_count"] == 12
    assert report["cross_case_count"] == 6
    assert report["same_case_count"] == 6
    assert report["truncated"] is True
    assert report["truncated_certificate_count"] == 6
    assert report["retained_certificate_count"] == 6
    assert len(report["chains"]) == 6
    assert {row["case_gap"] for row in report["chains"]} == {0}
    assert report["max_case_gap_seen"] == 3

    ip_row = report["by_direction"][IP_TO_CPU_TO_IP]
    assert ip_row["has_cross_case"] is True
    assert ip_row["cross_case_truncated_count"] == 6
    # Every gap sample was truncated, so the distribution is explicitly empty.
    assert ip_row["case_gap"]["sample_count"] == 0
    assert ip_row["case_gap"]["p50"] is None
    assert ip_row["case_gap"]["max"] is None


def test_max_gap_cases_must_be_a_nonnegative_integer(tmp_path):
    run = _write_run(tmp_path / "run", _cross_case_ip_journal())
    for invalid in (-1, 1.0, "1", True):
        with pytest.raises(ValueError):
            cross_case_chain_report(run, max_gap_cases=invalid)


# ------------------------------------------------------------ strict refusals


def test_cross_case_row_accepts_the_frozen_certificate():
    row = cross_case_chain_row(_certified_certificate(_ip_journal()))
    assert row["cross_case"] is False
    assert row["case_gap"] == 0
    assert row["certificate_id"] and row["source_admission_id"]


def test_contradicting_cross_case_flag_is_refused():
    cross_certificate = _certified_certificate(_cross_case_ip_journal())
    contradicted = dict(cross_certificate, cross_case=False)
    with pytest.raises(ValueError, match="cross_case"):
        cross_case_chain_row(contradicted)
    same_certificate = _certified_certificate(_ip_journal())
    with pytest.raises(ValueError, match="cross_case"):
        cross_case_chain_row(dict(same_certificate, cross_case=True))
    with pytest.raises(ValueError, match="cross_case"):
        cross_case_chain_row(dict(cross_certificate, cross_case=1))


def test_endpoint_case_before_the_source_case_is_refused():
    certificate = _certified_certificate(
        _cross_case_ip_journal(case_index=4, endpoint_case_index=7))
    forged = dict(certificate, endpoint_case_id="case-0", endpoint_case_index=0)
    with pytest.raises(ValueError, match="case"):
        cross_case_chain_row(forged)


@pytest.mark.parametrize("fault", ("schema", "hop_order", "hop_dropped",
                                   "missing_hops", "certificate_id",
                                   "non_mapping"))
def test_report_refuses_tampered_certificates(tmp_path, fault):
    certificate = _certified_certificate(_cross_case_ip_journal())

    def tamper(document):
        if fault == "non_mapping":
            return ("not", "a", "certificate")
        forged = json.loads(json.dumps(document))
        if fault == "schema":
            forged["schema_version"] = "runtime_chain_certificate.v2"
        elif fault == "hop_order":
            forged["hops"][3], forged["hops"][4] = (forged["hops"][4],
                                                    forged["hops"][3])
        elif fault == "hop_dropped":
            forged["hops"].pop(2)
        elif fault == "missing_hops":
            forged["missing_hops"] = ["pin8_injection"]
        elif fault == "certificate_id":
            forged["certificate_id"] = "0" * 64
        return forged

    with pytest.raises(ValueError):
        cross_case_chain_row(tamper(certificate))

    class _TamperingProducer:
        """Wrap the frozen producer and forge every certificate it settles."""

        def __init__(self, **kwargs):
            self._inner = ChainCertificates(**kwargs)

        def _tampered(self, certificates):
            return tuple(tamper(certificate) for certificate in certificates)

        def ingest(self, events):
            return self._tampered(self._inner.ingest(events))

        def flush(self):
            return self._tampered(self._inner.flush())

    with pytest.raises(ValueError):
        cross_case_chain_report(
            _write_run(tmp_path / "run", _cross_case_ip_journal()),
            chain_producer=_TamperingProducer)


# ------------------------------------------------------------------ CLI checks


def _cli(*arguments):
    environment = dict(os.environ)
    environment["PYTHONPATH"] = f"{ROOT / 'src'}:{ROOT}"
    return subprocess.run(
        (sys.executable, str(ROOT / "scripts/report_cross_case_chains.py"),
         *(str(argument) for argument in arguments)),
        cwd=ROOT, env=environment, capture_output=True, text=True, timeout=300)


def test_cli_writes_json_and_exits_zero_with_a_cross_case_chain(tmp_path):
    run = _write_run(tmp_path / "cross", _cross_case_ip_journal())
    out = tmp_path / "report.json"
    result = _cli("--run", run, "--out", out)
    assert result.returncode == 0, result.stderr
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["schema_version"] == REPORT_SCHEMA_VERSION
    assert document["cross_case_count"] == 1
    assert document["by_direction"][IP_TO_CPU_TO_IP]["has_cross_case"] is True
    assert str(run) in result.stdout


def test_cli_exits_two_and_explains_when_no_chain_crosses_a_case(tmp_path):
    journal = _merge(_ip_journal(),
                     _cpu_journal(case_index=5, tag="same_"),
                     _cpu_journal(case_index=9, tag="gap_").drop("mmio_write_delivery"))
    run = _write_run(tmp_path / "same", journal)
    out = tmp_path / "report.json"
    result = _cli("--run", run, "--out", out)
    assert result.returncode == 2, result.stderr
    assert "cross-case" in result.stderr.lower()
    assert IP_TO_CPU_TO_IP in result.stderr
    assert CPU_TO_IP_TO_CPU in result.stderr
    assert "mmio_write_delivery" in result.stderr
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["cross_case_count"] == 0
    assert document["by_direction"][CPU_TO_IP_TO_CPU]["same_case_count"] == 1
    assert document["by_direction"][CPU_TO_IP_TO_CPU]["first_missing_hops"] == {
        "mmio_write_delivery": 1}


def test_cli_max_gap_cases_reports_truncation_without_losing_the_count(tmp_path):
    run = _write_run(tmp_path / "cross",
                     _cross_case_ip_journal(case_index=1, endpoint_case_index=4))
    out = tmp_path / "report.json"
    result = _cli("--run", run, "--out", out, "--max-gap-cases", 0)
    assert result.returncode == 0, result.stderr
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["cross_case_count"] == 1
    assert document["truncated"] is True
    assert document["chains"] == []
    assert "truncat" in result.stderr.lower()


def test_cli_rejects_a_run_without_a_streamable_trace(tmp_path):
    run = tmp_path / "empty"
    run.mkdir()
    out = tmp_path / "report.json"
    result = _cli("--run", run, "--out", out)
    assert result.returncode == 1
    assert "trace" in result.stderr.lower()
    assert not out.exists()
