"""Task 4: the peer judgement basis and the peer RTL content hash in replay.

A ``soc_peer_oracle.v1`` record is only evidence if it says *on what basis* each
check was decided and *which peer RTL revision* was judged, and if a saved
record cannot be replayed into an agreement it does not deserve.  This module
pins those bindings:

1. every recorded check carries a non-empty ``basis``, and the oracle record
   carries the content hash of each peer's RTL source;
2. a replay compares the oracle record through its content-addressed hash (and
   its status), so a rerun that audits differently cannot agree;
3. a *changed* peer source changes the recorded hash and the oracle hash, and a
   replay of the old record against the new audit diverges on
   ``peer_oracle:hash`` -- the peer RTL revision is part of the evidence, not
   decoration;
4. deleting the wire trace (or marking it truncated) moves the wire check to
   ``not_assessed``: it must never appear as a passing check and must never let
   the package's own wire consumer report a pass;
5. a missing, truncated or count-mismatched trace can therefore never become a
   passing SPI transfer in a replayed package either.

The fixtures use the real peers plan (``examples/soc_generation/request-peers.json``)
and the production functions that bind peer slots to peer source content
(``soc_builder._peer_projection_slots``), but no compiler: the default suite runs
without Verilator.  ``src/myfuzz/protocols/rtl`` is never written to; a peer that
has to change is changed in a private copy of that tree.

Two boundaries are stated rather than papered over:

* a concurrent Task 1 change is rewriting ``audit_peer_run``'s raw-driven UART
  expectation basis.  The basis assertions here require only a non-empty string,
  so they hold before and after that change; only the SPI check's basis is
  compared verbatim, because it comes from the independent register contract
  this fixture supplies.
* the wire checks the oracle cannot decide are reported in ``unassessed`` while
  the oracle's own top-level ``status`` only summarises the checks it could run.
  The "never a pass" assertion is therefore made at three levels: the check must
  not exist as a decided pass, the record's wire consumer
  (``spi_wire_verdict``) must report ``not_assessed``, and the offline
  confirmation's run gate (``_run_problem``) must refuse an incomplete run
  instead of judging it.
"""
from __future__ import annotations

import functools
import hashlib
import json
import shutil
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from myfuzz.composition.component_profile import (
    load_component_profile,
    load_composition_request,
)
from myfuzz.composition.soc_composition import build_composition
from myfuzz.composition.soc_failure_evidence import (
    REPLAY_AGREEMENT,
    REPLAY_DIVERGENCE,
    EvidencePackage,
    _result_document,
    replay_package,
)
from myfuzz.composition.soc_image import build_image_plan, combined_input_layout
from myfuzz.composition.soc_offline_defect_confirmation import (
    _run_problem,
    spi_wire_verdict,
)
from myfuzz.composition.soc_peer_oracle import PEER_ORACLE_SCHEMA, audit_peer_run
from myfuzz.composition.soc_runtime import RunResult, RuntimeBuild, _peer_slots
from myfuzz.contracts import canonical_bytes
from myfuzz.integration.soc_builder import _peer_projection_slots

from tests.composition.soc_generation_fixture import ROOT

PEER_REQUEST = ROOT / "examples/soc_generation/request-peers.json"
PEER_PROFILE_NAMES = ("novacore", "novauart_link", "novaspi", "novagpio")

#: The three declared peers and the RTL each one is generated from.  These are
#: read-only inputs; a test that needs a different revision copies the tree.
PEER_SOURCES = {
    "uart0": "src/myfuzz/protocols/rtl/soc_uart_peer.sv",
    "spi0": "src/myfuzz/protocols/rtl/soc_spi_peer.sv",
    "gpio0": "src/myfuzz/protocols/rtl/soc_gpio_peer.sv",
}

#: The independent SPI TXDATA register norm the fixture hands the oracle.
SPI_WRITE_ADDRESS = 0x1008
SPI_CONTRACT_BASIS = "independent fixture register norm"
SPI_MOSI_BYTE = 0xA5
SPI_MISO_BYTE = 0x5A
UART_TX_BYTE = 0x31


# ---------------------------------------------------------------------------
# fixtures: the real peers plan, without a compiler
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def _peer_plan():
    profiles: dict = {}
    for name in PEER_PROFILE_NAMES:
        relative = f"examples/soc_generation/profiles/{name}.json"
        profile = load_component_profile(ROOT / relative)
        profiles[relative] = profile
        profiles.setdefault(profile.component_id, profile)
    request = load_composition_request(
        json.loads(PEER_REQUEST.read_text(encoding="utf-8")), profiles=profiles)
    return build_composition(request, base_dir=ROOT, drive_profile="cpu_execute")


@functools.lru_cache(maxsize=1)
def _peer_layout():
    plan = _peer_plan()
    return combined_input_layout(plan, build_image_plan(plan))


def peer_source_tree(directory: Path) -> Path:
    """One private copy of the declared peer RTL under ``directory``.

    The declared sources are referenced relative to the composition base
    directory, so a copy keeps the same relative path and
    :func:`runtime_peer_slots` can be pointed at it.  The real tree under
    ``src/myfuzz/protocols/rtl`` is only ever read.
    """
    for relative in PEER_SOURCES.values():
        target = directory / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    return directory


def runtime_peer_slots(base_dir: Path = ROOT) -> tuple[dict[str, object], ...]:
    """The peer ABI records an oracle audit consumes, from the real plan.

    ``_peer_projection_slots`` is the production function that binds each peer's
    source *content hash* to its slot ABI; the runtime's own record additionally
    carries the resolved peer parameters (``soc_runtime.build_profile_runtime``
    folds the same content hash into the build).  Joining the two here presents
    exactly what a built run supplies, so the audit is exercised against real
    slot contracts, real parameters and real RTL hashes.
    """
    plan = _peer_plan()
    records = [dict(item) for item in
               _peer_projection_slots(plan, _peer_layout(), base_dir=base_dir)]
    parameters = {(str(item["instance_id"]), str(item["slot"])): dict(item["parameters"])
                  for item in _peer_slots(plan)}
    for record in records:
        record["parameters"] = parameters[(str(record["instance_id"]),
                                           str(record["slot"]))]
    return tuple(records)


def _spi_frame(mosi: int = SPI_MOSI_BYTE, miso: int = SPI_MISO_BYTE, *,
               bits: int = 8, cpol: int = 0, cs_active_low: int = 1,
               instance_id: str | None = "spi0") -> list[dict[str, object]]:
    """One complete four-wire transfer: idle, select, two edges per bit, deselect."""
    idle = str(cpol)
    active = str(1 - cpol)
    deselected = str(cs_active_low)
    selected = str(1 - cs_active_low)
    rows: list[dict[str, object]] = [
        {"cycle": 0, "sck": idle, "cs": deselected, "mosi": "0", "miso": "0"},
        {"cycle": 1, "sck": idle, "cs": selected, "mosi": "0", "miso": "0"},
    ]
    cycle = 2
    for shift in range(bits - 1, -1, -1):
        tx = str((mosi >> shift) & 1)
        rx = str((miso >> shift) & 1)
        rows.append({"cycle": cycle, "sck": idle, "cs": selected,
                     "mosi": tx, "miso": rx})
        rows.append({"cycle": cycle + 1, "sck": active, "cs": selected,
                     "mosi": tx, "miso": rx})
        rows.append({"cycle": cycle + 2, "sck": idle, "cs": selected,
                     "mosi": tx, "miso": rx})
        cycle += 3
    rows.append({"cycle": cycle, "sck": idle, "cs": deselected,
                 "mosi": "0", "miso": "0"})
    if instance_id is not None:
        rows = [dict(item, instance_id=instance_id) for item in rows]
    return rows


SPI_FRAME = _spi_frame()


def audit_inputs(*, base_dir: Path = ROOT,
                 wire_trace: Sequence[Mapping[str, object]] | None = None,
                 wire_status: Sequence[Mapping[str, object]] | None = None,
                 uart_sent: int = 1, uart_drop: int = 0,
                 cycles: int = 200,
                 ) -> tuple[SimpleNamespace, SimpleNamespace, SimpleNamespace]:
    """One peer run's build/sample/result, consistent enough to audit.

    The wire trace and the status row are parameters because the negative cases
    are exactly "the trace is gone" and "the status says the trace is not
    complete"; everything else is the honest run of the plan's three peers.
    """
    slots = runtime_peer_slots(base_dir)
    index = {str(item["instance_id"]): int(item["index"]) for item in slots}
    if wire_trace is None:
        wire_trace = tuple(SPI_FRAME)
    if wire_status is None:
        wire_status = ({"instance_id": "spi0", "count": len(wire_trace),
                        "truncated": False},)
    layout = _peer_layout()
    build = SimpleNamespace(
        peer_slots=slots,
        peer_observations=(),
        spi_wire_contracts={"spi0": {"txdata_address": SPI_WRITE_ADDRESS,
                                     "basis": SPI_CONTRACT_BASIS}},
        cpu_data_sources=(0,),
        # A raw-decoding audit may want the layout the slots were projected
        # from; offering the real one keeps that path exercised too.
        layout=layout,
        soc_layout=layout,
        raw_layout=_peer_plan().raw_layout,
    )
    sample = SimpleNamespace(
        raw=(0,) * cycles,
        events=(),
        peer_events=({"slot": index["spi0"], "cycle": 0, "payload": SPI_MISO_BYTE},
                     {"slot": index["uart0"], "cycle": 0, "payload": UART_TX_BYTE}),
    )
    result = SimpleNamespace(
        cycles=cycles,
        peer_applied=({"cycle": 0, "instance": "spi0", "slot": "spi.arm_byte",
                       "value": SPI_MISO_BYTE},
                      {"cycle": 0, "instance": "uart0", "slot": "uart.tx_byte",
                       "value": UART_TX_BYTE}),
        peer_wire_trace=tuple(dict(item) for item in wire_trace),
        peer_wire_status=tuple(dict(item) for item in wire_status),
        requests=({"cycle": 0, "addr": SPI_WRITE_ADDRESS, "write": 1,
                   "wdata": SPI_MOSI_BYTE, "be": 0xF, "source": 0},),
        counters={"peer.uart0.tx_sent_count_o": uart_sent,
                  "peer.uart0.tx_drop_count_o": uart_drop},
        observations={},
        trace=tuple({"cycle": cycle, "raw": 0} for cycle in range(cycles)),
        requests_truncated=False,
    )
    return build, sample, result


def audit_run(**overrides) -> dict[str, object]:
    build, sample, result = audit_inputs(**overrides)
    return audit_peer_run(build, sample, result)


def _recompute_oracle_hash(document: Mapping[str, object]) -> str:
    """The hash a record's own content demands, recomputed without the oracle.

    ``soc_peer_oracle`` hashes the document before adding ``oracle_hash``, so a
    record whose stored hash differs from this value does not describe its own
    checks or model hashes.
    """
    payload = {key: value for key, value in document.items() if key != "oracle_hash"}
    return "sha256:" + hashlib.sha256(canonical_bytes(payload)).hexdigest()


def _peer_source_hash(relative: str, base_dir: Path = ROOT) -> str:
    return "sha256:" + hashlib.sha256((base_dir / relative).read_bytes()).hexdigest()


class OracleRecordBindingTests(unittest.TestCase):
    """Requirement 1 and the content-addressing of requirement 2."""

    def test_the_peer_rtl_source_content_hash_is_recorded_per_model(self) -> None:
        audit = audit_run()
        self.assertEqual(PEER_ORACLE_SCHEMA, audit["schema_version"])
        models = {str(item["instance_id"]): item for item in audit["models"]}
        self.assertEqual(set(PEER_SOURCES), set(models), audit["models"])
        for instance, relative in PEER_SOURCES.items():
            with self.subTest(peer=instance):
                record = models[instance]
                self.assertEqual(relative, record["source"])
                self.assertEqual(_peer_source_hash(relative), record["source_hash"],
                                 "the oracle record must name the peer RTL revision "
                                 "its checks were made against")

    def test_every_recorded_check_carries_a_non_empty_basis(self) -> None:
        """A check without a basis is not evidence.

        The exact text of the UART raw-decoding basis belongs to a concurrent
        Task 1 change, so only non-emptiness is required here; the SPI check's
        basis is the independent contract this fixture supplies and is compared
        verbatim.
        """
        audit = audit_run()
        self.assertTrue(audit["checks"], audit)
        for check in audit["checks"]:
            with self.subTest(check=check["check_id"]):
                self.assertIsInstance(check["basis"], str)
                self.assertTrue(check["basis"].strip(),
                                "a recorded check must state its basis")
        identifiers = {str(check["check_id"]) for check in audit["checks"]}
        self.assertIn("peer-event-transport", identifiers)
        self.assertIn("spi-transfer-wire", identifiers)
        self.assertIn("uart-tx-sent-count", identifiers)
        wire = next(check for check in audit["checks"]
                    if check["check_id"] == "spi-transfer-wire")
        self.assertEqual(SPI_CONTRACT_BASIS, wire["basis"])
        for item in audit["unassessed"]:
            with self.subTest(unassessed=item["check_id"]):
                self.assertTrue(str(item["check_id"]).strip())
                self.assertTrue(str(item["reason"]).strip(),
                                "an unassessed property must state why")

    def test_the_oracle_hash_covers_the_checks_and_the_model_hashes(self) -> None:
        audit = audit_run()
        self.assertEqual(_recompute_oracle_hash(audit), audit["oracle_hash"])
        altered_check = json.loads(json.dumps(audit))
        altered_check["checks"][0]["status"] = "mismatch"
        self.assertNotEqual(audit["oracle_hash"],
                            _recompute_oracle_hash(altered_check),
                            "a changed check must change the record's hash")
        altered_model = json.loads(json.dumps(audit))
        altered_model["models"][0]["source_hash"] = "sha256:" + "0" * 64
        self.assertNotEqual(audit["oracle_hash"],
                            _recompute_oracle_hash(altered_model),
                            "a changed peer RTL hash must change the record's hash")


class PeerSourceChangeTests(unittest.TestCase):
    """Requirement 3: a peer that changed is a different piece of evidence."""

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(
            prefix=".myfuzz-soc-peer-binding-", dir=ROOT)
        self.addCleanup(self._temporary.cleanup)
        self.base = peer_source_tree(Path(self._temporary.name))

    def _change_uart_peer(self) -> None:
        source = self.base / PEER_SOURCES["uart0"]
        source.write_text(source.read_text(encoding="utf-8")
                          + "\n// a different peer revision\n", encoding="utf-8")

    def test_a_changed_peer_source_changes_its_hash_and_the_oracle_hash(self) -> None:
        before = audit_run(base_dir=self.base)
        self._change_uart_peer()
        after = audit_run(base_dir=self.base)
        first = {str(item["instance_id"]): item for item in before["models"]}
        second = {str(item["instance_id"]): item for item in after["models"]}
        self.assertEqual(_peer_source_hash(PEER_SOURCES["uart0"], self.base),
                         second["uart0"]["source_hash"])
        self.assertNotEqual(first["uart0"]["source_hash"],
                            second["uart0"]["source_hash"])
        self.assertNotEqual(before["oracle_hash"], after["oracle_hash"],
                            "the peer RTL revision must be part of the record identity")
        for untouched in ("spi0", "gpio0"):
            with self.subTest(peer=untouched):
                self.assertEqual(first[untouched]["source_hash"],
                                 second[untouched]["source_hash"])

    def test_a_record_whose_stored_hash_is_not_the_current_peer_content_is_detected(self) -> None:
        """The peer-source binding is checkable without re-running the peers."""
        audit = audit_run(base_dir=self.base)
        self.assertEqual(_recompute_oracle_hash(audit), audit["oracle_hash"])
        self._change_uart_peer()
        recorded = next(item for item in audit["models"]
                        if item["instance_id"] == "uart0")["source_hash"]
        self.assertNotEqual(_peer_source_hash(PEER_SOURCES["uart0"], self.base),
                            recorded,
                            "a saved record must disagree with a changed peer source")


# ---------------------------------------------------------------------------
# replay: the oracle record travels with the package as a content hash
# ---------------------------------------------------------------------------


def _sha256_file(path: object) -> str:
    return "sha256:" + hashlib.sha256(Path(str(path)).read_bytes()).hexdigest()


def _fake_build(directory: Path, *, plan_hash: str, layout_hash: str,
                build_hash: str) -> RuntimeBuild:
    """A build whose recorded identity can be compared without compiling.

    ``replay_package`` decides on the identity the build directory carries: the
    plan/layout markers in the generated testbench, the rendered top, the
    testbench and the executable bytes.  A two-line record with an empty top and
    a placeholder binary is therefore enough to exercise the comparison arms
    honestly, and no compiler is needed for the default suite.
    """
    directory.mkdir(parents=True, exist_ok=True)
    testbench = directory / "profile_tb.sv"
    testbench.write_text(
        "// Generated by myfuzz profile runtime. Do not edit.\n"
        f"// plan: {plan_hash}\n"
        f"// raw-input layout: {layout_hash}\n"
        "module myfuzz_profile_tb;\nendmodule\n", encoding="utf-8")
    top = directory / "myfuzz_soc_top.sv"
    top.write_text("module myfuzz_soc_top;\nendmodule\n", encoding="utf-8")
    executable = directory / "obj_dir" / "myfuzz_profile_sim"
    executable.parent.mkdir(parents=True, exist_ok=True)
    executable.write_text(f"#!/bin/sh\n# {build_hash}\nexit 0\n", encoding="utf-8")
    return RuntimeBuild(output_dir=directory, top_path=top, testbench_path=testbench,
                        executable=executable, sources=(), raw_width=64, slots=(),
                        observations=(), boot_image=None,
                        boot_image_policy="no_preloaded_region",
                        build_hash=build_hash, warnings=0)


def _package_identity(build: RuntimeBuild, *, plan_hash: str,
                      layout_hash: str) -> dict[str, object]:
    return {
        "plan_hash": plan_hash,
        "layout_hash": layout_hash,
        "build_hash": build.build_hash,
        "testbench_hash": _sha256_file(build.testbench_path),
        "rendered_top_hash": _sha256_file(build.top_path),
        "boot_image_hash": "none",
        "boot_image_policy": "no_preloaded_region",
        "runtime": {"executable_hash": _sha256_file(build.executable)},
    }


def _package(build: RuntimeBuild, *, plan_hash: str, layout_hash: str,
             saved_result: Mapping[str, object]) -> EvidencePackage:
    return EvidencePackage(
        schema_version="soc_failure_evidence.v1", kind="peer_replay_binding",
        identity=_package_identity(build, plan_hash=plan_hash,
                                   layout_hash=layout_hash),
        samples=({"request_id": 1, "raw": [0, 0, 0, 0], "events": [],
                  "peer_events": []},),
        results=(saved_result,), inputs_complete=True)


def _run_result(peer_oracle: Mapping[str, object], *,
                counters: Mapping[str, int] | None = None,
                peer_wire_trace: Sequence[Mapping[str, object]] = (),
                peer_wire_status: Sequence[Mapping[str, object]] = (),
                cycles: int = 200) -> RunResult:
    """One run whose document carries the oracle record under test."""
    return RunResult(
        request_id=1, cycles=cycles, status="OK",
        counters=dict(counters if counters is not None
                      else {"peer.uart0.tx_sent_count_o": 1}),
        observations={},
        trace=tuple({"cycle": cycle, "raw": 0} for cycle in range(cycles)),
        applied=({"cycle": 0, "port": "spi0__tx_request_valid_i", "value": 1},),
        stdout="", stderr="", peer_applied=(),
        peer_oracle=peer_oracle,
        peer_wire_trace=tuple(dict(item) for item in peer_wire_trace),
        peer_wire_status=tuple(dict(item) for item in peer_wire_status),
        requests=(), requests_truncated=False)


def _replay(package: EvidencePackage, build: RuntimeBuild, rerun: RunResult):
    """Replay through the real comparison, with the rerun fixed."""
    with patch("myfuzz.composition.soc_failure_evidence.run_sample",
               return_value=rerun):
        return replay_package(package, build, timeout_seconds=1)


PLAN_HASH = "sha256:" + "a" * 64
LAYOUT_HASH = "sha256:" + "b" * 64
BUILD_HASH = "sha256:" + "c" * 64


class ReplayOracleBindingTests(unittest.TestCase):
    """Requirement 2, and the divergence half of requirement 3."""

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(
            prefix=".myfuzz-soc-peer-replay-", dir=ROOT)
        self.addCleanup(self._temporary.cleanup)
        self.directory = Path(self._temporary.name)
        self.build = _fake_build(self.directory / "build", plan_hash=PLAN_HASH,
                                 layout_hash=LAYOUT_HASH, build_hash=BUILD_HASH)

    def _package_for(self, result: RunResult) -> EvidencePackage:
        return _package(self.build, plan_hash=PLAN_HASH, layout_hash=LAYOUT_HASH,
                        saved_result=_result_document(result))

    def test_a_replay_compares_the_oracle_hash_and_status(self) -> None:
        result = _run_result(audit_run())
        replay = _replay(self._package_for(result), self.build, result)
        self.assertEqual(REPLAY_AGREEMENT, replay.status, replay.reason)
        self.assertIn("peer_oracle:hash", replay.checked_fields)
        self.assertIn("peer_oracle:hash", replay.matching_fields)
        self.assertIn("peer_oracle:status", replay.checked_fields)

    def test_a_changed_peer_source_makes_the_replay_diverge_on_the_oracle_hash(self) -> None:
        base = peer_source_tree(self.directory / "peers")
        before = audit_run(base_dir=base)
        source = base / PEER_SOURCES["uart0"]
        source.write_text(source.read_text(encoding="utf-8")
                          + "\n// a different peer revision\n", encoding="utf-8")
        after = audit_run(base_dir=base)
        self.assertNotEqual(before["oracle_hash"], after["oracle_hash"])
        counters = {"peer.uart0.tx_sent_count_o": 1}
        saved = _run_result(before, counters=counters)
        replay = _replay(self._package_for(saved), self.build,
                         _run_result(after, counters=counters))
        self.assertEqual(REPLAY_DIVERGENCE, replay.status, replay.reason)
        self.assertEqual(("peer_oracle:hash",), replay.mismatching_fields,
                         "the peer RTL revision must be the reported divergence")
        self.assertEqual("peer_oracle:hash", replay.divergence["field"])
        self.assertNotEqual(replay.divergence["expected"],
                            replay.divergence["observed"])

    def test_a_doctored_oracle_status_is_reported_by_replay(self) -> None:
        oracle = audit_run(uart_sent=0)          # a real mismatch, not an invented one
        self.assertEqual("mismatch", oracle["status"])
        honest = _run_result(oracle, counters={"peer.uart0.tx_sent_count_o": 0})
        tampered = json.loads(json.dumps(_result_document(honest)))
        self.assertEqual("mismatch", tampered["peer_oracle"]["status"])
        tampered["peer_oracle"]["status"] = "pass"
        package = _package(self.build, plan_hash=PLAN_HASH, layout_hash=LAYOUT_HASH,
                           saved_result=tampered)
        replay = _replay(package, self.build, honest)
        self.assertEqual(REPLAY_DIVERGENCE, replay.status, replay.reason)
        self.assertEqual(("peer_oracle:status",), replay.mismatching_fields)
        self.assertEqual("peer_oracle:status", replay.divergence["field"])
        self.assertEqual("pass", replay.divergence["expected"])
        self.assertEqual("mismatch", replay.divergence["observed"])

    def test_a_doctored_oracle_record_does_not_cover_its_own_hash(self) -> None:
        doctored = json.loads(json.dumps(audit_run()))
        doctored["checks"][0]["status"] = "mismatch"
        doctored["checks"][0]["observed"] = "invented"
        self.assertNotEqual(doctored["oracle_hash"],
                            _recompute_oracle_hash(doctored),
                            "the stored hash must not describe the doctored checks")


class DeletedWireTraceTests(unittest.TestCase):
    """Requirements 4 and 5: a trace that is gone is never a passing transfer."""

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(
            prefix=".myfuzz-soc-peer-wire-", dir=ROOT)
        self.addCleanup(self._temporary.cleanup)
        self.build = _fake_build(Path(self._temporary.name) / "build",
                                 plan_hash=PLAN_HASH, layout_hash=LAYOUT_HASH,
                                 build_hash=BUILD_HASH)

    def _audit(self, **overrides) -> dict[str, object]:
        build, sample, result = audit_inputs(**overrides)
        return audit_peer_run(build, sample, result)

    def test_a_deleted_wire_trace_is_not_assessed_and_never_a_pass(self) -> None:
        audit = self._audit(
            wire_trace=(),
            wire_status=({"instance_id": "spi0", "count": 0, "truncated": True},))
        self.assertFalse(
            [check for check in audit["checks"]
             if check["check_id"] == "spi-transfer-wire"],
            "a deleted wire trace must not produce a decided check")
        reasons = {str(item["check_id"]): str(item["reason"])
                   for item in audit["unassessed"]}
        self.assertIn("spi-transfer-wire", reasons, audit)
        self.assertIn("truncated", reasons["spi-transfer-wire"])

    def test_a_truncated_or_count_mismatched_trace_is_never_a_pass(self) -> None:
        complete = len(SPI_FRAME)
        cases = {
            "truncated-flag": ({"instance_id": "spi0", "count": complete,
                                "truncated": True},),
            "count-mismatch": ({"instance_id": "spi0", "count": complete - 1,
                                "truncated": False},),
            "no-status-row": (),
        }
        for label, status_rows in cases.items():
            with self.subTest(case=label):
                audit = self._audit(wire_status=status_rows)
                passing = [check for check in audit["checks"]
                           if check["check_id"] == "spi-transfer-wire"
                           and check["status"] == "pass"]
                self.assertFalse(passing, "an incomplete trace must never pass")
                self.assertTrue(any(str(item["check_id"]) == "spi-transfer-wire"
                                    for item in audit["unassessed"]), audit)

    def test_a_trace_deleted_package_never_yields_a_passing_wire_verdict(self) -> None:
        deleted_build, sample, deleted_result = audit_inputs(
            wire_trace=(),
            wire_status=({"instance_id": "spi0", "count": 0, "truncated": True},))
        deleted = _run_result(audit_peer_run(deleted_build, sample, deleted_result),
                              peer_wire_status=deleted_result.peer_wire_status)
        self.assertEqual(("not_assessed", None, None), spi_wire_verdict(deleted))
        good_build, good_sample, good_result = audit_inputs()
        good = _run_result(audit_peer_run(good_build, good_sample, good_result),
                           peer_wire_trace=SPI_FRAME,
                           peer_wire_status=good_result.peer_wire_status)
        self.assertEqual("pass", spi_wire_verdict(good)[0],
                         "the fixture does reach a pass; the deletion is what removes it")

    def test_a_truncated_wire_trace_blocks_the_package_level_confirmation(self) -> None:
        """The package's own consumer must not turn an incomplete trace into a pass."""
        build, sample, result = audit_inputs(
            wire_trace=(),
            wire_status=({"instance_id": "spi0", "count": 0, "truncated": True},))
        run = _run_result(audit_peer_run(build, sample, result),
                          peer_wire_status=result.peer_wire_status)
        self.assertEqual("not_assessed", spi_wire_verdict(run)[0])
        self.assertEqual(("component_candidate", "mutant-run-incomplete"),
                         _run_problem(run, "mutant"),
                         "an incomplete wire trace must stop the offline confirmation "
                         "instead of being judged")
        traced_build, traced_sample, traced_result = audit_inputs()
        complete = _run_result(audit_peer_run(traced_build, traced_sample, traced_result),
                               peer_wire_trace=SPI_FRAME,
                               peer_wire_status=traced_result.peer_wire_status)
        self.assertIsNone(_run_problem(complete, "mutant"),
                          "the same run with its trace present does proceed")

    def test_a_trace_deleted_package_cannot_replay_into_agreement(self) -> None:
        deleted = audit_run(
            wire_trace=(),
            wire_status=({"instance_id": "spi0", "count": 0, "truncated": True},))
        traced = audit_run()
        counters = {"peer.uart0.tx_sent_count_o": 1}
        saved = _run_result(deleted, counters=counters)
        rerun = _run_result(traced, counters=counters, peer_wire_trace=SPI_FRAME,
                            peer_wire_status=({"instance_id": "spi0",
                                               "count": len(SPI_FRAME),
                                               "truncated": False},))
        package = _package(self.build, plan_hash=PLAN_HASH, layout_hash=LAYOUT_HASH,
                           saved_result=_result_document(saved))
        replay = _replay(package, self.build, rerun)
        self.assertEqual(REPLAY_DIVERGENCE, replay.status, replay.reason)
        self.assertIn("peer_oracle:hash", replay.mismatching_fields)
        self.assertTrue(any(str(name).startswith("peer_wire_status:spi0")
                            for name in replay.mismatching_fields),
                        replay.mismatching_fields)


if __name__ == "__main__":
    unittest.main()
