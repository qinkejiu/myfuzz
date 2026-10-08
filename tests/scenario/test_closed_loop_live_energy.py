"""Closed-loop certificate energy wired into live online source selection.

No RTL is started here. Two offline pieces stand in for the live runtime:

* the frozen :class:`~myfuzz.scenario.chain_certificates.ChainCertificates`
  producer over the hand-built journals of
  :mod:`tests.scenario.test_chain_certificates` (the same single source of
  truth used by ``test_closed_loop_feedback.py``), and
* a ``ScenarioSession`` double that appends those journal events to a real
  ``ScenarioRunner`` event log and returns the real ``OnlineCaseReceipt``
  shape, so the executor's own journal cursor, contiguity rule, decode path and
  receipt construction all run unchanged.

Every assertion about energy is an assertion about a real certificate identity:
the credited source is the certificate's declared ``source_id``, never a
neighbouring event. The switch is off by default, so the disabled path has to
reproduce the frozen pre-change weight formula value for value.
"""

from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
from pathlib import Path

import pytest

from myfuzz.integration.rfuzz_wire import InputBatch
from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
from myfuzz.scenario import chain_certificates
from myfuzz.scenario.chain_certificates import (
    CPU_TO_IP_TO_CPU,
    IP_TO_CPU_TO_IP,
    ChainCertificates,
    SCHEMA_VERSION as CERTIFICATE_SCHEMA_VERSION,
)
from myfuzz.scenario.closed_loop_feedback import (
    CERTIFIED,
    CLOSED_LOOP,
    FEEDBACK_SCHEMA_VERSION,
    STAGE_REACHED,
    DEFAULT_GAINS,
    EnergyGains,
    certificate_hit,
    edge_feature,
    failure_feature,
    hit_feature,
    transition_feature,
)
from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.ibex_pulp_dual_source import dual_source_ownership
from myfuzz.scenario.online_case_decoder import (
    OnlineCaseDecoder,
    OnlineDependencyGraph,
    OnlineDependencySource,
    OnlineSource,
)
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.rfuzz_decoder import DecoderTemplate, GenomeRecordDecoder
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.session_runtime import OnlineCaseReceipt, ScenarioSession
from tests.scenario.test_chain_certificates import (
    _Journal,
    _ip_journal,
    _merge,
    _pin8_admission,
    _provenance,
)


CPU = "cpu.online_instruction"
PIN = "gpio_b.external_pin8"
SCHEDULE = ("cpu", "gpio_a", "gpio_b")
ENV_SWITCH = "MYFUZZ_CLOSED_LOOP_ENERGY"
#: With equal baseline weights, raw[2] == 0 names the CPU source directly, so
#: the first slot selects the CPU path with reason ``direct_source_byte``.
SLOT0_RAW = bytes.fromhex("1700000000000000")
#: Under the frozen baseline this raw names the CPU source directly; under the
#: credited weights the weighted path selector moves to the pin-8 path.
FLIP_RAW = bytes.fromhex("0500000000000000")
#: A journal event the certificate producer ignores, so a stub step can present
#: a real, contiguous slice without claiming any hop.
NEUTRAL_STEP = ({"kind": "state_dependency"},)
#: Weight-sensitive over the full range of live weight states this file
#: reaches: the CPU source wins without credit, the pin source with it.
DESYNC_RAW = bytes.fromhex("3400000000000000")


# --------------------------------------------------------------------- setup


def _template() -> ScenarioGenome:
    return ScenarioGenome(testcase_id="closed-loop-stub", direction=IP_TO_CPU_TO_IP,
                          path_id="pin-path", schedule_order=SCHEDULE,
                          max_steps=512, actions=())


def _decoder() -> OnlineCaseDecoder:
    """The two frozen live source identities over a caller-declared graph."""
    graph = OnlineDependencyGraph(
        sources=(OnlineDependencySource(CPU, "instruction", "cpu",
                                        (CPU_TO_IP_TO_CPU,)),
                 OnlineDependencySource(PIN, "source", "gpio_b",
                                        (IP_TO_CPU_TO_IP,), port="gpio_in",
                                        bit_offset=8, width=1)),
        rules=(DependencyRule("cpu-path", (CPU,), "DATA_BINDING"),
               DependencyRule("pin-path", (PIN,), "DATA_BINDING")))
    return OnlineCaseDecoder(
        sources=(
            OnlineSource(CPU, "instruction", "cpu", CPU_TO_IP_TO_CPU, "cpu-path",
                         coverage_target_ids=("cpu_data_write",)),
            OnlineSource(PIN, "source", "gpio_b", IP_TO_CPU_TO_IP, "pin-path",
                         port="gpio_in", bit_offset=8, width=1,
                         coverage_target_ids=("gpio_b_irq",))),
        ownership=dual_source_ownership(), graph=graph, schedule=SCHEDULE,
        instruction_start=0x11000, instruction_end=0x12000, support_words=4,
        max_input_bytes=8)


class _StubSession(ScenarioSession):
    """One real session journal fed by synthetic case events.

    ``steps`` holds one event tuple per admitted case; an event without an
    explicit ``event_id`` receives the next contiguous journal identity, so an
    ordinary step can never fabricate a gap.
    """

    def __init__(self, runner, steps=(), prefix=()):
        super().__init__(_template(), runner)
        self._manifest_sha256 = hashlib.sha256(b"stub-session-manifest").hexdigest()
        self._manifest_document = {"schema_version": "online_session_manifest.v1",
                                   "stub": True}
        for event in prefix:
            runner._events.append(dict(event))
        self._steps = [tuple(step) for step in steps]
        self.finishes = 0

    def submit_case(self, case, *, source_role="fuzz_source"):
        start = self.runner.event_count
        ticks_before = dict(self.runner.local_ticks)
        for event in (self._steps.pop(0) if self._steps else ()):
            record = dict(event)
            record.setdefault("event_id", self.runner.event_count + 1)
            self.runner._events.append(record)
        return OnlineCaseReceipt(case.case_id, start, self.runner.event_count,
                                 self.runner.events_since(start), ticks_before,
                                 dict(self.runner.local_ticks), "running")

    def finish(self, *, defer_semantic_hash=False):
        from myfuzz.scenario.replay import ScenarioTrace
        self.finishes += 1
        return ScenarioTrace(self._manifest_sha256, "complete", self.runner.events,
                             dict(self.runner.local_ticks), "s" * 64,
                             self._manifest_sha256)

    def encode_plan(self):
        return b"stub-plan"


def _session(steps=(), prefix=()) -> _StubSession:
    runner = ScenarioRunner(sessions={name: object() for name in SCHEDULE},
                            ownership=dual_source_ownership(), bindings=())
    return _StubSession(runner, steps, prefix)


def _executor(steps=(), prefix=(), decoder=None, **kwargs) -> ScenarioRfuzzExecutor:
    return ScenarioRfuzzExecutor(
        run_id="closed-loop-energy", online_decoder=decoder or _decoder(),
        session=_session(steps, prefix), factory=lambda: None,
        targets=(CoverageTarget("gpio_b_irq", "gpio_b", "irq", 1, 1),
                 CoverageTarget("cpu_data_write", "cpu", "data_write", 1, 1)),
        **kwargs)


def _certified_ip_document():
    """One certified IP certificate, produced by the frozen producer."""
    producer = ChainCertificates()
    certificates = []
    for event in _ip_journal().events:
        certificates.extend(producer.ingest((event,)))
    assert [item["status"] for item in certificates] == [CERTIFIED]
    return certificates[0]


def _frozen_baseline_weights(executor) -> dict:
    """The pre-change ``_online_weights`` formula, copied verbatim.

    The disabled switch must reproduce this frozen formula value for value.
    """
    return {source.source_id: max(1, min(65536, round(
        source.weight * (8 + (64 if any(target not in executor._target_hits
                                       for target in source.coverage_target_ids) else 0)
                         + 32 / (executor._selection_uses[(0, index, source.source_id)] + 1)
                         + 16 * executor._selection_gains[(0, index, source.source_id)]
                         / (executor._selection_uses[(0, index, source.source_id)] + 1)))))
        for index, source in enumerate(executor.online_decoder.sources)}


def _journal() -> list:
    return [dict(event) for event in _ip_journal().events]


def _rebased_journal(prefix_events: int):
    """A certified journal whose whole identity space starts at 1.

    The builder renumbers every event and resolves every symbolic cross
    reference together, which is exactly what a real runner does when its
    bootstrap runs before the fuzz cases.
    """
    prefix = _Journal()
    for _ in range(prefix_events):
        prefix.add(None, {"kind": "state_dependency"})
    return [dict(event) for event in _merge(prefix, _ip_journal()).events]


def _run(executor, raws, *, buffer_id=1) -> None:
    executor.execute_batch(InputBatch(buffer_id, 8, tuple((raw,) for raw in raws)))


def _sources(executor) -> list:
    return [decision["source_id"] for decision in executor.online_decisions]


def _reasons(executor) -> list:
    return [decision["source_selection_reason"] for decision in executor.online_decisions]


def _canonical(document) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def _closed_loop(receipt) -> dict:
    document = receipt.closed_loop_feedback
    assert isinstance(document, dict), "every online receipt records the switch state"
    return document


def _expected_hit_id(certificate) -> str:
    """Independent copy of the documented hit identity formula."""
    payload = json.dumps(
        [FEEDBACK_SCHEMA_VERSION, CLOSED_LOOP, certificate["direction"],
         certificate["source_admission_id"],
         [[hop["hop_id"], hop["event_id"]] for hop in certificate["hops"]]],
        separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _append_neutral_event(executor) -> int:
    """Add one contiguous, hop-free journal event outside the session."""
    event_id = executor.session.runner.event_count + 1
    executor.session.runner._events.append({"event_id": event_id,
                                            "kind": "state_dependency"})
    return event_id


def _assert_credit_would_flip(executor, raw) -> None:
    """Control: the credited weight, and only it, moves this raw to the pin."""
    live = executor._online_weights()
    control = _decoder()
    case, _ = control.decode_candidate(
        raw, coverage_hints={**live, PIN: live[PIN] + DEFAULT_GAINS.closed_loop})
    assert case is not None and case.source.component == "gpio_b"


def _admission_step(case_index: int) -> tuple:
    """One open pin-8 admission: a candidate the producer must bound."""
    admission = _pin8_admission(case_index)
    return ({"kind": "source_admission", "admission": admission.document(),
             "provenance": _provenance(case_index, origin="known",
                                       admissions=[admission.admission_id])},)


class _ForgedProducer:
    """Emit a forged certificate once, then the genuine one."""

    def __init__(self, forged, genuine):
        self.forged = forged
        self.genuine = genuine
        self.calls = 0

    @property
    def pending_count(self) -> int:
        return 0

    def ingest(self, events):
        self.calls += 1
        return (self.forged,) if self.calls == 1 else (self.genuine,)

    def flush(self):
        return ()


class _ScriptedProducer:
    """Return one prepared certificate batch per ingest call."""

    def __init__(self, batches):
        self.batches = [tuple(batch) for batch in batches]
        self.calls = 0

    @property
    def pending_count(self) -> int:
        return 0

    def ingest(self, events):
        batch = self.batches.pop(0) if self.batches else ()
        self.calls += 1
        return batch

    def flush(self):
        return ()


def _single_slot_decoder() -> OnlineCaseDecoder:
    """One instruction source with exactly one reservation slot left."""
    graph = OnlineDependencyGraph(
        sources=(OnlineDependencySource(CPU, "instruction", "cpu",
                                        (CPU_TO_IP_TO_CPU,)),),
        rules=(DependencyRule("cpu-path", (CPU,), "DATA_BINDING"),))
    return OnlineCaseDecoder(
        sources=(OnlineSource(CPU, "instruction", "cpu", CPU_TO_IP_TO_CPU,
                              "cpu-path"),),
        ownership=dual_source_ownership(), graph=graph, schedule=SCHEDULE,
        instruction_start=0x11000, instruction_end=0x11004, support_words=0,
        max_input_bytes=8)


# ------------------------------------------------------- default-off contract


def test_default_switch_is_off_and_reproduces_the_frozen_weight_baseline(monkeypatch):
    monkeypatch.delenv(ENV_SWITCH, raising=False)
    default = _executor([_journal(), ()])
    explicit = _executor([_journal(), ()], closed_loop_energy=False)
    assert default.closed_loop_energy is False
    assert default.closed_loop_energy_source == "default"
    assert explicit.closed_loop_energy is False

    _run(default, (SLOT0_RAW, FLIP_RAW))
    _run(explicit, (SLOT0_RAW, FLIP_RAW))

    assert default._online_weights() == explicit._online_weights()
    assert default._online_weights() == _frozen_baseline_weights(default)
    assert _sources(default) == [CPU, CPU]
    assert _reasons(explicit) == ["direct_source_byte", "direct_source_byte"]
    for receipt in explicit.receipts:
        document = _closed_loop(receipt)
        assert document["enabled"] is False
        assert document["status"] == "disabled"
        assert document["counts"] == {"certificate_count": 0,
                                      "closed_loop_count": 0,
                                      "partial_propagation_count": 0,
                                      "stage_reached_count": 0}
        assert document["credited"] == {}
    # The very same journal certifies a chain when the frozen producer reads
    # it, so the disabled run refused to credit a real certificate rather than
    # merely failing to find one.
    assert _certified_ip_document()["status"] == CERTIFIED
    assert explicit.closed_loop_state()["counts"]["certificate_count"] == 0


def test_switch_requires_the_online_decoder_path():
    graph = DependencyGraph(
        sources=(FuzzableSource("a.pin", "a", "pin", 0, 1, ("IP_TO_IP",)),),
        rules=(DependencyRule("a.out", ("a.pin",), "ENV_PRECONDITION"),))
    ownership = compile_ownership(
        (InputField("a", "pin", 1),),
        (InputOwner("a", "pin", 0, 1, "source", "external"),))
    decoder = GenomeRecordDecoder(
        graph=graph, ownership=ownership,
        templates=(DecoderTemplate("a.out", ScenarioGenome(
            testcase_id="offline", direction="IP_TO_IP", path_id="a",
            schedule_order=("a",), max_steps=1, actions=())),))
    with pytest.raises(ValueError, match="online"):
        ScenarioRfuzzExecutor(
            run_id="offline", decoder=decoder, factory=lambda: None,
            targets=(CoverageTarget("a.out", "a", "out", 1, 1),),
            allow_legacy_search=True, closed_loop_energy=True)


def test_a_bootstrap_prefix_is_absorbed_before_the_first_case():
    """A session that already ran its bootstrap keeps one contiguous journal."""
    journal = _rebased_journal(3)
    on = _executor([journal[3:], ()], prefix=tuple(journal[:3]),
                   closed_loop_energy=True)
    assert on.closed_loop_state()["journal_cursor"] == 3
    _run(on, (SLOT0_RAW, FLIP_RAW))

    document = _closed_loop(on.receipts[0])
    assert document["journal"] == {"start": 3, "end": len(journal)}
    entry, = document["certificates"]
    assert entry["status"] == CERTIFIED
    # Every hop identity kept its real, rebased event id.
    assert entry["hops"][0] == ["pin8_admission", 5]
    assert entry["hops"][-1] == ["isr_padin_retirement", 31]
    assert document["credited"] == {PIN: DEFAULT_GAINS.closed_loop}
    assert on.closed_loop_state()["initial"]["counts"]["certificate_count"] == 0
    _assert_credit_would_flip(on, FLIP_RAW)
    assert on.online_decisions[1]["source_id"] == PIN


def test_switch_state_survives_a_pre_rtl_refusal():
    on = _executor([(), ()], decoder=_single_slot_decoder(),
                   closed_loop_energy=True)
    _run(on, (SLOT0_RAW, SLOT0_RAW), buffer_id=1)
    assert on.receipts[0].status == "complete"
    # The reservation is exhausted, so the second candidate never reaches RTL.
    assert on.receipts[1].status == "input_invalid"
    document = _closed_loop(on.receipts[1])
    assert document["enabled"] is True
    assert document["status"] == "not_observed"
    assert document["credited"] == {}
    assert on.closed_loop_state()["credit_totals"] == {}


def test_environment_switch_bridges_the_a_b_gate(monkeypatch):
    monkeypatch.setenv(ENV_SWITCH, "1")
    enabled = _executor(())
    assert enabled.closed_loop_energy is True
    assert enabled.closed_loop_energy_source == "environment"
    # An explicit constructor value always wins over the environment.
    assert _executor((), closed_loop_energy=False).closed_loop_energy is False

    monkeypatch.setenv(ENV_SWITCH, "0")
    assert _executor(()).closed_loop_energy is False

    monkeypatch.setenv(ENV_SWITCH, "maybe")
    with pytest.raises(ValueError, match=ENV_SWITCH):
        _executor(())


# ------------------------------------------------------ energy into selection


def test_certified_chain_credits_its_source_and_flips_the_next_selection():
    off = _executor([_journal(), ()], closed_loop_energy=False)
    on = _executor([_journal(), ()], closed_loop_energy=True)
    gain = DEFAULT_GAINS.closed_loop
    _run(off, (SLOT0_RAW,))
    _run(on, (SLOT0_RAW,))

    # Slot zero is identical: no certificate existed when it was selected.
    assert _sources(off) == _sources(on) == [CPU]
    assert _reasons(off) == _reasons(on) == ["direct_source_byte"]

    off_state = off._online_weights()
    on_state = on._online_weights()
    # Enabling the switch changes exactly one weight: the certificate's own
    # declared source. Every other value stays the frozen baseline.
    assert off_state == _frozen_baseline_weights(off)
    assert _frozen_baseline_weights(on) == off_state
    assert on_state[CPU] == off_state[CPU]
    assert on_state[PIN] == off_state[PIN] + gain

    # The published mutation hint consumes the same credited weights.
    hint = on.mutation_hint()
    assert hint["source_id"] == PIN
    assert hint["online_weights"] == on_state

    # The credited weight really decides the following slot's selection.
    _run(off, (FLIP_RAW,), buffer_id=2)
    _run(on, (FLIP_RAW,), buffer_id=2)
    assert _sources(off)[1] == CPU
    assert _reasons(off)[1] == "direct_source_byte"
    assert _sources(on)[1] == PIN
    assert _reasons(on)[1] == "feedback_weighted_legal_source"
    assert off.receipts[1].applied_sources == (CPU,)
    assert on.receipts[1].applied_sources == (PIN,)
    assert off.receipts[1].online_weights == off_state
    assert on.receipts[1].online_weights == {**off_state, PIN: off_state[PIN] + gain}
    # ... and the receipt that earned the credit names the weight it produced.
    assert _closed_loop(on.receipts[0])["source_weights"] == {
        PIN: off_state[PIN] + gain}


def test_receipt_document_records_recomputable_certificate_identity():
    certificate = _certified_ip_document()
    journal = _journal()
    on = _executor([journal, ()], closed_loop_energy=True)
    _run(on, (SLOT0_RAW, FLIP_RAW))

    document = _closed_loop(on.receipts[0])
    assert document["enabled"] is True
    assert document["status"] == "ok"
    assert document["schema_version"] == "online_closed_loop_feedback.v1"
    assert document["certificate_schema_version"] == CERTIFICATE_SCHEMA_VERSION
    assert document["feedback_schema_version"] == FEEDBACK_SCHEMA_VERSION
    assert document["counts"] == {"certificate_count": 1, "closed_loop_count": 1,
                                 "partial_propagation_count": 0,
                                 "stage_reached_count": 0}
    assert document["journal"] == {"start": 0, "end": len(journal)}
    assert document["energy_gains"] == asdict(DEFAULT_GAINS)
    assert document["producer"]["module"] == "myfuzz.scenario.chain_certificates"
    assert document["producer"]["sha256"] == hashlib.sha256(
        Path(chain_certificates.__file__).read_bytes()).hexdigest()

    entry, = document["certificates"]
    assert entry["certificate_id"] == certificate["certificate_id"]
    assert entry["status"] == CERTIFIED
    assert entry["direction"] == IP_TO_CPU_TO_IP
    assert entry["source_id"] == PIN
    assert entry["source_admission_id"] == certificate["source_admission_id"]
    assert entry["kind"] == CLOSED_LOOP
    assert entry["hops"] == [[hop["hop_id"], hop["event_id"]]
                             for hop in certificate["hops"]]
    assert entry["hit_id"] == _expected_hit_id(certificate)
    assert document["hit_ids"] == [entry["hit_id"]]
    # ``certificate_id`` is independently recomputable from the declared pair.
    payload = json.dumps([IP_TO_CPU_TO_IP, certificate["source_admission_id"]],
                         separators=(",", ":")).encode("utf-8")
    assert certificate["certificate_id"] == hashlib.sha256(payload).hexdigest()
    assert document["credited"] == {PIN: DEFAULT_GAINS.closed_loop}
    assert document["credit_totals"] == {PIN: DEFAULT_GAINS.closed_loop}
    assert document["evidence"] == [{
        "feature": f"{CLOSED_LOOP}:{IP_TO_CPU_TO_IP}:{PIN}", "keys": [PIN],
        "gain": DEFAULT_GAINS.closed_loop, "penalty": False}]
    assert document["deduplicated"] == []
    assert document["refusals"] == []
    assert document["desynchronized"] is None

    # The next slot observed no new certificate and kept the totals.
    second = _closed_loop(on.receipts[1])
    assert second["counts"]["certificate_count"] == 0
    assert second["counts"]["closed_loop_count"] == 0
    assert second["credited"] == {}
    assert second["credit_totals"] == {PIN: DEFAULT_GAINS.closed_loop}
    assert second["journal"] == {"start": len(journal), "end": len(journal)}

    # Two identical runs produce one canonical document.
    twin = _executor([_journal(), ()], closed_loop_energy=True)
    _run(twin, (SLOT0_RAW, FLIP_RAW))
    assert _canonical(_closed_loop(twin.receipts[0])) == _canonical(document)
    assert _canonical(twin.closed_loop_state()) == _canonical(on.closed_loop_state())


def test_explicit_attribution_routes_the_credit_to_a_live_source():
    certificate = _certified_ip_document()
    feature = hit_feature(certificate_hit(certificate))
    assert feature == f"{CLOSED_LOOP}:{IP_TO_CPU_TO_IP}:{PIN}"
    on = _executor([_journal(), ()], closed_loop_energy=True,
                   closed_loop_attribution={feature: [CPU]})
    _run(on, (SLOT0_RAW, FLIP_RAW))

    document = _closed_loop(on.receipts[0])
    assert document["credited"] == {CPU: DEFAULT_GAINS.closed_loop}
    baseline = _frozen_baseline_weights(on)
    assert on._online_weights()[CPU] == baseline[CPU] + DEFAULT_GAINS.closed_loop
    assert on._online_weights()[PIN] == baseline[PIN]


def test_explicit_gains_scale_the_credited_energy():
    gains = EnergyGains(closed_loop=32, stage_reached=1)
    on = _executor([_journal(), ()], closed_loop_energy=True,
                   closed_loop_gains=gains)
    _run(on, (SLOT0_RAW, FLIP_RAW))
    document = _closed_loop(on.receipts[0])
    assert document["energy_gains"] == asdict(gains)
    assert document["credited"] == {PIN: 32}
    assert on._online_weights()[PIN] == _frozen_baseline_weights(on)[PIN] + 32


def test_unknown_attribution_key_is_refused_and_never_scored():
    certificate = _certified_ip_document()
    feature = hit_feature(certificate_hit(certificate))
    on = _executor([_journal(), ()], closed_loop_energy=True,
                   closed_loop_attribution={feature: ["not.a.live.source"]})
    _run(on, (SLOT0_RAW, FLIP_RAW))

    document = _closed_loop(on.receipts[0])
    assert document["status"] == "refused"
    refusal, = document["refusals"]
    assert refusal["reason"] == "unknown_weight_key"
    assert refusal["detail"]["unknown_keys"] == ["not.a.live.source"]
    assert document["credited"] == {}
    assert document["credit_totals"] == {}
    # No dead weight key was invented, and no selection changed.
    assert set(on._online_weights()) == {CPU, PIN}
    assert on._online_weights() == _frozen_baseline_weights(on)
    assert on.online_decisions[1]["source_id"] == CPU


# ---------------------------------------------------------------- fail-closed


def test_non_contiguous_journal_is_refused_and_the_session_continues():
    on = _executor([(), ()], closed_loop_energy=True)
    _run(on, (SLOT0_RAW,))
    assert _closed_loop(on.receipts[0])["status"] == "ok"

    # A defective transport leaves a hole in the journal the producer reads.
    on.session.runner._events.append({"event_id": 9, "kind": "state_dependency"})
    _run(on, (DESYNC_RAW,), buffer_id=2)
    document = _closed_loop(on.receipts[1])
    assert document["status"] == "desynchronized"
    refusal, = document["refusals"]
    assert refusal["reason"] == "certificate_journal_not_contiguous"
    assert on.receipts[1].status == "complete"
    # Control: this raw is weight-sensitive — a credited pin would select it.
    _assert_credit_would_flip(on, DESYNC_RAW)
    # ... but with no credit every weight is the frozen baseline of the live
    # state and the session keeps selecting the CPU source.
    assert on._online_weights() == _frozen_baseline_weights(on)
    assert on.online_decisions[1]["source_id"] == CPU
    assert on.closed_loop_state()["credit_totals"] == {}
    assert on.closed_loop_state()["penalty_totals"] == {}

    # The session keeps admitting cases; the desynchronisation stays reported.
    _run(on, (DESYNC_RAW,), buffer_id=3)
    assert on.receipts[2].status == "complete"
    assert on.online_decisions[2]["source_id"] == CPU
    assert _closed_loop(on.receipts[2])["status"] == "desynchronized"
    assert on._online_weights() == _frozen_baseline_weights(on)
    assert on.closed_loop_state()["desynchronized"] is not None
    assert on.closed_loop_state()["credit_totals"] == {}


def test_forged_certificate_is_refused_and_a_later_one_is_still_credited():
    forged = deepcopy(_certified_ip_document())
    forged["hops"][3]["hop_id"] = "isr_padin_retirement_forged"
    producer = _ForgedProducer(forged, _certified_ip_document())
    on = _executor([NEUTRAL_STEP, NEUTRAL_STEP, NEUTRAL_STEP],
                   closed_loop_energy=True, closed_loop_producer=producer)
    _run(on, (SLOT0_RAW, SLOT0_RAW, FLIP_RAW))

    first = _closed_loop(on.receipts[0])
    assert first["status"] == "refused"
    refusal, = first["refusals"]
    assert refusal["reason"] == "certificate_refused"
    assert "hop_id" in refusal["detail"]["error"]
    assert first["credited"] == {} and first["credit_totals"] == {}
    assert on.receipts[0].status == "complete"
    assert on.online_decisions[1]["source_id"] == CPU  # nothing was scored

    second = _closed_loop(on.receipts[1])
    assert second["status"] == "ok"
    assert second["credited"] == {PIN: DEFAULT_GAINS.closed_loop}
    assert on.online_decisions[2]["source_id"] == PIN
    assert on.receipts[2].applied_sources == (PIN,)


def test_a_session_journal_that_does_not_start_at_one_is_refused_loudly():
    prefix = ({"event_id": 5, "kind": "state_dependency"},)
    with pytest.raises(ValueError, match="event_id 1"):
        _executor((), prefix=prefix, closed_loop_energy=True)
    # The disabled switch needs no journal premise: unchanged behaviour.
    disabled = _executor((), prefix=prefix, closed_loop_energy=False)
    assert disabled.closed_loop_energy is False
    _run(disabled, (SLOT0_RAW,))
    assert disabled.receipts[-1].status == "complete"
    assert _closed_loop(disabled.receipts[-1])["enabled"] is False


# ------------------------------------------------------------------ bounding


def test_expired_chain_is_scored_as_partial_propagation():
    # The terminal hop never arrives, so the chain only settles when it ages
    # out beyond the declared event gap -- an incomplete certificate that
    # proved a downstream consumer but not the declared terminal hop.
    journal = [dict(event) for event
               in _ip_journal().without("isr_padin_retirement").events]
    on = _executor([journal], closed_loop_energy=True,
                   closed_loop_max_event_gap=20)
    _run(on, (SLOT0_RAW,))

    document = _closed_loop(on.receipts[0])
    assert document["counts"] == {"certificate_count": 1, "closed_loop_count": 0,
                                 "partial_propagation_count": 1,
                                 "stage_reached_count": 0}
    entry, = document["certificates"]
    assert entry["status"] == "incomplete"
    assert entry["source_id"] == PIN
    # The last proven hop is downstream of the source's own stages, and the
    # declared terminal hop is absent: partial propagation, never a loop.
    assert entry["hops"][-1] == ["isr_padin_register_read", 22]
    assert "isr_padin_retirement" not in [hop[0] for hop in entry["hops"]]
    assert document["credited"] == {PIN: DEFAULT_GAINS.partial_propagation}


def test_duplicate_certificate_is_never_credited_twice():
    certificate = _certified_ip_document()
    producer = _ScriptedProducer([[certificate], [certificate], []])
    on = _executor([NEUTRAL_STEP, NEUTRAL_STEP, NEUTRAL_STEP],
                   closed_loop_energy=True, closed_loop_producer=producer)
    _run(on, (SLOT0_RAW, SLOT0_RAW, FLIP_RAW))
    assert _closed_loop(on.receipts[0])["credited"] == {
        PIN: DEFAULT_GAINS.closed_loop}
    assert _closed_loop(on.receipts[1])["credited"] == {}
    assert _closed_loop(on.receipts[1])["credit_totals"] == {
        PIN: DEFAULT_GAINS.closed_loop}
    assert _closed_loop(on.receipts[1])["duplicates"] == [
        certificate["certificate_id"]]
    assert on.closed_loop_state()["counts"]["closed_loop_count"] == 1
    assert on.closed_loop_state()["duplicate_count"] == 1


def test_reused_certificate_identity_with_different_evidence_is_refused():
    certificate = _certified_ip_document()
    forged = deepcopy(certificate)
    forged["hops"].pop()
    assert certificate_hit(forged)["certificate_id"] == certificate["certificate_id"]
    assert certificate_hit(forged)["hit_id"] != certificate_hit(certificate)["hit_id"]
    producer = _ScriptedProducer([[certificate], [forged], []])
    on = _executor([NEUTRAL_STEP, NEUTRAL_STEP, NEUTRAL_STEP],
                   closed_loop_energy=True, closed_loop_producer=producer)
    _run(on, (SLOT0_RAW, SLOT0_RAW, FLIP_RAW))

    assert _closed_loop(on.receipts[0])["credited"] == {
        PIN: DEFAULT_GAINS.closed_loop}
    document = _closed_loop(on.receipts[1])
    assert document["status"] == "refused"
    refusal, = document["refusals"]
    assert refusal["reason"] == "certificate_id_reused_with_different_evidence"
    assert document["credited"] == {}
    assert document["credit_totals"] == {PIN: DEFAULT_GAINS.closed_loop}
    # Exactly one credit stands: the forged reuse added nothing.
    assert on._online_weights()[PIN] == (
        _frozen_baseline_weights(on)[PIN] + DEFAULT_GAINS.closed_loop)


def test_slot_evidence_needs_explicit_attribution_and_penalises_failures():
    edge = {"kind": "bound_input_consumed", "source": "gpio_a", "target": "gpio_b"}
    transition = "memory:RAW:ram0"
    interaction = {"new_run_features": [edge_feature(edge), transition],
                   "delta_edges": [edge],
                   "state_transitions": {transition: 1}}

    # Without an attribution entry neither identity may move a weight.
    blind = _executor([NEUTRAL_STEP], closed_loop_energy=True)
    _run(blind, (SLOT0_RAW,))
    _append_neutral_event(blind)
    document = blind._closed_loop_step(interaction=interaction,
                                       failures=("dut_violation",))
    assert document["credited"] == {} and document["penalized"] == {}
    assert {item["reason"] for item in document["refusals"]} == {
        "unattributable_evidence"}
    assert {item["detail"]["feature"] for item in document["refusals"]} == {
        edge_feature(edge), transition, failure_feature("dut_violation")}

    # An explicit attribution is applied exactly, credit and penalty alike.
    seen = _executor([NEUTRAL_STEP], closed_loop_energy=True,
                     closed_loop_attribution={
                         edge_feature(edge): [CPU],
                         transition_feature(transition): [PIN],
                         failure_feature("dut_violation"): [CPU]})
    _run(seen, (SLOT0_RAW,))
    _append_neutral_event(seen)
    document = seen._closed_loop_step(interaction=interaction,
                                      failures=("dut_violation",))
    assert document["refusals"] == []
    assert {item["feature"]: (item["keys"], item["gain"], item["penalty"])
            for item in document["evidence"]} == {
        edge_feature(edge): ([CPU], DEFAULT_GAINS.new_edge, False),
        transition_feature(transition): (
            [PIN], DEFAULT_GAINS.new_state_transition, False),
        failure_feature("dut_violation"): (
            [CPU], DEFAULT_GAINS.failure_penalty, True)}
    # ``energy_weights`` applies credit and penalty additively against the
    # current weight, so the receipt records the net delta per source.
    penalty = DEFAULT_GAINS.failure_penalty - DEFAULT_GAINS.new_edge
    assert document["credited"] == {PIN: DEFAULT_GAINS.new_state_transition}
    assert document["penalized"] == {CPU: penalty}
    weights = seen._online_weights()
    baseline = _frozen_baseline_weights(seen)
    assert weights[CPU] == baseline[CPU] - penalty
    assert weights[PIN] == baseline[PIN] + DEFAULT_GAINS.new_state_transition
    assert weights[CPU] < baseline[CPU]  # a failure really lowered the weight


def test_terminal_settlement_is_reported_as_evidence_without_credit():
    steps = [_admission_step(index) for index in range(1, 4)]
    on = _executor(steps, closed_loop_energy=True)
    _run(on, (SLOT0_RAW,), buffer_id=1)
    _run(on, (SLOT0_RAW,), buffer_id=2)
    weights = on._online_weights()
    _, plan_hex = on._finish_online_session()
    assert plan_hex is None  # the stub session was never begun

    terminal = on.closed_loop_state()["terminal"]
    assert terminal is not None
    assert terminal["status"] == "terminal"
    assert terminal["counts"]["certificate_count"] == 2
    assert terminal["counts"]["stage_reached_count"] == 2
    assert terminal["pending_count"] == 0
    # A chain settled at the end of the journal can no longer decide a slot,
    # so it is retained as evidence and never credited.
    assert on._online_weights() == weights
    assert on.closed_loop_state()["credit_totals"] == {}


def test_live_row_and_report_expose_the_switch_and_the_credit():
    """The frozen live writer must carry the record an A/B gate reads."""
    row_keys = set(_live_dict_keys("persist_receipt", marker="run_id"))
    assert {"closed_loop_enabled", "closed_loop_status",
            "closed_loop_delta_counts", "closed_loop_certificate_ids",
            "closed_loop_source_credit", "closed_loop_credit_totals",
            "closed_loop_source_weights",
            "closed_loop_refusals"} <= row_keys
    report_keys = set(_live_dict_keys("_run_scenario_rfuzz_live",
                                      marker="source_action_gate"))
    assert "closed_loop_energy" in report_keys

    from myfuzz.integration.scenario_rfuzz_live import _closed_loop_energy_record
    on = _executor([_journal(), ()], closed_loop_energy=True)
    _run(on, (SLOT0_RAW, FLIP_RAW))
    record = _closed_loop_energy_record(on)
    assert record["schema_version"] == "online_closed_loop_state.v1"
    assert record["enabled"] is True and record["status"] == "active"
    assert record["source"] == "constructor"
    assert record["counts"]["closed_loop_count"] == 1
    assert record["credit_totals"] == {PIN: DEFAULT_GAINS.closed_loop}
    assert record["bounds"] == {"max_pending": 128, "max_event_gap": 4096}
    assert record["refusal_count"] == 0 and record["duplicates"] == []

    off = _executor([_journal(), ()])
    _run(off, (SLOT0_RAW,))
    disabled = _closed_loop_energy_record(off)
    assert disabled["enabled"] is False and disabled["status"] == "disabled"
    assert disabled["counts"] == {"certificate_count": 0, "closed_loop_count": 0,
                                  "partial_propagation_count": 0,
                                  "stage_reached_count": 0}
    assert disabled["credit_totals"] == {}


def _live_dict_keys(function_name: str, *, marker: str) -> tuple[str, ...]:
    """Read one frozen writer dictionary literal straight from its source."""
    import ast
    from myfuzz.integration import scenario_rfuzz_live
    tree = ast.parse(Path(scenario_rfuzz_live.__file__).read_text(encoding="utf-8"))
    function = next(node for node in ast.walk(tree)
                    if isinstance(node, ast.FunctionDef)
                    and node.name == function_name)
    for node in ast.walk(function):
        if not isinstance(node, ast.Dict):
            continue
        if any(isinstance(key, ast.Constant) and key.value == marker
               for key in node.keys):
            return tuple(key.value for key in node.keys)
    raise AssertionError(f"{function_name} dictionary with {marker!r} was not found")


def test_per_document_certificate_detail_is_bounded():
    steps = [tuple(_admission_step(index)[0] for index in range(1, 101))]
    on = _executor(steps, closed_loop_energy=True, closed_loop_max_pending=4)
    _run(on, (SLOT0_RAW,))

    document = _closed_loop(on.receipts[0])
    assert document["counts"]["certificate_count"] == 96
    assert len(document["certificates"]) == 64
    assert document["certificates_truncated"] == 32
    assert len(document["hit_ids"]) == 64
    # The counts stay complete; only the per-document detail is bounded.
    assert on.closed_loop_state()["counts"]["certificate_count"] == 96
    # ``energy_weights`` scores a feature identity once, so 96 identical
    # stage_reached hits for one source are one piece of evidence.
    assert on.closed_loop_state()["credit_totals"] == {
        PIN: DEFAULT_GAINS.stage_reached}
    assert on.closed_loop_state()["scored_features"] == 1
    assert document["evidence"] == [{
        "feature": f"{STAGE_REACHED}:{IP_TO_CPU_TO_IP}:{PIN}", "keys": [PIN],
        "gain": DEFAULT_GAINS.stage_reached, "penalty": False}]
    assert document["deduplicated"] == [
        f"{STAGE_REACHED}:{IP_TO_CPU_TO_IP}:{PIN}"] * 64
    assert document["deduplicated_truncated"] == 31


def test_bounded_producer_state_over_a_long_synthetic_sequence():
    steps = [_admission_step(index) for index in range(1, 121)]
    on = _executor(steps, closed_loop_energy=True,
                   closed_loop_max_pending=4, closed_loop_max_event_gap=6)
    for index in range(len(steps)):
        _run(on, (SLOT0_RAW,), buffer_id=index + 1)
        state = on.closed_loop_state()
        assert state["pending_count"] <= 4
        assert state["retained_certificates"] <= 4
        assert set(state["credit_totals"]) <= {CPU, PIN}
        assert state["desynchronized"] is None
        assert on.receipts[-1].status == "complete"

    state = on.closed_loop_state()
    assert state["counts"]["certificate_count"] > 4
    assert state["counts"]["stage_reached_count"] > 4
    assert state["counts"]["closed_loop_count"] == 0
    assert state["bounds"] == {"max_pending": 4, "max_event_gap": 6}
    assert state["refusal_count"] == 0
    assert state["credit_totals"] == {PIN: DEFAULT_GAINS.stage_reached}
    assert state["scored_features"] == 1
    assert on._online_weights()[PIN] > _frozen_baseline_weights(on)[PIN]

    # The feature is scored exactly once: every later settlement of the same
    # source-side chain is recorded as evidence and adds no energy.
    documents = [document for document in map(_closed_loop, on.receipts)
                 if document["evidence"]]
    assert documents[0]["credited"] == {PIN: DEFAULT_GAINS.stage_reached}
    assert all(document["evidence"] == [] for document in documents[1:])
    assert all(document["credited"] == {} for document in documents[1:])
    assert all(document["deduplicated"] for document in documents[1:])


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
