"""Opt-in per-case advance budget that moves an IP admission's CPU acceptance
into a later case.

Software only: no RTL, no Verilator, no saved artifact.  The stub local
harnesses below reproduce exactly the facts the production runner consumes:

* GPIO B applies its ``gpio_in`` input to one synchroniser stage per local step
  and exposes the one-step-delayed value as its native ``irq`` output, which is
  the pinned PULP behaviour the causal GPIO profile authenticates;
* the CPU reports ``irq_taken_pre`` for the ``irq`` input it was handed.

Everything else is production code: the declared Ibex dual-source decoder (its
declared runtime paths, ownership, windows and instruction reservation), the
declared TCP bindings, the runner's own ``IrqPulseDelivery`` policy
(``irq_pulses={cpu.irq: 4}``), the session case machinery and the online source
provenance.  The case index carried by every event is therefore the real one and
not a stub claim.

Covered here:

* the shipped default budget is unchanged and the default decoder document
  carries no cross-case declaration;
* ``ip_cross_case=True`` declares a one-round budget for the declared external
  pin-8 source case only: a CPU instruction case keeps the full declared budget;
* with that option the real case boundary separates the injection half from the
  CPU acceptance half (different case indexes), the raised IRQ pulse is still
  pending at that boundary, no reset or cancel record exists, and the pulse is
  delivered by the next case;
* with the shipped default the same sequence accepts the interrupt inside the
  source case, so the separation is caused by the declaration and not by the
  stub;
* the host declaration is explicit, reachable from the frozen run script, and
  refuses an unknown or contradictory value instead of guessing.
"""

from __future__ import annotations

import json

import pytest

from myfuzz.integration.ibex_pulp_online import (
    IP_CROSS_CASE_DECLARATION_ENV, resolve_ip_cross_case,
)
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.ibex_pulp_dual_source import (
    DUAL_SOURCE_MEMORY_REGIONS,
    IP_CROSS_CASE_ADVANCE_SCHEMA_VERSION,
    IP_CROSS_CASE_RULE,
    PULP_GPIO_PROFILE_APERTURE,
    IpCrossCaseOnlineDecoder,
    make_ibex_pulp_dual_source_online_decoder,
)
from myfuzz.scenario.memory import PersistentMemory
from myfuzz.scenario.online_case_decoder import OnlineCaseDecoder
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner
from myfuzz.scenario.session_runtime import (ScenarioSession,
                                             replay_online_session)


PIN_SOURCE_ID = "gpio_b.external_pin8"
CPU_SOURCE_ID = "cpu.online_instruction"
IRQ_BINDING = Binding("gpio_b", "irq", "cpu", "irq", 1)
BOUND_LOW_BINDING = Binding("gpio_a", "gpio_out", "gpio_b", "gpio_in", 8)
#: Kinds the runner emits only when a pulse is cancelled or never delivered.
CANCEL_KINDS = frozenset(("reset_barrier", "gpio_reset_resource", "cpu_reset",
                          "pulse_cancelled_by_reset"))


class _StubBase:
    """The testcase lifecycle every local harness of this runner must answer."""

    def begin_case(self, testcase_id: str) -> None:
        self.testcase_id = testcase_id

    def end_case(self) -> None:
        pass


class _CpuStub(_StubBase):
    """CPU side: holds the declared RAM and MMIO router, answers the IRQ input.

    ``memory`` and ``router`` are the production resources the declared runtime
    path contract requires: a real :class:`PersistentMemory` over the declared
    region and a real :class:`DataflowRouter` over the two declared GPIO
    apertures, exactly as ``make_pulp_dual_source_factory`` builds them.  Only
    the local step is a stub.
    """

    def __init__(self, router: DataflowRouter) -> None:
        self.memory = PersistentMemory(
            regions=DUAL_SOURCE_MEMORY_REGIONS, initialization_seed=37,
            max_initialized_bytes=0x20000)
        self.router = router
        self.fragments: list[tuple[int, str, str]] = []
        self.steps = 0
        #: One interrupt per asserted input window, exactly as a real machine
        #: clears its global enable on trap entry.
        self.armed = True

    def declare_instruction_slots(self, address: int, count: int = 1) -> None:
        self.memory.declare_instruction_slots(address, count)

    def accept_instructions(self, address: int, data: bytes, *,
                            source_event_id: str) -> None:
        self.fragments.append((address, data.hex(), source_event_id))

    def step_local(self, inputs):
        self.steps += 1
        if not inputs.get("irq", 0) & 1:
            self.armed = True
            return {"irq_taken_pre": 0}
        taken = 1 if self.armed else 0
        self.armed = False
        return {"irq_taken_pre": taken}


class _GpioAStub(_StubBase):
    """GPIO A side: holds no state this path observes."""

    def __init__(self) -> None:
        self.memory = None
        self.steps = 0

    def step_local(self, inputs):
        self.steps += 1
        return {"gpio_out": inputs.get("gpio_out", 0)}


class _GpioBStub(_StubBase):
    """PULP GPIO B side: one synchroniser stage in front of its native IRQ."""

    def __init__(self) -> None:
        self.memory = None
        self.steps = 0
        self.sync0 = 0
        self.sync1 = 0
        self.applied: list[int] = []

    def step_local(self, inputs):
        self.steps += 1
        self.sync1 = self.sync0
        self.sync0 = (inputs.get("gpio_in", 0) >> 8) & 1
        self.applied.append(self.sync0)
        return {"irq": self.sync1, "gpio_in_sync": self.sync1 << 8}


def _decoder(*, ip_cross_case: bool = False):
    return make_ibex_pulp_dual_source_online_decoder(
        ip_cross_case=ip_cross_case)


def _no_findings(receipt):
    """The one checker both a live session and its replay are declared with."""
    return ()


def _runner_factory(decoder):
    """A fresh runner over fresh stub harnesses, as the live factory provides."""
    def factory() -> ScenarioRunner:
        a, b = _GpioAStub(), _GpioBStub()
        router = DataflowRouter((
            DeviceWindow("gpio_a", 0x40001000, PULP_GPIO_PROFILE_APERTURE, a),
            DeviceWindow("gpio_b", 0x40000000, PULP_GPIO_PROFILE_APERTURE, b)))
        return ScenarioRunner(
            sessions={"cpu": _CpuStub(router), "gpio_a": a, "gpio_b": b},
            ownership=decoder.ownership,
            bindings=(BOUND_LOW_BINDING, IRQ_BINDING),
            irq_pulses={IRQ_BINDING: 4})
    return factory


def _session(decoder):
    a, b = _GpioAStub(), _GpioBStub()
    router = DataflowRouter((
        DeviceWindow("gpio_a", 0x40001000, PULP_GPIO_PROFILE_APERTURE, a),
        DeviceWindow("gpio_b", 0x40000000, PULP_GPIO_PROFILE_APERTURE, b)))
    cpu = _CpuStub(router)
    runner = ScenarioRunner(
        sessions={"cpu": cpu, "gpio_a": a, "gpio_b": b},
        ownership=decoder.ownership,
        bindings=(BOUND_LOW_BINDING, IRQ_BINDING),
        irq_pulses={IRQ_BINDING: 4})
    template = ScenarioGenome(
        testcase_id="ip-cross-case-stub", direction="MULTI_COMPONENT_CHAIN",
        path_id="cpu-and-pin8-online-stream",
        schedule_order=("cpu", "gpio_a", "gpio_b"), max_steps=512, actions=())
    session = ScenarioSession(template, runner, checker=_no_findings)
    session.declare_instruction_slots("cpu", decoder.instruction_start,
                                      (decoder.instruction_end
                                       - decoder.instruction_start) // 4)
    session.configure_runtime_paths(decoder.graph, decoder.runtime_contract,
                                    decoder.runtime_paths,
                                    source_ownership=decoder.ownership)
    session.begin()
    return session, runner, cpu, b


def _decode(decoder, source_id: str, *, pin_value: int = 1):
    """Decode one input that the declared decoder really attributes to ``source_id``."""
    suffix = ":" + source_id
    direct = 0 if source_id == CPU_SOURCE_ID else 1
    for attempt in range(4096):
        raw = bytes((attempt & 0xFF, (attempt >> 8) & 0xFF, direct, pin_value,
                     (attempt >> 16) & 0xFF, 0, 0, 0))
        case = decoder.decode(raw)
        if case.source.action_id.endswith(suffix):
            return case
    raise AssertionError(f"no declared input selected {source_id}")


def _case_events(receipt) -> tuple[dict, ...]:
    return tuple(receipt.events)


def _events_of_kind(receipts, kind: str) -> list[tuple[int, dict]]:
    found = []
    for index, receipt in enumerate(receipts):
        for event in _case_events(receipt):
            if event.get("kind") == kind:
                found.append((index, event))
    return found


def _run_sequence(*, ip_cross_case: bool, sequence):
    """Submit one decoded case per entry.

    Returns the receipts, the runner's own delivered-pulse state observed
    immediately after each case closed (that is the state a case boundary leaves
    behind), and the live objects.
    """
    decoder = _decoder(ip_cross_case=ip_cross_case)
    session, runner, cpu, b = _session(decoder)
    receipts, boundaries = [], []
    for source_id, pin_value in sequence:
        case = _decode(decoder, source_id, pin_value=pin_value)
        receipts.append(session.submit_case(case))
        decoder.commit(case)
        pulse = runner._irq_pulses[IRQ_BINDING]
        boundaries.append((pulse.pending, pulse.source_level))
    return receipts, boundaries, cpu, b


def test_shipped_default_keeps_the_full_declared_budget():
    """The default decoder and the default identity are unchanged."""
    decoder = _decoder()
    assert len(decoder.advances) == 32
    assert "ip_cross_case" not in decoder.document()
    case = _decode(decoder, PIN_SOURCE_ID)
    assert case.source.component == "gpio_b"
    assert len(case.advances) == len(decoder.advances)
    assert tuple(case.advances[0].schedule) == ("cpu", "gpio_a", "gpio_b")


def test_ip_cross_case_declares_a_one_round_source_case():
    """Only the declared external source case loses rounds; the CPU case keeps them."""
    decoder = _decoder(ip_cross_case=True)
    document = decoder.document()
    assert document["advance_rounds"] == 32
    declaration = document["ip_cross_case"]
    assert declaration["schema_version"] == IP_CROSS_CASE_ADVANCE_SCHEMA_VERSION
    assert declaration["rule"] == IP_CROSS_CASE_RULE
    assert declaration["source_id"] == PIN_SOURCE_ID
    assert declaration["advance_rounds"] == 1
    assert declaration["declared_advance_rounds"] == 32

    source_case = _decode(decoder, PIN_SOURCE_ID)
    assert len(source_case.advances) == 1
    assert tuple(source_case.advances[0].schedule) == ("cpu", "gpio_a", "gpio_b")

    instruction_case = _decode(decoder, CPU_SOURCE_ID)
    assert len(instruction_case.advances) == len(decoder.advances)


def test_declared_source_case_never_accepts_its_own_interrupt():
    """The injection half and the CPU acceptance half land in different cases."""
    receipts, boundaries, cpu, b = _run_sequence(
        ip_cross_case=True,
        sequence=((PIN_SOURCE_ID, 1), (PIN_SOURCE_ID, 1), (CPU_SOURCE_ID, 0)))

    injection = _events_of_kind(receipts, "source_injection")
    assert len(injection) == 2
    assert [index for index, _ in injection] == [0, 1]
    for index, event in injection:
        assert event["provenance"]["observed_case"]["case_index"] == index
        assert event["component"] == "gpio_b" and event["bit_offset"] == 8

    # Neither source case accepted a CPU interrupt; the first one applied the
    # injected value in its own single declared round and nothing else.
    assert _events_of_kind(receipts[:2], "cpu_irq_input") == []
    assert _events_of_kind(receipts[:2], "cpu_irq_taken") == []
    assert b.applied[:2] == [1, 1]
    assert boundaries[0] == (False, 0)

    # The pulse is raised by the last declared step of the second source case,
    # so it is still pending when that case closes: it crossed the boundary
    # uncleared, and no reset or cancel record exists anywhere in the run.
    starts = _events_of_kind(receipts, "pulse_start")
    assert [index for index, _ in starts] == [1]
    assert boundaries[1] == (True, 1)
    assert [event for index, receipt in enumerate(receipts)
            for event in _case_events(receipt)
            if event.get("kind") in CANCEL_KINDS] == []

    # The next case's own CPU step is what accepts the pending pulse, and its
    # case index differs from the case the input was admitted and injected in.
    takes = _events_of_kind(receipts, "cpu_irq_taken")
    inputs = _events_of_kind(receipts, "cpu_irq_input")
    assert {index for index, _ in takes} == {2}
    assert {index for index, _ in inputs} == {2}
    assert takes[0][0] != injection[0][0]
    assert takes[0][1]["cpu_tick"] == starts[0][1]["start_cpu_tick"]

    # Structurally, no device step can observe a second source rise while that
    # pulse is pending: the very next local step after it is a CPU step, so the
    # pending window of this declaration contains no device step at all and the
    # runner's "unsupported_irq_overrun" failure mode cannot be introduced.
    events = [event for receipt in receipts for event in _case_events(receipt)]
    steps = [event for event in events
             if "inputs" in event and "outputs" in event]
    start_at = events.index(starts[0][1])
    following = next(event for event in events[start_at + 1:]
                     if "inputs" in event and "outputs" in event)
    assert following["component"] == "cpu"
    assert steps[-1]["component"] == "gpio_b"


def test_opted_in_plan_records_and_replays_the_shortened_case():
    """The per-case budget is part of the saved plan and replays unchanged."""
    decoder = _decoder(ip_cross_case=True)
    session, runner, cpu, b = _session(decoder)
    for source_id, pin_value in ((PIN_SOURCE_ID, 1), (PIN_SOURCE_ID, 1),
                                 (CPU_SOURCE_ID, 0)):
        case = _decode(decoder, source_id, pin_value=pin_value)
        session.submit_case(case)
        decoder.commit(case)
    reference = session.finish()
    plan = session.encode_plan()
    assert [len(item["advances"])
            for item in json.loads(plan)["cases"]] == [1, 1, 32]
    comparison = replay_online_session(
        plan, _runner_factory(decoder), reference, checker=_no_findings)
    assert comparison.matches is True, comparison.difference_context


def test_shipped_default_accepts_inside_the_source_case():
    """Negative control: without the declaration the halves share one case."""
    receipts, boundaries, cpu, b = _run_sequence(
        ip_cross_case=False,
        sequence=((PIN_SOURCE_ID, 1), (PIN_SOURCE_ID, 1), (CPU_SOURCE_ID, 0)))
    injection = _events_of_kind(receipts, "source_injection")
    takes = _events_of_kind(receipts, "cpu_irq_taken")
    assert [index for index, _ in injection] == [0, 1]
    assert {index for index, _ in takes} == {0}
    assert min(index for index, _ in takes) == injection[0][0]


def test_unknown_or_contradictory_host_declaration_is_refused(monkeypatch):
    monkeypatch.delenv(IP_CROSS_CASE_DECLARATION_ENV, raising=False)
    assert resolve_ip_cross_case(None) is False
    monkeypatch.setenv(IP_CROSS_CASE_DECLARATION_ENV, "1")
    assert resolve_ip_cross_case(None) is True
    monkeypatch.setenv(IP_CROSS_CASE_DECLARATION_ENV, "off")
    assert resolve_ip_cross_case(None) is False
    monkeypatch.setenv(IP_CROSS_CASE_DECLARATION_ENV, "maybe")
    with pytest.raises(ValueError):
        resolve_ip_cross_case(None)
    monkeypatch.setenv(IP_CROSS_CASE_DECLARATION_ENV, "0")
    with pytest.raises(ValueError):
        resolve_ip_cross_case(True)


def test_runtime_builder_forwards_the_declaration(monkeypatch, tmp_path):
    """The frozen run script's only seam reaches the decoder of the session.

    ``make_ibex_pulp_online_runtime`` renders the pinned harnesses (software
    only, cached under ``tmp_path``) and then assembles the shared online
    runtime, which would start real RTL processes.  That final assembly is
    replaced here, so this test observes exactly the declaration plumbing and
    no DUT: the decoder the runtime passes on is this policy's decoder when the
    host declared it, and the shipped decoder otherwise.
    """
    captured = {}

    def capture(**kwargs):
        captured.update(kwargs)
        return "runtime-not-started"

    import myfuzz.integration.ibex_pulp_online as online
    monkeypatch.setattr(online, "make_pulp_dual_source_online_runtime", capture)
    monkeypatch.setenv(IP_CROSS_CASE_DECLARATION_ENV, "1")
    online.make_ibex_pulp_online_runtime(cache_dir=tmp_path, run_id="declared")
    assert isinstance(captured["decoder"], IpCrossCaseOnlineDecoder)
    assert captured["decoder"].document()["ip_cross_case"]["source_id"] == PIN_SOURCE_ID
    captured.clear()
    monkeypatch.delenv(IP_CROSS_CASE_DECLARATION_ENV)
    online.make_ibex_pulp_online_runtime(cache_dir=tmp_path, run_id="shipped")
    assert type(captured["decoder"]) is OnlineCaseDecoder
