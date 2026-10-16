"""Assemble one reset-free OBI CPU and dual PULP GPIO RFuzz session.

Construction renders the pinned local harnesses once. ``begin`` starts their
real RTL processes once; subsequent RFuzz slots share those processes and RAM.
The returned objects also expose the full online plan for fresh replay.

The assembly, warm-up contract and saved-bundle replay order below are
CPU-agnostic: a caller supplies the already-resolved firmware bootstrap, online
decoder and factory, so a second CPU reuses them without a name branch.  The
``make_ibex_*`` and ``replay_ibex_*`` entry points keep the Ibex selection and
its published messages.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import hashlib
import os
from pathlib import Path
from typing import Callable

from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.ibex_pulp_online_checker import IbexPulpOnlineChecker
from myfuzz.scenario.ibex_pulp_dual_source import (
    declared_initial_ram_data_window,
    make_ibex_pulp_dual_source_factory,
    make_ibex_pulp_dual_source_online_decoder,
    make_ibex_pulp_dual_source_stream_bootstrap,
    make_pulp_dual_source_dynamic_binding_gate,
    GPIO_PROFILE, CAUSAL_GPIO_PROFILE,
)
from myfuzz.scenario.initial_ram_data import resolve_initial_ram_data_switch
from myfuzz.scenario.online_case_decoder import OnlineCaseDecoder
from myfuzz.scenario.event_journal import JsonlEventView, ZlibChunkEventView
from myfuzz.scenario.replay import ReplayComparison, ScenarioTrace
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.session_runtime import (OnlineCaseReceipt, ScenarioSession,
                                             replay_online_session)
from myfuzz.scenario.source_actions import InstructionSlotReservationGate

from myfuzz.scenario.rfuzz_decoder import RECORD_BYTES
from .scenario_rfuzz import ScenarioRfuzzExecutor
from .scenario_rfuzz_live import _verify_online_run_identity


#: The one host declaration that selects the opt-in per-case IP cross-case
#: budget.  ``scripts/run_ibex_pulp_online.py`` is a frozen published entry, so
#: the process environment is the only seam its callers have; the resolved value
#: is not a hidden default -- it is written into the saved
#: ``decoder_manifest.json`` by :class:`IpCrossCaseOnlineDecoder.document` and
#: therefore into the run identity.
IP_CROSS_CASE_DECLARATION_ENV = "MYFUZZ_IP_CROSS_CASE"
_IP_CROSS_CASE_TRUE = frozenset(("1", "true", "yes", "on"))
_IP_CROSS_CASE_FALSE = frozenset(("0", "false", "no", "off"))


def resolve_ip_cross_case(requested: bool | None = None) -> bool:
    """Resolve the opt-in IP cross-case declaration once, failing closed.

    ``requested`` is the explicit argument of
    :func:`make_ibex_pulp_online_runtime`; ``None`` means "not requested here",
    which is the shipped default. Unset, nothing below changes.  The environment
    variable is the declaration a caller of the frozen run script can make, and
    an unknown value, or a value that contradicts the explicit argument, raises
    instead of being rounded to a default.
    """
    if requested is not None and type(requested) is not bool:
        raise ValueError("ip_cross_case must be boolean or unset")
    raw = os.environ.get(IP_CROSS_CASE_DECLARATION_ENV)
    declared = None
    if raw is not None:
        value = raw.strip().lower()
        if value in _IP_CROSS_CASE_TRUE:
            declared = True
        elif value in _IP_CROSS_CASE_FALSE:
            declared = False
        else:
            raise ValueError(
                f"{IP_CROSS_CASE_DECLARATION_ENV} must be one of "
                f"{sorted(_IP_CROSS_CASE_TRUE | _IP_CROSS_CASE_FALSE)}, "
                f"not {raw!r}")
    if requested is None:
        return bool(declared)
    if declared is not None and declared is not requested:
        raise ValueError(
            f"ip_cross_case={requested} contradicts "
            f"{IP_CROSS_CASE_DECLARATION_ENV}={raw!r}")
    return requested


@dataclass(frozen=True)
class IbexPulpOnlineRuntime:
    """Running components plus their bounded, shared-buffer input adapter.

    The container is CPU-agnostic: the checker rules are keyed by component
    name and by the shared firmware addresses, so a second CPU on this wiring
    returns the same type without redefining the replay contract.
    """

    session: ScenarioSession
    decoder: OnlineCaseDecoder
    executor: ScenarioRfuzzExecutor
    factory: Callable[[], ScenarioRunner]
    custom_checker: bool = False

    @property
    def source_action_gate(self) -> InstructionSlotReservationGate | None:
        """The live cross-case prerequisite gate of this session, if enabled."""
        return getattr(self.session, "prerequisite_gate", None)

    def replay(self, reference: ScenarioTrace, *,
               checker: Callable[[OnlineCaseReceipt], tuple[str, ...]] | None = None
               ) -> ReplayComparison:
        """Re-run the complete admitted prefix with fresh CPU and IP RTL.

        Gate state is rebuilt for the fresh run. Trusted plans record each
        admission declaration; replay registers it against fresh actual RAM
        and slot witnesses before submitting the case. Saved decisions do not
        supply runtime authority.
        """
        if self.custom_checker and checker is None:
            raise ValueError("custom online checker needs a fresh replay checker")
        return replay_online_session(
            self.session.encode_plan(), self.factory, reference,
            checker=checker if checker is not None else IbexPulpOnlineChecker())


def _saved_cpu_retirement_mode(output: Path, verified_identity: dict | None) -> bool:
    if verified_identity is None:
        return False
    raw = (Path(output) / 'online_session_manifest.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != verified_identity['artifacts']['online_session_manifest.json']:
        raise ValueError('saved CPU profile manifest changed after verification')
    manifest = json.loads(raw)
    return 'cpu_observation_schema_version' in manifest['runner']['sessions']['cpu']['identity']


def _saved_pin8_native_irq_mode(output: Path, verified_identity: dict | None) -> bool:
    """Select native CPU receipts only from a verified saved run identity."""
    if verified_identity is None:
        return False
    from myfuzz.local_harness.ibex_irq_receipt_contract import validate_ibex_irq_receipt_contract
    root = Path(output).resolve()
    path = root / 'online_session_manifest.json'
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
        raise ValueError('saved native IRQ manifest path mismatch')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != verified_identity['artifacts']['online_session_manifest.json']:
        raise ValueError('saved native IRQ manifest changed after verification')
    try:
        identity = json.loads(raw)['runner']['sessions']['cpu']['identity']
        if type(identity) is not dict:
            raise ValueError('saved native IRQ identity is malformed')
        if 'cpu_native_irq_receipt_contract' not in identity:
            return False
        if identity.get('cpu_observation_schema_version') != 'ibex_rvfi_observation.v1':
            raise ValueError('saved native IRQ receipts require RVFI')
        validate_ibex_irq_receipt_contract(identity['cpu_native_irq_receipt_contract'])
    except (KeyError, TypeError) as exc:
        raise ValueError('saved native IRQ identity is malformed') from exc
    return True



def _saved_gpio_consumption_mode(output: Path, verified_identity: dict | None) -> bool:
    """Select only coherent GPIO identities from the already verified bundle.

    Recheck the raw artifact hash before reading any saved profile selector;
    strict source/runtime/build identity admission is frontend work, not an
    RTL build. Historical bundles without the authenticated envelope stay on
    the legacy GPIO profile.
    """
    if verified_identity is None:
        return False
    from myfuzz.local_harness.pulp_gpio_probe_contract import pulp_gpio_observation_contract
    from myfuzz.scenario.contracts import _verify_generated_session
    output = Path(output).resolve()
    path = output / 'online_session_manifest.json'
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(output):
        raise ValueError('saved GPIO profile manifest path mismatch')
    raw = path.read_bytes()
    artifacts = verified_identity.get('artifacts') if isinstance(verified_identity, dict) else None
    if (not isinstance(artifacts, dict) or hashlib.sha256(raw).hexdigest()
            != artifacts.get('online_session_manifest.json')):
        raise ValueError('saved GPIO profile manifest changed after verification')
    try:
        manifest = json.loads(raw)
        sessions = manifest['runner']['sessions']
        identities = [sessions[component]['identity'] for component in ('gpio_a', 'gpio_b')]
        modes = []
        for component, identity in zip(('gpio_a', 'gpio_b'), identities):
            observed = 'gpio_observation_contract' in identity
            if observed:
                if (identity.get('gpio_target_context_schema_version') != 'pulp_gpio_routed_access.v1'
                        or identity['gpio_observation_contract'] != pulp_gpio_observation_contract()):
                    raise ValueError('saved GPIO observation contract mismatch')
            elif 'gpio_target_context_schema_version' in identity:
                raise ValueError('saved GPIO observation contract is missing')
            document = identity['runtime_artifact']
            plan = document['plan']
            if (document['kind'] != 'apb_gpio'
                    or plan['instance_id'] != component
                    or plan['component_id'] != ('pulp_gpio_causal_local' if observed else 'pulp_gpio')
                    or plan['profile_path'] != (CAUSAL_GPIO_PROFILE if observed else GPIO_PROFILE)):
                raise ValueError('saved GPIO observation profile mismatch')
            modes.append(observed)
        if modes[0] != modes[1]:
            raise ValueError('saved GPIO observation profiles are incoherent')
    except (KeyError, TypeError) as exc:
        raise ValueError('saved GPIO component identities are missing or malformed') from exc
    for identity in identities:
        _verify_generated_session(identity)
    return modes[0]


def _saved_memory_commit_mode(output: Path, verified_identity: dict | None) -> bool:
    """Read the saved host-memory commit-stream mode after manifest verification.

    A saved bundle that does not declare the observation stays on the default-off
    mode, so historical bundles remain replayable; a malformed or changed
    declaration is refused instead of being silently downgraded.
    """
    if verified_identity is None:
        return False
    output = Path(output).resolve()
    path = output / 'online_session_manifest.json'
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(output):
        raise ValueError('saved memory commit manifest path mismatch')
    raw = path.read_bytes()
    artifacts = verified_identity.get('artifacts') if type(verified_identity) is dict else None
    if (type(artifacts) is not dict or hashlib.sha256(raw).hexdigest()
            != artifacts.get('online_session_manifest.json')):
        raise ValueError('saved memory commit manifest changed after verification')
    try:
        sessions = json.loads(raw)['runner']['sessions']
        if type(sessions) is not dict:
            raise ValueError('saved runner sessions must be an object')
        session = sessions.get('cpu')
        if session is None:
            # A bundle that does not even declare a CPU session cannot have
            # declared this observation; the shared replay entry also serves
            # saved bundles of the second CPU of this wiring.
            return False
        if type(session) is not dict:
            raise ValueError('saved CPU session must be an object')
        identity = session.get('identity')
        if type(identity) is not dict:
            raise ValueError('saved CPU identity must be an object')
        if 'memory_commit_stream' not in identity:
            return False
        contract = identity['memory_commit_stream']
        if (type(contract) is not dict
                or set(contract) != {'schema_version', 'capacity'}
                or contract['schema_version'] != 'memory_write_commit_stream.v1'
                or type(contract['capacity']) is not int or contract['capacity'] != 256):
            raise ValueError('saved memory commit stream contract mismatch')
        return True
    except (KeyError, TypeError) as exc:
        raise ValueError('saved CPU memory commit mode is malformed') from exc


def _saved_persistent_memory_mode(output: Path, verified_identity: dict | None) -> str | None:
    """Select the exact trusted factory configuration from verified bytes only."""
    if verified_identity is None:
        return None
    output = Path(output).resolve()
    path = output / 'online_session_manifest.json'
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(output):
        raise ValueError('saved persistent memory manifest path mismatch')
    raw = path.read_bytes()
    artifacts = verified_identity.get('artifacts') if type(verified_identity) is dict else None
    if (type(artifacts) is not dict or hashlib.sha256(raw).hexdigest()
            != artifacts.get('online_session_manifest.json')):
        raise ValueError('saved persistent memory manifest changed after verification')
    from myfuzz.scenario.ibex_pulp_dual_source import (
        make_pulp_dual_source_source_action_gate, pulp_live_memory_policy_declaration,
        result_slot_ram_location, dual_source_wiring, CPU_PROFILE)
    import re
    try:
        document = json.loads(raw)
        runner = document['runner']
        if type(runner) is not dict:
            raise ValueError('invalid saved persistent memory runner')
        if 'persistent_memory_prerequisites' not in runner:
            return None
        configuration = runner['memory_dependency_evidence']
        contract = configuration['runtime_contract_sha256']
        if type(contract) is not str or re.fullmatch('[0-9a-f]{64}', contract) is None:
            raise ValueError('invalid saved persistent memory contract')
        if document['runtime_paths']['contract_sha256'] != contract:
            raise ValueError('saved persistent memory runtime contract mismatch')
        component = dual_source_wiring(cpu_profile=CPU_PROFILE).memory_component
        expected_evidence = dict(schema_version='memory_dependency_configuration.v1',
            runtime_contract_sha256=contract, components=[component], max_records=256,
            max_writer_versions=4096, max_event_gap=4096)
        memory_id, offset = result_slot_ram_location()
        expected_gate = dict(schema_version='persistent_memory_prerequisite_configuration.v1',
            max_actions=256,
            instruction_slot_policy=make_pulp_dual_source_source_action_gate(component=component).declaration(),
            dynamic_ram_policy=pulp_live_memory_policy_declaration(component=component,
                memory_id=memory_id, byte_offset=offset))
        canonical = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'))
        if (canonical(configuration) != canonical(expected_evidence)
                or canonical(runner['persistent_memory_prerequisites']) != canonical(expected_gate)):
            raise ValueError('unsupported saved persistent memory policy')
        identity = runner['sessions'][component]['identity']
        if (canonical(identity['memory_commit_stream']) != canonical(dict(
                schema_version='memory_write_commit_stream.v1', capacity=256))
                or canonical(identity['memory_read_issuance']) != canonical(dict(
                    schema_version='memory_read_authority.v1', capacity=256))):
            raise ValueError('saved persistent memory authorities mismatch')
        return contract
    except (KeyError, TypeError) as exc:
        raise ValueError('saved persistent memory configuration incomplete') from exc


def replay_pulp_dual_source_online_files(
        *, cache_dir: Path, plan_path: Path, trace_path: Path,
        factory_builder: Callable[..., Callable[[], ScenarioRunner]]
        ) -> ReplayComparison:
    """Replay saved live evidence against fresh dual-source RTL processes.

    The exact saved plan bytes are hashed against the trace before a harness is
    started. The live campaign's default checker is recreated from scratch.
    Campaigns using a custom checker must call ``replay_online_session`` with
    an equivalent fresh checker instead.

    ``factory_builder`` is the saved-bundle-aware factory of the CPU that
    produced the bundle; the authentication and selection order below is
    shared, so a bundle whose saved identity selects an observation the CPU
    cannot provide fails in that factory instead of being downgraded here.
    Every opt-in observation is re-selected from the *verified* saved identity,
    and each option is only forwarded when the bundle declares it, so a builder
    that does not accept it (the second CPU of this shared wiring) is never
    handed a keyword it cannot take.
    """
    plan = Path(plan_path).read_bytes()
    trace_path = Path(trace_path)
    document = json.loads(trace_path.read_bytes())
    if not isinstance(document, dict):
        raise ValueError("invalid saved online trace")
    if document.get("schema_version") == "online_trace_jsonl.v1":
        expected = {"schema_version", "events_file", "event_count",
                    "genome_sha256", "status", "local_ticks",
                    "semantic_sha256", "manifest_sha256"}
        if set(document) != expected or document["events_file"] != "online_events.jsonl":
            raise ValueError("invalid saved online JSONL trace metadata")
        document["events"] = JsonlEventView(
            trace_path.parent / document.pop("events_file"),
            document.pop("event_count"))
        document.pop("schema_version")
    elif document.get("schema_version") == "online_trace_zlib_chunks.v1":
        expected = {"schema_version", "events_file", "event_count",
                    "genome_sha256", "status", "local_ticks",
                    "semantic_sha256", "manifest_sha256"}
        if set(document) != expected or document["events_file"] != "online_events.zlib":
            raise ValueError("invalid saved compressed online trace metadata")
        view = ZlibChunkEventView(
            trace_path.parent / document.pop("events_file"),
            document.pop("event_count"))
        view.verify_trace_semantic(status=document["status"],
                                   local_ticks=document["local_ticks"],
                                   expected_sha256=document["semantic_sha256"])
        document["events"] = view
        document.pop("schema_version")
    elif set(document) != {"genome_sha256", "status", "events", "local_ticks",
                            "semantic_sha256", "manifest_sha256"}:
        raise ValueError("invalid saved online trace")
    if not isinstance(document["events"], (list, JsonlEventView,
                                           ZlibChunkEventView)) or not isinstance(
            document["local_ticks"], dict):
        raise ValueError("invalid saved online trace events or ticks")
    reference = ScenarioTrace(**document)
    verified_identity = _verify_online_run_identity(
        trace_path.parent, plan_path=Path(plan_path), trace_path=trace_path,
        trace=reference)
    cpu_retirement = _saved_cpu_retirement_mode(trace_path.parent, verified_identity)
    gpio_consumption = _saved_gpio_consumption_mode(trace_path.parent, verified_identity)
    native_irq_receipts = _saved_pin8_native_irq_mode(trace_path.parent, verified_identity)
    memory_commit_receipts = _saved_memory_commit_mode(trace_path.parent,
                                                       verified_identity)
    persistent_memory_contract = _saved_persistent_memory_mode(trace_path.parent, verified_identity)
    return replay_online_session(
        plan, factory_builder(Path(cache_dir),
            cpu_retirement=cpu_retirement, gpio_consumption=gpio_consumption,
            **({'native_irq_receipts': True} if native_irq_receipts else {}),
            **({'persistent_memory_runtime_contract_sha256': persistent_memory_contract,
                'source_actions': True} if persistent_memory_contract is not None else {}),
            **({'memory_commit_receipts': True} if memory_commit_receipts else {})),
        reference, checker=IbexPulpOnlineChecker())


def replay_ibex_pulp_online_files(*, cache_dir: Path, plan_path: Path,
                                  trace_path: Path) -> ReplayComparison:
    """The Ibex instance of the shared saved-bundle replay entry."""
    return replay_pulp_dual_source_online_files(
        cache_dir=cache_dir, plan_path=plan_path, trace_path=trace_path,
        factory_builder=make_ibex_pulp_dual_source_factory)


def _declared_source_action_gate(bootstrap, decoder: OnlineCaseDecoder
                                 ) -> InstructionSlotReservationGate:
    """The shipped slot policy for a session whose factory declares none.

    The policy window is the bootstrap's declared online instruction
    reservation and its component is the one instruction source the decoder
    declares; nothing is guessed from a component name literal.  The gate is
    the same adapter a factory-declaring session gets
    (:func:`make_pulp_dual_source_dynamic_binding_gate`): the shipped slot
    reservation plus the declared result-slot RAM byte binding, over the one
    tracker both policies read.
    """
    components = sorted({source.component for source in decoder.sources
                         if source.kind == "instruction"})
    if len(components) != 1:
        raise ValueError(
            "shipped source-action policy requires exactly one declared "
            "instruction source")
    return make_pulp_dual_source_dynamic_binding_gate(
        component=components[0], instruction_start=bootstrap.instruction_start,
        instruction_end=bootstrap.instruction_end)


def make_pulp_dual_source_online_runtime(
        *, bootstrap, decoder: OnlineCaseDecoder,
        factory: Callable[[], ScenarioRunner], run_id: str,
        evidence_dir: Path | None = None,
        checker: Callable[[OnlineCaseReceipt], tuple[str, ...]] | None = None,
        feedback_interval: int = 16,
        max_warmup_rounds: int = 1024,
        prerequisite_gate: InstructionSlotReservationGate | None = None,
        source_actions: bool = False,
        initial_ram_data: bool | None = None,
        initial_ram_record: bytes | None = None,
        candidate_exploration: bool = False,
        candidate_exploration_max_cases: int = 65536,
        classified_feedback: bool = False,
        classified_feedback_max_records: int = 4096,
        closed_loop_energy: bool | None = None,
        path_switch: bool | None = None,
        initial_ram_data_resolution: tuple[bool, str] | None = None) -> IbexPulpOnlineRuntime:
    """Start one real RTL session; caller feeds many RFuzz slots until stop.

    The caller supplies the firmware bootstrap, its online decoder and the
    factory, so no component name is inspected here. The probes below are
    local coverage milestones. A complete cross-component chain requires
    witnessed interaction edges and checker assessment, not one probe bit. The
    fixed bootstrap/ISR remains immutable during the stream.

    ``source_actions`` attaches the shipped cross-case prerequisite gate to the
    session (and therefore to the executor, which discovers it): either the
    explicit ``prerequisite_gate``, or the factory's declared
    ``new_source_action_gate()`` when the factory exposes one.  The shipped gate
    is the adapter of both policies (slot reservation plus the declared
    result-slot RAM byte binding), so the executor, the live report and the
    session all observe that one object.  The gate is
    created once per session, so no gate state or reservation is ever shared
    between runners and none of it enters the session manifest identity.  With
    both switches off the session is the explicitly declared legacy path: no
    gate, no per-case action and no ``source_action`` receipt field.

    ``initial_ram_data`` is the opt-in pre-session initial RAM data operator.
    It is resolved by
    :func:`myfuzz.scenario.initial_ram_data.resolve_initial_ram_data_switch`
    (explicit argument, else ``MYFUZZ_INITIAL_RAM_DATA``, else off) and, when it
    was declared at all, runs once *before* ``session.begin()``: the declared
    byte becomes one more initial image of the session template, so the session
    manifest, the decoder manifest and every candidate identity are untouched,
    and the saved plan carries the mutated byte for a fresh replay.
    ``initial_ram_record`` is the raw pre-session record the draw is derived
    from; the live CLI passes the same eight bytes it gives the RFuzz client as
    its seed, which the run stores verbatim in ``seed.bin``.
    """
    _validate_candidate_options(candidate_exploration, candidate_exploration_max_cases)
    if type(classified_feedback) is not bool or type(classified_feedback_max_records) is not int or not 1 <= classified_feedback_max_records <= 65536:
        raise ValueError('classified feedback options invalid')
    if type(max_warmup_rounds) is not int or max_warmup_rounds < 1:
        raise ValueError("max_warmup_rounds must be positive")
    if type(source_actions) is not bool:
        raise ValueError("source_actions must be boolean")
    for name, value in (('closed_loop_energy', closed_loop_energy), ('path_switch', path_switch)):
        if value is not None and type(value) is not bool:
            raise ValueError(name + ' must be boolean')
    if initial_ram_data_resolution is None:
        initial_ram_enabled, initial_ram_source = resolve_initial_ram_data_switch(
            initial_ram_data, online=True)
    else:
        if (type(initial_ram_data_resolution) is not tuple
                or len(initial_ram_data_resolution) != 2
                or type(initial_ram_data_resolution[0]) is not bool
                or type(initial_ram_data_resolution[1]) is not str
                or initial_ram_data_resolution[1] not in ('default', 'constructor', 'environment')
                or initial_ram_data_resolution == (True, 'default')
                or initial_ram_data is not None):
            raise ValueError('invalid resolved initial RAM declaration')
        initial_ram_enabled, initial_ram_source = initial_ram_data_resolution
    if initial_ram_record is None:
        initial_ram_record = bytes(RECORD_BYTES)
    if not isinstance(initial_ram_record, bytes) or not initial_ram_record:
        raise ValueError("initial RAM data requires a nonempty raw record")
    runner = factory()
    trusted_gate = getattr(runner, 'persistent_memory_prerequisite_gate', None)
    if trusted_gate is not None:
        if prerequisite_gate is not None and prerequisite_gate is not trusted_gate:
            raise ValueError('online runtime must use the installed trusted prerequisite gate')
        prerequisite_gate = trusted_gate
    if prerequisite_gate is None and source_actions:
        declared = getattr(factory, "new_source_action_gate", None)
        if callable(declared):
            prerequisite_gate = declared()
        else:
            # A factory without the declared policy still gets the shipped
            # window, so a caller-supplied factory cannot silently drop it.
            prerequisite_gate = _declared_source_action_gate(bootstrap, decoder)
    session = ScenarioSession(
        bootstrap.template, runner, checker=checker if checker is not None else IbexPulpOnlineChecker(),
        prerequisite_gate=prerequisite_gate,
        **({'checker_configuration_only': True} if candidate_exploration or classified_feedback else {}))
    session.declare_instruction_slots(
        "cpu", bootstrap.instruction_start, bootstrap.instruction_count)
    session.configure_runtime_paths(decoder.graph, decoder.runtime_contract,
                                    decoder.runtime_paths, source_ownership=decoder.ownership)
    targets = (
        CoverageTarget("gpio_a_output_bit0", "gpio_a", "gpio_out", 1, 1),
        CoverageTarget("gpio_b_irq", "gpio_b", "irq", 1, 1),
        CoverageTarget("cpu_external_irq_vector_fetch", "cpu", "instr_addr",
                       0xffffffff, 0x1012c),
        CoverageTarget("cpu_data_write", "cpu", "data_write", 1, 1),
    )
    if candidate_exploration or classified_feedback:
        # Full actual-runner admission before begin/preload/bootstrap. This
        # object executes nothing and its scoring state is discarded; the
        # returned executor below starts afresh after the completed bootstrap.
        ScenarioRfuzzExecutor(run_id=run_id, online_decoder=decoder, session=session,
            factory=factory, targets=targets, feedback_interval=feedback_interval,
            candidate_exploration=candidate_exploration,
            classified_feedback=classified_feedback,
            classified_feedback_max_records=classified_feedback_max_records,
            candidate_exploration_max_cases=candidate_exploration_max_cases,
            closed_loop_energy=False, path_switch=False)
    if initial_ram_source != "default":
        # The operator was declared: it runs before the session starts, and a
        # disabled declaration still states itself in the run's own report.
        session.mutate_initial_ram_data(
            declaration=declared_initial_ram_data_window(bootstrap),
            raw=initial_ram_record, enabled=initial_ram_enabled,
            source=initial_ram_source)
    try:
        session.begin()
        for _ in range(max_warmup_rounds):
            if (session.runner.sessions["cpu"].waiting_instruction_address
                    == bootstrap.instruction_start):
                break
            receipt = session.advance_initial(bootstrap.template.schedule_order)
            if receipt.violations or receipt.status != "running":
                raise RuntimeError("fixed dual-source bootstrap stopped before online fetch")
        else:
            raise RuntimeError("fixed dual-source bootstrap did not reach online instruction slot")
        executor = ScenarioRfuzzExecutor(
            run_id=run_id, online_decoder=decoder, session=session,
            factory=factory, targets=targets, evidence_dir=evidence_dir,
            feedback_interval=feedback_interval,
            **({'closed_loop_energy': closed_loop_energy} if closed_loop_energy is not None else {}),
            **({'path_switch': path_switch} if path_switch is not None else {}),
            **({'candidate_exploration': True,
                'candidate_exploration_max_cases': candidate_exploration_max_cases}
               if candidate_exploration else {}),
            **({'classified_feedback': True, 'classified_feedback_max_records': classified_feedback_max_records}
               if classified_feedback else {}))
    except BaseException:
        try:
            session.finish()
        except Exception:
            pass
        raise
    return IbexPulpOnlineRuntime(session, decoder, executor, factory,
                                checker is not None)


def _validate_candidate_options(enabled, max_cases):
    if type(enabled) is not bool:
        raise ValueError('candidate exploration must be boolean')
    if type(max_cases) is not int or not 1 <= max_cases <= 65536:
        raise ValueError('candidate exploration max cases must be 1..65536')


def select_ibex_pulp_dual_source_bootstrap(
        selector: str | None = None):
    """Rebuild exactly the bootstrap one closed selector names.

    ``None`` is the shipped bootstrap and stays the default: every identity,
    plan, reservation and comparison built from the result is then the shipped
    one, byte for byte, so a caller that does not ask selects what it always
    selected.  The only other accepted value is
    :data:`myfuzz.scenario.ibex_pulp_dual_source.MINIMAL_BOOTSTRAP_SELECTOR`;
    every other value is refused here instead of silently falling back, and the
    selector is never inferred from a path, a name or saved bytes.

    The minimal branch re-decodes the bytes it just produced through
    :func:`myfuzz.scenario.ibex_pulp_dual_source.minimal_bootstrap_declaration`,
    which raises when the fixture writes a removed GPIO word or differs from the
    declared write sets.  A selector that cannot deliver the declared fixture
    therefore fails closed rather than running the shipped image under the
    minimal name.
    """
    from myfuzz.scenario.ibex_pulp_dual_source import (
        MINIMAL_BOOTSTRAP_SELECTOR,
        make_ibex_pulp_dual_source_minimal_bootstrap,
        minimal_bootstrap_declaration)
    if selector is None:
        return make_ibex_pulp_dual_source_stream_bootstrap()
    if selector != MINIMAL_BOOTSTRAP_SELECTOR:
        raise ValueError('online runtime bootstrap selector is not declared')
    bootstrap = make_ibex_pulp_dual_source_minimal_bootstrap()
    minimal_bootstrap_declaration(bootstrap)
    return bootstrap


def make_ibex_pulp_online_runtime(
        *, cache_dir: Path, run_id: str, evidence_dir: Path | None = None,
        checker: Callable[[OnlineCaseReceipt], tuple[str, ...]] | None = None,
        feedback_interval: int = 16,
        max_warmup_rounds: int = 1024,
        cpu_retirement: bool = False,
        gpio_consumption: bool = False,
        native_irq_receipts: bool = False,
        source_actions: bool = True,
        memory_commit_receipts: bool = False,
        persistent_memory_prerequisites: bool = False,
        ip_cross_case: bool | None = None,
        result_slot_byte_store: bool = False,
        initial_ram_data: bool | None = None,
        initial_ram_record: bytes | None = None,
        candidate_exploration: bool = False,
        candidate_exploration_max_cases: int = 65536,
        classified_feedback: bool = False,
        classified_feedback_max_records: int = 4096,
        bootstrap_selector: str | None = None) -> IbexPulpOnlineRuntime:
    """The Ibex instance of the shared online runtime assembly.

    ``source_actions`` is the shipped cross-case prerequisite policy and is on
    by default: the session is built with the factory's declared
    :class:`InstructionSlotReservationGate` and the executor discovers it.
    ``source_actions=False`` selects the explicitly declared legacy path.

    ``memory_commit_receipts`` declares the host-memory commit stream and stays
    off by default, so this runtime's default session identity is unchanged.  On,
    the session journals authenticated ``memory_write_commit`` records, which is
    what the RAM prerequisite policy's ``STORE`` whitelist consumes.  The Ibex
    online decoder always declares the result-slot window
    (``result_slot_readback=True``), because this entry point *is* the Ibex
    dual-source online campaign; the shared and second-CPU builders keep their
    previous declaration.

    ``persistent_memory_prerequisites`` enables the trusted current-memory
    gate using this decoder's runtime contract identity. It requires explicit
    source actions and commit receipts and remains disabled by default.

    ``ip_cross_case`` is the opt-in per-case budget declaration that lets an
    ``IP_TO_CPU_TO_IP`` admission be accepted in a later case than the one it
    was admitted in.  It is resolved once by :func:`resolve_ip_cross_case`
    (explicit argument, else ``MYFUZZ_IP_CROSS_CASE``, else off) and forwarded
    to :func:`make_ibex_pulp_dual_source_online_decoder`; off, the decoder and
    every identity below it are the shipped ones, on, the declaration is
    recorded in the decoder manifest.

    ``result_slot_byte_store`` is the explicit opt-in partial byte write of the
    declared result-slot window
    (:func:`myfuzz.scenario.ibex_pulp_dual_source.result_slot_byte_store_declaration`)
    and stays off by default: the kwarg is only forwarded when it is explicitly
    true, so off, the decoder manifest, and therefore the run identity, is the
    shipped one.  On, the decoder additionally declares the one-byte write width
    of ``SB`` for ``RESULT_ADDRESS``, which is what lets real RTL commit a
    partial ``byte_enable`` the P3 ``store_then_load`` criterion's
    ``byte_enable_lane_selectivity`` part can be measured from.  It is a
    *declaration* only: whether an RTL store really enabled one lane is read
    from the artifact's own byte-enable records.

    ``initial_ram_data`` is the opt-in pre-session initial RAM data operator of
    :mod:`myfuzz.scenario.initial_ram_data`, resolved once (explicit argument,
    else ``MYFUZZ_INITIAL_RAM_DATA``, else off) and forwarded to the shared
    builder, which mutates one declared initial byte before the session starts.
    Off, nothing is declared and no artifact, manifest or candidate identity
    changes; on, the adopted byte is one more initial image of the saved plan
    and the run's own report states the declaration and the decision.

    ``bootstrap_selector`` is the closed bootstrap selector of
    :func:`select_ibex_pulp_dual_source_bootstrap` and stays ``None`` by
    default: off, the shipped bootstrap, its reservation and every identity
    below it are exactly what they were.  On -- only
    ``MINIMAL_BOOTSTRAP_SELECTOR`` is accepted -- the declared minimal fixture
    is rebuilt and re-decoded before use; an unknown value is refused rather
    than silently falling back to the shipped bytes.
    """
    _validate_candidate_options(candidate_exploration, candidate_exploration_max_cases)
    if type(classified_feedback) is not bool or type(classified_feedback_max_records) is not int or not 1 <= classified_feedback_max_records <= 65536:
        raise ValueError('classified feedback options invalid')
    if type(gpio_consumption) is not bool:
        raise ValueError('gpio_consumption must be boolean')
    if type(native_irq_receipts) is not bool or (native_irq_receipts and not cpu_retirement):
        raise ValueError('native IRQ receipts require explicit RVFI retirement')
    if type(max_warmup_rounds) is not int or max_warmup_rounds < 1:
        raise ValueError("max_warmup_rounds must be positive")
    if type(source_actions) is not bool:
        raise ValueError('source_actions must be boolean')
    if type(memory_commit_receipts) is not bool:
        raise ValueError('memory_commit_receipts must be boolean')
    if (type(persistent_memory_prerequisites) is not bool
            or persistent_memory_prerequisites and (not source_actions or not memory_commit_receipts)):
        raise ValueError('persistent memory prerequisites require source actions and commit receipts')
    if type(result_slot_byte_store) is not bool:
        raise ValueError('result_slot_byte_store must be boolean')
    ip_cross_case = resolve_ip_cross_case(ip_cross_case)
    bootstrap = select_ibex_pulp_dual_source_bootstrap(bootstrap_selector)
    decoder = make_ibex_pulp_dual_source_online_decoder(
        bootstrap=bootstrap, result_slot_readback=True,
        ip_cross_case=ip_cross_case,
        **({'result_slot_byte_store': True} if result_slot_byte_store else {}))
    factory = make_ibex_pulp_dual_source_factory(Path(cache_dir),
        cpu_retirement=cpu_retirement, gpio_consumption=gpio_consumption,
        source_actions=source_actions,
        **({'physical_observations': True} if candidate_exploration or classified_feedback else {}),
        **({'native_irq_receipts': True} if native_irq_receipts else {}),
        **({'persistent_memory_runtime_contract_sha256': decoder.runtime_contract.identity_sha256}
           if persistent_memory_prerequisites else {}),
        **({'memory_commit_receipts': True} if memory_commit_receipts else {}))
    runtime = make_pulp_dual_source_online_runtime(
        bootstrap=bootstrap, decoder=decoder, factory=factory, run_id=run_id,
        evidence_dir=evidence_dir, checker=checker,
        feedback_interval=feedback_interval, max_warmup_rounds=max_warmup_rounds,
        source_actions=source_actions,
        initial_ram_data=initial_ram_data,
        initial_ram_record=initial_ram_record,
        **({'candidate_exploration': True,
            'candidate_exploration_max_cases': candidate_exploration_max_cases}
           if candidate_exploration else {}),
        **({'classified_feedback': True, 'classified_feedback_max_records': classified_feedback_max_records}
           if classified_feedback else {}))
    if candidate_exploration or classified_feedback:
        from .ibex_pulp_candidate_replay import ASSEMBLY_SCHEMA, ASSEMBLY_SCHEMA_V2, validate_candidate_assembly
        initial = runtime.session.initial_ram_data_state()
        declaration = dict(schema_version=ASSEMBLY_SCHEMA, run_id=run_id,
            feedback_interval=feedback_interval, max_warmup_rounds=max_warmup_rounds,
            candidate_exploration_max_cases=candidate_exploration_max_cases,
            cpu_retirement=cpu_retirement, gpio_consumption=gpio_consumption,
            native_irq_receipts=native_irq_receipts, source_actions=source_actions,
            memory_commit_receipts=memory_commit_receipts,
            persistent_memory_prerequisites=persistent_memory_prerequisites,
            ip_cross_case=ip_cross_case, result_slot_byte_store=result_slot_byte_store,
            closed_loop_energy=runtime.executor.closed_loop_energy,
            path_switch=runtime.executor.path_switch,
            initial_ram_data=initial['enabled'] if initial is not None else False,
            initial_ram_data_source=initial['source'] if initial is not None else 'default',
            initial_ram_record_hex=(initial_ram_record if initial_ram_record is not None
                                    else bytes(RECORD_BYTES)).hex())
        if classified_feedback:
            declaration.update(schema_version=ASSEMBLY_SCHEMA_V2,
                candidate_exploration=candidate_exploration, classified_feedback=True,
                classified_feedback_max_records=classified_feedback_max_records)
        try:
            runtime.executor.set_online_assembly_configuration(validate_candidate_assembly(declaration))
        except BaseException as error:
            try:
                runtime.session.finish()
            except BaseException as cleanup:
                error.add_note('candidate assembly cleanup failed: ' + str(cleanup))
            raise
    return runtime
