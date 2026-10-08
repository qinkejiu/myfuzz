"""One persistent Ibex plus OpenTitan UART dual-source RFuzz session."""

from __future__ import annotations

from dataclasses import dataclass
import json
import hashlib
from pathlib import Path

from myfuzz.scenario.batch import BatchSourceEvent
from myfuzz.scenario.event_journal import JsonlEventView, ZlibChunkEventView
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.ibex_uart_online import (
    make_ibex_uart_online_bootstrap, make_ibex_uart_online_decoder,
    make_ibex_uart_online_factory, uart_online_advances, UART_PROFILE, UART_FIFO_PROFILE)
from myfuzz.scenario.ibex_uart_online_checker import IbexUartOnlineChecker
from myfuzz.scenario.replay import ReplayComparison, ScenarioTrace
from myfuzz.scenario.session_runtime import (OnlineCase, OnlineCaseReceipt,
                                             ScenarioSession,
                                             replay_online_session)

from .scenario_rfuzz import ScenarioRfuzzExecutor
from .ibex_pulp_online import _saved_cpu_retirement_mode
from .scenario_rfuzz_live import _verify_online_run_identity


@dataclass(frozen=True)
class IbexUartOnlineRuntime:
    session: ScenarioSession
    decoder: object
    executor: ScenarioRfuzzExecutor
    factory: object
    custom_checker: bool = False

    def replay(self, reference: ScenarioTrace, *, checker=None) -> ReplayComparison:
        if self.custom_checker and checker is None:
            raise ValueError("custom UART checker needs a fresh replay checker")
        return replay_online_session(
            self.session.encode_plan(), self.factory, reference,
            checker=checker if checker is not None else IbexUartOnlineChecker())


def replay_ibex_uart_online_files(*, cache_dir: Path, plan_path: Path,
                                  trace_path: Path) -> ReplayComparison:
    plan = Path(plan_path).read_bytes()
    trace_path = Path(trace_path)
    reference = _read_uart_online_trace(trace_path)
    verified_identity = _verify_online_run_identity(
        trace_path.parent, plan_path=Path(plan_path), trace_path=trace_path,
        trace=reference)
    uart_fifo = _saved_uart_fifo_mode(trace_path.parent, verified_identity)
    cpu_retirement = _saved_cpu_retirement_mode(trace_path.parent, verified_identity)
    memory_commit = _saved_memory_commit_mode(trace_path.parent, verified_identity)
    memory_readback = _saved_memory_readback_mode(trace_path.parent, verified_identity)
    return replay_online_session(
        plan, make_ibex_uart_online_factory(Path(cache_dir), cpu_retirement=cpu_retirement,
                                           uart_fifo=uart_fifo,
                                           memory_commit=memory_commit,
                                           memory_readback=memory_readback), reference,
        checker=IbexUartOnlineChecker())


def _saved_memory_commit_mode(output: Path, verified_identity: dict | None) -> bool:
    """Read the exact saved opt-in mode after online manifest hash verification."""
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
        identity = json.loads(raw)['runner']['sessions']['cpu']['identity']
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


def _saved_memory_readback_mode(output: Path, verified_identity: dict | None) -> bool:
    if verified_identity is None:
        return False
    output = Path(output).resolve()
    path = output / 'online_session_manifest.json'
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(output):
        raise ValueError('saved memory readback manifest path mismatch')
    raw = path.read_bytes()
    artifacts = verified_identity.get('artifacts') if type(verified_identity) is dict else None
    if (type(artifacts) is not dict or hashlib.sha256(raw).hexdigest()
            != artifacts.get('online_session_manifest.json')):
        raise ValueError('saved memory readback manifest changed after verification')
    try:
        identity = json.loads(raw)['runner']['sessions']['cpu']['identity']
        if type(identity) is not dict:
            raise ValueError('saved CPU identity must be an object')
        if 'memory_read_issuance' not in identity:
            return False
        contract = identity['memory_read_issuance']
        if (type(contract) is not dict
                or set(contract) != {'schema_version', 'capacity'}
                or contract['schema_version'] != 'memory_read_authority.v1'
                or type(contract['capacity']) is not int or contract['capacity'] != 256):
            raise ValueError('saved memory readback contract mismatch')
        return True
    except (KeyError, TypeError) as exc:
        raise ValueError('saved CPU memory readback mode is malformed') from exc


def _saved_uart_fifo_mode(output: Path, verified_identity: dict | None) -> bool:
    """Select saved probes only after verifying the exact raw manifest bytes."""
    if verified_identity is None:
        return False
    from myfuzz.local_harness.opentitan_uart_fifo_contract import validate_uart_fifo_observation_contract
    from myfuzz.scenario.contracts import _verify_generated_session
    output = Path(output).resolve()
    path = output / 'online_session_manifest.json'
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(output):
        raise ValueError('saved UART profile manifest path mismatch')
    raw = path.read_bytes()
    artifacts = verified_identity.get('artifacts') if type(verified_identity) is dict else None
    if (type(artifacts) is not dict or hashlib.sha256(raw).hexdigest()
            != artifacts.get('online_session_manifest.json')):
        raise ValueError('saved UART profile manifest changed after verification')
    try:
        manifest = json.loads(raw)
        identity = manifest['runner']['sessions']['uart']['identity']
        if type(identity) is not dict:
            raise ValueError('saved UART identity must be an object')
        observed = 'uart_fifo_observation_contract' in identity
        if observed:
            validate_uart_fifo_observation_contract(identity['uart_fifo_observation_contract'])
            if 'uart_source_provenance' not in identity:
                raise ValueError('saved UART FIFO source provenance is missing')
        document = identity['runtime_artifact']
        plan = document['plan']
        if (document['kind'] != 'tlul_uart' or plan['instance_id'] != 'uart'
                or plan['component_id'] != ('opentitan_uart_fifo_local' if observed else 'opentitan_uart_local')
                or plan['profile_path'] != (UART_FIFO_PROFILE if observed else UART_PROFILE)
                or identity['source_component'] != 'uart'):
            raise ValueError('saved UART observation profile mismatch')
    except (KeyError, TypeError) as exc:
        raise ValueError('saved UART component identity is missing or malformed') from exc
    _verify_generated_session(identity)
    return observed


def _read_uart_online_trace(trace_path: Path) -> ScenarioTrace:
    document = json.loads(Path(trace_path).read_bytes())
    if not isinstance(document, dict):
        raise ValueError("invalid saved UART online trace")
    if document.get("schema_version") == "online_trace_jsonl.v1":
        expected = {"schema_version", "events_file", "event_count",
                    "genome_sha256", "status", "local_ticks",
                    "semantic_sha256", "manifest_sha256"}
        if (set(document) != expected
                or document["events_file"] != "online_events.jsonl"):
            raise ValueError("invalid saved UART online JSONL trace metadata")
        document["events"] = JsonlEventView(
            Path(trace_path).parent / document.pop("events_file"),
            document.pop("event_count"))
        document.pop("schema_version")
    elif document.get("schema_version") == "online_trace_zlib_chunks.v1":
        expected = {"schema_version", "events_file", "event_count",
                    "genome_sha256", "status", "local_ticks",
                    "semantic_sha256", "manifest_sha256"}
        if set(document) != expected or document["events_file"] != "online_events.zlib":
            raise ValueError("invalid saved UART compressed trace metadata")
        view = ZlibChunkEventView(
            Path(trace_path).parent / document.pop("events_file"),
            document.pop("event_count"))
        view.verify_trace_semantic(status=document["status"],
                                   local_ticks=document["local_ticks"],
                                   expected_sha256=document["semantic_sha256"])
        document["events"] = view
        document.pop("schema_version")
    elif set(document) != {"genome_sha256", "status", "events", "local_ticks",
                           "semantic_sha256", "manifest_sha256"}:
        raise ValueError("invalid saved UART online trace")
    if (not isinstance(document.get("events"), (list, JsonlEventView,
                                                 ZlibChunkEventView))
            or not isinstance(document.get("local_ticks"), dict)):
        raise ValueError("invalid saved UART online trace events or ticks")
    return ScenarioTrace(**document)


def make_ibex_uart_online_runtime(
        *, cache_dir: Path, run_id: str, evidence_dir: Path | None = None,
        checker=None, feedback_interval: int = 16,
        cpu_retirement: bool = False, uart_fifo: bool = False,
        memory_commit: bool = False,
        memory_readback: bool = False,
        uart_wdata_byte_store: bool = False) -> IbexUartOnlineRuntime:
    bootstrap = make_ibex_uart_online_bootstrap(memory_readback=memory_readback)
    decoder = make_ibex_uart_online_decoder(
        bootstrap=bootstrap, uart_wdata_byte_store=uart_wdata_byte_store)
    factory = make_ibex_uart_online_factory(Path(cache_dir), cpu_retirement=cpu_retirement,
                                            uart_fifo=uart_fifo,
                                            memory_commit=memory_commit,
                                            memory_readback=memory_readback)
    session = ScenarioSession(
        bootstrap.template, factory(),
        checker=checker if checker is not None else IbexUartOnlineChecker())
    session.declare_instruction_slots(
        "cpu", bootstrap.instruction_start, bootstrap.instruction_count)
    session.configure_runtime_paths(decoder.graph, decoder.runtime_contract,
                                    decoder.runtime_paths, source_ownership=decoder.ownership)
    session.begin()
    try:
        # UART needs one initial source to start its local 8N1 peer. This
        # recorded case also lets real Ibex configure UART and install its ISR.
        warmup = OnlineCase(
            "uart-fixed-warmup", "IP_TO_CPU", next(
                decoder.graph.path_identity(path, direction=direction)
                for direction, path in decoder.runtime_paths
                if direction == "IP_TO_CPU" and path.target == "uart_rx_to_cpu"),
            BatchSourceEvent("uart-fixed-warmup-rx", "uart", "uart_rx_byte",
                             0x5a, 0, 8),
            uart_online_advances("warmup"))
        receipt = session.submit_case(warmup, source_role="bootstrap")
        if receipt.violations or receipt.status != "running":
            raise RuntimeError("Ibex/UART fixed warmup did not remain running")
        if (session.runner.sessions["cpu"].waiting_instruction_address
                != bootstrap.instruction_start):
            raise RuntimeError("Ibex did not reach online UART instruction slot")
    except BaseException:
        try:
            session.finish()
        except Exception:
            pass
        raise
    targets = (
        CoverageTarget("uart_tx_activity", "uart", "serial_tx_count", 1, 1),
        CoverageTarget("uart_rx_irq", "uart", "uart_rx_watermark", 1, 1),
        CoverageTarget("cpu_uart_vector_fetch", "cpu", "instr_addr",
                       0xffffffff, 0x1012c),
        CoverageTarget("cpu_data_write", "cpu", "data_write", 1, 1),
    )
    # The UART session drives a queued RX waveform bit by bit and its own
    # ``_access`` refuses a TL-UL register access that overlaps it, which on the
    # online path would stop the whole session with ``uncertain_effect``.  The
    # same predicate is asked before any RTL command instead, so an overlapping
    # CPU MMIO candidate is a non-consuming pre-RTL refusal and the search keeps
    # running (see myfuzz.scenario.uart_waveform_gate).
    from myfuzz.scenario.ibex_uart_online import UART_BASE
    from myfuzz.scenario.uart_routing_witness import UartRoutingWitnessRecorder
    from myfuzz.scenario.uart_waveform_gate import UartWaveformAdmissionGate

    # The waveform guard lives on the UART *component* session, not on the
    # top-level ScenarioSession that owns the runner: exactly one declared
    # component must expose the query, and anything else is refused instead of
    # guessing which session the guard belongs to.
    guarded = [name for name, component in session.runner.sessions.items()
               if callable(getattr(component, "register_access_conflict", None))]
    if len(guarded) != 1:
        raise RuntimeError(
            "the UART waveform gate needs exactly one declared component "
            f"session with register_access_conflict(), found {sorted(guarded)}")
    waveform_session = session.runner.sessions[guarded[0]]

    executor = ScenarioRfuzzExecutor(
        run_id=run_id, online_decoder=decoder, session=session,
        factory=factory, targets=targets, evidence_dir=evidence_dir,
        feedback_interval=feedback_interval,
        # The routing/consumption witness table is read back from each case's own
        # event slice, so the heterogeneous run reports what it really routed
        # (UART register accesses, FIFO pops, consumption and retirement
        # witnesses) instead of null.
        case_witness_recorder=UartRoutingWitnessRecorder(),
        source_action_gate=UartWaveformAdmissionGate(
            session=waveform_session, window=(UART_BASE, 0x1000)))
    return IbexUartOnlineRuntime(session, decoder, executor, factory,
                                 checker is not None)
