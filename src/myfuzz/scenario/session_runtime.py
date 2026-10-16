"""Reset-free online testcase stream over independently clocked RTL harnesses.

A case admits one upstream source, then advances selected local harnesses.  The
runner, memory, command ledger, router, and pending events belong to the whole
session.  A case boundary is only an input/evidence boundary; it is not reset.

A session may be given an opt-in ``prerequisite_gate`` (see
``scenario/source_actions.py``).  When configured, the gate is queried with the
case *before* any RTL command and receives each case receipt afterwards, so
effects committed by one case become explicit evidence for the next one.  A
session without a gate behaves exactly as before.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from copy import deepcopy
import hashlib
from collections import Counter, deque
from itertools import zip_longest
import inspect
import json
from pathlib import Path
import sys
from typing import Callable

from .runtime_path_contract import PreparedRuntimePathContract
from .runtime_edge_index import RuntimeEdgeIndex
from .source_provenance import AdmissionRegistry, SourceAdmission
from .batch import BatchAdvance, BatchSourceEvent
from .event_journal import EventJournalSnapshot
from .genome import GenomeCodec, MemoryImage, ScenarioGenome
from .initial_ram_data import (
    INITIAL_RAM_DATA_DOMAIN,
    InitialRamDataState,
    TrustedInitialRamDataDeclaration,
    evaluate_initial_ram_data,
    operator_source_identity,
)
from .replay import ReplayComparison, ScenarioTrace, _difference_context
from .runner import (ScenarioRunner, guard_native_reset_evidence,
                     guard_register_program_verifier)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _canonical_text(value: object) -> str:
    return _canonical(value).decode("utf-8")


def _canonical_sha256(value: object) -> str:
    """Hash canonical JSON without allocating a second full trace buffer."""
    digest = hashlib.sha256()
    encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False, allow_nan=False)
    for fragment in encoder.iterencode(value):
        digest.update(fragment.encode("utf-8"))
    return digest.hexdigest()


def _checker_config_value(value: object) -> object:
    """Normalize deterministic checker containers into canonical JSON values."""
    if isinstance(value, deque):
        return [_checker_config_value(item) for item in value]
    if isinstance(value, (list, tuple)):
        return [_checker_config_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _checker_config_value(item) for key, item in value.items()}
    return json.loads(_canonical(value))


def _trace_semantic_sha256(status: str, events, ticks: dict[str, int]) -> str:
    if not isinstance(events, EventJournalSnapshot):
        return _canonical_sha256({"status": status, "events": events,
                                  "local_ticks": ticks})
    digest = hashlib.sha256()
    digest.update(b'{"events":[')
    for index, event in enumerate(events):
        if index:
            digest.update(b",")
        digest.update(_canonical(event))
    digest.update(b'],"local_ticks":')
    digest.update(_canonical(ticks))
    digest.update(b',"status":')
    digest.update(_canonical(status))
    digest.update(b"}")
    return digest.hexdigest()


_ROOT = Path(__file__).resolve().parents[3]
_ONLINE_SOURCE_PATHS = (
    'src/myfuzz/scenario/uart_retired_read.py',
    'src/myfuzz/scenario/uart_operand_seed.py',
    'src/myfuzz/scenario/uart_operand_use.py',
    'src/myfuzz/scenario/memory_service.py',
    'src/myfuzz/local_harness/cpu_session.py',
    'src/myfuzz/local_harness/session.py',
    'src/myfuzz/scenario/memory_commit_authority.py',
    'src/myfuzz/scenario/memory_read_authority.py',
    'src/myfuzz/scenario/uart_ram_commit_join.py',
    'src/myfuzz/scenario/uart_store_memory.py',
    'src/myfuzz/scenario/uart_memory_readback.py',
    'src/myfuzz/scenario/uart_irq_entry.py',
    'src/myfuzz/local_harness/uart_controlled_irq_contract.py',
    "src/myfuzz/scenario/uart_irq_consumption.py",
    "src/myfuzz/local_harness/ibex_irq_receipt_contract.py",
    "src/myfuzz/scenario/uart_consumption.py",
    "src/myfuzz/local_harness/opentitan_uart_fifo_contract.py",
    "src/myfuzz/scenario/cpu_retirement.py",
    "src/myfuzz/scenario/retirement_delivery.py",
    "src/myfuzz/scenario/gpio_consumption.py",
    "src/myfuzz/local_harness/pulp_gpio_probe_contract.py",
    "src/myfuzz/scenario/source_provenance.py",
    "src/myfuzz/scenario/runtime_edge_index.py",
    "src/myfuzz/scenario/event_provenance.py",
    "src/myfuzz/scenario/batch.py",
    "src/myfuzz/scenario/runtime_path_contract.py",
    "src/myfuzz/scenario/runner.py",
    "src/myfuzz/scenario/event_journal.py",
    "src/myfuzz/scenario/uart_peer.py",
    "src/myfuzz/local_harness/opentitan_uart_session.py",
    "src/myfuzz/integration/rfuzz_fifo.py",
    "src/myfuzz/integration/ibex_pulp_online.py",
    "src/myfuzz/integration/scenario_rfuzz.py",
    "src/myfuzz/integration/scenario_rfuzz_live.py",
    "src/myfuzz/scenario/ibex_pulp_dual_source.py",
    "src/myfuzz/scenario/ibex_pulp_online_checker.py",
    "src/myfuzz/scenario/ibex_uart_online.py",
    "src/myfuzz/scenario/ibex_uart_online_checker.py",
    "src/myfuzz/integration/ibex_uart_online.py",
    "src/myfuzz/scenario/ibex_pulp_rfuzz.py",
    "src/myfuzz/scenario/interaction_feedback.py",
    "src/myfuzz/scenario/online_case_decoder.py",
    "src/myfuzz/scenario/rv32i_sources.py",
    "src/myfuzz/scenario/source_actions.py",
    "src/myfuzz/scenario/session_runtime.py",
)


def _checker_identity(checker: Callable | None, *, configuration_only=False) -> dict | None:
    if checker is None:
        return None
    target = checker if hasattr(checker, "__qualname__") else type(checker)
    identity = {"module": target.__module__, "qualname": target.__qualname__}
    module = sys.modules.get(target.__module__)
    source_path = None
    try:
        source_path = inspect.getsourcefile(target)
    except (TypeError, OSError):
        pass
    if source_path is None and module is not None:
        source_path = getattr(module, "__file__", None)
    if source_path is not None:
        source = Path(source_path)
        if source.is_file():
            resolved = source.resolve()
            try:
                source_name = resolved.relative_to(_ROOT).as_posix()
            except ValueError:
                source_name = str(resolved)
            identity["source"] = {
                "path": source_name,
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            }
    code_target = getattr(checker, "__func__", checker)
    if not inspect.isfunction(code_target):
        code_target = getattr(type(checker), "__call__", code_target)
    closure = getattr(code_target, "__closure__", None)
    freevars = getattr(getattr(code_target, "__code__", None), "co_freevars", ())
    if closure:
        closure_config = {}
        for name, cell in zip(freevars, closure):
            try:
                value = cell.cell_contents
            except ValueError as exc:
                raise ValueError("online checker has an empty closure cell") from exc
            if name == "__class__" and inspect.isclass(value):
                closure_config[name] = {
                    "module": value.__module__, "qualname": value.__qualname__}
                continue
            try:
                closure_config[name] = _checker_config_value(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"online checker closure value {name!r} must be JSON serializable") from exc
        if closure_config:
            identity["closure_config"] = closure_config
    owner = getattr(checker, "__self__", None)
    configured = owner if owner is not None else checker
    provider = getattr(configured, 'online_identity_configuration', None)
    if configuration_only and callable(provider):
        config = _checker_config_value(provider())
        if type(config) is not dict:
            raise ValueError('online checker identity configuration must be a mapping')
        identity['configuration_scope'] = 'explicit_checker_configuration.v1'
        identity['config'] = config
        return identity
    if hasattr(configured, "__dict__"):
        config = {}
        for name, value in vars(configured).items():
            try:
                config[name] = _checker_config_value(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"online checker configuration {name!r} must be JSON serializable") from exc
        if config:
            identity["config"] = config
    return identity


def _register_capability_source_files():
    return [dict(path=name,sha256=hashlib.sha256((_ROOT/name).read_bytes()).hexdigest())
        for name in ('src/myfuzz/scenario/register_program_capabilities.py',
                     'src/myfuzz/composition/ip_test_levels.py')]


def _ordinary_apb_access_source_files(paths=None):
    """Code-owned import closure, never paths supplied by a saved document."""
    if paths is None:
        from myfuzz.local_harness.build import _host_sources
        paths=set(_host_sources()) | {
            'src/myfuzz/scenario/session_runtime.py','src/myfuzz/scenario/ordinary_apb_access_evidence.py',
            'src/myfuzz/local_harness/ordinary_apb_access_receipts.py',
            'src/myfuzz/scenario/runner.py','src/myfuzz/scenario/router.py','src/myfuzz/scenario/ledger.py',
            'src/myfuzz/scenario/ip_protocol_events.py','src/myfuzz/scenario/ip_protocol_checker.py',
            'src/myfuzz/scenario/ip_base_events.py','src/myfuzz/scenario/event_journal.py'}
    return [dict(path=name,sha256=hashlib.sha256((_ROOT/name).read_bytes()).hexdigest())
            for name in sorted(paths)]


def _register_program_verifier_source_files(paths=None):
    if paths is None:
        paths={row['path'] for row in _ordinary_apb_access_source_files()} | {
            'src/myfuzz/scenario/register_program_verifier.py',
            'src/myfuzz/composition/ip_test_levels.py',
            'src/myfuzz/scenario/memory_commit_authority.py',
            'src/myfuzz/scenario/memory_authority_distribution.py'}
    return _ordinary_apb_access_source_files(paths)


def _register_reset_default_source_files(paths=None):
    """Closed startup closure of the opt-in reset-default wrapper only.

    Nothing here enters the default-off register closure: the base assembly
    source disclosure is unchanged unless this channel is explicitly enabled.
    """
    if paths is None:
        paths={row['path'] for row in _register_program_verifier_source_files()} | {
            'src/myfuzz/scenario/register_reset_default_verifier.py',
            'src/myfuzz/scenario/native_reset_evidence.py',
            'src/myfuzz/scenario/register_program_runtime.py',
            'src/myfuzz/local_harness/native_reset_observation.py',
            'src/myfuzz/scenario/memory_commit_authority.py',
            'src/myfuzz/scenario/memory_authority_distribution.py'}
    return _ordinary_apb_access_source_files(paths)


def _online_manifest(runner: ScenarioRunner, checker: Callable | None = None, *,
                     runtime_paths: dict | None = None, checker_configuration_only=False,
                     register_program_configuration=None, register_capability_preflight=None,
                     ordinary_apb_access_evidence_configuration=None, ordinary_apb_access_source_files=None,
                     register_program_verifier_configuration=None, register_program_verifier_source_files=None,
                     register_reset_default_configuration=None,
                     register_reset_default_source_files=None) -> dict:
    """Versioned online extension without changing legacy host-source v1."""
    files = []
    for name in _ONLINE_SOURCE_PATHS:
        path = _ROOT / name
        if not path.is_file():
            raise ValueError(f"online runtime source is missing: {name}")
        files.append({"path": name,
                      "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    document = {"schema_version": "online_session_manifest.v1",
                "runner": runner.identity_document(), "online_source_files": files,
                "checker": _checker_identity(checker, configuration_only=checker_configuration_only)}
    if runtime_paths is not None:
        document["runtime_paths"] = runtime_paths
    if runner.provenance_enabled:
        document["provenance_configuration"] = runner.provenance_configuration
    if register_program_configuration is not None:
        document['register_program_configuration'] = json.loads(_canonical(register_program_configuration))
        document['register_program_source_files'] = [
            dict(path=name,sha256=hashlib.sha256((_ROOT/name).read_bytes()).hexdigest())
            for name in ('src/myfuzz/scenario/register_program_runtime.py',
                'src/myfuzz/scenario/register_program.py','src/myfuzz/scenario/rv32i_sources.py',
                'src/myfuzz/composition/test_capability.py','src/myfuzz/composition/component_profile.py',
                'src/myfuzz/scenario/source_actions.py','src/myfuzz/scenario/live_memory_prerequisites.py',
                'src/myfuzz/scenario/session_runtime.py','src/myfuzz/scenario/memory.py',
                'src/myfuzz/scenario/memory_service.py','src/myfuzz/scenario/memory_commit_authority.py',
                'src/myfuzz/scenario/memory_read_authority.py','src/myfuzz/scenario/router.py',
                'src/myfuzz/scenario/memory_authority_distribution.py',
                'src/myfuzz/scenario/ip_base_events.py','src/myfuzz/scenario/ip_protocol_events.py',
                'src/myfuzz/scenario/ip_protocol_checker.py',
                'src/myfuzz/local_harness/cpu_session.py',
                'src/myfuzz/local_harness/native_physical_observation.py')]
    if register_capability_preflight is not None:
        document['register_capability_preflight'] = json.loads(_canonical(register_capability_preflight))
        document['register_program_source_files'].extend(_register_capability_source_files())
    if ordinary_apb_access_evidence_configuration is not None:
        document['ordinary_apb_access_evidence_configuration']=json.loads(_canonical(ordinary_apb_access_evidence_configuration))
        document['ordinary_apb_access_source_files']=(ordinary_apb_access_source_files
            if ordinary_apb_access_source_files is not None else _ordinary_apb_access_source_files())
    if register_program_verifier_configuration is not None:
        document['register_program_verifier_configuration']=json.loads(_canonical(register_program_verifier_configuration))
        document['register_program_verifier_source_files']=(register_program_verifier_source_files
            if register_program_verifier_source_files is not None else _register_program_verifier_source_files())
    if register_reset_default_configuration is not None:
        document['register_reset_default_configuration']=json.loads(_canonical(register_reset_default_configuration))
        document['register_reset_default_source_files']=(register_reset_default_source_files
            if register_reset_default_source_files is not None else _register_reset_default_source_files())
    return document


@dataclass(frozen=True)
class OnlineInstruction:
    """One legal instruction fragment for previously reserved CPU RAM slots."""

    action_id: str
    component: str
    address: int
    data_hex: str

    def __post_init__(self) -> None:
        if not self.action_id or not self.component:
            raise ValueError("instruction action identity and component are required")
        if type(self.address) is not int or self.address < 0 or self.address % 4:
            raise ValueError("instruction address must be word aligned")
        if (not isinstance(self.data_hex, str) or not self.data_hex
                or len(self.data_hex) % 8):
            raise ValueError("instruction data must contain whole 32-bit words")
        try:
            raw = bytes.fromhex(self.data_hex)
        except ValueError as exc:
            raise ValueError("instruction data must be hexadecimal") from exc
        if raw.hex() != self.data_hex:
            raise ValueError("instruction data must use canonical lowercase hex")

    @property
    def data(self) -> bytes:
        return bytes.fromhex(self.data_hex)


OnlineInput = BatchSourceEvent | OnlineInstruction


@dataclass(frozen=True)
class OnlineCase:
    """One input decision and the local execution needed to observe its effect."""

    case_id: str
    direction: str
    path_id: str
    source: OnlineInput
    advances: tuple[BatchAdvance, ...]
    support_instructions: tuple[OnlineInstruction, ...] = ()

    def __post_init__(self) -> None:
        from .genome import DIRECTIONS

        if not self.case_id or not self.path_id or self.direction not in DIRECTIONS:
            raise ValueError("case identity, path, and direction are required")
        if not isinstance(self.source, (BatchSourceEvent, OnlineInstruction)):
            raise ValueError("a case requires one source input")
        if (not isinstance(self.advances, tuple) or not self.advances
                or any(not isinstance(item, BatchAdvance) for item in self.advances)):
            raise ValueError("a case requires a nonempty local advance sequence")
        if (not isinstance(self.support_instructions, tuple)
                or any(not isinstance(item, OnlineInstruction)
                       for item in self.support_instructions)):
            raise ValueError("support instructions must be a tuple of fixed fragments")
        if self.support_instructions and isinstance(self.source, OnlineInstruction):
            raise ValueError("CPU instruction source cannot have fixed support instructions")
        if any(item.data != b"\x13\x00\x00\x00" * (len(item.data) // 4)
               for item in self.support_instructions):
            raise ValueError("support instructions must be fixed RV32I NOP words")
        ids = (self.source.action_id,
               *(item.action_id for item in self.support_instructions))
        if len(set(ids)) != len(ids):
            raise ValueError("case instruction and source IDs must be unique")


@dataclass(frozen=True)
class OnlineCaseReceipt:
    case_id: str
    event_start: int
    event_end: int
    events: tuple[dict, ...]
    local_ticks_before: dict[str, int]
    local_ticks_after: dict[str, int]
    status: str
    violations: tuple[str, ...] = ()


def _resolve_case_source(prepared, case: OnlineCase, *, field_width=None,
                         require_unique: bool = True) -> str:
    direction, _ = prepared.resolve_path_id(case.path_id)
    if direction != case.direction:
        raise ValueError("runtime path direction differs from case")
    source = case.source
    candidates = prepared.source_nodes_for(case.path_id)
    if isinstance(source, BatchSourceEvent):
        width = source.width if source.width is not None else field_width
        matches = [node for node in candidates if node.kind == "source" and
                   (node.component, node.port, node.bit_offset, node.width) ==
                   (source.component, source.port, source.bit_offset, width)]
    else:
        matches = [node for node in candidates if node.kind == "instruction"
                   and node.component == source.component]
    if not matches or (require_unique and len(matches) != 1):
        raise ValueError("case source must match exactly one source on selected runtime path")
    return matches[0].source_id


def _case_admissions(case: OnlineCase, case_index: int, source_id: str,
                     source_role: str) -> tuple[SourceAdmission, ...]:
    if type(source_role) is not str or source_role not in ("fuzz_source", "bootstrap"):
        raise ValueError("online source_role must be fuzz_source or bootstrap")
    records = []
    for action, identity, role in (
            *((support, support.component + ".fixed_support", "fixed_support")
              for support in case.support_instructions),
            (case.source, source_id, source_role)):
        kind = "instruction" if isinstance(action, OnlineInstruction) else "source_event"
        records.append(SourceAdmission.create(case_id=case.case_id, case_index=case_index,
            source_id=identity, path_id=case.path_id, direction=case.direction,
            component=action.component, action_id=action.action_id, role=role,
            input_kind=kind, input_sha256=_canonical_sha256({**asdict(action), "kind": kind})))
    return tuple(records)


def _validate_saved_provenance(document: dict, prepared, cases: list,
                               roles: list[str], template: ScenarioGenome) -> None:
    """Authenticate the full attempted input prefix without constructing RTL."""
    index = RuntimeEdgeIndex(document["runtime_paths"], prepared.contract.document())
    expected_configuration = {"schema_version": "source_provenance_configuration.v1",
        "edge_index": index.document(), "edge_index_sha256": index.identity_sha256}
    if _canonical(document["provenance_configuration"]) != _canonical(expected_configuration):
        raise ValueError("online replay provenance configuration mismatch")
    saved = AdmissionRegistry.from_document(document["source_admissions"])
    rebuilt = AdmissionRegistry()
    topology = document["runtime_paths"]["topology"]
    fields = {(row["component"], row["port"]): row["owners"]
              for row in topology["ownership_inputs"]}
    seen_cases = set()
    seen_actions = set()
    final_case_start = 0
    final_case_count = 0
    for case_index, (case, role) in enumerate(zip(cases, roles)):
        if case.case_id in seen_cases:
            raise ValueError("duplicate online case_id in provenance plan")
        seen_cases.add(case.case_id)
        if any(component not in template.schedule_order
               for advance in case.advances for component in advance.schedule):
            raise ValueError("saved case schedule references unknown harness")
        if sum(len(advance.schedule) for advance in case.advances) > template.max_steps:
            raise ValueError("saved case exceeds local step limit")
        source = case.source
        width = None
        if isinstance(source, BatchSourceEvent):
            owners = fields.get((source.component, source.port))
            if owners is None:
                raise ValueError("saved source has no declared ownership field")
            width = source.width if source.width is not None else len(owners)
            if (type(width) is not int or width <= 0 or type(source.value) is not int
                    or not 0 <= source.value < 1 << width
                    or source.bit_offset + width > len(owners)
                    or any(owner["kind"] != "source"
                           for owner in owners[source.bit_offset:source.bit_offset + width])):
                raise ValueError("saved source value or ownership range is invalid")
        source_id = _resolve_case_source(prepared, case, field_width=width)
        admissions = _case_admissions(case, case_index, source_id, role)
        final_case_start = len(seen_actions)
        final_case_count = len(admissions)
        for admission in admissions:
            if admission.action_id in seen_actions:
                raise ValueError("duplicate source action_id in provenance plan")
            seen_actions.add(admission.action_id)
            if admission.component not in template.schedule_order:
                raise ValueError("saved admission references unknown harness")
            rebuilt.register(admission)
    expected_document = rebuilt.document()
    failure = document.get("terminal_failure")
    if failure is not None and failure["phase"] == "provenance_admission":
        attempted = failure["command_index"]
        if not 0 <= attempted < final_case_count:
            raise ValueError("invalid provenance admission failure index")
        saved_count = len(saved.document()["admissions"])
        # A failed append may occur either before registering the current entry
        # or after registry insertion. Both preserve exactly the declared prefix.
        if saved_count not in (final_case_start + attempted,
                               final_case_start + attempted + 1):
            raise ValueError("source admissions do not match failed registration prefix")
        expected_document["admissions"] = expected_document["admissions"][:saved_count]
    if _canonical(saved.document()) != _canonical(expected_document):
        raise ValueError("online replay source admissions mismatch")


def _reset_resume_checker_identity(checker):
    if checker is None:
        return (None, None, None, None)
    function = getattr(checker, '__func__', checker)
    code = getattr(function, '__code__', None)
    implementation = getattr(type(checker), '__call__', None)
    return (function, code, implementation, getattr(implementation, '__code__', None))


class ScenarioSession:
    """Keep one initialized Runner alive while accepting many online cases.

    ``submit_case`` returns only its event suffix so the hot path does not copy
    the full prefix for every mutation.  ``trace`` and ``plan`` intentionally
    materialize the full prefix only for a finding or replay.
    """

    def __init__(self, template: ScenarioGenome, runner: ScenarioRunner, *,
                 checker: Callable[[OnlineCaseReceipt], tuple[str, ...]] | None = None,
                 prerequisite_gate=None, checker_configuration_only=False) -> None:
        if type(checker_configuration_only) is not bool:
            raise ValueError('checker configuration identity policy must be boolean')
        self._checker_configuration_only = checker_configuration_only
        if not isinstance(template, ScenarioGenome) or not isinstance(runner, ScenarioRunner):
            raise ValueError("ScenarioGenome template and ScenarioRunner are required")
        if template.actions or template.reset_actions or template.quiesce_steps:
            raise ValueError("online template cannot contain actions or reset")
        if set(template.schedule_order) != set(runner.sessions):
            raise ValueError("template must name every local harness")
        if getattr(runner, "_status", None) != "created":
            raise ValueError("online session requires a fresh runner")
        # An opt-in gate supplies cross-case prerequisite admission and effect
        # ingestion.  It is duck-typed so this hot module keeps no import edge.
        trusted_gate = runner.persistent_memory_prerequisite_gate
        if trusted_gate is not None:
            if prerequisite_gate is not None and prerequisite_gate is not trusted_gate:
                raise ValueError('configured trusted memory prerequisite gate must be used')
            prerequisite_gate = trusted_gate
        if prerequisite_gate is not None and (
                not callable(getattr(prerequisite_gate, "require_case", None))
                or not callable(getattr(prerequisite_gate, "observe", None))):
            raise ValueError(
                "prerequisite gate must expose require_case and observe")
        self._prerequisite_gate = prerequisite_gate
        self._register_program_runtime = None
        self._register_export_runtime_binding = None
        self._register_program_configuration_json = None
        self._register_capability_preflight_json = None
        self._register_capability_sources_json = None
        self._ordinary_apb_observer = None
        self._ordinary_apb_configuration_json = None
        self._ordinary_apb_configuration_sha256 = None
        self._ordinary_apb_sources_json = None
        self._register_verifier = None
        self._register_verifier_configuration_json = None
        self._register_verifier_sources_json = None
        self._register_verifier_method_pins = None
        # Opt-in reset-default wrapper sentinels; empty unless explicitly configured.
        self._register_reset_default_verifier = None
        self._register_reset_default_configuration_json = None
        self._register_reset_default_sources_json = None
        self._register_reset_default_binding = None
        self._register_reset_default_max_records = None
        self._register_reset_default_max_commands = None
        self._register_reset_default_commits = None
        self._register_reset_default_commit_snapshot = {}
        self._register_reset_default_selected = {}
        self._register_reset_default_unmatched = ()
        self._register_reset_default_intervals = None
        self._register_reset_default_incomplete = False
        self._register_reset_default_reason = None
        runner.enable_event_journal()
        self.template = template
        self.runner = runner
        self._cases: list[OnlineCase] = []
        self._prerequisite_admissions: list[dict] = []
        self._case_source_roles: dict[str, str] = {}
        self._receipts: dict[str, tuple[OnlineCase, OnlineCaseReceipt]] = {}
        self._source_ids: set[str] = set()
        self._source_schedule_ticks: dict[str, int] = {}
        self._instruction_slots: list[tuple[str, int, int]] = []
        # Opt-in pre-session initial RAM data operator.  All of it stays empty
        # unless a caller declares the operator, so no shipped identity moves.
        self._initial_ram_declaration: TrustedInitialRamDataDeclaration | None = None
        self._initial_ram_enabled = False
        self._initial_ram_source = "default"
        self._initial_ram_max_bytes = 0
        self._initial_ram_attempts = 0
        self._initial_ram_adopted: list[dict] = []
        self._initial_ram_refusals: Counter[str] = Counter()
        self._initial_ram_codes: Counter[str] = Counter()
        self._initial_ram_raws: list[dict] = []
        self._warmup_advances: list[BatchAdvance] = []
        self._reset_operations: list[dict] = []
        self._uncertain_reset = False
        self._uncertain_reset_advance = False
        self._reset_resume_advances = {}
        self._resume_runner_methods = {name: (getattr(type(runner), name), getattr(runner, name))
            for name in ("step_batch", "retire_step_receipts_through")}
        self._manifest_sha256 = ""
        self._manifest_document: dict | None = None
        self._begun = False
        self._finished = False
        self._record_sequence = 0
        if checker is not None and not callable(checker):
            raise ValueError("online checker must be callable")
        self.checker = checker
        self._resume_checker = checker
        self._resume_checker_implementation = _reset_resume_checker_identity(checker)
        self._resume_gate = prerequisite_gate
        self._resume_gate_observe = (getattr(prerequisite_gate, "observe", None)
                                     if prerequisite_gate is not None else None)
        self._halted = False
        self._halt_reason: str | None = None
        self._terminal_failure: dict | None = None
        self._runtime_prepared = None
        self._runtime_compiled = None
        self._runtime_path_document_bytes = None

    def configure_runtime_paths(self, graph, contract, paths: tuple, *,
                                source_ownership=None, replay_only: bool = False,
                                provenance: bool = True) -> None:
        """Bind declared routes on the actual runner before any startup command."""
        if self._begun or self._finished or self._runtime_prepared is not None:
            raise RuntimeError("runtime paths must be configured once before begin")
        prepared = PreparedRuntimePathContract(graph, contract, paths)
        if type(replay_only) is not bool or type(provenance) is not bool:
            raise ValueError("runtime replay-only configuration must be boolean")
        if (not replay_only and source_ownership is None
                and any(prepared.graph.sources[source_id].kind == "source"
                        for _, path in prepared.runtime_paths for source_id in path.source_ids)):
            raise ValueError("runtime paths require trusted source ownership before begin")
        if source_ownership is not None:
            from .ownership import OwnershipMap
            if not isinstance(source_ownership, OwnershipMap):
                raise ValueError("runtime source ownership must be an OwnershipMap")
            for direction, path in prepared.runtime_paths:
                for source_id in path.source_ids:
                    source = prepared.graph.sources[source_id]
                    if source.kind != "source":
                        continue
                    expected = source_ownership.mutation_source(
                        source.component, source.port, source.bit_offset,
                        source.width, direction=direction)
                    actual = self.runner.ownership.mutation_source(
                        source.component, source.port, source.bit_offset,
                        source.width, direction=direction)
                    if actual != expected:
                        raise ValueError("runtime path source ownership producer mismatch")
        compiled = prepared.bind(self.runner)
        document = {**compiled.document(), "declaration": prepared.document()}
        if provenance:
            self.runner.configure_provenance(RuntimeEdgeIndex(document, contract.document()))
        self._runtime_prepared = prepared
        self._runtime_compiled = compiled
        self._runtime_path_document_bytes = _canonical(document)

    @property
    def runtime_contract(self):
        return self._runtime_prepared.contract if self._runtime_prepared else None

    @property
    def runtime_path_ids(self) -> tuple[str, ...]:
        return self._runtime_prepared.path_ids if self._runtime_prepared else ()

    @property
    def runtime_path_document(self) -> dict | None:
        return (json.loads(self._runtime_path_document_bytes)
                if self._runtime_path_document_bytes is not None else None)

    def _validate_runtime_case(self, case: OnlineCase) -> str | None:
        if self._runtime_prepared is None:
            return
        try:
            self._runtime_compiled.validate_topology()
        except ValueError:
            self._halted = True
            self._halt_reason = "environment_error"
            raise
        source = case.source
        width = (self.runner.ownership.field_width(source.component, source.port)
                 if isinstance(source, BatchSourceEvent) and source.width is None else None)
        return _resolve_case_source(self._runtime_prepared, case, field_width=width,
            require_unique=self.runner.provenance_enabled)

    @property
    def prerequisite_gate(self):
        # Startup configuration can finish after Session construction. Resolve
        # the Runner's current authority at every admission/observation point.
        trusted = self.runner.persistent_memory_prerequisite_gate
        if trusted is not None:
            if self._prerequisite_gate is not None and self._prerequisite_gate is not trusted:
                raise ValueError('configured trusted memory prerequisite gate must be used')
            return trusted
        return self._prerequisite_gate

    def attach_register_program_runtime(self, adapter):
        from .register_program_runtime import RegisterProgramRuntime
        if (type(adapter) is not RegisterProgramRuntime or adapter.session is not self
                or adapter.runner is not self.runner or self._register_program_runtime is not None
                or self._begun or self._finished or self.runner._status != 'created'
                or self._runtime_prepared is not None or self.runner.provenance_enabled):
            raise ValueError('register-program-runtime-installation-invalid')
        adapter.validate()
        self._register_program_runtime = adapter
        self._register_program_configuration_json = _canonical(adapter.configuration())
        self._register_export_runtime_binding = (adapter, type(adapter),
            type(adapter).validate_static_configuration, adapter._static_json)

    def configure_ordinary_apb_access_evidence(self, *, max_records=256):
        """Install actual target observations and the bounded collector prebegin."""
        from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
        from myfuzz.local_harness.ordinary_apb_access_receipts import OrdinaryApbAccessReceipts
        if (type(max_records) is not int or not 1<=max_records<=65536 or self._begun or self._finished
                or self.runner._status!='created' or self.runner.event_count or self._cases
                or self._ordinary_apb_observer is not None or self.runner._ordinary_apb_access_evidence is not None):
            raise ValueError('ordinary-apb-session-fresh-prebegin-required')
        targets=[target for target in self.runner.sessions.values() if type(target) is GeneratedPulpGpioSession]
        if not targets or any(target._ordinary_apb_receipts is not None for target in targets):
            raise ValueError('ordinary-apb-session-fresh-native-targets-required')
        if self._register_program_runtime is not None:self._register_program_runtime.validate()
        helpers=[OrdinaryApbAccessReceipts(target,max_records=max_records) for target in targets]
        sources=_ordinary_apb_access_source_files()
        caches=[self.runner._ip_protocol_event_normalizers,self.runner._ip_protocol_checkers]
        previous=[dict(cache) for cache in caches]
        try:
            for target,helper in zip(targets,helpers):target._ordinary_apb_receipts=helper
            configuration=self.runner.install_ordinary_apb_access_evidence(max_records=max_records)
            if self._register_program_runtime is not None:self._register_program_runtime.validate()
            observer=self.runner._ordinary_apb_access_evidence
            observer.validate()
        except BaseException:
            self.runner._ordinary_apb_access_evidence=None
            for target in targets:target._ordinary_apb_receipts=None
            for cache,old in zip(caches,previous):cache.clear();cache.update(old)
            raise
        self._ordinary_apb_observer=observer
        self._ordinary_apb_configuration_json=_canonical(configuration)
        self._ordinary_apb_configuration_sha256=observer.configuration_sha256
        self._ordinary_apb_sources_json=_canonical(sources)
        return json.loads(self._ordinary_apb_configuration_json)

    def configure_register_program_verifier(self, *, max_records=256):
        """Install only an actual live verifier, before any session execution."""
        from .register_program_verifier import RegisterProgramVerifier
        if (type(max_records) is not int or not 1<=max_records<=65536
                or self._begun or self._finished or self.runner._status!='created'
                or self.runner.event_count or self._cases or self._register_program_runtime is None
                or self._ordinary_apb_observer is None or self._register_verifier is not None
                or self.runner._register_program_verifier is not None):
            raise ValueError('register-verifier-prebegin-actual-runtime-required')
        self._register_configuration()
        self._guard_ordinary_apb_configuration()
        # All file work precedes the one-shot consumer registration.
        sources_json=_canonical(_register_program_verifier_source_files())
        authority=self.runner._memory_commit_authority
        consumers=authority._consumers
        previous=set(consumers)
        try:
            verifier=RegisterProgramVerifier(self._register_program_runtime,max_records=max_records)
            configuration_json=_canonical(verifier.configuration())
            pins={name:getattr(RegisterProgramVerifier,name) for name in ('configuration','report','snapshot','session_document')}
            guard_register_program_verifier(self.runner)
        except BaseException:
            consumers.clear();consumers.update(previous)
            self.runner._register_program_verifier=None
            raise
        self._register_verifier=verifier
        self._register_verifier_configuration_json=configuration_json
        self._register_verifier_sources_json=sources_json
        self._register_verifier_method_pins=pins
        return json.loads(configuration_json)

    def configure_register_reset_default(self, *, max_records=256, max_commands=4096):
        """Adopt or construct the actual Task3 consumer exactly once, before begin.

        Every fallible source/authority check runs before the one-shot recipient
        is registered; a rejected call leaves no half consumer and no half
        provider behind.  Saved documents never install this channel.
        """
        from . import register_reset_default_verifier as verifier_module
        from .register_program_runtime import RegisterProgramRuntime
        from .native_reset_evidence import NativeResetEvidence
        from .memory_commit_authority import MemoryCommitAuthority
        if ('configure_register_reset_default' in self.__dict__
                or type(self).configure_register_reset_default is not _RESET_DEFAULT_METHOD):
            raise ValueError('register-reset-default-configure-method-drift')
        if (type(max_records) is not int or not 1 <= max_records <= 65536
                or type(max_commands) is not int or not 1 <= max_commands <= 65536):
            raise ValueError('register-reset-default-invalid-capacity')
        if (self._begun or self._finished or self._cases or self.runner._status != 'created'
                or self.runner.event_count or self._register_reset_default_verifier is not None):
            raise ValueError('register-reset-default-prebegin-required')
        evidence = self.runner._native_reset_evidence
        if (type(evidence) is not NativeResetEvidence
                or self.runner._native_reset_evidence_failed_install):
            raise ValueError('register-reset-default-task2-evidence-required')
        adapter = self._register_program_runtime
        if (type(adapter) is not RegisterProgramRuntime or adapter.session is not self
                or adapter.runner is not self.runner):
            raise ValueError('register-reset-default-actual-runtime-required')
        if (verifier_module.RegisterResetDefaultVerifier is not verifier_module._TYPE
                or type(verifier_module._METHODS) is dict
                or any(name not in verifier_module._METHODS for name in
                       ('configuration', 'report', 'session_document', '_preflight_command',
                        '_consume_actual_commit'))):
            raise ValueError('register-reset-default-foreign-verifier-implementation')
        verifier_cls = verifier_module._TYPE
        if max_commands > evidence._limits[1]:
            raise ValueError('register-reset-default-command-capacity')
        # All fallible closure work precedes the non-rollback recipient.
        self._register_configuration()
        sources_json = _canonical_text(_register_reset_default_source_files())
        authority = self.runner._memory_commit_authority
        if type(authority) is not MemoryCommitAuthority:
            raise ValueError('register-reset-default-actual-authority-required')
        installed = self.runner._register_reset_default_verifier
        if installed is not None:
            # The plan's install order may already have constructed the actual
            # Task3 verifier; adopt only that exact object and capacity.
            if (type(installed) is not verifier_cls
                    or installed.runtime is not adapter
                    or getattr(installed, '_limit', None) != max_records):
                raise ValueError('register-reset-default-foreign-installed-verifier')
        consumers = authority._consumers
        previous = set(consumers)
        try:
            verifier = (verifier_cls(adapter, max_records=max_records)
                        if installed is None else installed)
            if self.runner._register_reset_default_verifier is not verifier:
                raise ValueError('register-reset-default-installation-binding-required')
            configuration_json = _canonical_text(verifier.configuration())
            commits = getattr(verifier, '_commits', None)
            if type(commits) is not dict:
                raise ValueError('register-reset-default-commit-registry-required')
            method_pins = dict(verifier_module._METHODS)
            guard_register_program_verifier(self.runner)
        except BaseException:
            consumers.clear()
            consumers.update(previous)
            if installed is None:
                self.runner._register_reset_default_verifier = None
            raise
        self._register_reset_default_verifier = verifier
        self._register_reset_default_configuration_json = configuration_json
        self._register_reset_default_sources_json = sources_json
        self._register_reset_default_binding = (
            verifier_module, verifier_cls, verifier_module._METHODS,
            method_pins, adapter, evidence, authority, commits)
        self._register_reset_default_max_records = max_records
        self._register_reset_default_max_commands = max_commands
        self._register_reset_default_commits = commits
        self._register_reset_default_commit_snapshot = {}
        self._register_reset_default_selected = {}
        self._register_reset_default_unmatched = ()
        self._register_reset_default_intervals = None
        self._register_reset_default_incomplete = False
        self._register_reset_default_reason = None
        return json.loads(configuration_json)

    def _register_reset_default_mark(self, reason):
        self._register_reset_default_incomplete = True
        if self._register_reset_default_reason is None:
            self._register_reset_default_reason = str(reason)

    def _register_reset_default_selected_spans(self):
        """Actual selected READ result spans and full CPU contexts; never saved."""
        adapter = self._register_program_runtime
        if adapter is None:
            return ()
        manifests = [row.get('manifest') for row in adapter._records]
        manifests += [json.loads(saved) for saved, _ in adapter._successful.values()]
        cpu = self.runner.sessions.get(adapter.cpu_component)
        memory = getattr(cpu, 'memory', None)
        if memory is None:
            return ()
        spans = []
        for manifest in manifests:
            if type(manifest) is not dict:
                continue
            request = manifest.get('request')
            context = manifest.get('context')
            if type(request) is not dict or type(context) is not dict:
                continue
            result = request.get('result_address')
            if (request.get('operation') != 'register_read' or type(result) is not int
                    or not 0 <= result < 1 << 32):
                continue
            # The declared result address is absolute; the commit document the
            # selection is checked against carries the memory-relative
            # ``byte_offset`` the write path itself derived.  Resolve the span
            # in the owning memory's address space with that same resolver and
            # pin the owning memory id, so the two sides cannot drift apart.
            try:
                memory_id, _, offset = memory.resolve_span(result, 4, write=True)
            except (TypeError, ValueError):
                # Unresolvable result spans stay unselected (fail closed).
                continue
            spans.append(dict(address=offset, width=4, memory_ids=(memory_id,),
                              context=_checker_config_value(context)))
        return tuple(spans)

    def _register_reset_default_selected_commit(self, issued, spans):
        """Retain only the active selected result span and full CPU context."""
        adapter = self._register_program_runtime
        if adapter is None or type(issued) not in (str, dict):
            return None
        # The pinned one-shot recipient stores every consumed commit in the
        # Task3 registry as one JSON string holding the exact
        # ``{'certificate', 'logged'}`` envelope its own reader requires
        # (register_reset_default_verifier.py:327 and :434-436), and the guard
        # below iterates that registry, so the issued authority certificate is
        # the inner value.  Decode and unwrap exactly that envelope and nothing
        # else: every other shape stays unselected, which keeps the commit on
        # the existing refusal path instead of making it a selected interval.
        entry = issued
        if type(entry) is str:
            try:
                entry = json.loads(entry)
            except (TypeError, ValueError):
                return None
        if type(entry) is not dict or set(entry) != {'certificate', 'logged'}:
            return None
        certificate = entry.get('certificate')
        if type(certificate) is not dict or type(entry.get('logged')) is not dict:
            return None
        issued = certificate
        document = issued.get('commit_document')
        fullkey = issued.get('fullkey')
        if type(document) is not dict or type(fullkey) is not dict:
            return None
        if (issued.get('component') != adapter.cpu_component
                or fullkey.get('source_component') != adapter.cpu_component):
            return None
        offset = document.get('byte_offset')
        width = document.get('width_bytes')
        generation = document.get('generation')
        memory_id = document.get('memory_id')
        if (type(offset) is not int or type(width) is not int or width < 1
                or type(generation) is not int or type(memory_id) is not str):
            return None
        for span in spans:
            context_generation = span['context'].get('generation')
            if type(context_generation) is not int:
                continue
            if (memory_id in span['memory_ids'] and span['address'] <= offset
                    and offset + width <= span['address'] + span['width']
                    and generation >= context_generation):
                return dict(result_span=[offset, width], cpu_component=adapter.cpu_component,
                            memory_id=memory_id, generation=generation,
                            context=deepcopy(span['context']))
        return None

    def _guard_register_reset_default_configuration(self, *, allow_incomplete=False,
                                                    new_operation=False):
        if type(allow_incomplete) is not bool or type(new_operation) is not bool:
            raise ValueError('register-reset-default-guard-boolean-required')
        if allow_incomplete and new_operation:
            raise ValueError('register-reset-default-export-cannot-admit-operations')
        if ('_guard_register_reset_default_configuration' in self.__dict__
                or type(self)._guard_register_reset_default_configuration is not _RESET_DEFAULT_GUARD):
            raise ValueError('register-reset-default-guard-method-drift')
        binding = self._register_reset_default_binding
        verifier = self._register_reset_default_verifier
        if binding is None:
            if verifier is not None or self.runner._register_reset_default_verifier is not None:
                raise ValueError('register-reset-default-session-unconfigured-verifier')
            return None
        (module, cls, pins, method_pins, adapter, evidence, authority, commits) = binding
        if (verifier is None or self.runner._register_reset_default_verifier is not verifier
                or type(verifier) is not cls or module.RegisterResetDefaultVerifier is not cls
                or module._TYPE is not cls or module._METHODS is not pins
                or self._register_reset_default_commits is not commits
                or getattr(verifier, '_commits', None) is not commits
                or self._register_program_runtime is not adapter or adapter.session is not self
                or adapter.runner is not self.runner
                or self.runner._native_reset_evidence is not evidence
                or self.runner._memory_commit_authority is not authority):
            raise ValueError('register-reset-default-session-object-drift')
        if (type(self._register_reset_default_max_records) is not int
                or type(self._register_reset_default_max_commands) is not int
                or type(self._register_reset_default_configuration_json) is not str):
            raise ValueError('register-reset-default-session-capacity-drift')
        if (json.loads(self._register_reset_default_configuration_json)['max_records']
                != self._register_reset_default_max_records
                or self._register_reset_default_max_commands > evidence._limits[1]):
            raise ValueError('register-reset-default-session-capacity-drift')
        for name, entry in method_pins.items():
            function, code = entry
            if (name in vars(verifier) or getattr(cls, name) is not function
                    or function.__code__ is not code):
                raise ValueError('register-reset-default-session-method-drift')
        if self._register_reset_default_sources_json is not None:
            paths = [row['path'] for row in json.loads(self._register_reset_default_sources_json)]
            if (_canonical_text(_register_reset_default_source_files(paths))
                    != self._register_reset_default_sources_json):
                raise ValueError('register-reset-default-session-source-drift')
        # Bounded capacity and a monotone, non-truncating retained prefix.
        if len(commits) < len(self._register_reset_default_commit_snapshot) or any(
                commits.get(commit_id) != encoded for commit_id, encoded
                in self._register_reset_default_commit_snapshot.items()):
            self._register_reset_default_mark('commit_truncation')
            raise ValueError('register-reset-default-commit-truncation')
        unmatched = list(self._register_reset_default_unmatched)
        if len(commits) > len(self._register_reset_default_commit_snapshot):
            spans = self._register_reset_default_selected_spans()
            for commit_id, encoded in commits.items():
                if commit_id in self._register_reset_default_commit_snapshot:
                    continue
                selected = self._register_reset_default_selected_commit(
                    encoded, spans)
                if selected is None:
                    unmatched.append(commit_id)
                else:
                    self._register_reset_default_selected[commit_id] = selected
            self._register_reset_default_commit_snapshot = dict(commits)
            self._register_reset_default_unmatched = tuple(unmatched)
        if len(commits) >= self._register_reset_default_max_records:
            self._register_reset_default_mark('capacity')
        if self._register_reset_default_unmatched:
            self._register_reset_default_mark('unselected_commit')
        intervals = {name: tuple(evidence._intervals[name]) for name in evidence._targets}
        previous_intervals = self._register_reset_default_intervals
        if previous_intervals is not None:
            for name, rows in previous_intervals.items():
                if intervals.get(name, ())[:len(rows)] != rows:
                    self._register_reset_default_mark('interval_truncation')
                    raise ValueError('register-reset-default-interval-truncation')
        self._register_reset_default_intervals = intervals
        if not allow_incomplete:
            if len(commits) >= self._register_reset_default_max_records:
                raise ValueError('register-reset-default-capacity')
            if self._register_reset_default_unmatched:
                raise ValueError('register-reset-default-unselected-commit')
            if self._register_reset_default_incomplete:
                raise ValueError('register-reset-default-incomplete:'
                                 + str(self._register_reset_default_reason))
        _RESET_DEFAULT_NATIVE_GUARD[0](self.runner, allow_incomplete=allow_incomplete,
                                       new_operation=new_operation)
        if (_canonical_text(verifier.configuration())
                != self._register_reset_default_configuration_json):
            self._register_reset_default_mark('configuration_drift')
            raise ValueError('register-reset-default-session-configuration-drift')
        return json.loads(self._register_reset_default_configuration_json)

    def _register_reset_default_configuration(self):
        _RESET_DEFAULT_GUARD(self, allow_incomplete=self._begun)
        return (json.loads(self._register_reset_default_configuration_json)
                if self._register_reset_default_verifier is not None else None)

    def register_reset_default_document(self):
        """One actual report, detached and purely validated; never an authority."""
        _RESET_DEFAULT_GUARD(self, allow_incomplete=self._begun)
        verifier = self._register_reset_default_verifier
        if verifier is None:
            return None
        adapter = self._register_program_runtime
        from .register_reset_default_verifier import (
            validate_register_reset_default_session_document)
        detached = json.loads(_canonical(verifier.session_document()))
        if (_canonical_text(detached['configuration'])
                != self._register_reset_default_configuration_json):
            raise ValueError('register-reset-default-session-document-configuration-drift')
        return validate_register_reset_default_session_document(
            detached, configuration=adapter.configuration())

    def _guard_register_verifier_configuration(self, *, allow_incomplete=False):
        verifier=self._register_verifier
        if verifier is None:
            guard_register_program_verifier(self.runner,allow_incomplete=allow_incomplete)
            return
        if self.runner._register_program_verifier is not verifier:
            raise ValueError('register-verifier-session-object-drift')
        paths=[row['path'] for row in json.loads(self._register_verifier_sources_json)]
        if _canonical(_register_program_verifier_source_files(paths))!=self._register_verifier_sources_json:
            raise ValueError('register-verifier-session-source-drift')
        for name,method in self._register_verifier_method_pins.items():
            if name in verifier.__dict__ or getattr(type(verifier),name) is not method:
                raise ValueError('register-verifier-session-method-drift')
        guard_register_program_verifier(self.runner,allow_incomplete=allow_incomplete)
        if _canonical(verifier.configuration())!=self._register_verifier_configuration_json:
            raise ValueError('register-verifier-session-configuration-drift')

    def _register_program_verifier_configuration(self):
        self._guard_register_verifier_configuration(allow_incomplete=self._begun)
        return (json.loads(self._register_verifier_configuration_json)
            if self._register_verifier is not None else None)

    def _register_program_verifier_document(self):
        configuration=self._register_program_verifier_configuration()
        if configuration is None:return None
        from .register_program_verifier import validate_register_program_verifier_session_document
        verifier=self._register_verifier
        document=verifier.session_document()
        if _canonical(document['configuration'])!=_canonical(configuration):
            raise ValueError('register-verifier-session-document-configuration-drift')
        return validate_register_program_verifier_session_document(json.loads(_canonical(document)),
            configuration=json.loads(self._register_program_configuration_json))

    def register_program_verifier_document(self):
        """Detached comparison evidence; never a saved-data authority installer."""
        return self._register_program_verifier_document()

    def _guard_ordinary_apb_configuration(self, *, allow_incomplete=False):
        self._guard_register_verifier_configuration(allow_incomplete=allow_incomplete)
        if self._ordinary_apb_observer is None:
            if self.runner._ordinary_apb_access_evidence is not None:
                raise ValueError('ordinary-apb-session-unconfigured-observer')
            return None
        if self.runner._ordinary_apb_access_evidence is not self._ordinary_apb_observer:
            raise ValueError('ordinary-apb-session-observer-drift')
        paths=[row['path'] for row in json.loads(self._ordinary_apb_sources_json)]
        if _canonical(_ordinary_apb_access_source_files(paths))!=self._ordinary_apb_sources_json:
            raise ValueError('ordinary-apb-session-source-drift')
        self._ordinary_apb_observer.validate(allow_incomplete=allow_incomplete)
        if self._ordinary_apb_observer.configuration_sha256!=self._ordinary_apb_configuration_sha256:
            raise ValueError('ordinary-apb-session-configuration-drift')

    def _ordinary_apb_configuration(self):
        self._guard_ordinary_apb_configuration(allow_incomplete=self._begun)
        if self._ordinary_apb_observer is None:return None
        return json.loads(self._ordinary_apb_configuration_json)

    def _ordinary_apb_document(self, *, validate=True):
        if type(validate) is not bool:raise ValueError('ordinary-apb-document-validation-boolean-required')
        configuration=self._ordinary_apb_configuration()
        if configuration is None:return None
        document=dict(schema_version='ordinary_apb_access_session.v1',configuration=configuration,
            state=self._ordinary_apb_observer.snapshot())
        document=json.loads(_canonical(document))
        return validate_ordinary_apb_access_session_document(document) if validate else document

    def configure_register_capability_preflight(self, requested_minimum_level=None):
        """Pin a fresh startup assessment; saved reports never install authority."""
        if (requested_minimum_level is not None and (type(requested_minimum_level) is not str
                or requested_minimum_level not in ('L1','L2','L3'))):
            raise ValueError('invalid-requested-minimum-level')
        adapter = self._register_program_runtime
        if (adapter is None or self._begun or self._finished or self.runner._status != 'created'):
            raise ValueError('register-capability-prebegin-adapter-required')
        if self._register_capability_preflight_json is not None:
            previous=json.loads(self._register_capability_preflight_json)
            if previous['requested_minimum_level'] != requested_minimum_level:
                raise ValueError('register-capability-already-configured')
            return self._register_capability_preflight()
        document=adapter.capability_preflight(requested_minimum_level=requested_minimum_level)
        from .register_program_capabilities import validate_register_capability_preflight_document
        document=validate_register_capability_preflight_document(document,configuration=adapter.configuration())
        document_json=_canonical(document)
        sources_json=_canonical(_register_capability_source_files())
        self._register_capability_preflight_json=document_json
        self._register_capability_sources_json=sources_json
        return json.loads(self._register_capability_preflight_json)

    def _register_capability_preflight(self, *, allow_incomplete=False):
        self._guard_ordinary_apb_configuration(allow_incomplete=allow_incomplete)
        if self._register_capability_preflight_json is None:
            return None
        adapter=self._register_program_runtime
        if not self._begun:
            adapter.validate()
        configuration = adapter.snapshot()['configuration'] if self._begun else adapter.configuration()
        if (_canonical(configuration) != self._register_program_configuration_json
                or _canonical(_register_capability_source_files()) != self._register_capability_sources_json):
            raise ValueError('register-capability-configuration-drift')
        document=json.loads(self._register_capability_preflight_json)
        if not self._begun:
            actual=adapter.capability_preflight(requested_minimum_level=document['requested_minimum_level'])
            if _canonical(actual) != self._register_capability_preflight_json:
                raise ValueError('register-capability-startup-drift')
        return document

    def _register_configuration(self):
        adapter = self._register_program_runtime
        if adapter is None:
            return None
        adapter.validate()
        if _canonical(adapter.configuration()) != self._register_program_configuration_json:
            raise ValueError('register-program-configuration-drift')
        return adapter.configuration()

    def _guard_register_submission(self, case):
        self._guard_ordinary_apb_configuration()
        adapter = self._register_program_runtime
        if adapter is None:
            return
        adapter.validate()
        active = getattr(adapter,'_active_submission',None)
        if (type(active) is not tuple or len(active) != 2 or active[0] is not case
                or not adapter._records or adapter._records[-1]['status'] != 'attempted'
                or adapter._records[-1]['phase'] != 'session_submission'
                or _canonical(active[1]) != _canonical(adapter._records[-1]['manifest'])):
            raise ValueError('register-program-direct-byte-submission-forbidden')
        manifest = active[1]
        source = manifest['program']['source']
        request = manifest['request']
        expected = OnlineCase(request['case_id'], 'CPU_TO_IP_TO_CPU' if request['operation']=='register_read'
            else 'CPU_TO_IP','register_program',OnlineInstruction(**source),
            tuple(BatchAdvance(self.template.schedule_order) for _ in range(adapter.advance_rounds)))
        action = self.prerequisite_gate._resolve(case.source.action_id)
        if case != expected or _canonical(action.document()) != _canonical(manifest['admitted_action']):
            raise ValueError('register-program-live-admission-disagreement')

    @property
    def cases(self) -> tuple[OnlineCase, ...]:
        return tuple(self._cases)

    @property
    def manifest_sha256(self) -> str:
        if not self._manifest_sha256:
            raise RuntimeError("online session identity is unavailable before begin")
        return self._manifest_sha256

    @property
    def manifest_document(self) -> dict:
        if self._manifest_document is None:
            raise RuntimeError("online session identity is unavailable before begin")
        return json.loads(_canonical(self._manifest_document))

    def declare_instruction_slots(self, component: str, address: int,
                                  count: int = 1) -> None:
        """Reserve online fetch slots before startup and retain replay setup."""
        if self._begun or self._finished:
            raise RuntimeError("instruction slots must be declared before begin")
        session = self.runner.sessions.get(component)
        declare = getattr(session, "declare_instruction_slots", None)
        if session is None or not callable(declare):
            raise ValueError("component cannot declare online instruction slots")
        declare(address, count)
        self._instruction_slots.append((component, address, count))

    def mutate_initial_ram_data(self, *, declaration, raw, enabled: bool = True,
                                max_bytes: int = 1,
                                source: str = "constructor") -> dict:
        """Decide one declared initial RAM data byte before the session starts.

        Plan requirement (P4/A2): "初始数据在会话启动前变异；会话内仅未知数据字节
        的首次读取可物化一次".  The decision is a *declaration*, not a memory
        write: an adopted byte is appended to this session template's initial
        images, so ``begin()`` preloads it exactly like every other declared
        image and a fresh replay rebuilds it from the saved plan alone -- no
        operator state has to be replayed and no byte is rewritten later.

        Fail closed, and record why: a byte a declared image already fixes, a
        byte a reserved online instruction slot will be fetched from, a byte a
        real read or Store already determined, a byte this operator already
        decided, a drawn byte this session's memory does not declare, a
        malformed record and every call after ``begin()`` are refused with the
        shipped rejection code that applies, and nothing is mutated.
        """
        if self._begun or self._finished:
            raise RuntimeError("initial RAM data must be mutated before begin")
        if not isinstance(declaration, TrustedInitialRamDataDeclaration):
            raise ValueError(
                "initial RAM data requires a TrustedInitialRamDataDeclaration")
        if type(enabled) is not bool:
            raise ValueError("initial RAM data enabled must be boolean")
        if (type(max_bytes) is not int or isinstance(max_bytes, bool)
                or max_bytes < 1):
            raise ValueError(
                "initial RAM data max_bytes must be a positive integer")
        if source not in ("constructor", "environment", "default"):
            raise ValueError(
                "initial RAM data source must name its own declaration")
        if (self._initial_ram_declaration is not None
                and self._initial_ram_declaration.declaration_id
                != declaration.declaration_id):
            # The declared window is fixed once per session: a second, different
            # declaration could silently widen what the operator may touch.
            raise ValueError(
                "the session's initial RAM data declaration is fixed once")
        memory = getattr(self.runner.sessions.get(declaration.component),
                         "memory", None)
        state = InitialRamDataState(
            regions=tuple((row["memory_id"], row["base"],
                           row["base"] + row["size"])
                          for row in (memory.identity_document()["regions"]
                                      if memory is not None else ())),
            determined=(tuple(memory.determined_bytes())
                        if memory is not None else ()),
            reserved=(tuple(memory.reserved_instruction_bytes())
                      if memory is not None else ()),
            fixed_images=tuple(
                (image.component, image.address, image.address + len(image.data),
                 image.image_id)
                for image in self.template.initial_images),
            adopted=tuple((row["memory_id"], row["byte_offset"], row["value"])
                          for row in self._initial_ram_adopted))
        decision = evaluate_initial_ram_data(declaration, raw, state,
                                             enabled=enabled,
                                             max_bytes=max_bytes)
        adopted = decision["adopted"]
        if adopted is not None:
            image = MemoryImage(adopted["image_id"], declaration.component,
                                adopted["address"],
                                bytes((adopted["value"],)).hex())
            # ``replace`` re-runs the genome validation, so a duplicate image
            # identity or an undeclared component is refused here too.
            self.template = replace(
                self.template,
                initial_images=(*self.template.initial_images, image))
            self._initial_ram_adopted.append(dict(adopted))
        if self._initial_ram_declaration is None:
            self._initial_ram_declaration = declaration
            self._initial_ram_enabled = enabled
            self._initial_ram_source = source
        self._initial_ram_max_bytes = max(self._initial_ram_max_bytes, max_bytes)
        self._initial_ram_attempts += 1
        if adopted is None:
            self._initial_ram_refusals[decision["reason"]] += 1
            rejection = decision["rejection"]
            if rejection is not None:
                self._initial_ram_codes[rejection["code"]] += 1
        if isinstance(raw, bytes) and len(self._initial_ram_raws) < 16:
            # The raw record is the whole input of the draw, so the run states
            # its digest (and its bytes when short) next to the proposal.
            self._initial_ram_raws.append(
                {"sha256": hashlib.sha256(raw).hexdigest(),
                 "hex": raw.hex() if len(raw) <= 64 else None,
                 "bytes": len(raw)})
        return decision

    def initial_ram_data_state(self) -> dict | None:
        """The operator's own run state, or ``None`` if it was never declared.

        Reported by the live run so an A/B pair is told apart by its own record.
        It is run state, not construction identity: with the operator undeclared
        this returns ``None`` and no artifact, manifest or decision changes.
        """
        if self._initial_ram_declaration is None:
            return None
        declaration = self._initial_ram_declaration
        return {
            "schema_version": "initial_ram_data_state.v1",
            "enabled": self._initial_ram_enabled,
            "source": self._initial_ram_source,
            "declaration": declaration.document(),
            "operator": {
                "source": operator_source_identity(),
                "domain": "myfuzz.online.initial_ram_data.v1",
                "domain_sha256": hashlib.sha256(
                    INITIAL_RAM_DATA_DOMAIN).hexdigest(),
                "raws": [dict(row) for row in self._initial_ram_raws],
            },
            "attempts": self._initial_ram_attempts,
            "adopted": len(self._initial_ram_adopted),
            "bounds": {"max_bytes": self._initial_ram_max_bytes,
                       "window_bytes": declaration.byte_count,
                       "value_mask": declaration.value_mask},
            "refusals": dict(sorted(self._initial_ram_refusals.items())),
            "rejection_codes": dict(sorted(self._initial_ram_codes.items())),
            "bytes": [dict(row) for row in self._initial_ram_adopted],
        }

    def begin(self) -> None:
        if self._begun or self._finished:
            raise RuntimeError("session begins exactly once")
        for image in self.template.initial_images:
            if image.component not in self.runner.sessions:
                raise ValueError("image references unknown harness")
            if getattr(self.runner.sessions[image.component], "memory", None) is None:
                raise ValueError("image destination has no persistent memory")
        if self._runtime_compiled is not None:
            self._runtime_compiled.validate_topology()
        self._manifest_document = _online_manifest(
            self.runner, self.checker, runtime_paths=self.runtime_path_document,
            checker_configuration_only=self._checker_configuration_only,
            register_program_configuration=self._register_configuration(),
            register_capability_preflight=self._register_capability_preflight(),
            ordinary_apb_access_evidence_configuration=self._ordinary_apb_configuration(),
            ordinary_apb_access_source_files=json.loads(self._ordinary_apb_sources_json) if self._ordinary_apb_sources_json is not None else None,
            register_program_verifier_configuration=self._register_program_verifier_configuration(),
            register_program_verifier_source_files=json.loads(self._register_verifier_sources_json) if self._register_verifier_sources_json is not None else None,
            register_reset_default_configuration=self._register_reset_default_configuration(),
            register_reset_default_source_files=json.loads(self._register_reset_default_sources_json) if self._register_reset_default_sources_json is not None else None)
        self._manifest_sha256 = hashlib.sha256(
            _canonical(self._manifest_document)).hexdigest()
        if self._register_program_runtime is not None:
            self._resume_checker = self.checker
            self._resume_checker_implementation = _reset_resume_checker_identity(self.checker)
            self._resume_gate = self.prerequisite_gate
            self._resume_gate_observe = (self._resume_gate.observe
                if self._resume_gate is not None else None)
        for image in self.template.initial_images:
            self.runner.preload_image(image)
        self.runner.begin_test(self.template.testcase_id)
        self._begun = True

    def reset(self, policy: str):
        """Reset all components between committed cases and retain replay order."""
        if (not self._begun or self._finished or self._halted or not self._cases
                or self.runner._status != 'running'):
            raise RuntimeError('online reset requires an active committed case prefix')
        if policy not in ('warm_all', 'cold_all'):
            raise ValueError('unsupported online reset policy')
        if len(self._reset_operations) >= 65536:
            raise ValueError('online reset operation capacity exceeded')
        if self.runner.command_epoch != len(self._reset_operations):
            raise ValueError('online session has an unrecorded reset')
        _RESET_DEFAULT_GUARD(self, new_operation=False)
        self._guard_ordinary_apb_configuration()
        try:
            result = self.runner.reset_all(policy)
        except BaseException:
            self._uncertain_reset = True
            self._halted = True
            self._halt_reason = 'uncertain_effect'
            raise
        self._reset_operations.append(dict(after_cases=len(self._cases), policy=policy))
        return result

    def _encoded_reset_operations(self):
        if not any(self._reset_resume_advances.values()):
            return list(self._reset_operations)
        return [dict(row, advances=[list(item.schedule) for item in
                    self._reset_resume_advances.get(index, ())])
                for index, row in enumerate(self._reset_operations)]

    def _guard_reset_resume(self, *, allow_incomplete=False):
        if ('_guard_reset_resume' in self.__dict__
                or type(self)._guard_reset_resume is not _RESET_RESUME_GUARD):
            raise ValueError('reset resume guard method drift')
        if ('_encoded_reset_operations' in self.__dict__
                or type(self)._encoded_reset_operations is not _RESET_RESUME_SERIALIZER):
            raise ValueError('reset resume serializer method drift')
        if any(actual is not pinned for actual, pinned in zip(
                _reset_resume_checker_identity(self.checker), self._resume_checker_implementation)):
            raise ValueError('reset resume checker implementation drift')
        for name, (class_method, bound_method) in self._resume_runner_methods.items():
            if (getattr(type(self.runner), name) is not class_method
                    or getattr(self.runner, name) != bound_method):
                raise ValueError('reset resume runner method drift:' + name)
        if ('advance_after_reset' in self.__dict__
                or type(self).advance_after_reset is not _RESET_RESUME_METHOD):
            raise ValueError('reset resume session method drift')
        if (self.checker is not self._resume_checker
                or self.prerequisite_gate is not self._resume_gate
                or self._resume_gate is not None and self._resume_gate.observe != self._resume_gate_observe):
            raise ValueError('reset resume checker or gate method drift')
        adapter = self._register_program_runtime
        binding = self._register_export_runtime_binding
        if (binding is None or binding[0] is not adapter or adapter.session is not self
                or adapter.runner is not self.runner
                or type(adapter) is not binding[1]
                or 'validate_static_configuration' in vars(adapter)
                or type(adapter).validate_static_configuration is not binding[2]):
            raise ValueError('reset resume runtime binding drift')
        binding[2](adapter)
        self._register_capability_preflight(allow_incomplete=allow_incomplete)

    def advance_after_reset(self, schedule: tuple[str, ...]) -> OnlineCaseReceipt:
        """Record actual bootstrap/resident-program execution after the latest reset."""
        adapter = self._register_program_runtime
        if (not self._begun or self._finished or self._halted
                or self.runner._status != 'running' or self._uncertain_reset
                or self._uncertain_reset_advance or adapter is None
                or adapter._uncertain or adapter._active_submission is not None
                or not self._reset_operations or not self._cases
                or self._reset_operations[-1]['after_cases'] != len(self._cases)
                or self.runner.command_epoch != len(self._reset_operations)):
            raise RuntimeError('reset resume requires an active certain reset boundary')
        if (type(schedule) is not tuple or not schedule
                or any(type(name) is not str or name not in self.template.schedule_order for name in schedule)):
            raise ValueError('invalid reset resume schedule')
        index = len(self._reset_operations) - 1
        previous = self._reset_resume_advances.get(index, ())
        ordinal = len(previous) + 1
        if len(schedule) + sum(len(item.schedule) for item in previous) > self.template.max_steps:
            raise ValueError('reset resume step capacity exceeded')
        _RESET_DEFAULT_GUARD(self, new_operation=False)
        _RESET_RESUME_GUARD(self)
        advance = BatchAdvance(schedule)
        start = self.runner.event_count
        before = dict(self.runner.local_ticks)
        self._reset_resume_advances.setdefault(index, []).append(advance)
        try:
            self._resume_runner_methods['step_batch'][1](schedule)
            _RESET_RESUME_GUARD(self)
            receipt = OnlineCaseReceipt(
                f'{self.template.testcase_id}:reset:{index}:advance:{ordinal}',
                start, self.runner.event_count, self.runner.events_since(start),
                before, dict(self.runner.local_ticks), self.runner.failure_status or 'running')
            if self.checker is not None:
                findings = self.checker(receipt)
                if type(findings) is not tuple or any(type(item) is not str for item in findings):
                    raise ValueError('online checker must return a tuple of finding IDs')
                _RESET_RESUME_GUARD(self)
                if findings:
                    raise RuntimeError('reset resume checker finding')
            if self.runner.failure_status:
                raise RuntimeError('reset resume execution failure')
            if self.prerequisite_gate is not None:
                self._resume_gate_observe(receipt)
            _RESET_RESUME_GUARD(self)
            self._resume_runner_methods['retire_step_receipts_through'][1](
                self.runner.command_epoch, self.runner._next_command_sequence - 1)
            _RESET_RESUME_GUARD(self)
            return receipt
        except BaseException:
            self._uncertain_reset_advance = True
            self._halted = True
            if self._halt_reason is None:
                self._halt_reason = 'uncertain_effect'
            raise

    def advance_initial(self, schedule: tuple[str, ...]) -> OnlineCaseReceipt:
        """Advance fixed bootstrap once and preserve its steps for replay."""
        if (not self._begun or self._finished or self._halted or self._cases
                or self.runner._status != "running"):
            raise RuntimeError("bootstrap advance requires an active pre-case session")
        advance = BatchAdvance(schedule)
        if any(component not in self.runner.sessions for component in advance.schedule):
            raise ValueError("bootstrap schedule references unknown harness")
        _RESET_DEFAULT_GUARD(self, new_operation=False)
        self._guard_ordinary_apb_configuration()
        start = self.runner.event_count
        ticks_before = dict(self.runner.local_ticks)
        self._warmup_advances.append(advance)
        try:
            self.runner.step_batch(advance.schedule)
        except BaseException:
            self._halted = True
            self._halt_reason = "uncertain_effect"
            raise
        receipt = OnlineCaseReceipt(
            f"{self.template.testcase_id}:bootstrap:{len(self._warmup_advances)}",
            start, self.runner.event_count, self.runner.events_since(start),
            ticks_before, dict(self.runner.local_ticks),
            self.runner.failure_status or "running")
        if self.checker is not None:
            try:
                violations = self.checker(receipt)
                if not isinstance(violations, tuple) or any(
                        not isinstance(item, str) for item in violations):
                    raise ValueError("online checker must return a tuple of finding IDs")
            except BaseException:
                self._halted = True
                self._halt_reason = "environment_error"
                raise
            if violations:
                self._halted = True
                self._halt_reason = "finding"
                receipt = replace(receipt, violations=violations, status="finding")
        self.runner.retire_step_receipts_through(
            self.runner.command_epoch, self.runner._next_command_sequence - 1)
        if self.prerequisite_gate is not None:
            self.prerequisite_gate.observe(receipt)
        return receipt

    def submit_case(self, case: OnlineCase, *, source_role: str = "fuzz_source") -> OnlineCaseReceipt:
        if not isinstance(case, OnlineCase):
            raise ValueError("OnlineCase is required")
        if type(source_role) is not str or source_role not in ("fuzz_source", "bootstrap"):
            raise ValueError("online source_role must be fuzz_source or bootstrap")
        _RESET_DEFAULT_GUARD(self, new_operation=False)
        self._guard_register_submission(case)
        existing = self._receipts.get(case.case_id)
        if existing is not None:
            if existing[0] != case or self._case_source_roles[case.case_id] != source_role:
                raise ValueError("case_id was reused with different input")
            # Only the receipt metadata is retained.  Its event suffix is
            # recovered from the runner's authoritative event log on retry.
            metadata = existing[1]
            return replace(metadata, events=self.runner.events_since(metadata.event_start)
                           [:metadata.event_end - metadata.event_start])
        if (not self._begun or self._finished or self._halted
                or self.runner._status != "running"):
            raise RuntimeError("online case requires an active session")
        if self.prerequisite_gate is not None:
            # Query cross-case prerequisites before any RTL command, so a
            # refusal leaves the runner, memory and case history untouched.
            self.prerequisite_gate.require_case(case)
        source_id = self._validate_runtime_case(case)
        action_ids = (case.source.action_id,
                      *(item.action_id for item in case.support_instructions))
        if any(action_id in self._source_ids for action_id in action_ids):
            raise ValueError("source action_id must be unique in a session")
        if any(component not in self.runner.sessions
               for advance in case.advances for component in advance.schedule):
            raise ValueError("case schedule references unknown harness")
        if sum(len(advance.schedule) for advance in case.advances) > self.template.max_steps:
            raise ValueError("case exceeds local step limit")
        if isinstance(case.source, BatchSourceEvent):
            source = case.source
            field_width = self.runner.ownership.field_width(source.component, source.port)
            width = source.width if source.width is not None else field_width
            self.runner.ownership.mutation_source(
                source.component, source.port, source.bit_offset, width,
                direction=case.direction)
            if type(source.value) is not int or not 0 <= source.value < 1 << width:
                raise ValueError("source value exceeds declared segment")
        else:
            session = self.runner.sessions.get(case.source.component)
            if session is None or not callable(getattr(session, "accept_instructions", None)):
                raise ValueError("CPU harness does not support online instruction input")
        for support in case.support_instructions:
            session = self.runner.sessions.get(support.component)
            if session is None or not callable(getattr(session, "accept_instructions", None)):
                raise ValueError("support CPU harness cannot accept fixed instructions")
        provenance = self.runner.provenance_enabled
        admissions = (_case_admissions(case, len(self._cases), source_id, source_role)
                      if provenance else ())
        start = self.runner.event_count
        ticks_before = dict(self.runner.local_ticks)
        # Record the attempted input before touching RTL so the exact prefix
        # remains available even if a local command fails partway through.
        declaration_reader = getattr(self.prerequisite_gate, 'replay_case_declaration', None)
        if declaration_reader is not None:
            self._prerequisite_admissions.append(declaration_reader(case))
        self._cases.append(case)
        self._case_source_roles[case.case_id] = source_role
        self._source_ids.update(action_ids)
        if provenance:
            self.runner.set_observation_case(case.case_id, len(self._cases) - 1)
        try:
            receipt = self._execute_case(case, start, ticks_before, admissions)
        finally:
            if provenance:
                self.runner.clear_observation_case()
        if self.prerequisite_gate is not None:
            self.prerequisite_gate.observe(receipt)
        return receipt

    def _execute_case(self, case: OnlineCase, start: int,
                      ticks_before: dict[str, int],
                      admissions: tuple[SourceAdmission, ...]) -> OnlineCaseReceipt:
        phase = "provenance_admission"
        command_index = None
        try:
            for command_index, admission in enumerate(admissions):
                self.runner.register_source_admission(admission)
            phase = "support_admission"
            command_index = None
            for command_index, support in enumerate(case.support_instructions):
                self.runner.sessions[support.component].accept_instructions(
                    support.address, support.data,
                    source_event_id=support.action_id)
            phase = "source_admission"
            command_index = None
            if isinstance(case.source, BatchSourceEvent):
                scheduled_tick = self.runner.inject_source(
                    case.source.component, case.source.port, case.source.value,
                    direction=case.direction, bit_offset=case.source.bit_offset,
                    width=case.source.width, action_id=case.source.action_id)
                if scheduled_tick is not None:
                    self._source_schedule_ticks[case.source.action_id] = scheduled_tick
            else:
                self.runner.sessions[case.source.component].accept_instructions(
                    case.source.address, case.source.data,
                    source_event_id=case.source.action_id)
            phase = "step"
            for command_index, advance in enumerate(case.advances):
                self.runner.step_batch(advance.schedule)
        except BaseException as exc:
            # A partially executed case has already changed real RTL state;
            # another input must not be admitted into that uncertain prefix.
            self._halted = True
            self._halt_reason = "uncertain_effect"
            self._terminal_failure = {
                "phase": phase, "case_index": len(self._cases) - 1,
                "case_id": case.case_id, "command_index": command_index,
                "error_type": type(exc).__name__, "error_message": str(exc)}
            raise
        receipt = OnlineCaseReceipt(
            case.case_id, start, self.runner.event_count,
            self.runner.events_since(start), ticks_before,
            dict(self.runner.local_ticks), self.runner.failure_status or "running")
        if self.checker is not None:
            try:
                violations = self.checker(receipt)
                if not isinstance(violations, tuple) or any(
                        not isinstance(item, str) for item in violations):
                    raise ValueError("online checker must return a tuple of finding IDs")
            except BaseException as exc:
                self._halted = True
                self._halt_reason = "environment_error"
                self._terminal_failure = {
                    "phase": "checker", "case_index": len(self._cases) - 1,
                    "case_id": case.case_id, "command_index": None,
                    "error_type": type(exc).__name__, "error_message": str(exc)}
                raise
            if violations:
                receipt = replace(receipt, violations=violations, status="finding")
                self._halted = True
                self._halt_reason = "finding"
        self.runner.retire_step_receipts_through(
            self.runner.command_epoch, self.runner._next_command_sequence - 1)
        self._receipts[case.case_id] = (case, replace(receipt, events=()))
        return receipt

    def trace(self, *, genome_sha256: str | None = None,
              defer_semantic_hash: bool = False) -> ScenarioTrace:
        if not self._begun:
            raise RuntimeError("session has not begun")
        events = self.runner.events
        ticks = dict(self.runner.local_ticks)
        status = self.runner.failure_status or self._halt_reason or (
            "complete" if self._finished else "running")
        identity = genome_sha256 or hashlib.sha256(self.encode_plan()).hexdigest()
        return ScenarioTrace(identity, status, events, ticks,
                             ("" if defer_semantic_hash else
                              _trace_semantic_sha256(status, events, ticks)),
                             self._manifest_sha256)

    def finish(self, *, defer_semantic_hash: bool = False) -> ScenarioTrace:
        if not self._begun or self._finished:
            raise RuntimeError("session finish requires an active session")
        self.runner.finalize()
        self._finished = True
        return self.trace(defer_semantic_hash=defer_semantic_hash)

    def finish_export(self, *, defer_semantic_hash: bool = False) -> tuple[bytes, ScenarioTrace]:
        """Finalize actual execution and encode its complete checked input once."""
        if not self._begun or self._finished:
            raise RuntimeError("session finish requires an active session")
        def check_methods():
            for name, method in _FINAL_EXPORT_METHOD_PINS.items():
                if name in self.__dict__ or getattr(type(self), name) is not method:
                    raise ValueError('session-final-export-method-drift:' + name)
        def check_runtime():
            binding = self._register_export_runtime_binding
            if binding is None:
                if self._register_program_runtime is not None:
                    raise ValueError('session-final-export-runtime-binding-drift')
                return
            adapter, adapter_type, static_check, static_json = binding
            if (self._register_program_runtime is not adapter or type(adapter) is not adapter_type
                    or adapter.session is not self or adapter.runner is not self.runner
                    or adapter._static_json is not static_json
                    or 'validate_static_configuration' in vars(adapter)
                    or adapter_type.validate_static_configuration is not static_check):
                raise ValueError('session-final-export-runtime-binding-drift')
            static_check(adapter)
        check_methods()
        check_runtime()
        _RESET_DEFAULT_GUARD(self, allow_incomplete=True)
        if any(self._reset_resume_advances.values()):
            _RESET_RESUME_GUARD(self, allow_incomplete=True)
        self.runner.finalize()
        self._finished = True
        check_methods()
        check_runtime()
        _RESET_DEFAULT_GUARD(self, allow_incomplete=True)
        if any(self._reset_resume_advances.values()):
            _RESET_RESUME_GUARD(self, allow_incomplete=True)
        plan = _FINAL_EXPORT_METHOD_PINS['encode_plan'](self)
        trace = _FINAL_EXPORT_METHOD_PINS['trace'](self,
            genome_sha256=hashlib.sha256(plan).hexdigest(),
            defer_semantic_hash=defer_semantic_hash)
        return plan, trace

    def encode_plan(self) -> bytes:
        """Canonical full input prefix for fresh replay and corpus storage."""
        if self._uncertain_reset or self._uncertain_reset_advance or self.runner.command_epoch != len(self._reset_operations):
            raise ValueError('online plan cannot encode an uncertain or unrecorded reset')
        if any(self._reset_resume_advances.values()):
            _RESET_RESUME_GUARD(self, allow_incomplete=True)
        cases = []
        for case in self._cases:
            source = asdict(case.source)
            source["kind"] = ("instruction" if isinstance(case.source, OnlineInstruction)
                              else "source_event")
            if case.source.action_id in self._source_schedule_ticks:
                source["scheduled_local_tick"] = self._source_schedule_ticks[
                    case.source.action_id]
            cases.append({"case_id": case.case_id, "direction": case.direction,
                          "path_id": case.path_id, "source": source,
                          "support_instructions": [asdict(item)
                                                   for item in case.support_instructions],
                          "advances": [list(item.schedule) for item in case.advances]})
            if self.runner.provenance_enabled:
                cases[-1]["source_role"] = self._case_source_roles[case.case_id]
        document = {"schema_version": 6 if self._source_schedule_ticks else 4,
                    "template": json.loads(GenomeCodec.encode(self.template)),
                    "instruction_slots": [list(item)
                                          for item in self._instruction_slots],
                    "warmup_advances": [list(item.schedule)
                                        for item in self._warmup_advances],
                    "cases": cases}
        if self._terminal_failure is not None:
            document["schema_version"] = 7 if self._source_schedule_ticks else 5
            document["terminal_failure"] = self._terminal_failure
        if self._runtime_prepared is not None:
            document["schema_version"] = 9 if self._terminal_failure is not None else 8
            document["runtime_paths"] = self.runtime_path_document
        if self.runner.provenance_enabled:
            document["schema_version"] = 11 if self._terminal_failure is not None else 10
            document["provenance_configuration"] = self.runner.provenance_configuration
            document["source_admissions"] = self.runner.source_admissions
        if self.runner.persistent_memory_prerequisite_gate is not None:
            if len(self._prerequisite_admissions) != len(self._cases):
                raise ValueError('trusted plan requires one admission declaration per case')
            document['schema_version'] = 13 if self._terminal_failure is not None else 12
            document['prerequisite_admissions'] = self._prerequisite_admissions
        if self._reset_operations:
            document['schema_version'] = 15 if self._terminal_failure is not None else 14
            document['reset_operations'] = self._reset_operations
        if self._register_program_runtime is not None:
            state = self._register_program_runtime.snapshot()
            if _canonical(state['configuration']) != self._register_program_configuration_json:
                raise ValueError('register-program-configuration-drift')
            records = state['records']
            uncertain = state['uncertain']
            terminal = records[-1] if uncertain and records else None
            manifests = [record['manifest'] for record in records if record['case_index'] is not None]
            document['schema_version'] = (19 if uncertain else 18) if any(self._reset_resume_advances.values()) else (17 if uncertain else 16)
            document['reset_operations'] = _RESET_RESUME_SERIALIZER(self)
            document['register_programs'] = dict(schema_version='register_program_session.v1',
                configuration=json.loads(self._register_program_configuration_json),
                case_manifests=manifests,terminal_attempt=terminal,
                gate_state=self.prerequisite_gate.document())
            capability = self._register_capability_preflight(allow_incomplete=self._begun)
            if capability is not None:
                document['register_programs']['capability_preflight'] = capability
            ordinary=self._ordinary_apb_document(validate=False)
            if ordinary is not None:document['register_programs']['ordinary_apb_access_evidence']=ordinary
            verifier=self._register_program_verifier_document()
            if verifier is not None:document['register_programs']['register_program_verifier']=verifier
            reset_default=self.register_reset_default_document()
            if reset_default is not None:
                document['register_programs']['register_reset_default']=reset_default
            if uncertain:
                document['terminal_failure'] = self._terminal_failure
            validate_register_program_plan(document)
            _validate_register_program_state(state,document['register_programs'])
        if self._ordinary_apb_observer is not None and self._register_program_runtime is None:
            raise ValueError('ordinary-apb-session-saving-requires-register-runtime')
        return _canonical(document)

    def record(self, genome: ScenarioGenome) -> ScenarioTrace:
        """Narrow RFuzz bridge for one online external source mutation.

        Startup images must match the session template.  RFuzz mutation of a
        boot image is not an online instruction source and is rejected here.
        """
        if not isinstance(genome, ScenarioGenome) or genome.initial_images != self.template.initial_images:
            raise ValueError("online RFuzz case cannot change initialized images")
        if genome.reset_actions or genome.quiesce_steps or len(genome.actions) != 1:
            raise ValueError("online RFuzz case requires exactly one source action")
        if not self._begun:
            self.begin()
        action = genome.actions[0]
        if action.trigger.kind != "START" or action.delay_ticks:
            raise ValueError("online RFuzz source must be immediate")
        if set(genome.schedule_order) != set(self.runner.sessions):
            raise ValueError("online RFuzz schedule must contain every harness")
        schedule = []
        remaining = genome.max_steps
        while remaining:
            group = genome.schedule_order[:remaining]
            schedule.append(BatchAdvance(group))
            remaining -= len(group)
        occurrence = self._record_sequence
        self.submit_case(OnlineCase(
            f"{genome.testcase_id}:{occurrence}", genome.direction, genome.path_id,
            BatchSourceEvent(f"{genome.testcase_id}:{action.action_id}:{occurrence}",
                             action.component, action.port,
                             action.value, action.bit_offset, action.width),
            tuple(schedule)))
        self._record_sequence += 1
        trace = self.trace(genome_sha256=hashlib.sha256(GenomeCodec.encode(genome)).hexdigest())
        if trace.status != "running":
            return trace
        # The slot finished while the shared session remains open. Keep the
        # per-slot verdict distinct from the session lifecycle state.
        status = "complete"
        semantic = _trace_semantic_sha256(status, trace.events,
                                          trace.local_ticks)
        return replace(trace, status=status, semantic_sha256=semantic)


def _register_plain_json(value):
    """Check exact JSON types; scalar-only leaves need no traversal frames."""
    none_type=type(None);kind=type(value)
    if kind is str or kind is int or kind is bool or kind is none_type:return True
    if kind is not list and kind is not dict:return False
    identifier=id(value);active={identifier};completed=set()
    stack=[(identifier,iter(value.items()) if kind is dict else iter(value),kind is dict)]
    while stack:
        identifier,iterator,mapping=stack[-1]
        for entry in iterator:
            if mapping:
                key,item=entry
                if type(key) is not str:return False
            else:item=entry
            kind=type(item)
            if kind is str or kind is int or kind is bool or kind is none_type:continue
            if kind is list:
                if len(item)==2:
                    first=type(item[0]);second=type(item[1])
                    if (first is str or first is int or first is bool or first is none_type) and (second is str or second is int or second is bool or second is none_type):continue
                if all((_leaf_type:=type(leaf)) is str or _leaf_type is int or _leaf_type is bool or _leaf_type is none_type for leaf in item):continue
            elif kind is dict:
                if all(type(key) is str and ((_leaf_type:=type(leaf)) is str or _leaf_type is int or _leaf_type is bool or _leaf_type is none_type) for key,leaf in item.items()):continue
            else:return False
            child=id(item)
            if child in active:return False
            if child in completed:continue
            active.add(child);stack.append((child,iter(item.items()) if kind is dict else iter(item),kind is dict));break
        else:stack.pop();active.remove(identifier);completed.add(identifier)
    return True


def _validate_register_manifest(manifest, configuration):
    from .register_program_runtime import validate_register_request
    from .source_actions import SourceAction
    if (type(manifest) is not dict or set(manifest) != {'schema_version','request','configuration',
            'context','program','source_action','admitted_action'}
            or manifest['schema_version'] != 'register_program_runtime_manifest.v1'
            or _canonical(manifest['configuration']) != _canonical(configuration)
            or type(manifest['context']) is not dict or type(manifest['program']) is not dict):
        raise ValueError('invalid register program manifest')
    request = validate_register_request(manifest['request'])
    context = manifest['context']
    context_keys = {'generation','reset_epoch','tracker_epoch','waiting_transaction','command_epoch',
        'waiting_instruction_address','program_size','target_reset_epoch','address_base','endpoint_id'}
    if (set(context) != context_keys or any(type(context[key]) is not int or context[key]<0
            for key in context_keys-{'waiting_transaction','endpoint_id'})
            or context['endpoint_id'] != request['endpoint_id']
            or type(context['waiting_transaction']) is not dict
            or set(context['waiting_transaction']) != {'execution_id','testcase_id','source_component',
                'source_epoch','channel_id','source_sequence'}):
        raise ValueError('invalid register program context')
    from .ledger import TransactionKey
    transaction = context['waiting_transaction']
    if (any(type(transaction[key]) is not str or not transaction[key]
            for key in ('execution_id','testcase_id','source_component','channel_id'))
            or any(type(transaction[key]) is not int or transaction[key]<0
                   for key in ('source_epoch','source_sequence'))
            or transaction['source_component'] != configuration['cpu_component']
            or transaction['source_epoch'] != context['reset_epoch']
            or context['waiting_instruction_address']%4 or context['address_base']%4
            or not 16 <= context['program_size'] <= configuration['max_program_bytes']
            or context['program_size']%4
            or context['waiting_instruction_address']+context['program_size'] > 1<<32):
        raise ValueError('invalid register program waiting transaction')
    TransactionKey(**transaction)
    program = manifest['program']
    if (set(program) != {'schema_version','profile_fingerprint','sidecar_fingerprint','operation_plan',
            'scope','grants_prerequisites','source','fragment_sha256','result_storage','access_context','identity_sha256'}
            or program.get('schema_version') != 'declarative_register_program.v1'
            or program['scope'] != 'declarative_cpu_register_program_only' or program['grants_prerequisites'] is not False
            or 'identity_sha256' not in program
            or hashlib.sha256(json.dumps({k:v for k,v in program.items() if k!='identity_sha256'},
                sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
                != program['identity_sha256']):
        raise ValueError('invalid register program compiler identity')
    raw_source = program['source']
    if (type(raw_source) is not dict or set(raw_source)!= {'action_id','component','address','data_hex'}
            or type(raw_source['action_id']) is not str or type(raw_source['component']) is not str
            or type(raw_source['address']) is not int or type(raw_source['data_hex']) is not str
            or len(raw_source['data_hex'])%8
            or len(raw_source['data_hex']) > 2*context['program_size']
            or len(raw_source['data_hex']) > 2*configuration['max_program_bytes']):
        raise ValueError('invalid register program source or fragment capacity')
    source = OnlineInstruction(**raw_source)
    plan = program['operation_plan']
    if (type(plan) is not dict or set(plan) != {'register','field','operation','offset','field_width',
            'bus_mask','bus_value','side_effect','evidence_ref'}
            or any(plan[key] != request[key] for key in ('register','field','operation'))
            or any(type(plan[key]) is not int or not 0 <= plan[key] < 1<<32
                   for key in ('offset','field_width','bus_mask'))
            or not 1 <= plan['field_width'] <= 32 or plan['offset']%4
            or plan['bus_value'] is not None and (type(plan['bus_value']) is not int or not 0 <= plan['bus_value'] < 1<<32)
            or any(type(plan[key]) is not str or not plan[key] for key in ('side_effect','evidence_ref'))):
        raise ValueError('invalid register program operation plan')
    narrow_read=request['operation']=='register_read' and plan['bus_mask']!=0xffffffff
    expected_bytes=36 if request['read_modify_write'] else 16
    extraction=None
    if narrow_read:
        mask=(1<<plan['field_width'])-1
        if not plan['bus_mask']:
            raise ValueError('invalid register program field extraction')
        lsb=(plan['bus_mask'] & -plan['bus_mask']).bit_length()-1
        if lsb+plan['field_width']>32 or plan['bus_mask']!=mask<<lsb:
            raise ValueError('invalid register program field extraction')
        extraction=dict(lsb=lsb,width=plan['field_width'],read_mask=mask,
            bus_width=32,representation='field_relative_zero_extended')
        expected_bytes+=4*int(lsb!=0)+(4 if mask<=0x7ff else 12)
    if len(source.data)!=expected_bytes:
        raise ValueError('invalid register program source or fragment capacity')
    access = program['access_context']
    if (type(access) is not dict or set(access) != {'address_base','windows','program_size','program_regions',
            'result_regions','allow_side_effect','base_register','data_register','read_modify_write','mask_register'}
            or any(type(access[key]) is not int for key in ('address_base','program_size','base_register','data_register','mask_register'))
            or type(access['allow_side_effect']) is not bool or type(access['read_modify_write']) is not bool
            or access['allow_side_effect'] != request['allow_side_effect']
            or access['read_modify_write'] != request['read_modify_write']
            or source.address != context['waiting_instruction_address']
            or access['program_size'] != context['program_size'] or access['address_base'] != context['address_base']
            or hashlib.sha256(source.data).hexdigest() != program['fragment_sha256']):
        raise ValueError('invalid register program access context')
    from .rv32i_sources import MmioWindow
    from .memory import MemoryRegion
    if type(access['windows']) is not list or not access['windows']:
        raise ValueError('invalid register program windows')
    for window in access['windows']:
        if (type(window) is not dict or set(window)!= {'base','size','readable','writable','write_widths'}
                or type(window['write_widths']) is not list):
            raise ValueError('invalid register program window')
        MmioWindow(**{**window,'write_widths':tuple(window['write_widths'])})
    for name in ('program_regions','result_regions'):
        if type(access[name]) is not list:
            raise ValueError('invalid register program regions')
        for region in access[name]:
            if (type(region) is not dict or set(region)!= {'memory_id','base','size','aliases','readable','writable'}
                    or type(region['aliases']) is not list or type(region['readable']) is not bool
                    or type(region['writable']) is not bool):
                raise ValueError('invalid register program region')
            MemoryRegion(**{**region,'aliases':tuple(region['aliases'])})
    result = program['result_storage']
    if request['operation']=='register_write':
        if result is not None:
            raise ValueError('invalid register program write result')
    elif (type(result) is not dict or set(result)!= ({'address','width_bytes','purpose','evidence_scope','field_extraction'}
            if narrow_read else {'address','width_bytes','purpose','evidence_scope'})
            or type(result['address']) is not int or result['address'] != request['result_address']
            or type(result['width_bytes']) is not int or result['width_bytes']!=4
            or result['purpose']!='caller_declared_result_storage'
            or result['evidence_scope']!='requires_actual_cpu_store_and_read_snapshot'):
        raise ValueError('invalid register program read result')
    if narrow_read and (not _register_plain_json(result['field_extraction'])
            or _canonical(result['field_extraction'])!=_canonical(extraction)):
        raise ValueError('invalid register program field extraction')
    action = SourceAction.from_document(manifest['source_action'])
    admitted = SourceAction.from_document(manifest['admitted_action'])
    if (source.action_id != request['action_id'] or action.kind != 'instruction'
            or action.ownership != 'fuzzable' or action.flow_id != 'F4'
            or action.action_id != source.action_id or action.component != source.component
            or action.payload != dict(address=source.address,words_hex=source.data_hex)
            or admitted.action_id != action.action_id or admitted.payload != action.payload
            or admitted.component != action.component):
        raise ValueError('register program source identity disagreement')
    return request,source


def validate_ordinary_apb_access_session_document(document):
    """Check closed saved comparison data; this never installs live authority."""
    from myfuzz.local_harness.ordinary_apb_access_receipts import _json, _uint, _text, _key_document
    from .ledger import TransactionKey
    def fail():raise ValueError('invalid ordinary APB session document')
    def sha(value):return type(value) is str and len(value)==64 and all(c in '0123456789abcdef' for c in value)
    def refs(value):
        return (type(value) is list and len(value)<=131072 and all(_uint(x) and x>0 for x in value)
                and len(set(value))==len(value))
    if (type(document) is not dict or set(document)!={'schema_version','configuration','state'}
            or document['schema_version']!='ordinary_apb_access_session.v1' or not _register_plain_json(document)):
        fail()
    config=document['configuration'];state=document['state']
    grants={'grants_verified','grants_storage','grants_functional'}
    if (type(config) is not dict or set(config)!={'schema_version','max_records','targets','bindings','source_files','proof_scope'}|grants
            or config['schema_version']!='ordinary_apb_access_evidence_configuration.v1'
            or type(config['max_records']) is not int or not 1<=config['max_records']<=65536
            or config['proof_scope']!='actual_command_protocol_boundary_association_only'
            or any(config[k] is not False for k in grants) or type(config['targets']) is not dict or not config['targets']
            or len(config['targets'])>65536 or type(config['bindings']) is not list or not config['bindings']
            or len(config['bindings'])>65536 or type(config['source_files']) is not dict or not config['source_files']
            or len(config['source_files'])>256 or any(type(p) is not str or not 0<len(p)<=4096 or not sha(h) for p,h in config['source_files'].items())):
        fail()
    for name,target in config['targets'].items():
        if (not _text(name) or type(target) is not dict
                or set(target)!={'schema_version','artifact_kind','target_instance','endpoint_id','max_records',
                    'max_pending_samples','native_trace_sha256','proof_scope'}|grants
                or target['schema_version']!='ordinary_apb_access_receipts.v1' or target['artifact_kind']!='apb_gpio'
                or target['target_instance']!=name or not _text(target['endpoint_id'])
                or type(target['max_records']) is not int or target['max_records']!=config['max_records']
                or type(target['max_pending_samples']) is not int or target['max_pending_samples']!=65536
                or not sha(target['native_trace_sha256']) or target['proof_scope']!='actual_target_command_observation_only'
                or any(target[k] is not False for k in grants)):
            fail()
    bound=set()
    for binding in config['bindings']:
        if (type(binding) is not dict or set(binding)!={'source_component','target_instance','window_base','window_size','memory'}
                or not _text(binding['source_component']) or not _text(binding['target_instance']) or binding['target_instance'] not in config['targets']
                or not _uint(binding['window_base'],(1<<32)-1) or type(binding['window_size']) is not int
                or not 1<=binding['window_size']<=1<<32 or binding['window_base']+binding['window_size']>1<<32):fail()
        identity=(binding['source_component'],binding['target_instance'])
        if identity in bound:fail()
        bound.add(identity)
        memory=binding['memory']
        if (type(memory) is not dict or set(memory)!={'regions','initialization_seed','initialization_algorithm',
                'max_initialized_bytes','instruction_slots'} or memory['initialization_algorithm']!='memory-init-v1'
                or not _uint(memory['initialization_seed']) or not _uint(memory['max_initialized_bytes'])
                or type(memory['regions']) is not list or not memory['regions'] or len(memory['regions'])>65536
                or type(memory['instruction_slots']) is not list
                ):fail()
        region_sizes={}
        for region in memory['regions']:
            if (type(region) is not dict or set(region)!={'memory_id','base','size','aliases','readable','writable'}
                    or not _text(region['memory_id']) or not _uint(region['base'])
                    or type(region['size']) is not int or not 1<=region['size']<=1<<64 or region['base']+region['size']>1<<64
                    or type(region['aliases']) is not list or len(region['aliases'])>65536
                    or any(not _uint(alias) or alias+region['size']>1<<64 for alias in region['aliases'])
                    or type(region['readable']) is not bool or type(region['writable']) is not bool):fail()
            if region['memory_id'] in region_sizes:fail()
            region_sizes[region['memory_id']]=region['size']
        slots=memory['instruction_slots']
        if len(slots)>sum(region_sizes.values()):fail()
        for slot in slots:
            if (type(slot) is not list or len(slot)!=2 or not _text(slot[0]) or slot[0] not in region_sizes
                    or not _uint(slot[1]) or slot[1]>=region_sizes[slot[0]]):fail()
        if slots!=sorted(slots) or len({tuple(slot) for slot in slots})!=len(slots):fail()
    if {name for _,name in bound}!=set(config['targets']):fail()
    if (type(state) is not dict or set(state)!={'schema_version','configuration','configuration_sha256','status','reason','counts','records'}
            or state['schema_version']!='ordinary_apb_access_evidence_state.v1' or _json(state['configuration'])!=_json(config)
            or not sha(state['configuration_sha256']) or state['configuration_sha256']!=hashlib.sha256(_json(config).encode()).hexdigest()
            or state['status'] not in ('complete','incomplete') or state['reason'] is not None and not _text(state['reason'])
            or state['status']=='complete' and state['reason'] is not None
            or state['status']=='incomplete' and state['reason'] is None
            or type(state['records']) is not list or len(state['records'])>config['max_records']
            or type(state['counts']) is not dict or set(state['counts'])!={'records','pending','cpu_delivery_confirmed'}
            or any(not _uint(n,config['max_records']) for n in state['counts'].values())
            or state['counts']['records']!=len(state['records'])
            or state['counts']['records']+state['counts']['pending']>config['max_records']):fail()
    record_keys={'schema_version','access_id','target_instance','endpoint_id','source_transaction','target_reset_epoch',
        'memory_generation','target_receipt_event_id','acceptance_event_id','delivery_event_id','raw_event_refs','base_event_refs',
        'status','reason','proof_scope'}|grants
    identities=set();sources=set();all_refs=set()
    for record in state['records']:
        if (type(record) is not dict or set(record)!=record_keys
                or record['schema_version']!='ordinary_apb_access_association.v1' or not _text(record['target_instance']) or record['target_instance'] not in config['targets']
                or record['status'] not in ('target_observed','cpu_delivery_confirmed','incomplete')
                or record['proof_scope']!='actual_command_protocol_boundary_association_only' or any(record[k] is not False for k in grants)
                or record['access_id'] is not None and not _text(record['access_id'])
                or record['endpoint_id'] is not None and record['endpoint_id']!=config['targets'][record['target_instance']]['endpoint_id']
                or not _uint(record['target_reset_epoch']) or not _uint(record['memory_generation'])
                or any(record[k] is not None and (not _uint(record[k]) or record[k]==0) for k in
                    ('target_receipt_event_id','acceptance_event_id','delivery_event_id'))
                or not refs(record['raw_event_refs']) or not refs(record['base_event_refs']) or len(record['base_event_refs'])>3
                or record['reason'] is not None and not _text(record['reason'])):fail()
        present_refs=[record[k] for k in ('target_receipt_event_id','acceptance_event_id','delivery_event_id') if record[k] is not None]
        present_refs+=record['raw_event_refs']+record['base_event_refs']
        if len(set(present_refs))!=len(present_refs) or any(ref in all_refs for ref in present_refs):fail()
        all_refs.update(present_refs)
        if record['raw_event_refs']!=sorted(record['raw_event_refs']) or record['base_event_refs']!=sorted(record['base_event_refs']):fail()
        if record['status']=='incomplete' and (state['status']!='incomplete' or record['reason'] is None):fail()
        transaction=record['source_transaction']
        try:canonical=_key_document(TransactionKey(**transaction))
        except (TypeError,ValueError):fail()
        if _json(canonical)!=_json(transaction) or (canonical['source_component'],record['target_instance']) not in bound:fail()
        token=_json(canonical)
        if token in sources:fail()
        sources.add(token)
        if record['access_id'] is not None:
            if record['access_id'] in identities:fail()
            identities.add(record['access_id'])
        if record['status']!='incomplete':
            if (record['reason'] is not None or record['access_id'] is None or record['endpoint_id'] is None
                    or record['target_receipt_event_id'] is None or record['acceptance_event_id'] is None
                    or len(record['raw_event_refs'])<2 or len(record['raw_event_refs'])%2 or len(record['base_event_refs'])!=3):fail()
        if record['status']=='cpu_delivery_confirmed' and record['delivery_event_id'] is None:fail()
    if state['counts']['cpu_delivery_confirmed']!=sum(r['status']=='cpu_delivery_confirmed' for r in state['records']):fail()
    return json.loads(_canonical(document))


def _validate_register_reset_operations(rows, *, schema, case_count, components, max_steps, terminal):
    resumed = schema in (18, 19)
    keys = {'after_cases', 'policy'} | ({'advances'} if resumed else set())
    last = 0
    used = False
    limit = case_count - (schema in (17, 19) and type(terminal) is dict
                          and terminal.get('case_index') is not None)
    if type(rows) is not list or len(rows) > 65536:
        raise ValueError('invalid register reset timeline')
    for row in rows:
        if (type(row) is not dict or set(row) != keys
                or type(row['after_cases']) is not int or not last <= row['after_cases'] <= limit
                or row['after_cases'] < 1 or type(row['policy']) is not str
                or row['policy'] not in ('warm_all', 'cold_all')):
            raise ValueError('invalid register reset timeline')
        last = row['after_cases']
        if resumed:
            advances = row['advances']
            if (type(advances) is not list or len(advances) > max_steps
                    or any(type(order) is not list or not order or len(order) > max_steps
                        or any(type(name) is not str or name not in components for name in order)
                        for order in advances)
                    or sum(len(order) for order in advances) > max_steps):
                raise ValueError('invalid register reset resume schedule')
            used = used or bool(advances)
    if resumed and not used:
        raise ValueError('register reset resume schema requires advances')


def validate_register_program_plan(document):
    """Closed saved-data validation; no file lookup, provider installation or authority."""
    keys = {'schema_version','template','instruction_slots','warmup_advances','cases',
            'prerequisite_admissions','reset_operations','register_programs'}
    if (type(document) is not dict or not _register_plain_json(document)
            or type(document.get('schema_version')) is not int or document['schema_version'] not in (16,17,18,19)
            or set(document) != keys | ({'terminal_failure'} if document['schema_version'] in (17,19) else set())):
        raise ValueError('invalid register program session plan')
    registers = document['register_programs']
    if (type(registers) is not dict or set(registers) != {'schema_version','configuration',
            'case_manifests','terminal_attempt','gate_state'} | ({'capability_preflight'} if 'capability_preflight' in registers else set())
            | ({'ordinary_apb_access_evidence'} if 'ordinary_apb_access_evidence' in registers else set())
            | ({'register_program_verifier'} if 'register_program_verifier' in registers else set())
            | ({'register_reset_default'} if 'register_reset_default' in registers else set())
            or registers['schema_version'] != 'register_program_session.v1'
            or type(registers['configuration']) is not dict
            or type(registers['gate_state']) is not dict
            or type(registers['case_manifests']) is not list
            or any(type(document[key]) is not list for key in ('cases','instruction_slots',
                'warmup_advances','prerequisite_admissions','reset_operations'))
            or len(document['cases']) != len(registers['case_manifests'])
            or len(document['cases']) != len(document['prerequisite_admissions'])):
        raise ValueError('invalid register program session records')
    configuration = registers['configuration']
    if 'register_program_verifier' in registers:
        if 'ordinary_apb_access_evidence' not in registers:
            raise ValueError('register verifier requires ordinary evidence')
        from .register_program_verifier import validate_register_program_verifier_session_document
        validate_register_program_verifier_session_document(registers['register_program_verifier'], configuration=configuration)
    if 'ordinary_apb_access_evidence' in registers:
        validate_ordinary_apb_access_session_document(registers['ordinary_apb_access_evidence'])
    if 'register_reset_default' in registers:
        from .register_reset_default_verifier import (
            validate_register_reset_default_session_document)
        validate_register_reset_default_session_document(
            registers['register_reset_default'], configuration=configuration)
    if 'capability_preflight' in registers:
        from .register_program_capabilities import validate_register_capability_preflight_document
        validate_register_capability_preflight_document(registers['capability_preflight'], configuration=configuration)
    configuration_keys = {'schema_version','cpu_component','advance_rounds','max_program_bytes','max_records',
        'sources','scope','grants_functional','sidecars','artifacts','memory','provider','tracker_bounds',
        'slots','policy','template','routes','gate_max_actions'}
    if (set(configuration) != configuration_keys
            or configuration.get('schema_version') != 'register_program_runtime_configuration.v1'
            or configuration.get('scope') != 'directed_declarative_register_program_only'
            or configuration.get('grants_functional') is not False
            or type(configuration.get('cpu_component')) is not str or not configuration['cpu_component']
            or type(configuration.get('max_program_bytes')) is not int
            or not 16 <= configuration['max_program_bytes'] <= 4096 or configuration['max_program_bytes']%4
            or type(configuration.get('gate_max_actions')) is not int
            or not 1 <= configuration['gate_max_actions'] <= 65536
            or type(configuration.get('advance_rounds')) is not int
            or not 1 <= configuration['advance_rounds'] <= 65536
            or type(configuration.get('max_records')) is not int
            or not 1 <= configuration['max_records'] <= 65536
            or len(document['cases']) > configuration['max_records']):
        raise ValueError('invalid register program configuration')
    terminal = registers['terminal_attempt']
    attempts = len(document['cases']) + int(type(terminal) is dict and terminal.get('case_index') is None)
    if attempts > configuration['max_records']:
        raise ValueError('register program attempt capacity exceeded')
    for key,expected_keys in (
            ('provider',{'runtime_contract_sha256','bounds'}),
            ('tracker_bounds',{'max_slots','max_effects','max_age_events'}),
            ('memory',{'regions','initialization_seed','initialization_algorithm','max_initialized_bytes','instruction_slots'}),
            ('policy',{'component','first_address','last_address','word_bytes','declared_words',
                       'reservation_ref_prefix','registration','prerequisite_kind'})):
        if type(configuration[key]) is not dict or set(configuration[key]) != expected_keys:
            raise ValueError('invalid register program configuration object')
    bounds = configuration['provider']['bounds']
    if (type(bounds) is not dict or set(bounds)!= {'max_records','max_writer_versions','max_event_gap',
            'max_declared_resources','max_transaction_text','max_writer_reference_text'}
            or any(type(value) is not int or value<1 for value in bounds.values())
            or any(type(value) is not int or value<1 for value in configuration['tracker_bounds'].values())
            or type(configuration['memory']['initialization_seed']) is not int
            or type(configuration['memory']['max_initialized_bytes']) is not int
            or configuration['memory']['max_initialized_bytes']<1
            or configuration['memory']['initialization_algorithm'] != 'memory-init-v1'
            or any(type(configuration['policy'][key]) is not int or configuration['policy'][key]<0
                   for key in ('first_address','last_address','word_bytes','declared_words'))
            or configuration['policy']['word_bytes'] != 4
            or configuration['policy']['component'] != configuration['cpu_component']
            or configuration['policy']['registration'] != 'lazy_per_admitted_case'
            or configuration['policy']['prerequisite_kind'] != 'instruction_slot_unmaterialized'
            or _canonical(configuration['slots']) != _canonical(document['instruction_slots'])
            or _canonical(configuration['template']) != _canonical(document['template'])):
        raise ValueError('invalid register program configuration bounds')
    def sha(value):
        return type(value) is str and len(value)==64 and all(char in '0123456789abcdef' for char in value)
    if not sha(configuration['provider']['runtime_contract_sha256']):
        raise ValueError('invalid register program provider identity')
    for key in ('sources','sidecars','artifacts'):
        if type(configuration[key]) is not dict or not configuration[key]:
            raise ValueError('invalid register program configuration declarations')
    if (any(type(name) is not str or not name or not sha(digest) for name,digest in configuration['sources'].items())
            or any(type(name) is not str or not name or type(row) is not dict or set(row)!= {'path','sha256'}
                or type(row['path']) is not str or not row['path'] or not sha(row['sha256'])
                for name,row in configuration['sidecars'].items())):
        raise ValueError('invalid register program source declarations')
    gate = registers['gate_state']
    if (set(gate)!= {'schema_version','enforce','action_ids','tracker'}
            or gate['schema_version']!='source_action_gate.v1' or gate['enforce'] is not True
            or type(gate['action_ids']) is not list or any(type(text) is not str or not text for text in gate['action_ids'])
            or type(gate['tracker']) is not dict):
        raise ValueError('invalid register program gate state')
    tracker = gate['tracker']
    if (set(tracker)!= {'schema_version','proof_scope','cursor','epoch','reset_floor','degraded',
            'retained_authority_writer_versions','max_writer_versions','max_event_gap','receipt_ingestion_grants'}
            or tracker['schema_version']!='live_memory_effect_tracker.v1'
            or tracker['proof_scope']!='current_installed_host_memory_bytes'
            or type(tracker['degraded']) is not bool or tracker['receipt_ingestion_grants'] is not False
            or any(type(tracker[key]) is not int or tracker[key]<0 for key in
                ('cursor','epoch','reset_floor','retained_authority_writer_versions','max_writer_versions','max_event_gap'))):
        raise ValueError('invalid register program tracker state')
    template = GenomeCodec.decode(_canonical(document['template']))
    if configuration['advance_rounds']*len(template.schedule_order)>template.max_steps:
        raise ValueError('register program schedule capacity exceeded')
    case_ids,action_ids = set(),set()
    for index,(case,manifest,declaration) in enumerate(zip(document['cases'],registers['case_manifests'],document['prerequisite_admissions'])):
        request,source = _validate_register_manifest(manifest,configuration)
        expected = dict(case_id=request['case_id'],direction='CPU_TO_IP_TO_CPU' if request['operation']=='register_read'
            else 'CPU_TO_IP',path_id='register_program',source={**asdict(source),'kind':'instruction'},
            support_instructions=[],advances=[list(template.schedule_order)]*configuration['advance_rounds'])
        expected_admission = dict(schema_version='persistent_memory_case_admission.v1',
            source_action=manifest['source_action'],admitted_action=manifest['admitted_action'],
            support_actions=[],dynamic_binding=None)
        if (_canonical(case) != _canonical(expected) or _canonical(declaration) != _canonical(expected_admission)
                or request['case_id'] in case_ids or request['action_id'] in action_ids):
            raise ValueError('register program case or admission disagreement')
        case_ids.add(request['case_id'])
        action_ids.add(request['action_id'])
    terminal = registers['terminal_attempt']
    _validate_register_reset_operations(document['reset_operations'], schema=document['schema_version'],
        case_count=len(document['cases']), components=template.schedule_order,
        max_steps=template.max_steps, terminal=terminal)
    if document['schema_version'] in (16,18):
        if terminal is not None:
            raise ValueError('register program normal plan contains terminal attempt')
    else:
        _validate_register_attempt(terminal,configuration,uncertain=True)
        index = terminal['case_index']
        if index is None:
            if terminal['manifest']['request']['case_id'] in case_ids or terminal['manifest']['request']['action_id'] in action_ids:
                raise ValueError('register program unrecorded terminal identity conflict')
            if document['terminal_failure'] is not None:
                raise ValueError('register program unrecorded terminal execution failure')
        elif (index != len(document['cases'])-1
                or _canonical(terminal['manifest']) != _canonical(registers['case_manifests'][index])
                or terminal['phase'] != 'session_submission' or document['terminal_failure'] is None):
            raise ValueError('register program terminal case boundary disagreement')
    return json.loads(_canonical(registers))


def _validate_register_attempt(record,configuration,*,uncertain):
    keys = {'manifest','status','phase','case_index'} | ({'error_type'} if uncertain else set())
    if (type(record) is not dict or set(record) != keys
            or record['status'] != ('uncertain' if uncertain else 'submitted')
            or (record['case_index'] is not None and (type(record['case_index']) is not int or record['case_index'] < 0))
            or uncertain and (record['phase'] not in ('registration','registration_verification','session_submission')
                or type(record['error_type']) is not str or not record['error_type'])
            or not uncertain and (record['phase']!='submitted' or record['case_index'] is None)):
        raise ValueError('invalid register program attempt')
    _validate_register_manifest(record['manifest'],configuration)


def _validate_register_program_state(state, registers):
    """Check the complete attempt history without making an ignored export copy."""
    if (type(state) is not dict or not _register_plain_json(state)
            or set(state) != {'schema_version','configuration','uncertain','records'}
            or state['schema_version'] != 'register_program_runtime_state.v1'
            or type(state['uncertain']) is not bool or type(state['records']) is not list
            or _canonical(state['configuration']) != _canonical(registers['configuration'])
            or state['uncertain'] != (registers['terminal_attempt'] is not None)):
        raise ValueError('invalid register program runtime state')
    if len(state['records']) > registers['configuration']['max_records']:
        raise ValueError('register program attempt capacity exceeded')
    manifests = []
    for index,record in enumerate(state['records']):
        uncertain = state['uncertain'] and index==len(state['records'])-1
        _validate_register_attempt(record,state['configuration'],uncertain=uncertain)
        if record['case_index'] is not None:
            if record['case_index'] != len(manifests):
                raise ValueError('register program state case order disagreement')
            manifests.append(record['manifest'])
        if uncertain and _canonical(record)!=_canonical(registers['terminal_attempt']):
            raise ValueError('register program terminal state disagreement')
    if (_canonical(manifests) != _canonical(registers['case_manifests'])
            or state['uncertain'] and not state['records']):
        raise ValueError('register program state prefix disagreement')


def validate_register_program_state(state, registers):
    """Validate the full history and return detached comparison data."""
    _validate_register_program_state(state, registers)
    return json.loads(_canonical(state))


def _replay_register_program_session(document,template,cases,factory,reference,checker,register_runtime_factory):
    registers = document['register_programs']
    session = None
    try:
        session = ScenarioSession(template,factory(),checker=checker)
        for component,address,count in document['instruction_slots']:
            session.declare_instruction_slots(component,address,count)
        adapter = register_runtime_factory(session)
        if (session._register_program_runtime is not adapter
                or _canonical(adapter.configuration()) != _canonical(registers['configuration'])):
            raise ValueError('register program replay configuration mismatch')
        capability = session._register_capability_preflight()
        if _canonical(capability) != _canonical(registers.get('capability_preflight')):
            raise ValueError('register capability fresh assessment mismatch')
        ordinary=session._ordinary_apb_configuration()
        saved_ordinary=registers.get('ordinary_apb_access_evidence')
        if _canonical(ordinary)!=_canonical(saved_ordinary['configuration'] if saved_ordinary is not None else None):
            raise ValueError('ordinary APB fresh configuration mismatch')
        verifier_configuration=session._register_program_verifier_configuration()
        saved_verifier=registers.get('register_program_verifier')
        if _canonical(verifier_configuration)!=_canonical(saved_verifier['configuration'] if saved_verifier is not None else None):
            raise ValueError('register verifier fresh configuration mismatch')
        reset_default=session._register_reset_default_configuration()
        saved_reset_default=registers.get('register_reset_default')
        if _canonical(reset_default)!=_canonical(saved_reset_default['configuration'] if saved_reset_default is not None else None):
            raise ValueError('reset default fresh configuration mismatch')
        actual_manifest = _online_manifest(session.runner,checker,
            register_program_configuration=session._register_configuration(),
            register_capability_preflight=capability,
            ordinary_apb_access_evidence_configuration=ordinary,
            ordinary_apb_access_source_files=json.loads(session._ordinary_apb_sources_json) if ordinary is not None else None,
            register_program_verifier_configuration=verifier_configuration,
            register_program_verifier_source_files=json.loads(session._register_verifier_sources_json) if verifier_configuration is not None else None,
            register_reset_default_configuration=reset_default,
            register_reset_default_source_files=json.loads(session._register_reset_default_sources_json) if reset_default is not None else None)
        if hashlib.sha256(_canonical(actual_manifest)).hexdigest() != reference.manifest_sha256:
            raise ValueError('register program replay manifest identity mismatch')
        session.begin()
        for order in document['warmup_advances']:
            session.advance_initial(tuple(order))
        reset_index = 0
        terminal = registers['terminal_attempt']
        entries = list(zip(cases,registers['case_manifests']))
        if terminal is not None and terminal['case_index'] is None:
            entries.append((None,terminal['manifest']))
        for index,(case,manifest) in enumerate(entries):
            prepared = adapter.prepare(manifest['request'],expected_manifest=manifest)
            if case is not None and prepared.case != case:
                raise ValueError('register program replay case reconstruction mismatch')
            try:
                adapter.submit(manifest['request'],expected_manifest=manifest)
            except BaseException:
                if terminal is None or index != len(entries)-1 or not adapter.snapshot()['uncertain']:
                    raise
                break
            while (reset_index<len(document['reset_operations'])
                    and document['reset_operations'][reset_index]['after_cases']==index+1):
                operation = document['reset_operations'][reset_index]
                session.reset(operation['policy'])
                for order in operation.get('advances', ()):
                    _RESET_RESUME_METHOD(session, tuple(order))
                reset_index += 1
        actual_plan, actual = _FINAL_EXPORT_METHOD_PINS['finish_export'](session)
        actual_registers = json.loads(actual_plan)['register_programs']
        runtime_match = _canonical(actual_registers)==_canonical(registers)
        admissions_match = _canonical(session._prerequisite_admissions)==_canonical(document['prerequisite_admissions'])
        reset_match = _canonical(_RESET_RESUME_SERIALIZER(session))==_canonical(document['reset_operations'])
        missing = object()
        for index,(expected_event,actual_event) in enumerate(zip_longest(reference.events,actual.events,fillvalue=missing)):
            expected_event = None if expected_event is missing else expected_event
            actual_event = None if actual_event is missing else actual_event
            if _canonical(expected_event)!=_canonical(actual_event):
                return ReplayComparison(False,index,expected_event,actual_event,actual,
                    _difference_context(expected_event,actual_event,index))
        matches = (runtime_match and admissions_match and reset_match
            and reference.genome_sha256==actual.genome_sha256
            and _canonical(session._terminal_failure)==_canonical(document.get('terminal_failure'))
            and reference.status==actual.status and reference.local_ticks==actual.local_ticks
            and reference.semantic_sha256==actual.semantic_sha256
            and reference.manifest_sha256==actual.manifest_sha256)
        context = None if matches else dict(register_program_state_match=runtime_match,
            canonical_plan_sha256_match=reference.genome_sha256==actual.genome_sha256,
            prerequisite_admissions_match=admissions_match,reset_operations_match=reset_match,
            expected_terminal_failure=document.get('terminal_failure'),actual_terminal_failure=session._terminal_failure)
        return ReplayComparison(matches,None if matches else len(reference.events),None,None,actual,context)
    except BaseException as error:
        if session is not None:
            try:
                if session._begun and not session._finished:
                    session.finish()
                elif not session._begun:
                    session.runner.finalize()
            except BaseException as cleanup:
                error.add_note(f'register program replay cleanup failed: {type(cleanup).__name__}: {cleanup}')
        raise


def replay_online_session(plan: bytes,
                          factory: Callable[[], ScenarioRunner],
                          reference: ScenarioTrace, *,
                          checker: Callable[[OnlineCaseReceipt], tuple[str, ...]] | None = None,
                          register_runtime_factory=None
                          ) -> ReplayComparison:
    """Rebuild from initial state and compare the complete committed prefix."""
    if not isinstance(plan, bytes) or not isinstance(reference, ScenarioTrace):
        raise ValueError("encoded plan and reference trace are required")
    document = json.loads(plan)
    base_keys = {"schema_version", "template", "instruction_slots",
                 "warmup_advances", "cases"}
    if not isinstance(document, dict):
        raise ValueError("invalid online session plan")
    schema = document.get("schema_version")
    register_plan = type(schema) is int and schema in (16,17,18,19)
    if register_plan:
        validate_register_program_plan(document)
        if not callable(register_runtime_factory):
            raise ValueError('register program replay requires a trusted runtime factory')
    elif register_runtime_factory is not None:
        raise ValueError('register runtime factory cannot replay legacy byte plans')
    reset_plan = schema in (14, 15,16,17,18,19)
    trusted_plan = schema in (12, 13,16,17,18,19) or reset_plan and 'prerequisite_admissions' in document
    flexible_plan = trusted_plan or reset_plan
    has_provenance = schema in (10, 11) or flexible_plan and 'provenance_configuration' in document
    has_runtime = schema in (8, 9, 10, 11) or flexible_plan and 'runtime_paths' in document
    if has_provenance and not has_runtime:
        raise ValueError('online provenance requires runtime paths')
    required = base_keys | ({"terminal_failure"} if schema in (5, 7, 9, 11, 13, 15,17,19) else set()) | ({"runtime_paths"} if has_runtime else set())
    if register_plan:
        required.add('register_programs')
    if reset_plan:
        required.add('reset_operations')
    if has_provenance:
        required |= {"provenance_configuration", "source_admissions"}
    if trusted_plan:
        required.add('prerequisite_admissions')
    if (type(schema) is not int or schema not in (4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,16,17,18,19)
            or set(document) != required
            or not isinstance(document["instruction_slots"], list)
            or not isinstance(document["warmup_advances"], list)
            or not isinstance(document["cases"], list)):
        raise ValueError("invalid online session plan")
    reset_operations = document.get('reset_operations', [])
    if reset_plan and not register_plan:
        if (type(reset_operations) is not list or not (0 if register_plan else 1) <= len(reset_operations) <= 65536
                or any(type(op) is not dict or set(op) != {'after_cases', 'policy'}
                       or type(op['after_cases']) is not int
                       or not 1 <= op['after_cases'] <= len(document['cases']) - (schema == 15)
                       or type(op['policy']) is not str
                       or op['policy'] not in ('warm_all', 'cold_all')
                       for op in reset_operations)
                or any(a['after_cases'] > b['after_cases']
                       for a, b in zip(reset_operations, reset_operations[1:]))):
            raise ValueError('invalid online reset operation timeline')
    if trusted_plan and (type(document['prerequisite_admissions']) is not list
            or len(document['prerequisite_admissions']) != len(document['cases'])
            or len(document['cases']) > 65536):
        raise ValueError('trusted plan admission count mismatch')
    prepared = None
    expected_runtime = document.get("runtime_paths")
    if has_runtime:
        if not isinstance(expected_runtime, dict) or expected_runtime.get("schema_version") != "runtime_path_compilation.v1":
            raise ValueError("invalid saved runtime path compilation")
        prepared = PreparedRuntimePathContract.from_document(expected_runtime.get("declaration"))
        if (expected_runtime.get("graph_sha256") != prepared.contract.graph_sha256
                or expected_runtime.get("contract_sha256") != prepared.contract.identity_sha256
                or hashlib.sha256(_canonical(expected_runtime.get("topology"))).hexdigest() != expected_runtime.get("topology_sha256")):
            raise ValueError("saved runtime path compilation identity mismatch")
    expected_failure = document.get("terminal_failure")
    if (document["schema_version"] in (5, 7, 9, 11, 13, 15) or schema in (17,19) and expected_failure is not None) and (
            not isinstance(expected_failure, dict)
            or set(expected_failure) != {"phase", "case_index", "case_id",
                                         "command_index", "error_type", "error_message"}
            or expected_failure["phase"] not in (
                "support_admission", "source_admission", "step", "checker",
                *(("provenance_admission",) if has_provenance else ()))
            or not document["cases"]
            or type(expected_failure["case_index"]) is not int
            or expected_failure["case_index"] != len(document["cases"]) - 1
            or not isinstance(expected_failure["case_id"], str)
            or not isinstance(document["cases"][-1], dict)
            or expected_failure["case_id"] != document["cases"][-1].get("case_id")
            or type(expected_failure["error_type"]) is not str
            or type(expected_failure["error_message"]) is not str
            or (expected_failure["command_index"] is not None
                and type(expected_failure["command_index"]) is not int)
            or (expected_failure["phase"] in ("support_admission", "step", "provenance_admission")
                and (expected_failure["command_index"] is None
                     or expected_failure["command_index"] < 0))
            or (expected_failure["phase"] in ("source_admission", "checker")
                and expected_failure["command_index"] is not None)):
        raise ValueError("invalid online terminal failure")
    if hashlib.sha256(plan).hexdigest() != reference.genome_sha256:
        raise ValueError("online replay plan identity mismatch")
    template = GenomeCodec.decode(_canonical(document["template"]))
    decoded_cases = []
    decoded_roles = []
    expected_schedule_ticks: dict[str, int] = {}
    for item in document["cases"]:
        case_keys = {
                "case_id", "direction", "path_id", "source", "advances",
                "support_instructions"}
        if has_provenance:
            case_keys.add("source_role")
        if not isinstance(item, dict) or set(item) != case_keys:
            raise ValueError("invalid online case record")
        instruction_fields = {"action_id", "component", "address", "data_hex"}
        if type(item["source"]) is not dict or "kind" not in item["source"]:
            raise ValueError("invalid online source record")
        kind = item["source"]["kind"]
        source_fields = (instruction_fields if kind == "instruction" else
                         {"action_id", "component", "port", "value", "bit_offset", "width"})
        source_keys = source_fields | {"kind"}
        if "scheduled_local_tick" in item["source"]:
            tick = item["source"]["scheduled_local_tick"]
            if kind != "source_event" or type(tick) is not int or tick < 0:
                raise ValueError("invalid online source schedule tick")
            source_keys.add("scheduled_local_tick")
        if kind not in ("instruction", "source_event") or set(item["source"]) != source_keys:
            raise ValueError("invalid online source fields")
        if (type(item["support_instructions"]) is not list
                or any(type(support) is not dict or set(support) != instruction_fields
                       for support in item["support_instructions"])
                or type(item["advances"]) is not list
                or any(type(order) is not list for order in item["advances"])):
            raise ValueError("invalid online support instructions or advances")
        source = dict(item["source"])
        kind = source.pop("kind")
        if kind == "instruction":
            if "scheduled_local_tick" in source:
                raise ValueError("instruction source cannot schedule a local tick")
            admitted: OnlineInput = OnlineInstruction(**source)
        elif kind == "source_event":
            scheduled_tick = source.pop("scheduled_local_tick", None)
            if scheduled_tick is not None:
                if (document["schema_version"] not in (6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
                        or type(scheduled_tick) is not int or scheduled_tick < 0):
                    raise ValueError("invalid online source schedule tick")
                if source["action_id"] in expected_schedule_ticks:
                    raise ValueError("duplicate scheduled online source action")
                expected_schedule_ticks[source["action_id"]] = scheduled_tick
            admitted = BatchSourceEvent(**source)
        else:
            raise ValueError("unknown online source kind")
        decoded_cases.append(OnlineCase(
            item["case_id"], item["direction"], item["path_id"], admitted,
            tuple(BatchAdvance(tuple(order)) for order in item["advances"]),
            tuple(OnlineInstruction(**support)
                  for support in item["support_instructions"])))
        decoded_roles.append(item.get("source_role", "fuzz_source"))
    if expected_failure is not None:
        final_case = decoded_cases[-1]
        command_counts = {"step": len(final_case.advances),
                          "support_admission": len(final_case.support_instructions)}
        phase = expected_failure["phase"]
        if phase in command_counts and expected_failure["command_index"] >= command_counts[phase]:
            raise ValueError("online terminal failure command_index is outside final case")
    if document["schema_version"] in (4, 5, 6, 7) and (document["schema_version"] in (6, 7)) != bool(expected_schedule_ticks):
        raise ValueError("online schedule schema disagrees with source actions")
    if has_provenance:
        _validate_saved_provenance(document, prepared, decoded_cases, decoded_roles, template)
    if register_plan:
        return _replay_register_program_session(document,template,decoded_cases,factory,
            reference,checker,register_runtime_factory)
    session = ScenarioSession(template, factory(), checker=checker)
    trusted_gate = session.runner.persistent_memory_prerequisite_gate
    if trusted_plan != (trusted_gate is not None):
        raise ValueError('trusted replay requires matching saved admission declarations and configured gate')
    if trusted_plan:
        for case, declaration in zip(decoded_cases, document['prerequisite_admissions']):
            trusted_gate.validate_replay_case_declaration(case, declaration)
    if prepared is not None:
        session.configure_runtime_paths(prepared.graph, prepared.contract,
                                        prepared.runtime_paths, replay_only=True,
                                        provenance=has_provenance)
        if _canonical(session.runtime_path_document) != _canonical(expected_runtime):
            raise ValueError("online replay runtime path topology mismatch")
    for component, address, count in document["instruction_slots"]:
        session.declare_instruction_slots(component, address, count)
    actual_manifest = hashlib.sha256(
        _canonical(_online_manifest(session.runner, checker, runtime_paths=session.runtime_path_document))).hexdigest()
    if actual_manifest != reference.manifest_sha256:
        raise ValueError("online replay manifest identity mismatch")
    session.begin()
    for order in document["warmup_advances"]:
        session.advance_initial(tuple(order))
    reset_index = 0
    for case_index, (case, source_role) in enumerate(zip(decoded_cases, decoded_roles)):
        if trusted_plan:
            try:
                trusted_gate.register_replay_case(case, document['prerequisite_admissions'][case_index])
            except BaseException as admission_error:
                try:
                    session.finish()
                except BaseException as cleanup_error:
                    admission_error.add_note(
                        f'online replay cleanup failed: {type(cleanup_error).__name__}: {cleanup_error}')
                raise
        if expected_failure is None:
            session.submit_case(case, source_role=source_role)
        else:
            try:
                session.submit_case(case, source_role=source_role)
            except BaseException:
                break
        while (reset_index < len(reset_operations)
               and reset_operations[reset_index]['after_cases'] == case_index + 1):
            try:
                session.reset(reset_operations[reset_index]['policy'])
            except BaseException as reset_error:
                try:
                    session.finish()
                except BaseException as cleanup_error:
                    reset_error.add_note(
                        f'online replay cleanup failed: {type(cleanup_error).__name__}: {cleanup_error}')
                raise
            reset_index += 1
    actual = session.finish()
    missing = object()
    for index, (expected_item, actual_item) in enumerate(zip_longest(
            reference.events, actual.events, fillvalue=missing)):
        expected_event = None if expected_item is missing else expected_item
        actual_event = None if actual_item is missing else actual_item
        if _canonical(expected_event) != _canonical(actual_event):
            return ReplayComparison(False, index, expected_event, actual_event,
                                    actual, _difference_context(expected_event,
                                                                actual_event, index))
    schedule_matches = expected_schedule_ticks == session._source_schedule_ticks
    admissions_match = (not has_provenance or
        _canonical(document["source_admissions"]) == _canonical(session.runner.source_admissions))
    matches = (expected_failure == session._terminal_failure
               and schedule_matches
               and admissions_match
               and reference.status == actual.status
               and reference.local_ticks == actual.local_ticks
               and reference.semantic_sha256 == actual.semantic_sha256
               and reference.manifest_sha256 == actual.manifest_sha256)
    context = None
    if expected_failure != session._terminal_failure or not schedule_matches or not admissions_match:
        context = {"expected_terminal_failure": expected_failure,
                   "actual_terminal_failure": session._terminal_failure,
                   "expected_source_schedule": expected_schedule_ticks,
                   "actual_source_schedule": session._source_schedule_ticks,
                   "source_admissions_match": admissions_match}
    return ReplayComparison(matches, None if matches else len(reference.events),
                            None, None, actual, context)


# Final export uses code-owned methods, never caller-provided serializers or traces.
_FINAL_EXPORT_METHOD_PINS = {name: getattr(ScenarioSession, name)
    for name in ('finish_export', 'encode_plan', 'trace')}

_RESET_RESUME_METHOD = ScenarioSession.advance_after_reset

_RESET_RESUME_GUARD = ScenarioSession._guard_reset_resume

_RESET_RESUME_SERIALIZER = ScenarioSession._encoded_reset_operations

# Opt-in reset-default wrapper uses code-owned entries, never caller dispatch.
_RESET_DEFAULT_METHOD = ScenarioSession.configure_register_reset_default

_RESET_DEFAULT_GUARD = ScenarioSession._guard_register_reset_default_configuration

_RESET_DEFAULT_NATIVE_GUARD = (guard_native_reset_evidence, guard_native_reset_evidence.__code__)
