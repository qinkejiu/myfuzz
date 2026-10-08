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
from .runner import ScenarioRunner


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


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


def _checker_identity(checker: Callable | None) -> dict | None:
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


def _online_manifest(runner: ScenarioRunner, checker: Callable | None = None, *,
                     runtime_paths: dict | None = None) -> dict:
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
                "checker": _checker_identity(checker)}
    if runtime_paths is not None:
        document["runtime_paths"] = runtime_paths
    if runner.provenance_enabled:
        document["provenance_configuration"] = runner.provenance_configuration
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


class ScenarioSession:
    """Keep one initialized Runner alive while accepting many online cases.

    ``submit_case`` returns only its event suffix so the hot path does not copy
    the full prefix for every mutation.  ``trace`` and ``plan`` intentionally
    materialize the full prefix only for a finding or replay.
    """

    def __init__(self, template: ScenarioGenome, runner: ScenarioRunner, *,
                 checker: Callable[[OnlineCaseReceipt], tuple[str, ...]] | None = None,
                 prerequisite_gate=None) -> None:
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
        if prerequisite_gate is not None and (
                not callable(getattr(prerequisite_gate, "require_case", None))
                or not callable(getattr(prerequisite_gate, "observe", None))):
            raise ValueError(
                "prerequisite gate must expose require_case and observe")
        self.prerequisite_gate = prerequisite_gate
        runner.enable_event_journal()
        self.template = template
        self.runner = runner
        self._cases: list[OnlineCase] = []
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
        self._manifest_sha256 = ""
        self._manifest_document: dict | None = None
        self._begun = False
        self._finished = False
        self._record_sequence = 0
        if checker is not None and not callable(checker):
            raise ValueError("online checker must be callable")
        self.checker = checker
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
            self.runner, self.checker, runtime_paths=self.runtime_path_document)
        self._manifest_sha256 = hashlib.sha256(
            _canonical(self._manifest_document)).hexdigest()
        for image in self.template.initial_images:
            self.runner.preload_image(image)
        self.runner.begin_test(self.template.testcase_id)
        self._begun = True

    def advance_initial(self, schedule: tuple[str, ...]) -> OnlineCaseReceipt:
        """Advance fixed bootstrap once and preserve its steps for replay."""
        if (not self._begun or self._finished or self._halted or self._cases
                or self.runner._status != "running"):
            raise RuntimeError("bootstrap advance requires an active pre-case session")
        advance = BatchAdvance(schedule)
        if any(component not in self.runner.sessions for component in advance.schedule):
            raise ValueError("bootstrap schedule references unknown harness")
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

    def encode_plan(self) -> bytes:
        """Canonical full input prefix for fresh replay and corpus storage."""
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


def replay_online_session(plan: bytes,
                          factory: Callable[[], ScenarioRunner],
                          reference: ScenarioTrace, *,
                          checker: Callable[[OnlineCaseReceipt], tuple[str, ...]] | None = None
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
    required = base_keys | ({"terminal_failure"} if schema in (5, 7, 9, 11) else set()) | ({"runtime_paths"} if schema in (8, 9, 10, 11) else set())
    if schema in (10, 11):
        required |= {"provenance_configuration", "source_admissions"}
    if (type(schema) is not int or schema not in (4, 5, 6, 7, 8, 9, 10, 11)
            or set(document) != required
            or not isinstance(document["instruction_slots"], list)
            or not isinstance(document["warmup_advances"], list)
            or not isinstance(document["cases"], list)):
        raise ValueError("invalid online session plan")
    prepared = None
    expected_runtime = document.get("runtime_paths")
    if schema in (8, 9, 10, 11):
        if not isinstance(expected_runtime, dict) or expected_runtime.get("schema_version") != "runtime_path_compilation.v1":
            raise ValueError("invalid saved runtime path compilation")
        prepared = PreparedRuntimePathContract.from_document(expected_runtime.get("declaration"))
        if (expected_runtime.get("graph_sha256") != prepared.contract.graph_sha256
                or expected_runtime.get("contract_sha256") != prepared.contract.identity_sha256
                or hashlib.sha256(_canonical(expected_runtime.get("topology"))).hexdigest() != expected_runtime.get("topology_sha256")):
            raise ValueError("saved runtime path compilation identity mismatch")
    expected_failure = document.get("terminal_failure")
    if document["schema_version"] in (5, 7, 9, 11) and (
            not isinstance(expected_failure, dict)
            or set(expected_failure) != {"phase", "case_index", "case_id",
                                         "command_index", "error_type", "error_message"}
            or expected_failure["phase"] not in (
                "support_admission", "source_admission", "step", "checker",
                *(("provenance_admission",) if schema == 11 else ()))
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
        if schema in (10, 11):
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
                if (document["schema_version"] not in (6, 7, 8, 9, 10, 11)
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
    if schema in (10, 11):
        _validate_saved_provenance(document, prepared, decoded_cases, decoded_roles, template)
    session = ScenarioSession(template, factory(), checker=checker)
    if prepared is not None:
        session.configure_runtime_paths(prepared.graph, prepared.contract,
                                        prepared.runtime_paths, replay_only=True,
                                        provenance=schema in (10, 11))
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
    for case, source_role in zip(decoded_cases, decoded_roles):
        if expected_failure is None:
            session.submit_case(case, source_role=source_role)
        else:
            try:
                session.submit_case(case, source_role=source_role)
            except BaseException:
                break
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
    admissions_match = (schema not in (10, 11) or
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
